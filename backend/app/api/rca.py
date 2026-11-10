"""POST /api/incidents/{id}/investigate and GET /api/incidents/{id}/rca."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Path, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Operator, SessionDep, Viewer
from app.api.incidents import INCIDENT_ID, get_incident_or_404
from app.llm.factory import ProviderChoice
from app.models import IncidentEventRecord, RecommendationRecord, RootCauseAnalysisRecord
from app.observability.context import incident_id_var
from app.observability.logging import get_logger
from app.schemas.entities import Recommendation, RootCauseAnalysis
from app.security.audit import record_audit
from app.services.rca import run_rca

router = APIRouter(prefix="/api/incidents", tags=["rca"])
log = get_logger("rca")


def rca_response(session: Session, record: RootCauseAnalysisRecord, choice: ProviderChoice | None = None
                 ) -> dict[str, Any]:
    body = RootCauseAnalysis.model_validate(record)
    body.recommended_actions = [Recommendation.model_validate(r) for r in session.scalars(
        select(RecommendationRecord).where(RecommendationRecord.rca_id == record.id)
        .order_by(RecommendationRecord.priority))]
    data = body.model_dump()
    timeline = session.scalars(select(IncidentEventRecord).where(
        IncidentEventRecord.incident_id == record.incident_id,
        IncidentEventRecord.type.in_(("deployment", "config_change", "metric_anomaly", "security")))
        .order_by(IncidentEventRecord.epoch).limit(20)).all()
    leading = record.hypotheses[0] if record.hypotheses else None
    # Spec §26 explainability chain: concise evidence and decisions, never hidden reasoning.
    data["explanation"] = {
        "observed_evidence": record.facts,
        "correlated_events": [{"epoch": e.epoch, "type": e.type, "description": e.description}
                              for e in timeline],
        "candidate_hypotheses": [{"cause_type": h["cause_type"], "confidence": h["confidence"]}
                                 for h in record.hypotheses + record.alternative_hypotheses],
        "hypothesis_evaluation": [{"cause_type": h["cause_type"], "assessment": h["assessment"]}
                                  for h in record.hypotheses + record.alternative_hypotheses],
        "most_likely_root_cause": record.root_cause,
        "confidence": record.confidence,
        "recommended_remediation": [r["action"] for r in data["recommended_actions"]],
        "leading_hypothesis_type": leading["cause_type"] if leading else None,
    }
    if choice is not None:
        data["provider_fallback_reason"] = choice.fallback_reason
    return data


@router.post("/{incident_id}/investigate", status_code=status.HTTP_201_CREATED)
def investigate_incident(request: Request, session: SessionDep, principal: Operator,
                         incident_id: str = Path(..., pattern=INCIDENT_ID)) -> dict[str, Any]:
    incident = get_incident_or_404(session, incident_id)
    choice: ProviderChoice = request.app.state.llm
    token = incident_id_var.set(incident_id)
    try:
        outcome = run_rca(session, incident, choice, actor=f"user:{principal.name}")
        log.info("rca completed", extra={"status": outcome.record.status, "provider": outcome.record.provider,
                                         "steps": outcome.record.steps,
                                         "tool_calls": len(outcome.result.tool_calls)})
    finally:
        incident_id_var.reset(token)
    request.app.state.metrics.rca_runs.labels(outcome.record.provider, outcome.record.status).inc()
    record_audit(session, actor=principal.name, role=principal.role.name.lower(), action="rca.investigate",
                 resource_type="incident", resource_id=incident_id,
                 outcome="success" if outcome.record.status == "completed" else "failure",
                 details={"rca_id": outcome.record.id, "provider": outcome.record.provider,
                          "model": outcome.record.model, "steps": outcome.record.steps,
                          "tool_calls": [{"id": t.id, "tool": t.tool, "ok": t.ok}
                                         for t in outcome.result.tool_calls],
                          "fallback_reason": choice.fallback_reason})
    return rca_response(session, outcome.record, choice)


@router.get("/{incident_id}/rca")
def latest_rca(session: SessionDep, _: Viewer,
               incident_id: str = Path(..., pattern=INCIDENT_ID)) -> dict[str, Any]:
    get_incident_or_404(session, incident_id)
    record = session.scalars(select(RootCauseAnalysisRecord).where(
        RootCauseAnalysisRecord.incident_id == incident_id)
        .order_by(RootCauseAnalysisRecord.id.desc()).limit(1)).first()
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no RCA yet; POST .../investigate first")
    return rca_response(session, record)
