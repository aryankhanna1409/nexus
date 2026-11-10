"""Runs an RCA investigation for a stored incident and persists the result."""

from __future__ import annotations

import time
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.llm.factory import ProviderChoice
from app.models import IncidentEventRecord, IncidentRecord, RecommendationRecord, RootCauseAnalysisRecord
from app.rca.engine import InvestigationResult, investigate
from app.rca.tools import InvestigationContext


@dataclass(frozen=True)
class RcaOutcome:
    record: RootCauseAnalysisRecord
    result: InvestigationResult


def run_rca(session: Session, incident: IncidentRecord, choice: ProviderChoice, actor: str,
            max_steps: int = 10) -> RcaOutcome:
    started = int(time.time())
    session.add(IncidentEventRecord(incident_id=incident.incident_id, epoch=started,
                                    type="ai_investigation_started",
                                    description=f"RCA investigation started ({choice.provider.name})",
                                    reference_id=None, actor=actor))
    if incident.status == "open":
        incident.status = "investigating"
    session.flush()

    result = investigate(InvestigationContext(session, incident), choice.provider, max_steps=max_steps)
    answer = result.answer
    record = RootCauseAnalysisRecord(
        incident_id=incident.incident_id, created_epoch=int(time.time()), status=result.status,
        provider=result.provider, model=result.model,
        root_cause=answer.root_cause if answer else f"Investigation failed: {result.failure_reason}",
        confidence=answer.confidence if answer else 0.0,
        impact=answer.impact if answer else "",
        steps=result.steps,
        facts=[f.model_dump() for f in answer.facts] if answer else [],
        inferences=[i.model_dump() for i in answer.inferences] if answer else [],
        hypotheses=[h.model_dump() for h in answer.hypotheses[:1]] if answer else [],
        alternative_hypotheses=[h.model_dump() for h in answer.hypotheses[1:]] if answer else [],
        evidence=[{"tool_call_id": r.id, "tool": r.tool, "ok": r.ok} for r in result.tool_calls],
        verification_steps=list(answer.verification_steps) if answer else [],
        tool_calls=[r.to_dict() for r in result.tool_calls])
    session.add(record)
    session.flush()
    if answer:
        for action in answer.recommended_actions:
            session.add(RecommendationRecord(rca_id=record.id, incident_id=incident.incident_id,
                                             priority=action.priority, action=action.action,
                                             rationale=action.rationale, risk_class=action.risk_class,
                                             agent_tool=action.agent_tool))
        session.add(IncidentEventRecord(
            incident_id=incident.incident_id, epoch=record.created_epoch, type="root_cause_identified",
            description=f"Leading hypothesis ({answer.confidence:.0%}): {answer.root_cause}",
            reference_id=f"RCA-{record.id}", actor=f"rca:{result.provider}"))
    else:
        session.add(IncidentEventRecord(
            incident_id=incident.incident_id, epoch=record.created_epoch, type="investigation_failed",
            description=f"RCA failed: {result.failure_reason}", reference_id=f"RCA-{record.id}",
            actor=f"rca:{result.provider}"))
    session.commit()
    return RcaOutcome(record, result)
