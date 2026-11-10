"""Builds a ReportDocument for an incident from stored analytics, RCA and C-library results.

All figures are computed here from the database. The LLM (or the mock
provider) only writes the executive-summary prose. That prose is accepted
only if every number in it appears in the context it was given; otherwise the
deterministic template is used and the rejection is recorded.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.llm.base import LLMError, UserMessage
from app.llm.factory import ProviderChoice
from app.llm.mock import CONTEXT_JSON_MARKER, template_summary
from app.models import (
    CallAnalysisRun,
    CallCellStatistics,
    IncidentCell,
    IncidentEventRecord,
    IncidentRecord,
    NetworkMetric,
    RecommendationRecord,
    ReportRecord,
    RootCauseAnalysisRecord,
)
from app.reporting.document import (
    AnomalyEntry,
    ImpactSection,
    KpiChange,
    ReportDocument,
    RootCauseSection,
)
from app.schemas.common import iso
from app.simulation.metrics import METRIC_BY_NAME, Direction

CORE_KPIS = ("packet_loss_pct", "latency_ms", "call_drop_rate", "throughput_mbps", "cpu_utilization",
             "memory_utilization", "call_setup_success_rate", "jitter_ms")
SUMMARY_SYSTEM = ("Write a 3-4 sentence executive summary of a network incident for an operations "
                  "audience. Use only facts and numbers present in the JSON context; do not add numbers. "
                  "Describe the root cause as the leading hypothesis with its confidence, not as a fact.")
DATA_NOTICE = "Generated from synthetic demonstration data (Aegis-Net simulator); not production telemetry."
_NUMBER = re.compile(r"\d+(?:\.\d+)?")


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _kpis(session: Session, incident: IncidentRecord, cells: list[str], metrics: list[str]) -> list[KpiChange]:
    out = []
    for metric in metrics:
        rows = session.execute(select(NetworkMetric.epoch, NetworkMetric.value).where(
            NetworkMetric.run_id == incident.run_id, NetworkMetric.metric == metric,
            NetworkMetric.cell_id.in_(cells),
            NetworkMetric.epoch >= incident.start_epoch - 3600, NetworkMetric.epoch <= incident.end_epoch)).all()
        baseline = [v for e, v in rows if e < incident.start_epoch]
        during = [v for e, v in rows if e >= incident.start_epoch]
        if not baseline or not during:
            continue
        spec = METRIC_BY_NAME[metric]
        bad_down = spec.bad_direction is Direction.DOWN
        b, d = _mean(baseline), _mean(during)
        out.append(KpiChange(metric=metric, unit=spec.unit, baseline=round(b, 3), incident_mean=round(d, 3),
                             worst=round(min(during) if bad_down else max(during), 3),
                             change_pct=round(100.0 * (d - b) / abs(b), 1) if b else None,
                             direction="down" if bad_down else "up"))
    return out


def _finding(k: KpiChange) -> str:
    verb = "fell" if k.incident_mean < k.baseline else "rose"
    unit = "%" if k.unit == "%" else f" {k.unit}"
    return (f"{k.metric} {verb} from {k.baseline:g}{unit} to {k.incident_mean:g}{unit} on average "
            f"(worst {k.worst:g}{unit})")


def _narrative_is_grounded(text: str, context: dict[str, Any]) -> bool:
    allowed = set(_NUMBER.findall(json.dumps(context)))
    return all(n in allowed for n in _NUMBER.findall(text))


def build_report(session: Session, incident_id: str, choice: ProviderChoice, created_by: str) -> ReportDocument:
    incident = session.get(IncidentRecord, incident_id)
    if incident is None:
        raise KeyError(incident_id)
    cell_rows = session.scalars(select(IncidentCell).where(IncidentCell.incident_id == incident_id)
                                .order_by(IncidentCell.cell_id)).all()
    cells = [c.cell_id for c in cell_rows]
    nodes = sorted({c.node_id for c in cell_rows})
    symptom_metrics = [s["metric"] for s in incident.symptoms]
    kpis = _kpis(session, incident, cells, [m for m in CORE_KPIS if m in symptom_metrics]
                 + [m for m in CORE_KPIS if m not in symptom_metrics][:2])

    rca = session.scalars(select(RootCauseAnalysisRecord).where(
        RootCauseAnalysisRecord.incident_id == incident_id, RootCauseAnalysisRecord.status == "completed")
        .order_by(RootCauseAnalysisRecord.id.desc()).limit(1)).first()
    recommendations: list[dict[str, Any]] = []
    if rca is not None:
        leading = rca.hypotheses[0] if rca.hypotheses else {}
        root = RootCauseSection(
            source="rca", statement=rca.root_cause, cause_type=leading.get("cause_type"),
            confidence=rca.confidence,
            status_label=f"Leading hypothesis from AI-assisted RCA ({rca.provider}/{rca.model}); "
                         "supported by the cited evidence, not a confirmed fact.",
            facts=rca.facts, inferences=rca.inferences, alternative_hypotheses=rca.alternative_hypotheses)
        recommendations = [{"priority": r.priority, "action": r.action, "rationale": r.rationale,
                            "risk_class": r.risk_class, "agent_tool": r.agent_tool}
                           for r in session.scalars(select(RecommendationRecord).where(
                               RecommendationRecord.rca_id == rca.id).order_by(RecommendationRecord.priority))]
        verification = list(rca.verification_steps)
    elif incident.suspected_causes:
        top = incident.suspected_causes[0]
        root = RootCauseSection(
            source="correlation", statement=top["description"], cause_type=top["cause_type"],
            confidence=incident.confidence,
            status_label="Leading correlation hypothesis (no RCA has been run); not a confirmed fact.",
            facts=[], inferences=[], alternative_hypotheses=incident.suspected_causes[1:])
        verification = []
        recommendations = [{"priority": 1, "action": f"Run an RCA investigation for {incident_id}",
                            "rationale": "No root-cause analysis has been performed yet.",
                            "risk_class": "READ_ONLY", "agent_tool": None}]
    else:
        root = RootCauseSection(source="none", statement="No cause hypothesis is available.", cause_type=None,
                                confidence=None, status_label="Undetermined.", facts=[], inferences=[],
                                alternative_hypotheses=[])
        verification = []

    users = session.execute(select(NetworkMetric.cell_id, func.avg(NetworkMetric.value)).where(
        NetworkMetric.run_id == incident.run_id, NetworkMetric.metric == "active_users",
        NetworkMetric.cell_id.in_(cells), NetworkMetric.epoch >= incident.start_epoch,
        NetworkMetric.epoch <= incident.end_epoch).group_by(NetworkMetric.cell_id)).all()
    estimated_users = int(round(sum(float(avg) for _, avg in users)))
    analysis = session.scalars(select(CallAnalysisRun).where(CallAnalysisRun.run_id == incident.run_id)).first()
    call_rows = [] if analysis is None else session.scalars(select(CallCellStatistics).where(
        CallCellStatistics.analysis_id == analysis.id, CallCellStatistics.cell_id.in_(cells))).all()
    calls = sum(c.total_calls for c in call_rows) if call_rows else None
    dropped = sum(c.dropped_calls for c in call_rows) if call_rows else None
    failed = sum(c.failed_setup_calls for c in call_rows) if call_rows else None
    duration = (incident.end_epoch - incident.start_epoch) // 60 + 1
    impact = ImpactSection(
        affected_cells=cells, affected_nodes=nodes, duration_minutes=duration,
        estimated_affected_users=estimated_users, calls_in_affected_cells=calls,
        dropped_calls_in_affected_cells=dropped, failed_setups_in_affected_cells=failed,
        summary=(f"{len(cells)} cell(s) on {', '.join(nodes)} degraded for {duration} min; about "
                 f"{estimated_users} users were connected to the affected cells"
                 + (f"; {dropped} dropped and {failed} failed call setups among {calls} calls in the "
                    f"analysed call log for these cells" if calls is not None else "") + "."))

    window = f"{iso(incident.start_epoch)} to {iso(incident.end_epoch)}"
    findings = [_finding(k) for k in kpis[:4]]
    context = {"incident_id": incident_id, "severity": incident.severity, "window": window,
               "affected_cells": cells, "key_findings": findings, "root_cause": root.statement,
               "confidence": root.confidence or 0.0,
               "confidence_pct": round((root.confidence or 0.0) * 100), "impact": impact.summary}
    narrative_provider = choice.provider.name
    try:
        response = choice.provider.generate(SUMMARY_SYSTEM, [UserMessage(
            f"Summarise this incident.\n{CONTEXT_JSON_MARKER} {json.dumps(context)}")], max_tokens=1024)
        summary = response.text.strip()
        if not summary or not _narrative_is_grounded(summary, context):
            summary = template_summary(context)
            narrative_provider = f"template (narrative from {choice.provider.name} rejected: ungrounded numbers)"
    except LLMError as exc:
        summary = template_summary(context)
        narrative_provider = f"template ({choice.provider.name} failed: {type(exc).__name__})"

    events = session.scalars(select(IncidentEventRecord).where(IncidentEventRecord.incident_id == incident_id)
                             .order_by(IncidentEventRecord.epoch, IncidentEventRecord.id)).all()
    count = session.scalar(select(func.count()).select_from(ReportRecord)
                           .where(ReportRecord.incident_id == incident_id)) or 0
    tool_refs = [f"RCA-{rca.id}:{t['id']}" for t in rca.tool_calls if t.get("ok")] if rca else []
    caveats = list(incident.caveats)
    if incident.status != "resolved":
        caveats.append("Remediation has not been verified; the root cause remains a hypothesis until "
                       "recovery is confirmed.")
    return ReportDocument(
        report_id=f"RPT-{incident_id}-{count + 1:02d}", incident_id=incident_id,
        title="Network Health & Incident Analysis", generated_at=iso(int(time.time())) or "",
        generated_by=created_by, severity=incident.severity, status=incident.status, window=window,
        data_notice=DATA_NOTICE, executive_summary=summary, narrative_provider=narrative_provider,
        kpi_analysis=kpis,
        anomaly_analysis=[AnomalyEntry(metric=s["metric"], cells=s["cells"], onset=s["onset"],
                                       worst_value=round(s["worst_value"], 3), baseline=round(s["baseline"], 3),
                                       severity=s["severity"]) for s in incident.symptoms],
        correlation_analysis={"causal_chain": incident.causal_chain,
                              "chain_consistency": incident.chain_consistency,
                              "hypotheses": incident.suspected_causes,
                              "excluded_candidates": incident.excluded_candidates,
                              "call_evidence": [{"type": c["type"], "subject": c["subject"],
                                                 "severity": c["severity"], "description": c["description"]}
                                                for c in incident.call_evidence]},
        root_cause=root, impact=impact, recommendations=recommendations, verification_steps=verification,
        confidence={"root_cause_confidence": root.confidence, "correlation_confidence": incident.confidence,
                    "chain_consistency": incident.chain_consistency, "caveats": caveats},
        evidence_references={"tool_calls": tool_refs,
                             "anomalies": sorted({a for s in incident.symptoms for a in s["anomaly_ids"]}),
                             "events": sorted({e.reference_id for e in events if e.reference_id})},
        timeline=[{"timestamp": iso(e.epoch), "type": e.type, "description": e.description} for e in events])
