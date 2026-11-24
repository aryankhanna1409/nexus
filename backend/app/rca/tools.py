"""Read-only investigation tools exposed to the LLM (spec §8).

Every tool has a strict JSON schema (sent to the model) and a Pydantic model
that re-validates the arguments before execution. Tools only read from the
database and are scoped to the incident's pipeline run. Inputs are bounded
(time spans ≤ 24 h, known metric names, cells and services) and outputs are
size-limited, so a single call can never dump the whole dataset into the
prompt.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.llm.base import ToolSpec
from app.models import (
    Anomaly,
    CallAnalysisRun,
    CallAnomalyRecord,
    CallCellStatistics,
    Deployment,
    IncidentCell,
    IncidentEventRecord,
    IncidentRecord,
    NetworkMetric,
    OperationalEventRecord,
)
from app.schemas.common import iso
from app.simulation.metrics import METRIC_NAMES

MAX_SPAN_SECONDS = 24 * 3600
MAX_SERIES_POINTS = 120
KNOWN_SERVICES = ("packet-gateway", "ci-cd", "config-manager", "ids")
ISO_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"


class ToolError(Exception):
    """Raised for invalid arguments or out-of-scope requests; reported back to the model."""


def parse_iso(text: str) -> int:
    try:
        return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())
    except ValueError as exc:
        raise ValueError(f"invalid timestamp {text!r}; use YYYY-MM-DDTHH:MM:SSZ") from exc


# ---- Argument models ------------------------------------------------------------------


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class NoArgs(_Args):
    pass


class CellArgs(_Args):
    cell_id: str = Field(pattern=r"^[0-9A-Za-z._-]{1,31}$")


class TimeRange(_Args):
    start: str = Field(pattern=ISO_PATTERN)
    end: str = Field(pattern=ISO_PATTERN)

    @model_validator(mode="after")
    def _span(self) -> TimeRange:
        start, end = parse_iso(self.start), parse_iso(self.end)
        if end <= start:
            raise ValueError("end must be after start")
        if end - start > MAX_SPAN_SECONDS:
            raise ValueError("time range may not exceed 24 hours")
        return self


class MetricHistoryArgs(TimeRange):
    metric: str
    cell_id: str = Field(pattern=r"^[0-9A-Za-z._-]{1,31}$")

    @field_validator("metric")
    @classmethod
    def _metric(cls, value: str) -> str:
        if value not in METRIC_NAMES:
            raise ValueError(f"unknown metric {value!r}")
        return value


class AnomalyArgs(TimeRange):
    cell_id: str | None = Field(pattern=r"^[0-9A-Za-z._-]{1,31}$")


class IncidentArgs(_Args):
    incident_id: str = Field(pattern=r"^INC-\d{4}-\d{3,6}$")


class DeploymentArgs(_Args):
    before: str | None = Field(pattern=ISO_PATTERN)


class LogArgs(TimeRange):
    service: str

    @field_validator("service")
    @classmethod
    def _service(cls, value: str) -> str:
        if value not in KNOWN_SERVICES:
            raise ValueError(f"unknown service {value!r}; known: {', '.join(KNOWN_SERVICES)}")
        return value


class BaselineArgs(TimeRange):
    metric: str
    cell_id: str | None = Field(pattern=r"^[0-9A-Za-z._-]{1,31}$")

    @field_validator("metric")
    @classmethod
    def _metric(cls, value: str) -> str:
        if value not in METRIC_NAMES:
            raise ValueError(f"unknown metric {value!r}")
        return value


# ---- JSON schemas sent to the model (strict: every property required) -----------------

_TIME = {"start": {"type": "string", "description": "UTC start, YYYY-MM-DDTHH:MM:SSZ"},
         "end": {"type": "string", "description": "UTC end, YYYY-MM-DDTHH:MM:SSZ (span <= 24h)"}}
_METRIC = {"type": "string", "enum": list(METRIC_NAMES)}


def _schema(properties: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": list(properties),
            "additionalProperties": False}


# ---- Context and implementations -------------------------------------------------------


@dataclass(frozen=True)
class InvestigationContext:
    session: Session
    incident: IncidentRecord

    @property
    def run_id(self) -> int:
        return self.incident.run_id

    def affected_cells(self) -> list[str]:
        return list(self.session.scalars(select(IncidentCell.cell_id)
                                         .where(IncidentCell.incident_id == self.incident.incident_id)
                                         .order_by(IncidentCell.cell_id)))

    def check_cell(self, cell_id: str) -> None:
        exists = self.session.scalar(select(func.count()).select_from(NetworkMetric).where(
            NetworkMetric.run_id == self.run_id, NetworkMetric.cell_id == cell_id).limit(1))
        if not exists:
            raise ToolError(f"unknown cell {cell_id!r}")


def _call_statistics(ctx: InvestigationContext, _: NoArgs) -> dict[str, Any]:
    analysis = ctx.session.scalars(select(CallAnalysisRun).where(CallAnalysisRun.run_id == ctx.run_id)).first()
    if analysis is None:
        raise ToolError("no call analysis for this incident's run")
    worst = ctx.session.scalars(select(CallCellStatistics).where(CallCellStatistics.analysis_id == analysis.id)
                                .order_by(CallCellStatistics.drop_rate.desc()).limit(12)).all()
    return {"source": "libcallanalyzer (C)", "total_calls": analysis.total_calls,
            "success_rate": round(analysis.success_rate, 4), "drop_rate": round(analysis.drop_rate, 4),
            "setup_failure_rate": round(analysis.setup_failure_rate, 4),
            "cells_by_drop_rate": [{"cell_id": c.cell_id, "drop_rate": round(c.drop_rate, 4),
                                    "setup_failure_rate": round(c.setup_failure_rate, 4),
                                    "calls": c.total_calls} for c in worst]}


def _cell_statistics(ctx: InvestigationContext, args: CellArgs) -> dict[str, Any]:
    ctx.check_cell(args.cell_id)
    analysis = ctx.session.scalars(select(CallAnalysisRun).where(CallAnalysisRun.run_id == ctx.run_id)).first()
    calls = None
    call_anomalies: list[dict[str, Any]] = []
    if analysis is not None:
        row = ctx.session.scalars(select(CallCellStatistics).where(
            CallCellStatistics.analysis_id == analysis.id, CallCellStatistics.cell_id == args.cell_id)).first()
        if row is not None:
            calls = {"total_calls": row.total_calls, "drop_rate": round(row.drop_rate, 4),
                     "setup_failure_rate": round(row.setup_failure_rate, 4),
                     "average_signal_dbm": round(row.average_signal, 1),
                     "average_packet_loss_pct": round(row.average_packet_loss, 2)}
        call_anomalies = [{"type": a.type, "severity": a.severity, "description": a.description}
                          for a in ctx.session.scalars(select(CallAnomalyRecord).where(
                              CallAnomalyRecord.analysis_id == analysis.id,
                              CallAnomalyRecord.subject == args.cell_id))]
    anomalies = ctx.session.scalars(select(Anomaly).where(Anomaly.run_id == ctx.run_id,
                                                          Anomaly.cell_id == args.cell_id)
                                    .order_by(Anomaly.start_epoch)).all()
    return {"cell_id": args.cell_id, "in_incident": args.cell_id in ctx.affected_cells(),
            "call_statistics": calls, "call_anomalies": call_anomalies,
            "metric_anomalies": [{"metric": a.metric, "onset": iso(a.start_epoch), "severity": a.severity,
                                  "baseline": round(a.baseline, 3), "worst": round(a.value, 3)}
                                 for a in anomalies]}


def _series(ctx: InvestigationContext, metric: str, cell_id: str, start: int, end: int) -> list[tuple[int, float]]:
    return [(int(e), float(v)) for e, v in ctx.session.execute(
        select(NetworkMetric.epoch, NetworkMetric.value).where(
            NetworkMetric.run_id == ctx.run_id, NetworkMetric.metric == metric,
            NetworkMetric.cell_id == cell_id, NetworkMetric.epoch >= start, NetworkMetric.epoch <= end)
        .order_by(NetworkMetric.epoch))]


def _metric_history(ctx: InvestigationContext, args: MetricHistoryArgs) -> dict[str, Any]:
    ctx.check_cell(args.cell_id)
    points = _series(ctx, args.metric, args.cell_id, parse_iso(args.start), parse_iso(args.end))
    if not points:
        raise ToolError("no samples in the requested range")
    step = max(1, -(-len(points) // MAX_SERIES_POINTS))
    sampled = points[::step]
    values = [v for _, v in points]
    return {"metric": args.metric, "cell_id": args.cell_id, "samples": len(points),
            "downsample_step": step, "min": round(min(values), 3), "max": round(max(values), 3),
            "mean": round(sum(values) / len(values), 3),
            "first": {"t": iso(points[0][0]), "v": round(points[0][1], 3)},
            "last": {"t": iso(points[-1][0]), "v": round(points[-1][1], 3)},
            "series": [[iso(t), round(v, 3)] for t, v in sampled]}


def _anomalies(ctx: InvestigationContext, args: AnomalyArgs) -> dict[str, Any]:
    start, end = parse_iso(args.start), parse_iso(args.end)
    query = select(Anomaly).where(Anomaly.run_id == ctx.run_id, Anomaly.start_epoch <= end,
                                  Anomaly.end_epoch >= start)
    if args.cell_id is not None:
        query = query.where(Anomaly.cell_id == args.cell_id)
    rows = ctx.session.scalars(query.order_by(Anomaly.start_epoch, Anomaly.cell_id).limit(60)).all()
    return {"count": len(rows), "truncated": len(rows) == 60,
            "anomalies": [{"anomaly_id": a.anomaly_id, "metric": a.metric, "cell_id": a.cell_id,
                           "onset": iso(a.start_epoch), "end": iso(a.end_epoch), "severity": a.severity,
                           "baseline": round(a.baseline, 3), "worst": round(a.value, 3),
                           "detectors": a.detectors} for a in rows]}


def _related_events(ctx: InvestigationContext, args: IncidentArgs) -> dict[str, Any]:
    if args.incident_id != ctx.incident.incident_id:
        raise ToolError("tools are scoped to the incident under investigation")
    events = ctx.session.scalars(select(IncidentEventRecord).where(
        IncidentEventRecord.incident_id == args.incident_id).order_by(IncidentEventRecord.epoch,
                                                                       IncidentEventRecord.id)).all()
    inc = ctx.incident
    return {"incident_id": inc.incident_id, "severity": inc.severity, "start": iso(inc.start_epoch),
            "end": iso(inc.end_epoch), "affected_cells": ctx.affected_cells(),
            "timeline": [{"t": iso(e.epoch), "type": e.type, "description": e.description,
                          "reference_id": e.reference_id} for e in events[:60]],
            "correlation_hypotheses": [{"cause_type": c["cause_type"], "description": c["description"],
                                        "score": c["score"], "status": "hypothesis"}
                                       for c in inc.suspected_causes],
            "excluded_candidates": inc.excluded_candidates,
            "correlation_confidence": inc.confidence, "chain_consistency": inc.chain_consistency}


def _recent_deployments(ctx: InvestigationContext, args: DeploymentArgs) -> dict[str, Any]:
    query = select(Deployment).where(Deployment.run_id == ctx.run_id)
    if args.before is not None:
        query = query.where(Deployment.deployed_epoch <= parse_iso(args.before))
    rows = ctx.session.scalars(query.order_by(Deployment.deployed_epoch.desc()).limit(20)).all()
    return {"deployments": [{"deployment_id": d.deployment_id, "service": d.service, "node_id": d.node_id,
                             "from_version": d.from_version, "to_version": d.to_version,
                             "deployed_at": iso(d.deployed_epoch), "status": d.status,
                             "change_summary": d.change_summary} for d in rows],
            "incident_nodes": sorted(set(ctx.session.scalars(select(IncidentCell.node_id).where(
                IncidentCell.incident_id == ctx.incident.incident_id))))}


def _security_events(ctx: InvestigationContext, args: TimeRange) -> dict[str, Any]:
    start, end = parse_iso(args.start), parse_iso(args.end)
    rows = ctx.session.scalars(select(OperationalEventRecord).where(
        OperationalEventRecord.run_id == ctx.run_id, OperationalEventRecord.type == "security",
        OperationalEventRecord.epoch >= start, OperationalEventRecord.epoch <= end)
        .order_by(OperationalEventRecord.epoch)).all()
    by_category: dict[str, int] = {}
    targeted: dict[str, int] = {}
    for r in rows:
        category = str(r.attributes.get("category", "unknown"))
        by_category[category] = by_category.get(category, 0) + 1
        target = r.cell_id or r.node_id or "unattributed"
        targeted[target] = targeted.get(target, 0) + 1
    return {"count": len(rows), "by_category": by_category, "by_target": targeted,
            "sample": [{"t": iso(r.epoch), "severity": r.severity, "message": r.message,
                        "target": r.cell_id or r.node_id} for r in rows[:10]]}


def _logs(ctx: InvestigationContext, args: LogArgs) -> dict[str, Any]:
    start, end = parse_iso(args.start), parse_iso(args.end)
    rows = ctx.session.scalars(select(OperationalEventRecord).where(
        OperationalEventRecord.run_id == ctx.run_id, OperationalEventRecord.source == args.service,
        OperationalEventRecord.epoch >= start, OperationalEventRecord.epoch <= end)
        .order_by(OperationalEventRecord.epoch).limit(50)).all()
    return {"service": args.service, "count": len(rows), "truncated": len(rows) == 50,
            "entries": [{"t": iso(r.epoch), "level": r.severity, "node": r.node_id, "message": r.message}
                        for r in rows]}


def _compare_baseline(ctx: InvestigationContext, args: BaselineArgs) -> dict[str, Any]:
    start, end = parse_iso(args.start), parse_iso(args.end)
    cells = [args.cell_id] if args.cell_id else ctx.affected_cells()
    results = []
    for cell in cells:
        ctx.check_cell(cell)
        window = [v for _, v in _series(ctx, args.metric, cell, start, end)]
        baseline = [v for _, v in _series(ctx, args.metric, cell, start - 3600, start - 60)]
        if not window or not baseline:
            continue
        w, b = sum(window) / len(window), sum(baseline) / len(baseline)
        results.append({"cell_id": cell, "baseline_mean": round(b, 3), "window_mean": round(w, 3),
                        "window_max": round(max(window), 3), "window_min": round(min(window), 3),
                        "delta": round(w - b, 3),
                        "pct_change": round(100.0 * (w - b) / abs(b), 1) if b else None})
    if not results:
        raise ToolError("no data for the requested metric, cells and range")
    return {"metric": args.metric, "baseline_window": "60 minutes before start", "cells": results}


@dataclass(frozen=True)
class RcaTool:
    spec: ToolSpec
    args_model: type[_Args]
    run: Callable[[InvestigationContext, Any], dict[str, Any]]


def _tool(name: str, description: str, properties: dict[str, Any], args_model: type[_Args],
          run: Callable[[InvestigationContext, Any], dict[str, Any]]) -> RcaTool:
    return RcaTool(ToolSpec(name, description, _schema(properties)), args_model, run)


_NULLABLE_CELL = {"type": ["string", "null"], "description": "cell id, or null for all affected cells"}
TOOLS: dict[str, RcaTool] = {t.spec.name: t for t in (
    _tool("get_call_statistics", "Overall call statistics from the C call-log analyser, with the cells "
          "that have the highest drop rates.", {}, NoArgs, _call_statistics),
    _tool("get_cell_statistics", "Call statistics, call anomalies and metric anomalies for one cell.",
          {"cell_id": {"type": "string"}}, CellArgs, _cell_statistics),
    _tool("get_metric_history", "Time series (downsampled to <= 120 points) of one KPI on one cell.",
          {"metric": _METRIC, "cell_id": {"type": "string"}, **_TIME}, MetricHistoryArgs, _metric_history),
    _tool("get_anomalies", "Detected metric anomalies overlapping a time range, optionally for one cell.",
          {**_TIME, "cell_id": _NULLABLE_CELL}, AnomalyArgs, _anomalies),
    _tool("get_related_events", "The incident's timeline, the correlation engine's ranked hypotheses "
          "and the candidates it excluded.", {"incident_id": {"type": "string"}}, IncidentArgs,
          _related_events),
    _tool("get_recent_deployments", "Recent packet-gateway deployments (optionally only those before a time).",
          {"before": {"type": ["string", "null"], "description": "YYYY-MM-DDTHH:MM:SSZ or null"}},
          DeploymentArgs, _recent_deployments),
    _tool("get_security_events", "IDS/security events in a time range, aggregated by category and target.",
          dict(_TIME), TimeRange, _security_events),
    _tool("get_logs", "Application/operational log entries for one service in a time range.",
          {"service": {"type": "string", "enum": list(KNOWN_SERVICES)}, **_TIME}, LogArgs, _logs),
    _tool("compare_baseline", "Mean of a KPI in a time range versus the 60 minutes before it, per cell.",
          {"metric": _METRIC, **_TIME, "cell_id": _NULLABLE_CELL}, BaselineArgs, _compare_baseline),
)}
