"""Network KPI series and detected metric anomalies."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.api.common import MAX_PAGE, resolve_run
from app.api.deps import SessionDep, Viewer
from app.models import Anomaly as AnomalyRow
from app.models import IncidentCell, IncidentRecord
from app.models import NetworkMetric as MetricRow
from app.schemas.entities import Anomaly
from app.schemas.common import iso
from app.simulation.metrics import METRIC_BY_NAME, METRIC_NAMES

router = APIRouter(prefix="/api/network", tags=["network"])
CELL_PATTERN = r"^[0-9A-Za-z._-]{1,31}$"
METRIC_PATTERN = "^(" + "|".join(METRIC_NAMES) + ")$"


@router.get("/metrics")
def metrics(
    session: SessionDep, _: Viewer,
    metric: str = Query(..., pattern=METRIC_PATTERN),
    cell_id: str | None = Query(None, pattern=CELL_PATTERN),
    start: int | None = Query(None, ge=0, description="epoch seconds, inclusive"),
    end: int | None = Query(None, ge=0, description="epoch seconds, inclusive"),
    run_id: int | None = Query(None, ge=1),
) -> dict[str, Any]:
    """One series per cell for `metric` (all cells unless `cell_id` is given)."""
    run = resolve_run(session, run_id)
    query = select(MetricRow.cell_id, MetricRow.node_id, MetricRow.epoch, MetricRow.value).where(
        MetricRow.run_id == run.id, MetricRow.metric == metric)
    if cell_id is not None:
        query = query.where(MetricRow.cell_id == cell_id)
    if start is not None:
        query = query.where(MetricRow.epoch >= start)
    if end is not None:
        query = query.where(MetricRow.epoch <= end)
    series: dict[str, dict[str, Any]] = {}
    for cell, node, epoch, value in session.execute(query.order_by(MetricRow.cell_id, MetricRow.epoch)):
        entry = series.setdefault(cell, {"cell_id": cell, "node_id": node, "epochs": [], "values": []})
        entry["epochs"].append(epoch)
        entry["values"].append(value)
    return {"run_id": run.id, "metric": metric, "series": list(series.values())}


@router.get("/anomalies", response_model=list[Anomaly])
def anomalies(
    session: SessionDep, _: Viewer,
    run_id: int | None = Query(None, ge=1),
    cell_id: str | None = Query(None, pattern=CELL_PATTERN),
    metric: str | None = Query(None, pattern=METRIC_PATTERN),
    severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    limit: int = Query(500, ge=1, le=MAX_PAGE),
) -> list[AnomalyRow]:
    run = resolve_run(session, run_id)
    query = select(AnomalyRow).where(AnomalyRow.run_id == run.id)
    if cell_id:
        query = query.where(AnomalyRow.cell_id == cell_id)
    if metric:
        query = query.where(AnomalyRow.metric == metric)
    if severity:
        query = query.where(AnomalyRow.severity == severity)
    return list(session.scalars(query.order_by(AnomalyRow.start_epoch, AnomalyRow.cell_id).limit(limit)))


OVERVIEW_KPIS = ("latency_ms", "packet_loss_pct", "call_drop_rate", "throughput_mbps", "cpu_utilization",
                 "memory_utilization", "call_setup_success_rate", "jitter_ms")
INCIDENT_PENALTY = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
RECENT_SECONDS = 1800


@router.get("/overview")
def overview(session: SessionDep, _: Viewer, run_id: int | None = Query(None, ge=1)) -> dict[str, Any]:
    """Network health for the dashboard.

    - current KPI = mean over all cells in the last 30 minutes of the run's data;
    - baseline = mean over the 60 minutes before the earliest active incident (or the
      first 60 minutes of the run when there is none);
    - health score = 100 - per active incident (CRITICAL 30, HIGH 20, MEDIUM 10, LOW 5)
      - 2 per cell with an anomaly active in the last 30 minutes, floored at 0.
    """
    run = resolve_run(session, run_id)
    active = list(session.scalars(select(IncidentRecord).where(IncidentRecord.status != "resolved")
                                  .order_by(IncidentRecord.start_epoch)))
    base_end = active[0].start_epoch if active else run.data_start_epoch + 3600
    base_start = base_end - 3600

    def mean(metric: str, start: int, end: int) -> float | None:
        value = session.scalar(select(func.avg(MetricRow.value)).where(
            MetricRow.run_id == run.id, MetricRow.metric == metric, MetricRow.epoch >= start,
            MetricRow.epoch <= end))
        return None if value is None else round(float(value), 3)

    kpis = []
    for metric in OVERVIEW_KPIS:
        current = mean(metric, run.data_end_epoch - RECENT_SECONDS, run.data_end_epoch)
        baseline = mean(metric, base_start, base_end)
        if current is not None and baseline is not None:
            spec = METRIC_BY_NAME[metric]
            kpis.append({"metric": metric, "unit": spec.unit, "current": current, "baseline": baseline,
                         "bad_direction": spec.bad_direction.value})
    recent: dict[str, set[str]] = {}
    for cell, metric in session.execute(select(AnomalyRow.cell_id, AnomalyRow.metric).where(
            AnomalyRow.run_id == run.id, AnomalyRow.end_epoch >= run.data_end_epoch - RECENT_SECONDS)):
        recent.setdefault(cell, set()).add(metric)
    cells = [{"cell_id": cell, "node_id": node, "status": "degraded" if cell in recent else "ok",
              "open_anomalies": sorted(recent.get(cell, set()))}
             for cell, node in session.execute(select(MetricRow.cell_id, MetricRow.node_id).where(
                 MetricRow.run_id == run.id).distinct().order_by(MetricRow.cell_id))]
    breakdown: list[dict[str, Any]] = [{"reason": f"{i.severity} incident {i.incident_id} ({i.status})",
                  "penalty": INCIDENT_PENALTY.get(i.severity, 0)} for i in active]
    if recent:
        breakdown.append({"reason": f"{len(recent)} cell(s) with anomalies in the last 30 min",
                          "penalty": 2 * len(recent)})
    anomaly_count = session.scalar(select(func.count()).select_from(AnomalyRow)
                                   .where(AnomalyRow.run_id == run.id)) or 0
    return {"run_id": run.id, "data_start": iso(run.data_start_epoch), "data_end": iso(run.data_end_epoch),
            "health_score": max(0, 100 - sum(b["penalty"] for b in breakdown)), "health_breakdown": breakdown,
            "active_incidents": len(active), "anomaly_count": anomaly_count, "kpis": kpis, "cells": cells,
            "affected_cells_by_incident": {i.incident_id: list(session.scalars(select(IncidentCell.cell_id).where(
                IncidentCell.incident_id == i.incident_id))) for i in active}}
