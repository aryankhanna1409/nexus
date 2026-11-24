"""Call-analysis results produced by libcallanalyzer (C) for a pipeline run."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.api.common import resolve_run
from app.api.deps import SessionDep, Viewer
from app.models import CallAnalysisRun, CallAnomalyRecord, CallCellStatistics
from app.schemas.common import iso

router = APIRouter(prefix="/api/calls", tags=["calls"])


def _analysis(session: SessionDep, run_id: int | None) -> CallAnalysisRun:
    run = resolve_run(session, run_id)
    analysis = session.scalars(select(CallAnalysisRun).where(CallAnalysisRun.run_id == run.id)).first()
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no call analysis for this run")
    return analysis


@router.get("/statistics")
def statistics(session: SessionDep, _: Viewer, run_id: int | None = Query(None, ge=1)) -> dict[str, Any]:
    a = _analysis(session, run_id)
    cells = session.scalars(select(CallCellStatistics).where(CallCellStatistics.analysis_id == a.id)
                            .order_by(CallCellStatistics.cell_id)).all()
    return {
        "run_id": a.run_id, "library_version": a.library_version, "total_calls": a.total_calls,
        "successful_calls": a.successful_calls, "failed_setup_calls": a.failed_setup_calls,
        "dropped_calls": a.dropped_calls, "success_rate": a.success_rate, "drop_rate": a.drop_rate,
        "setup_failure_rate": a.setup_failure_rate, "average_duration": a.average_duration,
        "average_signal": a.average_signal, "average_packet_loss": a.average_packet_loss,
        "first_timestamp": iso(a.first_epoch), "last_timestamp": iso(a.last_epoch),
        "cells": [{"cell_id": c.cell_id, "total_calls": c.total_calls,
                   "successful_calls": c.successful_calls, "failed_setup_calls": c.failed_setup_calls,
                   "dropped_calls": c.dropped_calls, "drop_rate": c.drop_rate,
                   "setup_failure_rate": c.setup_failure_rate, "average_signal": c.average_signal,
                   "average_packet_loss": c.average_packet_loss} for c in cells],
        "failure_codes": a.failure_codes, "time_windows": a.time_windows,
        "suspicious_time_windows": a.suspicious_time_windows, "parse_report": a.parse_report,
    }


@router.get("/anomalies")
def anomalies(session: SessionDep, _: Viewer, run_id: int | None = Query(None, ge=1)) -> list[dict[str, Any]]:
    a = _analysis(session, run_id)
    rows = session.scalars(select(CallAnomalyRecord).where(CallAnomalyRecord.analysis_id == a.id)
                           .order_by(CallAnomalyRecord.anomaly_score.desc(), CallAnomalyRecord.id)).all()
    return [{"type": r.type, "category": r.category, "severity": r.severity, "subject": r.subject,
             "window_start": iso(r.window_start_epoch), "window_end": iso(r.window_end_epoch),
             "value": r.value, "baseline": r.baseline, "z_score": r.z_score,
             "anomaly_score": r.anomaly_score, "sample_size": r.sample_size,
             "description": r.description} for r in rows]
