"""Pipeline runs: simulate -> analyse -> detect -> correlate -> persist."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.api.deps import Operator, SessionDep, SettingsDep, Viewer
from app.models import IncidentRecord, PipelineRun
from app.schemas.api import PipelineRunRequest, PipelineRunSummary
from app.security.audit import record_audit
from app.services.pipeline import PipelineParams, run_pipeline

router = APIRouter(prefix="/api/pipeline", tags=["pipeline"])


@router.post("/run", response_model=PipelineRunSummary, status_code=status.HTTP_201_CREATED)
def start_run(body: PipelineRunRequest, session: SessionDep, settings: SettingsDep,
              principal: Operator) -> PipelineRunSummary:
    params = PipelineParams(body.scenario, body.seed, body.minutes, body.rollback_minute)
    try:
        params.build().validate()
    except (ValueError, KeyError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    outcome = run_pipeline(session, params, settings.data_dir)
    record_audit(session, actor=principal.name, role=principal.role.name.lower(),
                 action="pipeline.run", resource_type="pipeline_run", resource_id=str(outcome.run.id),
                 details={"params": body.model_dump(), "incidents": outcome.incident_ids,
                          "anomalies": outcome.anomalies})
    summary = PipelineRunSummary.model_validate(outcome.run)
    summary.incident_ids = outcome.incident_ids
    return summary


@router.get("/runs", response_model=list[PipelineRunSummary])
def list_runs(session: SessionDep, _: Viewer,
              limit: int = Query(50, ge=1, le=500)) -> list[PipelineRunSummary]:
    runs = session.scalars(select(PipelineRun).order_by(PipelineRun.id.desc()).limit(limit)).all()
    out = []
    for run in runs:
        summary = PipelineRunSummary.model_validate(run)
        summary.incident_ids = list(session.scalars(
            select(IncidentRecord.incident_id).where(IncidentRecord.run_id == run.id)
            .order_by(IncidentRecord.incident_id)))
        out.append(summary)
    return out
