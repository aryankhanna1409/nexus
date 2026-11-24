"""Query helpers shared by routers."""

from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import PipelineRun

MAX_PAGE = 1000


def resolve_run(session: Session, run_id: int | None) -> PipelineRun:
    """The requested run, or the most recent completed run."""
    if run_id is not None:
        run = session.get(PipelineRun, run_id)
    else:
        run = session.scalars(select(PipelineRun).where(PipelineRun.status == "completed")
                              .order_by(PipelineRun.id.desc()).limit(1)).first()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "no pipeline run found; POST /api/pipeline/run first")
    return run
