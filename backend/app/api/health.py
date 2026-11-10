"""GET /api/health — unauthenticated liveness/readiness without sensitive details."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.api.deps import SessionDep, SettingsDep
from app.schemas.api import HealthResponse

router = APIRouter(tags=["health"])
VERSION = "0.1.0"


@router.get("/api/health", response_model=HealthResponse)
def health(session: SessionDep, settings: SettingsDep) -> HealthResponse:
    try:
        session.execute(text("SELECT 1"))
        database = "ok"
    except Exception:  # noqa: BLE001 - report, never raise, from the health probe
        database = "unavailable"
    try:
        import call_analyzer

        call_analyzer.library_version()
        library = "ok"
    except Exception:  # noqa: BLE001
        library = "unavailable"
    healthy = database == "ok" and library == "ok"
    return HealthResponse(status="ok" if healthy else "degraded", version=VERSION, database=database,
                          call_analyzer=library, llm_provider=settings.llm_provider)
