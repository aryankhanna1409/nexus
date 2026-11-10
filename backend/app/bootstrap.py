"""Loads the seeded demo incident into an empty database (AEGIS_BOOTSTRAP_DEMO=true)."""

from __future__ import annotations

from sqlalchemy import func, select

from app.config import Settings
from app.db import make_engine, make_session_factory
from app.models import PipelineRun
from app.observability.logging import configure_logging, get_logger
from app.services.pipeline import PipelineParams, run_pipeline


def main() -> int:
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    log = get_logger("bootstrap")
    engine = make_engine(settings.database_url)
    with make_session_factory(engine)() as session:
        if session.scalar(select(func.count()).select_from(PipelineRun)):
            log.info("database already populated; bootstrap skipped")
            return 0
        outcome = run_pipeline(session, PipelineParams("seeded", 7), settings.data_dir)
        log.info("bootstrap pipeline completed", extra={"run_id": outcome.run.id,
                                                        "incidents": outcome.incident_ids})
    engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
