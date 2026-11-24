"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI, Response

from app.api import admin, agent, calls, health, incidents, network, pipeline, rca, reports
from app.config import Settings
from app.db import make_engine, make_session_factory
from app.llm.factory import build_provider
from app.observability.logging import configure_logging, get_logger
from app.observability.metrics import Metrics
from app.security.middleware import (
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.security.ratelimit import MemoryRateLimiter, RateLimiter, RedisRateLimiter

API_TITLE = "Aegis-Net API"


def _limiter(settings: Settings) -> RateLimiter:
    if settings.redis_url:
        return RedisRateLimiter.from_url(settings.redis_url)
    return MemoryRateLimiter()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    configure_logging(settings.log_level)
    log = get_logger("app")
    app = FastAPI(title=API_TITLE, version=health.VERSION,
                  description="Network intelligence and autonomous DevSecOps platform (synthetic data).")
    engine = make_engine(settings.database_url)
    metrics = Metrics()
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine)
    app.state.llm = build_provider(settings)
    app.state.metrics = metrics
    if app.state.llm.fallback_reason:
        log.warning("llm provider fallback", extra={"reason": app.state.llm.fallback_reason})

    # Unhandled exceptions become generic 500 JSON responses in RequestContextMiddleware.

    @app.get("/metrics", include_in_schema=False)
    def prometheus() -> Response:
        return Response(metrics.render(), media_type="text/plain; version=0.0.4")

    for module in (health, pipeline, calls, network, incidents, rca, reports, agent, admin):
        app.include_router(module.router)

    # Added innermost-first: the last one added is the outermost.
    app.add_middleware(RateLimitMiddleware, limiter=_limiter(settings), per_minute=settings.rate_limit_per_minute,
                       metrics=metrics)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware, metrics=metrics)
    return app
