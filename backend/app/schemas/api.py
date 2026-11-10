"""Request bodies and response envelopes for the REST API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ApiModel, RequestModel


class PipelineRunRequest(RequestModel):
    scenario: Literal["seeded", "healthy"] = "seeded"
    seed: int = Field(default=7, ge=0, le=2**31 - 1)
    minutes: int = Field(default=360, ge=60, le=1440)
    rollback_minute: int | None = Field(default=None, ge=1, le=1439)


class PipelineRunSummary(ApiModel):
    id: int
    scenario: str
    seed: int
    status: str
    started_epoch: int
    finished_epoch: int | None
    data_start_epoch: int
    data_end_epoch: int
    fingerprint: str
    params: dict[str, Any]
    incident_ids: list[str] = []


class HealthResponse(ApiModel):
    status: Literal["ok", "degraded"]
    version: str
    database: str
    call_analyzer: str
    llm_provider: str


class Page(ApiModel):
    total: int
    limit: int
    offset: int
    items: list[Any]


class ChainVerificationResponse(ApiModel):
    valid: bool
    rows: int
    first_invalid_id: int | None
    reason: str | None
