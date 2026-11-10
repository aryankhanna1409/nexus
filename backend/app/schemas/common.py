"""Shared schema helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict


def iso(epoch: int | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ApiModel(BaseModel):
    """Response models: built from ORM objects or dicts."""

    model_config = ConfigDict(from_attributes=True)


class RequestModel(BaseModel):
    """Request bodies: unknown fields are rejected, strings are stripped."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
