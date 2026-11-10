"""Declarative base and portable column types.

Timestamps are stored as UTC epoch seconds (BigInteger) so SQLite (offline demo,
tests) and PostgreSQL behave identically. JSON columns become JSONB on
PostgreSQL and are reserved for evidence, tool outputs and similar documents.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, MetaData
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase

JSONType = JSON().with_variant(JSONB(), "postgresql")

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)
    type_annotation_map: dict[Any, Any] = {dict[str, Any]: JSONType, list[Any]: JSONType}
