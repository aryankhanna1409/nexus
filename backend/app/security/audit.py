"""Hash-chained audit log: each row's hash covers its content and the previous hash."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import AuditLogRecord
from app.observability.context import request_id_var

GENESIS_HASH = "0" * 64


def _digest(prev_hash: str, fields: dict[str, Any]) -> str:
    canonical = json.dumps({"prev": prev_hash, **fields}, sort_keys=True, separators=(",", ":"),
                           default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _content(row: AuditLogRecord) -> dict[str, Any]:
    return {"epoch": row.epoch, "actor": row.actor, "role": row.role, "action": row.action,
            "resource_type": row.resource_type, "resource_id": row.resource_id,
            "outcome": row.outcome, "request_id": row.request_id, "details": row.details,
            "note": row.note}


def record_audit(
    session: Session, *, actor: str, role: str, action: str, resource_type: str,
    resource_id: str | None = None, outcome: str = "success", details: dict[str, Any] | None = None,
    note: str | None = None, commit: bool = True,
) -> AuditLogRecord:
    """Appends one audit row. On PostgreSQL an advisory lock serialises chain appends."""
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(7340177)"))
    prev = session.scalar(select(AuditLogRecord.hash).order_by(AuditLogRecord.id.desc()).limit(1))
    row = AuditLogRecord(epoch=int(time.time()), actor=actor, role=role, action=action,
                         resource_type=resource_type, resource_id=resource_id, outcome=outcome,
                         request_id=request_id_var.get(), details=details or {}, note=note,
                         prev_hash=prev or GENESIS_HASH, hash="")
    row.hash = _digest(row.prev_hash, _content(row))
    session.add(row)
    if commit:
        session.commit()
    else:
        session.flush()
    return row


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    rows: int
    first_invalid_id: int | None
    reason: str | None


def verify_chain(session: Session) -> ChainVerification:
    prev = GENESIS_HASH
    count = 0
    for row in session.scalars(select(AuditLogRecord).order_by(AuditLogRecord.id)):
        count += 1
        if row.prev_hash != prev:
            return ChainVerification(False, count, row.id, "prev_hash does not match previous row")
        if _digest(row.prev_hash, _content(row)) != row.hash:
            return ChainVerification(False, count, row.id, "row content does not match its hash")
        prev = row.hash
    return ChainVerification(True, count, None, None)
