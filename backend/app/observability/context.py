"""Context variables carried through a request (and into logs and audit rows)."""

from __future__ import annotations

from contextvars import ContextVar

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
incident_id_var: ContextVar[str | None] = ContextVar("incident_id", default=None)
agent_run_id_var: ContextVar[str | None] = ContextVar("agent_run_id", default=None)
