"""DevSecOps agent runs, proposed/executed actions, and security findings."""

from __future__ import annotations

from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AgentRun(Base):
    __tablename__ = "agent_runs"
    run_id: Mapped[str] = mapped_column(String(48), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(48))
    state: Mapped[str] = mapped_column(String(16))   # OBSERVE | ANALYZE | PLAN | ACT | VERIFY | CLOSED
    status: Mapped[str] = mapped_column(String(24))  # running | awaiting_approval | completed | failed
    incident_id: Mapped[str | None] = mapped_column(String(32))
    started_epoch: Mapped[int] = mapped_column(BigInteger)
    finished_epoch: Mapped[int | None] = mapped_column(BigInteger)
    started_by: Mapped[str] = mapped_column(String(64))
    workspace: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[dict[str, Any]]


class AgentActionRecord(Base):
    __tablename__ = "agent_actions"
    action_id: Mapped[str] = mapped_column(String(48), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("agent_runs.run_id", ondelete="CASCADE"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    phase: Mapped[str] = mapped_column(String(16))
    tool: Mapped[str] = mapped_column(String(48))
    risk_class: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(24))  # proposed|approved|executing|succeeded|failed|denied|blocked
    rationale: Mapped[str] = mapped_column(Text)
    created_epoch: Mapped[int] = mapped_column(BigInteger)
    approved_by: Mapped[str | None] = mapped_column(String(64))
    approved_epoch: Mapped[int | None] = mapped_column(BigInteger)
    executed_by: Mapped[str | None] = mapped_column(String(64))
    executed_epoch: Mapped[int | None] = mapped_column(BigInteger)
    arguments: Mapped[dict[str, Any]]
    result: Mapped[dict[str, Any]]


class SecurityFindingRecord(Base):
    __tablename__ = "security_findings"
    finding_id: Mapped[str] = mapped_column(String(48), primary_key=True)
    source: Mapped[str] = mapped_column(String(48))  # dependency-scanner | ids | agent
    category: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(Text)
    resource: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))  # open | remediated | accepted
    created_epoch: Mapped[int] = mapped_column(BigInteger)
    updated_epoch: Mapped[int] = mapped_column(BigInteger)
    details: Mapped[dict[str, Any]]
