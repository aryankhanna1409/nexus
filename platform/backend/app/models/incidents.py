"""Incidents, their timeline, root-cause analyses, recommendations and reports."""

from __future__ import annotations

from typing import Any

from sqlalchemy import BigInteger, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class IncidentRecord(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id", ondelete="CASCADE"), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))  # open | investigating | mitigated | resolved
    start_epoch: Mapped[int] = mapped_column(BigInteger, index=True)
    end_epoch: Mapped[int] = mapped_column(BigInteger)
    confidence: Mapped[float] = mapped_column(Float)
    chain_consistency: Mapped[float] = mapped_column(Float)
    top_cause_type: Mapped[str | None] = mapped_column(String(48))
    resolved_epoch: Mapped[int | None] = mapped_column(BigInteger)
    symptoms: Mapped[list[Any]]
    suspected_causes: Mapped[list[Any]]
    excluded_candidates: Mapped[list[Any]]
    call_evidence: Mapped[list[Any]]
    causal_chain: Mapped[list[Any]]
    caveats: Mapped[list[Any]]


class IncidentCell(Base):
    __tablename__ = "incident_cells"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="CASCADE"),
                                             primary_key=True)
    cell_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    node_id: Mapped[str] = mapped_column(String(32))


class IncidentAnomaly(Base):
    __tablename__ = "incident_anomalies"
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="CASCADE"),
                                             primary_key=True)
    anomaly_id: Mapped[str] = mapped_column(ForeignKey("anomalies.anomaly_id", ondelete="CASCADE"),
                                            primary_key=True)


class IncidentEventRecord(Base):
    __tablename__ = "incident_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="CASCADE"),
                                             index=True)
    epoch: Mapped[int] = mapped_column(BigInteger)
    type: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text)
    reference_id: Mapped[str | None] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64))  # correlation-engine | rca-engine | agent | user:<name>


class RootCauseAnalysisRecord(Base):
    __tablename__ = "root_cause_analyses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="CASCADE"),
                                             index=True)
    created_epoch: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[str] = mapped_column(String(16))  # completed | failed
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(64))
    root_cause: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    impact: Mapped[str] = mapped_column(Text)
    steps: Mapped[int] = mapped_column(Integer)
    facts: Mapped[list[Any]]
    inferences: Mapped[list[Any]]
    hypotheses: Mapped[list[Any]]
    alternative_hypotheses: Mapped[list[Any]]
    evidence: Mapped[list[Any]]
    verification_steps: Mapped[list[Any]]
    tool_calls: Mapped[list[Any]]


class RecommendationRecord(Base):
    __tablename__ = "recommendations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rca_id: Mapped[int] = mapped_column(ForeignKey("root_cause_analyses.id", ondelete="CASCADE"), index=True)
    incident_id: Mapped[str] = mapped_column(String(32), index=True)
    priority: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(Text)
    rationale: Mapped[str] = mapped_column(Text)
    risk_class: Mapped[str] = mapped_column(String(24))
    agent_tool: Mapped[str | None] = mapped_column(String(48))


class ReportRecord(Base):
    __tablename__ = "reports"
    report_id: Mapped[str] = mapped_column(String(48), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id", ondelete="CASCADE"),
                                             index=True)
    rca_id: Mapped[int | None] = mapped_column(ForeignKey("root_cause_analyses.id", ondelete="SET NULL"))
    created_epoch: Mapped[int] = mapped_column(BigInteger)
    created_by: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]]
    markdown: Mapped[str] = mapped_column(Text)
    html: Mapped[str] = mapped_column(Text)
