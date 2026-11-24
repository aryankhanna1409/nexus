"""Structured report document (spec §9): the single source for JSON, Markdown and HTML."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class KpiChange(_Model):
    metric: str
    unit: str
    baseline: float          # mean over the hour before onset, affected cells
    incident_mean: float     # mean during the incident window, affected cells
    worst: float             # most extreme value in the bad direction
    change_pct: float | None
    direction: str           # "up" | "down": which way is bad


class AnomalyEntry(_Model):
    metric: str
    cells: list[str]
    onset: str
    worst_value: float
    baseline: float
    severity: str


class ImpactSection(_Model):
    affected_cells: list[str]
    affected_nodes: list[str]
    duration_minutes: int
    estimated_affected_users: int
    calls_in_affected_cells: int | None
    dropped_calls_in_affected_cells: int | None
    failed_setups_in_affected_cells: int | None
    summary: str


class RootCauseSection(_Model):
    source: str                      # "rca" | "correlation" | "none"
    statement: str
    cause_type: str | None
    confidence: float | None
    status_label: str                # always describes this as a hypothesis/assessment
    facts: list[dict[str, Any]]
    inferences: list[dict[str, Any]]
    alternative_hypotheses: list[dict[str, Any]]


class ReportDocument(_Model):
    report_id: str
    incident_id: str
    title: str
    generated_at: str
    generated_by: str
    severity: str
    status: str
    window: str
    data_notice: str
    executive_summary: str
    narrative_provider: str
    kpi_analysis: list[KpiChange]
    anomaly_analysis: list[AnomalyEntry]
    correlation_analysis: dict[str, Any]
    root_cause: RootCauseSection
    impact: ImpactSection
    recommendations: list[dict[str, Any]]
    verification_steps: list[str]
    confidence: dict[str, Any]
    evidence_references: dict[str, list[str]]
    timeline: list[dict[str, Any]]
