"""Pydantic schemas for the spec §15 entities (API layer)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, computed_field

from app.schemas.common import ApiModel, iso

Severity = Literal["low", "medium", "high", "critical"]
IncidentSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RiskClass = Literal["READ_ONLY", "LOW_RISK", "REQUIRES_APPROVAL", "HIGH_RISK", "BLOCKED"]


class CallRecord(ApiModel):
    """One CDR in the libcallanalyzer schema (validated by the C parser on ingest)."""

    timestamp: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    caller: str = Field(min_length=1, max_length=31, pattern=r"^[0-9A-Za-z+*#._-]+$")
    callee: str = Field(min_length=1, max_length=31, pattern=r"^[0-9A-Za-z+*#._-]+$")
    cell_id: str = Field(min_length=1, max_length=31, pattern=r"^[0-9A-Za-z._-]+$")
    duration: int = Field(ge=0, le=86400)
    status_code: int = Field(ge=100, le=999)
    signal_strength: int = Field(ge=-150, le=0)
    packet_loss: int = Field(ge=0, le=100)


class NetworkMetric(ApiModel):
    epoch: int
    cell_id: str
    node_id: str
    metric: str
    value: float

    @computed_field  # type: ignore[prop-decorator]
    @property
    def timestamp(self) -> str | None:
        return iso(self.epoch)


class Anomaly(ApiModel):
    anomaly_id: str
    metric: str
    cell_id: str
    node_id: str
    start_epoch: int
    end_epoch: int
    value: float
    baseline: float
    severity: Severity
    anomaly_score: float
    detectors: list[str]
    related_metrics: list[str]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def timestamp(self) -> str | None:
        return iso(self.start_epoch)


class IncidentEvent(ApiModel):
    epoch: int
    type: str
    description: str
    reference_id: str | None
    actor: str

    @computed_field  # type: ignore[prop-decorator]
    @property
    def timestamp(self) -> str | None:
        return iso(self.epoch)


class IncidentSummary(ApiModel):
    incident_id: str
    severity: IncidentSeverity
    status: Literal["open", "investigating", "mitigated", "resolved"]
    start_epoch: int
    end_epoch: int
    confidence: float
    top_cause_type: str | None
    affected_cells: list[str] = []

    @computed_field  # type: ignore[prop-decorator]
    @property
    def start_time(self) -> str | None:
        return iso(self.start_epoch)


class Incident(IncidentSummary):
    run_id: int
    chain_consistency: float
    resolved_epoch: int | None
    affected_nodes: list[str] = []
    symptoms: list[dict[str, Any]]
    suspected_causes: list[dict[str, Any]]
    excluded_candidates: list[dict[str, Any]]
    call_evidence: list[dict[str, Any]]
    causal_chain: list[dict[str, Any]]
    caveats: list[str]
    anomaly_ids: list[str] = []
    events: list[IncidentEvent] = []


class Recommendation(ApiModel):
    priority: int
    action: str
    rationale: str
    risk_class: RiskClass
    agent_tool: str | None


class RootCauseAnalysis(ApiModel):
    id: int
    incident_id: str
    created_epoch: int
    status: Literal["completed", "failed"]
    provider: str
    model: str
    root_cause: str
    confidence: float
    impact: str
    steps: int
    facts: list[dict[str, Any]]
    inferences: list[dict[str, Any]]
    hypotheses: list[dict[str, Any]]
    alternative_hypotheses: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    verification_steps: list[str]
    tool_calls: list[dict[str, Any]]
    recommended_actions: list[Recommendation] = []


class AgentAction(ApiModel):
    action_id: str
    run_id: str
    sequence: int
    phase: str
    tool: str
    risk_class: RiskClass
    status: str
    rationale: str
    created_epoch: int
    approved_by: str | None
    approved_epoch: int | None
    executed_by: str | None
    executed_epoch: int | None
    arguments: dict[str, Any]
    result: dict[str, Any]


class SecurityFinding(ApiModel):
    finding_id: str
    source: str
    category: str
    severity: str
    title: str
    resource: str
    status: str
    created_epoch: int
    updated_epoch: int
    details: dict[str, Any]


class Deployment(ApiModel):
    deployment_id: str
    run_id: int
    service: str
    node_id: str
    from_version: str
    to_version: str
    deployed_epoch: int
    change_summary: str
    status: str
    rolled_back_epoch: int | None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def deployed_at(self) -> str | None:
        return iso(self.deployed_epoch)


class AuditLog(ApiModel):
    id: int
    epoch: int
    actor: str
    role: str
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    request_id: str | None
    details: dict[str, Any]
    prev_hash: str
    hash: str
    note: str | None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def timestamp(self) -> str | None:
        return iso(self.epoch)
