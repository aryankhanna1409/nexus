"""Discrete operational events emitted alongside the telemetry."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class EventKind(StrEnum):
    DEPLOYMENT = "deployment"
    ROLLBACK = "rollback"
    CONFIG_CHANGE = "config_change"
    SECURITY = "security"
    APPLICATION_LOG = "application_log"


class EventSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SimEvent:
    """One event. `node_id`/`cell_id` locate it in the topology when known."""

    epoch: int
    kind: EventKind
    source: str
    severity: EventSeverity
    message: str
    node_id: str | None = None
    cell_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class DeploymentRecord:
    """A (simulated) software deployment of the packet-gateway service on one node."""

    deployment_id: str
    epoch: int
    service: str
    node_id: str
    from_version: str
    to_version: str
    change_summary: str
    rolled_back_epoch: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
