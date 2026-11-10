"""Incident injectors (spec §5): each perturbs *drivers* of the causal model.

Injectors never write output KPIs directly. They change exogenous drivers
(offered load, extra CPU or memory demand, interface loss, radio penalty,
configuration penalties) so that effects propagate through the causal model in
`model.py`, e.g. memory leak -> GC pressure -> CPU -> queueing latency -> loss
-> call drops.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

import numpy as np

from app.simulation.events import DeploymentRecord, EventKind, EventSeverity, SimEvent
from app.simulation.topology import Topology


class IncidentType(StrEnum):
    OVERLOADED_BASE_STATION = "overloaded_base_station"
    FAILING_NETWORK_INTERFACE = "failing_network_interface"
    PACKET_LOSS_BURST = "packet_loss_burst"
    ABNORMAL_TRAFFIC_SPIKE = "abnormal_traffic_spike"
    DEGRADED_RADIO_SIGNAL = "degraded_radio_signal"
    SOFTWARE_DEPLOYMENT_REGRESSION = "software_deployment_regression"
    MEMORY_LEAK = "memory_leak"
    SECURITY_ATTACK = "security_attack"
    MISCONFIGURATION = "misconfiguration"


# Incidents whose effects target a packet-gateway node (all of its cells).
NODE_SCOPED = {IncidentType.SOFTWARE_DEPLOYMENT_REGRESSION, IncidentType.MEMORY_LEAK}
# Incidents introduced by a deployment, and therefore reversible by rollback.
DEPLOYMENT_INDUCED = NODE_SCOPED


@dataclass(frozen=True)
class IncidentSpec:
    """One injected incident. `target` is a cell id, or a node id for NODE_SCOPED types."""

    type: IncidentType
    target: str
    start_minute: int
    duration_minutes: int
    intensity: float = 1.0
    to_version: str = "2.4.1"

    def validate(self, topology: Topology, total_minutes: int) -> None:
        if self.type in NODE_SCOPED:
            topology.cells_of(self.target)  # raises KeyError on unknown node
        elif not topology.has_cell(self.target):
            raise KeyError(f"unknown cell {self.target!r} for {self.type}")
        if self.start_minute < 0 or self.duration_minutes < 1:
            raise ValueError("incident must start at >= 0 and last >= 1 minute")
        if self.start_minute >= total_minutes:
            raise ValueError("incident starts after the simulated period")
        if not 0.1 <= self.intensity <= 3.0:
            raise ValueError("intensity must be in [0.1, 3.0]")


@dataclass
class Drivers:
    """Exogenous inputs to the causal model, one array per cell (length = minutes)."""

    minutes: int
    cells: list[str]
    user_factor: dict[str, np.ndarray] = field(default_factory=dict)
    cpu_add: dict[str, np.ndarray] = field(default_factory=dict)
    mem_add: dict[str, np.ndarray] = field(default_factory=dict)
    iface_loss: dict[str, np.ndarray] = field(default_factory=dict)
    radio_penalty_db: dict[str, np.ndarray] = field(default_factory=dict)
    handover_penalty: dict[str, np.ndarray] = field(default_factory=dict)
    setup_penalty: dict[str, np.ndarray] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("cpu_add", "mem_add", "iface_loss", "radio_penalty_db",
                     "handover_penalty", "setup_penalty"):
            setattr(self, name, {c: np.zeros(self.minutes) for c in self.cells})
        self.user_factor = {c: np.ones(self.minutes) for c in self.cells}


@dataclass
class InjectionResult:
    events: list[SimEvent] = field(default_factory=list)
    deployments: list[DeploymentRecord] = field(default_factory=list)


@dataclass(frozen=True)
class GroundTruth:
    """What was injected (used by tests and the demo, never by detection/RCA)."""

    incident_type: IncidentType
    target: str
    node_id: str
    affected_cells: tuple[str, ...]
    start_epoch: int
    end_epoch: int
    root_cause: str
    rolled_back_epoch: int | None


ROOT_CAUSE_TEXT: dict[IncidentType, str] = {
    IncidentType.OVERLOADED_BASE_STATION: "offered load exceeded the cell's processing capacity",
    IncidentType.FAILING_NETWORK_INTERFACE: "intermittently failing network interface on the cell backhaul",
    IncidentType.PACKET_LOSS_BURST: "transient packet-loss burst on the transport path",
    IncidentType.ABNORMAL_TRAFFIC_SPIKE: "abnormal surge of user traffic",
    IncidentType.DEGRADED_RADIO_SIGNAL: "degraded radio conditions (antenna/interference)",
    IncidentType.SOFTWARE_DEPLOYMENT_REGRESSION: "deployment introduced a CPU regression in the packet-gateway",
    IncidentType.MEMORY_LEAK: "deployment introduced a memory leak in the packet-gateway",
    IncidentType.SECURITY_ATTACK: "volumetric attack (SYN flood) against the cell's gateway",
    IncidentType.MISCONFIGURATION: "erroneous neighbour/handover configuration change",
}


def _ramp(minutes: int, start: int, end: int, ramp: int) -> np.ndarray:
    """0 outside [start, end); rises linearly to 1 over `ramp` minutes."""
    shape = np.zeros(minutes)
    idx = np.arange(minutes)
    active = (idx >= start) & (idx < end)
    shape[active] = np.minimum(1.0, (idx[active] - start + 1) / max(1, ramp))
    return shape


def inject(
    spec: IncidentSpec,
    drivers: Drivers,
    topology: Topology,
    epochs: np.ndarray,
    rng: np.random.Generator,
    rollback_minute: int | None,
) -> tuple[InjectionResult, GroundTruth]:
    """Applies one incident to `drivers` in place and returns its events."""
    n = drivers.minutes
    start = spec.start_minute
    end = min(n, start + spec.duration_minutes)
    k = spec.intensity
    result = InjectionResult()
    node = spec.target if spec.type in NODE_SCOPED else topology.node_of(spec.target)
    cells = topology.cells_of(node) if spec.type in NODE_SCOPED else [spec.target]
    rolled_back_epoch: int | None = None

    def ts(minute: int) -> int:
        return int(epochs[min(max(minute, 0), n - 1)])

    def log(minute: int, severity: EventSeverity, message: str, **attrs: object) -> None:
        result.events.append(SimEvent(ts(minute), EventKind.APPLICATION_LOG, topology.service,
                                      severity, message, node_id=node,
                                      cell_id=None if spec.type in NODE_SCOPED else spec.target,
                                      attributes=dict(attrs)))

    t = spec.type
    if t in DEPLOYMENT_INDUCED:
        from_version = topology.node_versions.get(node, "2.4.0")
        effect_end = end
        if rollback_minute is not None and start < rollback_minute < end:
            effect_end = rollback_minute
            rolled_back_epoch = ts(rollback_minute)
        summary = ("refactor session buffer pooling in packet-processing path"
                   if t is IncidentType.MEMORY_LEAK else "enable per-flow deep packet inspection")
        deployment = DeploymentRecord(
            deployment_id=f"DEP-{node}-{spec.to_version}-{ts(start)}",
            epoch=ts(start), service=topology.service, node_id=node,
            from_version=from_version, to_version=spec.to_version,
            change_summary=summary, rolled_back_epoch=rolled_back_epoch)
        result.deployments.append(deployment)
        result.events.append(SimEvent(ts(start), EventKind.DEPLOYMENT, "ci-cd", EventSeverity.INFO,
                                      f"Deployed {topology.service} {spec.to_version} to {node}",
                                      node_id=node, attributes={"deployment_id": deployment.deployment_id,
                                                                "from_version": from_version,
                                                                "to_version": spec.to_version}))
        if rolled_back_epoch is not None:
            result.events.append(SimEvent(rolled_back_epoch, EventKind.ROLLBACK, "ci-cd",
                                          EventSeverity.WARNING,
                                          f"Rolled back {topology.service} on {node} to {from_version}",
                                          node_id=node, attributes={"deployment_id": deployment.deployment_id,
                                                                    "to_version": from_version}))
        idx = np.arange(n)
        if t is IncidentType.MEMORY_LEAK:
            # Leak grows ~0.8 pp/min after a 1-minute warm-up, capped at +41 pp
            # (heap ~97 %, where GC pressure holds the CPU around 94 %).
            leak = np.clip((idx - start - 1) * 0.8 * k, 0.0, 41.0 * min(k, 1.0))
            leak[idx < start] = 0.0
            if effect_end < n:
                # Restart on rollback frees memory over ~3 minutes.
                peak = leak[effect_end - 1] if effect_end > 0 else 0.0
                decay = np.maximum(0.0, 1.0 - (idx - effect_end + 1) / 3.0)
                leak[idx >= effect_end] = peak * decay[idx >= effect_end]
            for c in cells:
                drivers.mem_add[c] += leak
            for minute in range(start, effect_end):
                if leak[minute] >= 30 and (minute - start) % 6 == 0:
                    log(minute, EventSeverity.WARNING,
                        f"GC pause {int(120 + 8 * leak[minute])} ms in packet-processing worker",
                        heap_pct=round(55 + leak[minute], 1))
                if leak[minute] >= 40 and (minute - start) % 6 == 3:
                    log(minute, EventSeverity.ERROR, "Worker queue backlog: dropping packets",
                        heap_pct=round(55 + leak[minute], 1))
        else:
            shape = _ramp(n, start, effect_end, 2)
            for c in cells:
                drivers.cpu_add[c] += 38.0 * k * shape
            for minute in range(start + 2, effect_end, 10):
                log(minute, EventSeverity.WARNING, "Per-flow inspection latency above SLO",
                    p99_ms=int(40 + 30 * k))
    elif t is IncidentType.OVERLOADED_BASE_STATION:
        drivers.user_factor[spec.target] *= 1.0 + 1.3 * k * _ramp(n, start, end, 15)
        for minute in range(start + 10, end, 15):
            log(minute, EventSeverity.WARNING, "Admission control engaged", cell=spec.target)
    elif t is IncidentType.FAILING_NETWORK_INTERFACE:
        flaps = (rng.random(n) < 0.45) & (_ramp(n, start, end, 1) > 0)
        drivers.iface_loss[spec.target] += flaps * rng.uniform(5.0, 14.0, n) * k
        for minute in np.flatnonzero(flaps)[::4]:
            log(int(minute), EventSeverity.ERROR, "Link flap detected on backhaul interface eth1",
                interface="eth1")
    elif t is IncidentType.PACKET_LOSS_BURST:
        drivers.iface_loss[spec.target] += 11.0 * k * _ramp(n, start, end, 1)
    elif t is IncidentType.ABNORMAL_TRAFFIC_SPIKE:
        # +80 % offered load: well above normal, but below the CPU saturation of an overload.
        drivers.user_factor[spec.target] *= 1.0 + 0.8 * k * _ramp(n, start, end, 3)
    elif t is IncidentType.DEGRADED_RADIO_SIGNAL:
        drivers.radio_penalty_db[spec.target] += 14.0 * k * _ramp(n, start, end, 10)
    elif t is IncidentType.SECURITY_ATTACK:
        shape = _ramp(n, start, end, 2)
        drivers.user_factor[spec.target] *= 1.0 + 0.9 * k * shape
        drivers.cpu_add[spec.target] += 22.0 * k * shape
        for minute in range(start, end):
            count = int(rng.integers(3, 9))
            for _ in range(count):
                attacker = f"203.0.113.{int(rng.integers(1, 255))}"
                kind = str(rng.choice(["syn_flood", "auth_failure", "port_scan"], p=[0.6, 0.25, 0.15]))
                result.events.append(SimEvent(
                    ts(minute) + int(rng.integers(0, 60)), EventKind.SECURITY, "ids",
                    EventSeverity.CRITICAL if kind == "syn_flood" else EventSeverity.WARNING,
                    f"{kind.replace('_', ' ')} from {attacker} targeting {node}",
                    node_id=node, cell_id=spec.target,
                    attributes={"category": str(kind), "source_ip": attacker}))
    elif t is IncidentType.MISCONFIGURATION:
        shape = _ramp(n, start, end, 1)
        drivers.handover_penalty[spec.target] += 7.0 * k * shape
        drivers.setup_penalty[spec.target] += 2.5 * k * shape
        result.events.append(SimEvent(ts(start), EventKind.CONFIG_CHANGE, "config-manager",
                                      EventSeverity.INFO,
                                      f"Neighbour relation table updated on {spec.target}",
                                      node_id=node, cell_id=spec.target,
                                      attributes={"change_id": f"CHG-{ts(start)}"}))

    truth_end = rolled_back_epoch if rolled_back_epoch is not None else ts(end - 1) + 60
    truth = GroundTruth(t, spec.target, node, tuple(cells), ts(start), truth_end,
                        ROOT_CAUSE_TEXT[t], rolled_back_epoch)
    return result, truth
