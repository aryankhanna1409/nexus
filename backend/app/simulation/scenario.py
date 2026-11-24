"""Scenario definition and deterministic simulation driver."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

import numpy as np

from app.simulation.events import DeploymentRecord, EventKind, EventSeverity, SimEvent
from app.simulation.incidents import (
    DEPLOYMENT_INDUCED,
    Drivers,
    GroundTruth,
    IncidentSpec,
    IncidentType,
    inject,
)
from app.simulation.metrics import METRIC_NAMES
from app.simulation.model import CellProfile, draw_profile, simulate_cell
from app.simulation.topology import Topology, default_topology

STEP_SECONDS = 60
SEEDED_SCENARIO_NAME = "memory_leak_deployment"


@dataclass(frozen=True)
class Scenario:
    name: str
    seed: int
    start: datetime = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    minutes: int = 360
    topology: Topology = field(default_factory=default_topology)
    incidents: tuple[IncidentSpec, ...] = ()
    rollback_minute: int | None = None
    background_events: bool = True

    def validate(self) -> None:
        if self.start.tzinfo is None:
            raise ValueError("scenario start must be timezone-aware")
        if not 10 <= self.minutes <= 7 * 24 * 60:
            raise ValueError("minutes must be in [10, 10080]")
        for spec in self.incidents:
            spec.validate(self.topology, self.minutes)
        if self.rollback_minute is not None:
            if not 0 < self.rollback_minute < self.minutes:
                raise ValueError("rollback_minute must fall inside the simulated period")
            if not any(s.type in DEPLOYMENT_INDUCED for s in self.incidents):
                raise ValueError("rollback requires a deployment-induced incident")


@dataclass
class SimulationResult:
    scenario: Scenario
    epochs: np.ndarray
    metrics: dict[str, dict[str, np.ndarray]]  # cell -> metric -> values
    events: list[SimEvent]
    deployments: list[DeploymentRecord]
    ground_truth: list[GroundTruth]
    profiles: dict[str, CellProfile]

    def series(self, cell_id: str, metric: str) -> np.ndarray:
        return self.metrics[cell_id][metric]

    def fingerprint(self) -> str:
        """SHA-256 over all metric values and events (for determinism checks)."""
        digest = hashlib.sha256()
        digest.update(self.epochs.tobytes())
        for cell in sorted(self.metrics):
            for metric in METRIC_NAMES:
                digest.update(f"{cell}/{metric}".encode())
                digest.update(np.ascontiguousarray(self.metrics[cell][metric]).tobytes())
        for event in self.events:
            digest.update(repr(event.to_dict()).encode())
        return digest.hexdigest()


def seeded_memory_leak_scenario(seed: int = 7, rollback_minute: int | None = None) -> Scenario:
    """Spec §24: deployment at 14:05 on pgw-1 introduces a memory leak."""
    return Scenario(
        name=SEEDED_SCENARIO_NAME,
        seed=seed,
        incidents=(IncidentSpec(IncidentType.MEMORY_LEAK, "pgw-1", start_minute=125,
                                duration_minutes=235),),
        rollback_minute=rollback_minute,
    )


def _background_events(
    scenario: Scenario, epochs: np.ndarray, rng: np.random.Generator
) -> tuple[list[SimEvent], list[DeploymentRecord]]:
    """Benign activity unrelated to incidents: a routine deployment, logins, info logs."""
    topo = scenario.topology
    events: list[SimEvent] = []
    deployments: list[DeploymentRecord] = []
    n = len(epochs)
    incident_nodes = {s.target if s.type in DEPLOYMENT_INDUCED else topo.node_of(s.target)
                      for s in scenario.incidents}
    quiet_nodes = [node for node in topo.node_ids if node not in incident_nodes] or topo.node_ids
    node = quiet_nodes[-1]
    minute = min(n - 1, 70)
    deployment = DeploymentRecord(
        deployment_id=f"DEP-{node}-2.4.0-hotfix1-{int(epochs[minute])}",
        epoch=int(epochs[minute]), service=topo.service, node_id=node,
        from_version=topo.node_versions.get(node, "2.4.0"), to_version="2.4.0-hotfix1",
        change_summary="log format change (no functional impact)")
    deployments.append(deployment)
    events.append(SimEvent(deployment.epoch, EventKind.DEPLOYMENT, "ci-cd", EventSeverity.INFO,
                           f"Deployed {topo.service} 2.4.0-hotfix1 to {node}", node_id=node,
                           attributes={"deployment_id": deployment.deployment_id,
                                       "from_version": deployment.from_version,
                                       "to_version": deployment.to_version}))
    for minute in range(0, n, 30):
        events.append(SimEvent(int(epochs[minute]), EventKind.APPLICATION_LOG, topo.service,
                               EventSeverity.INFO, "Health check passed",
                               node_id=topo.node_ids[minute // 30 % len(topo.node_ids)]))
    for login_minute in np.flatnonzero(rng.random(n) < 0.03):
        events.append(SimEvent(int(epochs[login_minute]) + int(rng.integers(0, 60)), EventKind.SECURITY,
                               "ids", EventSeverity.INFO, "single failed operator login",
                               attributes={"category": "auth_failure",
                                           "source_ip": f"198.51.100.{int(rng.integers(1, 255))}"}))
    return events, deployments


def simulate(scenario: Scenario) -> SimulationResult:
    """Runs a scenario. Identical scenarios (including seed) give identical results."""
    scenario.validate()
    topo = scenario.topology
    start_epoch = int(scenario.start.timestamp())
    epochs = start_epoch + STEP_SECONDS * np.arange(scenario.minutes, dtype=np.int64)
    root = np.random.SeedSequence(scenario.seed)
    profile_seq, event_seq, incident_seq, *cell_seqs = root.spawn(3 + len(topo.cells))

    profile_rng = np.random.default_rng(profile_seq)
    profiles = {cell: draw_profile(profile_rng) for cell in topo.cell_ids}

    drivers = Drivers(minutes=scenario.minutes, cells=topo.cell_ids)
    events: list[SimEvent] = []
    deployments: list[DeploymentRecord] = []
    truths: list[GroundTruth] = []
    incident_rng = np.random.default_rng(incident_seq)
    for spec in scenario.incidents:
        injected, truth = inject(spec, drivers, topo, epochs, incident_rng, scenario.rollback_minute)
        events += injected.events
        deployments += injected.deployments
        truths.append(truth)
    if scenario.background_events:
        bg_events, bg_deployments = _background_events(scenario, epochs,
                                                       np.random.default_rng(event_seq))
        events += bg_events
        deployments += bg_deployments

    metrics = {
        cell: simulate_cell(cell, profiles[cell], epochs, drivers, np.random.default_rng(seq))
        for cell, seq in zip(topo.cell_ids, cell_seqs, strict=True)
    }
    events.sort(key=lambda e: (e.epoch, e.kind.value, e.message))
    deployments.sort(key=lambda d: d.epoch)
    return SimulationResult(scenario, epochs, metrics, events, deployments, truths, profiles)
