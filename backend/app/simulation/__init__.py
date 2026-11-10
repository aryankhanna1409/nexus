"""Deterministic network telemetry simulator with seeded incidents (M3)."""

from app.simulation.incidents import GroundTruth, IncidentSpec, IncidentType
from app.simulation.metrics import METRIC_NAMES, METRICS, Direction, MetricSpec
from app.simulation.scenario import (
    Scenario,
    SimulationResult,
    seeded_memory_leak_scenario,
    simulate,
)
from app.simulation.topology import Topology, default_topology

__all__ = [
    "METRICS", "METRIC_NAMES", "Direction", "GroundTruth", "IncidentSpec", "IncidentType",
    "MetricSpec", "Scenario", "SimulationResult", "Topology", "default_topology",
    "seeded_memory_leak_scenario", "simulate",
]
