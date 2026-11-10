"""Catalogue of simulated network KPIs (spec §5) and their healthy behaviour."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Direction(StrEnum):
    """Which deviation is operationally bad."""

    UP = "up"
    DOWN = "down"
    BOTH = "both"


@dataclass(frozen=True)
class MetricSpec:
    name: str
    unit: str
    bad_direction: Direction
    lower: float  # physical bounds used for clipping
    upper: float
    description: str


METRICS: tuple[MetricSpec, ...] = (
    MetricSpec("throughput_mbps", "Mbit/s", Direction.DOWN, 0, 10_000, "Delivered user-plane throughput"),
    MetricSpec("latency_ms", "ms", Direction.UP, 0, 10_000, "Round-trip user-plane latency"),
    MetricSpec("packet_loss_pct", "%", Direction.UP, 0, 100, "User-plane packet loss"),
    MetricSpec("jitter_ms", "ms", Direction.UP, 0, 5_000, "Packet delay variation"),
    MetricSpec("rssi_dbm", "dBm", Direction.DOWN, -130, -20, "Received signal strength indicator"),
    MetricSpec("rsrp_dbm", "dBm", Direction.DOWN, -150, -40, "Reference signal received power"),
    MetricSpec("rsrq_db", "dB", Direction.DOWN, -30, -3, "Reference signal received quality"),
    MetricSpec("sinr_db", "dB", Direction.DOWN, -20, 40, "Signal to interference plus noise ratio"),
    MetricSpec("handover_success_rate", "%", Direction.DOWN, 0, 100, "Successful handovers"),
    MetricSpec("handover_failure_rate", "%", Direction.UP, 0, 100, "Failed handovers"),
    MetricSpec("call_setup_success_rate", "%", Direction.DOWN, 0, 100, "Call setup success"),
    MetricSpec("call_drop_rate", "%", Direction.UP, 0, 100, "Established calls dropped"),
    MetricSpec("retransmission_rate", "%", Direction.UP, 0, 100, "Link-layer retransmissions"),
    MetricSpec("cpu_utilization", "%", Direction.UP, 0, 100, "Serving packet-gateway CPU"),
    MetricSpec("memory_utilization", "%", Direction.UP, 0, 100, "Serving packet-gateway memory"),
    MetricSpec("active_users", "users", Direction.BOTH, 0, 100_000, "Connected users"),
    MetricSpec("bandwidth_utilization", "%", Direction.UP, 0, 100, "Backhaul utilisation"),
)

METRIC_NAMES: tuple[str, ...] = tuple(m.name for m in METRICS)
METRIC_BY_NAME: dict[str, MetricSpec] = {m.name: m for m in METRICS}
