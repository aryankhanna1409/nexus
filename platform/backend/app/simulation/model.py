"""Causal per-cell KPI model.

Causal structure (each arrow is an explicit term below):

    users (diurnal x drivers) -> CPU load, throughput demand
    memory (leak driver)      -> CPU (GC pressure above 75 %)
    CPU                       -> queueing delay -> latency -> jitter
    CPU saturation, interface -> packet loss -> retransmissions, throughput
    radio penalty             -> RSRP/RSSI/RSRQ/SINR -> handover failures, drops
    latency, loss, SINR       -> call setup success, call drops

Every metric also carries AR(1) noise so series are autocorrelated rather than
independent draws.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from app.simulation.incidents import Drivers
from app.simulation.metrics import METRIC_BY_NAME


@dataclass(frozen=True)
class CellProfile:
    """Static per-cell characteristics."""

    base_users: float
    rsrp_base: float
    sinr_base: float
    capacity_mbps: float


def draw_profile(rng: np.random.Generator) -> CellProfile:
    return CellProfile(
        base_users=float(rng.uniform(160, 260)),
        rsrp_base=float(rng.uniform(-94, -88)),
        sinr_base=float(rng.uniform(15, 20)),
        capacity_mbps=1000.0,
    )


def ar1_noise(rng: np.random.Generator, n: int, sigma: float, phi: float = 0.7) -> np.ndarray:
    """Stationary AR(1) noise with marginal standard deviation `sigma`."""
    shocks = rng.normal(0.0, sigma * np.sqrt(1.0 - phi * phi), n)
    out = np.empty(n)
    prev = rng.normal(0.0, sigma)
    for i in range(n):
        prev = phi * prev + shocks[i]
        out[i] = prev
    return out


def diurnal_factor(epochs: np.ndarray) -> np.ndarray:
    """Load cycle peaking around 18:00 UTC and bottoming out around 06:00."""
    hours = (epochs % 86400) / 3600.0
    return 1.0 + 0.25 * np.sin(2.0 * np.pi * (hours - 12.0) / 24.0)


def _clip(name: str, values: np.ndarray) -> np.ndarray:
    spec = METRIC_BY_NAME[name]
    clipped: np.ndarray = np.clip(values, spec.lower, spec.upper)
    return clipped


def simulate_cell(
    cell_id: str,
    profile: CellProfile,
    epochs: np.ndarray,
    drivers: Drivers,
    rng: np.random.Generator,
) -> dict[str, np.ndarray]:
    n = len(epochs)

    users = profile.base_users * diurnal_factor(epochs) * drivers.user_factor[cell_id]
    users = np.maximum(0.0, users * (1.0 + ar1_noise(rng, n, 0.03)))
    load = users / (profile.base_users * 1.25)

    memory = 50.0 + 8.0 * load + drivers.mem_add[cell_id] + ar1_noise(rng, n, 0.8)
    memory = _clip("memory_utilization", memory)
    gc_pressure = 1.8 * np.maximum(0.0, memory - 75.0)
    cpu = 22.0 + 35.0 * load + gc_pressure + drivers.cpu_add[cell_id] + ar1_noise(rng, n, 1.5)
    cpu = np.clip(cpu, 1.0, 99.5)

    utilisation = cpu / 100.0
    queueing_ms = np.minimum(400.0, 4.0 * utilisation / (1.0 - utilisation))
    radio_penalty = drivers.radio_penalty_db[cell_id]
    latency = 18.0 + queueing_ms + 0.8 * radio_penalty + ar1_noise(rng, n, 1.0)
    latency = _clip("latency_ms", latency)

    overflow_loss = 9.0 / (1.0 + np.exp(-(cpu - 93.0) / 1.5))
    packet_loss = (0.25 + overflow_loss + drivers.iface_loss[cell_id] + 0.12 * radio_penalty
                   + np.abs(ar1_noise(rng, n, 0.08)))
    packet_loss = _clip("packet_loss_pct", packet_loss)

    jitter = 2.0 + 0.25 * queueing_ms + 0.3 * packet_loss + np.abs(ar1_noise(rng, n, 0.4))
    retransmission = 0.5 + 1.6 * packet_loss + np.abs(ar1_noise(rng, n, 0.1))

    offered = users * 1.6
    # TCP-like goodput penalty for latency, bounded so throughput never collapses to 0.
    latency_penalty = np.clip(1.0 - 0.004 * np.maximum(0.0, latency - 50.0), 0.4, 1.0)
    # TCP goodput degrades super-linearly with loss (Mathis et al.); 1/(1 + 0.08 * loss %)
    # keeps ~98 % at background loss and ~58 % at 9 % loss.
    loss_penalty = 1.0 / (1.0 + 0.08 * packet_loss)
    throughput = np.minimum(offered, profile.capacity_mbps) * loss_penalty * latency_penalty
    throughput = _clip("throughput_mbps", throughput * (1.0 + ar1_noise(rng, n, 0.01)))
    bandwidth = _clip("bandwidth_utilization", 100.0 * throughput / profile.capacity_mbps)

    rsrp = profile.rsrp_base - radio_penalty + ar1_noise(rng, n, 1.2)
    rssi = rsrp + 25.0 + ar1_noise(rng, n, 0.8)
    rsrq = -9.5 - 0.35 * radio_penalty + ar1_noise(rng, n, 0.4)
    sinr = profile.sinr_base - 0.9 * radio_penalty - 1.5 * np.maximum(0.0, load - 1.2) \
        + ar1_noise(rng, n, 0.8)

    handover_success = (99.2 - 1.5 * np.maximum(0.0, 10.0 - sinr)
                        - drivers.handover_penalty[cell_id] + ar1_noise(rng, n, 0.15))
    handover_success = _clip("handover_success_rate", handover_success)

    setup_success = (99.4 - 0.08 * np.maximum(0.0, latency - 60.0) - 0.3 * packet_loss
                     - drivers.setup_penalty[cell_id] - 0.5 * np.maximum(0.0, 5.0 - sinr)
                     + ar1_noise(rng, n, 0.1))
    drop_rate = (0.6 + 0.35 * packet_loss + 0.6 * np.maximum(0.0, 8.0 - sinr)
                 + 0.03 * np.maximum(0.0, latency - 80.0) + 0.1 * drivers.handover_penalty[cell_id]
                 + np.abs(ar1_noise(rng, n, 0.08)))

    return {
        "throughput_mbps": throughput,
        "latency_ms": latency,
        "packet_loss_pct": packet_loss,
        "jitter_ms": _clip("jitter_ms", jitter),
        "rssi_dbm": _clip("rssi_dbm", rssi),
        "rsrp_dbm": _clip("rsrp_dbm", rsrp),
        "rsrq_db": _clip("rsrq_db", rsrq),
        "sinr_db": _clip("sinr_db", sinr),
        "handover_success_rate": handover_success,
        "handover_failure_rate": 100.0 - handover_success,
        "call_setup_success_rate": _clip("call_setup_success_rate", setup_success),
        "call_drop_rate": _clip("call_drop_rate", drop_rate),
        "retransmission_rate": _clip("retransmission_rate", retransmission),
        "cpu_utilization": cpu,
        "memory_utilization": memory,
        "active_users": users,
        "bandwidth_utilization": bandwidth,
    }
