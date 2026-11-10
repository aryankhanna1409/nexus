"""Synthetic network: 12 cells, 3 packet gateways, 6 hours of per-minute KPIs.

The story baked in (all fake):
  13:10  harmless hotfix deployed to pgw-3        (a decoy)
  14:05  packet-gateway 2.4.1 deployed to pgw-1   (leaks memory)
  -> memory climbs, garbage collection eats CPU, latency and packet loss
     rise, calls start dropping on the four cells behind pgw-1.

Pass rollback_minute to simulate the fix: the leak stops and memory is freed.
Everything is deterministic for a given seed.
"""
from __future__ import annotations

import csv
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

START = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
MINUTES = 360
CELLS = [f"CELL-{101 + i}" for i in range(12)]
NODE_OF = {cell: f"pgw-{i // 4 + 1}" for i, cell in enumerate(CELLS)}

# metric -> (unit, which direction is bad)
METRICS = {
    "memory_pct": ("%", "up"),
    "cpu_pct": ("%", "up"),
    "latency_ms": ("ms", "up"),
    "packet_loss_pct": ("%", "up"),
    "call_drop_pct": ("%", "up"),
    "setup_success_pct": ("%", "down"),
    "throughput_mbps": ("Mbit/s", "down"),
}

BAD_DEPLOY_MINUTE = 125    # 14:05
NOW = 180                  # 15:00, the moment the demo "runs"
DECOY_DEPLOY_MINUTE = 70   # 13:10


def iso(minute: float) -> str:
    return (START + timedelta(minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ")


def minute_of(text: str) -> int:
    """Inverse of iso(): '2026-03-01T14:05:00Z' or '14:05' -> minutes since START."""
    if len(text) == 5:
        text = START.strftime("%Y-%m-%dT") + text + ":00Z"
    t = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return int((t - START).total_seconds() // 60)


@dataclass
class World:
    seed: int
    rollback_minute: int | None
    metrics: dict[str, dict[str, list[float]]]   # cell -> metric -> one value per minute
    deployments: list[dict]
    logs: list[dict]
    security_events: list[dict]
    users: dict[str, list[float]] = field(default_factory=dict)

    def write_call_log(self, path: Path, start: int = 0, end: int = MINUTES) -> int:
        """Write one CSV row per phone call in [start, end) minutes. Returns row count."""
        rng = random.Random(self.seed * 7919 + 1)
        rows = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(["timestamp", "caller", "callee", "cell_id", "duration",
                        "status_code", "signal_strength", "packet_loss"])
            for minute in range(start, end):
                for cell in CELLS:
                    m = {k: v[minute] for k, v in self.metrics[cell].items()}
                    for _ in range(_poisson(rng, self.users[cell][minute] / 9.0)):
                        w.writerow(_call(rng, minute, cell, m))
                        rows += 1
        return rows


def _poisson(rng: random.Random, lam: float) -> int:
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _call(rng: random.Random, minute: int, cell: str, m: dict[str, float]) -> list:
    second = rng.randrange(60)
    ts = iso(minute + second / 60.0)
    caller = f"+1555{rng.randrange(10**6):06d}"
    callee = f"+1555{rng.randrange(10**6):06d}"
    signal = max(-150, min(0, int(rng.gauss(-86, 6))))
    loss = max(0, min(100, int(round(m["packet_loss_pct"] + rng.gauss(0, 0.5)))))
    if rng.random() > m["setup_success_pct"] / 100:
        return [ts, caller, callee, cell, 0, rng.choice([408, 486, 503]), signal, loss]
    duration = max(1, int(rng.gammavariate(2.0, 60)))
    if rng.random() < m["call_drop_pct"] / 100:
        return [ts, caller, callee, cell, rng.randrange(1, duration + 1),
                rng.choice([901, 903, 904]), signal, loss]
    return [ts, caller, callee, cell, duration, 200, signal, loss]


def _leak(minute: int, rollback_minute: int | None) -> float:
    """Extra memory % caused by the bad release on pgw-1."""
    if minute < BAD_DEPLOY_MINUTE:
        return 0.0

    def grown(t: float) -> float:
        return 41.0 * (1 - math.exp(-(t - BAD_DEPLOY_MINUTE) / 12.0))

    if rollback_minute is None or minute < rollback_minute:
        return grown(minute)
    return grown(rollback_minute) * math.exp(-(minute - rollback_minute) / 1.5)


def simulate(seed: int = 7, rollback_minute: int | None = None,
             bad_deploy: bool = True) -> World:
    rng = random.Random(seed)
    metrics: dict[str, dict[str, list[float]]] = {c: {k: [] for k in METRICS} for c in CELLS}
    users: dict[str, list[float]] = {c: [] for c in CELLS}
    logs: list[dict] = []
    noise = {(c, k): 0.0 for c in CELLS for k in METRICS}

    def ar(cell: str, key: str, sd: float) -> float:
        """Smooth AR(1) noise so series wiggle like real counters."""
        noise[(cell, key)] = 0.8 * noise[(cell, key)] + rng.gauss(0, sd)
        return noise[(cell, key)]

    for minute in range(MINUTES):
        leak = _leak(minute, rollback_minute) if bad_deploy else 0.0
        for i, cell in enumerate(CELLS):
            node = NODE_OF[cell]
            u = 80 + 25 * math.sin((minute + 40 * i) / 120.0) + rng.gauss(0, 3)
            mem = 55 + i % 4 + ar(cell, "memory_pct", 0.6) + (leak if node == "pgw-1" else 0)
            gc = max(0.0, mem - 75) * 2.3
            cpu = 38 + 0.15 * u + gc + ar(cell, "cpu_pct", 1.2)
            queue = 0.0 if cpu < 80 else (cpu - 80) ** 2 * 0.6
            latency = 21 + queue + ar(cell, "latency_ms", 1.0)
            loss = 0.3 + max(0.0, cpu - 90) * 0.95 + abs(ar(cell, "packet_loss_pct", 0.05))
            drop = 0.8 + 0.7 * loss + latency / 200 + ar(cell, "call_drop_pct", 0.08)
            setup = 99.3 - 1.6 * loss - max(0.0, latency - 100) / 40 + ar(cell, "setup_success_pct", 0.08)
            thr = u * 4.6 * max(0.0, 1 - 3 * loss / 100) + ar(cell, "throughput_mbps", 4)

            values = {
                "memory_pct": min(mem, 99.8), "cpu_pct": min(cpu, 99.5),
                "latency_ms": latency, "packet_loss_pct": loss, "call_drop_pct": max(drop, 0.0),
                "setup_success_pct": min(setup, 100.0), "throughput_mbps": max(thr, 0.0),
            }
            for k, v in values.items():
                metrics[cell][k].append(round(v, 3))
            users[cell].append(u)

        # Application logs from pgw-1: only while the leak is actually hurting.
        p1 = {k: sum(metrics[c][k][minute] for c in CELLS[:4]) / 4 for k in METRICS}
        if p1["memory_pct"] > 85 and minute % 3 == 0:
            logs.append({"minute": minute, "time": iso(minute), "node": "pgw-1", "level": "WARN",
                         "message": f"GC pause {int(200 + (p1['memory_pct'] - 85) * 18)} ms in packet-processing worker"})
        if p1["packet_loss_pct"] > 3 and minute % 3 == 1:
            logs.append({"minute": minute, "time": iso(minute), "node": "pgw-1", "level": "ERROR",
                         "message": "Worker queue backlog: dropping packets"})
        if minute % 30 == 0:
            for node in ("pgw-1", "pgw-2", "pgw-3"):
                logs.append({"minute": minute, "time": iso(minute), "node": node, "level": "INFO",
                             "message": "health check ok"})

    deployments = [{
        "id": "DEP-1", "time": iso(DECOY_DEPLOY_MINUTE), "minute": DECOY_DEPLOY_MINUTE,
        "node": "pgw-3", "service": "packet-gateway", "from_version": "2.4.0",
        "to_version": "2.4.0-hotfix1", "change": "log format tweak",
    }]
    if bad_deploy:
        deployments.append({
            "id": "DEP-2", "time": iso(BAD_DEPLOY_MINUTE), "minute": BAD_DEPLOY_MINUTE,
            "node": "pgw-1", "service": "packet-gateway", "from_version": "2.4.0",
            "to_version": "2.4.1", "change": "refactor session buffer pooling in packet path",
        })
    if bad_deploy and rollback_minute is not None:
        deployments.append({
            "id": "DEP-3", "time": iso(rollback_minute), "minute": rollback_minute,
            "node": "pgw-1", "service": "packet-gateway", "from_version": "2.4.1",
            "to_version": "2.4.0", "change": "rollback by agent",
        })

    # Background security noise: a few port scans at pgw-2, never enough to matter.
    sec_rng = random.Random(seed + 99)
    security = [{
        "minute": m, "time": iso(m), "node": "pgw-2", "type": "port_scan",
        "source_ip": f"203.0.113.{sec_rng.randrange(1, 255)}", "severity": "low",
    } for m in sorted(sec_rng.sample(range(MINUTES), 9))]

    return World(seed, rollback_minute, metrics, deployments, logs, security, users)
