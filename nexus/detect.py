"""Find anomalies in KPI series, then group them into one incident.

Step 1, detect: for every cell and metric, compare each minute with the
trailing hour of *normal* minutes (rolling mean and standard deviation).
A minute is suspicious when it is at least 4 standard deviations worse
than normal AND the change is big enough to matter in practice.
Suspicious minutes close together become one anomaly "episode".

Step 2, correlate: anomalies on the same gateway become an incident when
at least two different metrics are affected and one is severe. Recent
changes (deployments, security events) are ranked as candidate causes.
These are hypotheses, never facts.
"""
from __future__ import annotations

import math
import statistics

from .simulate import CELLS, METRICS, NODE_OF, NOW, World, iso

WINDOW = 60         # minutes of history in the baseline
WARMUP = 30         # minutes before detection starts
Z_FLAG = 4.0        # statistical bar
MAX_GAP = 5         # flagged minutes this close belong to one episode

# Smallest change that matters per metric, and the smallest spread we trust.
MIN_DELTA = {"memory_pct": 8, "cpu_pct": 12, "latency_ms": 25, "packet_loss_pct": 1.5,
             "call_drop_pct": 1.0, "setup_success_pct": 1.5, "throughput_mbps": 120}
MIN_STD = {"memory_pct": 1.0, "cpu_pct": 2.0, "latency_ms": 2.0, "packet_loss_pct": 0.1,
           "call_drop_pct": 0.15, "setup_success_pct": 0.15, "throughput_mbps": 10}


def detect_anomalies(world: World, end: int = NOW) -> list[dict]:
    found = []
    for cell in CELLS:
        for metric, (_, bad) in METRICS.items():
            series = world.metrics[cell][metric][:end]
            sign = 1 if bad == "up" else -1
            normal: list[float] = []
            flagged: list[tuple[int, float, float]] = []   # (minute, z, baseline)
            for minute, x in enumerate(series):
                base = normal[-WINDOW:]
                if minute < WARMUP or len(base) < 10:
                    normal.append(x)
                    continue
                mean = statistics.fmean(base)
                std = max(statistics.pstdev(base), MIN_STD[metric])
                z = sign * (x - mean) / std
                if z >= Z_FLAG and sign * (x - mean) >= MIN_DELTA[metric]:
                    flagged.append((minute, z, mean))
                elif abs(z) < 2.5:
                    normal.append(x)   # only clearly normal points teach the baseline
            found += _episodes(cell, metric, flagged, series)
    found.sort(key=lambda a: (a["start_minute"], a["cell"], a["metric"]))
    for i, a in enumerate(found, 1):
        a["id"] = f"ANOM-{i:03d}"
    return found


def _episodes(cell: str, metric: str, flagged: list, series: list[float]) -> list[dict]:
    groups: list[list] = []
    for point in flagged:
        if groups and point[0] - groups[-1][-1][0] <= MAX_GAP:
            groups[-1].append(point)
        else:
            groups.append([point])
    out = []
    sign = 1 if METRICS[metric][1] == "up" else -1
    for g in groups:
        if len(g) < 2:
            continue
        start, end = g[0][0], g[-1][0]
        peak_z = max(p[1] for p in g)
        worst = max(series[start:end + 1], key=lambda v: sign * v)
        out.append({
            "cell": cell, "node": NODE_OF[cell], "metric": metric,
            "start_minute": start, "end_minute": end, "start": iso(start), "end": iso(end),
            "baseline": round(g[0][2], 2), "worst": round(worst, 2), "peak_z": round(peak_z, 1),
            "severity": "critical" if peak_z >= 10 else "high" if peak_z >= 6 else "medium",
        })
    return out


def correlate(world: World, anomalies: list[dict]) -> dict | None:
    """Group anomalies per gateway and open an incident for the worst one."""
    by_node: dict[str, list[dict]] = {}
    for a in anomalies:
        by_node.setdefault(a["node"], []).append(a)

    best = None
    for node, group in by_node.items():
        metrics = {a["metric"] for a in group}
        severe = any(a["severity"] in ("high", "critical") for a in group)
        if len(metrics) >= 2 and severe and (best is None or len(group) > len(by_node[best])):
            best = node
    if best is None:
        return None

    group = by_node[best]
    onset = min(a["start_minute"] for a in group)
    symptoms = []
    for metric in sorted({a["metric"] for a in group},
                         key=lambda m: min(a["start_minute"] for a in group if a["metric"] == m)):
        rows = [a for a in group if a["metric"] == metric]
        first = min(rows, key=lambda a: a["start_minute"])
        symptoms.append({"metric": metric, "onset": first["start"], "onset_minute": first["start_minute"],
                         "cells": sorted({a["cell"] for a in rows}),
                         "baseline": first["baseline"], "worst": max(a["worst"] for a in rows)
                         if METRICS[metric][1] == "up" else min(a["worst"] for a in rows),
                         "severity": max((a["severity"] for a in rows), key=["medium", "high", "critical"].index)})

    candidates, excluded = [], []
    for d in world.deployments:
        lead = onset - d["minute"]
        if not 0 <= lead <= 120:
            continue
        if d["node"] != best:
            excluded.append({"cause": f"{d['service']} {d['to_version']} on {d['node']}",
                             "reason": f"targets {d['node']}, but the symptoms are on {best}"})
            continue
        candidates.append({"cause_type": "deployment_regression",
                           "description": f"{d['service']} {d['from_version']} -> {d['to_version']} on {d['node']} at {d['time'][11:16]}",
                           "score": round(0.55 + 0.4 * math.exp(-lead / 30), 2)})
    if symptoms[0]["metric"] == "memory_pct":
        candidates.append({"cause_type": "resource_exhaustion",
                           "description": f"memory exhaustion on {best} (memory was the first symptom)",
                           "score": 0.6})
    attacks = [e for e in world.security_events if e["node"] == best and onset - 60 <= e["minute"] <= onset + 30]
    if len(attacks) >= 10:
        candidates.append({"cause_type": "security_attack", "description": f"{len(attacks)} security events on {best}",
                           "score": 0.5})
    candidates.sort(key=lambda c: -c["score"])

    worst = max(group, key=lambda a: ["medium", "high", "critical"].index(a["severity"]))
    return {
        "id": "INC-2026-001",
        "node": best,
        "cells": sorted({a["cell"] for a in group}),
        "severity": worst["severity"].upper(),
        "onset": iso(onset), "onset_minute": onset,
        "symptoms": symptoms,
        "anomaly_ids": [a["id"] for a in group],
        "candidate_causes": candidates,
        "excluded": excluded,
        "status": "open",
    }
