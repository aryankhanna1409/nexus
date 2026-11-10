"""Test-only pure-Python reference for libcallanalyzer aggregations.

Used solely to cross-check the C results on valid fixtures. It implements the
definitions documented in ARCHITECTURE.md §3.1 independently of the C code and
is never imported by production code.
"""

from __future__ import annotations

import csv
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

WEAK_SIGNAL_DBM = -105
SHORT_CALL_SECONDS = 5


@dataclass(frozen=True)
class Row:
    epoch: int
    caller: str
    callee: str
    cell_id: str
    duration: int
    status_code: int
    signal: int
    loss: int

    @property
    def outcome(self) -> str:
        code = self.status_code
        if 200 <= code <= 299:
            return "completed"
        if 900 <= code <= 999:
            return "dropped"
        if 300 <= code <= 899:
            return "setup_failed"
        return "unknown"

    @property
    def established(self) -> bool:
        return self.outcome in ("completed", "dropped")


def read_rows(path: Path) -> list[Row]:
    rows: list[Row] = []
    with path.open(newline="", encoding="ascii") as handle:
        for record in csv.DictReader(handle):
            ts = datetime.strptime(record["timestamp"].rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
            rows.append(Row(
                epoch=int(ts.replace(tzinfo=UTC).timestamp()),
                caller=record["caller"],
                callee=record["callee"],
                cell_id=record["cell_id"],
                duration=int(record["duration"]),
                status_code=int(record["status_code"]),
                signal=int(record["signal_strength"]),
                loss=int(record["packet_loss"]),
            ))
    return rows


def _ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def _group_stats(rows: list[Row]) -> dict[str, Any]:
    completed = sum(r.outcome == "completed" for r in rows)
    dropped = sum(r.outcome == "dropped" for r in rows)
    failed = sum(r.outcome == "setup_failed" for r in rows)
    established = [r.duration for r in rows if r.established]
    return {
        "total_calls": len(rows),
        "successful_calls": completed,
        "failed_setup_calls": failed,
        "dropped_calls": dropped,
        "success_rate": _ratio(completed, len(rows)),
        "drop_rate": _ratio(dropped, completed + dropped),
        "setup_failure_rate": _ratio(failed, len(rows)),
        "average_duration": sum(established) / len(established) if established else 0.0,
        "average_signal": sum(r.signal for r in rows) / len(rows) if rows else 0.0,
        "average_packet_loss": sum(r.loss for r in rows) / len(rows) if rows else 0.0,
        "weak_signal_calls": sum(r.signal <= WEAK_SIGNAL_DBM for r in rows),
    }


def overall(rows: list[Row]) -> dict[str, Any]:
    result = _group_stats(rows)
    durations = [r.duration for r in rows if r.established]
    mean = sum(durations) / len(durations) if durations else 0.0
    result.update({
        "unknown_calls": sum(r.outcome == "unknown" for r in rows),
        "duration_stddev": math.sqrt(sum((d - mean) ** 2 for d in durations) / len(durations))
        if durations else 0.0,
        "min_duration": min(durations, default=0),
        "max_duration": max(durations, default=0),
        "unique_cells": len({r.cell_id for r in rows}),
        "unique_callers": len({r.caller for r in rows}),
        "first_epoch": min((r.epoch for r in rows), default=None),
        "last_epoch": max((r.epoch for r in rows), default=None),
    })
    return result


def cells(rows: list[Row]) -> list[dict[str, Any]]:
    groups: dict[str, list[Row]] = defaultdict(list)
    for r in rows:
        groups[r.cell_id].append(r)
    return [
        {"cell_id": cell, **_group_stats(g),
         "first_epoch": min(r.epoch for r in g), "last_epoch": max(r.epoch for r in g)}
        for cell, g in sorted(groups.items())
    ]


def failure_codes(rows: list[Row]) -> list[dict[str, Any]]:
    counts: dict[int, int] = defaultdict(int)
    for r in rows:
        counts[r.status_code] += 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{"status_code": code, "outcome": Row(0, "", "", "", 0, code, 0, 0).outcome,
             "count": n, "share": n / len(rows)} for code, n in ordered]


def time_windows(rows: list[Row], window_seconds: int) -> list[dict[str, Any]]:
    groups: dict[int, list[Row]] = defaultdict(list)
    for r in rows:
        groups[r.epoch - r.epoch % window_seconds].append(r)
    result = []
    for start, g in sorted(groups.items()):
        stats = _group_stats(g)
        result.append({
            "window_start_epoch": start,
            "window_end_epoch": start + window_seconds,
            **{k: stats[k] for k in ("total_calls", "successful_calls", "failed_setup_calls",
                                     "dropped_calls", "drop_rate", "setup_failure_rate",
                                     "average_signal", "average_packet_loss")},
        })
    return result


def callers(rows: list[Row]) -> list[dict[str, Any]]:
    groups: dict[str, list[Row]] = defaultdict(list)
    for r in rows:
        groups[r.caller].append(r)
    result = []
    for caller, g in sorted(groups.items()):
        established = [r for r in g if r.established]
        result.append({
            "caller": caller,
            "calls_made": len(g),
            "distinct_callees": len({r.callee for r in g}),
            "successful_calls": sum(r.outcome == "completed" for r in g),
            "failed_setup_calls": sum(r.outcome == "setup_failed" for r in g),
            "dropped_calls": sum(r.outcome == "dropped" for r in g),
            "short_calls": sum(r.duration < SHORT_CALL_SECONDS for r in established),
            "total_duration": sum(r.duration for r in established),
            "average_duration": sum(r.duration for r in established) / len(established)
            if established else 0.0,
            "first_epoch": min(r.epoch for r in g),
            "last_epoch": max(r.epoch for r in g),
        })
    return result


# ---- Anomaly detection (independent re-derivation of the documented rules) ----------
#
# Rules from c-library/README.md "Anomaly detection" and ARCHITECTURE.md §3.1:
# z = direction * (x - median) / max(1.4826 * MAD, floor); flag when z >= threshold
# and the absolute deviation reaches the minimum delta; score = 1 - 2^(-z/threshold).

DEFAULT_ANOMALY_CONFIG: dict[str, float] = {
    "z_threshold": 3.5,
    "duration_z_threshold": 10.0,
    "min_peer_groups": 3,
    "min_calls_per_cell": 20,
    "min_calls_per_window": 10,
    "min_calls_per_caller": 20,
    "min_established_for_duration": 30,
    "window_seconds": 300,
    "min_rate_delta": 0.05,
    "min_signal_delta_dbm": 6.0,
    "min_packet_loss_delta": 3.0,
    "min_volume_ratio": 2.0,
    "min_short_call_ratio": 0.6,
    "max_anomalies": 1000,
}
ANOMALY_TYPE_ORDER = [
    "cell_drop_rate", "cell_setup_failure_rate", "cell_low_signal", "cell_packet_loss",
    "window_drop_rate", "window_volume_spike", "caller_high_volume", "call_duration",
]


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2.0


def _robust(values: list[float], direction: int, floor: float) -> tuple[float, list[float]]:
    med = _median(values)
    mad = _median([abs(v - med) for v in values])
    scale = max(1.4826 * mad, floor)
    return med, [direction * ((v - med) / scale) for v in values]


def _severity(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _anomaly(kind: str, subject: str, value: float, baseline: float, z: float,
             threshold: float, sample: int, start: int, end: int, description: str,
             record_index: int | None = None) -> dict[str, Any]:
    score = 1.0 - 2.0 ** (-z / threshold) if z > 0 else 0.0
    return {
        "type": kind, "category": kind.split("_", 1)[0], "severity": _severity(score),
        "subject": subject, "window_start_epoch": start, "window_end_epoch": end,
        "window_start": _iso(start), "window_end": _iso(end), "value": value,
        "baseline": baseline, "z_score": z, "anomaly_score": score, "sample_size": sample,
        "record_index": record_index, "description": description,
    }


def anomalies(rows: list[Row], cfg: dict[str, float] = DEFAULT_ANOMALY_CONFIG) -> list[dict[str, Any]]:
    thr, peers = cfg["z_threshold"], cfg["min_peer_groups"]
    found: list[dict[str, Any]] = []

    cell_list = cells(rows)
    if len(cell_list) >= peers:
        metrics = [
            ("cell_drop_rate", "drop_rate", 1, 0.01, cfg["min_rate_delta"], True,
             "Cell {s} drop rate {v:.1f}% vs peer median {m:.1f}% ({n} established calls)", 100.0),
            ("cell_setup_failure_rate", "setup_failure_rate", 1, 0.01, cfg["min_rate_delta"], False,
             "Cell {s} setup failure rate {v:.1f}% vs peer median {m:.1f}% ({n} calls)", 100.0),
            ("cell_low_signal", "average_signal", -1, 1.0, cfg["min_signal_delta_dbm"], False,
             "Cell {s} average signal {v:.1f} dBm vs peer median {m:.1f} dBm ({n} calls)", 1.0),
            ("cell_packet_loss", "average_packet_loss", 1, 0.5, cfg["min_packet_loss_delta"], False,
             "Cell {s} average packet loss {v:.1f}% vs peer median {m:.1f}% ({n} calls)", 1.0),
        ]
        for kind, key, direction, floor, delta, by_established, text, factor in metrics:
            def sample(c: dict[str, Any], est: bool = by_established) -> int:
                return int(c["successful_calls"] + c["dropped_calls"]) if est else int(c["total_calls"])
            eligible = [c for c in cell_list if sample(c) >= cfg["min_calls_per_cell"]]
            if len(eligible) < peers:
                continue
            med, zs = _robust([c[key] for c in eligible], direction, floor)
            for c, z in zip(eligible, zs):
                if z >= thr and direction * (c[key] - med) >= delta:
                    desc = text.format(s=c["cell_id"], v=c[key] * factor, m=med * factor, n=sample(c))
                    found.append(_anomaly(kind, c["cell_id"], c[key], med, z, thr, sample(c),
                                          c["first_epoch"], c["last_epoch"], desc))

    windows = time_windows(rows, int(cfg["window_seconds"]))
    if len(windows) >= peers:
        eligible = [w for w in windows
                    if w["successful_calls"] + w["dropped_calls"] >= cfg["min_calls_per_window"]]
        if len(eligible) >= peers:
            med, zs = _robust([w["drop_rate"] for w in eligible], 1, 0.01)
            for w, z in zip(eligible, zs):
                if z >= thr and w["drop_rate"] - med >= cfg["min_rate_delta"]:
                    n = w["successful_calls"] + w["dropped_calls"]
                    subject = _iso(w["window_start_epoch"])
                    desc = (f"Window {subject} drop rate {w['drop_rate'] * 100:.1f}% vs median "
                            f"{med * 100:.1f}% ({n} established calls)")
                    found.append(_anomaly("window_drop_rate", subject, w["drop_rate"], med, z, thr, n,
                                          w["window_start_epoch"], w["window_end_epoch"], desc))
        med, zs = _robust([float(w["total_calls"]) for w in windows], 1, 1.0)
        for w, z in zip(windows, zs):
            if z >= thr and w["total_calls"] >= cfg["min_volume_ratio"] * med:
                subject = _iso(w["window_start_epoch"])
                desc = f"Window {subject} carried {w['total_calls']} calls vs median {med:.1f} per window"
                found.append(_anomaly("window_volume_spike", subject, float(w["total_calls"]), med, z,
                                      thr, w["total_calls"], w["window_start_epoch"],
                                      w["window_end_epoch"], desc))

    caller_list = callers(rows)
    if len(caller_list) >= peers:
        med, zs = _robust([float(c["calls_made"]) for c in caller_list], 1, 1.0)
        for c, z in zip(caller_list, zs):
            ratio = (c["short_calls"] + c["failed_setup_calls"]) / c["calls_made"]
            if (c["calls_made"] >= cfg["min_calls_per_caller"] and z >= thr
                    and ratio >= cfg["min_short_call_ratio"]):
                desc = (f"Caller {c['caller']} placed {c['calls_made']} calls to "
                        f"{c['distinct_callees']} callees (median {med:.1f}); {ratio * 100:.0f}% "
                        "short or unanswered")
                found.append(_anomaly("caller_high_volume", c["caller"], float(c["calls_made"]), med,
                                      z, thr, c["calls_made"], c["first_epoch"], c["last_epoch"], desc))

    established = [(i, r) for i, r in enumerate(rows) if r.established]
    if established and len(established) >= cfg["min_established_for_duration"]:
        dthr = cfg["duration_z_threshold"]
        med, zs = _robust([float(r.duration) for _, r in established], 1, 1.0)
        for (i, r), z in zip(established, zs):
            if z >= dthr:
                desc = f"Call {r.caller} -> {r.callee} on {r.cell_id} lasted {r.duration} s vs median {med:.0f} s"
                found.append(_anomaly("call_duration", r.caller, float(r.duration), med, z, dthr, 1,
                                      r.epoch, r.epoch + r.duration, desc, record_index=i))

    found.sort(key=lambda a: (-a["anomaly_score"], ANOMALY_TYPE_ORDER.index(a["type"]),
                              a["subject"].encode(), a["record_index"] if a["record_index"] is not None else -1))
    cap = int(cfg["max_anomalies"])
    return found[:cap] if cap else found
