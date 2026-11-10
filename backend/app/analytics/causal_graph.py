"""Domain causal graph used to judge whether observed symptom orderings are plausible.

Edges encode documented mechanisms (cause -> effect), not learned statistics.
The correlation engine uses them to check onset ordering and to match the
earliest symptoms of an incident against what each candidate cause would
produce first. Agreement with the graph is supporting evidence, never proof.
"""

from __future__ import annotations

from functools import cache

RADIO = ("rsrp_dbm", "rssi_dbm", "rsrq_db", "sinr_db")

EDGES: dict[str, tuple[str, ...]] = {
    "memory_utilization": ("cpu_utilization",),
    "active_users": ("cpu_utilization", "bandwidth_utilization", "throughput_mbps"),
    "cpu_utilization": ("latency_ms", "packet_loss_pct"),
    "latency_ms": ("jitter_ms", "packet_loss_pct", "call_setup_success_rate", "call_drop_rate",
                   "throughput_mbps"),
    "packet_loss_pct": ("retransmission_rate", "throughput_mbps", "call_drop_rate",
                        "call_setup_success_rate", "jitter_ms"),
    "throughput_mbps": ("bandwidth_utilization",),
    **{metric: ("handover_success_rate", "handover_failure_rate", "call_drop_rate",
                "packet_loss_pct", "latency_ms") for metric in RADIO},
}

# Symptoms each cause class is expected to produce first.
EXPECTED_FIRST: dict[str, frozenset[str]] = {
    "deployment_regression": frozenset({"memory_utilization", "cpu_utilization"}),
    "configuration_change": frozenset({"handover_failure_rate", "handover_success_rate",
                                       "call_setup_success_rate"}),
    "security_attack": frozenset({"active_users", "cpu_utilization", "bandwidth_utilization"}),
    "memory_exhaustion": frozenset({"memory_utilization"}),
    "traffic_overload": frozenset({"active_users", "cpu_utilization", "bandwidth_utilization"}),
    "radio_degradation": frozenset(RADIO),
    "transport_fault": frozenset({"packet_loss_pct", "retransmission_rate"}),
}


@cache
def reachable(source: str, target: str) -> bool:
    """True if `target` is downstream of `source` in the graph."""
    frontier, seen = [source], {source}
    while frontier:
        node = frontier.pop()
        for nxt in EDGES.get(node, ()):
            if nxt == target:
                return True
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    return False


def chain_consistency(onsets: dict[str, int], tolerance_seconds: int = 60) -> tuple[float, list[str]]:
    """Share of effects preceded by at least one of their observed upstream causes.

    Effects can have several causes (jitter follows latency *or* loss), so an
    effect is consistent if *some* observed ancestor started no later than it
    (within `tolerance_seconds`); it is a violation only if it precedes all of
    them. Returns (consistency in [0, 1], violations); with no observed
    cause/effect relations the consistency is 1.0.
    """
    checked = consistent = 0
    violations: list[str] = []
    for effect, t_effect in onsets.items():
        ancestors = [c for c in onsets if c != effect and reachable(c, effect)
                     and not reachable(effect, c)]
        if not ancestors:
            continue
        checked += 1
        if any(onsets[c] <= t_effect + tolerance_seconds for c in ancestors):
            consistent += 1
        else:
            violations.append(f"{effect} preceded all of its observed upstream causes "
                              f"({', '.join(sorted(ancestors))})")
    return (consistent / checked if checked else 1.0), violations
