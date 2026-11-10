"""Detection configuration: global parameters and per-metric rules.

Per-metric values encode operational judgement and are documented here rather
than learned:

- ``noise_floor`` / ``relative_floor``: minimum standard deviation used in
  z-scores, so tightly clustered baselines do not turn negligible changes
  into large z.
- ``min_delta``: smallest deviation (in the bad direction) that is
  operationally meaningful; smaller deviations never count as statistical hits.
- ``warning`` / ``critical``: static thresholds (spec §6 "threshold-based
  detection"); breaching them flags the point regardless of the baseline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.simulation.metrics import METRIC_BY_NAME, Direction


@dataclass(frozen=True)
class MetricRule:
    direction: Direction
    noise_floor: float
    relative_floor: float
    min_delta: float
    warning: float | None = None
    critical: float | None = None


def _rule(metric: str, noise: float, min_delta: float, warning: float | None = None,
          critical: float | None = None, relative: float = 0.0) -> MetricRule:
    return MetricRule(METRIC_BY_NAME[metric].bad_direction, noise, relative, min_delta,
                      warning, critical)


DEFAULT_RULES: dict[str, MetricRule] = {
    "throughput_mbps": _rule("throughput_mbps", 1.0, 40.0, relative=0.03),
    "latency_ms": _rule("latency_ms", 1.0, 6.0, warning=100.0, critical=200.0),
    "packet_loss_pct": _rule("packet_loss_pct", 0.1, 0.5, warning=2.0, critical=5.0),
    "jitter_ms": _rule("jitter_ms", 0.3, 3.0, warning=30.0, critical=60.0),
    "rssi_dbm": _rule("rssi_dbm", 1.0, 5.0),
    "rsrp_dbm": _rule("rsrp_dbm", 1.0, 5.0, warning=-110.0, critical=-120.0),
    "rsrq_db": _rule("rsrq_db", 0.3, 2.0, warning=-15.0, critical=-19.0),
    "sinr_db": _rule("sinr_db", 0.5, 4.0, warning=3.0, critical=0.0),
    "handover_success_rate": _rule("handover_success_rate", 0.2, 1.5, warning=95.0, critical=90.0),
    "handover_failure_rate": _rule("handover_failure_rate", 0.2, 1.5, warning=5.0, critical=10.0),
    "call_setup_success_rate": _rule("call_setup_success_rate", 0.15, 1.0, warning=97.0, critical=95.0),
    "call_drop_rate": _rule("call_drop_rate", 0.1, 0.5, warning=2.0, critical=5.0),
    "retransmission_rate": _rule("retransmission_rate", 0.15, 1.0, warning=5.0, critical=10.0),
    "cpu_utilization": _rule("cpu_utilization", 1.0, 8.0, warning=85.0, critical=95.0),
    "memory_utilization": _rule("memory_utilization", 1.0, 6.0, warning=85.0, critical=95.0),
    "active_users": _rule("active_users", 2.0, 40.0, relative=0.03),
    "bandwidth_utilization": _rule("bandwidth_utilization", 1.0, 8.0, warning=90.0, critical=97.0),
}


@dataclass(frozen=True)
class DetectionConfig:
    window_seconds: int = 3600         # trailing baseline window
    min_baseline_points: int = 20      # healthy points needed before z-detection starts
    z_threshold: float = 4.0           # robust z needed by z-score / EWMA detectors
    roc_threshold: float = 5.0         # z of rate of change vs typical change
    ewma_tau_seconds: float = 900.0    # EWMA time constant
    warning_threshold_score: float = 0.7
    critical_threshold_score: float = 0.95
    min_episode_points: int = 2        # consecutive flagged points for an episode...
    spike_score: float = 0.85          # ...unless a single point scores at least this
    merge_gap_seconds: int = 300       # flagged points closer than this join one episode
    baseline_admit_z: float = 2.5      # only points with |z| below this update the baseline
    rebaseline_after_seconds: int = 21600  # accept a new normal after 6 h without admissions
    related_window_seconds: int = 900  # overlap tolerance for related_metrics
    rules: dict[str, MetricRule] = field(default_factory=lambda: dict(DEFAULT_RULES))

    def validate(self) -> None:
        if self.window_seconds < 60 or self.min_baseline_points < 3:
            raise ValueError("window_seconds must be >= 60 and min_baseline_points >= 3")
        if self.z_threshold <= 0 or self.roc_threshold <= 0 or self.ewma_tau_seconds <= 0:
            raise ValueError("thresholds and ewma_tau_seconds must be positive")
        if not 0 < self.warning_threshold_score <= self.critical_threshold_score <= 1:
            raise ValueError("threshold scores must satisfy 0 < warning <= critical <= 1")
        if self.baseline_admit_z <= 0 or self.rebaseline_after_seconds < self.window_seconds:
            raise ValueError("baseline_admit_z > 0 and rebaseline_after_seconds >= window required")
        if self.min_episode_points < 1 or self.merge_gap_seconds < 0:
            raise ValueError("min_episode_points >= 1 and merge_gap_seconds >= 0 required")
