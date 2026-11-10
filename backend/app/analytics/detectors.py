"""Interpretable anomaly detectors over one metric time series (spec §6).

Detectors evaluated per point, in time order:

- moving average + rolling standard deviation -> z-score (``zscore``)
- exponentially weighted moving average/variance -> z-score (``ewma``)
- static thresholds per metric (``threshold``)
- rate of change versus the typical point-to-point change (``rate_of_change``)

Baselines use a trailing *time* window (not a point count), so irregular
sampling and gaps are handled; EWMA uses a time-aware smoothing factor.
Only clearly normal points (|z| < ``baseline_admit_z`` in either direction)
update the baseline ("baseline freeze"), so neither a slow ramp nor a
good-direction excursion (e.g. throughput collapse lowering a bandwidth
baseline) can contaminate it. When the trailing window holds no admitted
points, the last healthy baseline is reused. After ``rebaseline_after_seconds``
without any admission, the series is re-seeded from the current values: a
persistent shift is then accepted as the new normal.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field

import numpy as np

from app.analytics.config import DetectionConfig, MetricRule
from app.simulation.metrics import Direction


@dataclass(frozen=True)
class PointResult:
    """Detector outcome for one sample."""

    index: int
    epoch: int
    value: float
    baseline: float
    scores: dict[str, float]      # detector -> anomaly score in [0, 1]
    deviations: dict[str, float]  # detector -> signed z (positive = bad direction)
    threshold_level: str | None   # "warning" / "critical" when a static threshold is breached
    flagged: bool

    @property
    def score(self) -> float:
        return max(self.scores.values(), default=0.0)


def score_from_z(z: float, threshold: float) -> float:
    """Same mapping as the C library: 0.5 at the threshold, -> 1 as z grows."""
    if z <= 0.0 or threshold <= 0.0:
        return 0.0
    return float(1.0 - math.pow(2.0, -z / threshold))


def _oriented(delta: float, direction: Direction) -> float:
    if direction is Direction.UP:
        return delta
    if direction is Direction.DOWN:
        return -delta
    return abs(delta)


@dataclass
class _Baseline:
    window_seconds: int
    points: deque[tuple[int, float]] = field(default_factory=deque)
    total: float = 0.0
    total_sq: float = 0.0
    frozen_mean: float | None = None
    frozen_std: float | None = None

    def evict(self, now: int) -> None:
        while self.points and self.points[0][0] < now - self.window_seconds:
            _, v = self.points.popleft()
            self.total -= v
            self.total_sq -= v * v

    def add(self, epoch: int, value: float) -> None:
        self.points.append((epoch, value))
        self.total += value
        self.total_sq += value * value

    def stats(self, min_points: int) -> tuple[float, float] | None:
        n = len(self.points)
        if n >= min_points:
            mean = self.total / n
            var = max(0.0, self.total_sq / n - mean * mean)
            self.frozen_mean, self.frozen_std = mean, math.sqrt(var)
            return mean, math.sqrt(var)
        if self.frozen_mean is not None and self.frozen_std is not None:
            return self.frozen_mean, self.frozen_std
        return None


def evaluate_series(
    epochs: np.ndarray, values: np.ndarray, rule: MetricRule, config: DetectionConfig
) -> list[PointResult]:
    """Runs all detectors over one series. Non-finite values are skipped."""
    if epochs.shape != values.shape or epochs.ndim != 1:
        raise ValueError("epochs and values must be 1-D arrays of equal length")
    if len(epochs) > 1 and np.any(np.diff(epochs) <= 0):
        raise ValueError("epochs must be strictly increasing")

    baseline = _Baseline(config.window_seconds)
    ewma_mean: float | None = None
    ewma_var = 0.0
    prev_epoch: int | None = None
    prev_value: float | None = None
    healthy_rates: deque[tuple[int, float]] = deque()
    last_admitted: int | None = None
    results: list[PointResult] = []

    for i, (raw_epoch, raw_value) in enumerate(zip(epochs, values, strict=True)):
        epoch, value = int(raw_epoch), float(raw_value)
        if not math.isfinite(value):
            continue
        baseline.evict(epoch)
        while healthy_rates and healthy_rates[0][0] < epoch - config.window_seconds:
            healthy_rates.popleft()

        if last_admitted is not None and epoch - last_admitted > config.rebaseline_after_seconds:
            baseline = _Baseline(config.window_seconds)
            ewma_mean, ewma_var, last_admitted = None, 0.0, None
            healthy_rates.clear()
        stats = baseline.stats(config.min_baseline_points)
        scores: dict[str, float] = {}
        deviations: dict[str, float] = {}
        mean = stats[0] if stats else value
        scale_floor = max(rule.noise_floor, rule.relative_floor * abs(mean))

        practical = stats is not None and _oriented(value - mean, rule.direction) >= rule.min_delta
        if stats is not None:
            z = _oriented(value - mean, rule.direction) / max(stats[1], scale_floor)
            deviations["zscore"] = z
            scores["zscore"] = score_from_z(z, config.z_threshold) if practical else 0.0
        if ewma_mean is not None and stats is not None:
            z = _oriented(value - ewma_mean, rule.direction) / max(math.sqrt(ewma_var), scale_floor)
            deviations["ewma"] = z
            ewma_practical = _oriented(value - ewma_mean, rule.direction) >= rule.min_delta
            scores["ewma"] = score_from_z(z, config.z_threshold) if ewma_practical else 0.0

        rate: float | None = None
        if prev_epoch is not None and prev_value is not None:
            rate = (value - prev_value) / ((epoch - prev_epoch) / 60.0)  # per minute
            if len(healthy_rates) >= config.min_baseline_points and practical:
                rates = np.fromiter((r for _, r in healthy_rates), float)
                med = float(np.median(rates))
                mad = float(np.median(np.abs(rates - med)))
                z = _oriented(rate - med, rule.direction) / max(1.4826 * mad, scale_floor)
                deviations["rate_of_change"] = z
                scores["rate_of_change"] = score_from_z(z, config.roc_threshold)

        level: str | None = None
        if rule.critical is not None and _oriented(value - rule.critical, rule.direction) >= 0:
            level = "critical"
            scores["threshold"] = config.critical_threshold_score
        elif rule.warning is not None and _oriented(value - rule.warning, rule.direction) >= 0:
            level = "warning"
            scores["threshold"] = config.warning_threshold_score

        z_hit = scores.get("zscore", 0.0) >= 0.5
        ewma_hit = scores.get("ewma", 0.0) >= 0.5
        roc_hit = scores.get("rate_of_change", 0.0) >= 0.5
        flagged = level is not None or (z_hit and ewma_hit) or (roc_hit and (z_hit or ewma_hit))

        results.append(PointResult(i, epoch, value, mean, scores, deviations, level, flagged))

        admit = not flagged
        if stats is not None:
            admit = admit and abs(value - mean) / max(stats[1], scale_floor) < config.baseline_admit_z
        if last_admitted is None and stats is None:
            last_admitted = epoch
        if admit:
            last_admitted = epoch
            baseline.add(epoch, value)
            if rate is not None:
                healthy_rates.append((epoch, rate))
            if ewma_mean is None:
                ewma_mean = value
            else:
                dt = epoch - (prev_epoch if prev_epoch is not None else epoch)
                alpha = 1.0 - math.exp(-max(dt, 1) / config.ewma_tau_seconds)
                delta = value - ewma_mean
                ewma_mean += alpha * delta
                ewma_var = (1.0 - alpha) * (ewma_var + alpha * delta * delta)
        prev_epoch, prev_value = epoch, value
    return results


def moving_average(epochs: np.ndarray, values: np.ndarray, window_seconds: int) -> np.ndarray:
    """Trailing time-window mean including the current point (for charts/reports)."""
    out = np.empty(len(values))
    start = 0
    total = 0.0
    for i in range(len(values)):
        total += float(values[i])
        while epochs[start] <= epochs[i] - window_seconds:
            total -= float(values[start])
            start += 1
        out[i] = total / (i - start + 1)
    return out


def rolling_std(epochs: np.ndarray, values: np.ndarray, window_seconds: int) -> np.ndarray:
    """Trailing time-window population standard deviation including the current point."""
    out = np.empty(len(values))
    start = 0
    for i in range(len(values)):
        while epochs[start] <= epochs[i] - window_seconds:
            start += 1
        out[i] = float(np.std(values[start:i + 1]))
    return out


def ewma(epochs: np.ndarray, values: np.ndarray, tau_seconds: float) -> np.ndarray:
    """Time-aware exponentially weighted moving average."""
    out = np.empty(len(values))
    for i in range(len(values)):
        if i == 0:
            out[i] = values[0]
            continue
        alpha = 1.0 - math.exp(-max(int(epochs[i] - epochs[i - 1]), 1) / tau_seconds)
        out[i] = out[i - 1] + alpha * (values[i] - out[i - 1])
    return out
