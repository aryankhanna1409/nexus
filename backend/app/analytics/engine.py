"""Turns per-point detector results into anomaly episodes (spec §6 objects)."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

import numpy as np

from app.analytics.config import DetectionConfig
from app.analytics.detectors import PointResult, evaluate_series


@dataclass(frozen=True)
class MetricSeries:
    """One KPI series for one cell. `node_id` locates the cell in the topology."""

    metric: str
    cell_id: str
    node_id: str
    epochs: np.ndarray
    values: np.ndarray


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def severity_for_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


@dataclass(frozen=True)
class MetricAnomaly:
    """A contiguous anomalous episode of one metric on one cell.

    `timestamp`/`value`/`baseline` follow spec §6: onset time, most extreme
    value, and the healthy baseline at onset.
    """

    anomaly_id: str
    metric: str
    cell_id: str
    node_id: str
    start_epoch: int
    end_epoch: int
    value: float
    baseline: float
    anomaly_score: float
    severity: str
    detectors: tuple[str, ...]
    points: int
    related_metrics: tuple[str, ...] = field(default=())

    @property
    def timestamp(self) -> str:
        return iso(self.start_epoch)

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_id": self.anomaly_id, "metric": self.metric, "cell_id": self.cell_id,
            "node_id": self.node_id, "timestamp": self.timestamp, "start_epoch": self.start_epoch,
            "end_epoch": self.end_epoch, "value": self.value, "baseline": self.baseline,
            "severity": self.severity, "anomaly_score": self.anomaly_score,
            "detectors": list(self.detectors), "points": self.points,
            "related_metrics": list(self.related_metrics),
        }


def _episodes(flagged: list[PointResult], config: DetectionConfig) -> list[list[PointResult]]:
    groups: list[list[PointResult]] = []
    for point in flagged:
        if groups and point.epoch - groups[-1][-1].epoch <= config.merge_gap_seconds:
            groups[-1].append(point)
        else:
            groups.append([point])
    return [g for g in groups
            if len(g) >= config.min_episode_points or max(p.score for p in g) >= config.spike_score]


def _anomaly_from_episode(series: MetricSeries, episode: list[PointResult]) -> MetricAnomaly:
    onset = episode[0]
    # Flagged points deviate in the bad direction, so the farthest from baseline is the peak.
    extreme = max(episode, key=lambda p: abs(p.value - onset.baseline))
    detectors = sorted({name for p in episode for name, s in p.scores.items() if s >= 0.5})
    score = round(max(p.score for p in episode), 6)
    key = f"{series.metric}|{series.cell_id}|{onset.epoch}".encode()
    return MetricAnomaly(
        anomaly_id="ANOM-" + hashlib.sha256(key).hexdigest()[:12],
        metric=series.metric, cell_id=series.cell_id, node_id=series.node_id,
        start_epoch=onset.epoch, end_epoch=episode[-1].epoch,
        value=extreme.value, baseline=onset.baseline,
        anomaly_score=score, severity=severity_for_score(score),
        detectors=tuple(detectors), points=len(episode),
    )


def detect_series(series: MetricSeries, config: DetectionConfig | None = None) -> list[MetricAnomaly]:
    cfg = config or DetectionConfig()
    cfg.validate()
    if series.metric not in cfg.rules:
        raise KeyError(f"no detection rule for metric {series.metric!r}")
    points = evaluate_series(series.epochs, series.values, cfg.rules[series.metric], cfg)
    return [_anomaly_from_episode(series, ep) for ep in _episodes([p for p in points if p.flagged], cfg)]


def _with_related(anomalies: list[MetricAnomaly], tolerance: int) -> list[MetricAnomaly]:
    """related_metrics = other metrics on the same cell whose episodes overlap in time."""
    out = []
    for a in anomalies:
        related = sorted({
            b.metric for b in anomalies
            if b.cell_id == a.cell_id and b.metric != a.metric
            and b.start_epoch <= a.end_epoch + tolerance and a.start_epoch <= b.end_epoch + tolerance
        })
        out.append(replace(a, related_metrics=tuple(related)))
    return out


def detect_anomalies(series: Iterable[MetricSeries], config: DetectionConfig | None = None) -> list[MetricAnomaly]:
    """Detects anomalies on every series; sorted by onset, then cell and metric."""
    cfg = config or DetectionConfig()
    found: list[MetricAnomaly] = []
    for s in series:
        found += detect_series(s, cfg)
    found.sort(key=lambda a: (a.start_epoch, a.cell_id, a.metric))
    return _with_related(found, cfg.related_window_seconds)
