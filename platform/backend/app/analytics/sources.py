"""Adapters that build MetricSeries from simulator output or the metrics CSV.

The detection engine depends only on MetricSeries; it never imports the
simulator's model or incident code.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np

from app.analytics.correlation import EventType, OperationalEvent
from app.analytics.engine import MetricSeries
from app.simulation.scenario import SimulationResult


def series_from_simulation(result: SimulationResult, metrics: list[str] | None = None) -> list[MetricSeries]:
    topo = result.scenario.topology
    out = []
    for cell in topo.cell_ids:
        for metric, values in result.metrics[cell].items():
            if metrics is None or metric in metrics:
                out.append(MetricSeries(metric, cell, topo.node_of(cell), result.epochs, values))
    return out


def series_from_csv(path: Path) -> list[MetricSeries]:
    """Reads the wide metrics CSV written by `app.simulation.io.write_metrics_csv`."""
    epochs: dict[str, list[int]] = defaultdict(list)
    values: dict[tuple[str, str], list[float]] = defaultdict(list)
    nodes: dict[str, str] = {}
    with path.open(newline="", encoding="ascii") as handle:
        reader = csv.DictReader(handle)
        metric_names = [f for f in reader.fieldnames or [] if f not in ("timestamp", "cell_id", "node_id")]
        for row in reader:
            cell = row["cell_id"]
            nodes[cell] = row["node_id"]
            epochs[cell].append(int(datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).timestamp()))
            for metric in metric_names:
                values[(cell, metric)].append(float(row[metric]))
    return [MetricSeries(metric, cell, nodes[cell], np.asarray(epochs[cell], dtype=np.int64),
                         np.asarray(values[(cell, metric)]))
            for (cell, metric) in sorted(values)]


def events_from_simulation(result: SimulationResult) -> list[OperationalEvent]:
    return [OperationalEvent.make(e.epoch, EventType(e.kind.value), e.source, e.severity.value,
                                  e.message, e.node_id, e.cell_id, e.attributes)
            for e in result.events]


def series_lookup(series: list[MetricSeries]) -> dict[tuple[str, str], tuple[np.ndarray, np.ndarray]]:
    return {(s.cell_id, s.metric): (s.epochs, s.values) for s in series}
