"""Persist simulation output as CSV (metrics) and JSON Lines (events)."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.simulation.cdr import generate_cdrs, write_cdr_csv
from app.simulation.metrics import METRIC_NAMES
from app.simulation.scenario import SimulationResult


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_metrics_csv(result: SimulationResult, path: Path) -> None:
    """Wide format: one row per (timestamp, cell) with all KPI columns."""
    path.parent.mkdir(parents=True, exist_ok=True)
    topo = result.scenario.topology
    with path.open("w", newline="", encoding="ascii") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("timestamp", "cell_id", "node_id", *METRIC_NAMES))
        for i, epoch in enumerate(result.epochs):
            for cell in topo.cell_ids:
                values = result.metrics[cell]
                writer.writerow((iso(int(epoch)), cell, topo.node_of(cell),
                                 *(f"{values[m][i]:.4f}" for m in METRIC_NAMES)))


def write_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")


def write_all(result: SimulationResult, out_dir: Path, cdr_seed: int | None = None) -> dict[str, Path]:
    """Writes metrics, events, deployments, ground truth and CDRs under `out_dir`."""
    paths = {
        "metrics": out_dir / "network_metrics" / "network_metrics.csv",
        "events": out_dir / "incidents" / "events.jsonl",
        "deployments": out_dir / "incidents" / "deployments.jsonl",
        "security": out_dir / "security" / "security_events.jsonl",
        "ground_truth": out_dir / "incidents" / "ground_truth.json",
        "call_logs": out_dir / "call_logs" / "call_logs.csv",
    }
    write_metrics_csv(result, paths["metrics"])
    write_jsonl([e.to_dict() for e in result.events], paths["events"])
    write_jsonl([d.to_dict() for d in result.deployments], paths["deployments"])
    write_jsonl([e.to_dict() for e in result.events if e.kind.value == "security"], paths["security"])
    truth = [{**t.__dict__, "incident_type": t.incident_type.value,
              "affected_cells": list(t.affected_cells)} for t in result.ground_truth]
    paths["ground_truth"].parent.mkdir(parents=True, exist_ok=True)
    paths["ground_truth"].write_text(json.dumps({
        "scenario": result.scenario.name, "seed": result.scenario.seed, "synthetic": True,
        "fingerprint": result.fingerprint(), "incidents": truth}, indent=2) + "\n", encoding="utf-8")
    write_cdr_csv(generate_cdrs(result, cdr_seed if cdr_seed is not None else result.scenario.seed),
                  paths["call_logs"])
    return paths
