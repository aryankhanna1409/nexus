"""Tests for scripts/generate_call_logs.py, including detection by the real C library."""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from call_analyzer import analyze_call_log

from .conftest import GENERATOR_PATH

CELL_ANOMALY_TYPES = {"cell_drop_rate", "cell_packet_loss", "cell_low_signal"}


def _write(generator: ModuleType, path: Path, **config: object) -> Path:
    rows = generator.generate_rows(generator.GeneratorConfig(**config))
    path.write_text(generator.render_csv(rows), encoding="ascii", newline="")
    return path


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(GENERATOR_PATH), *args],
                          capture_output=True, text=True, timeout=120)


# ---- Determinism -----------------------------------------------------------------


def test_same_seed_is_byte_identical(generator: ModuleType) -> None:
    a = generator.render_csv(generator.generate_rows(generator.GeneratorConfig(seed=7)))
    b = generator.render_csv(generator.generate_rows(generator.GeneratorConfig(seed=7)))
    assert a == b


def test_cli_same_seed_is_byte_identical(tmp_path: Path) -> None:
    for name in ("a.csv", "b.csv"):
        proc = _run_cli("--seed", "11", "--output", str(tmp_path / name))
        assert proc.returncode == 0, proc.stderr
    assert (tmp_path / "a.csv").read_bytes() == (tmp_path / "b.csv").read_bytes()


def test_different_seed_changes_output(generator: ModuleType) -> None:
    outputs = {
        hashlib.sha256(generator.render_csv(
            generator.generate_rows(generator.GeneratorConfig(seed=seed))).encode()).hexdigest()
        for seed in (1, 2, 3)
    }
    assert len(outputs) == 3


# ---- Format ------------------------------------------------------------------------


def test_output_is_valid_for_the_c_parser_in_strict_mode(generated_log: Path) -> None:
    result = analyze_call_log(generated_log, strict=True)
    report = result["parse_report"]
    assert report["header_present"] is True
    assert report["records_rejected"] == 0
    assert report["records_parsed"] == result["total_calls"] > 0


def test_rows_sorted_and_within_period(generator: ModuleType) -> None:
    config = generator.GeneratorConfig(seed=5)
    rows = generator.generate_rows(config)
    epochs = [r.epoch for r in rows]
    assert epochs == sorted(epochs)
    start = int(config.start.timestamp())
    assert start <= epochs[0] and epochs[-1] < start + config.duration_minutes * 60
    assert all(r.caller != r.callee for r in rows)
    assert {r.cell_id for r in rows} == set(config.cell_ids())


def test_header_matches_library_schema(generated_log: Path) -> None:
    with generated_log.open(newline="") as handle:
        header = next(csv.reader(handle))
    assert header == ["timestamp", "caller", "callee", "cell_id", "duration",
                      "status_code", "signal_strength", "packet_loss"]


# ---- Healthy baseline and seeded fault -------------------------------------------------


@pytest.mark.parametrize("seed", range(5))
def test_healthy_baseline_has_no_anomalies(generator: ModuleType, tmp_path: Path, seed: int) -> None:
    path = _write(generator, tmp_path / "healthy.csv", seed=seed, fault=None)
    result = analyze_call_log(path)
    assert result["anomalies"] == [], [a["description"] for a in result["anomalies"]]
    assert result["drop_rate"] < 0.03


@pytest.mark.parametrize("seed", range(10))
def test_seeded_faulty_cell_detected_by_c_library(
    generator: ModuleType, tmp_path: Path, seed: int
) -> None:
    path = _write(generator, tmp_path / "fault.csv", seed=seed)
    result = analyze_call_log(path)
    cell_anomalies = [a for a in result["anomalies"] if a["category"] == "cell"]
    flagged = {(a["subject"], a["type"]) for a in cell_anomalies}
    assert ("CELL-107", "cell_drop_rate") in flagged
    assert ("CELL-107", "cell_packet_loss") in flagged
    assert {a["subject"] for a in cell_anomalies} == {"CELL-107"}  # no other cell blamed
    drop = next(a for a in cell_anomalies if a["type"] == "cell_drop_rate")
    assert drop["severity"] in {"high", "critical"}
    assert drop["value"] > 0.08 and drop["baseline"] < 0.03


def test_detection_rates_over_50_seeds(generator: ModuleType, tmp_path: Path) -> None:
    """Acceptance check over 50 seeds (generation is deterministic, so this is reproducible).

    Observed on 2026-10-19: drop rate 50/50, packet loss 50/50, low signal 49/50,
    other cells flagged 0, healthy-baseline anomalies 0/50. The thresholds below are the
    acceptance criteria: the low-signal penalty is diluted over the whole log, so it is
    required in >= 96% of seeds rather than all of them.
    """
    hits: dict[str, int] = {t: 0 for t in CELL_ANOMALY_TYPES}
    wrong_cells: list[tuple[int, str, str]] = []
    healthy_anomalies: list[tuple[int, str]] = []
    for seed in range(50):
        result = analyze_call_log(_write(generator, tmp_path / "f.csv", seed=seed))
        for a in result["anomalies"]:
            if a["category"] != "cell":
                continue
            if a["subject"] != "CELL-107":
                wrong_cells.append((seed, a["subject"], a["type"]))
            elif a["type"] in hits:
                hits[a["type"]] += 1
        healthy = analyze_call_log(_write(generator, tmp_path / "h.csv", seed=seed, fault=None))
        healthy_anomalies += [(seed, a["description"]) for a in healthy["anomalies"]]
    assert hits["cell_drop_rate"] == 50
    assert hits["cell_packet_loss"] == 50
    assert hits["cell_low_signal"] >= 48, hits
    assert wrong_cells == []
    assert healthy_anomalies == []


def test_faulty_cell_is_configurable(generator: ModuleType, tmp_path: Path) -> None:
    fault = generator.FaultSpec(cell_id="CELL-103", start_minute=10, duration_minutes=90)
    result = analyze_call_log(_write(generator, tmp_path / "c103.csv", seed=3, fault=fault))
    flagged = {(a["subject"], a["type"]) for a in result["anomalies"] if a["category"] == "cell"}
    assert ("CELL-103", "cell_drop_rate") in flagged
    assert all(subject == "CELL-103" for subject, _ in flagged)


def test_degradation_pattern_is_confined_to_fault_window(generator: ModuleType) -> None:
    config = generator.GeneratorConfig(seed=9)
    fault = config.fault
    start = int(config.start.timestamp())
    lo = start + int(fault.start_minute * 60)
    hi = lo + int(fault.duration_minutes * 60)
    rows = generator.generate_rows(config)

    def mean(values: list[int]) -> float:
        return sum(values) / len(values)

    inside = [r for r in rows if r.cell_id == fault.cell_id and lo <= r.epoch < hi]
    before = [r for r in rows if r.cell_id == fault.cell_id and r.epoch < lo]
    others_inside = [r for r in rows if r.cell_id != fault.cell_id and lo <= r.epoch < hi]
    assert mean([r.signal_strength for r in inside]) < mean([r.signal_strength for r in before]) - 10
    assert mean([r.packet_loss for r in inside]) > mean([r.packet_loss for r in before]) + 5
    drops = lambda rs: sum(900 <= r.status_code <= 999 for r in rs) / len(rs)  # noqa: E731
    assert drops(inside) > 0.15
    assert drops(before) < 0.05 and drops(others_inside) < 0.05


# ---- Configuration and CLI --------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"cells": 0},
        {"duration_minutes": 0},
        {"calls_per_minute": 0},
        {"subscribers": 1},
    ],
)
def test_invalid_config_rejected(generator: ModuleType, overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        generator.generate_rows(generator.GeneratorConfig(seed=1, **overrides))


@pytest.mark.parametrize(
    "fault_kwargs",
    [
        {"cell_id": "CELL-999"},
        {"cell_id": "CELL-101", "start_minute": 100, "duration_minutes": 60},
        {"cell_id": "CELL-101", "max_drop_rate": 1.5},
        {"cell_id": "CELL-101", "duration_minutes": 0},
    ],
)
def test_invalid_fault_rejected(generator: ModuleType, fault_kwargs: dict[str, object]) -> None:
    fault = generator.FaultSpec(**fault_kwargs)
    with pytest.raises(ValueError):
        generator.generate_rows(generator.GeneratorConfig(seed=1, fault=fault))


def test_cli_rejects_unknown_cell(tmp_path: Path) -> None:
    proc = _run_cli("--faulty-cell", "CELL-999", "--output", str(tmp_path / "x.csv"))
    assert proc.returncode == 2
    assert "CELL-999" in proc.stderr
    assert not (tmp_path / "x.csv").exists()


def test_cli_manifest_records_ground_truth(tmp_path: Path) -> None:
    out, manifest_path = tmp_path / "logs" / "calls.csv", tmp_path / "logs" / "calls.json"
    proc = _run_cli("--seed", "21", "--faulty-cell", "CELL-104", "--output", str(out),
                    "--manifest", str(manifest_path))
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads(manifest_path.read_text())
    csv_bytes = out.read_bytes()
    assert manifest["seed"] == 21
    assert manifest["synthetic"] is True
    assert manifest["sha256"] == hashlib.sha256(csv_bytes).hexdigest()
    assert manifest["rows"] == csv_bytes.count(b"\n") - 1
    assert manifest["fault"]["cell_id"] == "CELL-104"
    assert manifest["fault"]["start"] == "2026-03-01T14:45:00Z"
    assert manifest["fault"]["end"] == "2026-03-01T15:45:00Z"


def test_cli_healthy_baseline(tmp_path: Path) -> None:
    proc = _run_cli("--faulty-cell", "none", "--output", str(tmp_path / "h.csv"),
                    "--manifest", str(tmp_path / "h.json"))
    assert proc.returncode == 0, proc.stderr
    assert json.loads((tmp_path / "h.json").read_text())["fault"] is None
    assert "healthy baseline" in proc.stderr
