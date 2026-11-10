"""M4 acceptance tests: detectors on generic series, seeded incident, false positives."""

from __future__ import annotations

import ast
import math
from pathlib import Path

import numpy as np
import pytest

from app.analytics import DetectionConfig, MetricSeries, detect_anomalies, detect_series, series_from_simulation
from app.analytics.detectors import ewma, evaluate_series, moving_average, rolling_std, score_from_z
from app.analytics.sources import series_from_csv
from app.simulation import Scenario, seeded_memory_leak_scenario, simulate
from app.simulation.io import write_metrics_csv

ANALYTICS_DIR = Path(__file__).resolve().parents[1] / "app" / "analytics"
T0 = 1_772_366_400  # 2026-03-01T12:00:00Z


def make_series(values: np.ndarray, metric: str = "latency_ms", epochs: np.ndarray | None = None) -> MetricSeries:
    if epochs is None:
        epochs = T0 + 60 * np.arange(len(values), dtype=np.int64)
    return MetricSeries(metric, "CELL-T", "pgw-T", epochs, np.asarray(values, dtype=float))


def noise(n: int, seed: int = 1, sigma: float = 1.0) -> np.ndarray:
    return np.random.default_rng(seed).normal(0.0, sigma, n)


# ---- Building blocks -------------------------------------------------------------------


def test_moving_average_and_rolling_std_match_reference() -> None:
    rng = np.random.default_rng(3)
    epochs = T0 + np.cumsum(rng.integers(20, 150, 200)).astype(np.int64)
    values = rng.normal(10, 2, 200)
    ma, sd = moving_average(epochs, values, 600), rolling_std(epochs, values, 600)
    for i in range(len(values)):
        window = values[(epochs > epochs[i] - 600) & (epochs <= epochs[i])]
        assert ma[i] == pytest.approx(window.mean())
        assert sd[i] == pytest.approx(window.std())


def test_ewma_is_time_aware() -> None:
    epochs = np.array([0, 60, 120, 1020], dtype=np.int64)
    values = np.array([0.0, 10.0, 10.0, 10.0])
    out = ewma(epochs, values, tau_seconds=300)
    assert out[1] == pytest.approx(10 * (1 - math.exp(-60 / 300)))
    # A long gap moves the EWMA further than a short one.
    assert (out[3] - out[2]) > (out[2] - out[1]) * 0.9


def test_score_mapping_matches_c_library_convention() -> None:
    assert score_from_z(4.0, 4.0) == pytest.approx(0.5)
    assert score_from_z(0.0, 4.0) == 0.0 and score_from_z(-3, 4.0) == 0.0
    assert score_from_z(12.0, 4.0) == pytest.approx(0.875)


# ---- Generic patterns -------------------------------------------------------------------


def test_healthy_noise_produces_no_anomalies() -> None:
    for seed in range(10):
        assert detect_series(make_series(20 + noise(600, seed))) == []


def test_step_change_detected_at_onset() -> None:
    values = 20 + noise(240)
    values[180:] += 30
    anomalies = detect_series(make_series(values))
    assert len(anomalies) == 1
    a = anomalies[0]
    assert a.start_epoch == T0 + 180 * 60
    assert a.end_epoch == T0 + 239 * 60
    assert a.baseline == pytest.approx(20, abs=0.5)
    assert a.value > 45 and a.severity in {"high", "critical"}
    assert {"zscore", "ewma"} <= set(a.detectors)


def test_single_point_spike_detected() -> None:
    values = 20 + noise(240)
    values[150] += 40
    anomalies = detect_series(make_series(values))
    assert [(a.start_epoch, a.points) for a in anomalies] == [(T0 + 150 * 60, 1)]


def test_sustained_shift_below_practical_delta_ignored() -> None:
    values = 20 + noise(240, sigma=0.2)
    values[150:210] += 5.0  # z = 5 (noise floor 1 ms) but below latency's 6 ms practical delta
    assert detect_series(make_series(values)) == []
    values[150:210] += 2.0  # 7 ms: now operationally meaningful
    assert len(detect_series(make_series(values))) == 1


def test_slow_ramp_detected_without_baseline_drift() -> None:
    values = 20 + noise(400)
    values[200:] += np.linspace(0, 60, 200)  # +0.3 ms/min: never a step
    anomalies = detect_series(make_series(values))
    assert len(anomalies) == 1
    a = anomalies[0]
    assert T0 + 200 * 60 < a.start_epoch < T0 + 260 * 60
    assert a.end_epoch == T0 + 399 * 60  # baseline frozen, so the ramp stays anomalous
    assert a.baseline == pytest.approx(20, abs=1.0)


def test_down_direction_metric() -> None:
    values = 400 + noise(240, sigma=8)
    values[180:] -= 150
    anomalies = detect_series(make_series(values, "throughput_mbps"))
    assert len(anomalies) == 1 and anomalies[0].value < 300
    up = 400 + noise(240, sigma=8)
    up[180:] += 150  # throughput going up is not bad
    assert detect_series(make_series(up, "throughput_mbps")) == []


def test_static_threshold_detects_without_history() -> None:
    values = np.full(10, 97.0)  # CPU above the critical threshold from the start
    anomalies = detect_series(make_series(values, "cpu_utilization"))
    assert len(anomalies) == 1
    assert anomalies[0].detectors == ("threshold",) and anomalies[0].severity == "critical"


def test_rate_of_change_detector_contributes() -> None:
    values = 20 + noise(240, sigma=0.5)
    values[200:] += 25
    a = detect_series(make_series(values))[0]
    assert "rate_of_change" in a.detectors


def test_irregular_sampling_and_gaps() -> None:
    rng = np.random.default_rng(5)
    deltas = rng.integers(30, 120, 400)
    deltas[150] = 1800  # 30-minute telemetry gap
    epochs = T0 + np.cumsum(deltas).astype(np.int64)
    values = 20 + noise(400, seed=6)
    assert detect_series(make_series(values, epochs=epochs)) == []
    values[300:] += 30
    anomalies = detect_series(make_series(values, epochs=epochs))
    assert len(anomalies) == 1 and anomalies[0].start_epoch == int(epochs[300])


def test_non_finite_values_skipped() -> None:
    values = 20 + noise(240)
    values[[10, 50, 100]] = [np.nan, np.inf, -np.inf]
    assert detect_series(make_series(values)) == []
    results = evaluate_series(T0 + 60 * np.arange(240, dtype=np.int64), values,
                              DetectionConfig().rules["latency_ms"], DetectionConfig())
    assert len(results) == 237


def test_constant_series_uses_noise_floor() -> None:
    values = np.full(240, 20.0)
    assert detect_series(make_series(values)) == []
    values[200:] = 27.0  # +7 ms over a zero-variance baseline: above floor and practical delta
    assert len(detect_series(make_series(values))) == 1


def test_short_and_empty_series() -> None:
    assert detect_series(make_series(np.array([]))) == []
    assert detect_series(make_series(np.array([20.0, 21.0, 22.0]))) == []


def test_invalid_inputs_rejected() -> None:
    with pytest.raises(ValueError, match="increasing"):
        detect_series(make_series(np.ones(3), epochs=np.array([3, 2, 1], dtype=np.int64)))
    with pytest.raises(ValueError, match="equal length"):
        detect_series(MetricSeries("latency_ms", "c", "n", np.arange(3, dtype=np.int64), np.ones(4)))
    with pytest.raises(KeyError):
        detect_series(make_series(np.ones(3), metric="unknown_metric"))
    with pytest.raises(ValueError):
        detect_series(make_series(np.ones(3)), DetectionConfig(window_seconds=10))


def test_permanent_shift_accepted_after_rebaseline_period() -> None:
    cfg = DetectionConfig(rebaseline_after_seconds=7200)
    values = 20 + noise(600)
    values[200:] += 30
    anomalies = detect_series(make_series(values), cfg)
    assert len(anomalies) == 1
    assert anomalies[0].end_epoch < T0 + (200 + 125) * 60  # episode ends once re-baselined


# ---- Seeded incident ---------------------------------------------------------------------

LEAK_CELLS = {"CELL-101", "CELL-102", "CELL-103", "CELL-104"}
SPEC_SYMPTOMS = {"memory_utilization", "cpu_utilization", "latency_ms", "packet_loss_pct",
                 "throughput_mbps", "call_drop_rate"}


@pytest.fixture(scope="module")
def seeded_anomalies() -> list:
    return detect_anomalies(series_from_simulation(simulate(seeded_memory_leak_scenario())))


def test_seeded_incident_symptoms_detected_on_affected_cells_only(seeded_anomalies: list) -> None:
    deploy_epoch = T0 + 125 * 60
    assert {a.cell_id for a in seeded_anomalies} == LEAK_CELLS
    for cell in LEAK_CELLS:
        metrics = {a.metric for a in seeded_anomalies if a.cell_id == cell}
        assert SPEC_SYMPTOMS <= metrics, (cell, metrics)
    assert all(a.start_epoch > deploy_epoch for a in seeded_anomalies)


def test_seeded_onsets_follow_causal_order(seeded_anomalies: list) -> None:
    for cell in LEAK_CELLS:
        onset = {a.metric: a.start_epoch for a in seeded_anomalies if a.cell_id == cell}
        chain = [onset[m] for m in ("memory_utilization", "cpu_utilization", "latency_ms",
                                    "packet_loss_pct", "call_drop_rate")]
        assert chain == sorted(chain) and chain[0] < chain[1], (cell, onset)
        assert onset["throughput_mbps"] >= onset["latency_ms"]


def test_seeded_anomaly_objects_follow_spec_schema(seeded_anomalies: list) -> None:
    loss = next(a for a in seeded_anomalies if a.cell_id == "CELL-101" and a.metric == "packet_loss_pct")
    record = loss.to_dict()
    for key in ("metric", "timestamp", "value", "baseline", "severity", "anomaly_score", "related_metrics"):
        assert key in record
    assert record["value"] > 5 * record["baseline"]
    assert record["severity"] == "critical" and 0.9 <= record["anomaly_score"] <= 1.0
    assert {"latency_ms", "call_drop_rate", "throughput_mbps"} <= set(record["related_metrics"])
    assert record["timestamp"].endswith("Z")
    assert len({a.anomaly_id for a in seeded_anomalies}) == len(seeded_anomalies)


def test_rollback_ends_anomaly_episodes() -> None:
    result = simulate(seeded_memory_leak_scenario(rollback_minute=200))
    anomalies = detect_anomalies(series_from_simulation(result))
    rollback_epoch = T0 + 200 * 60
    assert anomalies
    assert all(a.end_epoch <= rollback_epoch + 5 * 60 for a in anomalies)


def test_healthy_false_positive_rate_within_bound() -> None:
    """Acceptance bound: <= 1 false-positive episode per 100 series-days, none high/critical.

    8 seeds x 12 cells x 17 KPIs x 24 h = 1,632 series-days (2.35 M samples).
    Measured on 20 seeds (2026-10-19): 11 episodes / 4,080 series-days = 0.27 per 100,
    all low/medium severity.
    """
    episodes = []
    for seed in range(8):
        result = simulate(Scenario(name="healthy", seed=seed, minutes=1440))
        episodes += detect_anomalies(series_from_simulation(result))
    series_days = 8 * 12 * 17
    assert len(episodes) <= series_days / 100, [(a.cell_id, a.metric, a.severity) for a in episodes]
    assert all(a.severity in {"low", "medium"} for a in episodes)


def test_csv_source_round_trip(tmp_path: Path) -> None:
    result = simulate(seeded_memory_leak_scenario())
    write_metrics_csv(result, tmp_path / "m.csv")
    from_csv = detect_anomalies(series_from_csv(tmp_path / "m.csv"))
    direct = detect_anomalies(series_from_simulation(result))
    assert [(a.cell_id, a.metric, a.start_epoch) for a in from_csv] == \
        [(a.cell_id, a.metric, a.start_epoch) for a in direct]


def test_detection_engine_does_not_depend_on_simulator_internals() -> None:
    """Separation: only the KPI catalogue (metric names/directions) may be imported."""
    for module in ("detectors.py", "engine.py", "config.py"):
        tree = ast.parse((ANALYTICS_DIR / module).read_text())
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        simulation = {m for m in imported if m and m.startswith("app.simulation")}
        assert simulation <= {"app.simulation.metrics"}, (module, simulation)
