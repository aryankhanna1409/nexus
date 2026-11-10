"""M3 acceptance tests: telemetry simulator, seeded incident, rollback, determinism."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from app.simulation import (
    METRIC_NAMES,
    Direction,
    IncidentSpec,
    IncidentType,
    Scenario,
    seeded_memory_leak_scenario,
    simulate,
)
from app.simulation.cdr import generate_cdrs, render_cdr_csv
from app.simulation.events import EventKind
from app.simulation.io import write_all
from app.simulation.metrics import METRIC_BY_NAME
from call_analyzer import analyze_call_log

from .conftest import REPO_ROOT

DEPLOY_MINUTE = 125
LEAK_CELLS = ["CELL-101", "CELL-102", "CELL-103", "CELL-104"]
OTHER_CELLS = [f"CELL-{n}" for n in range(105, 113)]
CHAIN = ["memory_utilization", "cpu_utilization", "latency_ms", "packet_loss_pct", "call_drop_rate"]


def onset(values: np.ndarray, start: int, direction: Direction, sigmas: float = 4.0,
          consecutive: int = 3) -> int | None:
    """First minute >= start where the metric leaves its pre-start band for 3 minutes.

    Band: mean +/- `sigmas` * std of the 60 minutes before `start`.
    """
    pre = values[start - 60:start]
    mean, std = float(pre.mean()), max(float(pre.std()), 1e-9)
    if direction is Direction.DOWN:
        outside = values < mean - sigmas * std
    else:
        outside = values > mean + sigmas * std
    for i in range(start, len(values) - consecutive + 1):
        if outside[i:i + consecutive].all():
            return i
    return None


@pytest.fixture(scope="module")
def seeded() -> object:
    return simulate(seeded_memory_leak_scenario())


@pytest.fixture(scope="module")
def healthy() -> object:
    return simulate(Scenario(name="healthy", seed=7))


# ---- Determinism ------------------------------------------------------------------


def test_same_seed_is_identical() -> None:
    a, b = simulate(seeded_memory_leak_scenario(seed=11)), simulate(seeded_memory_leak_scenario(seed=11))
    assert a.fingerprint() == b.fingerprint()
    assert render_cdr_csv(generate_cdrs(a, 11)) == render_cdr_csv(generate_cdrs(b, 11))


def test_different_seed_differs() -> None:
    prints = {simulate(seeded_memory_leak_scenario(seed=s)).fingerprint() for s in (1, 2, 3)}
    assert len(prints) == 3


# ---- Healthy baseline -------------------------------------------------------------------


def test_healthy_baseline_within_operating_ranges(healthy: object) -> None:
    for cell in healthy.scenario.topology.cell_ids:  # type: ignore[attr-defined]
        m = healthy.metrics[cell]  # type: ignore[attr-defined]
        assert m["cpu_utilization"].max() < 75
        assert m["memory_utilization"].max() < 70
        assert m["latency_ms"].max() < 35
        assert m["packet_loss_pct"].max() < 1.0
        assert m["call_drop_rate"].max() < 1.5
        assert m["handover_success_rate"].min() > 97
        assert m["call_setup_success_rate"].min() > 98
        np.testing.assert_allclose(m["handover_success_rate"] + m["handover_failure_rate"], 100.0)
        for name in METRIC_NAMES:
            spec = METRIC_BY_NAME[name]
            assert m[name].min() >= spec.lower and m[name].max() <= spec.upper


def test_series_are_autocorrelated_not_independent(healthy: object) -> None:
    latency = healthy.metrics["CELL-101"]["latency_ms"]  # type: ignore[attr-defined]
    detrended = latency - np.convolve(latency, np.ones(15) / 15, mode="same")
    lag1 = np.corrcoef(detrended[20:-20][:-1], detrended[20:-20][1:])[0, 1]
    assert lag1 > 0.3


def test_metric_catalogue_covers_spec_kpis() -> None:
    assert len(METRIC_NAMES) == 17
    for required in ("throughput", "latency", "packet_loss", "jitter", "rssi", "rsrp", "rsrq",
                     "sinr", "handover_success", "handover_failure", "call_setup_success",
                     "call_drop", "retransmission", "cpu", "memory", "active_users", "bandwidth"):
        assert any(name.startswith(required) for name in METRIC_NAMES), required


def test_background_deployment_is_on_an_unaffected_node(seeded: object) -> None:
    deployments = seeded.deployments  # type: ignore[attr-defined]
    assert [d.node_id for d in deployments] == ["pgw-3", "pgw-1"]
    assert deployments[0].epoch < deployments[1].epoch


# ---- Seeded memory-leak deployment (spec §24) --------------------------------------------


def test_seeded_deployment_event_at_1405(seeded: object) -> None:
    leak = [d for d in seeded.deployments if d.node_id == "pgw-1"]  # type: ignore[attr-defined]
    assert len(leak) == 1 and leak[0].to_version == "2.4.1"
    assert leak[0].epoch == int(seeded.epochs[DEPLOY_MINUTE])  # type: ignore[attr-defined]
    assert seeded.ground_truth[0].affected_cells == tuple(LEAK_CELLS)  # type: ignore[attr-defined]


@pytest.mark.parametrize("seed", [7, 8, 9])
def test_ordered_degradation_chain(seed: int) -> None:
    result = simulate(seeded_memory_leak_scenario(seed=seed))
    for cell in LEAK_CELLS:
        m = result.metrics[cell]
        onsets = {name: onset(m[name], DEPLOY_MINUTE, METRIC_BY_NAME[name].bad_direction)
                  for name in [*CHAIN, "throughput_mbps"]}
        assert all(v is not None for v in onsets.values()), (cell, onsets)
        chain = [onsets[name] for name in CHAIN]
        assert DEPLOY_MINUTE < chain[0] < chain[1], (cell, onsets)  # memory strictly before CPU
        assert chain == sorted(chain), (cell, onsets)  # cpu <= latency <= loss <= drops
        assert onsets["throughput_mbps"] >= onsets["latency_ms"], (cell, onsets)  # type: ignore[operator]


def test_unaffected_cells_identical_to_healthy_run(seeded: object, healthy: object) -> None:
    for cell in OTHER_CELLS:
        for name in METRIC_NAMES:
            np.testing.assert_array_equal(seeded.metrics[cell][name],  # type: ignore[attr-defined]
                                          healthy.metrics[cell][name])  # type: ignore[attr-defined]


def _spearman(x: np.ndarray, y: np.ndarray) -> float:
    rank_x = np.argsort(np.argsort(x)).astype(float)
    rank_y = np.argsort(np.argsort(y)).astype(float)
    return float(np.corrcoef(rank_x, rank_y)[0, 1])


def test_cpu_latency_correlation_strong_in_incident_weak_at_baseline(seeded: object) -> None:
    """Rank (Spearman) correlation: queueing latency is monotone but strongly non-linear in
    CPU, and CPU saturates at its clip, so Pearson understates the dependence."""
    for cell in LEAK_CELLS:
        m = seeded.metrics[cell]  # type: ignore[attr-defined]
        during = slice(DEPLOY_MINUTE, len(m["cpu_utilization"]))
        baseline = slice(DEPLOY_MINUTE - 60, DEPLOY_MINUTE)
        r_incident = _spearman(m["cpu_utilization"][during], m["latency_ms"][during])
        r_baseline = _spearman(m["cpu_utilization"][baseline], m["latency_ms"][baseline])
        assert r_incident > 0.7, (cell, r_incident)
        assert abs(r_baseline) < 0.5, (cell, r_baseline)


def test_application_logs_follow_memory_pressure(seeded: object) -> None:
    logs = [e for e in seeded.events  # type: ignore[attr-defined]
            if e.kind is EventKind.APPLICATION_LOG and e.node_id == "pgw-1" and "GC pause" in e.message]
    assert logs
    deploy_epoch = int(seeded.epochs[DEPLOY_MINUTE])  # type: ignore[attr-defined]
    assert min(e.epoch for e in logs) > deploy_epoch + 30 * 60


# ---- Rollback and recovery ------------------------------------------------------------------


def test_rollback_restores_counterfactual_baseline(healthy: object) -> None:
    rolled = simulate(seeded_memory_leak_scenario(rollback_minute=200))
    assert any(e.kind is EventKind.ROLLBACK for e in rolled.events)
    assert rolled.deployments[-1].rolled_back_epoch == int(rolled.epochs[200])
    for cell in LEAK_CELLS:
        for name in METRIC_NAMES:
            # Same noise streams: after the 3-minute restart the series equal the healthy run.
            np.testing.assert_allclose(rolled.metrics[cell][name][203:],
                                       healthy.metrics[cell][name][203:],  # type: ignore[attr-defined]
                                       rtol=0, atol=1e-9, err_msg=f"{cell}/{name}")
        assert rolled.metrics[cell]["latency_ms"][195:200].mean() > 60  # degraded before rollback


def test_without_rollback_degradation_persists(seeded: object, healthy: object) -> None:
    for cell in LEAK_CELLS:
        latency = seeded.metrics[cell]["latency_ms"][-30:]  # type: ignore[attr-defined]
        assert latency.mean() > 3 * healthy.metrics[cell]["latency_ms"][-30:].mean()  # type: ignore[attr-defined]


def test_rollback_validation() -> None:
    with pytest.raises(ValueError, match="deployment-induced"):
        simulate(Scenario(name="x", seed=1, rollback_minute=100))
    with pytest.raises(ValueError, match="inside"):
        simulate(seeded_memory_leak_scenario(rollback_minute=10_000))


# ---- All nine incident types -------------------------------------------------------------------

# type -> (target, {metric: expected direction of change in the incident window})
INCIDENT_EXPECTATIONS: dict[IncidentType, tuple[str, dict[str, str]]] = {
    IncidentType.OVERLOADED_BASE_STATION: ("CELL-106", {"active_users": "up", "cpu_utilization": "up",
                                                        "latency_ms": "up"}),
    IncidentType.FAILING_NETWORK_INTERFACE: ("CELL-106", {"packet_loss_pct": "up",
                                                          "retransmission_rate": "up",
                                                          "throughput_mbps": "down"}),
    IncidentType.PACKET_LOSS_BURST: ("CELL-106", {"packet_loss_pct": "up", "call_drop_rate": "up"}),
    IncidentType.ABNORMAL_TRAFFIC_SPIKE: ("CELL-106", {"active_users": "up",
                                                       "bandwidth_utilization": "up"}),
    IncidentType.DEGRADED_RADIO_SIGNAL: ("CELL-106", {"rsrp_dbm": "down", "sinr_db": "down",
                                                      "handover_failure_rate": "up",
                                                      "call_drop_rate": "up"}),
    IncidentType.SOFTWARE_DEPLOYMENT_REGRESSION: ("pgw-2", {"cpu_utilization": "up",
                                                            "latency_ms": "up"}),
    IncidentType.MEMORY_LEAK: ("pgw-2", {"memory_utilization": "up", "cpu_utilization": "up"}),
    IncidentType.SECURITY_ATTACK: ("CELL-106", {"active_users": "up", "cpu_utilization": "up"}),
    IncidentType.MISCONFIGURATION: ("CELL-106", {"handover_failure_rate": "up",
                                                 "call_setup_success_rate": "down"}),
}
EXPECTED_EVENTS: dict[IncidentType, EventKind] = {
    IncidentType.SOFTWARE_DEPLOYMENT_REGRESSION: EventKind.DEPLOYMENT,
    IncidentType.MEMORY_LEAK: EventKind.DEPLOYMENT,
    IncidentType.SECURITY_ATTACK: EventKind.SECURITY,
    IncidentType.MISCONFIGURATION: EventKind.CONFIG_CHANGE,
    IncidentType.FAILING_NETWORK_INTERFACE: EventKind.APPLICATION_LOG,
}


@pytest.mark.parametrize("incident_type", list(IncidentType))
def test_each_incident_type(incident_type: IncidentType, healthy: object) -> None:
    target, effects = INCIDENT_EXPECTATIONS[incident_type]
    spec = IncidentSpec(incident_type, target, start_minute=120, duration_minutes=60)
    result = simulate(Scenario(name=incident_type.value, seed=7, incidents=(spec,),
                               background_events=False))
    truth = result.ground_truth[0]
    window = slice(150, 180)  # second half of the incident (after ramps)
    for cell in result.scenario.topology.cell_ids:
        for name in METRIC_NAMES:
            same = np.array_equal(result.metrics[cell][name], healthy.metrics[cell][name])  # type: ignore[attr-defined]
            if cell not in truth.affected_cells:
                assert same, f"{incident_type}: {cell}/{name} changed but cell is not affected"
    for cell in truth.affected_cells:
        for name, direction in effects.items():
            during = result.metrics[cell][name][window].mean()
            reference = healthy.metrics[cell][name][window].mean()  # type: ignore[attr-defined]
            delta = during - reference
            # Margin: twice the minute-to-minute noise of the healthy series.
            scale = max(2.0 * float(healthy.metrics[cell][name][window].std()), 0.25)  # type: ignore[attr-defined]
            if direction == "up":
                assert delta > scale, (incident_type, cell, name, during, reference)
            else:
                assert delta < -scale, (incident_type, cell, name, during, reference)
        # Effects end with the incident (memory-leak restart decays within 3 minutes).
        after = slice(190, 220)
        for name in effects:
            np.testing.assert_allclose(result.metrics[cell][name][after],
                                       healthy.metrics[cell][name][after],  # type: ignore[attr-defined]
                                       atol=1e-9, err_msg=f"{incident_type} {cell}/{name}")
    if incident_type in EXPECTED_EVENTS:
        kinds = {e.kind for e in result.events}
        assert EXPECTED_EVENTS[incident_type] in kinds
    if incident_type is IncidentType.SECURITY_ATTACK:
        security = [e for e in result.events if e.kind is EventKind.SECURITY]
        assert all(e.attributes["source_ip"].startswith("203.0.113.") for e in security)
        assert all(truth.start_epoch <= e.epoch < truth.end_epoch for e in security)


def test_invalid_incident_specs_rejected() -> None:
    bad = [
        IncidentSpec(IncidentType.MEMORY_LEAK, "CELL-101", 10, 10),  # node-scoped needs a node
        IncidentSpec(IncidentType.PACKET_LOSS_BURST, "CELL-999", 10, 10),
        IncidentSpec(IncidentType.PACKET_LOSS_BURST, "CELL-101", 10, 0),
        IncidentSpec(IncidentType.PACKET_LOSS_BURST, "CELL-101", 999, 10),
        IncidentSpec(IncidentType.PACKET_LOSS_BURST, "CELL-101", 10, 10, intensity=9),
    ]
    for spec in bad:
        with pytest.raises((ValueError, KeyError)):
            simulate(Scenario(name="bad", seed=1, incidents=(spec,)))


# ---- CDRs analysed by the C library ------------------------------------------------------------


def test_cdrs_of_seeded_incident_flag_only_affected_cells(seeded: object, tmp_path: Path) -> None:
    path = tmp_path / "calls.csv"
    path.write_text(render_cdr_csv(generate_cdrs(seeded, 7)), encoding="ascii")  # type: ignore[arg-type]
    result = analyze_call_log(path, strict=True)
    flagged = {a["subject"] for a in result["anomalies"] if a["category"] == "cell"}
    assert flagged == set(LEAK_CELLS)


def test_cdrs_of_healthy_run_have_no_cell_anomalies(healthy: object, tmp_path: Path) -> None:
    path = tmp_path / "calls.csv"
    path.write_text(render_cdr_csv(generate_cdrs(healthy, 7)), encoding="ascii")  # type: ignore[arg-type]
    result = analyze_call_log(path, strict=True)
    assert [a for a in result["anomalies"] if a["category"] == "cell"] == []
    assert result["total_calls"] > 15000


# ---- Files and CLIs ----------------------------------------------------------------------------


def test_write_all_outputs(seeded: object, tmp_path: Path) -> None:
    paths = write_all(seeded, tmp_path)  # type: ignore[arg-type]
    header = paths["metrics"].read_text().splitlines()[0].split(",")
    assert header == ["timestamp", "cell_id", "node_id", *METRIC_NAMES]
    assert len(paths["metrics"].read_text().splitlines()) == 1 + 360 * 12
    truth = json.loads(paths["ground_truth"].read_text())
    assert truth["synthetic"] is True and truth["incidents"][0]["incident_type"] == "memory_leak"
    events = [json.loads(line) for line in paths["events"].read_text().splitlines()]
    assert [e["epoch"] for e in events] == sorted(e["epoch"] for e in events)


def test_generate_network_metrics_cli(tmp_path: Path) -> None:
    script = REPO_ROOT / "scripts" / "generate_network_metrics.py"
    for out in ("a", "b"):
        proc = subprocess.run([sys.executable, str(script), "--seed", "3", "--out-dir", str(tmp_path / out)],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stderr
    for rel in ("network_metrics/network_metrics.csv", "call_logs/call_logs.csv", "incidents/events.jsonl"):
        assert (tmp_path / "a" / rel).read_bytes() == (tmp_path / "b" / rel).read_bytes(), rel


def test_simulate_incident_cli_rejects_bad_target(tmp_path: Path) -> None:
    script = REPO_ROOT / "scripts" / "simulate_incident.py"
    proc = subprocess.run([sys.executable, str(script), "--type", "memory_leak", "--target", "CELL-101",
                           "--out-dir", str(tmp_path)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 2
    ok = subprocess.run([sys.executable, str(script), "--type", "misconfiguration", "--target", "CELL-105",
                         "--out-dir", str(tmp_path)], capture_output=True, text=True, timeout=120)
    assert ok.returncode == 0, ok.stderr
    assert (tmp_path / "incidents" / "ground_truth.json").exists()
