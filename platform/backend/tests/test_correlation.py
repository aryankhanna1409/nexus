"""M5 acceptance tests: correlation of anomalies, call anomalies and events into incidents."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from app.analytics import detect_anomalies, series_from_simulation
from app.analytics.causal_graph import chain_consistency
from app.analytics.correlation import (
    CorrelationConfig,
    EventType,
    OperationalEvent,
    correlate,
    lagged_correlation,
)
from app.analytics.engine import MetricAnomaly
from app.analytics.sources import events_from_simulation, series_lookup
from app.simulation import IncidentSpec, IncidentType, Scenario, seeded_memory_leak_scenario, simulate
from app.simulation.cdr import generate_cdrs, write_cdr_csv
from call_analyzer import analyze_call_log

T0 = 1_772_366_400  # 2026-03-01T12:00:00Z
DEPLOY = T0 + 125 * 60
LEAK_CELLS = ["CELL-101", "CELL-102", "CELL-103", "CELL-104"]


def anomaly(metric: str, cell: str, node: str, start_min: int, end_min: int,
            severity: str = "critical") -> MetricAnomaly:
    return MetricAnomaly(f"ANOM-{metric}-{cell}-{start_min}", metric, cell, node,
                         T0 + start_min * 60, T0 + end_min * 60, 10.0, 1.0, 0.95, severity,
                         ("zscore",), end_min - start_min + 1)


@pytest.fixture(scope="module")
def seeded(tmp_path_factory: pytest.TempPathFactory) -> dict:
    result = simulate(seeded_memory_leak_scenario())
    series = series_from_simulation(result)
    path = tmp_path_factory.mktemp("cdr") / "calls.csv"
    write_cdr_csv(generate_cdrs(result, 7), path)
    calls = analyze_call_log(path)["anomalies"]
    incidents = correlate(detect_anomalies(series), events_from_simulation(result), calls,
                          series_lookup(series))
    return {"incidents": incidents, "result": result, "calls": calls}


# ---- Seeded scenario --------------------------------------------------------------------


def test_seeded_scenario_yields_one_incident(seeded: dict) -> None:
    incidents = seeded["incidents"]
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.incident_id == "INC-2026-001"
    assert list(inc.affected_cells) == LEAK_CELLS and inc.affected_nodes == ("pgw-1",)
    assert inc.severity == "CRITICAL"
    record = inc.to_dict()
    for key in ("incident_id", "severity", "start_time", "affected_cells", "symptoms", "events",
                "suspected_causes", "confidence"):
        assert key in record


def test_seeded_deployment_is_leading_hypothesis_with_evidence(seeded: dict) -> None:
    inc = seeded["incidents"][0]
    top = inc.suspected_causes[0]
    assert top.cause_type == "deployment_regression"
    assert "2.4.1" in top.description and "pgw-1" in top.description
    deployment_events = [e for e in events_from_simulation(seeded["result"])
                         if e.type is EventType.DEPLOYMENT and e.node_id == "pgw-1"]
    assert top.evidence == (deployment_events[0].event_id,)
    assert top.score > inc.suspected_causes[1].score + 0.1
    assert 0.8 <= inc.confidence <= 0.95
    assert all(c.to_dict()["status"] == "hypothesis" for c in inc.suspected_causes)


def test_seeded_distractor_deployment_is_excluded_with_reason(seeded: dict) -> None:
    excluded = seeded["incidents"][0].excluded_candidates
    assert len(excluded) == 1
    assert "pgw-3" in excluded[0]["description"] and "outside the affected nodes" in excluded[0]["reason"]


def test_seeded_timeline_is_ordered_and_starts_with_deployment(seeded: dict) -> None:
    timeline = seeded["incidents"][0].events
    epochs = [e.epoch for e in timeline]
    assert epochs == sorted(epochs)
    assert timeline[0].type == "deployment" and timeline[0].epoch == DEPLOY
    created = next(e for e in timeline if e.type == "incident_created")
    first_symptom = min(e.epoch for e in timeline if e.type == "metric_anomaly")
    assert created.epoch > first_symptom
    assert any(e.type == "application_log" for e in timeline)


def test_seeded_symptoms_and_causal_chain(seeded: dict) -> None:
    inc = seeded["incidents"][0]
    metrics = [s.metric for s in inc.symptoms]
    for required in ("memory_utilization", "cpu_utilization", "latency_ms", "packet_loss_pct",
                     "throughput_mbps", "call_drop_rate"):
        assert required in metrics
    assert metrics[0] == "memory_utilization"
    assert inc.chain_consistency == 1.0
    assert inc.causal_chain[0]["from"] == "memory_utilization"
    assert all(link["lag_seconds"] >= 0 for link in inc.causal_chain)
    assert all("xcorr" in link for link in inc.causal_chain)


def test_seeded_call_evidence_comes_from_c_library(seeded: dict) -> None:
    evidence = seeded["incidents"][0].call_evidence
    assert evidence
    cells = {e["subject"] for e in evidence if e["category"] == "cell"}
    assert cells == set(LEAK_CELLS)


def test_seeded_caveats_disclaim_causation(seeded: dict) -> None:
    assert any("does not establish causation" in c for c in seeded["incidents"][0].caveats)


# ---- Each incident type ------------------------------------------------------------------

EXPECTED_TOP_CAUSE = {
    IncidentType.OVERLOADED_BASE_STATION: ("CELL-106", 60, "traffic_overload"),
    IncidentType.FAILING_NETWORK_INTERFACE: ("CELL-106", 60, "transport_fault"),
    IncidentType.PACKET_LOSS_BURST: ("CELL-106", 8, "transport_fault"),
    IncidentType.ABNORMAL_TRAFFIC_SPIKE: ("CELL-106", 20, "traffic_overload"),
    IncidentType.DEGRADED_RADIO_SIGNAL: ("CELL-106", 60, "radio_degradation"),
    IncidentType.SOFTWARE_DEPLOYMENT_REGRESSION: ("pgw-2", 60, "deployment_regression"),
    IncidentType.MEMORY_LEAK: ("pgw-2", 200, "deployment_regression"),
    IncidentType.SECURITY_ATTACK: ("CELL-106", 60, "security_attack"),
    IncidentType.MISCONFIGURATION: ("CELL-106", 60, "configuration_change"),
}


@pytest.mark.parametrize("incident_type", list(IncidentType))
def test_top_cause_per_incident_type(incident_type: IncidentType) -> None:
    target, duration, expected = EXPECTED_TOP_CAUSE[incident_type]
    result = simulate(Scenario(name=incident_type.value, seed=7,
                               incidents=(IncidentSpec(incident_type, target, 120, duration),)))
    incidents = correlate(detect_anomalies(series_from_simulation(result)), events_from_simulation(result))
    assert len(incidents) == 1, [i.to_dict()["affected_cells"] for i in incidents]
    inc = incidents[0]
    assert inc.suspected_causes[0].cause_type == expected
    assert set(inc.affected_cells) == set(result.ground_truth[0].affected_cells)
    assert 0 < inc.confidence <= 0.95
    if expected in ("traffic_overload", "transport_fault", "radio_degradation"):
        assert any("No triggering event" in c for c in inc.caveats)
        assert inc.confidence < 0.7  # symptom-only hypotheses carry less confidence


# ---- Multiple incidents and boundaries ------------------------------------------------------


def test_two_concurrent_incidents_stay_separate() -> None:
    result = simulate(Scenario(name="two", seed=7, incidents=(
        IncidentSpec(IncidentType.MEMORY_LEAK, "pgw-1", 125, 235),
        IncidentSpec(IncidentType.DEGRADED_RADIO_SIGNAL, "CELL-110", 200, 60))))
    incidents = correlate(detect_anomalies(series_from_simulation(result)), events_from_simulation(result))
    assert [i.incident_id for i in incidents] == ["INC-2026-001", "INC-2026-002"]
    assert incidents[0].affected_nodes == ("pgw-1",) and incidents[1].affected_cells == ("CELL-110",)
    assert incidents[0].suspected_causes[0].cause_type == "deployment_regression"
    assert incidents[1].suspected_causes[0].cause_type == "radio_degradation"


def test_isolated_single_metric_anomaly_is_not_an_incident() -> None:
    assert correlate([anomaly("rssi_dbm", "CELL-101", "pgw-1", 100, 102, "low")]) == []


@pytest.mark.parametrize("seed", [0, 19])
def test_healthy_run_produces_no_incidents(seed: int) -> None:
    # Seeds 0 and 19 contain 2 and 3 low/medium false-positive anomalies respectively (M4).
    result = simulate(Scenario(name="healthy", seed=seed, minutes=1440))
    anomalies = detect_anomalies(series_from_simulation(result))
    assert anomalies
    assert correlate(anomalies, events_from_simulation(result)) == []


def test_low_severity_coincidence_is_not_an_incident() -> None:
    noise = [anomaly("rssi_dbm", "CELL-101", "pgw-1", 100, 102, "low"),
             anomaly("rsrp_dbm", "CELL-101", "pgw-1", 101, 103, "medium")]
    assert correlate(noise) == []
    assert len(correlate(noise, config=CorrelationConfig(min_peak_severity="medium"))) == 1


def test_same_node_far_apart_in_time_are_separate_incidents() -> None:
    anomalies = [anomaly("cpu_utilization", "CELL-101", "pgw-1", 10, 20),
                 anomaly("latency_ms", "CELL-101", "pgw-1", 12, 20),
                 anomaly("cpu_utilization", "CELL-101", "pgw-1", 120, 130),
                 anomaly("latency_ms", "CELL-101", "pgw-1", 121, 130)]
    assert len(correlate(anomalies)) == 2


def test_simultaneous_anomalies_on_different_nodes_never_merge() -> None:
    anomalies = [anomaly("cpu_utilization", "CELL-101", "pgw-1", 10, 20),
                 anomaly("latency_ms", "CELL-101", "pgw-1", 12, 20),
                 anomaly("cpu_utilization", "CELL-105", "pgw-2", 10, 20),
                 anomaly("latency_ms", "CELL-105", "pgw-2", 12, 20)]
    incidents = correlate(anomalies)
    assert [i.affected_nodes for i in incidents] == [("pgw-1",), ("pgw-2",)]


def test_cells_on_same_node_merge_only_with_close_onsets() -> None:
    near = [anomaly("cpu_utilization", "CELL-101", "pgw-1", 10, 60),
            anomaly("latency_ms", "CELL-101", "pgw-1", 12, 60),
            anomaly("cpu_utilization", "CELL-102", "pgw-1", 14, 60),
            anomaly("latency_ms", "CELL-102", "pgw-1", 15, 60)]
    assert len(correlate(near)) == 1
    far = near[:2] + [anomaly("cpu_utilization", "CELL-102", "pgw-1", 40, 90),
                      anomaly("latency_ms", "CELL-102", "pgw-1", 41, 90)]
    assert len(correlate(far)) == 2


def _deployment(minute: int, node: str = "pgw-1") -> OperationalEvent:
    return OperationalEvent.make(T0 + minute * 60, EventType.DEPLOYMENT, "ci-cd", "info",
                                 f"Deployed packet-gateway 9.9.9 to {node}", node_id=node,
                                 attributes={"to_version": "9.9.9"})


def test_event_timing_boundaries() -> None:
    symptoms = [anomaly("memory_utilization", "CELL-101", "pgw-1", 200, 260),
                anomaly("cpu_utilization", "CELL-101", "pgw-1", 210, 260)]
    cfg = CorrelationConfig()
    lookback = cfg.cause_lookback_seconds // 60

    def top_types(events: list[OperationalEvent]) -> list[str]:
        return [c.cause_type for c in correlate(symptoms, events)[0].suspected_causes]

    assert "deployment_regression" in top_types([_deployment(150)])                 # before onset
    assert "deployment_regression" in top_types([_deployment(203)])                 # within look-ahead
    assert "deployment_regression" not in top_types([_deployment(220)])             # after look-ahead
    assert "deployment_regression" not in top_types([_deployment(200 - lookback - 5)])  # too early
    near, far = (correlate(symptoms, [_deployment(m)])[0].suspected_causes[0] for m in (195, 120))
    assert near.temporal_score > far.temporal_score


def test_correlation_is_deterministic(seeded: dict) -> None:
    result = seeded["result"]
    series = series_from_simulation(result)
    again = correlate(detect_anomalies(series), events_from_simulation(result), seeded["calls"],
                      series_lookup(series))
    assert [i.to_dict() for i in again] == [i.to_dict() for i in seeded["incidents"]]


# ---- Supporting functions ------------------------------------------------------------------


def test_chain_consistency_allows_multiple_causes_and_flags_violations() -> None:
    # jitter after latency but before packet loss: consistent (latency also drives jitter)
    ok, violations = chain_consistency({"latency_ms": 0, "jitter_ms": 300, "packet_loss_pct": 600})
    assert ok == 1.0 and violations == []
    # call drops before every upstream cause: violation
    bad, violations = chain_consistency({"call_drop_rate": 0, "packet_loss_pct": 600, "latency_ms": 900})
    assert bad < 1.0 and "call_drop_rate" in violations[0]
    assert chain_consistency({"rssi_dbm": 0})[0] == 1.0


def test_lagged_correlation_recovers_known_lag() -> None:
    rng = np.random.default_rng(0)
    a = np.cumsum(rng.normal(size=300))
    b = np.concatenate([np.zeros(5), a[:-5]]) + rng.normal(scale=0.05, size=300)
    lag, r = lagged_correlation(a, b, max_lag=15)
    assert lag == 5 and r > 0.9


def test_violating_order_reduces_confidence() -> None:
    ordered = [anomaly("memory_utilization", "CELL-101", "pgw-1", 200, 260),
               anomaly("cpu_utilization", "CELL-101", "pgw-1", 210, 260),
               anomaly("call_drop_rate", "CELL-101", "pgw-1", 220, 260)]
    # call drops start 15 min before every upstream cause (memory, CPU): a violation
    reversed_order = [anomaly("memory_utilization", "CELL-101", "pgw-1", 200, 260),
                      anomaly("cpu_utilization", "CELL-101", "pgw-1", 210, 260),
                      anomaly("call_drop_rate", "CELL-101", "pgw-1", 185, 260)]
    good = correlate(ordered, [_deployment(195)])[0]
    bad = correlate(reversed_order, [_deployment(195)])[0]
    assert good.chain_consistency == 1.0 and bad.chain_consistency < 1.0
    assert bad.confidence < good.confidence
    assert any("contradicts the causal graph" in c for c in bad.caveats)
