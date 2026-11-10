"""End-to-end ingestion: simulate -> CDRs -> C analysis -> detection -> correlation -> DB.

Identifiers produced by the analytics layer are deterministic per scenario, so
they are made run-scoped (`R<run>-...`) before storage. Incidents get globally
sequential ids (`INC-<year>-<NNN>`) at persistence time.
"""

from __future__ import annotations

import dataclasses
import re
import time
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.analytics import detect_anomalies, series_from_simulation
from app.analytics.correlation import Incident, correlate
from app.analytics.engine import MetricAnomaly
from app.analytics.sources import events_from_simulation, series_lookup
from app.models import (
    Anomaly,
    CallAnalysisRun,
    CallAnomalyRecord,
    CallCellStatistics,
    Deployment,
    IncidentAnomaly,
    IncidentCell,
    IncidentEventRecord,
    IncidentRecord,
    NetworkMetric,
    OperationalEventRecord,
    PipelineRun,
)
from app.simulation import Scenario, seeded_memory_leak_scenario, simulate
from app.simulation.cdr import generate_cdrs, write_cdr_csv
from app.simulation.scenario import SimulationResult
from call_analyzer import CallAnalysisResult, analyze_call_log

_INCIDENT_ID = re.compile(r"^INC-(\d{4})-(\d+)$")


@dataclass(frozen=True)
class PipelineParams:
    scenario: str = "seeded"   # seeded | healthy
    seed: int = 7
    minutes: int = 360
    rollback_minute: int | None = None

    def build(self) -> Scenario:
        if self.scenario == "seeded":
            base = seeded_memory_leak_scenario(self.seed, self.rollback_minute)
            return dataclasses.replace(base, minutes=self.minutes)
        if self.scenario == "healthy":
            if self.rollback_minute is not None:
                raise ValueError("rollback_minute applies only to the seeded scenario")
            return Scenario(name="healthy", seed=self.seed, minutes=self.minutes)
        raise ValueError(f"unknown scenario {self.scenario!r}")


@dataclass(frozen=True)
class PipelineOutcome:
    run: PipelineRun
    incident_ids: list[str]
    anomalies: int
    call_analysis: CallAnalysisResult


def _next_incident_numbers(session: Session, year: int, count: int) -> list[str]:
    existing = session.scalars(select(IncidentRecord.incident_id)
                               .where(IncidentRecord.incident_id.like(f"INC-{year}-%"))).all()
    highest = max((int(m.group(2)) for i in existing if (m := _INCIDENT_ID.match(i))), default=0)
    return [f"INC-{year}-{highest + k:03d}" for k in range(1, count + 1)]


def _store_metrics(session: Session, run_id: int, result: SimulationResult) -> None:
    topo = result.scenario.topology
    rows = [
        {"run_id": run_id, "epoch": int(epoch), "cell_id": cell, "node_id": topo.node_of(cell),
         "metric": metric, "value": float(values[i])}
        for cell in topo.cell_ids
        for metric, values in result.metrics[cell].items()
        for i, epoch in enumerate(result.epochs)
    ]
    for start in range(0, len(rows), 20_000):
        session.execute(insert(NetworkMetric), rows[start:start + 20_000])


def _store_call_analysis(session: Session, run_id: int, calls: CallAnalysisResult) -> None:
    analysis = CallAnalysisRun(
        run_id=run_id, source=calls["source"], library_version=calls["library_version"],
        total_calls=calls["total_calls"], successful_calls=calls["successful_calls"],
        failed_setup_calls=calls["failed_setup_calls"], dropped_calls=calls["dropped_calls"],
        success_rate=calls["success_rate"], drop_rate=calls["drop_rate"],
        setup_failure_rate=calls["setup_failure_rate"], average_duration=calls["average_duration"],
        average_signal=calls["average_signal"], average_packet_loss=calls["average_packet_loss"],
        first_epoch=calls["first_epoch"], last_epoch=calls["last_epoch"],
        failure_codes=list(calls["failure_codes"]), time_windows=list(calls["time_windows"]),
        suspicious_time_windows=list(calls["suspicious_time_windows"]),
        parse_report=dict(calls["parse_report"]))
    session.add(analysis)
    session.flush()
    for c in calls["cells"]:
        session.add(CallCellStatistics(
            analysis_id=analysis.id, cell_id=c["cell_id"], total_calls=c["total_calls"],
            successful_calls=c["successful_calls"], failed_setup_calls=c["failed_setup_calls"],
            dropped_calls=c["dropped_calls"], drop_rate=c["drop_rate"],
            setup_failure_rate=c["setup_failure_rate"], average_signal=c["average_signal"],
            average_packet_loss=c["average_packet_loss"]))
    for a in calls["anomalies"]:
        session.add(CallAnomalyRecord(
            analysis_id=analysis.id, type=a["type"], category=a["category"], severity=a["severity"],
            subject=a["subject"], window_start_epoch=a["window_start_epoch"],
            window_end_epoch=a["window_end_epoch"], value=a["value"], baseline=a["baseline"],
            z_score=a["z_score"], anomaly_score=a["anomaly_score"], sample_size=a["sample_size"],
            description=a["description"]))


def _store_incident(session: Session, run_id: int, incident: Incident, incident_id: str,
                    prefix: str, node_by_cell: dict[str, str]) -> None:
    record = incident.to_dict()
    for cause in record["suspected_causes"]:
        cause["evidence"] = [prefix + e for e in cause["evidence"]]
    for excluded in record["excluded_candidates"]:
        excluded["event_id"] = prefix + excluded["event_id"]
    for symptom in record["symptoms"]:
        symptom["anomaly_ids"] = [prefix + a for a in symptom["anomaly_ids"]]
    session.add(IncidentRecord(
        incident_id=incident_id, run_id=run_id, severity=incident.severity, status="open",
        start_epoch=incident.start_epoch, end_epoch=incident.end_epoch,
        confidence=incident.confidence, chain_consistency=incident.chain_consistency,
        top_cause_type=incident.suspected_causes[0].cause_type if incident.suspected_causes else None,
        resolved_epoch=None, symptoms=record["symptoms"], suspected_causes=record["suspected_causes"],
        excluded_candidates=record["excluded_candidates"], call_evidence=record["call_evidence"],
        causal_chain=record["causal_chain"], caveats=record["caveats"]))
    session.flush()
    for cell in incident.affected_cells:
        session.add(IncidentCell(incident_id=incident_id, cell_id=cell, node_id=node_by_cell[cell]))
    for anomaly_id in incident.anomaly_ids:
        session.add(IncidentAnomaly(incident_id=incident_id, anomaly_id=prefix + anomaly_id))
    for entry in incident.events:
        ref = entry.reference_id
        session.add(IncidentEventRecord(
            incident_id=incident_id, epoch=entry.epoch, type=entry.type, description=entry.description,
            reference_id=prefix + ref if ref else None,
            actor="correlation-engine" if entry.type == "incident_created" else "telemetry"))


def run_pipeline(session: Session, params: PipelineParams, data_dir: Path) -> PipelineOutcome:
    return run_scenario(session, params.build(), data_dir, dataclasses.asdict(params))


def run_scenario(session: Session, scenario: Scenario, data_dir: Path,
                 params: dict[str, object] | None = None, *, correlate_flag: bool = True) -> PipelineOutcome:
    """Runs the full pipeline for any scenario (used by the API, tests and the agent).

    `correlate_flag=False` stores telemetry, call analysis and anomalies but opens no
    incidents (used for the agent's post-rollback verification runs).
    """
    result = simulate(scenario)
    run = PipelineRun(scenario=scenario.name, seed=scenario.seed, status="running",
                      started_epoch=int(time.time()), finished_epoch=None,
                      data_start_epoch=int(result.epochs[0]), data_end_epoch=int(result.epochs[-1]),
                      fingerprint=result.fingerprint(),
                      params={**(params or {"scenario": scenario.name}), "seed": scenario.seed,
                              "minutes": scenario.minutes, "rollback_minute": scenario.rollback_minute,
                              "incidents": [{**dataclasses.asdict(s), "type": s.type.value}
                                            for s in scenario.incidents]})
    session.add(run)
    session.flush()
    prefix = f"R{run.id}-"

    run_dir = data_dir / "runs" / f"run-{run.id:04d}"
    cdr_path = run_dir / "call_logs.csv"
    write_cdr_csv(generate_cdrs(result, scenario.seed), cdr_path)
    calls = analyze_call_log(cdr_path)

    series = series_from_simulation(result)
    anomalies: list[MetricAnomaly] = detect_anomalies(series)
    events = events_from_simulation(result)
    incidents = correlate(anomalies, events, calls["anomalies"], series_lookup(series)) if correlate_flag else []

    _store_metrics(session, run.id, result)
    _store_call_analysis(session, run.id, calls)
    for e in events:
        session.add(OperationalEventRecord(
            event_id=prefix + e.event_id, run_id=run.id, epoch=e.epoch, type=e.type.value,
            source=e.source, severity=e.severity, message=e.message, node_id=e.node_id,
            cell_id=e.cell_id, attributes=dict(e.attributes)))
    for d in result.deployments:
        session.add(Deployment(
            deployment_id=prefix + d.deployment_id, run_id=run.id, service=d.service,
            node_id=d.node_id, from_version=d.from_version, to_version=d.to_version,
            deployed_epoch=d.epoch, change_summary=d.change_summary,
            status="rolled_back" if d.rolled_back_epoch else "active",
            rolled_back_epoch=d.rolled_back_epoch))
    for a in anomalies:
        session.add(Anomaly(
            anomaly_id=prefix + a.anomaly_id, run_id=run.id, metric=a.metric, cell_id=a.cell_id,
            node_id=a.node_id, start_epoch=a.start_epoch, end_epoch=a.end_epoch, value=a.value,
            baseline=a.baseline, severity=a.severity, anomaly_score=a.anomaly_score,
            points=a.points, detectors=list(a.detectors), related_metrics=list(a.related_metrics)))
    session.flush()

    incident_ids: list[str] = []
    if incidents:
        year = time.gmtime(incidents[0].start_epoch).tm_year
        for incident, incident_id in zip(incidents, _next_incident_numbers(session, year, len(incidents)),
                                         strict=True):
            _store_incident(session, run.id, incident, incident_id, prefix,
                            {a.cell_id: a.node_id for a in anomalies})
            incident_ids.append(incident_id)

    run.status = "completed"
    run.finished_epoch = int(time.time())
    session.commit()
    return PipelineOutcome(run, incident_ids, len(anomalies), calls)
