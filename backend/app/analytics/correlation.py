"""Correlates metric anomalies, call anomalies and operational events into incidents.

Steps:

1. Per cell, anomaly episodes whose intervals lie within `cluster_gap_seconds`
   form a cell cluster.
2. Cell clusters on the same packet-gateway node merge when their onsets are
   within `cross_cell_onset_seconds` (a shared node with simultaneous onset
   suggests a common cause; different nodes never merge).
3. Clusters with at least `min_symptom_metrics` distinct metrics become
   incidents. C-library call anomalies for the incident's cells (or
   network-wide windows) overlapping the incident are attached as evidence.
4. Candidate causes are scored from temporal precedence, topological match and
   agreement with the causal graph. Events outside the incident's topology are
   recorded as excluded candidates with a reason.

Every cause is a *hypothesis*. Confidence is capped at `max_confidence`
because correlation alone does not establish causation.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import numpy as np

from app.analytics.causal_graph import EXPECTED_FIRST, chain_consistency, reachable
from app.analytics.engine import MetricAnomaly, iso


class EventType(StrEnum):
    DEPLOYMENT = "deployment"
    ROLLBACK = "rollback"
    CONFIG_CHANGE = "config_change"
    SECURITY = "security"
    APPLICATION_LOG = "application_log"


@dataclass(frozen=True)
class OperationalEvent:
    """Normalised operational event (deployment, config change, security, log)."""

    event_id: str
    epoch: int
    type: EventType
    source: str
    severity: str
    message: str
    node_id: str | None = None
    cell_id: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    @staticmethod
    def make(epoch: int, type: EventType, source: str, severity: str, message: str,
             node_id: str | None = None, cell_id: str | None = None,
             attributes: Mapping[str, Any] | None = None) -> OperationalEvent:
        key = f"{epoch}|{type}|{source}|{message}|{node_id}|{cell_id}".encode()
        return OperationalEvent("EVT-" + hashlib.sha256(key).hexdigest()[:12], epoch, type, source,
                                severity, message, node_id, cell_id, dict(attributes or {}))


@dataclass(frozen=True)
class CorrelationConfig:
    cluster_gap_seconds: int = 900
    cross_cell_onset_seconds: int = 900
    min_symptom_metrics: int = 2
    # At least one symptom must reach this severity. M4 bounds false positives to
    # low/medium severity, so chance coincidences of noise do not open incidents.
    min_peak_severity: str = "high"
    cause_lookback_seconds: int = 7200
    cause_lookahead_seconds: int = 300
    temporal_tau_seconds: float = 1800.0
    min_security_events: int = 10
    max_confidence: float = 0.95
    max_lag_minutes: int = 30


@dataclass(frozen=True)
class SuspectedCause:
    cause_type: str
    description: str
    score: float
    evidence: tuple[str, ...]
    rationale: str
    temporal_score: float
    mechanism_score: float
    topology_score: float

    def to_dict(self) -> dict[str, Any]:
        return {"cause_type": self.cause_type, "description": self.description,
                "score": self.score, "evidence": list(self.evidence), "rationale": self.rationale,
                "temporal_score": self.temporal_score, "mechanism_score": self.mechanism_score,
                "topology_score": self.topology_score, "status": "hypothesis"}


@dataclass(frozen=True)
class TimelineEntry:
    epoch: int
    type: str
    description: str
    reference_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"timestamp": iso(self.epoch), "epoch": self.epoch, "type": self.type,
                "description": self.description, "reference_id": self.reference_id}


@dataclass(frozen=True)
class Symptom:
    metric: str
    cells: tuple[str, ...]
    onset_epoch: int
    end_epoch: int
    worst_value: float
    baseline: float
    severity: str
    anomaly_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"metric": self.metric, "cells": list(self.cells), "onset": iso(self.onset_epoch),
                "onset_epoch": self.onset_epoch, "end_epoch": self.end_epoch,
                "worst_value": self.worst_value, "baseline": self.baseline,
                "severity": self.severity, "anomaly_ids": list(self.anomaly_ids)}


@dataclass(frozen=True)
class Incident:
    incident_id: str
    severity: str
    start_epoch: int
    end_epoch: int
    affected_cells: tuple[str, ...]
    affected_nodes: tuple[str, ...]
    symptoms: tuple[Symptom, ...]
    events: tuple[TimelineEntry, ...]
    suspected_causes: tuple[SuspectedCause, ...]
    excluded_candidates: tuple[dict[str, Any], ...]
    call_evidence: tuple[dict[str, Any], ...]
    causal_chain: tuple[dict[str, Any], ...]
    chain_consistency: float
    confidence: float
    caveats: tuple[str, ...]
    anomaly_ids: tuple[str, ...]

    @property
    def start_time(self) -> str:
        return iso(self.start_epoch)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id, "severity": self.severity,
            "start_time": self.start_time, "end_time": iso(self.end_epoch),
            "affected_cells": list(self.affected_cells), "affected_nodes": list(self.affected_nodes),
            "symptoms": [s.to_dict() for s in self.symptoms],
            "events": [e.to_dict() for e in self.events],
            "suspected_causes": [c.to_dict() for c in self.suspected_causes],
            "excluded_candidates": list(self.excluded_candidates),
            "call_evidence": list(self.call_evidence),
            "causal_chain": list(self.causal_chain), "chain_consistency": self.chain_consistency,
            "confidence": self.confidence, "caveats": list(self.caveats),
            "anomaly_ids": list(self.anomaly_ids),
        }


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# ---- Clustering -------------------------------------------------------------------------


def _cluster(anomalies: Sequence[MetricAnomaly], cfg: CorrelationConfig) -> list[list[MetricAnomaly]]:
    by_cell: dict[str, list[MetricAnomaly]] = {}
    for a in sorted(anomalies, key=lambda a: (a.cell_id, a.start_epoch)):
        by_cell.setdefault(a.cell_id, []).append(a)
    cell_clusters: list[list[MetricAnomaly]] = []
    for items in by_cell.values():
        current: list[MetricAnomaly] = []
        span_end = -1
        for a in items:
            if current and a.start_epoch > span_end + cfg.cluster_gap_seconds:
                cell_clusters.append(current)
                current = []
            current.append(a)
            span_end = max(span_end, a.end_epoch) if len(current) > 1 else a.end_epoch
        if current:
            cell_clusters.append(current)

    # Merge cell clusters that share a node and started at about the same time.
    cell_clusters.sort(key=lambda c: (c[0].node_id, min(a.start_epoch for a in c)))
    merged: list[list[MetricAnomaly]] = []
    for cluster in cell_clusters:
        onset = min(a.start_epoch for a in cluster)
        for target in merged:
            if (target[0].node_id == cluster[0].node_id
                    and abs(min(a.start_epoch for a in target) - onset) <= cfg.cross_cell_onset_seconds):
                target.extend(cluster)
                break
        else:
            merged.append(list(cluster))
    return merged


def _symptoms(cluster: Sequence[MetricAnomaly]) -> list[Symptom]:
    by_metric: dict[str, list[MetricAnomaly]] = {}
    for a in cluster:
        by_metric.setdefault(a.metric, []).append(a)
    symptoms = []
    for metric, items in by_metric.items():
        worst = max(items, key=lambda a: (abs(a.value - a.baseline), a.anomaly_score))
        symptoms.append(Symptom(
            metric=metric, cells=tuple(sorted({a.cell_id for a in items})),
            onset_epoch=min(a.start_epoch for a in items), end_epoch=max(a.end_epoch for a in items),
            worst_value=worst.value, baseline=worst.baseline,
            severity=max((a.severity for a in items), key=_SEVERITY_RANK.__getitem__),
            anomaly_ids=tuple(sorted(a.anomaly_id for a in items))))
    symptoms.sort(key=lambda s: (s.onset_epoch, s.metric))
    return symptoms


# ---- Cause scoring ------------------------------------------------------------------------


EARLIEST_TOLERANCE_SECONDS = 120
# Cause classes that can be proposed from symptoms alone (no triggering event needed).
SYMPTOM_ONLY_CAUSES: dict[str, str] = {
    "memory_exhaustion": "memory exhaustion on the serving gateway",
    "traffic_overload": "offered load exceeded processing capacity",
    "radio_degradation": "degraded radio conditions on the affected cells",
    "transport_fault": "transport/backhaul fault causing packet loss",
}


def _earliest(symptoms: Sequence[Symptom]) -> list[str]:
    """Metrics whose onset is within EARLIEST_TOLERANCE_SECONDS of the first onset."""
    if not symptoms:
        return []
    first = symptoms[0].onset_epoch
    return [s.metric for s in symptoms if s.onset_epoch <= first + EARLIEST_TOLERANCE_SECONDS]


def _mechanism_score(cause_type: str, symptoms: Sequence[Symptom]) -> float:
    """Half: share of the earliest symptoms the cause produces first. Half: share of all
    symptoms the cause explains (they are expected first symptoms or downstream of them)."""
    expected = EXPECTED_FIRST[cause_type]
    earliest = _earliest(symptoms)
    if not earliest:
        return 0.0
    share = sum(m in expected for m in earliest) / len(earliest)
    explained = sum(s.metric in expected or any(reachable(e, s.metric) for e in expected)
                    for s in symptoms) / len(symptoms)
    return 0.5 * share + 0.5 * explained


def _temporal_score(event_epoch: int, onset: int, cfg: CorrelationConfig) -> float:
    if event_epoch <= onset:
        return math.exp(-(onset - event_epoch) / cfg.temporal_tau_seconds)
    return 0.3  # within the look-ahead: concurrent rather than preceding


def _metric_only_causes(symptoms: Sequence[Symptom]) -> list[tuple[str, str]]:
    """Symptom-only cause classes whose expected first symptoms appear among the earliest."""
    earliest = set(_earliest(symptoms))
    return [(cause, text) for cause, text in SYMPTOM_ONLY_CAUSES.items()
            if earliest & EXPECTED_FIRST[cause]]


def _score_causes(
    symptoms: Sequence[Symptom], onset: int, end: int, cells: set[str], nodes: set[str],
    events: Sequence[OperationalEvent], cfg: CorrelationConfig,
) -> tuple[list[SuspectedCause], list[dict[str, Any]]]:
    causes: list[SuspectedCause] = []
    excluded: list[dict[str, Any]] = []
    lo, hi = onset - cfg.cause_lookback_seconds, onset + cfg.cause_lookahead_seconds

    def add(cause_type: str, description: str, temporal: float, topology: float,
            evidence: tuple[str, ...], rationale: str) -> None:
        mechanism = _mechanism_score(cause_type, symptoms)
        score = round(0.45 * temporal + 0.35 * mechanism + 0.2 * topology, 4)
        causes.append(SuspectedCause(cause_type, description, score, evidence, rationale,
                                     round(temporal, 4), round(mechanism, 4), topology))

    security: list[OperationalEvent] = []
    for event in events:
        in_window = lo <= event.epoch <= (end if event.type is EventType.SECURITY else hi)
        if not in_window or event.type not in (EventType.DEPLOYMENT, EventType.CONFIG_CHANGE,
                                               EventType.SECURITY):
            continue
        on_topology = event.node_id in nodes or event.cell_id in cells
        if not on_topology and event.type is EventType.SECURITY:
            continue  # unrelated security noise is not a candidate cause
        if not on_topology:
            excluded.append({"event_id": event.event_id, "type": event.type.value,
                             "description": event.message,
                             "reason": f"targets {event.cell_id or event.node_id or 'no known element'}, "
                                       f"outside the affected nodes {sorted(nodes)}"})
            continue
        if event.type is EventType.SECURITY:
            security.append(event)
            continue
        temporal = _temporal_score(event.epoch, onset, cfg)
        lead = (onset - event.epoch) / 60
        when = f"{lead:.0f} min before" if lead >= 0 else f"{-lead:.0f} min after"
        if event.type is EventType.DEPLOYMENT:
            topology = 1.0 if event.node_id in nodes else 0.5
            add("deployment_regression", event.message,
                temporal, topology, (event.event_id,),
                f"deployment {when} symptom onset on the same node; earliest symptoms "
                f"{[s.metric for s in symptoms[:2]]}")
        else:
            topology = 1.0 if event.cell_id in cells else 0.5
            add("configuration_change", event.message, temporal, topology, (event.event_id,),
                f"configuration change {when} symptom onset on an affected element")

    if len(security) >= cfg.min_security_events:
        first = min(e.epoch for e in security)
        add("security_attack", f"{len(security)} security events against the affected elements",
            _temporal_score(first, onset, cfg), 1.0, tuple(e.event_id for e in security[:20]),
            f"{len(security)} IDS events from {first - onset:+d} s relative to onset")

    for cause_type, description in _metric_only_causes(symptoms):
        # No triggering event: lower temporal prior and partial topology weight.
        add(cause_type, description, 0.5, 0.5, (), "inferred from the earliest symptom only")

    causes.sort(key=lambda c: (-c.score, c.cause_type))
    return causes, excluded


# ---- Supporting analysis --------------------------------------------------------------------


def lagged_correlation(a: np.ndarray, b: np.ndarray, max_lag: int) -> tuple[int, float]:
    """Lag (in samples, b after a) maximising Pearson correlation of first differences."""
    da, db = np.diff(a), np.diff(b)
    best = (0, 0.0)
    for lag in range(0, max_lag + 1):
        x, y = da[:len(da) - lag], db[lag:]
        if len(x) < 10 or np.std(x) == 0 or np.std(y) == 0:
            continue
        r = float(np.corrcoef(x, y)[0, 1])
        if r > best[1]:
            best = (lag, r)
    return best


def _severity(symptoms: Sequence[Symptom], cells: set[str]) -> str:
    """CRITICAL needs a critical symptom plus customer-visible call impact on >= 2 cells."""
    worst = max((_SEVERITY_RANK[s.severity] for s in symptoms), default=0)
    service_impact = any(s.metric in ("call_drop_rate", "call_setup_success_rate")
                         and _SEVERITY_RANK[s.severity] >= 2 for s in symptoms)
    if worst == 3:
        return "CRITICAL" if service_impact and len(cells) >= 2 else "HIGH"
    if worst == 2:
        return "MEDIUM"
    return "LOW"


MAX_TIMELINE_LOGS = 10


def _timeline_events(events: Sequence[OperationalEvent], onset: int, end: int, cells: set[str],
                     nodes: set[str], cfg: CorrelationConfig) -> list[OperationalEvent]:
    """Events on the incident's topology: changes from the look-back window, and the
    first warning/error application logs during the incident."""
    selected: list[OperationalEvent] = []
    logs = 0
    for e in events:
        if not (e.node_id in nodes or e.cell_id in cells):
            continue
        if e.type is EventType.APPLICATION_LOG:
            if e.severity in ("warning", "error", "critical") and onset <= e.epoch <= end \
                    and logs < MAX_TIMELINE_LOGS:
                selected.append(e)
                logs += 1
        elif onset - cfg.cause_lookback_seconds <= e.epoch <= end:
            selected.append(e)
    return selected


def correlate(
    anomalies: Sequence[MetricAnomaly],
    events: Iterable[OperationalEvent] = (),
    call_anomalies: Sequence[Mapping[str, Any]] = (),
    series: Mapping[tuple[str, str], tuple[np.ndarray, np.ndarray]] | None = None,
    config: CorrelationConfig | None = None,
    id_prefix: str | None = None,
) -> list[Incident]:
    """Builds incidents. `series` maps (cell_id, metric) -> (epochs, values) for lag analysis."""
    cfg = config or CorrelationConfig()
    event_list = sorted(events, key=lambda e: (e.epoch, e.event_id))
    incidents: list[Incident] = []
    min_rank = _SEVERITY_RANK[cfg.min_peak_severity]
    clusters = [c for c in _cluster(anomalies, cfg)
                if len({a.metric for a in c}) >= cfg.min_symptom_metrics
                and max(_SEVERITY_RANK[a.severity] for a in c) >= min_rank]
    clusters.sort(key=lambda c: min(a.start_epoch for a in c))

    for seq, cluster in enumerate(clusters, start=1):
        symptoms = _symptoms(cluster)
        onset = min(s.onset_epoch for s in symptoms)
        end = max(s.end_epoch for s in symptoms)
        cells = {a.cell_id for a in cluster}
        nodes = {a.node_id for a in cluster}
        causes, excluded = _score_causes(symptoms, onset, end, cells, nodes, event_list, cfg)
        onsets = {s.metric: s.onset_epoch for s in symptoms}
        consistency, violations = chain_consistency(onsets)

        chain: list[dict[str, Any]] = []
        for prev, cur in zip(symptoms, symptoms[1:]):
            link: dict[str, Any] = {"from": prev.metric, "to": cur.metric,
                                    "lag_seconds": cur.onset_epoch - prev.onset_epoch}
            if series is not None:
                cell = sorted(set(prev.cells) & set(cur.cells) or cur.cells)[0]
                pa, pb = series.get((cell, prev.metric)), series.get((cell, cur.metric))
                if pa is not None and pb is not None:
                    window = (pa[0] >= onset - 3600) & (pa[0] <= end)
                    lag, r = lagged_correlation(pa[1][window], pb[1][window], cfg.max_lag_minutes)
                    link.update({"xcorr_lag_minutes": lag, "xcorr": round(r, 3), "cell": cell})
            chain.append(link)

        top = causes[0] if causes else None
        close_call = top is not None and len(causes) > 1 and top.score - causes[1].score < 0.1
        confidence = 0.0
        if top is not None:
            confidence = top.score * (0.6 + 0.4 * consistency) * (0.9 if close_call else 1.0)
        confidence = round(min(cfg.max_confidence, confidence), 4)

        call_evidence = [
            dict(a) for a in call_anomalies
            if (a.get("category") == "cell" and a.get("subject") in cells
                or a.get("category") == "window")
            and int(a["window_start_epoch"]) <= end and int(a["window_end_epoch"]) >= onset
        ]

        timeline = [TimelineEntry(e.epoch, e.type.value, e.message, e.event_id)
                    for e in _timeline_events(event_list, onset, end, cells, nodes, cfg)]
        timeline += [TimelineEntry(s.onset_epoch, "metric_anomaly",
                                   f"{s.metric} anomaly on {', '.join(s.cells)} ({s.severity})",
                                   s.anomaly_ids[0]) for s in symptoms]
        detected = max(s.onset_epoch for s in symptoms[:cfg.min_symptom_metrics])
        timeline.append(TimelineEntry(detected, "incident_created", "Incident opened by correlation engine"))
        timeline.sort(key=lambda t: (t.epoch, t.type != "deployment", t.type))

        caveats = ["Suspected causes are hypotheses ranked by temporal precedence, topology and "
                   "causal-graph agreement; correlation does not establish causation."]
        if violations:
            caveats.append("Onset order contradicts the causal graph: " + "; ".join(violations[:3]))
        if close_call:
            caveats.append(f"Top hypotheses are close (margin {causes[0].score - causes[1].score:.2f}); "
                           "confidence reduced.")
        if len(causes) == 1:
            caveats.append("Only one candidate cause was identified; alternatives were not ruled out.")
        if not any(c.evidence for c in causes):
            caveats.append("No triggering event found; causes are inferred from symptoms only.")

        prefix = id_prefix or f"INC-{datetime.fromtimestamp(onset, tz=UTC).year}"
        incidents.append(Incident(
            incident_id=f"{prefix}-{seq:03d}", severity=_severity(symptoms, cells),
            start_epoch=onset, end_epoch=end, affected_cells=tuple(sorted(cells)),
            affected_nodes=tuple(sorted(nodes)), symptoms=tuple(symptoms), events=tuple(timeline),
            suspected_causes=tuple(causes), excluded_candidates=tuple(excluded),
            call_evidence=tuple(call_evidence), causal_chain=tuple(chain),
            chain_consistency=round(consistency, 4), confidence=confidence, caveats=tuple(caveats),
            anomaly_ids=tuple(sorted(a.anomaly_id for a in cluster))))
    return incidents
