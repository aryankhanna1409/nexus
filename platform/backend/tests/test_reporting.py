"""M8 acceptance tests: report content, numeric accuracy, renderers, escaping, API."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select, update

from app.db import make_engine, make_session_factory
from app.llm.base import LLMProvider, LLMResponse, LLMUnavailableError, Message, ToolSpec
from app.llm.factory import ProviderChoice
from app.llm.mock import MockProvider
from app.models import AuditLogRecord, IncidentEventRecord, IncidentRecord, NetworkMetric
from app.reporting.builder import build_report
from app.reporting.render import render_html, render_json, render_markdown

from .api_support import ApiHarness, make_harness

SECTIONS = ["Executive Summary", "KPI Analysis", "Anomaly Analysis", "Correlation Analysis", "Root Cause",
            "Impact", "Recommendations", "Confidence"]


@pytest.fixture(scope="module")
def api(tmp_path_factory: pytest.TempPathFactory) -> ApiHarness:
    harness = make_harness(tmp_path_factory.mktemp("reports"))
    assert harness.post("/api/pipeline/run", json={"scenario": "seeded"}).status_code == 201  # type: ignore[attr-defined]
    assert harness.post("/api/incidents/INC-2026-001/investigate").status_code == 201  # type: ignore[attr-defined]
    return harness


@pytest.fixture()
def session(api: ApiHarness):  # type: ignore[no-untyped-def]
    s = make_session_factory(make_engine(api.settings.database_url))()
    yield s
    s.close()


class NarrativeProvider(LLMProvider):
    name = "scripted"
    model = "scripted"

    def __init__(self, text: str | None = None, error: Exception | None = None) -> None:
        self.text, self.error = text, error

    def generate(self, system: str, messages: list[Message], *, max_tokens: int = 4096) -> LLMResponse:
        if self.error:
            raise self.error
        return LLMResponse(self.text or "", (), "end_turn", self.model, self.name)

    def tool_call(self, system: str, messages: list[Message], tools: list[ToolSpec], *,
                  max_tokens: int = 16000) -> LLMResponse:
        raise NotImplementedError


def _mock() -> ProviderChoice:
    return ProviderChoice(MockProvider(), "mock", None)


# ---- Content and accuracy ---------------------------------------------------------------------


def test_report_sections_and_root_cause(session: Any) -> None:
    doc = build_report(session, "INC-2026-001", _mock(), "test")
    assert doc.root_cause.source == "rca" and doc.root_cause.cause_type == "deployment_regression"
    assert "not a confirmed fact" in doc.root_cause.status_label
    assert 0 < (doc.root_cause.confidence or 0) <= 0.95
    assert doc.root_cause.facts and all(f["tool_call_ids"] for f in doc.root_cause.facts)
    assert doc.root_cause.alternative_hypotheses
    assert doc.recommendations[0]["risk_class"] == "HIGH_RISK"
    assert doc.verification_steps
    assert doc.evidence_references["tool_calls"] and doc.evidence_references["anomalies"]
    assert doc.impact.affected_cells == ["CELL-101", "CELL-102", "CELL-103", "CELL-104"]
    assert doc.impact.estimated_affected_users > 0 and doc.impact.dropped_calls_in_affected_cells
    assert any("hypothesis" in c for c in doc.confidence["caveats"])
    assert "synthetic" in doc.data_notice


def test_kpi_numbers_match_independent_computation(session: Any) -> None:
    doc = build_report(session, "INC-2026-001", _mock(), "test")
    incident = session.get(IncidentRecord, "INC-2026-001")
    cells = doc.impact.affected_cells
    for kpi in doc.kpi_analysis:
        rows = session.execute(select(NetworkMetric.epoch, NetworkMetric.value).where(
            NetworkMetric.run_id == incident.run_id, NetworkMetric.metric == kpi.metric,
            NetworkMetric.cell_id.in_(cells))).all()
        before = [v for e, v in rows if incident.start_epoch - 3600 <= e < incident.start_epoch]
        during = [v for e, v in rows if incident.start_epoch <= e <= incident.end_epoch]
        assert kpi.baseline == pytest.approx(sum(before) / len(before), abs=1e-3), kpi.metric
        assert kpi.incident_mean == pytest.approx(sum(during) / len(during), abs=1e-3), kpi.metric
        expected_worst = min(during) if kpi.direction == "down" else max(during)
        assert kpi.worst == pytest.approx(expected_worst, abs=1e-3), kpi.metric
    by_metric = {k.metric: k for k in doc.kpi_analysis}
    assert {"packet_loss_pct", "latency_ms", "call_drop_rate", "cpu_utilization"} <= set(by_metric)
    assert by_metric["throughput_mbps"].direction == "down"
    assert by_metric["throughput_mbps"].incident_mean < by_metric["throughput_mbps"].baseline
    assert by_metric["packet_loss_pct"].change_pct > 500  # type: ignore[operator]


def test_report_without_rca_uses_correlation_hypothesis(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)
    harness.post("/api/pipeline/run", json={"scenario": "seeded"})
    with make_session_factory(make_engine(harness.settings.database_url))() as s:
        doc = build_report(s, "INC-2026-001", _mock(), "test")
    assert doc.root_cause.source == "correlation" and doc.root_cause.facts == []
    assert "no RCA" in doc.root_cause.status_label
    assert doc.recommendations[0]["action"].startswith("Run an RCA")


# ---- Narrative grounding --------------------------------------------------------------------------


def test_mock_narrative_is_grounded(session: Any) -> None:
    doc = build_report(session, "INC-2026-001", _mock(), "test")
    assert doc.narrative_provider == "mock"
    assert "INC-2026-001" in doc.executive_summary and "hypothesis" in doc.executive_summary


def test_ungrounded_llm_narrative_is_replaced(session: Any) -> None:
    fabricated = "Packet loss reached 73.9% and 12345 users were affected."
    choice = ProviderChoice(NarrativeProvider(fabricated), "scripted", None)
    doc = build_report(session, "INC-2026-001", choice, "test")
    assert "73.9" not in doc.executive_summary and "rejected" in doc.narrative_provider


def test_grounded_llm_narrative_is_kept(session: Any) -> None:
    choice = ProviderChoice(NarrativeProvider("Incident INC-2026-001 affected 4 cells on CELL-101."),
                            "scripted", None)
    doc = build_report(session, "INC-2026-001", choice, "test")
    assert doc.executive_summary.startswith("Incident INC-2026-001") and doc.narrative_provider == "scripted"


def test_provider_failure_falls_back_to_template(session: Any) -> None:
    choice = ProviderChoice(NarrativeProvider(error=LLMUnavailableError("down")), "scripted", None)
    doc = build_report(session, "INC-2026-001", choice, "test")
    assert "LLMUnavailableError" in doc.narrative_provider and doc.executive_summary


# ---- Renderers and escaping --------------------------------------------------------------------


def test_renderers_cover_all_sections(session: Any) -> None:
    doc = build_report(session, "INC-2026-001", _mock(), "test")
    assert json.loads(render_json(doc)) == json.loads(doc.model_dump_json())
    markdown, html = render_markdown(doc), render_html(doc)
    for section in SECTIONS:
        assert f"## {section}" in markdown and f"<h2>{section}</h2>" in html
    for kpi in doc.kpi_analysis:
        assert kpi.metric in markdown and str(kpi.baseline) in html
    assert "<script" not in html.lower()


def test_untrusted_text_is_escaped(tmp_path: Path) -> None:
    harness = make_harness(tmp_path)
    harness.post("/api/pipeline/run", json={"scenario": "seeded"})
    payload = '<script>alert("x")</script> | <img src=x onerror=alert(1)>'
    engine = make_engine(harness.settings.database_url)
    with engine.begin() as conn:
        conn.execute(update(IncidentEventRecord).where(IncidentEventRecord.type == "deployment")
                     .values(description=payload))
        conn.execute(update(IncidentRecord).values(caveats=[payload]))
    with make_session_factory(engine)() as s:
        doc = build_report(s, "INC-2026-001", _mock(), "test")
    html, markdown = render_html(doc), render_markdown(doc)
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html
    assert "<script>" not in markdown and "\\|" in markdown


# ---- API ------------------------------------------------------------------------------------------


def test_generate_and_fetch_report(api: ApiHarness) -> None:
    assert api.post("/api/reports/generate", role="viewer", json={"incident_id": "INC-2026-001"}).status_code == 403  # type: ignore[attr-defined]
    created = api.post("/api/reports/generate", json={"incident_id": "INC-2026-001"})
    assert created.status_code == 201, created.text  # type: ignore[attr-defined]
    body = created.json()  # type: ignore[attr-defined]
    report_id = body["report_id"]
    assert report_id.startswith("RPT-INC-2026-001-") and body["rca_id"] is not None
    as_json = api.get(f"/api/reports/{report_id}")
    assert as_json.headers["content-type"].startswith("application/json")  # type: ignore[attr-defined]
    assert as_json.json()["incident_id"] == "INC-2026-001"  # type: ignore[attr-defined]
    md = api.get(f"/api/reports/{report_id}", params={"format": "markdown"})
    assert md.headers["content-type"].startswith("text/markdown") and "## Root Cause" in md.text  # type: ignore[attr-defined]
    html = api.get(f"/api/reports/{report_id}", params={"format": "html"})
    assert html.headers["content-type"].startswith("text/html")  # type: ignore[attr-defined]
    assert "default-src 'none'" in html.headers["content-security-policy"]  # type: ignore[attr-defined]
    listing = api.get("/api/reports", params={"incident_id": "INC-2026-001"}).json()  # type: ignore[attr-defined]
    assert report_id in [r["report_id"] for r in listing]
    second = api.post("/api/reports/generate", json={"incident_id": "INC-2026-001"}).json()  # type: ignore[attr-defined]
    assert second["report_id"] != report_id
    with make_session_factory(make_engine(api.settings.database_url))() as s:
        assert s.scalars(select(AuditLogRecord).where(AuditLogRecord.action == "report.generate")).first()


def test_report_api_validation(api: ApiHarness) -> None:
    assert api.post("/api/reports/generate", json={"incident_id": "INC-2026-777"}).status_code == 404  # type: ignore[attr-defined]
    assert api.post("/api/reports/generate", json={"incident_id": "../../etc/passwd"}).status_code == 422  # type: ignore[attr-defined]
    assert api.post("/api/reports/generate", json={"incident_id": "INC-2026-001", "x": 1}).status_code == 422  # type: ignore[attr-defined]
    assert api.get("/api/reports/RPT-INC-2026-001-99").status_code == 404  # type: ignore[attr-defined]
    assert api.get("/api/reports/..%2F..%2Fsecrets").status_code in (404, 422)  # type: ignore[attr-defined]
    assert api.get("/api/reports/RPT-INC-2026-001-01", params={"format": "pdf"}).status_code == 422  # type: ignore[attr-defined]
