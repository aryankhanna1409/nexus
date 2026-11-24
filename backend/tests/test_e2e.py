"""M13 end-to-end tests for the two chains in spec §22, plus the offline demo."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sqlalchemy import select

from app.db import make_engine, make_session_factory
from app.models import AuditLogRecord

from .api_support import make_harness
from .conftest import REPO_ROOT


def test_data_to_analytics_to_incident_to_rca_to_report(tmp_path: Path) -> None:
    """data → analytics → anomaly → incident → RCA → report, with the spec §24 evidence chain."""
    api = make_harness(tmp_path)
    run = api.post("/api/pipeline/run", json={"scenario": "seeded", "seed": 7}).json()  # type: ignore[attr-defined]
    assert run["incident_ids"] == ["INC-2026-001"]
    calls = api.get("/api/calls/anomalies").json()  # type: ignore[attr-defined]
    assert {a["subject"] for a in calls if a["category"] == "cell"} == {"CELL-101", "CELL-102", "CELL-103", "CELL-104"}
    anomalies = api.get("/api/network/anomalies").json()  # type: ignore[attr-defined]
    onset = {}
    for a in anomalies:
        onset.setdefault(a["metric"], a["start_epoch"])
    incident = api.get("/api/incidents/INC-2026-001").json()  # type: ignore[attr-defined]
    deployment = next(e for e in incident["events"] if e["type"] == "deployment")
    # spec §24: (1) deployment preceded degradation, (2) CPU/memory increased afterwards,
    # (3) network performance deteriorated, (4) call failures increased.
    assert deployment["epoch"] < onset["memory_utilization"] < onset["cpu_utilization"]
    assert onset["cpu_utilization"] <= onset["latency_ms"] <= onset["packet_loss_pct"] <= onset["call_drop_rate"]
    rca = api.post("/api/incidents/INC-2026-001/investigate").json()  # type: ignore[attr-defined]
    assert rca["status"] == "completed" and rca["explanation"]["leading_hypothesis_type"] == "deployment_regression"
    cited = {i for f in rca["facts"] for i in f["tool_call_ids"]}
    assert cited <= {t["id"] for t in rca["tool_calls"] if t["ok"]}
    report = api.post("/api/reports/generate", json={"incident_id": "INC-2026-001"}).json()  # type: ignore[attr-defined]
    payload = report["report"]
    assert payload["root_cause"]["source"] == "rca" and payload["root_cause"]["confidence"] == rca["confidence"]
    assert payload["evidence_references"]["tool_calls"] and payload["kpi_analysis"]
    markdown = api.get(f"/api/reports/{report['report_id']}", params={"format": "markdown"}).text  # type: ignore[attr-defined]
    assert "## Root Cause" in markdown and "2.4.1" in markdown


def test_security_finding_to_agent_to_approval_to_execution_to_verification(tmp_path: Path) -> None:
    """security finding → agent → proposed action → approval → execution → verification."""
    api = make_harness(tmp_path)
    run = api.post("/api/agent/investigate", json={"scenario": "vulnerable_dependency"}).json()  # type: ignore[attr-defined]
    finding = api.get("/api/security/findings").json()[0]  # type: ignore[attr-defined]
    assert finding["status"] == "open" and finding["title"].startswith("DEMO-CVE-2026-0001")
    pending = next(a for a in run["actions"] if a["status"] == "awaiting_approval")
    api.post(f"/api/agent/approve/{pending['action_id']}", role="approver", json={"decision": "approve"})
    done = api.post(f"/api/agent/execute/{pending['action_id']}").json()  # type: ignore[attr-defined]
    verification = [a for a in done["actions"] if a["phase"] == "VERIFY"]
    assert [a["tool"] for a in verification] == ["run_unit_tests", "run_security_scan"]
    assert verification[0]["result"]["passed"] and verification[1]["result"]["findings"] == []
    assert api.get("/api/security/findings").json()[0]["status"] == "remediated"  # type: ignore[attr-defined]
    with make_session_factory(make_engine(api.settings.database_url))() as s:
        trail = [r.action for r in s.scalars(select(AuditLogRecord).where(AuditLogRecord.resource_type == "agent")
                                             .order_by(AuditLogRecord.id))]
    assert trail.index("agent.action.approved") < trail.index("agent.action.succeeded",
                                                              trail.index("agent.action.approved"))
    assert api.get("/api/audit/verify", role="admin").json()["valid"] is True  # type: ignore[attr-defined]


def test_offline_demo_runs_end_to_end(tmp_path: Path) -> None:
    proc = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "demo.py"), "--out-dir", str(tmp_path / "demo"),
                           "--reports-dir", str(tmp_path / "reports")], capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-3000:]
    out = proc.stdout
    for step in range(1, 14):
        assert f"[{step:02d}]" in out, step
    assert "execute before approval -> HTTP 409" in out and "recovered=True" in out
    assert "status: resolved" in out and "Audit chain valid: True" in out and "DEMO COMPLETED" in out
    reports = sorted(p.suffix for p in (tmp_path / "reports").iterdir())
    assert reports == [".html", ".json", ".md"]
    final = next((tmp_path / "reports").glob("*.md")).read_text()
    assert "**Status:** resolved" in final and "rollback_executed" in final
