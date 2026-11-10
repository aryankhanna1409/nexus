#!/usr/bin/env python3
"""Aegis-Net offline end-to-end demo (`make demo`).

Runs the 13 steps of spec §23 against the real FastAPI application in-process,
with a fresh SQLite database, the deterministic mock LLM provider and synthetic
data. Every step goes through the API with role-scoped tokens, so authentication,
RBAC, policy gates and the audit log are all exercised. No network access, API
key or Docker is required.

HIGH_RISK actions are enabled *for this demo only* (AGENT_ALLOW_HIGH_RISK=true),
and the production rollback is a simulation: telemetry is re-simulated with the
deployment reverted.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings, parse_token_specs  # noqa: E402
from app.main import create_app  # noqa: E402
from app.security.tokens import generate_token, hash_token  # noqa: E402

ROLES = ("viewer", "operator", "approver", "admin")


class DemoError(Exception):
    pass


class Demo:
    def __init__(self, out_dir: Path, reports_dir: Path, quiet: bool) -> None:
        self.out_dir, self.reports_dir, self.quiet = out_dir, reports_dir, quiet
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        reports_dir.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{out_dir / 'demo.db'}"
        cfg = Config(str(REPO_ROOT / "backend" / "alembic.ini"))
        cfg.set_main_option("script_location", str(REPO_ROOT / "backend" / "alembic"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        self.tokens = {role: generate_token() for role in ROLES}
        spec = ",".join(f"demo-{r}:{r}:{hash_token(t)}" for r, t in self.tokens.items())
        settings = Settings(database_url=url, data_dir=out_dir / "data", api_tokens=parse_token_specs(spec),
                            llm_provider="mock", agent_allow_high_risk=True,
                            agent_workspace_root=out_dir / "workspaces", log_level="WARNING")
        self.client = TestClient(create_app(settings))
        self.step_no = 0

    def call(self, method: str, path: str, role: str, body: dict[str, Any] | None = None,
             params: dict[str, Any] | None = None, expect: int = 200) -> Any:
        response = self.client.request(method, path, headers={"Authorization": f"Bearer {self.tokens[role]}"},
                                       json=body, params=params)
        if response.status_code != expect:
            raise DemoError(f"{method} {path} as {role}: HTTP {response.status_code}: {response.text[:300]}")
        return response.json() if "json" in response.headers.get("content-type", "") else response.text

    def step(self, title: str) -> None:
        self.step_no += 1
        print(f"\n[{self.step_no:02d}] {title}")

    def say(self, text: str) -> None:
        print(textwrap.indent(text, "     "))

    def run(self) -> int:
        print("Aegis-Net offline demo — synthetic data, deterministic mock LLM provider, simulated rollback")

        self.step("Generate realistic telemetry, inject the seeded incident, analyse call logs, detect, correlate")
        run = self.call("POST", "/api/pipeline/run", "operator", {"scenario": "seeded", "seed": 7}, expect=201)
        self.say(f"pipeline run {run['id']}: data {run['params']['minutes']} min, fingerprint {run['fingerprint'][:12]}…")
        self.step("Seeded incident: packet-gateway 2.4.1 deployed to pgw-1 at 14:05 (memory leak)")
        deployments = self.call("GET", "/api/deployments", "viewer")
        for d in deployments:
            self.say(f"deployment {d['service']} {d['from_version']} -> {d['to_version']} on {d['node_id']} at {d['deployed_at']}")
        self.step("Process call logs with the C library (libcallanalyzer)")
        calls = self.call("GET", "/api/calls/statistics", "viewer")
        call_anoms = self.call("GET", "/api/calls/anomalies", "viewer")
        self.say(f"{calls['total_calls']} calls, success {calls['success_rate']:.1%}, drop {calls['drop_rate']:.2%}; "
                 f"{len(call_anoms)} call anomalies, e.g. {call_anoms[0]['description'] if call_anoms else '-'}")
        self.step("Detect anomalies in network KPIs")
        anomalies = self.call("GET", "/api/network/anomalies", "viewer")
        first = {}
        for a in anomalies:
            first.setdefault(a["metric"], a["timestamp"][11:16])
        self.say(f"{len(anomalies)} anomaly episodes; first onsets: "
                 + ", ".join(f"{m} {t}" for m, t in sorted(first.items(), key=lambda kv: kv[1])[:7]))
        self.step("Correlate events and create the incident")
        incidents = self.call("GET", "/api/incidents", "viewer")
        if not incidents:
            raise DemoError("no incident was created")
        incident_id = incidents[0]["incident_id"]
        incident = self.call("GET", f"/api/incidents/{incident_id}", "viewer")
        top = incident["suspected_causes"][0]
        self.say(f"{incident_id} {incident['severity']} cells {', '.join(incident['affected_cells'])}; "
                 f"leading correlation hypothesis {top['cause_type']} ({top['score']}), confidence {incident['confidence']}")
        for e in incident["events"][:6]:
            self.say(f"  {e['timestamp'][11:16]} {e['type']:<16} {e['description']}")
        self.step("Incident timeline recorded; health score")
        overview = self.call("GET", "/api/network/overview", "viewer")
        self.say(f"network health score {overview['health_score']}/100")

        self.step("Run AI root-cause analysis (tool-driven investigation)")
        rca = self.call("POST", f"/api/incidents/{incident_id}/investigate", "operator", expect=201)
        self.say(f"[{rca['provider']}] {rca['status']}: {rca['root_cause']} (confidence {rca['confidence']:.0%}, "
                 f"{len(rca['tool_calls'])} tool calls)")
        for fact in rca["facts"][:4]:
            self.say(f"  fact: {fact['statement']} [{', '.join(fact['tool_call_ids'])}]")
        for alt in rca["alternative_hypotheses"]:
            self.say(f"  alternative: {alt['cause_type']} ({alt['confidence']}) — {alt['assessment']}")

        self.step("Generate an incident report")
        report = self.call("POST", "/api/reports/generate", "operator", {"incident_id": incident_id}, expect=201)
        self.say(f"{report['report_id']} generated")

        self.step("Invoke the DevSecOps agent on the production anomaly")
        agent = self.call("POST", "/api/agent/investigate", "operator", {"scenario": "production_anomaly",
                                                                         "incident_id": incident_id}, expect=201)
        for a in agent["actions"]:
            self.say(f"  {a['phase']:<8} {a['tool']:<22} {a['risk_class']:<18} {a['status']}")

        self.step("Proposed remediation (awaiting approval)")
        pending = [a for a in agent["actions"] if a["status"] == "awaiting_approval"]
        if not pending:
            raise DemoError("agent did not propose a remediation awaiting approval")
        action = pending[0]
        self.say(f"{action['tool']} {json.dumps(action['arguments'])}\n  rationale: {action['rationale']}")

        self.step("Execute safe actions: approver approves, admin executes the (simulated) rollback")
        denied = self.client.post(f"/api/agent/execute/{action['action_id']}",
                                  headers={"Authorization": f"Bearer {self.tokens['admin']}"})
        self.say(f"execute before approval -> HTTP {denied.status_code} (policy gate)")
        self.call("POST", f"/api/agent/approve/{action['action_id']}", "approver",
                  {"decision": "approve", "comment": "demo approval"})
        final = self.call("POST", f"/api/agent/execute/{action['action_id']}", "admin")
        for a in final["actions"][len(agent["actions"]) - 1:]:
            self.say(f"  {a['phase']:<8} {a['tool']:<22} {a['status']}")

        self.step("Verify recovery")
        verify = [a for a in final["actions"] if a["tool"] == "inspect_metrics" and a["arguments"].get("run_id")]
        if not verify:
            raise DemoError("recovery verification did not run")
        result = verify[-1]["result"]
        self.say(f"recovered={result['recovered']}; last 30 min vs baseline: "
                 + ", ".join(f"{m} {result['last_30_min'][m]} (baseline {result['baseline'][m]})"
                             for m in ("memory_utilization", "latency_ms", "call_drop_rate")))
        if not result["recovered"]:
            raise DemoError("recovery was not verified")

        self.step("Final incident report")
        final_report = self.call("POST", "/api/reports/generate", "operator", {"incident_id": incident_id}, expect=201)
        rid = final_report["report_id"]
        markdown = self.call("GET", f"/api/reports/{rid}", "viewer", params={"format": "markdown"})
        html = self.call("GET", f"/api/reports/{rid}", "viewer", params={"format": "html"})
        (self.reports_dir / f"{rid}.md").write_text(markdown, encoding="utf-8")
        (self.reports_dir / f"{rid}.html").write_text(html, encoding="utf-8")
        (self.reports_dir / f"{rid}.json").write_text(json.dumps(final_report["report"], indent=2), encoding="utf-8")
        status = self.call("GET", f"/api/incidents/{incident_id}", "viewer")["status"]
        chain = self.call("GET", "/api/audit/verify", "admin")
        summary = markdown.split("## KPI Analysis")[0]
        self.say(summary.strip()[:1500])
        print(f"\nIncident {incident_id} status: {status}. Audit chain valid: {chain['valid']} ({chain['rows']} rows).")
        print(f"Report written to {self.reports_dir / rid}.{{md,html,json}}")
        print("DEMO COMPLETED")
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out-dir", type=Path, default=REPO_ROOT / "data" / "demo")
    parser.add_argument("--reports-dir", type=Path, default=REPO_ROOT / "reports")
    args = parser.parse_args(argv)
    try:
        return Demo(args.out_dir, args.reports_dir, quiet=False).run()
    except DemoError as exc:
        print(f"\nDEMO FAILED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
