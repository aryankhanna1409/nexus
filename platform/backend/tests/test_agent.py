"""M9 acceptance tests: command sandbox, policy, approvals, and the three DevSecOps scenarios."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from app.agents import advisories
from app.agents.planner import PlannedAction
from app.agents.policy import Decision, RiskClass, evaluate
from app.agents.runner import CommandNotAllowed, CommandRunner
from app.agents.service import AgentDeps, AgentError, _propose, execute_action
from app.agents.tools import TOOLS
from app.agents.workspace import WorkspaceError, create_workspace, inside
from app.config import Role
from app.db import make_engine, make_session_factory
from app.models import AgentActionRecord, AgentRun, AuditLogRecord, Deployment, IncidentRecord, PipelineRun
from app.security.tokens import Principal

from .api_support import ApiHarness, make_harness

APP_DIR = Path(__file__).resolve().parents[1] / "app"


def _session(api: ApiHarness):  # type: ignore[no-untyped-def]
    return make_session_factory(make_engine(api.settings.database_url))()


def _pending(run: dict[str, Any]) -> dict[str, Any]:
    pending = [a for a in run["actions"] if a["status"] == "awaiting_approval"]
    assert len(pending) == 1, [(a["tool"], a["status"]) for a in run["actions"]]
    return pending[0]


# ---- Command sandbox ------------------------------------------------------------------------


@pytest.fixture()
def workspace(tmp_path: Path) -> tuple[Path, CommandRunner]:
    return create_workspace(tmp_path / "ws", "AGR-test", "vulnerable_dependency")


@pytest.mark.parametrize(("program", "args"), [
    ("bash", ["-c", "id"]), ("sh", ["-c", "id"]), ("rm", ["-rf", "/"]), ("/usr/bin/python3", ["-m", "pytest"]),
    ("python", ["-c", "import os; os.system('id')"]), ("python", ["-m", "pip", "install", "x"]),
    ("python", ["script.py"]), ("git", ["push", "origin"]), ("git", ["clone", "https://example.invalid/x"]),
    ("git", ["-c", "core.sshCommand=id", "status"]), ("git", ["remote", "add", "x", "y"]),
    ("git", ["status", "bad\x00arg"]),
])
def test_runner_rejects_non_allowlisted_commands(workspace: tuple[Path, CommandRunner], program: str,
                                                 args: list[str]) -> None:
    with pytest.raises(CommandNotAllowed):
        workspace[1].run(program, args)


def test_runner_confines_workspace(tmp_path: Path) -> None:
    with pytest.raises(CommandNotAllowed):
        CommandRunner(tmp_path / "elsewhere", tmp_path / "root")
    with pytest.raises(CommandNotAllowed):
        CommandRunner(tmp_path / "root", tmp_path / "root")  # the root itself is not a run workspace


def test_runner_scrubs_environment(workspace: tuple[Path, CommandRunner], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    env = workspace[1]._environment()
    assert "ANTHROPIC_API_KEY" not in env and "LD_PRELOAD" not in env
    assert env["HOME"] == str(workspace[0]) and env["GIT_CONFIG_GLOBAL"] == "/dev/null"


def test_runner_timeout(workspace: tuple[Path, CommandRunner]) -> None:
    path, runner = workspace
    (path / "tests" / "test_slow.py").write_text("import time\n\ndef test_slow():\n    time.sleep(30)\n")
    result = runner.run("python", ["-m", "pytest", "tests/test_slow.py"], timeout_s=2)
    assert result.timed_out and result.returncode is None


def test_runner_never_uses_a_shell() -> None:
    for source in APP_DIR.rglob("*.py"):
        tree = ast.parse(source.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "shell":
                assert isinstance(node.value, ast.Constant) and node.value.value is False, source
            if isinstance(node, ast.Attribute) and node.attr in ("system", "popen", "spawnl", "execv"):
                assert not (isinstance(node.value, ast.Name) and node.value.id == "os"), source


def test_workspace_paths_cannot_escape(workspace: tuple[Path, CommandRunner]) -> None:
    path, _ = workspace
    assert inside(path, "pgw/checksum.py") == (path / "pgw" / "checksum.py").resolve()
    for bad in ("../outside.txt", "/etc/passwd", "pgw/../../x"):
        with pytest.raises(WorkspaceError):
            inside(path, bad)


def test_failed_ci_workspace_has_regression(tmp_path: Path) -> None:
    path, runner = create_workspace(tmp_path / "ws", "AGR-ci", "failed_ci")
    log = runner.run("git", ["log", "--oneline"])
    assert len(log.stdout.splitlines()) == 2
    result = runner.run("python", ["-m", "pytest", "-rf"])
    assert result.returncode == 1 and "FAILED tests/test_checksum.py::test_known_vector" in result.stdout


# ---- Advisories and policy -----------------------------------------------------------------------


def test_synthetic_advisories() -> None:
    findings = advisories.scan("netparse==1.4.2\nfastjsonx==2.1.0\n")
    assert [f.advisory_id for f in findings] == ["DEMO-CVE-2026-0001"]
    assert all(f.advisory_id.startswith("DEMO-CVE-") for f in findings)
    assert advisories.minimal_safe_upgrade("netparse", "1.4.2") == "1.4.3"
    assert advisories.scan("fastjsonx==2.0.3")[0].severity == "MEDIUM"
    with pytest.raises(ValueError):
        advisories.parse_requirements("netparse>=1.0\n")


@pytest.mark.parametrize(("risk", "allow", "expected"), [
    (RiskClass.READ_ONLY, False, Decision.ALLOW), (RiskClass.LOW_RISK, False, Decision.ALLOW),
    (RiskClass.REQUIRES_APPROVAL, False, Decision.NEEDS_APPROVAL),
    (RiskClass.HIGH_RISK, False, Decision.DENY), (RiskClass.HIGH_RISK, True, Decision.NEEDS_APPROVAL),
    (RiskClass.BLOCKED, True, Decision.DENY),
])
def test_policy_table(risk: RiskClass, allow: bool, expected: Decision) -> None:
    assert evaluate(risk, allow).decision is expected


def test_tool_risk_classes_follow_spec() -> None:
    expected = {"run_unit_tests": "READ_ONLY", "run_tests": "READ_ONLY", "run_security_scan": "READ_ONLY",
                "inspect_logs": "READ_ONLY", "generate_report": "LOW_RISK", "generate_patch": "LOW_RISK",
                "modify_dependency": "REQUIRES_APPROVAL", "restart_service": "REQUIRES_APPROVAL",
                "rollback_deployment": "HIGH_RISK", "delete_infrastructure": "BLOCKED"}
    for name, risk in expected.items():
        assert TOOLS[name].risk.value == risk, name
    spec_tools = {"inspect_repository", "inspect_git_diff", "run_unit_tests", "run_linter", "run_security_scan",
                  "inspect_dependencies", "inspect_container", "inspect_logs", "inspect_metrics",
                  "create_incident", "generate_patch", "run_tests", "generate_report", "rollback_deployment"}
    assert spec_tools <= set(TOOLS)


# ---- Scenario 1: vulnerable dependency ------------------------------------------------------------


@pytest.fixture()
def api(tmp_path: Path) -> ApiHarness:
    return make_harness(tmp_path)


def test_vulnerable_dependency_flow(api: ApiHarness) -> None:
    run = api.post("/api/agent/investigate", json={"scenario": "vulnerable_dependency"}).json()  # type: ignore[attr-defined]
    assert run["status"] == "awaiting_approval" and run["state"] == "PLAN"
    pending = _pending(run)
    assert pending["tool"] == "modify_dependency" and pending["risk_class"] == "REQUIRES_APPROVAL"
    assert pending["arguments"] == {"package": "netparse", "version": "1.4.3"}
    assert "approval" in pending["rationale"]
    workspace = Path(api.settings.agent_workspace_root) / run["run_id"]
    assert "netparse==1.4.2" in (workspace / "requirements.txt").read_text()  # nothing changed yet
    findings = api.get("/api/security/findings").json()  # type: ignore[attr-defined]
    assert findings[0]["title"].startswith("DEMO-CVE-2026-0001") and findings[0]["status"] == "open"

    action = pending["action_id"]
    assert api.post(f"/api/agent/execute/{action}").status_code == 409  # type: ignore[attr-defined]  # not approved
    assert api.post(f"/api/agent/approve/{action}", role="operator",  # type: ignore[attr-defined]
                    json={"decision": "approve"}).status_code == 403
    approved = api.post(f"/api/agent/approve/{action}", role="approver",
                        json={"decision": "approve", "comment": "ok"}).json()  # type: ignore[attr-defined]
    assert _pending_or_none(approved, "approved")
    done = api.post(f"/api/agent/execute/{action}").json()  # type: ignore[attr-defined]
    assert done["status"] == "completed" and done["state"] == "CLOSED"
    assert "netparse==1.4.3" in (workspace / "requirements.txt").read_text()
    tools = [(a["tool"], a["status"]) for a in done["actions"]]
    assert tools == [("run_security_scan", "succeeded"), ("create_incident", "succeeded"),
                     ("inspect_dependencies", "succeeded"), ("modify_dependency", "succeeded"),
                     ("run_unit_tests", "succeeded"), ("run_security_scan", "succeeded"),
                     ("generate_report", "succeeded")]
    assert done["actions"][4]["result"]["passed"] is True
    assert done["actions"][5]["result"]["findings"] == []
    assert done["actions"][3]["result"]["deployed"] is False
    assert api.get("/api/security/findings").json()[0]["status"] == "remediated"  # type: ignore[attr-defined]


def _pending_or_none(run: dict[str, Any], status: str) -> bool:
    return any(a["status"] == status for a in run["actions"])


def test_denied_dependency_change_is_never_applied(api: ApiHarness) -> None:
    run = api.post("/api/agent/investigate", json={"scenario": "vulnerable_dependency"}).json()  # type: ignore[attr-defined]
    action = _pending(run)["action_id"]
    after = api.post(f"/api/agent/approve/{action}", role="approver", json={"decision": "deny"}).json()  # type: ignore[attr-defined]
    assert after["status"] == "completed"
    workspace = Path(api.settings.agent_workspace_root) / run["run_id"]
    assert "netparse==1.4.2" in (workspace / "requirements.txt").read_text()
    assert api.post(f"/api/agent/execute/{action}").status_code == 409  # type: ignore[attr-defined]


def test_initiator_cannot_approve_own_action(api: ApiHarness) -> None:
    run = api.post("/api/agent/investigate", role="approver", json={"scenario": "vulnerable_dependency"}).json()  # type: ignore[attr-defined]
    action = _pending(run)["action_id"]
    response = api.post(f"/api/agent/approve/{action}", role="approver", json={"decision": "approve"})
    assert response.status_code == 403 and "separation of duties" in response.text  # type: ignore[attr-defined]


# ---- Scenario 2: failed CI ----------------------------------------------------------------------------


def test_failed_ci_flow(api: ApiHarness) -> None:
    run = api.post("/api/agent/investigate", json={"scenario": "failed_ci"}).json()  # type: ignore[attr-defined]
    actions = {a["tool"]: a for a in run["actions"]}
    assert actions["run_unit_tests"]["result"]["failed_tests"] == [
        {"file": "tests/test_checksum.py", "test": "test_known_vector"}]
    assert actions["inspect_git_diff"]["result"]["changed_files"] == ["pgw/checksum.py"]
    assert "Optimise checksum" in actions["generate_patch"]["rationale"]
    assert "+        total = (total & 0xFFFF) + (total >> 16)" in actions["generate_patch"]["result"]["patch"]
    pending = _pending(run)
    assert pending["tool"] == "apply_patch"
    api.post(f"/api/agent/approve/{pending['action_id']}", role="approver", json={"decision": "approve"})
    done = api.post(f"/api/agent/execute/{pending['action_id']}").json()  # type: ignore[attr-defined]
    assert done["status"] == "completed"
    verify = next(a for a in done["actions"] if a["tool"] == "run_tests")
    assert verify["result"]["passed"] is True and verify["result"]["lint"]["clean"] is True


# ---- Scenario 3: production anomaly --------------------------------------------------------------------


def test_production_anomaly_with_high_risk_disabled(api: ApiHarness) -> None:
    api.post("/api/pipeline/run", json={"scenario": "seeded"})
    run = api.post("/api/agent/investigate", json={"scenario": "production_anomaly"}).json()  # type: ignore[attr-defined]
    rollback = next(a for a in run["actions"] if a["tool"] == "rollback_deployment")
    assert rollback["status"] == "blocked" and "AGENT_ALLOW_HIGH_RISK" in rollback["result"]["policy_reason"]
    assert run["status"] == "completed"
    incident = api.get("/api/incidents/INC-2026-001").json()  # type: ignore[attr-defined]
    assert incident["status"] == "investigating"
    deployments = api.get("/api/deployments").json()  # type: ignore[attr-defined]
    assert all(d["status"] == "active" for d in deployments)
    assert api.post(f"/api/agent/execute/{rollback['action_id']}", role="admin").status_code == 409  # type: ignore[attr-defined]


def test_production_anomaly_rollback_and_recovery(tmp_path: Path) -> None:
    api = make_harness(tmp_path, agent_allow_high_risk=True)
    api.post("/api/pipeline/run", json={"scenario": "seeded"})
    run = api.post("/api/agent/investigate", json={"scenario": "production_anomaly"}).json()  # type: ignore[attr-defined]
    rca = next(a for a in run["actions"] if a["tool"] == "request_rca")
    assert rca["result"]["root_cause_type"] == "deployment_regression"
    pending = _pending(run)
    assert pending["tool"] == "rollback_deployment" and pending["risk_class"] == "HIGH_RISK"
    assert "HIGH_RISK" in pending["rationale"]
    action = pending["action_id"]
    api.post(f"/api/agent/approve/{action}", role="approver", json={"decision": "approve"})
    response = api.post(f"/api/agent/execute/{action}", role="operator")
    assert response.status_code == 403 and "admin" in response.text  # type: ignore[attr-defined]
    done = api.post(f"/api/agent/execute/{action}", role="admin").json()  # type: ignore[attr-defined]
    assert done["status"] == "completed", done
    tools = [a["tool"] for a in done["actions"]]
    assert tools[-3:] == ["inspect_metrics", "close_incident", "generate_report"]
    verify = done["actions"][-3]["result"]
    assert verify["recovered"] is True and verify["open_anomalies"] == []
    executed = next(a for a in done["actions"] if a["tool"] == "rollback_deployment")
    assert executed["executed_by"] == "test-admin" and executed["approved_by"] == "test-approver"
    assert executed["result"]["simulated"] is True
    incident = api.get("/api/incidents/INC-2026-001").json()  # type: ignore[attr-defined]
    assert incident["status"] == "resolved"
    rollback_epoch = next(e["epoch"] for e in incident["events"] if e["type"] == "rollback_executed")
    # Incident window now ends when the degradation ended after the rollback, not at the end of the data.
    assert rollback_epoch <= incident["end_epoch"] <= rollback_epoch + 600
    assert {"agent_opened", "rollback_executed", "incident_resolved"} <= {e["type"] for e in incident["events"]}
    assert [i["incident_id"] for i in api.get("/api/incidents").json()] == ["INC-2026-001"]  # type: ignore[attr-defined]
    with _session(api) as s:
        dep = s.scalars(select(Deployment).where(Deployment.node_id == "pgw-1", Deployment.run_id == 1)).one()
        assert dep.status == "rolled_back"
        verification = s.get(PipelineRun, verify["run_id"])
        assert verification is not None and verification.params["purpose"] == "rollback-verification"
        actions = {r.action for r in s.scalars(select(AuditLogRecord))}
    assert {"agent.run.start", "agent.action.proposed", "agent.action.approved", "agent.action.succeeded",
            "agent.action.execute_rejected", "agent.run.closed"} <= actions


# ---- Blocked actions and direct-service bypass attempts -------------------------------------------


def test_blocked_action_never_executes(api: ApiHarness) -> None:
    run = api.post("/api/agent/investigate", json={"scenario": "vulnerable_dependency"}).json()  # type: ignore[attr-defined]
    with _session(api) as s:
        deps = AgentDeps(s, api.settings, api.client.app.state.llm)  # type: ignore[attr-defined]
        agent_run = s.get(AgentRun, run["run_id"])
        assert agent_run is not None
        blocked = _propose(deps, agent_run, PlannedAction("ACT", "delete_infrastructure", {"target": "pgw-1"},
                                                          "test"), 99)
        s.commit()
        assert blocked.status == "blocked"
        admin = Principal("someone-else", Role.ADMIN)
        with pytest.raises(AgentError):
            execute_action(deps, blocked.action_id, admin)
        assert s.get(AgentActionRecord, blocked.action_id).status == "blocked"  # type: ignore[union-attr]
    assert api.post(f"/api/agent/approve/{blocked.action_id}", role="admin",  # type: ignore[attr-defined]
                    json={"decision": "approve"}).status_code == 409


def test_unapproved_action_cannot_execute_via_service(api: ApiHarness) -> None:
    run = api.post("/api/agent/investigate", json={"scenario": "failed_ci"}).json()  # type: ignore[attr-defined]
    action = _pending(run)["action_id"]
    with _session(api) as s:
        deps = AgentDeps(s, api.settings, api.client.app.state.llm)  # type: ignore[attr-defined]
        with pytest.raises(AgentError, match="only approved"):
            execute_action(deps, action, Principal("root", Role.ADMIN))
    workspace = Path(api.settings.agent_workspace_root) / run["run_id"]
    assert "fold only at the end" in (workspace / "pgw" / "checksum.py").read_text()


def test_agent_api_validation_and_status(api: ApiHarness) -> None:
    assert api.post("/api/agent/investigate", role="viewer", json={"scenario": "failed_ci"}).status_code == 403  # type: ignore[attr-defined]
    assert api.post("/api/agent/investigate", json={"scenario": "rm -rf"}).status_code == 422  # type: ignore[attr-defined]
    assert api.post("/api/agent/investigate", json={"scenario": "production_anomaly"}).status_code == 404  # type: ignore[attr-defined]
    assert api.post("/api/agent/approve/not-an-id", role="approver", json={"decision": "approve"}).status_code == 422  # type: ignore[attr-defined]
    status = api.get("/api/agent/status").json()  # type: ignore[attr-defined]
    assert status["policy"]["tools"]["delete_infrastructure"] == "BLOCKED"
    assert status["policy"]["allow_high_risk"] is False


def test_failed_ci_without_identifiable_failures_escalates(api: ApiHarness, monkeypatch: pytest.MonkeyPatch) -> None:
    """A broken test environment (e.g. pytest missing) must not be misdiagnosed as a code change."""
    from app.agents import tools as agent_tools

    def broken(ctx: Any) -> dict[str, Any]:
        return {"passed": False, "returncode": 1, "timed_out": False, "counts": {}, "failed_tests": [],
                "output_tail": "No module named pytest"}

    monkeypatch.setattr(agent_tools, "_pytest", broken)
    run = api.post("/api/agent/investigate", json={"scenario": "failed_ci"}).json()  # type: ignore[attr-defined]
    assert run["status"] == "completed"
    assert [a["tool"] for a in run["actions"]] == ["run_unit_tests", "generate_report"]
    assert "cannot be attributed" in run["actions"][-1]["rationale"]
