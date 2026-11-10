"""Deterministic scenario playbooks (spec §11). Pure functions of the run's action history.

Each step names the tool, its arguments (built from earlier results, never from
LLM text) and a rationale that is recorded before execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.models import AgentActionRecord, AgentRun

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass(frozen=True)
class PlannedAction:
    phase: str
    tool: str
    arguments: dict[str, Any]
    rationale: str


def _done(history: list[AgentActionRecord], tool: str, **match: Any) -> list[AgentActionRecord]:
    return [a for a in history if a.tool == tool
            and all(a.arguments.get(k) == v for k, v in match.items())]


def _last(history: list[AgentActionRecord], tool: str, **match: Any) -> AgentActionRecord | None:
    found = _done(history, tool, **match)
    return found[-1] if found else None


def _ok(action: AgentActionRecord | None) -> bool:
    return action is not None and action.status == "succeeded"


def _report(rationale: str) -> PlannedAction:
    return PlannedAction("CLOSE", "generate_report", {}, rationale)


def _closing(history: list[AgentActionRecord], rationale: str) -> PlannedAction | None:
    return None if _last(history, "generate_report") else _report(rationale)


def _vulnerable_dependency(run: AgentRun, history: list[AgentActionRecord]) -> PlannedAction | None:
    scan = _last(history, "run_security_scan")
    if scan is None:
        return PlannedAction("OBSERVE", "run_security_scan", {},
                             "Scan pinned dependencies against the advisory database.")
    first_scan = _done(history, "run_security_scan")[0]
    findings = sorted(first_scan.result.get("findings", []), key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    if not findings:
        return _closing(history, "No vulnerable dependencies found; record the clean result.")
    if not _last(history, "create_incident"):
        return PlannedAction("OBSERVE", "create_incident", {"kind": "security_finding"},
                             f"Record {len(findings)} finding(s), led by {findings[0]['advisory_id']} "
                             f"({findings[0]['severity']}) in {findings[0]['package']}.")
    deps = _last(history, "inspect_dependencies")
    if deps is None:
        return PlannedAction("ANALYZE", "inspect_dependencies", {},
                             "Determine the smallest released version that fixes the advisory.")
    top = findings[0]
    safe = next((d["minimal_safe_upgrade"] for d in deps.result.get("dependencies", [])
                 if d["package"] == top["package"]), None)
    change = _last(history, "modify_dependency")
    if change is None:
        if safe is None:
            return _closing(history, f"No fixed release of {top['package']} exists; escalate to a human.")
        return PlannedAction("ACT", "modify_dependency", {"package": top["package"], "version": safe},
                             f"Upgrade {top['package']} {top['installed']} -> {safe}, the smallest release "
                             f"that fixes {top['advisory_id']}. Changes a dependency, so it needs approval; "
                             "it is not deployed.")
    if change.status in ("denied", "failed", "blocked"):
        return _closing(history, f"Dependency change was {change.status}; report without remediation.")
    if len(_done(history, "run_unit_tests")) == 0:
        return PlannedAction("VERIFY", "run_unit_tests", {}, "Confirm the upgrade does not break the tests.")
    if len(_done(history, "run_security_scan")) < 2:
        return PlannedAction("VERIFY", "run_security_scan", {}, "Confirm the advisory no longer applies.")
    return _closing(history, "Summarise the remediation and verification results.")


def _failed_ci(run: AgentRun, history: list[AgentActionRecord]) -> PlannedAction | None:
    tests = _done(history, "run_unit_tests")
    if not tests:
        return PlannedAction("OBSERVE", "run_unit_tests", {}, "Reproduce the CI result locally in the sandbox.")
    if tests[0].result.get("passed"):
        return _closing(history, "Tests pass; nothing to fix.")
    if not tests[0].result.get("failed_tests"):
        return _closing(history, f"The test run failed (exit code {tests[0].result.get('returncode')}) without "
                                 "reporting failing tests, so the failure cannot be attributed to a change "
                                 "(likely an environment or collection error); escalate to a human.")
    if not _last(history, "inspect_logs"):
        return PlannedAction("OBSERVE", "inspect_logs", {"source": "ci"}, "Identify the failing tests from the CI log.")
    diff = _last(history, "inspect_git_diff")
    if diff is None:
        return PlannedAction("ANALYZE", "inspect_git_diff", {"base": "HEAD~1", "head": "HEAD"},
                             "Inspect the most recent change, which is the first suspect for a new failure.")
    failing = {f["file"] for f in tests[0].result.get("failed_tests", [])}
    # Hypothesis: a module changed in the last commit is exercised by a failing test file.
    suspects = [f for f in diff.result.get("changed_files", [])
                if f.endswith(".py") and any(t.endswith(f"test_{f.rsplit('/', 1)[-1]}") for t in failing)]
    patch = _last(history, "generate_patch")
    if patch is None:
        if not suspects:
            return _closing(history, "The last commit does not touch code exercised by the failing tests; "
                                     "escalate to a human.")
        return PlannedAction("PLAN", "generate_patch", {"file": suspects[0]},
                             f"Hypothesis: commit '{diff.result.get('commit', '')}' broke {suspects[0]} "
                             f"(failing: {', '.join(sorted(failing))}). Propose reverting that file's change.")
    if not _ok(patch):
        return _closing(history, "Patch generation failed; escalate to a human.")
    applied = _last(history, "apply_patch")
    if applied is None:
        return PlannedAction("ACT", "apply_patch", {"patch_path": patch.result["patch_path"]},
                             "Apply the revert patch in the sandbox. Modifies source code, so it needs approval.")
    if applied.status in ("denied", "failed", "blocked"):
        return _closing(history, f"Patch application was {applied.status}; report without a fix.")
    if not _last(history, "run_tests"):
        return PlannedAction("VERIFY", "run_tests", {}, "Run the full tests and linter on the patched code.")
    return _closing(history, "Summarise the diagnosis, patch and verification.")


def _production_anomaly(run: AgentRun, history: list[AgentActionRecord]) -> PlannedAction | None:
    incident_id = run.incident_id
    assert incident_id is not None
    if not _done(history, "inspect_metrics"):
        return PlannedAction("OBSERVE", "inspect_metrics", {"incident_id": incident_id},
                             "Gather current KPIs for the incident's cells against their baseline.")
    if not _last(history, "create_incident"):
        return PlannedAction("OBSERVE", "create_incident", {"kind": "incident_ack"},
                             f"Take ownership of {incident_id} and mark it under investigation.")
    rca = _last(history, "request_rca")
    if rca is None:
        return PlannedAction("ANALYZE", "request_rca", {"incident_id": incident_id},
                             "Ask the RCA engine for an evidence-based root-cause hypothesis.")
    container = _last(history, "inspect_container")
    if container is None:
        return PlannedAction("ANALYZE", "inspect_container", {},
                             "Check the deployment registry of the affected gateway nodes.")
    if rca.result.get("root_cause_type") != "deployment_regression":
        return _closing(history, f"RCA leading hypothesis is {rca.result.get('root_cause_type')}; no automated "
                                 "remediation is defined for it. Report recommendations for humans.")
    candidates = [d for d in container.result.get("deployments", [])
                  if d["status"] == "active" and d["preceded_incident"]]
    rollback = _last(history, "rollback_deployment")
    if rollback is None:
        if not candidates:
            return _closing(history, "No active deployment preceded the incident; nothing to roll back.")
        d = candidates[0]
        return PlannedAction("ACT", "rollback_deployment", {"deployment_id": d["deployment_id"]},
                             f"RCA attributes the incident to {d['service']} {d['to_version']} on {d['node_id']} "
                             f"(confidence {rca.result.get('confidence', 0):.0%}). Roll back to {d['from_version']} "
                             "(simulated). Production rollback is HIGH_RISK: approval and admin execution required.")
    if rollback.status in ("denied", "failed", "blocked"):
        return _closing(history, f"Rollback was {rollback.status}; the incident stays open with the RCA "
                                 "recommendation for human action.")
    verify_run = rollback.result.get("verification_run_id")
    if not _done(history, "inspect_metrics", run_id=verify_run):
        return PlannedAction("VERIFY", "inspect_metrics", {"incident_id": incident_id, "run_id": verify_run},
                             "Compare post-rollback KPIs with the pre-incident baseline.")
    verified = bool(_last(history, "inspect_metrics", run_id=verify_run).result.get("recovered"))  # type: ignore[union-attr]
    if verified and not _last(history, "close_incident"):
        return PlannedAction("CLOSE", "close_incident", {"incident_id": incident_id},
                             "Recovery verified against baseline; resolve the incident.")
    return _closing(history, "Produce the final incident report" + ("" if verified else
                                                                    " (recovery NOT verified; incident left open)."))


PLAYBOOKS = {"vulnerable_dependency": _vulnerable_dependency, "failed_ci": _failed_ci,
             "production_anomaly": _production_anomaly}


def next_action(run: AgentRun, history: list[AgentActionRecord]) -> PlannedAction | None:
    return PLAYBOOKS[run.scenario](run, history)
