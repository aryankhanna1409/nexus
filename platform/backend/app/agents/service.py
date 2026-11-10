"""DevSecOps agent orchestration: OBSERVE -> ANALYZE -> PLAN -> ACT -> VERIFY -> CLOSE.

The planner is deterministic: it picks the next allowlisted tool and its
arguments from the results of earlier actions. Every action is persisted with
its rationale *before* it executes. The policy is evaluated at proposal time and
re-evaluated at execution time, inside `execute_action`, so no API path can
bypass it. The LLM participates only through the RCA engine (read-only
tools); it never selects or parameterises agent tools or commands.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agents.planner import PlannedAction, next_action
from app.agents.policy import Decision, RiskClass, evaluate, executor_role
from app.agents.runner import CommandNotAllowed
from app.agents.tools import TOOLS, AgentContext, AgentToolError
from app.agents.workspace import WorkspaceError, create_workspace
from app.config import Role, Settings
from app.llm.factory import ProviderChoice
from app.models import AgentActionRecord, AgentRun, IncidentRecord
from app.observability.context import agent_run_id_var, incident_id_var
from app.observability.logging import get_logger
from app.observability.metrics import Metrics
from app.security.audit import record_audit
from app.security.tokens import Principal

SCENARIOS = ("vulnerable_dependency", "failed_ci", "production_anomaly")
PHASES = ("OBSERVE", "ANALYZE", "PLAN", "ACT", "VERIFY", "CLOSE")
MAX_ACTIONS_PER_RUN = 40
log = get_logger("agent")


class AgentError(Exception):
    """Invalid request against the agent (bad state, missing permissions)."""

    def __init__(self, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class AgentDeps:
    session: Session
    settings: Settings
    llm: ProviderChoice
    metrics: Metrics | None = None

    def count(self, tool: str, status: str) -> None:
        if self.metrics is not None:
            self.metrics.agent_actions.labels(tool, status).inc()


def _audit(deps: AgentDeps, actor: str, role: str, action: str, resource: str, outcome: str = "success",
           **details: Any) -> None:
    record_audit(deps.session, actor=actor, role=role, action=action, resource_type="agent",
                 resource_id=resource, outcome=outcome, details=details, commit=False)


def _context(deps: AgentDeps, run: AgentRun, actor: str) -> AgentContext:
    ctx = AgentContext(deps.session, deps.settings, run, actor, deps.llm)
    if run.workspace:
        from pathlib import Path

        from app.agents.runner import CommandRunner

        ctx.workspace = Path(run.workspace)
        ctx.runner = CommandRunner(ctx.workspace, deps.settings.agent_workspace_root)
    return ctx


def _history(deps: AgentDeps, run: AgentRun) -> list[AgentActionRecord]:
    return list(deps.session.scalars(select(AgentActionRecord).where(AgentActionRecord.run_id == run.run_id)
                                     .order_by(AgentActionRecord.sequence)))


def _execute(deps: AgentDeps, run: AgentRun, action: AgentActionRecord, executor: str, executor_role_name: str) -> None:
    tool = TOOLS[action.tool]
    action.status = "executing"
    action.executed_by = executor
    action.executed_epoch = int(time.time())
    deps.session.flush()
    try:
        args = tool.args_model.model_validate(action.arguments)
        result = tool.run(_context(deps, run, executor), args)
        action.status = "succeeded"
        action.result = result
    except (AgentToolError, CommandNotAllowed, WorkspaceError, ValidationError, ValueError) as exc:
        action.status = "failed"
        action.result = {"error": str(exc)[:2000]}
    deps.count(action.tool, action.status)
    log.info("agent action", extra={"action_id": action.action_id, "tool": action.tool,
                                    "status": action.status, "risk_class": action.risk_class})
    _audit(deps, executor, executor_role_name, f"agent.action.{action.status}", action.action_id,
           tool=action.tool, risk_class=action.risk_class, run_id=run.run_id,
           outcome_summary={k: v for k, v in action.result.items() if k in ("error", "passed", "recovered",
                                                                           "findings", "report_id", "simulated")})


def _propose(deps: AgentDeps, run: AgentRun, planned: PlannedAction, sequence: int) -> AgentActionRecord:
    tool = TOOLS[planned.tool]
    decision = evaluate(tool.risk, deps.settings.agent_allow_high_risk)
    action = AgentActionRecord(
        action_id=f"ACT-{run.run_id[4:]}-{sequence:02d}", run_id=run.run_id, sequence=sequence,
        phase=planned.phase, tool=planned.tool, risk_class=tool.risk.value, status="proposed",
        rationale=planned.rationale, created_epoch=int(time.time()), approved_by=None, approved_epoch=None,
        executed_by=None, executed_epoch=None, arguments=planned.arguments,
        result={"policy": decision.decision.value, "policy_reason": decision.reason})
    deps.session.add(action)
    deps.session.flush()
    _audit(deps, f"agent:{run.run_id}", "agent", "agent.action.proposed", action.action_id, tool=planned.tool,
           risk_class=tool.risk.value, rationale=planned.rationale, policy=decision.decision.value,
           arguments=planned.arguments)
    if decision.decision is Decision.DENY:
        action.status = "blocked"
        deps.count(planned.tool, "blocked")
        log.warning("agent action blocked by policy", extra={"action_id": action.action_id, "tool": planned.tool})
        _audit(deps, "policy-engine", "system", "agent.action.blocked", action.action_id, outcome="denied",
               tool=planned.tool, reason=decision.reason)
    elif decision.decision is Decision.NEEDS_APPROVAL:
        action.status = "awaiting_approval"
    return action


def advance(deps: AgentDeps, run: AgentRun) -> AgentRun:
    """Proposes and auto-executes actions until approval is needed or the run closes."""
    run_token = agent_run_id_var.set(run.run_id)
    incident_token = incident_id_var.set(run.incident_id)
    try:
        return _advance(deps, run)
    finally:
        agent_run_id_var.reset(run_token)
        incident_id_var.reset(incident_token)


def _advance(deps: AgentDeps, run: AgentRun) -> AgentRun:
    for _ in range(MAX_ACTIONS_PER_RUN):
        history = _history(deps, run)
        if any(a.status in ("awaiting_approval", "approved") for a in history):
            run.status = "awaiting_approval"
            break
        if len(history) >= MAX_ACTIONS_PER_RUN:
            run.status, run.state = "failed", "CLOSED"
            run.summary = {**run.summary, "failure": "action limit reached"}
            break
        planned = next_action(run, history)
        if planned is None:
            run.status = "completed"
            run.state = "CLOSED"
            run.finished_epoch = int(time.time())
            _audit(deps, f"agent:{run.run_id}", "agent", "agent.run.closed", run.run_id,
                   outcome=run.summary.get("outcome", "completed"))
            break
        if PHASES.index(planned.phase) < PHASES.index(run.state if run.state in PHASES else "OBSERVE"):
            raise AgentError(f"planner attempted to move from {run.state} back to {planned.phase}", 500)
        if planned.phase != "ACT":
            run.state = planned.phase
        action = _propose(deps, run, planned, len(history) + 1)
        if action.status == "proposed":
            _execute(deps, run, action, f"agent:{run.run_id}", "agent")
            run.summary = _summary_after(run, action)
        elif action.status == "awaiting_approval":
            run.status = "awaiting_approval"
            run.state = "PLAN"  # the plan is proposed; ACT starts once it is approved and executed
            break
        deps.session.flush()
    deps.session.commit()
    return run


def _summary_after(run: AgentRun, action: AgentActionRecord) -> dict[str, Any]:
    summary = dict(run.summary)
    if action.tool == "inspect_metrics" and action.status == "succeeded" \
            and action.arguments.get("run_id") is not None:
        summary["recovery_verified"] = bool(action.result.get("recovered"))
    return summary


def start_run(deps: AgentDeps, scenario: str, principal: Principal, incident_id: str | None = None) -> AgentRun:
    if scenario not in SCENARIOS:
        raise AgentError(f"unknown scenario {scenario!r}", 422)
    if scenario == "production_anomaly":
        if incident_id is None:
            incident_id = deps.session.scalar(select(IncidentRecord.incident_id).where(
                IncidentRecord.status.in_(("open", "investigating"))).order_by(IncidentRecord.start_epoch.desc()))
        if incident_id is None or deps.session.get(IncidentRecord, incident_id) is None:
            raise AgentError("production_anomaly needs an existing open incident", 404)
    elif incident_id is not None:
        raise AgentError(f"scenario {scenario} does not take an incident", 422)
    count = deps.session.scalar(select(func.count()).select_from(AgentRun)) or 0
    run = AgentRun(run_id=f"AGR-{count + 1:04d}{secrets.token_hex(3)}", scenario=scenario, state="OBSERVE",
                   status="running", incident_id=incident_id, started_epoch=int(time.time()),
                   finished_epoch=None, started_by=principal.name, workspace=None, summary={})
    deps.session.add(run)
    deps.session.flush()
    if scenario in ("vulnerable_dependency", "failed_ci"):
        try:
            path, _ = create_workspace(deps.settings.agent_workspace_root, run.run_id, scenario)
        except WorkspaceError as exc:
            raise AgentError(f"workspace setup failed: {exc}", 500) from exc
        run.workspace = str(path)
    _audit(deps, principal.name, principal.role.name.lower(), "agent.run.start", run.run_id,
           scenario=scenario, incident_id=incident_id, workspace=run.workspace)
    return advance(deps, run)


def _action_and_run(deps: AgentDeps, action_id: str) -> tuple[AgentActionRecord, AgentRun]:
    action = deps.session.get(AgentActionRecord, action_id)
    if action is None:
        raise AgentError(f"action {action_id} not found", 404)
    run = deps.session.get(AgentRun, action.run_id)
    assert run is not None
    return action, run


def approve_action(deps: AgentDeps, action_id: str, principal: Principal, approve: bool, comment: str) -> AgentRun:
    action, run = _action_and_run(deps, action_id)
    role = principal.role.name.lower()
    if not principal.has(Role.APPROVER):
        raise AgentError("only approvers may approve actions", 403)
    if action.status != "awaiting_approval":
        raise AgentError(f"action is {action.status}, not awaiting approval")
    if principal.name == run.started_by:
        _audit(deps, principal.name, role, "agent.action.self_approval_rejected", action_id, outcome="denied")
        deps.session.commit()
        raise AgentError("separation of duties: the run's initiator cannot approve its actions", 403)
    action.approved_by = principal.name
    action.approved_epoch = int(time.time())
    action.status = "approved" if approve else "denied"
    action.result = {**action.result, "approval_comment": comment}
    _audit(deps, principal.name, role, f"agent.action.{action.status}", action_id, tool=action.tool,
           risk_class=action.risk_class, comment=comment)
    if not approve:
        run.status = "running"
        return advance(deps, run)
    run.status = "awaiting_approval"  # approved but not yet executed
    deps.session.commit()
    return run


def execute_action(deps: AgentDeps, action_id: str, principal: Principal) -> AgentRun:
    """Executes an approved action after re-checking every policy rule, then continues the run."""
    action, run = _action_and_run(deps, action_id)
    role = principal.role.name.lower()
    risk = RiskClass(action.risk_class)
    problem = None
    if action.status != "approved":
        problem = f"action is {action.status}; only approved actions can be executed"
    elif evaluate(risk, deps.settings.agent_allow_high_risk).decision is not Decision.NEEDS_APPROVAL:
        problem = "policy no longer permits this action"
    elif not principal.has(executor_role(risk)):
        problem = f"{risk.value} actions must be executed by {executor_role(risk).name.lower()} or higher"
    if problem:
        _audit(deps, principal.name, role, "agent.action.execute_rejected", action_id, outcome="denied",
               reason=problem)
        deps.session.commit()
        raise AgentError(problem, 403 if "executed by" in problem else 409)
    run.state = action.phase
    _execute(deps, run, action, principal.name, role)
    run.summary = _summary_after(run, action)
    run.status = "running"
    return advance(deps, run)
