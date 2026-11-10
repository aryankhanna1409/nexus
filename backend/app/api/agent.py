"""DevSecOps agent API (spec §16): status, actions, investigate, approve, execute."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query, Request
from pydantic import Field
from sqlalchemy import func, select

from app.agents.service import SCENARIOS, AgentDeps, AgentError, approve_action, execute_action, start_run
from app.agents.tools import TOOLS
from app.api.common import MAX_PAGE
from app.api.deps import Approver, Operator, SessionDep, SettingsDep, Viewer
from app.models import AgentActionRecord, AgentRun
from app.schemas.common import RequestModel, iso
from app.schemas.entities import AgentAction

router = APIRouter(prefix="/api/agent", tags=["agent"])
ACTION_ID = r"^ACT-[0-9a-f]{10}-[0-9]{2}$"
RUN_ID = r"^AGR-[0-9]{4}[0-9a-f]{6}$"


class InvestigateRequest(RequestModel):
    scenario: Literal["vulnerable_dependency", "failed_ci", "production_anomaly"]
    incident_id: str | None = Field(default=None, pattern=r"^INC-\d{4}-\d{3,6}$")


class ApprovalRequest(RequestModel):
    decision: Literal["approve", "deny"]
    comment: str = Field(default="", max_length=500)


def _deps(request: Request, session: SessionDep, settings: SettingsDep) -> AgentDeps:
    return AgentDeps(session, settings, request.app.state.llm, request.app.state.metrics)


def _run_view(deps: AgentDeps, run: AgentRun) -> dict[str, Any]:
    actions = deps.session.scalars(select(AgentActionRecord).where(AgentActionRecord.run_id == run.run_id)
                                   .order_by(AgentActionRecord.sequence)).all()
    summary = {k: v for k, v in run.summary.items() if k != "last_test_output"}
    return {"run_id": run.run_id, "scenario": run.scenario, "state": run.state, "status": run.status,
            "incident_id": run.incident_id, "started_at": iso(run.started_epoch),
            "finished_at": iso(run.finished_epoch), "started_by": run.started_by, "summary": summary,
            "actions": [AgentAction.model_validate(a).model_dump() for a in actions]}


def _raise(exc: AgentError) -> HTTPException:
    return HTTPException(exc.status_code, str(exc))


@router.get("/status")
def status(request: Request, session: SessionDep, settings: SettingsDep, _: Viewer) -> dict[str, Any]:
    counts = dict(session.execute(select(AgentRun.status, func.count()).group_by(AgentRun.status)).all())
    pending = session.scalar(select(func.count()).select_from(AgentActionRecord).where(
        AgentActionRecord.status.in_(("awaiting_approval", "approved")))) or 0
    latest = session.scalars(select(AgentRun).order_by(AgentRun.started_epoch.desc(), AgentRun.run_id.desc())
                             .limit(1)).first()
    return {"runs_by_status": counts, "pending_approvals": pending,
            "latest_run": latest.run_id if latest else None, "scenarios": list(SCENARIOS),
            "policy": {"allow_high_risk": settings.agent_allow_high_risk,
                       "tools": {name: tool.risk.value for name, tool in TOOLS.items()}},
            "llm_provider": request.app.state.llm.provider.name}


@router.get("/actions", response_model=list[AgentAction])
def actions(session: SessionDep, _: Viewer, run_id: str | None = Query(None, pattern=RUN_ID),
            status_filter: str | None = Query(None, alias="status", pattern=r"^[a-z_]{3,24}$"),
            limit: int = Query(200, ge=1, le=MAX_PAGE)) -> list[AgentActionRecord]:
    query = select(AgentActionRecord)
    if run_id:
        query = query.where(AgentActionRecord.run_id == run_id)
    if status_filter:
        query = query.where(AgentActionRecord.status == status_filter)
    return list(session.scalars(query.order_by(AgentActionRecord.created_epoch.desc(),
                                               AgentActionRecord.action_id.desc()).limit(limit)))


@router.get("/runs")
def runs(request: Request, session: SessionDep, settings: SettingsDep, _: Viewer,
         limit: int = Query(50, ge=1, le=500)) -> list[dict[str, Any]]:
    deps = _deps(request, session, settings)
    return [_run_view(deps, r) for r in session.scalars(
        select(AgentRun).order_by(AgentRun.started_epoch.desc(), AgentRun.run_id.desc()).limit(limit))]


@router.get("/runs/{run_id}")
def run_detail(request: Request, session: SessionDep, settings: SettingsDep, _: Viewer,
               run_id: str = Path(..., pattern=RUN_ID)) -> dict[str, Any]:
    run = session.get(AgentRun, run_id)
    if run is None:
        raise HTTPException(404, f"agent run {run_id} not found")
    return _run_view(_deps(request, session, settings), run)


@router.post("/investigate", status_code=201)
def investigate(body: InvestigateRequest, request: Request, session: SessionDep, settings: SettingsDep,
                principal: Operator) -> dict[str, Any]:
    deps = _deps(request, session, settings)
    try:
        run = start_run(deps, body.scenario, principal, body.incident_id)
    except AgentError as exc:
        session.rollback()
        raise _raise(exc) from exc
    return _run_view(deps, run)


@router.post("/approve/{action_id}")
def approve(body: ApprovalRequest, request: Request, session: SessionDep, settings: SettingsDep,
            principal: Approver, action_id: str = Path(..., pattern=ACTION_ID)) -> dict[str, Any]:
    deps = _deps(request, session, settings)
    try:
        run = approve_action(deps, action_id, principal, body.decision == "approve", body.comment)
    except AgentError as exc:
        raise _raise(exc) from exc
    return _run_view(deps, run)


@router.post("/execute/{action_id}")
def execute(request: Request, session: SessionDep, settings: SettingsDep, principal: Operator,
            action_id: str = Path(..., pattern=ACTION_ID)) -> dict[str, Any]:
    deps = _deps(request, session, settings)
    try:
        run = execute_action(deps, action_id, principal)
    except AgentError as exc:
        raise _raise(exc) from exc
    return _run_view(deps, run)
