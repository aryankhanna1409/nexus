"""Allowlisted DevSecOps agent tools (spec §10), each tagged with a risk class.

Tools receive validated, typed arguments and act only on:
- the run's disposable workspace (through `CommandRunner`, fixed argv);
- the Aegis-Net database (incidents, findings, simulated deployment registry);
- the simulator (deployment rollback is a *simulation*: telemetry is re-generated
  from the rollback point; no real infrastructure exists or is touched).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agents import advisories
from app.agents.policy import RiskClass
from app.agents.runner import CommandRunner
from app.agents.workspace import inside
from app.analytics.config import DEFAULT_RULES
from app.config import Settings
from app.llm.factory import ProviderChoice
from app.models import (
    AgentRun,
    Anomaly,
    Deployment,
    IncidentCell,
    IncidentEventRecord,
    IncidentRecord,
    NetworkMetric,
    OperationalEventRecord,
    PipelineRun,
    ReportRecord,
    SecurityFindingRecord,
)
from app.schemas.common import iso
from app.simulation import IncidentSpec, IncidentType, Scenario
from app.simulation.scenario import SEEDED_SCENARIO_NAME

RECOVERY_KPIS = ("memory_utilization", "cpu_utilization", "latency_ms", "packet_loss_pct", "call_drop_rate")
_FAILED_TEST = re.compile(r"^FAILED (\S+?)::(\S+)", re.M)
_SUMMARY = re.compile(r"(\d+) (passed|failed|error)")


class AgentToolError(Exception):
    pass


@dataclass
class AgentContext:
    session: Session
    settings: Settings
    run: AgentRun
    actor: str
    llm: ProviderChoice
    workspace: Path | None = None
    runner: CommandRunner | None = None

    def need_workspace(self) -> tuple[Path, CommandRunner]:
        if self.workspace is None or self.runner is None:
            raise AgentToolError("this tool needs a workspace; the run has none")
        return self.workspace, self.runner

    def incident(self, incident_id: str) -> IncidentRecord:
        incident = self.session.get(IncidentRecord, incident_id)
        if incident is None or incident_id != self.run.incident_id:
            raise AgentToolError(f"incident {incident_id} is not the incident assigned to this run")
        return incident


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class NoArgs(_Args):
    pass


class DiffArgs(_Args):
    base: str = Field(pattern=r"^(HEAD(~[0-9]{1,2})?|[0-9a-f]{7,40})$")
    head: str = Field(pattern=r"^(HEAD(~[0-9]{1,2})?|[0-9a-f]{7,40})$")


class LogArgs(_Args):
    source: str = Field(pattern=r"^(ci|application)$")


class IncidentArgs(_Args):
    incident_id: str = Field(pattern=r"^INC-\d{4}-\d{3,6}$")


class MetricsArgs(IncidentArgs):
    run_id: int | None = Field(default=None, ge=1)


class CreateIncidentArgs(_Args):
    kind: str = Field(pattern=r"^(security_finding|incident_ack)$")


class PatchArgs(_Args):
    file: str = Field(pattern=r"^[A-Za-z0-9_./-]{1,200}$")


class ApplyPatchArgs(_Args):
    patch_path: str = Field(pattern=r"^\.aegis/patches/[0-9]{3}\.patch$")


class DependencyArgs(_Args):
    package: str = Field(pattern=r"^[a-z0-9_.-]{1,64}$")
    version: str = Field(pattern=r"^[0-9]+(\.[0-9]+){0,3}$")


class DeploymentArgs(_Args):
    deployment_id: str = Field(pattern=r"^R[0-9]+-DEP-[A-Za-z0-9.-]{1,80}$")


class NodeArgs(_Args):
    node_id: str = Field(pattern=r"^pgw-[0-9]{1,3}$")


class TargetArgs(_Args):
    target: str = Field(min_length=1, max_length=64)


# ---- Workspace tools -----------------------------------------------------------------------


def inspect_repository(ctx: AgentContext, _args: NoArgs) -> dict[str, Any]:
    path, runner = ctx.need_workspace()
    log = runner.run("git", ["log", "--oneline", "-n", "10"])
    files = sorted(str(p.relative_to(path)) for p in path.rglob("*")
                   if p.is_file() and ".git" not in p.parts and ".aegis" not in p.parts)
    return {"files": files, "recent_commits": log.stdout.strip().splitlines()}


def inspect_git_diff(ctx: AgentContext, args: DiffArgs) -> dict[str, Any]:
    _, runner = ctx.need_workspace()
    stat = runner.run("git", ["diff", "--stat", args.base, args.head])
    names = runner.run("git", ["diff", "--name-only", args.base, args.head])
    diff = runner.run("git", ["diff", args.base, args.head])
    message = runner.run("git", ["log", "-1", "--format=%h %s", args.head])
    if diff.returncode != 0:
        raise AgentToolError(f"git diff failed: {diff.stderr.strip()}")
    return {"commit": message.stdout.strip(), "changed_files": names.stdout.split(),
            "stat": stat.stdout.strip(), "diff": diff.stdout}


def _pytest(ctx: AgentContext) -> dict[str, Any]:
    _, runner = ctx.need_workspace()
    result = runner.run("python", ["-m", "pytest", "-rf"], timeout_s=180)
    counts = {kind: int(n) for n, kind in _SUMMARY.findall(result.stdout)}
    failed = [{"file": f, "test": t} for f, t in _FAILED_TEST.findall(result.stdout)]
    ctx.run.summary = {**ctx.run.summary, "last_test_output": result.stdout[-6000:]}
    return {"passed": result.returncode == 0, "returncode": result.returncode,
            "timed_out": result.timed_out, "counts": counts, "failed_tests": failed,
            "output_tail": result.stdout[-1500:]}


def run_unit_tests(ctx: AgentContext, _args: NoArgs) -> dict[str, Any]:
    return _pytest(ctx)


def run_linter(ctx: AgentContext, _args: NoArgs) -> dict[str, Any]:
    _, runner = ctx.need_workspace()
    result = runner.run("python", ["-m", "pyflakes", "pgw", "tests"], timeout_s=60)
    issues = [line for line in result.stdout.splitlines() if line.strip()]
    return {"clean": result.returncode == 0 and not issues, "issues": issues[:50],
            "returncode": result.returncode}


def run_tests(ctx: AgentContext, _args: NoArgs) -> dict[str, Any]:
    tests = _pytest(ctx)
    lint = run_linter(ctx, NoArgs())
    return {"passed": tests["passed"] and lint["clean"], "tests": tests, "lint": lint}


def run_security_scan(ctx: AgentContext, _args: NoArgs) -> dict[str, Any]:
    path, _ = ctx.need_workspace()
    findings = advisories.scan((path / "requirements.txt").read_text())
    return {"scanner": "aegis-synthetic-advisory-db", "notice": advisories.notice(),
            "findings": [f.to_dict() for f in findings]}


def inspect_dependencies(ctx: AgentContext, _args: NoArgs) -> dict[str, Any]:
    path, _ = ctx.need_workspace()
    pins = advisories.parse_requirements((path / "requirements.txt").read_text())
    return {"dependencies": [{"package": p.package, "pinned": p.version,
                              "available": advisories.available_versions(p.package),
                              "minimal_safe_upgrade": advisories.minimal_safe_upgrade(p.package, p.version)}
                             for p in pins]}


def inspect_logs(ctx: AgentContext, args: LogArgs) -> dict[str, Any]:
    if args.source == "ci":
        output = str(ctx.run.summary.get("last_test_output", ""))
        if not output:
            raise AgentToolError("no CI output recorded yet; run the tests first")
        return {"source": "ci", "failed_tests": [{"file": f, "test": t} for f, t in _FAILED_TEST.findall(output)],
                "log_tail": output[-3000:]}
    if ctx.run.incident_id is None:
        raise AgentToolError("application logs require an incident")
    incident = ctx.incident(ctx.run.incident_id)
    rows = ctx.session.scalars(select(OperationalEventRecord).where(
        OperationalEventRecord.run_id == incident.run_id, OperationalEventRecord.type == "application_log",
        OperationalEventRecord.severity.in_(("warning", "error", "critical")))
        .order_by(OperationalEventRecord.epoch).limit(30)).all()
    return {"source": "application", "entries": [{"t": iso(r.epoch), "level": r.severity, "node": r.node_id,
                                                  "message": r.message} for r in rows]}


def generate_patch(ctx: AgentContext, args: PatchArgs) -> dict[str, Any]:
    """Proposes reverting the last commit's change to `file` (written to .aegis/patches, not applied)."""
    path, runner = ctx.need_workspace()
    target = inside(path, args.file)
    if not target.is_file():
        raise AgentToolError(f"{args.file} does not exist in the workspace")
    diff = runner.run("git", ["diff", "HEAD", "HEAD~1", "--", args.file])
    if diff.returncode != 0 or not diff.stdout.strip():
        raise AgentToolError(f"no change to {args.file} in the last commit; nothing to revert")
    patches = path / ".aegis" / "patches"
    patches.mkdir(parents=True, exist_ok=True)
    number = len(list(patches.glob("*.patch"))) + 1
    patch_path = patches / f"{number:03d}.patch"
    patch_path.write_text(diff.stdout)
    return {"patch_path": str(patch_path.relative_to(path)), "strategy": "revert last commit's change",
            "file": args.file, "patch": diff.stdout}


def apply_patch(ctx: AgentContext, args: ApplyPatchArgs) -> dict[str, Any]:
    path, runner = ctx.need_workspace()
    patch = inside(path, args.patch_path)
    if not patch.is_file():
        raise AgentToolError(f"{args.patch_path} not found")
    check = runner.run("git", ["apply", "--check", args.patch_path])
    if check.returncode != 0:
        raise AgentToolError(f"patch does not apply cleanly: {check.stderr.strip()}")
    for git_args in (["apply", args.patch_path], ["add", "-A", "pgw", "tests"],
                     ["commit", "-q", "-m", f"Agent: apply {args.patch_path}"]):
        result = runner.run("git", git_args)
        if result.returncode != 0:
            raise AgentToolError(f"git {git_args[0]} failed: {result.stderr.strip()}")
    head = runner.run("git", ["rev-parse", "--short", "HEAD"])
    return {"applied": args.patch_path, "commit": head.stdout.strip()}


def modify_dependency(ctx: AgentContext, args: DependencyArgs) -> dict[str, Any]:
    path, runner = ctx.need_workspace()
    req = path / "requirements.txt"
    text = req.read_text()
    pins = {p.package: p for p in advisories.parse_requirements(text)}
    if args.package not in pins:
        raise AgentToolError(f"{args.package} is not a dependency of this repository")
    if args.version not in advisories.available_versions(args.package):
        raise AgentToolError(f"{args.package}=={args.version} is not a released version")
    if advisories.scan(f"{args.package}=={args.version}"):
        raise AgentToolError(f"{args.package}=={args.version} is itself affected by an advisory")
    old = pins[args.package]
    lines = text.splitlines(keepends=True)
    lines[old.line - 1] = lines[old.line - 1].replace(f"=={old.version}", f"=={args.version}", 1)
    req.write_text("".join(lines))
    for git_args in (["add", "requirements.txt"],
                     ["commit", "-q", "-m", f"Agent: upgrade {args.package} {old.version} -> {args.version}"]):
        result = runner.run("git", git_args)
        if result.returncode != 0:
            raise AgentToolError(f"git {git_args[0]} failed: {result.stderr.strip()}")
    return {"package": args.package, "from": old.version, "to": args.version, "deployed": False}


# ---- Incident / infrastructure tools ------------------------------------------------------------


def _kpi_window(ctx: AgentContext, run_id: int, cells: list[str], start: int, end: int) -> dict[str, float]:
    out = {}
    for metric in RECOVERY_KPIS:
        values = [v for (v,) in ctx.session.execute(select(NetworkMetric.value).where(
            NetworkMetric.run_id == run_id, NetworkMetric.metric == metric, NetworkMetric.cell_id.in_(cells),
            NetworkMetric.epoch >= start, NetworkMetric.epoch <= end))]
        if values:
            out[metric] = round(sum(values) / len(values), 3)
    return out


def inspect_metrics(ctx: AgentContext, args: MetricsArgs) -> dict[str, Any]:
    """Pre-incident baseline vs the last 30 minutes of data, for the incident's cells."""
    incident = ctx.incident(args.incident_id)
    run_id = args.run_id or incident.run_id
    run = ctx.session.get(PipelineRun, run_id)
    if run is None or run_id not in (incident.run_id, ctx.run.summary.get("verification_run_id")):
        raise AgentToolError("run is not related to this incident")
    cells = list(ctx.session.scalars(select(IncidentCell.cell_id).where(
        IncidentCell.incident_id == incident.incident_id)))
    baseline = _kpi_window(ctx, run_id, cells, incident.start_epoch - 3600, incident.start_epoch - 60)
    current = _kpi_window(ctx, run_id, cells, run.data_end_epoch - 1800, run.data_end_epoch)
    deviations = {m: round(current[m] - baseline[m], 3) for m in current if m in baseline}
    recovered = all(abs(deviations[m]) <= DEFAULT_RULES[m].min_delta for m in deviations)
    open_anomalies = ctx.session.scalars(select(Anomaly.metric).where(
        Anomaly.run_id == run_id, Anomaly.cell_id.in_(cells), Anomaly.end_epoch >= run.data_end_epoch - 1800)).all()
    return {"run_id": run_id, "cells": cells, "baseline": baseline, "last_30_min": current,
            "deviation": deviations, "recovered": recovered and not open_anomalies,
            "open_anomalies": sorted(set(open_anomalies)),
            "tolerance": {m: DEFAULT_RULES[m].min_delta for m in RECOVERY_KPIS}}


def inspect_container(ctx: AgentContext, _args: NoArgs) -> dict[str, Any]:
    """Simulated deployment registry for the incident's packet-gateway nodes."""
    if ctx.run.incident_id is None:
        raise AgentToolError("requires an incident")
    incident = ctx.incident(ctx.run.incident_id)
    nodes = sorted(set(ctx.session.scalars(select(IncidentCell.node_id).where(
        IncidentCell.incident_id == incident.incident_id))))
    rows = ctx.session.scalars(select(Deployment).where(Deployment.run_id == incident.run_id,
                                                        Deployment.node_id.in_(nodes))
                               .order_by(Deployment.deployed_epoch.desc())).all()
    return {"simulated": True, "nodes": nodes, "incident_start": iso(incident.start_epoch),
            "deployments": [{"deployment_id": d.deployment_id, "node_id": d.node_id, "service": d.service,
                             "from_version": d.from_version, "to_version": d.to_version,
                             "deployed_at": iso(d.deployed_epoch), "status": d.status,
                             "preceded_incident": d.deployed_epoch <= incident.start_epoch}
                            for d in rows]}


def create_incident(ctx: AgentContext, args: CreateIncidentArgs) -> dict[str, Any]:
    now = int(time.time())
    if args.kind == "security_finding":
        findings = run_security_scan(ctx, NoArgs())["findings"]
        created = []
        for f in findings:
            finding_id = f"{f['advisory_id']}:{ctx.run.run_id}"
            if ctx.session.get(SecurityFindingRecord, finding_id) is None:
                ctx.session.add(SecurityFindingRecord(
                    finding_id=finding_id, source="dependency-scanner", category="vulnerable_dependency",
                    severity=f["severity"], title=f"{f['advisory_id']} in {f['package']} {f['installed']}",
                    resource=f"demo-workspace:requirements.txt:{f['package']}", status="open",
                    created_epoch=now, updated_epoch=now, details={**f, "agent_run": ctx.run.run_id}))
            created.append(finding_id)
        return {"created_findings": created}
    if ctx.run.incident_id is None:
        raise AgentToolError("incident_ack requires an incident")
    incident = ctx.incident(ctx.run.incident_id)
    if incident.status == "open":
        incident.status = "investigating"
    ctx.session.add(IncidentEventRecord(incident_id=incident.incident_id, epoch=now, type="agent_opened",
                                        description=f"DevSecOps agent run {ctx.run.run_id} took the incident",
                                        reference_id=ctx.run.run_id, actor=f"agent:{ctx.run.run_id}"))
    return {"incident_id": incident.incident_id, "status": incident.status}


def request_rca(ctx: AgentContext, args: IncidentArgs) -> dict[str, Any]:
    from app.services.rca import run_rca

    incident = ctx.incident(args.incident_id)
    outcome = run_rca(ctx.session, incident, ctx.llm, actor=f"agent:{ctx.run.run_id}")
    record = outcome.record
    leading = record.hypotheses[0] if record.hypotheses else {}
    return {"rca_id": record.id, "status": record.status, "provider": record.provider,
            "root_cause": record.root_cause, "root_cause_type": leading.get("cause_type"),
            "confidence": record.confidence}


def _scenario_from_run(run: PipelineRun) -> Scenario:
    params = run.params
    if "incidents" in params:
        specs = tuple(IncidentSpec(IncidentType(s["type"]), s["target"], s["start_minute"], s["duration_minutes"],
                                   s.get("intensity", 1.0), s.get("to_version", "2.4.1"))
                      for s in params["incidents"])
        return Scenario(name=str(params.get("scenario", run.scenario)), seed=run.seed,
                        minutes=int(params["minutes"]), incidents=specs)
    if params.get("scenario") == "seeded" or run.scenario == SEEDED_SCENARIO_NAME:
        from app.services.pipeline import PipelineParams

        return PipelineParams("seeded", run.seed, int(params.get("minutes", 360))).build()
    raise AgentToolError(f"run {run.id} cannot be re-simulated (scenario {run.scenario!r})")


def rollback_deployment(ctx: AgentContext, args: DeploymentArgs) -> dict[str, Any]:
    """SIMULATED rollback: telemetry is regenerated with the deployment reverted at the rollback point."""
    from app.services.pipeline import run_scenario

    deployment = ctx.session.get(Deployment, args.deployment_id)
    if deployment is None or ctx.run.incident_id is None:
        raise AgentToolError(f"deployment {args.deployment_id} not found")
    incident = ctx.incident(ctx.run.incident_id)
    if deployment.run_id != incident.run_id or deployment.status != "active":
        raise AgentToolError("deployment is not an active deployment of the incident's run")
    source = ctx.session.get(PipelineRun, incident.run_id)
    assert source is not None
    scenario = _scenario_from_run(source)
    rollback_minute = (incident.start_epoch - source.data_start_epoch) // 60 + 45
    if rollback_minute >= scenario.minutes - 45:
        raise AgentToolError("not enough simulated time after the rollback point to verify recovery")
    outcome = run_scenario(ctx.session, replace(scenario, rollback_minute=rollback_minute),
                           ctx.settings.data_dir,
                           params={"purpose": "rollback-verification", "source_run": source.id,
                                   "rollback_minute": rollback_minute, "agent_run": ctx.run.run_id},
                           correlate_flag=False)
    rollback_epoch = source.data_start_epoch + rollback_minute * 60
    # The degradation ended when the last anomaly on the affected cells ended in the
    # post-rollback telemetry (not at the end of the original, un-remediated data).
    cells = list(ctx.session.scalars(select(IncidentCell.cell_id).where(
        IncidentCell.incident_id == incident.incident_id)))
    last_anomaly_end = ctx.session.scalar(select(func.max(Anomaly.end_epoch)).where(
        Anomaly.run_id == outcome.run.id, Anomaly.cell_id.in_(cells)))
    incident.end_epoch = max(rollback_epoch, int(last_anomaly_end or rollback_epoch))
    deployment.status = "rolled_back"
    deployment.rolled_back_epoch = rollback_epoch
    incident.status = "mitigated"
    ctx.session.add(IncidentEventRecord(
        incident_id=incident.incident_id, epoch=rollback_epoch, type="rollback_executed",
        description=f"(simulated) {deployment.service} on {deployment.node_id} rolled back "
                    f"{deployment.to_version} -> {deployment.from_version}",
        reference_id=deployment.deployment_id, actor=f"agent:{ctx.run.run_id}"))
    ctx.run.summary = {**ctx.run.summary, "verification_run_id": outcome.run.id}
    return {"simulated": True, "deployment_id": deployment.deployment_id,
            "rolled_back_to": deployment.from_version, "rollback_at": iso(rollback_epoch),
            "verification_run_id": outcome.run.id}


def restart_service(ctx: AgentContext, args: NodeArgs) -> dict[str, Any]:
    """SIMULATED restart: recorded as an operational event; no real service exists."""
    raise AgentToolError(f"restart of {args.node_id} is not simulated by the telemetry model; "
                         "use rollback_deployment for deployment-induced faults")


def delete_infrastructure(ctx: AgentContext, args: TargetArgs) -> dict[str, Any]:
    raise AgentToolError("delete_infrastructure is BLOCKED and has no implementation")


def close_incident(ctx: AgentContext, args: IncidentArgs) -> dict[str, Any]:
    incident = ctx.incident(args.incident_id)
    if not ctx.run.summary.get("recovery_verified"):
        raise AgentToolError("recovery has not been verified; the incident stays open")
    now = int(time.time())
    incident.status = "resolved"
    incident.resolved_epoch = now
    ctx.session.add(IncidentEventRecord(incident_id=incident.incident_id, epoch=now, type="incident_resolved",
                                        description="Recovery verified after remediation; incident resolved",
                                        reference_id=ctx.run.run_id, actor=f"agent:{ctx.run.run_id}"))
    return {"incident_id": incident.incident_id, "status": "resolved"}


def generate_report(ctx: AgentContext, _args: NoArgs) -> dict[str, Any]:
    if ctx.run.incident_id is not None:
        from app.reporting.builder import build_report
        from app.reporting.render import render_html, render_markdown

        doc = build_report(ctx.session, ctx.run.incident_id, ctx.llm, created_by=f"agent:{ctx.run.run_id}")
        ctx.session.add(ReportRecord(report_id=doc.report_id, incident_id=ctx.run.incident_id, rca_id=None,
                                     created_epoch=int(time.time()), created_by=f"agent:{ctx.run.run_id}",
                                     payload=doc.model_dump(mode="json"), markdown=render_markdown(doc),
                                     html=render_html(doc)))
        return {"report_id": doc.report_id}
    # Findings recorded by this run are remediated when the latest scan is clean.
    remediated = []
    if ctx.workspace is not None and not run_security_scan(ctx, NoArgs())["findings"]:
        for finding in ctx.session.scalars(select(SecurityFindingRecord).where(
                SecurityFindingRecord.status == "open")):
            if finding.details.get("agent_run") == ctx.run.run_id:
                finding.status = "remediated"
                finding.updated_epoch = int(time.time())
                remediated.append(finding.finding_id)
    return {"report": "agent run summary", "remediated_findings": remediated,
            "summary": {k: v for k, v in ctx.run.summary.items() if k != "last_test_output"}}


@dataclass(frozen=True)
class AgentTool:
    name: str
    risk: RiskClass
    args_model: type[_Args]
    run: Callable[[AgentContext, Any], dict[str, Any]]


TOOLS: dict[str, AgentTool] = {t.name: t for t in (
    AgentTool("inspect_repository", RiskClass.READ_ONLY, NoArgs, inspect_repository),
    AgentTool("inspect_git_diff", RiskClass.READ_ONLY, DiffArgs, inspect_git_diff),
    AgentTool("run_unit_tests", RiskClass.READ_ONLY, NoArgs, run_unit_tests),
    AgentTool("run_linter", RiskClass.READ_ONLY, NoArgs, run_linter),
    AgentTool("run_tests", RiskClass.READ_ONLY, NoArgs, run_tests),
    AgentTool("run_security_scan", RiskClass.READ_ONLY, NoArgs, run_security_scan),
    AgentTool("inspect_dependencies", RiskClass.READ_ONLY, NoArgs, inspect_dependencies),
    AgentTool("inspect_container", RiskClass.READ_ONLY, NoArgs, inspect_container),
    AgentTool("inspect_logs", RiskClass.READ_ONLY, LogArgs, inspect_logs),
    AgentTool("inspect_metrics", RiskClass.READ_ONLY, MetricsArgs, inspect_metrics),
    AgentTool("create_incident", RiskClass.LOW_RISK, CreateIncidentArgs, create_incident),
    AgentTool("request_rca", RiskClass.LOW_RISK, IncidentArgs, request_rca),
    AgentTool("generate_patch", RiskClass.LOW_RISK, PatchArgs, generate_patch),
    AgentTool("generate_report", RiskClass.LOW_RISK, NoArgs, generate_report),
    AgentTool("close_incident", RiskClass.LOW_RISK, IncidentArgs, close_incident),
    AgentTool("apply_patch", RiskClass.REQUIRES_APPROVAL, ApplyPatchArgs, apply_patch),
    AgentTool("modify_dependency", RiskClass.REQUIRES_APPROVAL, DependencyArgs, modify_dependency),
    AgentTool("restart_service", RiskClass.REQUIRES_APPROVAL, NodeArgs, restart_service),
    AgentTool("rollback_deployment", RiskClass.HIGH_RISK, DeploymentArgs, rollback_deployment),
    AgentTool("delete_infrastructure", RiskClass.BLOCKED, TargetArgs, delete_infrastructure),
)}
