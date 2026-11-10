"""DevSecOps agent: fix the incident, then secure the code base.

Claude decides which tool to use next. Our code decides whether that tool
may run, using one fixed table of risk levels:

  read_only       runs immediately                (look at data, run tests)
  needs_approval  pauses until a human says yes   (rollback, change a dependency)
  anything else   refused                         (not on the list = not possible)

Every proposal, decision and result goes into the hash-chained audit log.
Commands run with an argument list (never a shell), inside a throwaway copy
of demo-workspace/, with a clean environment and a timeout.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

from . import ai
from .audit import AuditLog
from .detect import MIN_DELTA, detect_anomalies
from .simulate import METRICS, NOW, World, iso, simulate

WORKSPACE = Path(__file__).resolve().parent.parent / "demo-workspace"
VERIFY_AFTER = 30   # minutes the simulator fast-forwards after a rollback

RISK = {
    "get_rca": "read_only", "get_incident_status": "read_only", "list_deployments": "read_only",
    "verify_recovery": "read_only", "scan_dependencies": "read_only", "run_tests": "read_only",
    "rollback_deployment": "needs_approval", "upgrade_dependency": "needs_approval",
    "finish": "read_only",
}

STR = {"type": "string"}
TOOLS = [
    ai.schema("get_rca", "The completed root-cause analysis for the incident. Do not re-investigate."),
    ai.schema("get_incident_status", "Current KPIs on the affected cells vs. their pre-incident baseline."),
    ai.schema("list_deployments", "Deployment history for every gateway."),
    ai.schema("rollback_deployment", "Roll a gateway's service back to an earlier version. NEEDS HUMAN APPROVAL.",
              node=STR, service=STR, to_version=STR,
              reason={"type": "string", "description": "One sentence shown to the human approver."}),
    ai.schema("verify_recovery", "After a rollback: fast-forward 30 minutes and check the KPIs are back to baseline."),
    ai.schema("scan_dependencies", "Check the packet-gateway code base's pinned dependencies against the advisory feed."),
    ai.schema("upgrade_dependency", "Change one pinned dependency version in the packet-gateway code base. "
              "NEEDS HUMAN APPROVAL. Run the tests afterwards.", package=STR, version=STR,
              reason={"type": "string", "description": "One sentence shown to the human approver."}),
    ai.schema("run_tests", "Run the packet-gateway unit tests in the sandbox."),
    ai.schema("finish", "End the run with a short summary for the on-call engineer.", summary=STR,
              incident_resolved={"type": "boolean"}),
]

SYSTEM = """You are an autonomous DevSecOps agent on a mobile network operations team.
You act only through the tools. Risky tools pause for a human; if one is denied, do not retry
it. Respect that decision and leave the incident open for a person.

Work like a careful on-call engineer: understand the situation, act, then verify. Never claim
an incident is resolved unless verify_recovery said so. Only change dependencies that the scan
shows are vulnerable, to the smallest fixed version, and run the tests afterwards.
Call finish when done."""

TASK = """Incident {id} is open on {node}. A root-cause analysis has already been done (use get_rca).
1. Restore service safely and verify recovery.
2. Then check the packet-gateway code base for vulnerable dependencies and fix them.
3. Finish with a summary."""

# (tool, args, risk) -> approved?
Approver = Callable[[str, dict], bool]


def _version(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v))


class Agent:
    def __init__(self, world: World, incident: dict, rca: dict, audit: AuditLog, approve: Approver):
        self.world, self.incident, self.rca = world, incident, rca
        self.audit, self.approve = audit, approve
        self.fixed_world: World | None = None
        self.recovery: dict | None = None
        self.actions: list[dict] = []
        self.sandbox = Path(tempfile.mkdtemp(prefix="nexus-ws-"))
        shutil.copytree(WORKSPACE, self.sandbox, dirs_exist_ok=True)
        self.original_requirements = (self.sandbox / "gateway" / "requirements.txt").read_text()
        self.finished: dict | None = None

    # ---- policy gate: every tool call goes through here ---------------
    def execute(self, name: str, args: dict) -> tuple[str, bool]:
        risk = RISK.get(name)
        action = {"tool": name, "input": args, "risk": risk or "blocked"}
        self.actions.append(action)
        self.audit.record("agent", "propose", tool=name, input=args, risk=action["risk"])

        if risk is None:
            action.update(status="blocked", result="not on the allowlist")
            self.audit.record("policy", "block", tool=name)
            return f"{name} is not an allowed tool", True
        if risk == "needs_approval":
            approved = self.approve(name, args)
            self.audit.record("human", "approve" if approved else "deny", tool=name)
            if not approved:
                action.update(status="denied", result="a human denied this action")
                return "DENIED by the human approver. Do not retry; leave this for a person.", True
            action["approved"] = True

        try:
            result = getattr(self, "t_" + name)(**args)
        except (ValueError, KeyError, TypeError, subprocess.SubprocessError) as e:
            action.update(status="failed", result=str(e))
            self.audit.record("agent", "fail", tool=name, error=str(e))
            return f"error: {e}", True
        action.update(status="done", result=result)
        self.audit.record("agent", "execute", tool=name, result=result)
        return ai.dumps(result), False

    # ---- tools ---------------------------------------------------------
    def t_get_rca(self) -> dict:
        r = self.rca
        return {"root_cause": r["root_cause"], "cause_type": r["cause_type"], "confidence": r["confidence"],
                "recommended_actions": r["recommended_actions"]}

    def _kpis(self, world: World, start: int, end: int) -> list[dict]:
        onset = self.incident["onset_minute"]
        rows = []
        for metric in ("memory_pct", "latency_ms", "call_drop_pct"):
            vals = [world.metrics[c][metric] for c in self.incident["cells"]]
            base = statistics.fmean(v[m] for v in vals for m in range(onset - 60, onset))
            now = statistics.fmean(v[m] for v in vals for m in range(start, end))
            rows.append({"metric": metric, "unit": METRICS[metric][0], "baseline": round(base, 2),
                         "current": round(now, 2), "ok": abs(now - base) < MIN_DELTA[metric]})
        return rows

    def t_get_incident_status(self) -> dict:
        return {"incident": self.incident["id"], "status": self.incident["status"], "time": iso(NOW)[11:16],
                "kpis_last_10_min": self._kpis(self.world, NOW - 10, NOW)}

    def t_list_deployments(self) -> dict:
        return {"deployments": [{k: d[k] for k in ("time", "node", "service", "from_version", "to_version")}
                                for d in self.world.deployments if d["minute"] <= NOW]}

    def t_rollback_deployment(self, node: str, service: str, to_version: str, reason: str) -> dict:
        current = [d for d in self.world.deployments if d["node"] == node and d["service"] == service
                   and d["minute"] <= NOW]
        if not current:
            raise ValueError(f"no {service} deployment found on {node}")
        if current[-1]["from_version"] != to_version:
            raise ValueError(f"{node} runs {current[-1]['to_version']}; the previous version was "
                             f"{current[-1]['from_version']}, not {to_version}")
        # Simulated: re-run the same network with the bad release removed at 15:00.
        self.fixed_world = simulate(self.world.seed, rollback_minute=NOW)
        self.incident["status"] = "mitigating"
        return {"rolled_back": f"{service} on {node}: {current[-1]['to_version']} -> {to_version}",
                "at": iso(NOW)[11:16], "note": "simulated rollback"}

    def t_verify_recovery(self) -> dict:
        if self.fixed_world is None:
            raise ValueError("nothing to verify: no rollback has been done")
        start, end = NOW + VERIFY_AFTER - 10, NOW + VERIFY_AFTER
        kpis = self._kpis(self.fixed_world, start, end)
        late = [a for a in detect_anomalies(self.fixed_world, end=end)
                if a["node"] == self.incident["node"] and a["end_minute"] >= start]
        self.recovery = {"checked_window": f"{iso(start)[11:16]}-{iso(end)[11:16]}", "kpis": kpis,
                         "open_anomalies": len(late),
                         "recovered": all(k["ok"] for k in kpis) and not late}
        if self.recovery["recovered"]:
            self.incident["status"] = "resolved"
        return self.recovery

    def _requirements(self) -> dict[str, str]:
        text = (self.sandbox / "gateway" / "requirements.txt").read_text()
        return dict(re.findall(r"^([A-Za-z0-9_.-]+)==([^\s#]+)", text, re.M))

    def t_scan_dependencies(self) -> dict:
        advisories = json.loads((self.sandbox / "advisories.json").read_text())
        findings = [{"package": p, "version": v, "advisory": a["id"], "severity": a["severity"],
                     "fixed_in": a["fixed_in"], "summary": a["summary"]}
                    for p, v in self._requirements().items() for a in advisories
                    if a["package"] == p and _version(v) < _version(a["affected_below"])]
        return {"dependencies": self._requirements(), "vulnerable": findings}

    def t_upgrade_dependency(self, package: str, version: str, reason: str) -> dict:
        reqs = self._requirements()
        if package not in reqs:
            raise ValueError(f"{package} is not a dependency")
        if not re.fullmatch(r"\d+(\.\d+){0,3}", version):
            raise ValueError("version must look like 1.2.3")
        if _version(version) <= _version(reqs[package]):
            raise ValueError("only upgrades are allowed")
        path = self.sandbox / "gateway" / "requirements.txt"
        path.write_text(re.sub(rf"^{re.escape(package)}==\S+", f"{package}=={version}", path.read_text(), flags=re.M))
        return {"changed": f"{package} {reqs[package]} -> {version}", "diff": self.diff()}

    def t_run_tests(self) -> dict:
        proc = subprocess.run([sys.executable, "-m", "unittest", "-q"], cwd=self.sandbox / "gateway",
                              capture_output=True, text=True, timeout=60, shell=False,
                              env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"})
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
        return {"passed": proc.returncode == 0, "output": tail}

    def t_finish(self, summary: str, incident_resolved: bool) -> dict:
        if incident_resolved and not (self.recovery and self.recovery["recovered"]):
            raise ValueError("cannot mark resolved: verify_recovery has not confirmed recovery")
        self.finished = {"summary": summary, "incident_resolved": incident_resolved}
        return self.finished

    def diff(self) -> str:
        new = (self.sandbox / "gateway" / "requirements.txt").read_text()
        return "".join(difflib.unified_diff(self.original_requirements.splitlines(True), new.splitlines(True),
                                            "a/gateway/requirements.txt", "b/gateway/requirements.txt"))


def run_agent(world: World, incident: dict, rca: dict, audit: AuditLog, approve: Approver,
              on_event=lambda kind, data: None, client=None) -> dict:
    agent = Agent(world, incident, rca, audit, approve)
    use_ai, reason = (True, "test client") if client else ai.available()
    provider = reason

    def execute(name: str, args: dict) -> tuple[str, bool]:
        return agent.execute(name, args)

    if use_ai:
        try:
            ai.run_tools(SYSTEM, TASK.format(**incident), TOOLS, execute, "finish", on_event, client=client)
        except Exception as e:
            on_event("fallback", {"reason": f"{type(e).__name__}: {e}"})
            provider = f"offline playbook (Claude failed: {e})"
            if agent.finished is None:
                offline_playbook(agent, on_event)
    else:
        provider = f"offline playbook ({reason})"
        offline_playbook(agent, on_event)

    diff = agent.diff()
    shutil.rmtree(agent.sandbox, ignore_errors=True)
    return {"provider": provider, "actions": agent.actions, "recovery": agent.recovery,
            "fixed_world": agent.fixed_world, "diff": diff,
            "finished": agent.finished, "incident_status": incident["status"]}


def offline_playbook(agent: Agent, on_event) -> None:
    """The same steps a careful engineer would take, without an LLM."""
    def call(name: str, **args) -> tuple[dict | None, bool]:
        on_event("tool_call", {"name": name, "input": args})
        text, err = agent.execute(name, args)
        on_event("tool_result", {"name": name, "text": text, "is_error": err})
        return (None if err else json.loads(text)), err

    rca, _ = call("get_rca")
    call("get_incident_status")
    deps, _ = call("list_deployments")
    node = agent.incident["node"]
    bad = [d for d in deps["deployments"] if d["node"] == node][-1]
    _, denied = call("rollback_deployment", node=node, service=bad["service"], to_version=bad["from_version"],
                     reason=f"RCA ({rca['confidence']:.0%}): {bad['to_version']} leaks memory on {node}.")
    recovered = False
    if not denied:
        rec, _ = call("verify_recovery")
        recovered = bool(rec and rec["recovered"])
    scan, _ = call("scan_dependencies")
    for f in scan["vulnerable"]:
        _, err = call("upgrade_dependency", package=f["package"], version=f["fixed_in"],
                      reason=f"{f['advisory']} ({f['severity']}) fixed in {f['fixed_in']}.")
        if not err:
            call("run_tests")
    if scan["vulnerable"]:
        call("scan_dependencies")
    call("finish", incident_resolved=recovered,
         summary=("Rolled back the bad release and verified recovery. " if recovered
                  else "Rollback was not approved; the incident stays open for a person. ")
         + f"{len(scan['vulnerable'])} vulnerable dependenc{'y' if len(scan['vulnerable']) == 1 else 'ies'} handled.")
