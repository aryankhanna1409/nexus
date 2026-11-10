"""LLM planner: the model picks the agent's next tool instead of the fixed playbook.

Used when `AGENT_PLANNER=llm` and a real provider (Claude, NVIDIA NIM, OpenAI or a
local endpoint) is configured. The model only *proposes*: every call is checked
against the tool registry and the tool's argument model, then goes through the
same policy gate as a playbook step (`service._propose`). BLOCKED tools are never
offered. If the model fails, asks for something invalid or the provider is the
offline mock, the deterministic playbook chooses the step instead, and the
fallback reason is stored on the run.
"""

from __future__ import annotations

import json
import types
from typing import Any, Union, get_args, get_origin

from app.agents.planner import PlannedAction
from app.agents.planner import next_action as playbook_next_action
from app.agents.policy import RiskClass
from app.agents.tools import TOOLS
from app.llm.base import LLMError, LLMProvider, ToolSpec, UserMessage
from app.models import AgentActionRecord, AgentRun

PHASES = ("OBSERVE", "ANALYZE", "PLAN", "ACT", "VERIFY", "CLOSE")
FINISH = "finish"
MAX_RESULT_CHARS = 1500

DESCRIPTIONS = {
    "inspect_repository": "List the files and recent commits of the sandbox repository.",
    "inspect_git_diff": "Show the diff between two commits of the sandbox repository.",
    "run_unit_tests": "Run pytest in the sandbox and report failing tests.",
    "run_linter": "Run pyflakes on the sandbox code.",
    "run_tests": "Run the unit tests and the linter together (use to verify a fix).",
    "run_security_scan": "Scan pinned dependencies against the advisory database.",
    "inspect_dependencies": "List dependencies with the smallest release that fixes each advisory.",
    "inspect_container": "Read the deployment registry for the incident's gateway nodes.",
    "inspect_logs": "Read CI or application logs.",
    "inspect_metrics": "Compare the incident's KPIs with their baseline; pass run_id to check a "
                       "post-rollback verification run.",
    "create_incident": "Record a security finding or take ownership of an incident.",
    "request_rca": "Ask the RCA engine for an evidence-based root cause of the incident.",
    "generate_patch": "Generate a patch that reverts the last commit's change to one file.",
    "generate_report": "Write the run's final report. Call this before finish.",
    "close_incident": "Resolve the incident. Only after recovery has been verified.",
    "apply_patch": "Apply a generated patch in the sandbox (needs approval).",
    "modify_dependency": "Upgrade a pinned dependency in the sandbox (needs approval).",
    "restart_service": "Restart a gateway service (needs approval; not modelled).",
    "rollback_deployment": "Roll back a deployment (HIGH_RISK, simulated).",
}

TOOL_PHASE = {
    "inspect_repository": "OBSERVE", "run_unit_tests": "OBSERVE", "run_security_scan": "OBSERVE",
    "inspect_logs": "OBSERVE", "inspect_metrics": "OBSERVE", "create_incident": "OBSERVE",
    "inspect_git_diff": "ANALYZE", "inspect_dependencies": "ANALYZE", "inspect_container": "ANALYZE",
    "request_rca": "ANALYZE", "generate_patch": "PLAN", "apply_patch": "ACT",
    "modify_dependency": "ACT", "restart_service": "ACT", "rollback_deployment": "ACT",
    "run_tests": "VERIFY", "run_linter": "VERIFY", "close_incident": "CLOSE", "generate_report": "CLOSE",
}

SYSTEM = """You are the planner of a DevSecOps agent working on a simulated telecom network.
Each turn, call exactly one tool: the single next step for this run. Every tool takes a
`rationale`: one or two sentences, grounded in earlier results, explaining why this step is next.

Work through OBSERVE -> ANALYZE -> PLAN -> ACT -> VERIFY -> CLOSE. Gather evidence before you act,
verify after you act, and never claim a fix you have not verified. Prefer the smallest change that
fixes the problem. Some tools need human approval or are disabled by policy; a denied or blocked
step is final, so report it rather than working around it. Close an incident only after recovery
is verified. Call generate_report, then finish."""


def _json_type(annotation: Any) -> dict[str, Any]:
    if get_origin(annotation) in (Union, types.UnionType):
        inner = [a for a in get_args(annotation) if a is not type(None)]
        return {"type": [_json_type(inner[0])["type"], "null"]}
    return {"type": {str: "string", int: "integer", bool: "boolean"}.get(annotation, "string")}


def tool_specs() -> list[ToolSpec]:
    """Every non-BLOCKED tool, plus `finish`, as strict schemas (all properties required)."""
    specs = []
    for name, tool in TOOLS.items():
        if tool.risk is RiskClass.BLOCKED:
            continue
        props: dict[str, Any] = {}
        for field_name, info in tool.args_model.model_fields.items():
            prop = _json_type(info.annotation)
            pattern = next((m.pattern for m in info.metadata if hasattr(m, "pattern")), None)
            if pattern:
                prop["description"] = f"must match {pattern}"
            props[field_name] = prop
        props["rationale"] = {"type": "string"}
        desc = f"{DESCRIPTIONS.get(name, name)} Risk: {tool.risk.value}."
        specs.append(ToolSpec(name, desc, {"type": "object", "properties": props,
                                           "required": list(props), "additionalProperties": False}))
    specs.append(ToolSpec(FINISH, "End the run. Call after generate_report.",
                          {"type": "object", "properties": {"rationale": {"type": "string"}},
                           "required": ["rationale"], "additionalProperties": False}))
    return specs


def _brief(run: AgentRun, history: list[AgentActionRecord], allow_high_risk: bool) -> str:
    steps = []
    for a in history:
        result = json.dumps(a.result, default=str)
        if len(result) > MAX_RESULT_CHARS:
            result = result[:MAX_RESULT_CHARS] + "...(truncated)"
        steps.append(f"{a.sequence}. {a.tool} {json.dumps(a.arguments)} -> {a.status}: {result}")
    return "\n".join([
        f"Scenario: {run.scenario}",
        f"Incident: {run.incident_id or 'none'}",
        f"HIGH_RISK actions enabled: {allow_high_risk}",
        "Steps so far:" if steps else "No steps yet.",
        *steps,
    ])


def _phase(tool: str, current: str) -> str:
    mapped = TOOL_PHASE.get(tool, "OBSERVE")
    current = current if current in PHASES else "OBSERVE"
    return max(mapped, current, key=PHASES.index)


def llm_next_action(run: AgentRun, history: list[AgentActionRecord], llm: LLMProvider,
                    allow_high_risk: bool) -> tuple[PlannedAction | None, str | None]:
    """Returns (step, fallback reason). The step is None when the run should end."""
    fallback = playbook_next_action(run, history)
    try:
        response = llm.tool_call(SYSTEM, [UserMessage(_brief(run, history, allow_high_risk))],
                                 tool_specs(), max_tokens=4096)
    except LLMError as exc:
        return fallback, f"{type(exc).__name__}: {exc}"[:300]
    if not response.tool_calls:
        return fallback, "the model did not call a tool"
    call = response.tool_calls[0]
    args = dict(call.arguments)
    rationale = str(args.pop("rationale", "")).strip()[:1000] or "(no rationale given)"
    if call.name == FINISH:
        if not any(a.tool == "generate_report" for a in history):
            return PlannedAction("CLOSE", "generate_report", {}, f"Report before finishing. {rationale}"), None
        return None, None
    tool = TOOLS.get(call.name)
    if tool is None or tool.risk is RiskClass.BLOCKED:
        return fallback, f"the model asked for an unknown or blocked tool {call.name!r}"
    try:
        validated = tool.args_model.model_validate({k: v for k, v in args.items() if v is not None})
    except ValueError as exc:
        return fallback, f"invalid arguments for {call.name}: {str(exc)[:200]}"
    return PlannedAction(_phase(call.name, run.state), call.name,
                         validated.model_dump(exclude_none=True), rationale), None
