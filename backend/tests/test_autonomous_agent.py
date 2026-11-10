"""Autonomous mode, the LLM planner and the NVIDIA NIM provider."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from app.agents import llm_planner
from app.agents.llm_planner import FINISH, tool_specs
from app.agents.planner import next_action
from app.config import Settings
from app.db import make_engine, make_session_factory
from app.llm.base import LLMProvider, LLMResponse, LLMUnavailableError, Message, ToolCall, ToolSpec, UserMessage
from app.llm.factory import NIM_DEFAULT_MODEL, ProviderChoice, build_provider
from app.llm.openai_provider import OpenAIProvider
from app.models import AuditLogRecord

from .api_support import make_harness


class PlaybookLLM(LLMProvider):
    """A stand-in model that answers with real tool calls, choosing what the playbook would.

    `_brief` (the prompt builder) is wrapped so the fake can see the run it is planning;
    a real model gets the same information as text.
    """

    name = "fake"
    model = "fake-planner"

    def __init__(self) -> None:
        self.fail = self.bogus = False
        self.current: tuple[Any, Any] | None = None

    def generate(self, system: str, messages: list[Message], *, max_tokens: int = 4096) -> LLMResponse:
        return LLMResponse("summary", (), "end_turn", self.model, self.name)

    def tool_call(self, system: str, messages: list[Message], tools: list[ToolSpec], *,
                  max_tokens: int = 16000) -> LLMResponse:
        if self.fail:
            raise LLMUnavailableError("down")
        if self.bogus:
            return LLMResponse("", (ToolCall("c1", "delete_infrastructure", {"target": "pgw-1"}),),
                               "tool_use", self.model, self.name)
        assert self.current is not None and isinstance(messages[0], UserMessage)
        run, history = self.current
        assert f"Scenario: {run.scenario}" in messages[0].text
        step = next_action(run, history)
        if step is None:
            call = ToolCall("c1", FINISH, {"rationale": "done"})
        else:
            call = ToolCall("c1", step.tool, {**step.arguments, "rationale": step.rationale})
        return LLMResponse("", (call,), "tool_use", self.model, self.name)


def _harness(tmp_path: Path, fake: PlaybookLLM | None = None, monkeypatch: Any = None,
             **overrides: object):  # type: ignore[no-untyped-def]
    api = make_harness(tmp_path, **overrides)
    if fake is not None:
        original = llm_planner._brief

        def brief(run: Any, history: Any, allow_high_risk: bool) -> str:
            fake.current = (run, history)
            return original(run, history, allow_high_risk)

        monkeypatch.setattr(llm_planner, "_brief", brief)
        api.client.app.state.llm = ProviderChoice(fake, "fake", None)  # type: ignore[attr-defined]
    return api


def _audit_actions(api) -> set[str]:  # type: ignore[no-untyped-def]
    with make_session_factory(make_engine(api.settings.database_url))() as s:
        return {r.action for r in s.scalars(select(AuditLogRecord))}


def test_autonomous_mode_runs_dependency_fix_without_a_human(tmp_path: Path) -> None:
    api = _harness(tmp_path, agent_autonomous=True)
    run = api.post("/api/agent/investigate", json={"scenario": "vulnerable_dependency"}).json()  # type: ignore[attr-defined]
    assert run["status"] == "completed", run
    change = next(a for a in run["actions"] if a["tool"] == "modify_dependency")
    assert change["status"] == "succeeded" and change["approved_by"] == "autopilot"
    assert run["summary"]["autonomous"] is True
    assert "agent.action.auto_approved" in _audit_actions(api)


def test_autonomous_mode_still_respects_high_risk_policy(tmp_path: Path) -> None:
    api = _harness(tmp_path, agent_autonomous=True)  # AGENT_ALLOW_HIGH_RISK is off
    summary = api.post("/api/pipeline/run", json={"scenario": "seeded"}).json()  # type: ignore[attr-defined]
    assert [r["status"] for r in summary["agent_runs"]] == ["completed"]
    run = api.get(f"/api/agent/runs/{summary['agent_runs'][0]['run_id']}").json()  # type: ignore[attr-defined]
    rollback = next(a for a in run["actions"] if a["tool"] == "rollback_deployment")
    assert rollback["status"] == "blocked"
    assert api.get("/api/incidents/INC-2026-001").json()["status"] != "resolved"  # type: ignore[attr-defined]


def test_autonomous_pipeline_detects_and_remediates_end_to_end(tmp_path: Path) -> None:
    api = _harness(tmp_path, agent_autonomous=True, agent_allow_high_risk=True)
    summary = api.post("/api/pipeline/run", json={"scenario": "seeded"}).json()  # type: ignore[attr-defined]
    assert summary["incident_ids"] == ["INC-2026-001"]
    run = api.get(f"/api/agent/runs/{summary['agent_runs'][0]['run_id']}").json()  # type: ignore[attr-defined]
    assert run["status"] == "completed", run
    rollback = next(a for a in run["actions"] if a["tool"] == "rollback_deployment")
    assert rollback["executed_by"] == "autopilot" and rollback["status"] == "succeeded"
    assert api.get("/api/incidents/INC-2026-001").json()["status"] == "resolved"  # type: ignore[attr-defined]


def test_pipeline_does_not_start_the_agent_unless_autonomous(tmp_path: Path) -> None:
    api = _harness(tmp_path)
    summary = api.post("/api/pipeline/run", json={"scenario": "seeded"}).json()  # type: ignore[attr-defined]
    assert summary["agent_runs"] == []


def test_llm_planner_drives_the_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    api = _harness(tmp_path, PlaybookLLM(), monkeypatch, agent_planner="llm", agent_autonomous=True)
    run = api.post("/api/agent/investigate", json={"scenario": "failed_ci"}).json()  # type: ignore[attr-defined]
    assert run["status"] == "completed", run
    assert run["summary"]["planner"] == "llm:fake" and "planner_fallbacks" not in run["summary"]
    assert [a["tool"] for a in run["actions"]][-2:] == ["run_tests", "generate_report"]
    assert next(a for a in run["actions"] if a["tool"] == "run_tests")["result"]["passed"] is True


def test_llm_planner_never_offers_blocked_tools_and_rejects_them(tmp_path: Path,
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    assert "delete_infrastructure" not in {t.name for t in tool_specs()}
    for spec in tool_specs():
        schema = spec.input_schema
        assert schema["additionalProperties"] is False and set(schema["required"]) == set(schema["properties"])
    fake = PlaybookLLM()
    fake.bogus = True
    api = _harness(tmp_path, fake, monkeypatch, agent_planner="llm")
    run = api.post("/api/agent/investigate", json={"scenario": "vulnerable_dependency"}).json()  # type: ignore[attr-defined]
    assert "delete_infrastructure" not in {a["tool"] for a in run["actions"]}
    assert "blocked tool" in run["summary"]["planner_fallbacks"][0]
    assert _pending(run)["tool"] == "modify_dependency"  # the playbook took over; approval still required


def test_llm_planner_falls_back_to_playbook_when_the_model_is_down(tmp_path: Path,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    fake = PlaybookLLM()
    fake.fail = True
    api = _harness(tmp_path, fake, monkeypatch, agent_planner="llm", agent_autonomous=True)
    run = api.post("/api/agent/investigate", json={"scenario": "vulnerable_dependency"}).json()  # type: ignore[attr-defined]
    assert run["status"] == "completed"
    assert run["summary"]["planner_fallbacks"][0].startswith("LLMUnavailableError")


def _pending(run: dict[str, Any]) -> dict[str, Any]:
    pending = [a for a in run["actions"] if a["status"] == "awaiting_approval"]
    assert len(pending) == 1, [(a["tool"], a["status"]) for a in run["actions"]]
    return pending[0]


def test_nim_provider_uses_the_openai_compatible_endpoint() -> None:
    assert build_provider(Settings(llm_provider="nim")).fallback_reason is not None  # no key -> mock
    choice = build_provider(Settings(llm_provider="nim", nvidia_api_key="nvapi-test"))
    provider = choice.provider
    assert isinstance(provider, OpenAIProvider) and choice.fallback_reason is None
    assert provider.name == "nim" and provider.model == NIM_DEFAULT_MODEL and provider.strict_tools is False
    assert str(provider._client.base_url).startswith("https://integrate.api.nvidia.com/v1")
    wire = provider._tools(tool_specs()[:1])
    assert "strict" not in wire[0]["function"]
    settings = Settings.from_env({"LLM_PROVIDER": "nim", "NVIDIA_API_KEY": "nvapi-secret-123", "NIM_BASE_URL": "http://nim:8000/v1",
                                  "AGENT_PLANNER": "LLM", "AGENT_AUTONOMOUS": "true"})
    assert settings.nim_base_url == "http://nim:8000/v1" and settings.agent_planner == "llm"
    assert settings.agent_autonomous is True and "nvapi-secret-123" not in repr(settings)
