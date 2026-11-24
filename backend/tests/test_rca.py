"""M7 acceptance tests: LLM providers, read-only RCA tools, investigation loop, API."""

from __future__ import annotations

import ast
import json
import os
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from app.config import Settings
from app.db import make_engine, make_session_factory
from app.llm.anthropic_provider import DEFAULT_MODEL, FALLBACK_BETA, AnthropicProvider
from app.llm.base import (
    AssistantMessage,
    LLMConfigurationError,
    LLMProvider,
    LLMRateLimitError,
    LLMRefusalError,
    LLMResponse,
    LLMUnavailableError,
    Message,
    ToolCall,
    ToolResult,
    ToolResultsMessage,
    ToolSpec,
    UserMessage,
)
from app.llm.factory import build_provider
from app.llm.mock import MockProvider
from app.llm.openai_provider import INVALID_ARGUMENTS_KEY, OpenAIProvider
from app.models import AuditLogRecord, IncidentRecord
from app.rca.engine import CONTEXT_MARKER, investigate
from app.rca.schemas import RCAAnswer
from app.rca.tools import TOOLS, InvestigationContext
from app.services.pipeline import run_scenario
from app.simulation import IncidentSpec, IncidentType, Scenario

from .api_support import ApiHarness, make_harness

APP_DIR = Path(__file__).resolve().parents[1] / "app"


@pytest.fixture(scope="module")
def api(tmp_path_factory: pytest.TempPathFactory) -> ApiHarness:
    harness = make_harness(tmp_path_factory.mktemp("rca"))
    assert harness.post("/api/pipeline/run", json={"scenario": "seeded"}).status_code == 201  # type: ignore[attr-defined]
    return harness


@pytest.fixture()
def ctx(api: ApiHarness):  # type: ignore[no-untyped-def]
    session = make_session_factory(make_engine(api.settings.database_url))()
    yield InvestigationContext(session, session.get(IncidentRecord, "INC-2026-001"))  # type: ignore[arg-type]
    session.close()


class ScriptedProvider(LLMProvider):
    """Replays a fixed list of turns; each turn is (text, [ToolCall])."""

    name = "scripted"
    model = "scripted-1"

    def __init__(self, turns: list[tuple[str, list[ToolCall]]] | Callable[[list[Message]], tuple[str, list[ToolCall]]]):
        self.turns = turns
        self.calls = 0
        self.seen: list[list[Message]] = []

    def tool_call(self, system: str, messages: list[Message], tools: list[ToolSpec], *,
                  max_tokens: int = 16000) -> LLMResponse:
        self.seen.append(list(messages))
        if callable(self.turns):
            text, calls = self.turns(messages)
        else:
            text, calls = self.turns[min(self.calls, len(self.turns) - 1)]
        self.calls += 1
        return LLMResponse(text, tuple(calls), "tool_use" if calls else "end_turn", self.model, self.name)

    def generate(self, system: str, messages: list[Message], *, max_tokens: int = 4096) -> LLMResponse:
        raise NotImplementedError


def _valid_answer(call_id: str, **overrides: Any) -> str:
    answer = {
        "root_cause": "Deployment regression on pgw-1", "root_cause_type": "deployment_regression",
        "confidence": 0.8, "impact": "4 cells degraded",
        "facts": [{"statement": "A deployment happened before onset", "tool_call_ids": [call_id]}],
        "inferences": [], "hypotheses": [{"cause_type": "deployment_regression", "description": "regression",
                                          "confidence": 0.8, "supporting_evidence": [call_id],
                                          "contradicting_evidence": [], "assessment": "preceded onset"}],
        "recommended_actions": [{"priority": 1, "action": "Roll back", "rationale": "removes regression",
                                 "risk_class": "HIGH_RISK", "agent_tool": "rollback_deployment"}],
        "verification_steps": ["latency returns to baseline"],
    }
    answer.update(overrides)
    return json.dumps(answer)


DEPLOYMENTS = ToolCall("c1", "get_recent_deployments", {"before": None})


# ---- Provider factory --------------------------------------------------------------------


@pytest.mark.parametrize(("settings", "expected", "fallback"), [
    (Settings(), "mock", False),
    (Settings(llm_provider="anthropic"), "mock", True),
    (Settings(llm_provider="openai"), "mock", True),
    (Settings(llm_provider="local"), "mock", True),
    (Settings(llm_provider="nonsense"), "mock", True),
    (Settings(llm_provider="anthropic", anthropic_api_key="sk-test"), "anthropic", False),
    (Settings(llm_provider="openai", openai_api_key="sk-test", model_name="gpt-test"), "openai", False),
    (Settings(llm_provider="local", local_llm_base_url="http://127.0.0.1:9/v1", model_name="llama"), "local", False),
])
def test_provider_selection(settings: Settings, expected: str, fallback: bool) -> None:
    choice = build_provider(settings)
    assert choice.provider.name == expected
    assert (choice.fallback_reason is not None) == fallback
    if expected == "anthropic":
        assert choice.provider.model == DEFAULT_MODEL == "claude-opus-5-5"


def test_openai_requires_model_name() -> None:
    with pytest.raises(LLMConfigurationError):
        OpenAIProvider("k", "", client=object())


# ---- Anthropic provider (fake client; no network) -------------------------------------------


class FakeAnthropicClient:
    def __init__(self, response: Any = None, error: Exception | None = None) -> None:
        self.requests: list[dict[str, Any]] = []
        self.response, self.error = response, error
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **params: Any) -> Any:
        self.requests.append(params)
        if self.error:
            raise self.error
        return self.response


def _anthropic_response(content: list[Any], stop_reason: str = "end_turn", **extra: Any) -> Any:
    return SimpleNamespace(content=content, stop_reason=stop_reason, model="claude-opus-5-5",
                           usage=SimpleNamespace(input_tokens=10, output_tokens=5), **extra)


def test_anthropic_request_shape_and_tool_round_trip() -> None:
    thinking = SimpleNamespace(type="thinking", thinking="", signature="sig")
    tool_use = SimpleNamespace(type="tool_use", id="toolu_1", name="get_call_statistics", input={})
    client = FakeAnthropicClient(_anthropic_response([thinking, tool_use], "tool_use"))
    provider = AnthropicProvider("sk-test", client=client)
    spec = TOOLS["get_call_statistics"].spec
    response = provider.tool_call("system", [UserMessage("hi")], [spec])
    params = client.requests[0]
    assert params["model"] == "claude-opus-5-5" and params["max_tokens"] == 16000
    assert params["output_config"] == {"effort": "high"}
    assert params["betas"] == [FALLBACK_BETA] and params["fallbacks"] == "default"
    assert "thinking" not in params and "tool_choice" not in params and "temperature" not in params
    assert params["tools"][0]["strict"] is True
    assert params["tools"][0]["input_schema"]["additionalProperties"] is False
    assert response.stop_reason == "tool_use" and response.tool_calls == (ToolCall("toolu_1", "get_call_statistics", {}),)

    # Assistant content (with its thinking block) is echoed back unchanged.
    follow = [UserMessage("hi"), response.as_message(),
              ToolResultsMessage((ToolResult("toolu_1", '{"ok": 1}'),))]
    client.response = _anthropic_response([SimpleNamespace(type="text", text="done")])
    final = provider.tool_call("system", follow, [spec])
    wire = client.requests[1]["messages"]
    assert wire[1] == {"role": "assistant", "content": [thinking, tool_use]}
    assert wire[2]["content"][0] == {"type": "tool_result", "tool_use_id": "toolu_1",
                                     "content": '{"ok": 1}', "is_error": False}
    assert final.text == "done" and final.stop_reason == "end_turn"


def test_anthropic_refusal_checked_before_content() -> None:
    client = FakeAnthropicClient(_anthropic_response([], "refusal",
                                                     stop_details=SimpleNamespace(category="cyber")))
    with pytest.raises(LLMRefusalError, match="cyber"):
        AnthropicProvider("k", client=client).tool_call("s", [UserMessage("x")], [])


def test_anthropic_error_mapping() -> None:
    import anthropic
    import httpx2

    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")

    def status_error(cls: type, code: int) -> Exception:
        return cls("err", response=httpx2.Response(code, request=request), body=None)

    cases = [(status_error(anthropic.RateLimitError, 429), LLMRateLimitError),
             (status_error(anthropic.AuthenticationError, 401), LLMConfigurationError),
             (status_error(anthropic.BadRequestError, 400), LLMConfigurationError),
             (status_error(anthropic.InternalServerError, 500), LLMUnavailableError),
             (anthropic.APIConnectionError(request=request), LLMUnavailableError)]
    for error, expected in cases:
        with pytest.raises(expected):
            AnthropicProvider("k", client=FakeAnthropicClient(error=error)).generate("s", [UserMessage("x")])


# ---- OpenAI / local provider (fake client) ----------------------------------------------------


def _openai_response(content: str | None, tool_calls: list[Any] | None, finish: str) -> Any:
    message = SimpleNamespace(content=content, tool_calls=tool_calls, refusal=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=finish)],
                           model="gpt-test", usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2))


def test_openai_request_and_parsing() -> None:
    calls = [SimpleNamespace(id="call_1", function=SimpleNamespace(name="get_logs", arguments='{"service": "ids"}')),
             SimpleNamespace(id="call_2", function=SimpleNamespace(name="get_logs", arguments="not json"))]
    created: list[dict[str, Any]] = []

    def create(**params: Any) -> Any:
        created.append(params)
        return _openai_response(None, calls, "tool_calls")

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    provider = OpenAIProvider("k", "gpt-test", client=client, name="local")
    response = provider.tool_call("sys", [UserMessage("q"), AssistantMessage("", (ToolCall("a", "x", {"k": 1}),)),
                                          ToolResultsMessage((ToolResult("a", "{}"),))], [TOOLS["get_logs"].spec])
    wire = created[0]
    assert wire["messages"][0] == {"role": "system", "content": "sys"}
    assert wire["messages"][2]["tool_calls"][0]["function"]["arguments"] == '{"k": 1}'
    assert wire["messages"][3] == {"role": "tool", "tool_call_id": "a", "content": "{}"}
    assert wire["tools"][0]["function"]["strict"] is True and wire["max_completion_tokens"] == 16000
    assert response.provider == "local" and response.stop_reason == "tool_use"
    assert response.tool_calls[0].arguments == {"service": "ids"}
    assert response.tool_calls[1].arguments == {INVALID_ARGUMENTS_KEY: "not json"}


def test_openai_content_filter_is_refusal() -> None:
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(
        create=lambda **_: _openai_response("", None, "content_filter"))))
    with pytest.raises(LLMRefusalError):
        OpenAIProvider("k", "m", client=client).generate("s", [UserMessage("x")])


# ---- Tools -------------------------------------------------------------------------------------


def test_tool_registry_matches_spec() -> None:
    assert set(TOOLS) == {"get_call_statistics", "get_cell_statistics", "get_metric_history", "get_anomalies",
                          "get_related_events", "get_recent_deployments", "get_security_events", "get_logs",
                          "compare_baseline"}
    for tool in TOOLS.values():
        schema = tool.spec.input_schema
        assert schema["additionalProperties"] is False
        assert schema["required"] == list(schema["properties"])


def test_tools_are_read_only_and_never_execute_commands() -> None:
    for module in ("rca/tools.py", "rca/engine.py", "rca/mock_investigator.py", "llm/base.py",
                   "llm/mock.py", "llm/anthropic_provider.py", "llm/openai_provider.py"):
        tree = ast.parse((APP_DIR / module).read_text())
        names = {n.names[0].name if isinstance(n, ast.Import) else n.module for n in ast.walk(tree)
                 if isinstance(n, (ast.Import, ast.ImportFrom))}
        assert not names & {"subprocess", "os", "shutil", "pty"}, (module, names)
        source = (APP_DIR / module).read_text()
        for forbidden in ("session.add(", "session.commit(", ".delete(", "insert(", "update("):
            if module == "rca/tools.py":
                assert forbidden not in source, (module, forbidden)


@pytest.mark.parametrize(("name", "arguments", "message"), [
    ("get_metric_history", {"metric": "rm -rf", "cell_id": "CELL-101", "start": "2026-03-01T14:00:00Z",
                            "end": "2026-03-01T15:00:00Z"}, "unknown metric"),
    ("get_metric_history", {"metric": "latency_ms", "cell_id": "CELL-101", "start": "2026-03-01T14:00:00Z",
                            "end": "2026-03-03T15:00:00Z"}, "24 hours"),
    ("get_logs", {"service": "/etc/passwd", "start": "2026-03-01T14:00:00Z",
                  "end": "2026-03-01T15:00:00Z"}, "unknown service"),
    ("get_cell_statistics", {"cell_id": "CELL-101", "extra": 1}, "Extra inputs"),
    ("get_cell_statistics", {"cell_id": "../../x"}, "pattern"),
    ("get_cell_statistics", {"cell_id": "CELL-999"}, "unknown cell"),
    ("get_related_events", {"incident_id": "INC-2026-999"}, "scoped"),
    ("get_anomalies", {"start": "2026-03-01T15:00:00Z", "end": "2026-03-01T14:00:00Z", "cell_id": None},
     "after start"),
])
def test_invalid_tool_calls_are_rejected(ctx: InvestigationContext, name: str, arguments: dict[str, Any],
                                         message: str) -> None:
    turns = [("", [ToolCall("bad", name, arguments)]), ("", [DEPLOYMENTS]), (_valid_answer("c1"), [])]
    result = investigate(ctx, ScriptedProvider(turns))
    bad = next(r for r in result.tool_calls if r.id == "bad")
    assert not bad.ok and message in (bad.error or "")
    assert result.status == "completed"


def test_unknown_tool_is_not_executed(ctx: InvestigationContext) -> None:
    turns = [("", [ToolCall("x", "run_shell", {"cmd": "rm -rf /"})]), ("", [DEPLOYMENTS]), (_valid_answer("c1"), [])]
    result = investigate(ctx, ScriptedProvider(turns))
    assert result.tool_calls[0].ok is False and "unknown tool" in (result.tool_calls[0].error or "")


def test_tool_results_are_bounded(ctx: InvestigationContext) -> None:
    turns = [("", [ToolCall("h", "get_metric_history", {"metric": "latency_ms", "cell_id": "CELL-101",
                                                         "start": "2026-03-01T12:00:00Z",
                                                         "end": "2026-03-01T17:59:00Z"})]),
             (_valid_answer("h"), [])]
    result = investigate(ctx, ScriptedProvider(turns))
    series = result.tool_calls[0].result["series"]  # type: ignore[index]
    assert len(series) <= 120 and result.tool_calls[0].result["samples"] == 360  # type: ignore[index]


# ---- Investigation loop ----------------------------------------------------------------------------


def test_prompt_contains_summary_not_raw_data(ctx: InvestigationContext) -> None:
    provider = ScriptedProvider([("", [DEPLOYMENTS]), (_valid_answer("c1"), [])])
    investigate(ctx, provider)
    opening = provider.seen[0][0]
    assert isinstance(opening, UserMessage) and CONTEXT_MARKER in opening.text
    assert len(opening.text) < 3000
    context = json.loads(opening.text.split(CONTEXT_MARKER, 1)[1])
    assert set(context) == {"incident_id", "severity", "start", "end", "affected_cells", "symptoms"}


@pytest.mark.parametrize(("answer", "problem"), [
    (_valid_answer("c-does-not-exist"), "unknown tool call"),
    (_valid_answer("c1", confidence=0.99,
                   hypotheses=[{"cause_type": "deployment_regression", "description": "x", "confidence": 0.99,
                                "supporting_evidence": ["c1"], "contradicting_evidence": [], "assessment": "x"}]),
     "less than or equal to 0.95"),
    (_valid_answer("c1", facts=[{"statement": "uncited claim", "tool_call_ids": []}]), "at least 1"),
    ("The root cause is the deployment.", "no JSON"),
    (_valid_answer("c1", root_cause_type="security_attack"), "highest-confidence"),
])
def test_invalid_answers_are_rejected_then_fail(ctx: InvestigationContext, answer: str, problem: str) -> None:
    provider = ScriptedProvider([("", [DEPLOYMENTS]), (answer, [])])
    result = investigate(ctx, provider, max_answer_attempts=2)
    assert result.status == "failed" and result.answer is None
    assert problem in (result.failure_reason or "")
    feedback = provider.seen[-1][-1]
    assert isinstance(feedback, UserMessage) and "rejected" in feedback.text


def test_rejected_answer_can_be_corrected(ctx: InvestigationContext) -> None:
    provider = ScriptedProvider([("", [DEPLOYMENTS]), (_valid_answer("nope"), []), (_valid_answer("c1"), [])])
    result = investigate(ctx, provider)
    assert result.status == "completed" and result.answer is not None


def test_failed_tool_cannot_be_the_only_evidence(ctx: InvestigationContext) -> None:
    turns = [("", [ToolCall("bad", "get_cell_statistics", {"cell_id": "CELL-999"})]), (_valid_answer("bad"), [])]
    result = investigate(ctx, ScriptedProvider(turns), max_answer_attempts=1)
    assert result.status == "failed" and "no successful tool call" in (result.failure_reason or "")


def test_step_budget_and_per_turn_call_limit(ctx: InvestigationContext) -> None:
    looping = ScriptedProvider(lambda _m: ("", [DEPLOYMENTS]))
    result = investigate(ctx, looping, max_steps=4)
    assert result.status == "failed" and "within 4 steps" in (result.failure_reason or "")
    assert looping.calls == 4
    flood = [ToolCall(f"f{i}", "get_call_statistics", {}) for i in range(12)]
    result = investigate(ctx, ScriptedProvider([("", flood), (_valid_answer("f0"), [])]), max_calls_per_step=8)
    assert sum(r.ok for r in result.tool_calls) == 8
    assert all("limit" in (r.error or "") for r in result.tool_calls[8:])


def test_provider_errors_fail_the_investigation(ctx: InvestigationContext) -> None:
    class Refusing(ScriptedProvider):
        def tool_call(self, *a: Any, **k: Any) -> LLMResponse:
            raise LLMRefusalError("declined")

    result = investigate(ctx, Refusing([]))
    assert result.status == "failed" and "LLMRefusalError" in (result.failure_reason or "")


# ---- Mock investigator on the seeded incident and other incident types ----------------------------------


def test_mock_rca_on_seeded_incident(ctx: InvestigationContext) -> None:
    result = investigate(ctx, MockProvider())
    answer = result.answer
    assert result.status == "completed" and answer is not None
    assert answer.root_cause_type == "deployment_regression" and "2.4.1" in answer.root_cause
    assert 0.7 <= answer.confidence <= 0.95
    ids = {r.id for r in result.tool_calls if r.ok}
    assert all(set(f.tool_call_ids) <= ids for f in answer.facts)
    assert {h.cause_type for h in answer.hypotheses} >= {"deployment_regression", "security_attack"}
    rollback = answer.recommended_actions[0]
    assert rollback.risk_class == "HIGH_RISK" and rollback.agent_tool == "rollback_deployment"
    assert any("memory_utilization" in f.statement for f in answer.facts)
    assert any("deployed to pgw-1" in f.statement for f in answer.facts)
    used = {r.tool for r in result.tool_calls}
    assert len(used) >= 8


@pytest.mark.parametrize(("incident_type", "target", "expected"), [
    (IncidentType.SECURITY_ATTACK, "CELL-106", "security_attack"),
    (IncidentType.MISCONFIGURATION, "CELL-106", "configuration_change"),
    (IncidentType.DEGRADED_RADIO_SIGNAL, "CELL-106", "radio_degradation"),
    (IncidentType.SOFTWARE_DEPLOYMENT_REGRESSION, "pgw-2", "deployment_regression"),
])
def test_mock_rca_per_incident_type(tmp_path: Path, incident_type: IncidentType, target: str, expected: str) -> None:
    harness = make_harness(tmp_path)
    factory = make_session_factory(make_engine(harness.settings.database_url))
    with factory() as session:
        outcome = run_scenario(session, Scenario(name=incident_type.value, seed=7,
                                                 incidents=(IncidentSpec(incident_type, target, 120, 60),)),
                               tmp_path / "data")
        incident = session.get(IncidentRecord, outcome.incident_ids[0])
        result = investigate(InvestigationContext(session, incident), MockProvider())  # type: ignore[arg-type]
    assert result.status == "completed" and result.answer is not None
    assert result.answer.root_cause_type == expected


def test_rca_answer_schema_round_trip() -> None:
    answer = RCAAnswer.model_validate_json(_valid_answer("c1"))
    assert answer.cited_ids() == {"c1"}


# ---- API -------------------------------------------------------------------------------------------------


def test_investigate_endpoint(api: ApiHarness) -> None:
    assert api.get("/api/incidents/INC-2026-001/rca").status_code == 404  # type: ignore[attr-defined]
    assert api.post("/api/incidents/INC-2026-001/investigate", role="viewer").status_code == 403  # type: ignore[attr-defined]
    response = api.post("/api/incidents/INC-2026-001/investigate", role="operator")
    assert response.status_code == 201, response.text  # type: ignore[attr-defined]
    body = response.json()  # type: ignore[attr-defined]
    assert body["status"] == "completed" and body["provider"] == "mock"
    assert body["provider_fallback_reason"] is None
    explanation = body["explanation"]
    for key in ("observed_evidence", "correlated_events", "candidate_hypotheses", "hypothesis_evaluation",
                "most_likely_root_cause", "confidence", "recommended_remediation"):
        assert key in explanation
    assert explanation["leading_hypothesis_type"] == "deployment_regression"
    latest = api.get("/api/incidents/INC-2026-001/rca").json()  # type: ignore[attr-defined]
    assert latest["id"] == body["id"] and latest["recommended_actions"][0]["risk_class"] == "HIGH_RISK"
    detail = api.get("/api/incidents/INC-2026-001").json()  # type: ignore[attr-defined]
    assert detail["status"] == "investigating"
    assert {"ai_investigation_started", "root_cause_identified"} <= {e["type"] for e in detail["events"]}
    session = make_session_factory(make_engine(api.settings.database_url))()
    audit = session.scalars(select(AuditLogRecord).where(AuditLogRecord.action == "rca.investigate")).first()
    session.close()
    assert audit is not None and len(audit.details["tool_calls"]) >= 8
    assert api.post("/api/incidents/INC-2026-404/investigate").status_code == 404  # type: ignore[attr-defined]


def test_investigate_reports_provider_fallback(tmp_path: Path) -> None:
    harness = make_harness(tmp_path, llm_provider="anthropic")
    harness.post("/api/pipeline/run", json={"scenario": "seeded"})
    body = harness.post("/api/incidents/INC-2026-001/investigate").json()  # type: ignore[attr-defined]
    assert body["provider"] == "mock" and "ANTHROPIC_API_KEY not set" in body["provider_fallback_reason"]


@pytest.mark.skipif(not (os.environ.get("AEGIS_RUN_LIVE_LLM_TESTS") == "1" and os.environ.get("ANTHROPIC_API_KEY")),
                    reason="live Anthropic test is opt-in: set AEGIS_RUN_LIVE_LLM_TESTS=1 and ANTHROPIC_API_KEY")
def test_live_anthropic_rca(ctx: InvestigationContext) -> None:
    provider = AnthropicProvider(os.environ["ANTHROPIC_API_KEY"])
    result = investigate(ctx, provider)
    assert result.status == "completed", result.failure_reason
