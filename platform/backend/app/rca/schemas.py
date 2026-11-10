"""Validated structure of an RCA answer (spec §8, §26).

The model must separate:
- `facts`: observations, each citing the tool calls that returned them;
- `inferences`: relationships derived from facts, citing the facts' tool calls;
- `hypotheses`: candidate causes with confidence, supporting and contradicting evidence;
- `recommended_actions`: what to do, each with a risk class.

`validate_citations` rejects any answer that cites a tool call that did not
happen, or states a fact without citing a tool call.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CauseType = Literal["deployment_regression", "configuration_change", "security_attack",
                    "memory_exhaustion", "traffic_overload", "radio_degradation", "transport_fault",
                    "unknown"]
RiskClass = Literal["READ_ONLY", "LOW_RISK", "REQUIRES_APPROVAL", "HIGH_RISK", "BLOCKED"]
MAX_CONFIDENCE = 0.95


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Fact(_Strict):
    statement: str = Field(min_length=3, max_length=500)
    tool_call_ids: list[str] = Field(min_length=1)


class Inference(_Strict):
    statement: str = Field(min_length=3, max_length=500)
    based_on: list[str] = Field(min_length=1, description="tool call ids")


class Hypothesis(_Strict):
    cause_type: CauseType
    description: str = Field(min_length=3, max_length=500)
    confidence: float = Field(ge=0.0, le=MAX_CONFIDENCE)
    supporting_evidence: list[str] = Field(default_factory=list, description="tool call ids")
    contradicting_evidence: list[str] = Field(default_factory=list, description="tool call ids")
    assessment: str = Field(min_length=3, max_length=800)


class RecommendedAction(_Strict):
    priority: int = Field(ge=1, le=10)
    action: str = Field(min_length=3, max_length=300)
    rationale: str = Field(min_length=3, max_length=500)
    risk_class: RiskClass
    agent_tool: str | None = Field(default=None, pattern=r"^[a-z_]{3,48}$")


class RCAAnswer(_Strict):
    root_cause: str = Field(min_length=3, max_length=500)
    root_cause_type: CauseType
    confidence: float = Field(ge=0.0, le=MAX_CONFIDENCE)
    impact: str = Field(min_length=3, max_length=800)
    facts: list[Fact] = Field(min_length=1)
    inferences: list[Inference] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(min_length=1)
    recommended_actions: list[RecommendedAction] = Field(min_length=1)
    verification_steps: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _consistent(self) -> RCAAnswer:
        top = max(self.hypotheses, key=lambda h: h.confidence)
        if top.cause_type != self.root_cause_type:
            raise ValueError("root_cause_type must be the highest-confidence hypothesis")
        if abs(top.confidence - self.confidence) > 1e-6:
            raise ValueError("confidence must equal the leading hypothesis' confidence")
        return self

    def cited_ids(self) -> set[str]:
        ids = {i for f in self.facts for i in f.tool_call_ids}
        ids |= {i for inf in self.inferences for i in inf.based_on}
        for h in self.hypotheses:
            ids |= set(h.supporting_evidence) | set(h.contradicting_evidence)
        return ids


def validate_citations(answer: RCAAnswer, known_ids: set[str], successful_ids: set[str]) -> list[str]:
    """Problems with the answer's evidence references (empty list when valid)."""
    problems = [f"cites unknown tool call {i!r}" for i in sorted(answer.cited_ids() - known_ids)]
    for fact in answer.facts:
        if not set(fact.tool_call_ids) & successful_ids:
            problems.append(f"fact {fact.statement[:60]!r} cites no successful tool call")
    leading = max(answer.hypotheses, key=lambda h: h.confidence)
    if not set(leading.supporting_evidence) & successful_ids:
        problems.append("the leading hypothesis has no supporting evidence from a successful tool call")
    return problems
