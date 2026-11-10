"""Provider-neutral LLM interface (spec §20).

Conversations are lists of neutral messages:

    UserMessage(text)                          -- prompt text
    AssistantMessage(text, tool_calls, raw)    -- a model turn; `raw` holds the provider's
                                                  own content (e.g. thinking blocks) so it can
                                                  be echoed back unchanged on the next request
    ToolResultsMessage(results)                -- results for every tool call of the previous turn

Providers translate this to their wire format. They never execute tools: the
caller (the RCA engine) validates each requested call against an allowlisted
registry and runs it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

StopReason = Literal["end_turn", "tool_use", "max_tokens", "refusal", "other"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ToolResult:
    tool_call_id: str
    content: str  # JSON text
    is_error: bool = False


@dataclass(frozen=True)
class UserMessage:
    text: str


@dataclass(frozen=True)
class AssistantMessage:
    text: str
    tool_calls: tuple[ToolCall, ...] = ()
    provider: str = ""
    raw: Any = None


@dataclass(frozen=True)
class ToolResultsMessage:
    results: tuple[ToolResult, ...]


Message = UserMessage | AssistantMessage | ToolResultsMessage


@dataclass(frozen=True)
class LLMResponse:
    text: str
    tool_calls: tuple[ToolCall, ...]
    stop_reason: StopReason
    model: str
    provider: str
    raw: Any = None
    usage: dict[str, int] = field(default_factory=dict)

    def as_message(self) -> AssistantMessage:
        return AssistantMessage(self.text, self.tool_calls, self.provider, self.raw)


class LLMError(Exception):
    """Base class for provider failures."""

    retryable = False


class LLMRefusalError(LLMError):
    """The model declined the request (e.g. a safety classifier)."""


class LLMRateLimitError(LLMError):
    retryable = True


class LLMUnavailableError(LLMError):
    """Network or 5xx failure."""

    retryable = True


class LLMConfigurationError(LLMError):
    """Bad credentials, unknown model, malformed request: retrying will not help."""


class LLMProvider(ABC):
    name: str
    model: str

    @abstractmethod
    def generate(self, system: str, messages: list[Message], *, max_tokens: int = 4096) -> LLMResponse:
        """Plain text generation (no tools)."""

    @abstractmethod
    def tool_call(self, system: str, messages: list[Message], tools: list[ToolSpec], *,
                  max_tokens: int = 16000) -> LLMResponse:
        """One model turn that may request calls to `tools`."""
