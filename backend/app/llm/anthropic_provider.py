"""Anthropic Claude provider (official `anthropic` Python SDK, imported lazily).

Request shape (per the Claude API documentation for current models):
- default model `claude-opus-5-5`; adaptive thinking is always on for it, so no
  `thinking` parameter is sent (an explicit disable is rejected);
- `output_config.effort` is set explicitly (this model defaults to `medium`);
- tool choice stays `auto` (forced tool choice is rejected on this model) and
  every tool is `strict` so arguments match the schema;
- server-side refusal fallbacks (`fallbacks="default"`) are enabled by default;
- assistant turns are echoed back with their original content blocks (including
  thinking blocks) unchanged; thinking text is never stored or exposed.
"""

from __future__ import annotations

from typing import Any

from app.llm.base import (
    AssistantMessage,
    LLMConfigurationError,
    LLMProvider,
    LLMRateLimitError,
    LLMRefusalError,
    LLMResponse,
    LLMUnavailableError,
    Message,
    StopReason,
    ToolCall,
    ToolResultsMessage,
    ToolSpec,
    UserMessage,
)

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str = "", *, effort: str = "high",
                 enable_fallbacks: bool = True, client: Any = None) -> None:
        self.model = model or DEFAULT_MODEL
        self.effort = effort
        self.enable_fallbacks = enable_fallbacks
        if client is None:
            import anthropic  # optional dependency; see requirements-llm.txt

            client = anthropic.Anthropic(api_key=api_key)
        self._client = client

    # ---- wire format ----------------------------------------------------------------

    def _messages(self, messages: list[Message]) -> list[dict[str, Any]]:
        wire: list[dict[str, Any]] = []
        for m in messages:
            if isinstance(m, UserMessage):
                wire.append({"role": "user", "content": m.text})
            elif isinstance(m, AssistantMessage):
                if m.provider == self.name and m.raw is not None:
                    wire.append({"role": "assistant", "content": m.raw})  # unchanged, incl. thinking
                else:
                    blocks: list[dict[str, Any]] = [{"type": "text", "text": m.text}] if m.text else []
                    blocks += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments}
                               for c in m.tool_calls]
                    wire.append({"role": "assistant", "content": blocks})
            elif isinstance(m, ToolResultsMessage):
                wire.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": r.tool_call_id, "content": r.content,
                     "is_error": r.is_error} for r in m.results]})
        return wire

    @staticmethod
    def _tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [{"name": t.name, "description": t.description, "input_schema": t.input_schema,
                 "strict": True} for t in tools]

    def _request(self, system: str, messages: list[Message], max_tokens: int,
                 tools: list[ToolSpec] | None) -> LLMResponse:
        import anthropic

        params: dict[str, Any] = {
            "model": self.model, "max_tokens": max_tokens, "system": system,
            "messages": self._messages(messages), "output_config": {"effort": self.effort},
        }
        if tools:
            params["tools"] = self._tools(tools)
        try:
            if self.enable_fallbacks:
                response = self._client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default",
                                                             **params)
            else:
                response = self._client.messages.create(**params)
        except anthropic.RateLimitError as exc:
            raise LLMRateLimitError(f"anthropic rate limited: {exc.message}") from exc
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError,
                anthropic.NotFoundError, anthropic.BadRequestError) as exc:
            raise LLMConfigurationError(f"anthropic request rejected: {exc.message}") from exc
        except anthropic.APIStatusError as exc:
            if exc.status_code >= 500:
                raise LLMUnavailableError(f"anthropic server error {exc.status_code}") from exc
            raise LLMConfigurationError(f"anthropic error {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMUnavailableError("could not reach the Anthropic API") from exc
        return self._parse(response)

    def _parse(self, response: Any) -> LLMResponse:
        if response.stop_reason == "refusal":  # check before reading content
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise LLMRefusalError(f"model declined the request (category: {category})")
        text = "".join(b.text for b in response.content if b.type == "text")
        calls = tuple(ToolCall(b.id, b.name, dict(b.input)) for b in response.content
                      if b.type == "tool_use")
        mapping: dict[str, StopReason] = {"end_turn": "end_turn", "tool_use": "tool_use",
                                          "max_tokens": "max_tokens"}
        usage = {}
        if getattr(response, "usage", None) is not None:
            usage = {"input_tokens": int(response.usage.input_tokens),
                     "output_tokens": int(response.usage.output_tokens)}
        return LLMResponse(text=text, tool_calls=calls,
                           stop_reason=mapping.get(response.stop_reason, "other"),
                           model=str(response.model), provider=self.name, raw=response.content,
                           usage=usage)

    # ---- LLMProvider -----------------------------------------------------------------

    def generate(self, system: str, messages: list[Message], *, max_tokens: int = 4096) -> LLMResponse:
        return self._request(system, messages, max_tokens, None)

    def tool_call(self, system: str, messages: list[Message], tools: list[ToolSpec], *,
                  max_tokens: int = 16000) -> LLMResponse:
        return self._request(system, messages, max_tokens, tools)
