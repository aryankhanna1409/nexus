"""OpenAI Chat Completions provider; also serves OpenAI-compatible local endpoints.

`LLM_PROVIDER=local` uses this class with `LOCAL_LLM_BASE_URL` (e.g. an Ollama or
vLLM server exposing `/v1/chat/completions`). The `openai` SDK is optional and
imported lazily.
"""

from __future__ import annotations

import json
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

INVALID_ARGUMENTS_KEY = "__invalid_json__"


class OpenAIProvider(LLMProvider):
    def __init__(self, api_key: str, model: str, *, base_url: str | None = None,
                 name: str = "openai", client: Any = None) -> None:
        if not model:
            raise LLMConfigurationError(f"MODEL_NAME must be set for LLM_PROVIDER={name}")
        self.name = name
        self.model = model
        if client is None:
            import openai  # optional dependency; see requirements-llm.txt

            client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self._client = client

    @staticmethod
    def _messages(system: str, messages: list[Message]) -> list[dict[str, Any]]:
        wire: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            if isinstance(m, UserMessage):
                wire.append({"role": "user", "content": m.text})
            elif isinstance(m, AssistantMessage):
                entry: dict[str, Any] = {"role": "assistant", "content": m.text or None}
                if m.tool_calls:
                    entry["tool_calls"] = [{"id": c.id, "type": "function",
                                            "function": {"name": c.name,
                                                         "arguments": json.dumps(c.arguments)}}
                                           for c in m.tool_calls]
                wire.append(entry)
            elif isinstance(m, ToolResultsMessage):
                wire += [{"role": "tool", "tool_call_id": r.tool_call_id, "content": r.content}
                         for r in m.results]
        return wire

    @staticmethod
    def _tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                  "parameters": t.input_schema, "strict": True}}
                for t in tools]

    def _request(self, system: str, messages: list[Message], max_tokens: int,
                 tools: list[ToolSpec] | None) -> LLMResponse:
        import openai

        params: dict[str, Any] = {"model": self.model, "messages": self._messages(system, messages),
                                  "max_completion_tokens": max_tokens}
        if tools:
            params["tools"] = self._tools(tools)
        try:
            response = self._client.chat.completions.create(**params)
        except openai.RateLimitError as exc:
            raise LLMRateLimitError(f"{self.name} rate limited") from exc
        except (openai.AuthenticationError, openai.PermissionDeniedError, openai.NotFoundError,
                openai.BadRequestError) as exc:
            raise LLMConfigurationError(f"{self.name} request rejected: {exc}") from exc
        except openai.APIStatusError as exc:
            if exc.status_code >= 500:
                raise LLMUnavailableError(f"{self.name} server error {exc.status_code}") from exc
            raise LLMConfigurationError(f"{self.name} error {exc.status_code}") from exc
        except openai.APIConnectionError as exc:
            raise LLMUnavailableError(f"could not reach the {self.name} endpoint") from exc
        return self._parse(response)

    def _parse(self, response: Any) -> LLMResponse:
        choice = response.choices[0]
        message = choice.message
        if choice.finish_reason == "content_filter" or getattr(message, "refusal", None):
            raise LLMRefusalError(f"{self.name} model declined the request")
        calls = []
        for call in message.tool_calls or []:
            try:
                arguments = json.loads(call.function.arguments or "{}")
                if not isinstance(arguments, dict):
                    raise ValueError("arguments are not a JSON object")
            except ValueError:
                arguments = {INVALID_ARGUMENTS_KEY: call.function.arguments}
            calls.append(ToolCall(call.id, call.function.name, arguments))
        mapping: dict[str, StopReason] = {"stop": "end_turn", "tool_calls": "tool_use",
                                          "length": "max_tokens"}
        usage = {}
        if getattr(response, "usage", None) is not None:
            usage = {"input_tokens": int(response.usage.prompt_tokens),
                     "output_tokens": int(response.usage.completion_tokens)}
        return LLMResponse(text=message.content or "", tool_calls=tuple(calls),
                           stop_reason=mapping.get(choice.finish_reason, "other"),
                           model=str(response.model), provider=self.name, raw=None, usage=usage)

    def generate(self, system: str, messages: list[Message], *, max_tokens: int = 4096) -> LLMResponse:
        return self._request(system, messages, max_tokens, None)

    def tool_call(self, system: str, messages: list[Message], tools: list[ToolSpec], *,
                  max_tokens: int = 16000) -> LLMResponse:
        return self._request(system, messages, max_tokens, tools)
