"""Builds the configured LLM provider, falling back to the deterministic mock."""

from __future__ import annotations

from dataclasses import dataclass

from app.config import Settings
from app.llm.base import LLMProvider
from app.llm.mock import MockProvider


@dataclass(frozen=True)
class ProviderChoice:
    provider: LLMProvider
    requested: str
    fallback_reason: str | None


def build_provider(settings: Settings) -> ProviderChoice:
    requested = settings.llm_provider
    try:
        if requested == "anthropic":
            if not settings.anthropic_api_key:
                return ProviderChoice(MockProvider("ANTHROPIC_API_KEY not set"), requested,
                                      "ANTHROPIC_API_KEY not set; using the deterministic mock provider")
            from app.llm.anthropic_provider import AnthropicProvider

            return ProviderChoice(AnthropicProvider(settings.anthropic_api_key, settings.model_name),
                                  requested, None)
        if requested == "openai":
            if not settings.openai_api_key:
                return ProviderChoice(MockProvider("OPENAI_API_KEY not set"), requested,
                                      "OPENAI_API_KEY not set; using the deterministic mock provider")
            from app.llm.openai_provider import OpenAIProvider

            return ProviderChoice(OpenAIProvider(settings.openai_api_key, settings.model_name),
                                  requested, None)
        if requested == "local":
            if not settings.local_llm_base_url:
                return ProviderChoice(MockProvider("LOCAL_LLM_BASE_URL not set"), requested,
                                      "LOCAL_LLM_BASE_URL not set; using the deterministic mock provider")
            from app.llm.openai_provider import OpenAIProvider

            return ProviderChoice(OpenAIProvider("not-needed", settings.model_name,
                                                 base_url=settings.local_llm_base_url, name="local"),
                                  requested, None)
    except ImportError as exc:
        return ProviderChoice(MockProvider(f"SDK missing: {exc.name}"), requested,
                              f"SDK for {requested} is not installed ({exc.name}); using the mock provider")
    if requested != "mock":
        return ProviderChoice(MockProvider(f"unknown provider {requested!r}"), requested,
                              f"unknown LLM_PROVIDER {requested!r}; using the mock provider")
    return ProviderChoice(MockProvider(), requested, None)
