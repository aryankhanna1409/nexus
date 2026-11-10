"""The one place that talks to Claude.

run_tools() is a plain tool-use loop: send the conversation and the tool
list, run whatever tools Claude asks for, send the results back, repeat
until Claude calls the `finish_tool`. Claude never runs anything itself;
it can only ask for tools from the list, and our code decides whether to
run them.

Without an API key (or with --offline) nothing here is used and the
caller falls back to its deterministic, rule-based path.
"""
from __future__ import annotations

import json
import os
from typing import Callable

MODEL = os.environ.get("NEXUS_MODEL", "claude-opus-5-5")

# (tool name, tool input) -> (result text, is_error)
Executor = Callable[[str, dict], tuple[str, bool]]


def available() -> tuple[bool, str]:
    """Can we call Claude? Returns (yes/no, reason shown to the user)."""
    if os.environ.get("NEXUS_OFFLINE"):
        return False, "--offline"
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False, "the anthropic package is not installed (pip install anthropic)"
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        return False, "no ANTHROPIC_API_KEY set"
    return True, f"Claude ({MODEL})"


class AIError(RuntimeError):
    pass


def run_tools(system: str, task: str, tools: list[dict], execute: Executor,
              finish_tool: str, on_event: Callable[[str, dict], None] = lambda kind, data: None,
              max_turns: int = 16, client=None) -> dict:
    """Run the tool loop until Claude calls `finish_tool`; return that call's input."""
    if client is None:
        import anthropic
        client = anthropic.Anthropic()
    messages: list[dict] = [{"role": "user", "content": task}]
    strict_tools = [{**t, "strict": True} for t in tools]

    for _ in range(max_turns):
        response = client.beta.messages.create(
            model=MODEL,
            max_tokens=16000,
            system=system,
            tools=strict_tools,
            messages=messages,
            output_config={"effort": "high"},
            # If a safety classifier declines, the API retries on a fallback model.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        if response.stop_reason == "refusal":
            raise AIError("Claude declined this request")
        if response.stop_reason == "max_tokens":
            raise AIError("response was cut off (max_tokens)")

        messages.append({"role": "assistant", "content": response.content})
        for block in response.content:
            if block.type == "text" and block.text.strip():
                on_event("thought", {"text": block.text.strip()})

        calls = [b for b in response.content if b.type == "tool_use"]
        if not calls:
            messages.append({"role": "user", "content": f"Please continue. Call {finish_tool} when you are done."})
            continue

        results = []
        finished = None
        for call in calls:
            on_event("tool_call", {"name": call.name, "input": call.input})
            text, is_error = execute(call.name, dict(call.input))
            on_event("tool_result", {"name": call.name, "text": text, "is_error": is_error})
            results.append({"type": "tool_result", "tool_use_id": call.id,
                            "content": text, "is_error": is_error})
            if call.name == finish_tool and not is_error:
                finished = dict(call.input)
        if finished is not None:
            return finished
        messages.append({"role": "user", "content": results})

    raise AIError(f"no {finish_tool} call after {max_turns} turns")


def schema(name: str, description: str, **props: dict) -> dict:
    """Build a strict tool definition: every property is required, no extras."""
    return {"name": name, "description": description,
            "input_schema": {"type": "object", "properties": props,
                             "required": list(props), "additionalProperties": False}}


def dumps(data) -> str:
    return json.dumps(data, separators=(",", ":"), default=str)
