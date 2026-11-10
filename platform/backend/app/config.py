"""Application settings, read from environment variables only.

Secrets (API keys, token hashes) never get a default value in code and are
excluded from `repr`, so they cannot leak through logs or error pages.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_TOKEN_SPEC = re.compile(r"^(?P<name>[A-Za-z0-9_.-]{1,64}):(?P<role>[a-z]+):(?P<hash>[0-9a-f]{64})$")


class Role(IntEnum):
    """Ordered roles: each role includes the permissions of the lower ones."""

    VIEWER = 1
    OPERATOR = 2
    APPROVER = 3
    ADMIN = 4


@dataclass(frozen=True)
class TokenEntry:
    name: str
    role: Role
    sha256: str = field(repr=False)


def parse_token_specs(raw: str) -> tuple[TokenEntry, ...]:
    """Parses `name:role:sha256hex[,name:role:sha256hex...]`."""
    entries = []
    for item in filter(None, (part.strip() for part in raw.split(","))):
        match = _TOKEN_SPEC.match(item)
        if match is None:
            raise ValueError("invalid AEGIS_API_TOKENS entry (expected name:role:sha256hex)")
        try:
            role = Role[match["role"].upper()]
        except KeyError as exc:
            raise ValueError(f"unknown role {match['role']!r} in AEGIS_API_TOKENS") from exc
        entries.append(TokenEntry(match["name"], role, match["hash"]))
    if len({e.name for e in entries}) != len(entries):
        raise ValueError("duplicate token names in AEGIS_API_TOKENS")
    return tuple(entries)


@dataclass(frozen=True)
class Settings:
    database_url: str = f"sqlite:///{REPO_ROOT / 'data' / 'aegis.db'}"
    data_dir: Path = REPO_ROOT / "data"
    api_tokens: tuple[TokenEntry, ...] = field(default=(), repr=False)
    llm_provider: str = "mock"
    model_name: str = ""
    anthropic_api_key: str = field(default="", repr=False)
    openai_api_key: str = field(default="", repr=False)
    local_llm_base_url: str = ""
    redis_url: str = ""
    rate_limit_per_minute: int = 120
    max_request_bytes: int = 1_000_000
    agent_allow_high_risk: bool = False
    agent_workspace_root: Path = Path("/tmp/aegis-agent-workspaces")
    log_level: str = "INFO"

    @staticmethod
    def from_env(env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        defaults = Settings()

        def flag(name: str) -> bool:
            return e.get(name, "").strip().lower() in ("1", "true", "yes")

        return Settings(
            database_url=e.get("DATABASE_URL", defaults.database_url),
            data_dir=Path(e.get("AEGIS_DATA_DIR", str(defaults.data_dir))),
            api_tokens=parse_token_specs(e.get("AEGIS_API_TOKENS", "")),
            llm_provider=e.get("LLM_PROVIDER", "mock").strip().lower() or "mock",
            model_name=e.get("MODEL_NAME", ""),
            anthropic_api_key=e.get("ANTHROPIC_API_KEY", ""),
            openai_api_key=e.get("OPENAI_API_KEY", ""),
            local_llm_base_url=e.get("LOCAL_LLM_BASE_URL", ""),
            redis_url=e.get("REDIS_URL", ""),
            rate_limit_per_minute=int(e.get("AEGIS_RATE_LIMIT_PER_MINUTE", "120")),
            max_request_bytes=int(e.get("AEGIS_MAX_REQUEST_BYTES", "1000000")),
            agent_allow_high_risk=flag("AGENT_ALLOW_HIGH_RISK"),
            agent_workspace_root=Path(e.get("AGENT_WORKSPACE_ROOT", str(defaults.agent_workspace_root))),
            log_level=e.get("LOG_LEVEL", "INFO").upper(),
        )
