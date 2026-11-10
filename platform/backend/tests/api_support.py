"""Helpers for API tests: migrated SQLite databases, per-role tokens, clients."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from app.config import Settings, parse_token_specs
from app.main import create_app
from app.security.tokens import generate_token, hash_token

BACKEND_DIR = Path(__file__).resolve().parents[1]
ROLES = ("viewer", "operator", "approver", "admin")


def alembic_config(url: str) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def migrate(url: str) -> None:
    command.upgrade(alembic_config(url), "head")


@dataclass
class ApiHarness:
    client: TestClient
    settings: Settings
    tokens: dict[str, str]

    def headers(self, role: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens[role]}"}

    def get(self, path: str, role: str = "viewer", **kwargs: object) -> object:
        return self.client.get(path, headers=self.headers(role), **kwargs)  # type: ignore[arg-type]

    def post(self, path: str, role: str = "operator", **kwargs: object) -> object:
        return self.client.post(path, headers=self.headers(role), **kwargs)  # type: ignore[arg-type]


def make_harness(tmp: Path, database_url: str | None = None, **overrides: object) -> ApiHarness:
    url = database_url or f"sqlite:///{tmp / 'aegis.db'}"
    migrate(url)
    tokens = {role: generate_token() for role in ROLES}
    spec = ",".join(f"test-{role}:{role}:{hash_token(token)}" for role, token in tokens.items())
    settings = Settings(database_url=url, data_dir=tmp / "data", api_tokens=parse_token_specs(spec),
                        agent_workspace_root=tmp / "workspaces", **overrides)  # type: ignore[arg-type]
    return ApiHarness(TestClient(create_app(settings)), settings, tokens)
