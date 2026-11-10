"""API token hashing and verification. Raw tokens are never stored."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from app.config import Role, TokenEntry


@dataclass(frozen=True)
class Principal:
    name: str
    role: Role

    def has(self, role: Role) -> bool:
        return self.role >= role


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def authenticate(token: str, entries: tuple[TokenEntry, ...]) -> Principal | None:
    """Constant-time comparison against every configured hash (no early exit)."""
    digest = hash_token(token)
    match: TokenEntry | None = None
    for entry in entries:
        if hmac.compare_digest(digest, entry.sha256):
            match = entry
    return Principal(match.name, match.role) if match else None
