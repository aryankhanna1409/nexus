#!/usr/bin/env python3
"""Generate an API token and its AEGIS_API_TOKENS entry.

Usage: scripts/hash_token.py <name> <viewer|operator|approver|admin>

Prints the raw token (give it to the client; it is not stored anywhere) and the
`name:role:sha256` entry to append to AEGIS_API_TOKENS in your .env file.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import sys

ROLES = ("viewer", "operator", "approver", "admin")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ROLES or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", argv[0]):
        print(__doc__, file=sys.stderr)
        return 2
    token = secrets.token_urlsafe(32)
    print(f"token: {token}")
    print(f"AEGIS_API_TOKENS entry: {argv[0]}:{argv[1]}:{hashlib.sha256(token.encode()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
