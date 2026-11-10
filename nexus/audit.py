"""Tamper-evident audit log.

Every entry stores the SHA-256 hash of the previous entry, so changing or
deleting any line breaks the chain from that point on. verify() finds it.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path | None = None):
        self.entries: list[dict] = []
        self.path = path
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")

    def record(self, actor: str, action: str, **details) -> dict:
        entry = {"seq": len(self.entries) + 1,
                 "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "actor": actor, "action": action, "details": details,
                 "prev": self.entries[-1]["hash"] if self.entries else "0" * 64}
        entry["hash"] = _digest(entry)
        self.entries.append(entry)
        if self.path:
            with self.path.open("a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        return entry


def verify(entries: list[dict]) -> tuple[bool, str]:
    prev = "0" * 64
    for e in entries:
        if e["prev"] != prev or _digest(e) != e["hash"]:
            return False, f"chain broken at entry {e['seq']}"
        prev = e["hash"]
    return True, f"{len(entries)} entries, chain intact"


def verify_file(path: Path) -> tuple[bool, str]:
    return verify([json.loads(line) for line in path.read_text().splitlines() if line.strip()])
