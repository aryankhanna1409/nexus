"""Dependency scanning against the bundled synthetic advisory database (no network)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

DATA = Path(__file__).resolve().parent / "data" / "advisories.json"
_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([0-9]+(?:\.[0-9]+)*)$")


def parse_version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


@cache
def _database() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(DATA.read_text())
    return data


@dataclass(frozen=True)
class Pin:
    package: str
    version: str
    line: int


@dataclass(frozen=True)
class Finding:
    advisory_id: str
    package: str
    installed: str
    severity: str
    summary: str
    fixed_in: str

    def to_dict(self) -> dict[str, str]:
        return self.__dict__.copy()


def parse_requirements(text: str) -> list[Pin]:
    pins = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = _PIN.match(line)
        if match is None:
            raise ValueError(f"line {number}: only exact pins (name==version) are supported")
        pins.append(Pin(match.group(1).lower(), match.group(2), number))
    return pins


def scan(text: str) -> list[Finding]:
    findings = []
    for pin in parse_requirements(text):
        for adv in _database()["advisories"]:
            if adv["package"] != pin.package:
                continue
            version = parse_version(pin.version)
            if parse_version(adv["affected_from"]) <= version < parse_version(adv["vulnerable_below"]):
                findings.append(Finding(adv["id"], pin.package, pin.version, adv["severity"],
                                        adv["summary"], adv["fixed_in"]))
    return findings


def available_versions(package: str) -> list[str]:
    return list(_database()["package_index"].get(package, []))


def minimal_safe_upgrade(package: str, current: str) -> str | None:
    """Smallest released version above `current` not affected by any advisory."""
    for candidate in sorted(available_versions(package), key=parse_version):
        if parse_version(candidate) <= parse_version(current):
            continue
        if not scan(f"{package}=={candidate}"):
            return candidate
    return None


def notice() -> str:
    return str(_database()["notice"])
