#!/usr/bin/env python3
"""Deterministic synthetic call-log (CDR) generator for Aegis-Net.

Produces CSV in the libcallanalyzer schema:

    timestamp,caller,callee,cell_id,duration,status_code,signal_strength,packet_loss

The healthy baseline models per-cell signal levels, Poisson call arrivals with a
mild load cycle, gamma-distributed call durations and low background failure
rates. Optionally one cell suffers a progressive radio degradation:

    severity ramps from 0.3 to 1.0 over the first half of the fault window
      -> signal strength falls (up to --fault-signal-penalty dB)
      -> packet loss rises (up to --fault-packet-loss percentage points)
      -> drops rise (up to +--fault-drop-rate, mostly 901 radio-link failure / 903 congestion)
      -> setup failures rise (408 timeout / 503 unavailable)

The same seed and arguments always yield byte-identical output. All data is
synthetic; subscriber numbers use the +1555 / +1556 fictional ranges.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import random
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "data" / "call_logs" / "call_logs.csv"
HEADER = (
    "timestamp", "caller", "callee", "cell_id",
    "duration", "status_code", "signal_strength", "packet_loss",
)

CodeWeights = tuple[tuple[int, float], ...]  # (status_code, relative weight)

# Background behaviour of a healthy network.
BASE_SETUP_FAILURE_RATE = 0.025
BASE_DROP_RATE = 0.012
SETUP_FAILURE_CODES: CodeWeights = ((486, 0.45), (480, 0.25), (408, 0.15), (503, 0.15))
HEALTHY_DROP_CODES: CodeWeights = ((901, 0.4), (902, 0.3), (903, 0.2), (904, 0.1))
FAULT_DROP_CODES: CodeWeights = ((901, 0.7), (903, 0.2), (902, 0.1))
FAULT_SETUP_FAILURE_CODES: CodeWeights = ((408, 0.6), (503, 0.4))
FAULT_EXTRA_SETUP_FAILURE_RATE = 0.08
DURATION_GAMMA_SHAPE = 2.5
DURATION_GAMMA_SCALE = 50.0  # mean 125 s
MAX_DURATION = 3600
SIGNAL_NOISE_DB = 4.0


@dataclass(frozen=True)
class FaultSpec:
    cell_id: str
    start_minute: float = 45.0
    duration_minutes: float = 60.0
    max_drop_rate: float = 0.35
    max_signal_penalty_db: float = 22.0
    max_packet_loss: float = 14.0

    def severity(self, minute: float) -> float:
        """0 outside the fault window; ramps 0.3 -> 1.0 over its first half."""
        if not self.start_minute <= minute < self.start_minute + self.duration_minutes:
            return 0.0
        progress = (minute - self.start_minute) / self.duration_minutes
        return min(1.0, 0.3 + 1.4 * progress)


@dataclass(frozen=True)
class GeneratorConfig:
    seed: int
    start: datetime = datetime(2026, 3, 1, 14, 0, tzinfo=UTC)
    duration_minutes: int = 120
    cells: int = 12
    calls_per_minute: float = 40.0
    subscribers: int = 2000
    fault: FaultSpec | None = field(default_factory=lambda: FaultSpec(cell_id="CELL-107"))

    def cell_ids(self) -> list[str]:
        return [f"CELL-{101 + i}" for i in range(self.cells)]

    def validate(self) -> None:
        if not 1 <= self.cells <= 999:
            raise ValueError("cells must be in [1, 999]")
        if self.duration_minutes < 1:
            raise ValueError("duration_minutes must be >= 1")
        if self.calls_per_minute <= 0 or self.calls_per_minute > 10_000:
            raise ValueError("calls_per_minute must be in (0, 10000]")
        if self.subscribers < 2:
            raise ValueError("subscribers must be >= 2")
        if self.start.tzinfo is None or self.start.year < 1970:
            raise ValueError("start must be timezone-aware and not before 1970")
        fault = self.fault
        if fault is None:
            return
        if fault.cell_id not in self.cell_ids():
            raise ValueError(f"faulty cell {fault.cell_id!r} is not one of the generated cells")
        if fault.start_minute < 0 or fault.duration_minutes <= 0:
            raise ValueError("fault window must start at >= 0 and have positive duration")
        if fault.start_minute + fault.duration_minutes > self.duration_minutes:
            raise ValueError("fault window must end within the generated period")
        if not 0 <= fault.max_drop_rate <= 0.9:
            raise ValueError("fault drop rate must be in [0, 0.9]")
        if not 0 <= fault.max_signal_penalty_db <= 60:
            raise ValueError("fault signal penalty must be in [0, 60] dB")
        if not 0 <= fault.max_packet_loss <= 90:
            raise ValueError("fault packet loss must be in [0, 90]")


@dataclass(frozen=True, order=True)
class CallRow:
    epoch: int
    cell_id: str
    caller: str
    callee: str
    duration: int
    status_code: int
    signal_strength: int
    packet_loss: int

    def csv_fields(self) -> tuple[str, ...]:
        timestamp = datetime.fromtimestamp(self.epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return (
            timestamp, self.caller, self.callee, self.cell_id, str(self.duration),
            str(self.status_code), str(self.signal_strength), str(self.packet_loss),
        )


def _weighted(rng: random.Random, options: CodeWeights) -> int:
    codes = [code for code, _ in options]
    weights = [weight for _, weight in options]
    return rng.choices(codes, weights=weights, k=1)[0]


def _poisson(rng: random.Random, lam: float) -> int:
    """Knuth's method for moderate lambda; normal approximation for large lambda."""
    if lam > 500:
        return max(0, round(rng.gauss(lam, math.sqrt(lam))))
    limit = math.exp(-lam)
    k, product = 0, rng.random()
    while product > limit:
        k += 1
        product *= rng.random()
    return k


def _subscriber(index: int) -> str:
    prefix = "+1555" if index < 10_000_000 else "+1556"
    return f"{prefix}{index % 10_000_000:07d}"


def generate_rows(config: GeneratorConfig) -> list[CallRow]:
    """Generates calls sorted by time; deterministic for a given config."""
    config.validate()
    rng = random.Random(config.seed)
    cells = config.cell_ids()
    base_signal = {cell: -84.0 + rng.uniform(-2.0, 2.0) for cell in cells}
    load_weight = [rng.uniform(0.85, 1.15) for _ in cells]
    start_epoch = int(config.start.timestamp())
    fault = config.fault
    rows: list[CallRow] = []

    for minute in range(config.duration_minutes):
        load_cycle = 1.0 + 0.15 * math.sin(2 * math.pi * minute / 240.0)
        for _ in range(_poisson(rng, config.calls_per_minute * load_cycle)):
            second = rng.randrange(60)
            cell = rng.choices(cells, weights=load_weight, k=1)[0]
            caller_idx = rng.randrange(config.subscribers)
            callee_idx = rng.randrange(config.subscribers - 1)
            if callee_idx >= caller_idx:
                callee_idx += 1
            severity = fault.severity(minute + second / 60.0) if fault and cell == fault.cell_id else 0.0

            signal = base_signal[cell] + rng.gauss(0.0, SIGNAL_NOISE_DB)
            loss = max(0.0, rng.gauss(0.6, 0.8))
            setup_failure_rate = BASE_SETUP_FAILURE_RATE
            drop_rate = BASE_DROP_RATE
            if fault is not None and severity > 0.0:
                signal -= severity * fault.max_signal_penalty_db
                loss += severity * fault.max_packet_loss * rng.uniform(0.6, 1.2)
                setup_failure_rate += severity * FAULT_EXTRA_SETUP_FAILURE_RATE
                drop_rate += severity * fault.max_drop_rate

            planned = min(MAX_DURATION, max(1, round(rng.gammavariate(DURATION_GAMMA_SHAPE,
                                                                      DURATION_GAMMA_SCALE))))
            roll = rng.random()
            if roll < setup_failure_rate:
                codes = FAULT_SETUP_FAILURE_CODES if severity > 0.5 else SETUP_FAILURE_CODES
                status, duration = _weighted(rng, codes), 0
            elif roll < setup_failure_rate + drop_rate:
                codes = FAULT_DROP_CODES if severity > 0.0 else HEALTHY_DROP_CODES
                status = _weighted(rng, codes)
                duration = max(1, round(planned * rng.uniform(0.05, 0.9)))
            else:
                status, duration = 200, planned

            rows.append(CallRow(
                epoch=start_epoch + minute * 60 + second,
                cell_id=cell,
                caller=_subscriber(caller_idx),
                callee=_subscriber(callee_idx),
                duration=duration,
                status_code=status,
                signal_strength=int(min(0, max(-150, round(signal)))),
                packet_loss=int(min(100, round(loss))),
            ))
    rows.sort()
    return rows


def render_csv(rows: Sequence[CallRow]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(HEADER)
    for row in rows:
        writer.writerow(row.csv_fields())
    return buffer.getvalue()


def build_manifest(config: GeneratorConfig, rows: Sequence[CallRow], csv_text: str) -> dict[str, object]:
    """Ground truth for the generated file (what was injected, not what is detected)."""
    fault = config.fault
    fault_info: dict[str, object] | None = None
    if fault is not None:
        fault_start = config.start + timedelta(minutes=fault.start_minute)
        fault_end = fault_start + timedelta(minutes=fault.duration_minutes)
        fault_info = {
            **asdict(fault),
            "pattern": "progressive_radio_degradation",
            "start": fault_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": fault_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    return {
        "generator": "scripts/generate_call_logs.py",
        "synthetic": True,
        "seed": config.seed,
        "start": config.start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_minutes": config.duration_minutes,
        "cells": config.cell_ids(),
        "calls_per_minute": config.calls_per_minute,
        "subscribers": config.subscribers,
        "rows": len(rows),
        "sha256": hashlib.sha256(csv_text.encode("ascii")).hexdigest(),
        "fault": fault_info,
    }


def _parse_start(text: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO-8601 timestamp: {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help="CSV path, or '-' for stdout (default: %(default)s)")
    parser.add_argument("--manifest", type=Path, default=None,
                        help="optional JSON ground-truth manifest path")
    parser.add_argument("--start", type=_parse_start, default="2026-03-01T14:00:00Z")
    parser.add_argument("--duration-minutes", type=int, default=120)
    parser.add_argument("--cells", type=int, default=12)
    parser.add_argument("--calls-per-minute", type=float, default=40.0)
    parser.add_argument("--subscribers", type=int, default=2000)
    parser.add_argument("--faulty-cell", default="CELL-107",
                        help="cell to degrade, or 'none' for a healthy baseline")
    parser.add_argument("--fault-start-minute", type=float, default=45.0)
    parser.add_argument("--fault-duration-minutes", type=float, default=60.0)
    parser.add_argument("--fault-drop-rate", type=float, default=0.35)
    parser.add_argument("--fault-signal-penalty", type=float, default=22.0)
    parser.add_argument("--fault-packet-loss", type=float, default=14.0)
    return parser


def config_from_args(args: argparse.Namespace) -> GeneratorConfig:
    fault = None
    if args.faulty_cell.lower() != "none":
        fault = FaultSpec(
            cell_id=args.faulty_cell,
            start_minute=args.fault_start_minute,
            duration_minutes=args.fault_duration_minutes,
            max_drop_rate=args.fault_drop_rate,
            max_signal_penalty_db=args.fault_signal_penalty,
            max_packet_loss=args.fault_packet_loss,
        )
    return GeneratorConfig(
        seed=args.seed,
        start=args.start,
        duration_minutes=args.duration_minutes,
        cells=args.cells,
        calls_per_minute=args.calls_per_minute,
        subscribers=args.subscribers,
        fault=fault,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = config_from_args(args)
    try:
        rows = generate_rows(config)
    except ValueError as exc:
        parser.error(str(exc))
    csv_text = render_csv(rows)

    if str(args.output) == "-":
        sys.stdout.write(csv_text)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(csv_text, encoding="ascii", newline="")
    if args.manifest is not None:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(build_manifest(config, rows, csv_text), indent=2) + "\n",
                                 encoding="ascii")
    if str(args.output) != "-":
        fault_desc = f"fault on {config.fault.cell_id}" if config.fault else "healthy baseline"
        print(f"wrote {len(rows)} calls to {args.output} (seed {config.seed}, {fault_desc})",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
