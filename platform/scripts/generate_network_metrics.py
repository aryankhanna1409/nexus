#!/usr/bin/env python3
"""Generate deterministic synthetic network telemetry, events and matching CDRs.

Scenarios: `healthy` (no incident), `seeded` (spec §24 memory-leak deployment on
pgw-1 at 14:05), or any single incident type (see scripts/simulate_incident.py
for full control). Output layout under --out-dir:

    network_metrics/network_metrics.csv   incidents/events.jsonl
    incidents/deployments.jsonl           incidents/ground_truth.json
    security/security_events.jsonl        call_logs/call_logs.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.simulation import Scenario, seeded_memory_leak_scenario, simulate  # noqa: E402
from app.simulation.io import write_all  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--scenario", choices=["healthy", "seeded"], default="seeded")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--minutes", type=int, default=360)
    parser.add_argument("--rollback-minute", type=int, default=None,
                        help="seeded scenario only: simulate a rollback at this minute")
    parser.add_argument("--out-dir", type=Path, default=REPO_ROOT / "data")
    args = parser.parse_args(argv)

    try:
        if args.scenario == "seeded":
            base = seeded_memory_leak_scenario(args.seed, args.rollback_minute)
            scenario = Scenario(name=base.name, seed=base.seed, minutes=args.minutes,
                                incidents=base.incidents, rollback_minute=base.rollback_minute)
        else:
            if args.rollback_minute is not None:
                parser.error("--rollback-minute requires --scenario seeded")
            scenario = Scenario(name="healthy", seed=args.seed, minutes=args.minutes)
        result = simulate(scenario)
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))
    paths = write_all(result, args.out_dir)
    print(f"scenario={scenario.name} seed={scenario.seed} fingerprint={result.fingerprint()[:16]}",
          file=sys.stderr)
    for name, path in paths.items():
        print(f"  {name}: {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
