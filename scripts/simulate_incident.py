#!/usr/bin/env python3
"""Simulate one injected incident of any of the nine spec §5 types.

Example:
    scripts/simulate_incident.py --type degraded_radio_signal --target CELL-106 \
        --start-minute 90 --duration-minutes 60 --out-dir /tmp/radio
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.simulation import IncidentSpec, IncidentType, Scenario, simulate  # noqa: E402
from app.simulation.io import write_all  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--type", required=True, choices=[t.value for t in IncidentType])
    parser.add_argument("--target", required=True, help="cell id, or node id (pgw-N) for "
                        "software_deployment_regression / memory_leak")
    parser.add_argument("--start-minute", type=int, default=120)
    parser.add_argument("--duration-minutes", type=int, default=60)
    parser.add_argument("--intensity", type=float, default=1.0)
    parser.add_argument("--rollback-minute", type=int, default=None)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--minutes", type=int, default=360)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    spec = IncidentSpec(IncidentType(args.type), args.target, args.start_minute,
                        args.duration_minutes, args.intensity)
    scenario = Scenario(name=f"incident_{args.type}", seed=args.seed, minutes=args.minutes,
                        incidents=(spec,), rollback_minute=args.rollback_minute)
    try:
        result = simulate(scenario)
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))
    write_all(result, args.out_dir)
    truth = result.ground_truth[0]
    print(f"{truth.incident_type.value} on {truth.target} affecting {', '.join(truth.affected_cells)}"
          f" -> {args.out_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
