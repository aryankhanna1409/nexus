"""Call-detail records consistent with the simulated network state.

Per cell and minute, call attempts are Poisson in the number of active users,
setup failures follow `call_setup_success_rate`, drops follow `call_drop_rate`,
and signal/packet-loss fields come from the cell's RSRP and packet loss. The
output uses the libcallanalyzer CSV schema so it can be analysed by the C
library (M1/M2).
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from app.simulation.scenario import SimulationResult

CSV_HEADER = ("timestamp", "caller", "callee", "cell_id", "duration", "status_code",
              "signal_strength", "packet_loss")
CALLS_PER_USER_PER_MINUTE = 0.02
SETUP_FAILURE_CODES = np.array([486, 480, 408, 503])
DROP_CODES = np.array([901, 902, 903, 904])


@dataclass(frozen=True, order=True)
class Cdr:
    epoch: int
    cell_id: str
    caller: str
    callee: str
    duration: int
    status_code: int
    signal_strength: int
    packet_loss: int


def generate_cdrs(result: SimulationResult, seed: int, subscribers: int = 5000) -> list[Cdr]:
    rng = np.random.default_rng(np.random.SeedSequence([seed, 0xCD12]))
    rows: list[Cdr] = []
    for cell in result.scenario.topology.cell_ids:
        m = result.metrics[cell]
        attempts = rng.poisson(m["active_users"] * CALLS_PER_USER_PER_MINUTE)
        for minute, n_calls in enumerate(attempts):
            setup_fail = 1.0 - m["call_setup_success_rate"][minute] / 100.0
            drop = m["call_drop_rate"][minute] / 100.0
            for _ in range(int(n_calls)):
                caller, callee = rng.choice(subscribers, size=2, replace=False)
                roll = rng.random()
                planned = int(min(3600, max(1, round(rng.gamma(2.5, 50.0)))))
                if roll < setup_fail:
                    status, duration = int(rng.choice(SETUP_FAILURE_CODES)), 0
                elif roll < setup_fail + (1.0 - setup_fail) * drop:
                    status = int(rng.choice(DROP_CODES))
                    duration = max(1, round(planned * rng.uniform(0.05, 0.9)))
                else:
                    status, duration = 200, planned
                signal = int(np.clip(round(m["rsrp_dbm"][minute] + rng.normal(0, 3)), -150, 0))
                loss = int(np.clip(round(m["packet_loss_pct"][minute] + rng.normal(0, 0.5)), 0, 100))
                rows.append(Cdr(int(result.epochs[minute]) + int(rng.integers(0, 60)), cell,
                                f"+1555{int(caller):07d}", f"+1555{int(callee):07d}",
                                duration, status, signal, loss))
    rows.sort()
    return rows


def render_cdr_csv(rows: list[Cdr]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_HEADER)
    for r in rows:
        writer.writerow((datetime.fromtimestamp(r.epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         r.caller, r.callee, r.cell_id, r.duration, r.status_code,
                         r.signal_strength, r.packet_loss))
    return buffer.getvalue()


def write_cdr_csv(rows: list[Cdr], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_cdr_csv(rows), encoding="ascii", newline="")
