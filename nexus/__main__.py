"""Command line entry point.

  python -m nexus demo            run the whole story, write out/report.html
  python -m nexus demo --yes      approve risky agent steps automatically
  python -m nexus demo --offline  no Claude, use the rule-based fallbacks
  python -m nexus calls FILE.csv  analyse any call log with the C library
  python -m nexus bench           C library vs plain Python on 1M calls
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
import time
from pathlib import Path

from . import ai, calls
from .agent import run_agent
from .audit import AuditLog, verify_file
from .detect import correlate, detect_anomalies
from .investigate import investigate
from .report import build
from .simulate import NOW, iso, simulate

TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if TTY else text


def step(n: int, title: str) -> None:
    print("\n" + c(f"[{n}/5] {title}", "1;36"))


def on_event(kind: str, data: dict) -> None:
    if kind == "thought":
        for line in textwrap.wrap(data["text"], 96)[:4]:
            print(c("      " + line, "2"))
    elif kind == "tool_call":
        args = ", ".join(f"{k}={v!r}" for k, v in data["input"].items() if k != "reason")
        print(f"   {c('→', '36')} {data['name']}({args})")
    elif kind == "tool_result":
        text = data["text"]
        try:
            parsed = json.loads(text)
            text = parsed.get("evidence_id", "") + " " if isinstance(parsed, dict) else ""
            text += _gist(data["name"], parsed)
        except (json.JSONDecodeError, AttributeError):
            pass
        print(f"     {c('✗' if data['is_error'] else '←', '31' if data['is_error'] else '2')} {text[:110]}")
    elif kind == "fallback":
        print(c(f"   Claude unavailable ({data['reason'][:120]}); using the offline fallback", "33"))


def _gist(name: str, r: dict) -> str:
    if "deployments" in r:
        return "; ".join(f"{d['time'][11:16]} {d['to_version']} on {d['node']}" for d in r["deployments"])
    if "lines" in r:
        return f"{r['count']} warnings/errors" + (f", first: {r['lines'][0]}" if r["lines"] else "")
    if "per_gateway" in r:
        return f"security events per gateway: {r['per_gateway']}"
    if "flagged" in r:
        return "C analyzer flagged " + ", ".join(sorted({a['cell_id'] for a in r["flagged"]}))
    if "symptoms" in r:
        return "symptoms: " + " → ".join(f"{s['metric']} {s['onset'][11:16]}" for s in r["symptoms"])
    if "cells" in r and "metric" in r:
        return f"{r['metric']}: " + ", ".join(f"{x['cell']} {x['hour_before']}→{x['incident_mean']}" for x in r["cells"])
    if "points" in r:
        return f"{len(r['points'])} points, {r['points'][0][1]} → {r['points'][-1][1]}"
    for k in ("rolled_back", "changed", "summary", "root_cause"):
        if k in r:
            return str(r[k])
    if "recovered" in r:
        return ("recovered" if r["recovered"] else "NOT recovered") + " in " + r["checked_window"]
    if "vulnerable" in r:
        return f"{len(r['vulnerable'])} vulnerable: " + ", ".join(f"{v['package']} {v['version']} ({v['advisory']})" for v in r["vulnerable"])
    if "passed" in r:
        return "tests passed" if r["passed"] else "tests FAILED"
    if "kpis_last_10_min" in r:
        return "; ".join(f"{k['metric']} {k['current']} (baseline {k['baseline']})" for k in r["kpis_last_10_min"])
    return ""


def approver(auto: bool):
    def approve(tool: str, args: dict) -> bool:
        what = ", ".join(f"{k}={v}" for k, v in args.items() if k != "reason")
        print(c(f"\n   ⚠  APPROVAL NEEDED: {tool}({what})", "1;33"))
        print(f"      reason: {args.get('reason', '(none given)')}")
        if auto:
            print(c("      approved automatically (--yes)", "33"))
            return True
        if not sys.stdin.isatty():
            print(c("      no terminal to ask; denied (use --yes to auto-approve)", "33"))
            return False
        answer = input("      approve? [y/N] ").strip().lower()
        return answer in ("y", "yes")
    return approve


def demo(args: argparse.Namespace) -> int:
    if args.offline:
        os.environ["NEXUS_OFFLINE"] = "1"
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    started = time.time()
    use_ai, reason = ai.available()
    print(c("nexus", "1") + f" · AI: {reason}" + ("" if use_ai else c("  (set ANTHROPIC_API_KEY for the real thing)", "2")))

    step(1, f"Simulating 12 cells on 3 gateways, 12:00-{iso(NOW)[11:16]}")
    world = simulate(args.seed)
    rows = world.write_call_log(out / "call_log.csv", NOW - 60, NOW)
    print(f"   7 KPIs per cell per minute; {rows:,} calls written to {out / 'call_log.csv'}")

    step(2, "Analysing the last hour of calls with the C library")
    call_result = calls.analyze(out / "call_log.csv")
    o = call_result["overall"]
    print(f"   {o['total']:,} calls, drop rate {100 * o['drop_rate']:.2f}%, setup failures {100 * o['setup_failure_rate']:.2f}%")
    for a in call_result["anomalies"][:5]:
        print(f"   {c('!', '31')} {a['cell_id']} {a['metric']} {a['value']} vs median {a['baseline']} ({a['severity']})")

    step(3, "Detecting KPI anomalies and correlating them into an incident")
    anomalies = detect_anomalies(world)
    incident = correlate(world, anomalies)
    if incident is None:
        print("   no incident: the network looks healthy")
        return 0
    print(f"   {len(anomalies)} anomalies → {c(incident['id'], '1')} {incident['severity']} on {incident['node']} "
          f"({', '.join(incident['cells'])})")
    print("   " + " → ".join(f"{s['metric']} {s['onset'][11:16]}" for s in incident["symptoms"]))

    step(4, "Investigating the root cause")
    rca = investigate(world, incident, call_result, on_event)
    print(c(f"\n   Root cause ({rca['confidence']:.0%}): ", "1") + rca["root_cause"])

    step(5, "DevSecOps agent: fix, verify, secure")
    audit = AuditLog(out / "audit.jsonl")
    agent = run_agent(world, incident, rca, audit, approver(args.yes), on_event)
    chain = verify_file(out / "audit.jsonl")

    (out / "report.html").write_text(build(world, incident, anomalies, call_result, rca, agent, chain))
    (out / "run.json").write_text(json.dumps({"incident": incident, "rca": rca, "calls": call_result,
                                              "agent": {k: v for k, v in agent.items() if k != "fixed_world"}},
                                             indent=2, default=str))
    status = incident["status"]
    print("\n" + c(f"Incident {incident['id']}: {status}", "1;32" if status == "resolved" else "1;31")
          + f" · audit: {chain[1]} · {time.time() - started:.1f}s")
    print(f"Report: {(out / 'report.html').resolve()}")
    return 0


def bench(args: argparse.Namespace) -> int:
    """Time the C analyzer against a straightforward pure-Python version."""
    import csv
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    small, big = out / "call_log.csv", out / "bench_calls.csv"
    simulate(7).write_call_log(small, NOW - 60, NOW)
    header, *rows = small.read_text().splitlines()
    with big.open("w") as f:
        f.write(header + "\n")
        for i in range(args.rows):
            f.write(rows[i % len(rows)] + "\n")
    print(f"{args.rows:,} calls, {big.stat().st_size / 1e6:.0f} MB")

    t = time.perf_counter()
    calls.analyze(big)
    c_time = time.perf_counter() - t

    t = time.perf_counter()
    per_cell: dict[str, list[int]] = {}
    with big.open() as f:
        for row in csv.DictReader(f):
            s = per_cell.setdefault(row["cell_id"], [0, 0])
            s[0] += 1
            s[1] += 900 <= int(row["status_code"]) <= 999
    py_time = time.perf_counter() - t

    print(f"C library : {c_time:.2f}s  (parse, validate, per-cell stats, anomaly detection)")
    print(f"Python csv: {py_time:.2f}s  (parse and count drops only)")
    print(c(f"C is {py_time / c_time:.0f}x faster while doing more work", "1;32"))
    big.unlink()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nexus", description="Network incident detection, AI root-cause analysis and a DevSecOps agent.")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run the full story and write an HTML report")
    d.add_argument("--yes", action="store_true", help="approve risky agent actions automatically")
    d.add_argument("--offline", action="store_true", help="do not call Claude; use the rule-based fallbacks")
    d.add_argument("--seed", type=int, default=7)
    d.add_argument("--out", default="out")
    k = sub.add_parser("calls", help="analyse a call-log CSV with the C library")
    k.add_argument("csv")
    b = sub.add_parser("bench", help="time the C library against plain Python")
    b.add_argument("--rows", type=int, default=1_000_000)
    b.add_argument("--out", default="out")
    args = p.parse_args(argv)
    if args.cmd == "calls":
        print(json.dumps(calls.analyze(args.csv), indent=2))
        return 0
    if args.cmd == "bench":
        return bench(args)
    return demo(args)


if __name__ == "__main__":
    sys.exit(main())
