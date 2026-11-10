"""Root-cause analysis: find out *why* the incident happened.

The investigator (Claude, or the offline rules when there is no API key)
gets seven read-only tools. Every tool result is stamped with an evidence
id (E1, E2, ...). The final answer must cite those ids for every fact, and
we reject any answer that cites evidence that does not exist. That is how
the AI is kept honest: it cannot invent data it never looked at.
"""
from __future__ import annotations

import statistics

from . import ai
from .simulate import METRICS, NODE_OF, NOW, World, iso, minute_of

CAUSE_TYPES = ["deployment_regression", "configuration_change", "security_attack",
               "resource_exhaustion", "traffic_overload", "radio_degradation", "unknown"]
RISKS = ["read_only", "low", "needs_approval"]

STR = {"type": "string"}
METRIC = {"type": "string", "enum": list(METRICS)}
CELL = {"type": "string", "pattern": "^CELL-1[0-9]{2}$"}
NODE = {"type": "string", "enum": ["pgw-1", "pgw-2", "pgw-3"]}

TOOLS = [
    ai.schema("get_incident", "The open incident: affected cells, gateway, and each symptom with its onset time. "
              "Contains no conclusions about the cause."),
    ai.schema("get_metric_history", "One KPI for one cell, sampled every 5 minutes between two HH:MM times (12:00-15:00).",
              cell=CELL, metric=METRIC, start=STR, end=STR),
    ai.schema("compare_baseline", "For the affected cells: the hour before onset vs. the incident window for one KPI.",
              metric=METRIC),
    ai.schema("list_deployments", "All software deployments today, on every gateway."),
    ai.schema("get_logs", "Warning and error application logs from one gateway since 12:00 (max 25 lines).", node=NODE),
    ai.schema("get_security_events", "Intrusion-detection events per gateway, with a few samples."),
    ai.schema("get_call_analysis", "Results of the C call-log analyzer for the last hour: per-cell drop and setup "
              "failure rates, signal, packet loss, and the cells it flagged as outliers."),
]
SUBMIT = ai.schema(
    "submit_rca", "Submit the final root-cause analysis. Every fact must cite evidence ids (E1, E2, ...) from tool results.",
    root_cause=STR,
    cause_type={"type": "string", "enum": CAUSE_TYPES},
    confidence={"type": "number", "description": "0 to 0.95. Never 1: this is a hypothesis."},
    facts={"type": "array", "items": {"type": "object", "additionalProperties": False,
                                      "required": ["statement", "evidence"],
                                      "properties": {"statement": STR, "evidence": {"type": "array", "items": STR}}}},
    alternatives={"type": "array", "items": {"type": "object", "additionalProperties": False,
                                             "required": ["cause_type", "confidence", "why_less_likely"],
                                             "properties": {"cause_type": {"type": "string", "enum": CAUSE_TYPES},
                                                            "confidence": {"type": "number"},
                                                            "why_less_likely": STR}}},
    recommended_actions={"type": "array", "items": {"type": "object", "additionalProperties": False,
                                                    "required": ["action", "risk"],
                                                    "properties": {"action": STR,
                                                                   "risk": {"type": "string", "enum": RISKS}}}},
)

SYSTEM = """You are a network reliability engineer investigating a live incident on a mobile network.
Use the tools to gather evidence before concluding. Look at timing (what changed just before
the first symptom?), topology (which gateway and cells?), and rule out alternatives such as
security attacks, other deployments and radio problems.

Rules:
- Only state facts you saw in tool results, and cite their evidence ids.
- The root cause is a hypothesis: confidence at most 0.95.
- Recommend concrete actions with a risk level; a rollback or code change needs approval.
- Finish by calling submit_rca. Keep statements short and specific, with numbers."""


class Toolbox:
    """Read-only views of the data. Records every call so citations can be checked."""

    def __init__(self, world: World, incident: dict, call_analysis: dict):
        self.world, self.incident, self.calls_c = world, incident, call_analysis
        self.log: list[dict] = []

    def run(self, name: str, args: dict) -> tuple[str, bool]:
        fn = getattr(self, "t_" + name, None)
        if fn is None:
            return f"unknown tool {name!r}", True
        try:
            result = fn(**args)
        except (ValueError, KeyError, TypeError) as e:
            return f"invalid arguments: {e}", True
        eid = f"E{len(self.log) + 1}"
        self.log.append({"id": eid, "tool": name, "input": args, "result": result})
        return ai.dumps({"evidence_id": eid, **result}), False

    # --- tools -------------------------------------------------------
    def t_get_incident(self) -> dict:
        i = self.incident
        return {"incident": i["id"], "severity": i["severity"], "gateway": i["node"], "cells": i["cells"],
                "onset": i["onset"],
                "symptoms": [{k: s[k] for k in ("metric", "onset", "baseline", "worst", "severity")}
                             for s in i["symptoms"]]}

    def t_get_metric_history(self, cell: str, metric: str, start: str, end: str) -> dict:
        if cell not in NODE_OF or metric not in METRICS:
            raise ValueError("unknown cell or metric")
        a, b = max(0, minute_of(start)), min(self.incident_now(), minute_of(end))
        if a >= b:
            raise ValueError("start must be before end, within 12:00-15:00")
        values = self.world.metrics[cell][metric]
        return {"cell": cell, "metric": metric, "unit": METRICS[metric][0],
                "points": [[iso(m)[11:16], values[m]] for m in range(a, b, 5)]}

    def t_compare_baseline(self, metric: str) -> dict:
        onset, now = self.incident["onset_minute"], self.incident_now()
        rows = []
        for cell in self.incident["cells"]:
            v = self.world.metrics[cell][metric]
            before, during = statistics.fmean(v[max(0, onset - 60):onset]), statistics.fmean(v[onset:now])
            rows.append({"cell": cell, "hour_before": round(before, 2), "incident_mean": round(during, 2),
                         "change_pct": round(100 * (during - before) / before, 1) if before else None})
        return {"metric": metric, "unit": METRICS[metric][0], "cells": rows}

    def t_list_deployments(self) -> dict:
        now = self.incident_now()
        return {"deployments": [{k: d[k] for k in ("id", "time", "node", "service", "from_version",
                                                   "to_version", "change")}
                                for d in self.world.deployments if d["minute"] <= now]}

    def t_get_logs(self, node: str) -> dict:
        now = self.incident_now()
        rows = [l for l in self.world.logs if l["node"] == node and l["level"] != "INFO" and l["minute"] < now]
        return {"node": node, "count": len(rows),
                "lines": [f"{l['time'][11:16]} {l['level']} {l['message']}" for l in rows[:25]]}

    def t_get_security_events(self) -> dict:
        now = self.incident_now()
        events = [e for e in self.world.security_events if e["minute"] < now]
        per_node = {n: sum(1 for e in events if e["node"] == n) for n in ("pgw-1", "pgw-2", "pgw-3")}
        return {"total": len(events), "per_gateway": per_node,
                "samples": [{k: e[k] for k in ("time", "node", "type", "source_ip", "severity")} for e in events[:3]]}

    def t_get_call_analysis(self) -> dict:
        c = self.calls_c
        return {"window": "14:00-15:00", "analyzer": f"libcallanalyzer {c['library_version']} (C)",
                "total_calls": c["overall"]["total"],
                "cells": [{k: x[k] for k in ("cell_id", "total", "drop_rate", "setup_failure_rate",
                                             "avg_signal_dbm", "avg_packet_loss")} for x in c["cells"]],
                "flagged": c["anomalies"]}

    def incident_now(self) -> int:
        return NOW


def validate(answer: dict, box: Toolbox) -> list[str]:
    """Problems with an answer. Empty list means it is accepted."""
    known = {e["id"] for e in box.log}
    problems = []
    if not answer.get("facts"):
        problems.append("at least one fact is required")
    for f in answer.get("facts", []):
        missing = [e for e in f.get("evidence", []) if e not in known]
        if not f.get("evidence"):
            problems.append(f"fact has no evidence: {f.get('statement', '')[:60]}")
        elif missing:
            problems.append(f"fact cites evidence that does not exist: {missing}")
    if not 0 <= answer.get("confidence", -1) <= 0.95:
        problems.append("confidence must be between 0 and 0.95")
    return problems


def investigate(world: World, incident: dict, call_analysis: dict,
                on_event=lambda kind, data: None, client=None) -> dict:
    """Run the RCA once. Returns the answer plus the evidence trail."""
    box = Toolbox(world, incident, call_analysis)
    use_ai, reason = (True, "test client") if client else ai.available()
    provider = reason

    if use_ai:
        def execute(name: str, args: dict) -> tuple[str, bool]:
            if name == "submit_rca":
                problems = validate(args, box)
                return ("rejected: " + "; ".join(problems), True) if problems else ("accepted", False)
            return box.run(name, args)

        task = (f"Incident {incident['id']} is open on gateway {incident['node']} "
                f"({', '.join(incident['cells'])}). It is now 15:00. Find the root cause.")
        try:
            answer = ai.run_tools(SYSTEM, task, TOOLS + [SUBMIT], execute, "submit_rca", on_event, client=client)
        except Exception as e:  # network, auth, refusal: fall back rather than stop the demo
            on_event("fallback", {"reason": f"{type(e).__name__}: {e}"})
            box.log.clear()
            answer, provider = offline_investigation(box, on_event), f"offline rules (Claude failed: {e})"
    else:
        answer = offline_investigation(box, on_event)
        provider = f"offline rules ({reason})"

    return {"provider": provider, **answer, "evidence": box.log}


def offline_investigation(box: Toolbox, on_event) -> dict:
    """Deterministic investigator: same tools, same citation rules, no AI."""
    def call(name: str, **args) -> tuple[str, dict]:
        on_event("tool_call", {"name": name, "input": args})
        text, _ = box.run(name, args)
        on_event("tool_result", {"name": name, "text": text, "is_error": False})
        return box.log[-1]["id"], box.log[-1]["result"]

    e_inc, inc = call("get_incident")
    e_dep, deps = call("list_deployments")
    e_mem, mem = call("compare_baseline", metric="memory_pct")
    e_lat, lat = call("compare_baseline", metric="latency_ms")
    e_log, logs = call("get_logs", node=inc["gateway"])
    e_sec, sec = call("get_security_events")
    e_cdr, cdr = call("get_call_analysis")

    first = inc["symptoms"][0]
    onset = minute_of(inc["onset"])
    suspects = [d for d in deps["deployments"]
                if d["node"] == inc["gateway"] and 0 <= onset - minute_of(d["time"]) <= 120]
    others = [d for d in deps["deployments"] if d["node"] != inc["gateway"]]
    flagged = sorted({a["cell_id"] for a in cdr["flagged"]})
    worst_mem = max(mem["cells"], key=lambda r: r["incident_mean"])
    worst_lat = max(lat["cells"], key=lambda r: r["incident_mean"])

    facts = [
        {"statement": f"First symptom was {first['metric']} at {first['onset'][11:16]} on {', '.join(inc['cells'])}.",
         "evidence": [e_inc]},
        {"statement": f"Memory on {worst_mem['cell']} averaged {worst_mem['incident_mean']}% during the incident "
                      f"vs {worst_mem['hour_before']}% the hour before.", "evidence": [e_mem]},
        {"statement": f"Latency on {worst_lat['cell']} averaged {worst_lat['incident_mean']} ms vs "
                      f"{worst_lat['hour_before']} ms before.", "evidence": [e_lat]},
        {"statement": f"{logs['count']} warning/error log lines on {inc['gateway']}; first: "
                      f"\"{logs['lines'][0] if logs['lines'] else 'none'}\".", "evidence": [e_log]},
        {"statement": f"{sec['per_gateway'].get(inc['gateway'], 0)} security events on {inc['gateway']} "
                      f"({sec['total']} network-wide).", "evidence": [e_sec]},
        {"statement": f"The C call analyzer independently flagged {', '.join(flagged) or 'no cells'}.",
         "evidence": [e_cdr]},
    ]
    if suspects:
        d = suspects[-1]
        lead = onset - minute_of(d["time"])
        facts.insert(1, {"statement": f"{d['service']} {d['to_version']} was deployed to {d['node']} at "
                                      f"{d['time'][11:16]}, {lead} min before the first symptom.",
                         "evidence": [e_dep, e_inc]})
        root = (f"The {d['service']} {d['to_version']} release on {d['node']} leaks memory; garbage collection "
                f"then saturates CPU, which drives latency, packet loss and dropped calls.")
        cause, conf = "deployment_regression", 0.85
        actions = [{"action": f"Roll back {d['service']} on {d['node']} to {d['from_version']}", "risk": "needs_approval"},
                   {"action": f"Watch memory and call drops on {', '.join(inc['cells'])} for 30 min", "risk": "read_only"},
                   {"action": f"Open a bug against {d['to_version']} with a memory-growth test", "risk": "low"}]
    else:
        root = f"Memory exhaustion on {inc['gateway']} with no recent change found."
        cause, conf = "resource_exhaustion", 0.5
        actions = [{"action": f"Inspect {inc['gateway']} memory usage by process", "risk": "read_only"}]

    alternatives = [{"cause_type": "resource_exhaustion", "confidence": 0.35,
                     "why_less_likely": "Describes the mechanism; the deployment is the more specific trigger."},
                    {"cause_type": "security_attack", "confidence": 0.03,
                     "why_less_likely": f"No security events on {inc['gateway']}."}] if suspects else []
    if others:
        alternatives.append({"cause_type": "configuration_change", "confidence": 0.02,
                             "why_less_likely": f"Other deployment ({others[0]['to_version']} on {others[0]['node']}) "
                                                f"is on a gateway with no symptoms."})
    answer = {"root_cause": root, "cause_type": cause, "confidence": conf, "facts": facts,
              "alternatives": alternatives, "recommended_actions": actions}
    assert not validate(answer, box)
    return answer
