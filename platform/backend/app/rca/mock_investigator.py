"""Deterministic, rule-based stand-in for an LLM investigator (offline demo and tests).

It is *not* a language model. It follows a fixed evidence-gathering plan through
the same read-only tools, then builds an answer only from the tool results it
received, citing their tool call ids. The answer goes through exactly the same
validation as a real model's answer. Every hypothesis states why it was scored
as it was.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from app.llm.base import AssistantMessage, Message, ToolCall, ToolResultsMessage, UserMessage

CONTEXT_MARKER = "INCIDENT_CONTEXT_JSON:"
RESOURCE_METRICS = ("memory_utilization", "cpu_utilization")
BASELINE_ORDER = ("memory_utilization", "cpu_utilization", "active_users", "rsrp_dbm", "sinr_db",
                  "handover_failure_rate", "latency_ms", "packet_loss_pct", "call_drop_rate",
                  "throughput_mbps")


def _shift(ts: str, minutes: int) -> str:
    moment = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC) + timedelta(minutes=minutes)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _clamp_span(start: str, end: str, hours: int = 23) -> str:
    limit = _shift(start, hours * 60)
    return min(end, limit)


class _Transcript:
    """Tool calls and results gathered so far, keyed by tool name."""

    def __init__(self, messages: list[Message]) -> None:
        first = next(m for m in messages if isinstance(m, UserMessage))
        self.context: dict[str, Any] = json.loads(first.text.split(CONTEXT_MARKER, 1)[1])
        calls: dict[str, ToolCall] = {}
        self.results: dict[str, list[tuple[str, dict[str, Any], dict[str, Any], bool]]] = {}
        self.turns = 0
        self.rejections = [m.text for m in messages if isinstance(m, UserMessage) and m is not first]
        for m in messages:
            if isinstance(m, AssistantMessage):
                self.turns += 1
                for c in m.tool_calls:
                    calls[c.id] = c
            elif isinstance(m, ToolResultsMessage):
                for r in m.results:
                    call = calls[r.tool_call_id]
                    self.results.setdefault(call.name, []).append(
                        (r.tool_call_id, call.arguments, json.loads(r.content), not r.is_error))

    def ok(self, tool: str) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
        return [(i, a, res) for i, a, res, good in self.results.get(tool, []) if good]


def _plan(t: _Transcript) -> list[ToolCall]:
    ctx = t.context
    start, end = ctx["start"], ctx["end"]
    window_end = _clamp_span(start, end)
    symptoms = [s["metric"] for s in ctx["symptoms"]]
    cell = ctx["affected_cells"][0]
    n = t.turns + 1

    def call(i: int, name: str, args: dict[str, Any]) -> ToolCall:
        return ToolCall(f"mock-{n}-{i}", name, args)

    if n == 1:
        return [call(1, "get_related_events", {"incident_id": ctx["incident_id"]}),
                call(2, "get_anomalies", {"start": _shift(start, -30), "end": window_end, "cell_id": None})]
    if n == 2:
        lookback = _shift(start, -120)
        return [call(1, "get_recent_deployments", {"before": end}),
                call(2, "get_security_events", {"start": lookback, "end": _clamp_span(lookback, end)}),
                call(3, "get_logs", {"service": "packet-gateway", "start": lookback,
                                     "end": _clamp_span(lookback, end)}),
                call(4, "get_call_statistics", {})]
    if n == 3:
        chosen = [m for m in BASELINE_ORDER if m in symptoms][:5]
        calls = [call(i + 1, "compare_baseline", {"metric": m, "start": start, "end": window_end,
                                                  "cell_id": None}) for i, m in enumerate(chosen)]
        first_metric = ctx["symptoms"][0]["metric"]
        calls.append(call(len(calls) + 1, "get_metric_history", {
            "metric": first_metric, "cell_id": cell, "start": _shift(start, -60),
            "end": _clamp_span(_shift(start, -60), _shift(start, 120))}))
        return calls
    return []


def _answer(t: _Transcript) -> dict[str, Any]:
    ctx = t.context
    cells = ctx["affected_cells"]
    start = ctx["start"]
    facts: list[dict[str, Any]] = []
    inferences: list[dict[str, Any]] = []

    related = t.ok("get_related_events")
    deployments = t.ok("get_recent_deployments")
    security = t.ok("get_security_events")
    logs = t.ok("get_logs")
    calls = t.ok("get_call_statistics")
    baselines = t.ok("compare_baseline")
    history = t.ok("get_metric_history")

    rel_id, _, rel = related[0] if related else ("", {}, {})
    timeline = rel.get("timeline", []) if rel else []
    first_symptom = next((e for e in timeline if e["type"] == "metric_anomaly"), None)
    if first_symptom:
        facts.append({"statement": f"First anomaly in the incident timeline: {first_symptom['description']} "
                                   f"at {first_symptom['t']}.", "tool_call_ids": [rel_id]})

    # Baseline comparisons -> facts
    rising: dict[str, str] = {}
    for call_id, args, res in baselines:
        cells_res = res["cells"]
        mean_base = sum(c["baseline_mean"] for c in cells_res) / len(cells_res)
        mean_win = sum(c["window_mean"] for c in cells_res) / len(cells_res)
        worst = max(cells_res, key=lambda c: abs(c["delta"]))
        facts.append({"statement": f"{args['metric']} on {len(cells_res)} affected cell(s): window mean "
                                   f"{mean_win:.2f} vs baseline {mean_base:.2f}; largest change on "
                                   f"{worst['cell_id']} ({worst['pct_change']}%).",
                      "tool_call_ids": [call_id]})
        rising[args["metric"]] = call_id

    # Deployments on the affected nodes before onset
    candidate = None
    dep_id = ""
    if deployments:
        dep_id, _, dep = deployments[0]
        nodes = set(dep["incident_nodes"])
        for d in dep["deployments"]:
            if d["node_id"] in nodes and d["deployed_at"] <= start and d["deployed_at"] >= _shift(start, -120):
                candidate = d
                break
        others = [d for d in dep["deployments"] if d["node_id"] not in nodes]
        if candidate:
            lead = (datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
                    - datetime.strptime(candidate["deployed_at"], "%Y-%m-%dT%H:%M:%SZ")).seconds // 60
            facts.append({"statement": f"{candidate['service']} {candidate['to_version']} was deployed to "
                                       f"{candidate['node_id']} at {candidate['deployed_at']}, {lead} min before "
                                       f"the first anomaly ({candidate['change_summary']}).",
                          "tool_call_ids": [dep_id]})
        if others:
            facts.append({"statement": f"Other deployments in the period targeted nodes outside the incident "
                                       f"({', '.join(sorted({d['node_id'] for d in others}))}).",
                          "tool_call_ids": [dep_id]})

    sec_id, _, sec = security[0] if security else ("", {}, {"count": 0, "by_target": {}})
    targeted = sum(v for k, v in sec.get("by_target", {}).items() if k in cells or k.startswith("pgw"))
    if security:
        facts.append({"statement": f"{sec['count']} security events in the window; {targeted} targeted the "
                                   f"affected cells or gateway nodes.", "tool_call_ids": [sec_id]})

    log_id, _, log = logs[0] if logs else ("", {}, {"entries": []})
    warnings = [e for e in log.get("entries", []) if e["level"] in ("warning", "error", "critical")]
    if logs and warnings:
        facts.append({"statement": f"{len(warnings)} warning/error entries from packet-gateway, first at "
                                   f"{warnings[0]['t']}: \"{warnings[0]['message']}\".",
                      "tool_call_ids": [log_id]})

    call_id, _, call_stats = calls[0] if calls else ("", {}, {})
    affected_calls = [c for c in call_stats.get("cells_by_drop_rate", []) if c["cell_id"] in cells]
    if affected_calls:
        avg_drop = sum(c["drop_rate"] for c in affected_calls) / len(affected_calls)
        facts.append({"statement": f"C call analysis: average drop rate {avg_drop * 100:.1f}% across affected "
                                   f"cells vs {call_stats['drop_rate'] * 100:.1f}% network-wide.",
                      "tool_call_ids": [call_id]})

    # Inferences
    if rel and len([e for e in timeline if e["type"] == "metric_anomaly"]) >= 2:
        order = [e["description"].split(" ")[0] for e in timeline if e["type"] == "metric_anomaly"][:4]
        inferences.append({"statement": "Symptom onsets follow the order " + " -> ".join(order)
                                        + ", consistent with a causal chain starting at the first symptom.",
                           "based_on": [rel_id]})
    if candidate:
        inferences.append({"statement": "The deployment preceded symptom onset on the same node; temporal "
                                        "precedence supports but does not prove causation.",
                           "based_on": [dep_id, rel_id] if rel_id else [dep_id]})
    if history:
        h_id, h_args, h = history[0]
        inferences.append({"statement": f"{h_args['metric']} on {h_args['cell_id']} moved from {h['first']['v']} "
                                        f"to {h['last']['v']} over the inspected window.", "based_on": [h_id]})

    # Hypotheses
    first_metric = ctx["symptoms"][0]["metric"] if ctx["symptoms"] else ""
    hypotheses: list[dict[str, Any]] = []
    if candidate:
        confidence = 0.55
        support = [dep_id]
        if first_metric in RESOURCE_METRICS:
            confidence += 0.1
            support += [rising[m] for m in RESOURCE_METRICS if m in rising]
        if warnings:
            confidence += 0.1
            support.append(log_id)
        contradicting = []
        if targeted >= 10:
            contradicting.append(sec_id)
        else:
            confidence += 0.05
        if rel and rel["correlation_hypotheses"] and rel["correlation_hypotheses"][0]["cause_type"] == "deployment_regression":
            confidence += 0.05
            support.append(rel_id)
        hypotheses.append({
            "cause_type": "deployment_regression",
            "description": f"Deployment of {candidate['service']} {candidate['to_version']} to {candidate['node_id']} "
                           f"introduced a regression ({'resource growth first' if first_metric in RESOURCE_METRICS else 'symptoms followed'}).",
            "confidence": round(min(confidence, 0.9), 2), "supporting_evidence": sorted(set(support)),
            "contradicting_evidence": contradicting,
            "assessment": "Deployment on the affected node preceded onset"
                          + ("; resource metrics degraded first" if first_metric in RESOURCE_METRICS else "")
                          + ("; application logs report GC pressure/backlog" if warnings else "")
                          + ("; no attack traffic against the affected elements" if targeted < 10 else "")
                          + ". Confirmable by rolling back and checking recovery."})
    if security:
        attack = targeted >= 10
        hypotheses.append({
            "cause_type": "security_attack",
            "description": "Volumetric attack against the affected elements.",
            "confidence": 0.75 if attack and first_metric in ("active_users", "cpu_utilization") else
                          (0.6 if attack else 0.05),
            "supporting_evidence": [sec_id] if attack else [],
            "contradicting_evidence": [] if attack else [sec_id],
            "assessment": f"{targeted} security events targeted the affected elements"
                          + ("." if attack else "; too few to explain the degradation.")})
    for ev in timeline:
        if ev["type"] == "config_change":
            hypotheses.append({"cause_type": "configuration_change", "description": ev["description"],
                               "confidence": 0.7, "supporting_evidence": [rel_id], "contradicting_evidence": [],
                               "assessment": "Configuration change on an affected element preceded "
                                             "handover/setup degradation."})
            break
    for c in rel.get("correlation_hypotheses", []) if rel else []:
        if c["cause_type"] in ("memory_exhaustion", "traffic_overload", "radio_degradation", "transport_fault"):
            explained_by_deployment = candidate is not None and c["cause_type"] == "memory_exhaustion"
            hypotheses.append({
                "cause_type": c["cause_type"], "description": c["description"],
                "confidence": round(min(0.6, c["score"] * (0.5 if explained_by_deployment else 0.85)), 2),
                "supporting_evidence": [rel_id], "contradicting_evidence": [dep_id] if explained_by_deployment else [],
                "assessment": ("Describes the mechanism, but the deployment is the more specific trigger."
                               if explained_by_deployment else
                               "Inferred from the symptom pattern; no triggering event was found.")})
    if not hypotheses:
        hypotheses.append({"cause_type": "unknown", "description": "No hypothesis is supported by the evidence.",
                           "confidence": 0.1, "supporting_evidence": [rel_id] if rel_id else [],
                           "contradicting_evidence": [], "assessment": "Insufficient evidence."})
    hypotheses.sort(key=lambda h: (-h["confidence"], h["cause_type"]))
    top = hypotheses[0]

    actions, verification = _remediation(top["cause_type"], candidate, cells)
    impact = (f"{len(cells)} cell(s) affected ({', '.join(cells)})"
              + (f"; average call drop rate {sum(c['drop_rate'] for c in affected_calls) / len(affected_calls) * 100:.1f}% "
                 f"on affected cells" if affected_calls else "")
              + f"; severity {ctx['severity']}.")
    return {"root_cause": top["description"], "root_cause_type": top["cause_type"],
            "confidence": top["confidence"], "impact": impact, "facts": facts or [
                {"statement": "Incident context retrieved.", "tool_call_ids": [rel_id]}],
            "inferences": inferences, "hypotheses": hypotheses, "recommended_actions": actions,
            "verification_steps": verification}


def _remediation(cause: str, deployment: dict[str, Any] | None,
                 cells: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    monitor = {"priority": 3, "action": "Monitor latency, packet loss and call-drop rate on the affected cells",
               "rationale": "Confirms whether the remediation restores the baseline.",
               "risk_class": "READ_ONLY", "agent_tool": "inspect_metrics"}
    if cause == "deployment_regression" and deployment:
        return ([{"priority": 1, "action": f"Roll back {deployment['service']} on {deployment['node_id']} from "
                                           f"{deployment['to_version']} to {deployment['from_version']}",
                  "rationale": "Removes the suspected regression; recovery after rollback is the strongest "
                               "available test of this hypothesis.",
                  "risk_class": "HIGH_RISK", "agent_tool": "rollback_deployment"},
                 {"priority": 2, "action": "Open a fix for the regression and add a memory-growth regression test",
                  "rationale": "Prevents redeploying the same defect.", "risk_class": "LOW_RISK",
                  "agent_tool": "create_incident"},
                 monitor],
                ["memory_utilization returns below 70% within 10 minutes of rollback",
                 "cpu_utilization and latency_ms return to their pre-deployment baselines",
                 f"call_drop_rate on {', '.join(cells)} returns below 1%",
                 "no new anomalies on the affected cells for 30 minutes"])
    if cause == "security_attack":
        return ([{"priority": 1, "action": "Apply rate limiting / blocklist for the attacking sources",
                  "rationale": "Reduces attack traffic reaching the gateway.", "risk_class": "REQUIRES_APPROVAL",
                  "agent_tool": None}, monitor],
                ["security event rate falls to background level", "active_users and CPU return to baseline"])
    if cause == "configuration_change":
        return ([{"priority": 1, "action": "Revert the most recent neighbour/handover configuration change",
                  "rationale": "Handover and setup failures began with the change.",
                  "risk_class": "REQUIRES_APPROVAL", "agent_tool": None}, monitor],
                ["handover_failure_rate returns below 2%", "call_setup_success_rate returns above 99%"])
    return ([{"priority": 1, "action": "Dispatch field/transport engineering to inspect the affected cells",
              "rationale": "No software trigger was identified.", "risk_class": "READ_ONLY",
              "agent_tool": None}, monitor],
            ["affected KPIs return to baseline", "no new anomalies for 30 minutes"])


def next_turn(messages: list[Message]) -> tuple[str, list[ToolCall]]:
    """Returns (text, tool_calls): more tool calls, or the final JSON answer."""
    transcript = _Transcript(messages)
    calls = _plan(transcript)
    if calls:
        return "", calls
    return json.dumps(_answer(transcript)), []
