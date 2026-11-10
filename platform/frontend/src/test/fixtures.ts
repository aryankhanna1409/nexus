import type { AgentAction, IncidentEvent, IncidentSummary, NetworkOverview, RootCauseAnalysis } from "../types/api";

export const overview: NetworkOverview = {
  run_id: 1, data_start: "2026-03-01T12:00:00Z", data_end: "2026-03-01T17:59:00Z", health_score: 62,
  health_breakdown: [{ reason: "CRITICAL incident INC-2026-001", penalty: 30 }, { reason: "4 cells with open anomalies", penalty: 8 }],
  active_incidents: 1, anomaly_count: 36,
  kpis: [
    { metric: "latency_ms", unit: "ms", current: 300, baseline: 22, bad_direction: "up" },
    { metric: "throughput_mbps", unit: "Mbit/s", current: 400, baseline: 410, bad_direction: "down" },
    { metric: "call_drop_rate", unit: "%", current: 8.6, baseline: 0.8, bad_direction: "up" },
    { metric: "packet_loss_pct", unit: "%", current: 7.2, baseline: 0.3, bad_direction: "up" },
    { metric: "cpu_utilization", unit: "%", current: 92, baseline: 52, bad_direction: "up" },
  ],
  cells: [{ cell_id: "CELL-101", node_id: "pgw-1", status: "degraded", open_anomalies: ["latency_ms"] },
          { cell_id: "CELL-105", node_id: "pgw-2", status: "ok", open_anomalies: [] }],
};

export const incident: IncidentSummary = {
  incident_id: "INC-2026-001", severity: "CRITICAL", status: "investigating", start_epoch: 1772374380,
  end_epoch: 1772387940, start_time: "2026-03-01T14:13:00Z", confidence: 0.89,
  top_cause_type: "deployment_regression", affected_cells: ["CELL-101", "CELL-102"],
};

export const events: IncidentEvent[] = [
  { epoch: 300, timestamp: "2026-03-01T14:31:00Z", type: "metric_anomaly", description: "cpu anomaly", reference_id: null, actor: "telemetry" },
  { epoch: 100, timestamp: "2026-03-01T14:05:00Z", type: "deployment", description: "Deployed 2.4.1", reference_id: null, actor: "telemetry" },
  { epoch: 200, timestamp: "2026-03-01T14:13:00Z", type: "metric_anomaly", description: "memory anomaly", reference_id: null, actor: "telemetry" },
];

export const rca: RootCauseAnalysis = {
  id: 1, incident_id: "INC-2026-001", status: "completed", provider: "mock", model: "mock-deterministic-v1",
  root_cause: "Deployment of packet-gateway 2.4.1 to pgw-1 introduced a regression", confidence: 0.85,
  impact: "4 cells", facts: [], inferences: [], hypotheses: [], alternative_hypotheses: [], verification_steps: [],
  recommended_actions: [{ priority: 1, action: "Roll back packet-gateway", rationale: "r", risk_class: "HIGH_RISK", agent_tool: "rollback_deployment" }],
  tool_calls: [],
  explanation: {
    observed_evidence: [{ statement: "Deployed 2.4.1 at 14:05", tool_call_ids: ["mock-2-1"] }],
    correlated_events: [{ epoch: 100, type: "deployment", description: "Deployed 2.4.1" }],
    candidate_hypotheses: [{ cause_type: "deployment_regression", confidence: 0.85 }, { cause_type: "security_attack", confidence: 0.05 }],
    hypothesis_evaluation: [{ cause_type: "deployment_regression", assessment: "preceded onset" }, { cause_type: "security_attack", assessment: "no attack traffic" }],
    most_likely_root_cause: "Deployment of packet-gateway 2.4.1 to pgw-1 introduced a regression", confidence: 0.85,
    recommended_remediation: ["Roll back packet-gateway"],
  },
};

export function action(overrides: Partial<AgentAction>): AgentAction {
  return { action_id: "ACT-0001abcdef-01", run_id: "AGR-0001abcdef", sequence: 1, phase: "OBSERVE", tool: "run_unit_tests",
           risk_class: "READ_ONLY", status: "succeeded", rationale: "why", approved_by: null, executed_by: null,
           arguments: {}, result: {}, ...overrides };
}

/** Routes fetch calls to canned JSON by URL prefix. */
export function mockFetch(routes: Record<string, unknown>, status: Record<string, number> = {}) {
  return vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
    const url = String(input);
    const key = Object.keys(routes).sort((a, b) => b.length - a.length).find((k) => url.startsWith(k));
    const code = key && status[key] ? status[key] : key ? 200 : 404;
    const body = key ? routes[key] : { detail: "not found" };
    return new Response(JSON.stringify(body), { status: code, headers: { "content-type": "application/json" } });
  });
}
