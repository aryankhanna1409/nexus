// Types mirror the backend's Pydantic response models (backend/app/schemas, app/api/*).

export type Severity = "low" | "medium" | "high" | "critical";
export type IncidentSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type RiskClass = "READ_ONLY" | "LOW_RISK" | "REQUIRES_APPROVAL" | "HIGH_RISK" | "BLOCKED";

export interface Health {
  status: "ok" | "degraded";
  version: string;
  database: string;
  call_analyzer: string;
  llm_provider: string;
}

export interface KpiSummary {
  metric: string;
  unit: string;
  current: number;
  baseline: number;
  bad_direction: "up" | "down" | "both";
}

export interface CellStatus {
  cell_id: string;
  node_id: string;
  status: "ok" | "degraded";
  open_anomalies: string[];
}

export interface NetworkOverview {
  run_id: number;
  data_start: string;
  data_end: string;
  health_score: number;
  health_breakdown: { reason: string; penalty: number }[];
  active_incidents: number;
  anomaly_count: number;
  kpis: KpiSummary[];
  cells: CellStatus[];
}

export interface MetricSeries {
  cell_id: string;
  node_id: string;
  epochs: number[];
  values: number[];
}

export interface MetricsResponse {
  run_id: number;
  metric: string;
  series: MetricSeries[];
}

export interface Anomaly {
  anomaly_id: string;
  metric: string;
  cell_id: string;
  node_id: string;
  start_epoch: number;
  end_epoch: number;
  timestamp: string;
  value: number;
  baseline: number;
  severity: Severity;
  anomaly_score: number;
  detectors: string[];
  related_metrics: string[];
}

export interface IncidentEvent {
  epoch: number;
  timestamp: string;
  type: string;
  description: string;
  reference_id: string | null;
  actor: string;
}

export interface SuspectedCause {
  cause_type: string;
  description: string;
  score: number;
  evidence: string[];
  rationale: string;
  status: "hypothesis";
}

export interface Symptom {
  metric: string;
  cells: string[];
  onset: string;
  worst_value: number;
  baseline: number;
  severity: Severity;
}

export interface IncidentSummary {
  incident_id: string;
  severity: IncidentSeverity;
  status: "open" | "investigating" | "mitigated" | "resolved";
  start_epoch: number;
  end_epoch: number;
  start_time: string;
  confidence: number;
  top_cause_type: string | null;
  affected_cells: string[];
}

export interface Incident extends IncidentSummary {
  run_id: number;
  chain_consistency: number;
  resolved_epoch: number | null;
  affected_nodes: string[];
  symptoms: Symptom[];
  suspected_causes: SuspectedCause[];
  excluded_candidates: { description: string; reason: string }[];
  caveats: string[];
  events: IncidentEvent[];
}

export interface Fact {
  statement: string;
  tool_call_ids: string[];
}

export interface Hypothesis {
  cause_type: string;
  description: string;
  confidence: number;
  supporting_evidence: string[];
  contradicting_evidence: string[];
  assessment: string;
}

export interface Recommendation {
  priority: number;
  action: string;
  rationale: string;
  risk_class: RiskClass;
  agent_tool: string | null;
}

export interface RootCauseAnalysis {
  id: number;
  incident_id: string;
  status: "completed" | "failed";
  provider: string;
  model: string;
  root_cause: string;
  confidence: number;
  impact: string;
  facts: Fact[];
  inferences: { statement: string; based_on: string[] }[];
  hypotheses: Hypothesis[];
  alternative_hypotheses: Hypothesis[];
  verification_steps: string[];
  recommended_actions: Recommendation[];
  tool_calls: { id: string; tool: string; ok: boolean; error: string | null }[];
  explanation: {
    observed_evidence: Fact[];
    correlated_events: { epoch: number; type: string; description: string }[];
    candidate_hypotheses: { cause_type: string; confidence: number }[];
    hypothesis_evaluation: { cause_type: string; assessment: string }[];
    most_likely_root_cause: string;
    confidence: number;
    recommended_remediation: string[];
  };
  provider_fallback_reason?: string | null;
}

export interface ReportSummary {
  report_id: string;
  incident_id: string;
  created_at: string;
  created_by: string;
  formats: string[];
}

export interface AgentAction {
  action_id: string;
  run_id: string;
  sequence: number;
  phase: string;
  tool: string;
  risk_class: RiskClass;
  status: string;
  rationale: string;
  approved_by: string | null;
  executed_by: string | null;
  arguments: Record<string, unknown>;
  result: Record<string, unknown>;
}

export interface AgentRun {
  run_id: string;
  scenario: string;
  state: string;
  status: string;
  incident_id: string | null;
  started_at: string;
  finished_at: string | null;
  started_by: string;
  actions: AgentAction[];
}

export interface AgentStatus {
  runs_by_status: Record<string, number>;
  pending_approvals: number;
  latest_run: string | null;
  scenarios: string[];
  policy: { allow_high_risk: boolean; tools: Record<string, RiskClass> };
  llm_provider: string;
}

export interface CallStatistics {
  total_calls: number;
  success_rate: number;
  drop_rate: number;
  setup_failure_rate: number;
  average_duration: number;
  cells: { cell_id: string; total_calls: number; drop_rate: number; setup_failure_rate: number;
            average_signal: number; average_packet_loss: number }[];
  failure_codes: { status_code: number; outcome: string; count: number; share: number }[];
  suspicious_time_windows: { window_start: string; reasons: string[]; severity: string; total_calls: number }[];
}

export interface CallAnomaly {
  type: string;
  category: string;
  severity: Severity;
  subject: string;
  description: string;
  anomaly_score: number;
}

export interface SecurityFinding {
  finding_id: string;
  source: string;
  category: string;
  severity: string;
  title: string;
  resource: string;
  status: string;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  actor: string;
  role: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: string;
  request_id: string | null;
  hash: string;
}

export interface Page<T> {
  total: number;
  limit: number;
  offset: number;
  items: T[];
}
