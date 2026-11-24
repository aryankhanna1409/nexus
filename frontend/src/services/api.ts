// Typed client for the Aegis-Net REST API. The bearer token is kept in sessionStorage only.

import type {
  AgentRun, AgentStatus, Anomaly, AuditEntry, CallAnomaly, CallStatistics, Health, Incident,
  IncidentSummary, MetricsResponse, NetworkOverview, Page, ReportSummary, RootCauseAnalysis, SecurityFinding,
} from "../types/api";

const TOKEN_KEY = "aegis.token";

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

export const tokenStore = {
  get: (): string | null => sessionStorage.getItem(TOKEN_KEY),
  set: (token: string): void => sessionStorage.setItem(TOKEN_KEY, token),
  clear: (): void => sessionStorage.removeItem(TOKEN_KEY),
};

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = tokenStore.get();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(response.status, detail);
  }
  const type = response.headers.get("content-type") ?? "";
  return (type.includes("application/json") ? response.json() : response.text()) as Promise<T>;
}

const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

const query = (params: Record<string, string | number | undefined | null>) => {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "");
  return entries.length ? `?${new URLSearchParams(entries.map(([k, v]) => [k, String(v)]))}` : "";
};

export const api = {
  health: () => request<Health>("/api/health"),
  overview: () => request<NetworkOverview>("/api/network/overview"),
  metrics: (metric: string, cellId?: string) => request<MetricsResponse>(`/api/network/metrics${query({ metric, cell_id: cellId })}`),
  anomalies: (filters: { cell_id?: string; metric?: string; severity?: string } = {}) =>
    request<Anomaly[]>(`/api/network/anomalies${query(filters)}`),
  callStatistics: () => request<CallStatistics>("/api/calls/statistics"),
  callAnomalies: () => request<CallAnomaly[]>("/api/calls/anomalies"),
  incidents: () => request<IncidentSummary[]>("/api/incidents"),
  incident: (id: string) => request<Incident>(`/api/incidents/${encodeURIComponent(id)}`),
  investigate: (id: string) => post<RootCauseAnalysis>(`/api/incidents/${encodeURIComponent(id)}/investigate`),
  rca: (id: string) => request<RootCauseAnalysis>(`/api/incidents/${encodeURIComponent(id)}/rca`),
  reports: (incidentId?: string) => request<ReportSummary[]>(`/api/reports${query({ incident_id: incidentId })}`),
  generateReport: (incidentId: string) => post<ReportSummary>("/api/reports/generate", { incident_id: incidentId }),
  reportHtml: (reportId: string) => request<string>(`/api/reports/${encodeURIComponent(reportId)}?format=html`),
  agentStatus: () => request<AgentStatus>("/api/agent/status"),
  agentRuns: () => request<AgentRun[]>("/api/agent/runs"),
  startAgent: (scenario: string, incidentId?: string) =>
    post<AgentRun>("/api/agent/investigate", incidentId ? { scenario, incident_id: incidentId } : { scenario }),
  approve: (actionId: string, decision: "approve" | "deny", comment = "") =>
    post<AgentRun>(`/api/agent/approve/${encodeURIComponent(actionId)}`, { decision, comment }),
  execute: (actionId: string) => post<AgentRun>(`/api/agent/execute/${encodeURIComponent(actionId)}`),
  findings: () => request<SecurityFinding[]>("/api/security/findings"),
  audit: (limit = 100) => request<Page<AuditEntry>>(`/api/audit${query({ limit })}`),
  verifyAudit: () => request<{ valid: boolean; rows: number; reason: string | null }>("/api/audit/verify"),
};
