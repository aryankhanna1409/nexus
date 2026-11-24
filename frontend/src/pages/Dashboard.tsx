import { Link } from "react-router-dom";
import { ErrorMessage, Loading, Panel, SeverityBadge, pct } from "../components/common";
import { KpiCard } from "../components/KpiCard";
import { TimeSeriesChart } from "../components/TimeSeriesChart";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { RootCauseAnalysis } from "../types/api";

const HEADLINE_KPIS = ["call_drop_rate", "latency_ms", "packet_loss_pct", "throughput_mbps", "cpu_utilization"];

/** Answers: healthy? what is broken? how severe? why? what is the AI doing? did remediation work? */
export function DashboardPage() {
  const overview = useApi(() => api.overview());
  const incidents = useApi(() => api.incidents());
  const agent = useApi(() => api.agentRuns());
  const top = incidents.data?.find((i) => i.status !== "resolved") ?? incidents.data?.[0];
  const rca = useApi<RootCauseAnalysis | null>(
    () => (top ? api.rca(top.incident_id).catch(() => null) : Promise.resolve(null)), [top?.incident_id]);
  const latency = useApi(() => api.metrics("latency_ms"), []);
  const anomalies = useApi(() => api.anomalies({ metric: "latency_ms" }), []);

  if (overview.error) return <ErrorMessage error={overview.error} />;
  if (!overview.data) return <Loading />;
  const o = overview.data;
  const affected = new Set(top?.affected_cells ?? []);
  const latestRun = agent.data?.[0];
  const verification = latestRun?.actions.filter((a) => a.tool === "inspect_metrics" && a.arguments.run_id).at(-1);

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <Panel title="Is the network healthy?">
          <div className={`text-5xl font-bold ${o.health_score >= 80 ? "text-sev-ok" : o.health_score >= 50 ? "text-sev-medium" : "text-sev-critical"}`}
               data-testid="health-score">{o.health_score}</div>
          <p className="text-sm text-noc-muted">health score / 100 · {o.active_incidents} active incident(s) · {o.anomaly_count} anomalies</p>
          <ul className="mt-2 text-xs text-noc-muted">{o.health_breakdown.map((b, i) => <li key={i}>−{b.penalty}: {b.reason}</li>)}</ul>
        </Panel>
        <Panel title="What is broken? How severe?">
          {top ? (
            <div>
              <Link to={`/incidents/${top.incident_id}`} className="text-lg font-semibold text-sky-300 hover:underline">{top.incident_id}</Link>{" "}
              <SeverityBadge severity={top.severity} />
              <p className="mt-1 text-sm">Cells: {top.affected_cells.join(", ")}</p>
              <p className="text-sm text-noc-muted">since {top.start_time} · status {top.status}</p>
            </div>
          ) : <p className="text-sev-ok">No incidents.</p>}
        </Panel>
        <Panel title="Why is it broken?">
          {rca.data ? (
            <div>
              <p className="text-sm">{rca.data.root_cause}</p>
              <p className="mt-1 text-xs text-noc-muted">RCA confidence {pct(rca.data.confidence, 0)} · leading hypothesis, not a confirmed fact</p>
            </div>
          ) : top ? (
            <p className="text-sm text-noc-muted">No RCA yet. Correlation suggests: {top.top_cause_type ?? "unknown"} ({pct(top.confidence, 0)}).</p>
          ) : <p className="text-sm text-noc-muted">—</p>}
        </Panel>
      </div>

      <div className="grid gap-4 md:grid-cols-5">
        {HEADLINE_KPIS.map((m) => o.kpis.find((k) => k.metric === m)).filter(Boolean).map((k) => <KpiCard key={k!.metric} kpi={k!} />)}
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="md:col-span-2">
          <Panel title="Latency on affected cells (shaded: detected anomalies)">
            {latency.data ? (
              <TimeSeriesChart series={latency.data.series.filter((s) => affected.size === 0 || affected.has(s.cell_id))}
                               anomalies={(anomalies.data ?? []).filter((a) => affected.has(a.cell_id))} />
            ) : <Loading />}
          </Panel>
        </div>
        <div className="space-y-4">
          <Panel title="What is the AI doing?">
            {latestRun ? (
              <div className="text-sm">
                <p>Agent run <span className="font-mono">{latestRun.run_id}</span> ({latestRun.scenario})</p>
                <p className="text-noc-muted">state {latestRun.state} · {latestRun.status.replace(/_/g, " ")}</p>
                <ul className="mt-2 text-xs">
                  {latestRun.actions.slice(-4).map((a) => <li key={a.action_id}>{a.tool} — {a.status.replace(/_/g, " ")}</li>)}
                </ul>
                <Link to="/agent" className="text-xs text-sky-300 hover:underline">Open agent console</Link>
              </div>
            ) : <p className="text-sm text-noc-muted">No agent runs yet.</p>}
          </Panel>
          <Panel title="Has the remediation worked?">
            {verification ? (
              <p className={verification.result.recovered ? "text-sev-ok" : "text-sev-critical"} data-testid="remediation-status">
                {verification.result.recovered ? "Yes — KPIs back within baseline tolerance" : "Not yet — KPIs still deviate from baseline"}
              </p>
            ) : <p className="text-sm text-noc-muted" data-testid="remediation-status">No remediation verified yet{top ? ` (incident ${top.status})` : ""}.</p>}
          </Panel>
        </div>
      </div>

      <Panel title="Cells">
        <div className="flex flex-wrap gap-2">
          {o.cells.map((c) => (
            <span key={c.cell_id} title={c.open_anomalies.join(", ")}
                  className={`rounded px-2 py-1 text-xs ${c.status === "ok" ? "bg-noc-line" : "bg-sev-critical text-black"}`}>
              {c.cell_id}
            </span>
          ))}
        </div>
      </Panel>
    </div>
  );
}
