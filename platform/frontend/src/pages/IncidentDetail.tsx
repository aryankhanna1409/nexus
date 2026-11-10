import { useState } from "react";
import { useParams } from "react-router-dom";
import { ErrorMessage, Loading, Panel, SeverityBadge, fmt, pct } from "../components/common";
import { IncidentTimeline } from "../components/IncidentTimeline";
import { RcaPanel } from "../components/RcaPanel";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { RootCauseAnalysis } from "../types/api";

export function IncidentDetailPage() {
  const { incidentId = "" } = useParams();
  const incident = useApi(() => api.incident(incidentId), [incidentId]);
  const rca = useApi<RootCauseAnalysis | null>(() => api.rca(incidentId).catch(() => null), [incidentId]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function run(action: () => Promise<unknown>, done: string) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
      setMessage(done);
      incident.reload();
      rca.reload();
    } catch (err) {
      setMessage(`Failed: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  if (incident.error) return <ErrorMessage error={incident.error} />;
  if (!incident.data) return <Loading />;
  const i = incident.data;
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-bold">{i.incident_id}</h1><SeverityBadge severity={i.severity} />
        <span className="text-noc-muted">{i.status} · cells {i.affected_cells.join(", ")} · nodes {i.affected_nodes.join(", ")}</span>
        <div className="ml-auto flex gap-2">
          <button className="btn-primary" disabled={busy} onClick={() => run(() => api.investigate(i.incident_id), "RCA completed.")}>Run AI investigation</button>
          <button className="btn-ghost" disabled={busy} onClick={() => run(() => api.generateReport(i.incident_id), "Report generated (see AI Reports).")}>Generate report</button>
          <button className="btn-ghost" disabled={busy} onClick={() => run(() => api.startAgent("production_anomaly", i.incident_id), "Agent started (see DevSecOps Agent).")}>Start agent</button>
        </div>
      </div>
      {message && <p role="status" className="text-sm text-sky-300">{message}</p>}
      <div className="grid gap-4 md:grid-cols-3">
        <Panel title="Timeline"><IncidentTimeline events={i.events} /></Panel>
        <div className="space-y-4 md:col-span-2">
          <Panel title="Root cause analysis">
            {rca.data ? <RcaPanel rca={rca.data} /> : <p className="text-sm text-noc-muted">No RCA yet. Run the AI investigation.</p>}
          </Panel>
          <Panel title="Symptoms">
            <table className="data">
              <thead><tr><th>Metric</th><th>Onset</th><th>Baseline</th><th>Worst</th><th>Severity</th></tr></thead>
              <tbody>{i.symptoms.map((s) => (
                <tr key={s.metric}><td>{s.metric}</td><td>{s.onset}</td><td>{fmt(s.baseline)}</td><td>{fmt(s.worst_value)}</td><td><SeverityBadge severity={s.severity} /></td></tr>))}
              </tbody>
            </table>
          </Panel>
          <Panel title={`Correlation hypotheses (confidence ${pct(i.confidence, 0)}, chain consistency ${i.chain_consistency})`}>
            <ul className="space-y-1 text-sm">
              {i.suspected_causes.map((c) => <li key={c.cause_type}><strong>{c.cause_type}</strong> ({c.score}) — {c.rationale}</li>)}
              {i.excluded_candidates.map((e, n) => <li key={n} className="text-noc-muted">Excluded: {e.description} — {e.reason}</li>)}
            </ul>
            <ul className="mt-2 text-xs text-noc-muted">{i.caveats.map((c, n) => <li key={n}>⚠ {c}</li>)}</ul>
          </Panel>
        </div>
      </div>
    </div>
  );
}
