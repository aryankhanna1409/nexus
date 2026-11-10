import { useState } from "react";
import { ErrorMessage, Loading, Panel } from "../components/common";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

/** Reports are rendered in a sandboxed iframe (no scripts) from the server's escaped HTML. */
export function ReportsPage() {
  const reports = useApi(() => api.reports());
  const [html, setHtml] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function open(id: string) {
    setError(null);
    try { setHtml(await api.reportHtml(id)); } catch (err) { setError((err as Error).message); }
  }
  return (
    <div className="grid gap-4 md:grid-cols-3">
      <Panel title="AI reports">
        {reports.error ? <ErrorMessage error={reports.error} /> : !reports.data ? <Loading /> : reports.data.length === 0
          ? <p className="text-sm text-noc-muted">No reports yet. Generate one from an incident.</p> : (
          <ul className="space-y-1 text-sm">{reports.data.map((r) => (
            <li key={r.report_id}><button className="text-sky-300 hover:underline" onClick={() => open(r.report_id)}>{r.report_id}</button>
              <span className="ml-2 text-xs text-noc-muted">{r.created_at} by {r.created_by}</span></li>))}
          </ul>
        )}
      </Panel>
      <div className="md:col-span-2">
        <Panel title="Report">
          {error && <p role="alert" className="text-sev-critical">{error}</p>}
          {html ? <iframe title="report" sandbox="" srcDoc={html} className="h-[70vh] w-full rounded bg-noc-bg" />
                : <p className="text-sm text-noc-muted">Select a report.</p>}
        </Panel>
      </div>
    </div>
  );
}
