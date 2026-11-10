import { useState } from "react";
import { ErrorMessage, Loading, Panel } from "../components/common";
import { RcaPanel } from "../components/RcaPanel";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { RootCauseAnalysis } from "../types/api";

export function RcaPage() {
  const incidents = useApi(() => api.incidents());
  const [selected, setSelected] = useState<string>("");
  const id = selected || incidents.data?.[0]?.incident_id || "";
  const rca = useApi<RootCauseAnalysis | null>(() => (id ? api.rca(id).catch(() => null) : Promise.resolve(null)), [id]);
  if (incidents.error) return <ErrorMessage error={incidents.error} />;
  if (!incidents.data) return <Loading />;
  return (
    <Panel title="Root cause analysis" actions={
      <select aria-label="Incident" value={id} onChange={(e) => setSelected(e.target.value)}
              className="rounded border border-noc-line bg-noc-bg px-2 py-1 text-sm">
        {incidents.data.map((i) => <option key={i.incident_id}>{i.incident_id}</option>)}
      </select>}>
      {rca.loading ? <Loading /> : rca.data ? (
        <div className="space-y-4">
          <RcaPanel rca={rca.data} />
          <div>
            <div className="label mb-1">Tool calls (read-only, allowlisted)</div>
            <ul className="text-xs">{rca.data.tool_calls.map((t) => <li key={t.id} className={t.ok ? "" : "text-sev-critical"}>{t.id} {t.tool} {t.ok ? "ok" : `error: ${t.error}`}</li>)}</ul>
          </div>
        </div>
      ) : <p className="text-sm text-noc-muted">No RCA for {id || "this incident"} yet.</p>}
    </Panel>
  );
}
