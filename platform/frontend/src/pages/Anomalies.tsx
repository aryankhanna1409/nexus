import { useState } from "react";
import { ErrorMessage, Loading, Panel, SeverityBadge, fmt } from "../components/common";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function AnomaliesPage() {
  const [severity, setSeverity] = useState("");
  const rows = useApi(() => api.anomalies({ severity: severity || undefined }), [severity]);
  return (
    <Panel title="Detected metric anomalies" actions={
      <select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}
              className="rounded border border-noc-line bg-noc-bg px-2 py-1 text-sm">
        <option value="">all severities</option>{["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
      </select>}>
      {rows.error ? <ErrorMessage error={rows.error} /> : !rows.data ? <Loading /> : (
        <table className="data">
          <thead><tr><th>Onset</th><th>Cell</th><th>Metric</th><th>Baseline</th><th>Worst</th><th>Severity</th><th>Score</th><th>Detectors</th><th>Related</th></tr></thead>
          <tbody>{rows.data.map((a) => (
            <tr key={a.anomaly_id}>
              <td>{a.timestamp}</td><td>{a.cell_id}</td><td>{a.metric}</td><td>{fmt(a.baseline)}</td><td>{fmt(a.value)}</td>
              <td><SeverityBadge severity={a.severity} /></td><td>{a.anomaly_score.toFixed(2)}</td>
              <td className="text-xs">{a.detectors.join(", ")}</td><td className="text-xs">{a.related_metrics.join(", ")}</td>
            </tr>))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
