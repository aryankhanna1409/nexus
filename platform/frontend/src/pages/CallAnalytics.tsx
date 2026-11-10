import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ErrorMessage, Loading, Panel, SeverityBadge, pct } from "../components/common";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

/** Results computed by the C call-analysis library (libcallanalyzer). */
export function CallAnalyticsPage() {
  const stats = useApi(() => api.callStatistics());
  const anomalies = useApi(() => api.callAnomalies());
  if (stats.error) return <ErrorMessage error={stats.error} />;
  if (!stats.data) return <Loading />;
  const s = stats.data;
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-4">
        {[["Total calls", s.total_calls.toLocaleString()], ["Success rate", pct(s.success_rate)],
          ["Drop rate", pct(s.drop_rate)], ["Avg duration", `${s.average_duration.toFixed(0)} s`]].map(([label, value]) => (
          <div key={label} className="panel"><div className="label">{label}</div><div className="mt-1 text-2xl font-semibold">{value}</div></div>
        ))}
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Panel title="Drop rate by cell">
          <div style={{ width: "100%", height: 260 }} data-testid="cell-drop-chart">
            <ResponsiveContainer>
              <BarChart data={s.cells.map((c) => ({ cell: c.cell_id, drop: +(c.drop_rate * 100).toFixed(2) }))}>
                <CartesianGrid stroke="#1f2d3b" /><XAxis dataKey="cell" stroke="#8aa0b5" fontSize={10} />
                <YAxis stroke="#8aa0b5" fontSize={11} unit="%" /><Tooltip contentStyle={{ background: "#111a24" }} />
                <Bar dataKey="drop" fill="#ff9f43" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Status codes">
          <table className="data">
            <thead><tr><th>Code</th><th>Outcome</th><th>Calls</th><th>Share</th></tr></thead>
            <tbody>{s.failure_codes.map((c) => (
              <tr key={c.status_code}><td>{c.status_code}</td><td>{c.outcome}</td><td>{c.count}</td><td>{pct(c.share)}</td></tr>))}
            </tbody>
          </table>
        </Panel>
      </div>
      <Panel title="Call anomalies (C library)">
        {anomalies.data?.length ? (
          <table className="data">
            <thead><tr><th>Severity</th><th>Type</th><th>Subject</th><th>Description</th></tr></thead>
            <tbody>{anomalies.data.map((a, i) => (
              <tr key={i}><td><SeverityBadge severity={a.severity} /></td><td>{a.type}</td><td>{a.subject}</td><td>{a.description}</td></tr>))}
            </tbody>
          </table>
        ) : <p className="text-sm text-noc-muted">No call anomalies.</p>}
      </Panel>
    </div>
  );
}
