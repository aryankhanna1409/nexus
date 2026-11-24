import { Link } from "react-router-dom";
import { ErrorMessage, Loading, Panel, SeverityBadge, pct } from "../components/common";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function IncidentsPage() {
  const rows = useApi(() => api.incidents());
  return (
    <Panel title="Incidents">
      {rows.error ? <ErrorMessage error={rows.error} /> : !rows.data ? <Loading /> : rows.data.length === 0
        ? <p className="text-noc-muted">No incidents.</p> : (
        <table className="data">
          <thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Start</th><th>Cells</th><th>Leading hypothesis</th><th>Confidence</th></tr></thead>
          <tbody>{rows.data.map((i) => (
            <tr key={i.incident_id}>
              <td><Link className="text-sky-300 hover:underline" to={`/incidents/${i.incident_id}`}>{i.incident_id}</Link></td>
              <td><SeverityBadge severity={i.severity} /></td><td>{i.status}</td><td>{i.start_time}</td>
              <td>{i.affected_cells.join(", ")}</td><td>{i.top_cause_type ?? "—"}</td><td>{pct(i.confidence, 0)}</td>
            </tr>))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
