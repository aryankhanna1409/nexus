import { ErrorMessage, Loading, Panel, SeverityBadge } from "../components/common";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function SecurityPage() {
  const findings = useApi(() => api.findings());
  return (
    <Panel title="Security findings (synthetic DEMO-CVE advisories)">
      {findings.error ? <ErrorMessage error={findings.error} /> : !findings.data ? <Loading /> : findings.data.length === 0
        ? <p className="text-sm text-noc-muted">No findings. Run the vulnerable-dependency agent scenario.</p> : (
        <table className="data">
          <thead><tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Source</th><th>Status</th></tr></thead>
          <tbody>{findings.data.map((f) => (
            <tr key={f.finding_id}><td><SeverityBadge severity={f.severity} /></td><td>{f.title}</td><td className="text-xs">{f.resource}</td><td>{f.source}</td><td>{f.status}</td></tr>))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
