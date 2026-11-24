import { useState } from "react";
import { ErrorMessage, Loading, Panel } from "../components/common";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

export function AuditPage() {
  const page = useApi(() => api.audit(200));
  const [verdict, setVerdict] = useState<string | null>(null);
  async function verify() {
    try {
      const v = await api.verifyAudit();
      setVerdict(v.valid ? `Hash chain valid (${v.rows} rows).` : `Hash chain INVALID: ${v.reason}`);
    } catch (err) {
      setVerdict(`Verification unavailable: ${(err as Error).message}`);
    }
  }
  return (
    <Panel title="Audit log (append-only, hash-chained)" actions={<button className="btn-ghost" onClick={verify}>Verify chain</button>}>
      {verdict && <p role="status" className="mb-2 text-sm">{verdict}</p>}
      {page.error ? <ErrorMessage error={page.error} /> : !page.data ? <Loading /> : (
        <table className="data">
          <thead><tr><th>Time</th><th>Actor</th><th>Role</th><th>Action</th><th>Resource</th><th>Outcome</th><th>Request</th></tr></thead>
          <tbody>{page.data.items.map((e) => (
            <tr key={e.id}><td>{e.timestamp}</td><td>{e.actor}</td><td>{e.role}</td><td>{e.action}</td>
              <td className="text-xs">{e.resource_type} {e.resource_id}</td>
              <td className={e.outcome === "success" ? "" : "text-sev-critical"}>{e.outcome}</td>
              <td className="font-mono text-xs">{e.request_id?.slice(0, 8)}</td></tr>))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
