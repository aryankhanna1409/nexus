import type { AgentAction } from "../types/api";

const STATUS_COLOURS: Record<string, string> = {
  succeeded: "text-sev-ok", failed: "text-sev-critical", blocked: "text-sev-critical",
  awaiting_approval: "text-sev-medium", approved: "text-sky-300", denied: "text-noc-muted",
};

/** Agent actions with rationale, risk class and approve/deny/execute controls (server enforces policy). */
export function AgentActionPanel({ actions, onApprove, onDeny, onExecute, busy }: {
  actions: AgentAction[];
  onApprove: (a: AgentAction) => void;
  onDeny: (a: AgentAction) => void;
  onExecute: (a: AgentAction) => void;
  busy: boolean;
}) {
  return (
    <table className="data" data-testid="agent-actions">
      <thead><tr><th>#</th><th>Phase</th><th>Tool</th><th>Risk</th><th>Status</th><th>Rationale</th><th /></tr></thead>
      <tbody>
        {actions.map((a) => (
          <tr key={a.action_id}>
            <td>{a.sequence}</td>
            <td>{a.phase}</td>
            <td className="font-mono text-xs">{a.tool}</td>
            <td className="text-xs">{a.risk_class}</td>
            <td className={STATUS_COLOURS[a.status] ?? ""}>{a.status.replace(/_/g, " ")}</td>
            <td className="max-w-md text-xs">{a.rationale}</td>
            <td className="whitespace-nowrap">
              {a.status === "awaiting_approval" && (
                <>
                  <button className="btn-primary mr-1" disabled={busy} onClick={() => onApprove(a)}>Approve</button>
                  <button className="btn-ghost" disabled={busy} onClick={() => onDeny(a)}>Deny</button>
                </>
              )}
              {a.status === "approved" && (
                <button className={a.risk_class === "HIGH_RISK" ? "btn-danger" : "btn-primary"} disabled={busy}
                        onClick={() => onExecute(a)}>Execute</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
