import { useState } from "react";
import { AgentActionPanel } from "../components/AgentActionPanel";
import { ErrorMessage, Loading, Panel } from "../components/common";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import type { AgentAction } from "../types/api";

export function AgentPage() {
  const status = useApi(() => api.agentStatus());
  const runs = useApi(() => api.agentRuns());
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  async function act(action: () => Promise<unknown>) {
    setBusy(true);
    setMessage(null);
    try { await action(); } catch (err) { setMessage((err as Error).message); } finally {
      setBusy(false);
      runs.reload();
      status.reload();
    }
  }

  return (
    <div className="space-y-4">
      <Panel title="DevSecOps agent" actions={
        <div className="flex gap-2">
          {status.data?.scenarios.map((s) => (
            <button key={s} className="btn-ghost" disabled={busy} onClick={() => act(() => api.startAgent(s))}>Run {s.replace(/_/g, " ")}</button>
          ))}
        </div>}>
        {status.data ? (
          <div className="text-sm">
            <p>Pending approvals: <strong>{status.data.pending_approvals}</strong> · HIGH_RISK actions {status.data.policy.allow_high_risk ? "enabled (approval + admin required)" : "disabled by policy"}</p>
            <details className="mt-2"><summary className="cursor-pointer text-noc-muted">Tool risk classes</summary>
              <ul className="mt-1 grid grid-cols-2 gap-x-6 text-xs">{Object.entries(status.data.policy.tools).map(([t, r]) => <li key={t}>{t}: {r}</li>)}</ul>
            </details>
          </div>
        ) : status.error ? <ErrorMessage error={status.error} /> : <Loading />}
        {message && <p role="alert" className="mt-2 text-sm text-sev-critical">{message}</p>}
      </Panel>
      {runs.data?.map((run) => (
        <Panel key={run.run_id} title={`${run.run_id} · ${run.scenario} · ${run.state} · ${run.status.replace(/_/g, " ")}`}>
          <AgentActionPanel actions={run.actions} busy={busy}
            onApprove={(a: AgentAction) => act(() => api.approve(a.action_id, "approve"))}
            onDeny={(a: AgentAction) => act(() => api.approve(a.action_id, "deny"))}
            onExecute={(a: AgentAction) => act(() => api.execute(a.action_id))} />
        </Panel>
      ))}
      {runs.data?.length === 0 && <p className="text-noc-muted">No agent runs yet.</p>}
    </div>
  );
}
