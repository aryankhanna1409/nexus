import type { RootCauseAnalysis } from "../types/api";
import { pct } from "./common";

/** Spec §26 explainability chain: evidence → events → hypotheses → evaluation → cause → confidence → remediation. */
export function RcaPanel({ rca }: { rca: RootCauseAnalysis }) {
  const e = rca.explanation;
  return (
    <div className="space-y-4" data-testid="rca-panel">
      <div>
        <div className="label">Most likely root cause (hypothesis, not a confirmed fact)</div>
        <p className="mt-1 text-lg font-semibold">{e.most_likely_root_cause}</p>
        <p className="text-sm text-noc-muted">
          Confidence <strong className="text-noc-text">{pct(e.confidence, 0)}</strong> · {rca.provider}/{rca.model}
          {rca.status === "failed" && <span className="ml-2 text-sev-critical">investigation failed</span>}
        </p>
      </div>
      <Step title="1. Observed evidence">
        <ul className="list-disc space-y-1 pl-5 text-sm">
          {e.observed_evidence.map((f, i) => (
            <li key={i}>{f.statement} <span className="text-xs text-noc-muted">[{f.tool_call_ids.join(", ")}]</span></li>
          ))}
        </ul>
      </Step>
      <Step title="2. Correlated events">
        <ul className="list-disc pl-5 text-sm">{e.correlated_events.slice(0, 8).map((ev, i) => <li key={i}>{ev.description}</li>)}</ul>
      </Step>
      <Step title="3–4. Candidate hypotheses and evaluation">
        <table className="data">
          <thead><tr><th>Hypothesis</th><th>Confidence</th><th>Assessment</th></tr></thead>
          <tbody>
            {e.candidate_hypotheses.map((h, i) => (
              <tr key={h.cause_type}>
                <td>{h.cause_type}</td><td>{pct(h.confidence, 0)}</td>
                <td>{e.hypothesis_evaluation[i]?.assessment}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Step>
      <Step title="5. Recommended remediation">
        <ol className="list-decimal space-y-1 pl-5 text-sm">
          {rca.recommended_actions.map((a) => (
            <li key={a.priority}>{a.action} <span className="text-xs text-noc-muted">({a.risk_class})</span></li>
          ))}
        </ol>
      </Step>
    </div>
  );
}

function Step({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="label mb-1">{title}</div>
      {children}
    </div>
  );
}
