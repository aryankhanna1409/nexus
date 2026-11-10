import type { IncidentEvent } from "../types/api";

const TYPE_COLOURS: Record<string, string> = {
  deployment: "bg-sky-500", rollback_executed: "bg-sev-ok", metric_anomaly: "bg-sev-high",
  incident_created: "bg-sev-critical", ai_investigation_started: "bg-purple-400",
  root_cause_identified: "bg-purple-300", incident_resolved: "bg-sev-ok", agent_opened: "bg-slate-400",
};

/** Vertical incident timeline (spec §14); entries are ordered by time. */
export function IncidentTimeline({ events }: { events: IncidentEvent[] }) {
  const ordered = [...events].sort((a, b) => a.epoch - b.epoch);
  return (
    <ol className="relative border-l border-noc-line pl-5" data-testid="incident-timeline">
      {ordered.map((e, i) => (
        <li key={`${e.epoch}-${i}`} className="mb-3">
          <span className={`absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full ${TYPE_COLOURS[e.type] ?? "bg-noc-muted"}`} />
          <div className="text-xs text-noc-muted">{e.timestamp.replace("T", " ").replace("Z", " UTC")} · {e.type.replace(/_/g, " ")}</div>
          <div className="text-sm">{e.description}</div>
        </li>
      ))}
    </ol>
  );
}
