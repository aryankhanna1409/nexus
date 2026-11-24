import type { KpiSummary } from "../types/api";
import { fmt } from "./common";

/** Current value vs baseline; colour shows whether the change is in the bad direction. */
export function KpiCard({ kpi }: { kpi: KpiSummary }) {
  const delta = kpi.current - kpi.baseline;
  const relative = kpi.baseline !== 0 ? (delta / Math.abs(kpi.baseline)) * 100 : 0;
  const bad = kpi.bad_direction === "down" ? relative < -10 : kpi.bad_direction === "up" ? relative > 10 : Math.abs(relative) > 10;
  return (
    <div className="panel" data-testid={`kpi-${kpi.metric}`}>
      <div className="label">{kpi.metric.replace(/_/g, " ")}</div>
      <div className={`mt-1 text-2xl font-semibold ${bad ? "text-sev-critical" : "text-noc-text"}`}>
        {fmt(kpi.current)} <span className="text-sm text-noc-muted">{kpi.unit}</span>
      </div>
      <div className="text-xs text-noc-muted">
        all-cell mean, last 30 min · baseline {fmt(kpi.baseline)} · {relative >= 0 ? "+" : ""}{relative.toFixed(0)}%
      </div>
    </div>
  );
}
