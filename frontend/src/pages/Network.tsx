import { useState } from "react";
import { ErrorMessage, Loading, Panel } from "../components/common";
import { KpiCard } from "../components/KpiCard";
import { TimeSeriesChart } from "../components/TimeSeriesChart";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";

const METRICS = ["latency_ms", "packet_loss_pct", "call_drop_rate", "throughput_mbps", "cpu_utilization",
  "memory_utilization", "jitter_ms", "sinr_db", "rsrp_dbm", "handover_failure_rate", "call_setup_success_rate",
  "active_users", "bandwidth_utilization", "retransmission_rate", "rssi_dbm", "rsrq_db", "handover_success_rate"];

export function NetworkPage() {
  const [metric, setMetric] = useState("latency_ms");
  const [cell, setCell] = useState("");
  const overview = useApi(() => api.overview());
  const series = useApi(() => api.metrics(metric, cell || undefined), [metric, cell]);
  const anomalies = useApi(() => api.anomalies({ metric, cell_id: cell || undefined }), [metric, cell]);
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-4">
        {overview.data?.kpis.map((k) => <KpiCard key={k.metric} kpi={k} />)}
      </div>
      <Panel title="KPI time series" actions={
        <div className="flex gap-2">
          <select aria-label="Metric" value={metric} onChange={(e) => setMetric(e.target.value)}
                  className="rounded border border-noc-line bg-noc-bg px-2 py-1 text-sm">
            {METRICS.map((m) => <option key={m}>{m}</option>)}
          </select>
          <select aria-label="Cell" value={cell} onChange={(e) => setCell(e.target.value)}
                  className="rounded border border-noc-line bg-noc-bg px-2 py-1 text-sm">
            <option value="">all cells</option>
            {overview.data?.cells.map((c) => <option key={c.cell_id}>{c.cell_id}</option>)}
          </select>
        </div>}>
        {series.error ? <ErrorMessage error={series.error} /> : series.data
          ? <TimeSeriesChart series={series.data.series} anomalies={anomalies.data ?? []} height={360} /> : <Loading />}
      </Panel>
    </div>
  );
}
