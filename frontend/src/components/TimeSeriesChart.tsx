import { CartesianGrid, Legend, Line, LineChart, ReferenceArea, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Anomaly, MetricSeries } from "../types/api";

const COLOURS = ["#5dade2", "#ff9f43", "#2ecc71", "#c39bd3", "#f7d046", "#ff5d5d", "#48c9b0", "#eb984e"];

function hhmm(epoch: number): string {
  return new Date(epoch * 1000).toISOString().slice(11, 16);
}

/** Overlays several cells' series; anomaly episodes are shaded as reference areas. */
export function TimeSeriesChart({ series, anomalies = [], height = 260 }:
  { series: MetricSeries[]; anomalies?: Anomaly[]; height?: number }) {
  if (series.length === 0) return <p className="text-noc-muted">No data.</p>;
  const rows = series[0].epochs.map((epoch, i) => {
    const row: Record<string, number> = { epoch };
    for (const s of series) row[s.cell_id] = s.values[i];
    return row;
  });
  return (
    <div data-testid="timeseries-chart" style={{ width: "100%", height }}>
      <ResponsiveContainer>
        <LineChart data={rows} margin={{ top: 8, right: 16, bottom: 0, left: 0 }}>
          <CartesianGrid stroke="#1f2d3b" />
          <XAxis dataKey="epoch" tickFormatter={hhmm} stroke="#8aa0b5" fontSize={11} minTickGap={40} />
          <YAxis stroke="#8aa0b5" fontSize={11} width={50} />
          <Tooltip labelFormatter={(v) => hhmm(Number(v))} formatter={(v) => (typeof v === "number" ? v.toFixed(2) : v)}
                   contentStyle={{ background: "#111a24", border: "1px solid #1f2d3b" }} />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          {anomalies.map((a) => (
            <ReferenceArea key={a.anomaly_id} x1={a.start_epoch} x2={a.end_epoch}
                           fill={a.severity === "critical" ? "#ff5d5d" : "#ff9f43"} fillOpacity={0.08} />
          ))}
          {series.map((s, i) => (
            <Line key={s.cell_id} type="monotone" dataKey={s.cell_id} dot={false} strokeWidth={1.5}
                  stroke={COLOURS[i % COLOURS.length]} isAnimationActive={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
