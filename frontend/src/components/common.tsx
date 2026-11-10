import type { ReactNode } from "react";

const SEVERITY_CLASSES: Record<string, string> = {
  critical: "bg-sev-critical text-black", high: "bg-sev-high text-black",
  medium: "bg-sev-medium text-black", low: "bg-sev-low text-black", ok: "bg-sev-ok text-black",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toLowerCase();
  return (
    <span data-testid="severity-badge"
          className={`inline-block rounded-full px-2 py-0.5 text-xs font-bold uppercase ${SEVERITY_CLASSES[key] ?? "bg-noc-line"}`}>
      {severity}
    </span>
  );
}

export function StatusDot({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span aria-hidden className={`h-2.5 w-2.5 rounded-full ${ok ? "bg-sev-ok" : "bg-sev-critical"}`} />
      {label}
    </span>
  );
}

export function Panel({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="panel">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="label">{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function Loading() {
  return <p className="text-noc-muted" role="status">Loading…</p>;
}

export function ErrorMessage({ error }: { error: Error }) {
  return <p role="alert" className="text-sev-critical">Error: {error.message}</p>;
}

export function pct(value: number | null | undefined, digits = 1): string {
  return value === null || value === undefined ? "n/a" : `${(value * 100).toFixed(digits)}%`;
}

export function fmt(value: number, digits = 2): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(digits);
}
