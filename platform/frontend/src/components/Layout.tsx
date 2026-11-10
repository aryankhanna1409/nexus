import { NavLink, Outlet } from "react-router-dom";
import { api, tokenStore } from "../services/api";
import { useApi } from "../hooks/useApi";
import { StatusDot } from "./common";

const NAV = [
  ["/", "Dashboard"], ["/network", "Network Overview"], ["/calls", "Call Analytics"], ["/anomalies", "Anomalies"],
  ["/incidents", "Incidents"], ["/rca", "Root Cause Analysis"], ["/reports", "AI Reports"],
  ["/agent", "DevSecOps Agent"], ["/security", "Security"], ["/audit", "Audit Log"],
] as const;

export function Layout({ onLogout }: { onLogout: () => void }) {
  const health = useApi(() => api.health());
  return (
    <div className="flex min-h-screen">
      <nav className="w-56 shrink-0 border-r border-noc-line bg-noc-panel p-4" aria-label="Main">
        <div className="mb-6 text-lg font-bold tracking-wide">AEGIS<span className="text-sky-400">-NET</span></div>
        <ul className="space-y-1">
          {NAV.map(([to, label]) => (
            <li key={to}>
              <NavLink to={to} end={to === "/"}
                       className={({ isActive }) => `block rounded px-2 py-1.5 text-sm ${isActive ? "bg-noc-line text-white" : "text-noc-muted hover:text-noc-text"}`}>
                {label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <div className="flex-1">
        <header className="flex items-center justify-between border-b border-noc-line px-6 py-3">
          <div className="flex gap-4">
            {health.data && (
              <>
                <StatusDot ok={health.data.status === "ok"} label={`API ${health.data.status}`} />
                <StatusDot ok={health.data.database === "ok"} label="Database" />
                <StatusDot ok={health.data.call_analyzer === "ok"} label="C analyzer" />
                <span className="text-sm text-noc-muted">LLM: {health.data.llm_provider}</span>
              </>
            )}
            {health.error && <StatusDot ok={false} label="API unreachable" />}
          </div>
          <div className="flex items-center gap-3 text-xs text-noc-muted">
            <span>Synthetic demonstration data</span>
            <button className="btn-ghost" onClick={() => { tokenStore.clear(); onLogout(); }}>Sign out</button>
          </div>
        </header>
        <main className="p-6"><Outlet /></main>
      </div>
    </div>
  );
}
