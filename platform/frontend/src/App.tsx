import { useState } from "react";
import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { tokenStore } from "./services/api";
import { AgentPage } from "./pages/Agent";
import { AnomaliesPage } from "./pages/Anomalies";
import { AuditPage } from "./pages/Audit";
import { CallAnalyticsPage } from "./pages/CallAnalytics";
import { DashboardPage } from "./pages/Dashboard";
import { IncidentDetailPage } from "./pages/IncidentDetail";
import { IncidentsPage } from "./pages/Incidents";
import { Login } from "./pages/Login";
import { NetworkPage } from "./pages/Network";
import { RcaPage } from "./pages/Rca";
import { ReportsPage } from "./pages/Reports";
import { SecurityPage } from "./pages/Security";

export function App() {
  const [signedIn, setSignedIn] = useState(() => tokenStore.get() !== null);
  if (!signedIn) return <Login onLogin={() => setSignedIn(true)} />;
  return (
    <Routes>
      <Route element={<Layout onLogout={() => setSignedIn(false)} />}>
        <Route index element={<DashboardPage />} />
        <Route path="network" element={<NetworkPage />} />
        <Route path="calls" element={<CallAnalyticsPage />} />
        <Route path="anomalies" element={<AnomaliesPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="incidents/:incidentId" element={<IncidentDetailPage />} />
        <Route path="rca" element={<RcaPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="agent" element={<AgentPage />} />
        <Route path="security" element={<SecurityPage />} />
        <Route path="audit" element={<AuditPage />} />
      </Route>
    </Routes>
  );
}
