import { fireEvent, render, screen, within } from "@testing-library/react";
import { AgentActionPanel } from "../components/AgentActionPanel";
import { SeverityBadge } from "../components/common";
import { IncidentTimeline } from "../components/IncidentTimeline";
import { KpiCard } from "../components/KpiCard";
import { RcaPanel } from "../components/RcaPanel";
import { action, events, overview, rca } from "./fixtures";

describe("SeverityBadge", () => {
  it("renders the severity with its colour class", () => {
    render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByTestId("severity-badge")).toHaveTextContent("CRITICAL");
    expect(screen.getByTestId("severity-badge").className).toContain("bg-sev-critical");
  });
});

describe("KpiCard", () => {
  it("highlights a bad-direction change", () => {
    render(<KpiCard kpi={overview.kpis[0]} />);
    const card = screen.getByTestId("kpi-latency_ms");
    expect(card).toHaveTextContent("300");
    expect(card.querySelector(".text-2xl")?.className).toContain("text-sev-critical");
  });
  it("does not flag a small change in the good direction", () => {
    render(<KpiCard kpi={overview.kpis[1]} />);
    expect(screen.getByTestId("kpi-throughput_mbps").querySelector(".text-2xl")?.className).not.toContain("text-sev-critical");
  });
});

describe("IncidentTimeline", () => {
  it("orders events by time", () => {
    render(<IncidentTimeline events={events} />);
    const items = within(screen.getByTestId("incident-timeline")).getAllByRole("listitem");
    expect(items.map((li) => li.textContent)).toEqual([
      expect.stringContaining("Deployed 2.4.1"), expect.stringContaining("memory anomaly"), expect.stringContaining("cpu anomaly"),
    ]);
  });
});

describe("RcaPanel", () => {
  it("shows the explanation chain and labels the cause as a hypothesis", () => {
    render(<RcaPanel rca={rca} />);
    expect(screen.getByText(/hypothesis, not a confirmed fact/)).toBeInTheDocument();
    expect(screen.getByText(/\[mock-2-1\]/)).toBeInTheDocument();
    expect(screen.getAllByText("85%")).toHaveLength(2); // headline confidence + hypothesis row
    expect(screen.getByText("no attack traffic")).toBeInTheDocument();
    expect(screen.getByText(/Roll back packet-gateway/)).toHaveTextContent("HIGH_RISK");
  });
});

describe("AgentActionPanel", () => {
  it("offers approve/deny only for awaiting actions and execute only for approved ones", () => {
    const onApprove = vi.fn(), onDeny = vi.fn(), onExecute = vi.fn();
    render(<AgentActionPanel busy={false} onApprove={onApprove} onDeny={onDeny} onExecute={onExecute} actions={[
      action({}),
      action({ action_id: "a2", sequence: 2, tool: "apply_patch", risk_class: "REQUIRES_APPROVAL", status: "awaiting_approval" }),
      action({ action_id: "a3", sequence: 3, tool: "rollback_deployment", risk_class: "HIGH_RISK", status: "approved" }),
      action({ action_id: "a4", sequence: 4, tool: "delete_infrastructure", risk_class: "BLOCKED", status: "blocked" }),
    ]} />);
    expect(screen.getAllByRole("button", { name: "Approve" })).toHaveLength(1);
    expect(screen.getAllByRole("button", { name: "Execute" })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    fireEvent.click(screen.getByRole("button", { name: "Execute" }));
    expect(onApprove).toHaveBeenCalledWith(expect.objectContaining({ action_id: "a2" }));
    expect(onDeny).toHaveBeenCalledWith(expect.objectContaining({ action_id: "a2" }));
    expect(onExecute).toHaveBeenCalledWith(expect.objectContaining({ action_id: "a3" }));
    expect(screen.getByRole("button", { name: "Execute" }).className).toContain("btn-danger");
  });
});
