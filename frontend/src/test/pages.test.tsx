import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { api, ApiError, tokenStore } from "../services/api";
import { incident, mockFetch, overview, rca } from "./fixtures";

const metrics = { run_id: 1, metric: "latency_ms", series: [{ cell_id: "CELL-101", node_id: "pgw-1", epochs: [1, 2], values: [20, 300] }] };
const health = { status: "ok", version: "0.1.0", database: "ok", call_analyzer: "ok", llm_provider: "mock" };

beforeEach(() => { sessionStorage.clear(); });
afterEach(() => { vi.unstubAllGlobals(); });

describe("api client", () => {
  it("sends the bearer token and raises ApiError with the server's detail", async () => {
    tokenStore.set("tok-123");
    const fetchMock = mockFetch({ "/api/incidents": { detail: "requires role viewer or higher" } }, { "/api/incidents": 403 });
    vi.stubGlobal("fetch", fetchMock);
    await expect(api.incidents()).rejects.toEqual(new ApiError(403, "requires role viewer or higher"));
    const headers = fetchMock.mock.calls[0][1]?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer tok-123");
  });
  it("URL-encodes path parameters", async () => {
    tokenStore.set("t");
    const fetchMock = mockFetch({ "/api/incidents/": incident });
    vi.stubGlobal("fetch", fetchMock);
    await api.incident("../audit");
    expect(String(fetchMock.mock.calls[0][0])).toBe("/api/incidents/..%2Faudit");
  });
});

describe("Login", () => {
  it("rejects an invalid token and keeps nothing in storage", async () => {
    vi.stubGlobal("fetch", mockFetch({ "/api/incidents": { detail: "invalid" } }, { "/api/incidents": 401 }));
    render(<MemoryRouter><App /></MemoryRouter>);
    await userEvent.type(screen.getByLabelText("API token"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid token");
    expect(tokenStore.get()).toBeNull();
  });
});

describe("Dashboard", () => {
  it("answers the six NOC questions from API data", async () => {
    tokenStore.set("t");
    vi.stubGlobal("fetch", mockFetch({
      "/api/health": health, "/api/network/overview": overview, "/api/incidents/INC-2026-001/rca": rca,
      "/api/incidents": [incident], "/api/agent/runs": [], "/api/network/metrics": metrics, "/api/network/anomalies": [],
    }));
    render(<MemoryRouter><App /></MemoryRouter>);
    expect(await screen.findByTestId("health-score")).toHaveTextContent("62");           // healthy?
    expect(await screen.findByText("INC-2026-001")).toBeInTheDocument();                  // what is broken?
    expect(screen.getAllByTestId("severity-badge")[0]).toHaveTextContent("CRITICAL");     // how severe?
    await waitFor(() => expect(screen.getByText(/introduced a regression/)).toBeInTheDocument()); // why?
    expect(screen.getByText("No agent runs yet.")).toBeInTheDocument();                   // what is the AI doing?
    expect(screen.getByTestId("remediation-status")).toHaveTextContent("No remediation verified yet"); // worked?
    expect(screen.getByTestId("kpi-call_drop_rate")).toBeInTheDocument();
  });
});
