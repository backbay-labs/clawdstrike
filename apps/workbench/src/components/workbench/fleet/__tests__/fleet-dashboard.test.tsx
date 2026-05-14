import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, within, fireEvent } from "@testing-library/react";

import { renderWithProviders } from "@/test/test-helpers";
import { FleetDashboard } from "../fleet-dashboard";

const useFleetConnectionMock = vi.hoisted(() => ({
  refreshAgents: vi.fn(),
}));

const mockOpenApp = vi.fn();

vi.mock("@/features/panes/pane-store", () => ({
  usePaneStore: {
    getState: () => ({
      openApp: mockOpenApp,
    }),
  },
}));

vi.mock("@/features/fleet/fleet-client", async () => {
  const actual = await vi.importActual<typeof import("@/features/fleet/fleet-client")>(
    "@/features/fleet/fleet-client",
  );
  return {
    ...actual,
    deployPolicy: vi.fn().mockResolvedValue({ success: true }),
    validateRemotely: vi.fn().mockResolvedValue({ valid: true }),
  };
});

vi.mock("@/features/fleet/use-fleet-connection", async () => {
  const actual = await vi.importActual<typeof import("@/features/fleet/use-fleet-connection")>(
    "@/features/fleet/use-fleet-connection",
  );

  return {
    ...actual,
    AGENT_POLL_MS: 60000,
    useFleetConnection: () => ({
      connection: {
        connected: true,
        hushdUrl: "http://localhost:9876",
        controlApiUrl: "http://localhost:9877",
        hushdHealth: null,
        agentCount: 2,
      },
      agents: [
        {
          endpoint_agent_id: "agent-online-001",
          last_heartbeat_at: new Date().toISOString(),
          posture: "strict",
          policy_version: "sha256:abc",
          daemon_version: "0.2.7",
          runtime_count: 1,
          seconds_since_heartbeat: 5,
          online: true,
          drift: { policy_drift: false, daemon_drift: false, stale: false },
        },
        {
          endpoint_agent_id: "agent-stale-001",
          last_heartbeat_at: new Date(Date.now() - 120_000).toISOString(),
          posture: "default",
          policy_version: "sha256:old",
          daemon_version: "0.2.4",
          runtime_count: 0,
          seconds_since_heartbeat: 120,
          online: false,
          drift: { policy_drift: true, daemon_drift: false, stale: true },
        },
      ],
      refreshAgents: useFleetConnectionMock.refreshAgents,
      pollError: null,
      secureStorageWarning: false,
      getCredentials: () => ({ apiKey: "test-api-key", controlApiToken: "test-control-token" }),
      getAuthenticatedConnection: () => ({ connected: true, hushdUrl: "http://localhost:9876", controlApiUrl: "http://localhost:9877", apiKey: "test-api-key", controlApiToken: "test-control-token", hushdHealth: null, agentCount: 2 }),
    }),
    useFleetConnectionStore: Object.assign(
      () => ({
        sseState: "connected" as const,
        remotePolicyInfo: { policyHash: "sha256:expected", version: "1.0.0", yaml: "schema_version: '1.5.0'" },
      }),
      {
        use: {
          sseState: () => "connected" as const,
          remotePolicyInfo: () => ({
            policyHash: "sha256:expected",
            version: "1.0.0",
            yaml: "schema_version: '1.5.0'",
          }),
          agents: () => [],
        },
        getState: () => ({
          sseState: "connected" as const,
          remotePolicyInfo: { policyHash: "sha256:expected", version: "1.0.0", yaml: "schema_version: '1.5.0'" },
        }),
      },
    ),
  };
});

describe("FleetDashboard", () => {
  let localStorageState: Record<string, string>;

  const localStorageMock = {
    getItem: (key: string) => localStorageState[key] ?? null,
    setItem: (key: string, value: string) => {
      localStorageState[key] = value;
    },
    removeItem: (key: string) => {
      delete localStorageState[key];
    },
    clear: () => {
      localStorageState = {};
    },
    key: (index: number) => Object.keys(localStorageState)[index] ?? null,
    get length() {
      return Object.keys(localStorageState).length;
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    localStorageState = {};
    vi.stubGlobal("localStorage", localStorageMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("counts stale offline agents in the stale summary card", () => {
    renderWithProviders(<FleetDashboard />);

    const staleCard = screen.getByText("Stale").closest("div");
    expect(staleCard).not.toBeNull();
    expect(within(staleCard as HTMLElement).getByText("1")).toBeInTheDocument();
    expect(screen.getByText("agent-stale-001")).toBeInTheDocument();
  });

  it("shows Live SSE indicator when sseState is connected", () => {
    renderWithProviders(<FleetDashboard />);

    const sseIndicator = screen.getByTestId("sse-indicator");
    expect(sseIndicator).toBeInTheDocument();
    expect(sseIndicator.textContent).toBe("Live");
  });

  it("shows Live updates text in subtitle when SSE is connected", () => {
    renderWithProviders(<FleetDashboard />);
    expect(screen.getByText(/Live updates via SSE/)).toBeInTheDocument();
  });

  it("shows bulk action bar when agents are selected", () => {
    renderWithProviders(<FleetDashboard />);

    // Find all checkboxes (header + 2 agent rows)
    const checkboxes = screen.getAllByRole("checkbox");
    expect(checkboxes.length).toBe(3); // 1 header + 2 agents

    // Click the first agent checkbox (index 1 since 0 is the header)
    fireEvent.click(checkboxes[1]);

    // Bulk action bar should appear
    const bulkBar = screen.getByTestId("bulk-action-bar");
    expect(bulkBar).toBeInTheDocument();
    expect(within(bulkBar).getByText("1 agent selected")).toBeInTheDocument();
    expect(within(bulkBar).getByText("Push Policy")).toBeInTheDocument();
  });

  it("clicking agent row calls openApp for detail navigation", () => {
    renderWithProviders(<FleetDashboard />);

    const row = screen.getByTestId("agent-row-agent-online-001");
    fireEvent.click(row);

    expect(mockOpenApp).toHaveBeenCalledWith(
      "/fleet/agent-online-001",
      "agent-online-001",
    );
  });

  it("renders view toggle buttons for table and topology", () => {
    renderWithProviders(<FleetDashboard />);

    // View toggle buttons exist
    const tableBtn = screen.getByTitle("Table view");
    const topoBtn = screen.getByTitle("Topology view");
    expect(tableBtn).toBeInTheDocument();
    expect(topoBtn).toBeInTheDocument();
  });
});
