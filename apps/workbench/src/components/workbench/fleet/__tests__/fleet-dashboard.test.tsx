import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, within } from "@testing-library/react";

import { renderWithProviders } from "@/test/test-helpers";
import { FleetDashboard } from "../fleet-dashboard";

const useFleetConnectionMock = vi.hoisted(() => ({
  refreshAgents: vi.fn(),
}));

vi.mock("@/lib/workbench/use-fleet-connection", async () => {
  const actual = await vi.importActual<typeof import("@/lib/workbench/use-fleet-connection")>(
    "@/lib/workbench/use-fleet-connection",
  );

  return {
    ...actual,
    useFleetConnection: () => ({
      connection: {
        connected: true,
        hushdUrl: "http://localhost:9876",
        controlApiUrl: "http://localhost:9877",
        apiKey: "test-api-key",
        controlApiToken: "test-control-token",
        hushdHealth: null,
        agentCount: 2,
      },
      agents: [
        {
          endpoint_agent_id: "agent-online-001",
          last_heartbeat_at: new Date().toISOString(),
          posture: "strict",
          policy_version: "sha256:abc",
          daemon_version: "0.2.5",
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
    }),
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
});
