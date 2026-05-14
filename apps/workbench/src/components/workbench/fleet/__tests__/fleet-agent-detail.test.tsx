import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";

import { renderWithProviders } from "@/test/test-helpers";
import { FleetAgentDetail } from "../fleet-agent-detail";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockAgents = [
  {
    endpoint_agent_id: "agent-alpha-001",
    last_heartbeat_at: new Date().toISOString(),
    posture: "strict",
    policy_version: "sha256:abc123",
    daemon_version: "0.2.6",
    last_seen_ip: "10.0.0.1",
    last_session_id: "sess-001",
    runtime_count: 3,
    seconds_since_heartbeat: 5,
    online: true,
    drift: { policy_drift: true, daemon_drift: false, stale: false },
  },
];

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>(
    "react-router-dom",
  );
  return {
    ...actual,
    useParams: () => ({ id: "agent-alpha-001" }),
  };
});

vi.mock("@/features/fleet/use-fleet-connection", async () => {
  const actual = await vi.importActual<typeof import("@/features/fleet/use-fleet-connection")>(
    "@/features/fleet/use-fleet-connection",
  );
  return {
    ...actual,
    useFleetConnectionStore: Object.assign(
      () => ({
        agents: mockAgents,
        remotePolicyInfo: { policyHash: "sha256:expected", version: "1.0.0", yaml: "" },
        actions: {
          getAuthenticatedConnection: () => ({
            hushdUrl: "http://localhost:9876",
            controlApiUrl: "",
            apiKey: "test",
            controlApiToken: "",
            connected: true,
            hushdHealth: null,
            agentCount: 1,
          }),
        },
      }),
      {
        use: {
          agents: () => mockAgents,
          remotePolicyInfo: () => ({
            policyHash: "sha256:expected",
            version: "1.0.0",
            yaml: "",
          }),
          actions: () => ({
            getAuthenticatedConnection: () => ({
              hushdUrl: "http://localhost:9876",
              controlApiUrl: "",
              apiKey: "test",
              controlApiToken: "",
              connected: true,
              hushdHealth: null,
              agentCount: 1,
            }),
          }),
        },
        getState: () => ({
          agents: mockAgents,
          remotePolicyInfo: { policyHash: "sha256:expected", version: "1.0.0", yaml: "" },
          actions: {
            getAuthenticatedConnection: () => ({
              hushdUrl: "http://localhost:9876",
              controlApiUrl: "",
              apiKey: "test",
              controlApiToken: "",
              connected: true,
              hushdHealth: null,
              agentCount: 1,
            }),
          },
        }),
      },
    ),
  };
});

vi.mock("@/features/fleet/fleet-client", async () => {
  const actual = await vi.importActual<typeof import("@/features/fleet/fleet-client")>(
    "@/features/fleet/fleet-client",
  );
  return {
    ...actual,
    fetchAuditEvents: vi.fn().mockResolvedValue([]),
  };
});

vi.mock("@/features/panes/pane-store", () => ({
  usePaneStore: {
    getState: () => ({
      openApp: vi.fn(),
    }),
  },
}));

describe("FleetAgentDetail", () => {
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

  it("renders agent ID in the page header", () => {
    renderWithProviders(<FleetAgentDetail />);
    // Agent ID appears in both the header title and the detail row
    const matches = screen.getAllByText("agent-alpha-001");
    expect(matches.length).toBeGreaterThanOrEqual(1);
    // The h1 title should be one of them
    const h1 = matches.find((el) => el.tagName === "H1");
    expect(h1).toBeTruthy();
  });

  it("shows drift flags section with correct indicators", () => {
    renderWithProviders(<FleetAgentDetail />);
    // Agent has policy_drift=true so "YES" should appear for policy drift
    const yesElements = screen.getAllByText("YES");
    expect(yesElements.length).toBeGreaterThanOrEqual(1);
    // Agent has daemon_drift=false and stale=false so "No" should appear
    const noElements = screen.getAllByText("No");
    expect(noElements.length).toBeGreaterThanOrEqual(2);
  });

  it("shows policy version mismatch when drift is true", () => {
    renderWithProviders(<FleetAgentDetail />);
    expect(screen.getByText("Policy Version Mismatch")).toBeInTheDocument();
    expect(screen.getByText("sha256:expected")).toBeInTheDocument();
    // sha256:abc123 appears in both Agent Info card and the drift diff
    const policyVersionMatches = screen.getAllByText("sha256:abc123");
    expect(policyVersionMatches.length).toBeGreaterThanOrEqual(1);
  });

  it("shows Quick Deploy button when policy drift is detected", () => {
    renderWithProviders(<FleetAgentDetail />);
    expect(screen.getByText("Quick Deploy")).toBeInTheDocument();
  });

  it("shows Agent Info section with key fields", () => {
    renderWithProviders(<FleetAgentDetail />);
    expect(screen.getByText("Agent Info")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
    expect(screen.getByText("0.2.6")).toBeInTheDocument();
  });
});
