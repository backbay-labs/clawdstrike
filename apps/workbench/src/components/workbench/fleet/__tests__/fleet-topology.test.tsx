import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { FleetTopologyView } from "../fleet-topology-view";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockAgents = [
  {
    endpoint_agent_id: "agent-001",
    last_heartbeat_at: new Date().toISOString(),
    posture: "strict",
    policy_version: "sha256:abc",
    daemon_version: "0.2.6",
    runtime_count: 1,
    seconds_since_heartbeat: 5,
    online: true,
    drift: { policy_drift: false, daemon_drift: false, stale: false },
  },
  {
    endpoint_agent_id: "agent-002",
    last_heartbeat_at: new Date().toISOString(),
    posture: "default",
    policy_version: "sha256:abc",
    daemon_version: "0.2.6",
    runtime_count: 2,
    seconds_since_heartbeat: 10,
    online: true,
    drift: { policy_drift: false, daemon_drift: false, stale: false },
  },
  {
    endpoint_agent_id: "agent-003",
    last_heartbeat_at: new Date(Date.now() - 120_000).toISOString(),
    posture: "permissive",
    policy_version: "sha256:old",
    daemon_version: "0.2.4",
    runtime_count: 0,
    seconds_since_heartbeat: 120,
    online: false,
    drift: { policy_drift: true, daemon_drift: false, stale: true },
  },
];

const mockOpenApp = vi.fn();

vi.mock("@/features/fleet/use-fleet-connection", async () => {
  const actual = await vi.importActual<typeof import("@/features/fleet/use-fleet-connection")>(
    "@/features/fleet/use-fleet-connection",
  );
  return {
    ...actual,
    useFleetConnectionStore: Object.assign(
      () => ({ agents: mockAgents }),
      {
        use: {
          agents: () => mockAgents,
        },
        getState: () => ({ agents: mockAgents }),
      },
    ),
  };
});

vi.mock("@/features/panes/pane-store", () => ({
  usePaneStore: {
    getState: () => ({
      openApp: mockOpenApp,
    }),
  },
}));

describe("FleetTopologyView", () => {
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

  it("renders SVG with circles for each agent", () => {
    const { container } = render(<FleetTopologyView />);
    const svg = container.querySelector("svg");
    expect(svg).not.toBeNull();
    // Each agent has a main circle + possibly a drift ring circle
    // agent-003 has drift so it has 2 circles, others have 1 each = 4 total
    const circles = svg?.querySelectorAll("circle");
    expect(circles?.length).toBeGreaterThanOrEqual(3);
  });

  it("renders edges between agents with matching policy_version", () => {
    const { container } = render(<FleetTopologyView />);
    const svg = container.querySelector("svg");
    // agent-001 and agent-002 share "sha256:abc" so there should be 1 edge line
    const lines = svg?.querySelectorAll("line");
    expect(lines?.length).toBe(1);
  });

  it("renders drift ring on agent with policy_drift", () => {
    const { container } = render(<FleetTopologyView />);
    const svg = container.querySelector("svg");
    // agent-003 has drift so should have a dashed ring
    const dashedCircles = svg?.querySelectorAll('circle[stroke-dasharray]');
    expect(dashedCircles?.length).toBe(1);
  });

  it("calls openApp when clicking on a node", () => {
    render(<FleetTopologyView />);
    const node = screen.getByTestId("topology-node-agent-001");
    fireEvent.click(node);
    expect(mockOpenApp).toHaveBeenCalledWith("/fleet/agent-001", "agent-001");
  });
});
