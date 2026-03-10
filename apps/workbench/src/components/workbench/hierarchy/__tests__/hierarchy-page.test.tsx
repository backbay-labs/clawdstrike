import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { renderWithProviders } from "@/test/test-helpers";

const fleetClientMocks = vi.hoisted(() => ({
  fetchHierarchyTree: vi.fn(),
  fetchScopedPolicies: vi.fn(),
  fetchPolicyAssignments: vi.fn(),
  createHierarchyNode: vi.fn(),
  updateHierarchyNode: vi.fn(),
  deleteHierarchyNode: vi.fn(),
}));

vi.mock("@/lib/workbench/fleet-client", async () => {
  const actual = await vi.importActual<typeof import("@/lib/workbench/fleet-client")>(
    "@/lib/workbench/fleet-client",
  );

  return {
    ...actual,
    fetchHierarchyTree: fleetClientMocks.fetchHierarchyTree,
    fetchScopedPolicies: fleetClientMocks.fetchScopedPolicies,
    fetchPolicyAssignments: fleetClientMocks.fetchPolicyAssignments,
    createHierarchyNode: fleetClientMocks.createHierarchyNode,
    updateHierarchyNode: fleetClientMocks.updateHierarchyNode,
    deleteHierarchyNode: fleetClientMocks.deleteHierarchyNode,
  };
});

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
        agentCount: 0,
      },
      isConnecting: false,
      error: null,
      agents: [],
      remotePolicyInfo: null,
      connect: vi.fn(),
      disconnect: vi.fn(),
      testConnection: vi.fn(),
      refreshAgents: vi.fn(),
      refreshRemotePolicy: vi.fn(),
    }),
  };
});

import { HierarchyPage } from "../hierarchy-page";

describe("HierarchyPage", () => {
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
    fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
      root_id: null,
      nodes: [],
    });
    fleetClientMocks.fetchScopedPolicies.mockResolvedValue([]);
    fleetClientMocks.fetchPolicyAssignments.mockResolvedValue([]);
    fleetClientMocks.createHierarchyNode.mockResolvedValue({ success: true });
    fleetClientMocks.updateHierarchyNode.mockResolvedValue({ success: true });
    fleetClientMocks.deleteHierarchyNode.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("keeps the local draft when the live hierarchy is empty", async () => {
    const user = userEvent.setup();

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    expect(screen.getByText("Local Draft")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Pull from Fleet" }));

    await waitFor(() => {
      expect(
        screen.getByText("Fleet hierarchy is empty — keeping local draft"),
      ).toBeInTheDocument();
    });

    expect(screen.getByText("Local Draft")).toBeInTheDocument();
    expect(screen.queryByText("Fleet Snapshot")).not.toBeInTheDocument();
    expect(fleetClientMocks.fetchScopedPolicies).not.toHaveBeenCalled();
    expect(fleetClientMocks.fetchPolicyAssignments).not.toHaveBeenCalled();
  });

  it("deduplicates duplicate child ids from a live hierarchy pull without React key warnings", async () => {
    const user = userEvent.setup();
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
        root_id: "root-1",
        nodes: [
          {
            id: "root-1",
            name: "Fleet Fixture Org",
            node_type: "org",
            parent_id: null,
            policy_id: null,
            policy_name: null,
            metadata: {},
            children: [
              {
                id: "team-1",
                name: "Duplicate Team",
                node_type: "team",
                parent_id: "root-1",
                policy_id: null,
                policy_name: null,
                metadata: {},
                children: [],
              },
              {
                id: "team-1",
                name: "Duplicate Team",
                node_type: "team",
                parent_id: "root-1",
                policy_id: null,
                policy_name: null,
                metadata: {},
                children: [],
              },
            ],
          },
        ],
      });

      renderWithProviders(<HierarchyPage />);

      await user.click(screen.getByRole("button", { name: "DEMO" }));
      await user.click(screen.getByRole("button", { name: "Pull from Fleet" }));

      await waitFor(() => {
        expect(screen.getByText("Fleet Snapshot")).toBeInTheDocument();
      });

      expect(
        consoleError.mock.calls.some(([message]) =>
          String(message).includes('Each child in a list should have a unique "key" prop.'),
        ),
      ).toBe(false);
    } finally {
      consoleError.mockRestore();
    }
  });

  it("reconstructs flat tree responses with child id lists without key warnings", async () => {
    const user = userEvent.setup();
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
        root_id: "root-1",
        nodes: [
          {
            id: "root-1",
            name: "Fleet Fixture Org",
            node_type: "org",
            parent_id: null,
            policy_id: null,
            policy_name: null,
            metadata: {},
            children: ["team-1", "team-2"],
          },
          {
            id: "team-1",
            name: "Fixture Engineering",
            node_type: "team",
            parent_id: "root-1",
            policy_id: null,
            policy_name: null,
            metadata: {},
            children: [],
          },
          {
            id: "team-2",
            name: "Fixture Security",
            node_type: "team",
            parent_id: "root-1",
            policy_id: null,
            policy_name: null,
            metadata: {},
            children: [],
          },
        ],
      });

      renderWithProviders(<HierarchyPage />);

      await user.click(screen.getByRole("button", { name: "DEMO" }));
      await user.click(screen.getByRole("button", { name: "Pull from Fleet" }));

      await waitFor(() => {
        expect(screen.getByText("Fleet Snapshot")).toBeInTheDocument();
      });

      expect(screen.getByText("2 direct children")).toBeInTheDocument();
      expect(
        consoleError.mock.calls.some(([message]) =>
          String(message).includes('Each child in a list should have a unique "key" prop.'),
        ),
      ).toBe(false);
    } finally {
      consoleError.mockRestore();
    }
  });
});
