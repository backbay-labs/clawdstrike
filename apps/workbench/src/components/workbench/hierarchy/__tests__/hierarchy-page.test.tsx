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
      pollError: null,
      secureStorageWarning: false,
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

  it("preserves endpoint and runtime node types from live hierarchy pulls", async () => {
    const user = userEvent.setup();

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
          children: ["team-1"],
        },
        {
          id: "team-1",
          name: "Platform Team",
          node_type: "team",
          parent_id: "root-1",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["endpoint-1"],
        },
        {
          id: "endpoint-1",
          name: "CI Endpoint",
          node_type: "endpoint",
          parent_id: "team-1",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["runtime-1"],
        },
        {
          id: "runtime-1",
          name: "Worker Runtime",
          node_type: "runtime",
          parent_id: "endpoint-1",
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

    await user.click(screen.getByText("CI Endpoint"));
    expect(screen.getByText("Endpoint")).toBeInTheDocument();
    expect(screen.getByText("1 runtime")).toBeInTheDocument();

    const runtimeRow = screen.getAllByText("Worker Runtime").find((element) =>
      element.closest("[draggable='true']"),
    );
    expect(runtimeRow).toBeTruthy();
    await user.click(runtimeRow!);
    expect(screen.getByText("Runtime")).toBeInTheDocument();
  });

  it("hides endpoint metadata counts when the endpoint row is already visible", async () => {
    const user = userEvent.setup();

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
          children: ["team-1"],
        },
        {
          id: "team-1",
          name: "Platform Team",
          node_type: "team",
          parent_id: "root-1",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["endpoint-1"],
        },
        {
          id: "endpoint-1",
          name: "CI Endpoint",
          node_type: "endpoint",
          parent_id: "team-1",
          policy_id: null,
          policy_name: null,
          metadata: { agentCount: 2 },
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

    expect(screen.queryByText("2 runtimes")).not.toBeInTheDocument();
    expect(screen.queryByText("2 agents")).not.toBeInTheDocument();
  });

  it("labels org and team metadata counts as enforcement targets", async () => {
    const user = userEvent.setup();

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
          metadata: { agentCount: 3 },
          children: ["team-1"],
        },
        {
          id: "team-1",
          name: "Platform Team",
          node_type: "team",
          parent_id: "root-1",
          policy_id: null,
          policy_name: null,
          metadata: { agentCount: 1 },
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

    expect(screen.getByText("3 enforcement targets")).toBeInTheDocument();
    expect(screen.getByText("1 enforcement target")).toBeInTheDocument();
    expect(screen.queryByText("3 agents")).not.toBeInTheDocument();
  });

  it("preserves external ids when a live hierarchy pull is pushed back to fleet", async () => {
    const user = userEvent.setup();

    fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
      root_id: "root-1",
      nodes: [
        {
          id: "root-1",
          name: "Fleet Fixture Org",
          node_type: "org",
          external_id: "org-1",
          parent_id: null,
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["team-1"],
        },
        {
          id: "team-1",
          name: "Platform Team",
          node_type: "team",
          external_id: "team-1-ext",
          parent_id: "root-1",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["endpoint-1"],
        },
        {
          id: "endpoint-1",
          name: "CI Endpoint",
          node_type: "endpoint",
          external_id: "agent-123",
          parent_id: "team-1",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["runtime-1"],
        },
        {
          id: "runtime-1",
          name: "Worker Runtime",
          node_type: "runtime",
          external_id: "agent-123/runtime/worker",
          parent_id: "endpoint-1",
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

    fleetClientMocks.createHierarchyNode.mockClear();
    fleetClientMocks.createHierarchyNode
      .mockResolvedValueOnce({ success: true, id: "server-root" })
      .mockResolvedValueOnce({ success: true, id: "server-team" })
      .mockResolvedValueOnce({ success: true, id: "server-endpoint" })
      .mockResolvedValueOnce({ success: true, id: "server-runtime" });
    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    await waitFor(() => {
      expect(fleetClientMocks.createHierarchyNode).toHaveBeenCalledTimes(4);
    });

    const createInputs = fleetClientMocks.createHierarchyNode.mock.calls.map(([, input]) => input);
    expect(createInputs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "CI Endpoint", external_id: "agent-123" }),
        expect.objectContaining({
          name: "Worker Runtime",
          external_id: "agent-123/runtime/worker",
        }),
      ]),
    );
  });

  it("uses server-assigned parent ids when pushing a local hierarchy to fleet", async () => {
    const user = userEvent.setup();

    fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
      root_id: "local-root",
      nodes: [
        {
          id: "local-root",
          name: "Fleet Fixture Org",
          node_type: "org",
          parent_id: null,
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["local-team"],
        },
        {
          id: "local-team",
          name: "Platform Team",
          node_type: "team",
          parent_id: "local-root",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["local-endpoint"],
        },
        {
          id: "local-endpoint",
          name: "CI Endpoint",
          node_type: "endpoint",
          parent_id: "local-team",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: [],
        },
      ],
    });
    fleetClientMocks.createHierarchyNode
      .mockResolvedValueOnce({ success: true, id: "remote-root" })
      .mockResolvedValueOnce({ success: true, id: "remote-team" })
      .mockResolvedValueOnce({ success: true, id: "remote-endpoint" });

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    await user.click(screen.getByRole("button", { name: "Pull from Fleet" }));

    await waitFor(() => {
      expect(screen.getByText("Fleet Snapshot")).toBeInTheDocument();
    });

    fleetClientMocks.createHierarchyNode.mockClear();
    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    await waitFor(() => {
      expect(fleetClientMocks.createHierarchyNode).toHaveBeenCalledTimes(3);
    });

    const createInputs = fleetClientMocks.createHierarchyNode.mock.calls.map(([, input]) => input);
    expect(createInputs[0].parent_id).toBeNull();
    expect(createInputs[1].parent_id).toBe("remote-root");
    expect(createInputs[2].parent_id).toBe("remote-team");
  });

  it("reports skipped descendants when a parent node fails during push", async () => {
    const user = userEvent.setup();

    fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
      root_id: "local-root",
      nodes: [
        {
          id: "local-root",
          name: "Fleet Fixture Org",
          node_type: "org",
          parent_id: null,
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["local-team"],
        },
        {
          id: "local-team",
          name: "Platform Team",
          node_type: "team",
          parent_id: "local-root",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["local-endpoint"],
        },
        {
          id: "local-endpoint",
          name: "CI Endpoint",
          node_type: "endpoint",
          parent_id: "local-team",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: [],
        },
      ],
    });
    fleetClientMocks.createHierarchyNode.mockReset();
    fleetClientMocks.createHierarchyNode
      .mockResolvedValueOnce({ success: true, id: "remote-root" })
      .mockResolvedValueOnce({ success: false, error: "boom" });

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    await user.click(screen.getByRole("button", { name: "Pull from Fleet" }));

    await waitFor(() => {
      expect(screen.getByText("Fleet Snapshot")).toBeInTheDocument();
    });

    fleetClientMocks.createHierarchyNode.mockReset();
    fleetClientMocks.createHierarchyNode
      .mockResolvedValueOnce({ success: true, id: "remote-root" })
      .mockResolvedValueOnce({ success: false, error: "boom" });

    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    await waitFor(() => {
      expect(screen.getByText("Pushed 1 nodes, 1 failed, 1 skipped")).toBeInTheDocument();
    });
  });

  it("continues pushing independent sibling branches when a parent is created without returning an id", async () => {
    const user = userEvent.setup();

    fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
      root_id: "local-root",
      nodes: [
        {
          id: "local-root",
          name: "Fleet Fixture Org",
          node_type: "org",
          parent_id: null,
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["local-team-a", "local-team-b"],
        },
        {
          id: "local-team-a",
          name: "Platform Team",
          node_type: "team",
          parent_id: "local-root",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["local-endpoint"],
        },
        {
          id: "local-endpoint",
          name: "CI Endpoint",
          node_type: "endpoint",
          parent_id: "local-team-a",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: [],
        },
        {
          id: "local-team-b",
          name: "Ops Team",
          node_type: "team",
          parent_id: "local-root",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: [],
        },
      ],
    });
    fleetClientMocks.createHierarchyNode.mockReset();
    fleetClientMocks.createHierarchyNode
      .mockResolvedValueOnce({ success: true, id: "remote-root" })
      .mockResolvedValueOnce({ success: true })
      .mockResolvedValueOnce({ success: true, id: "remote-ops-team" });

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    await user.click(screen.getByRole("button", { name: "Pull from Fleet" }));

    await waitFor(() => {
      expect(screen.getByText("Fleet Snapshot")).toBeInTheDocument();
    });

    fleetClientMocks.createHierarchyNode.mockReset();
    fleetClientMocks.createHierarchyNode
      .mockResolvedValueOnce({ success: true, id: "remote-root" })
      .mockResolvedValueOnce({ success: true })
      .mockResolvedValueOnce({ success: true, id: "remote-ops-team" });

    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    await waitFor(() => {
      expect(
        screen.getByText("Pushed 2 nodes, 1 incomplete, 1 skipped"),
      ).toBeInTheDocument();
    });

    expect(
      screen.getByText("Pushed 2 nodes, 1 incomplete, 1 skipped"),
    ).toHaveClass("text-[#3dbf84]");
  });

  it("treats childless responses without ids as incomplete rather than complete success", async () => {
    const user = userEvent.setup();

    fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
      root_id: "local-root",
      nodes: [
        {
          id: "local-root",
          name: "Fleet Fixture Org",
          node_type: "org",
          parent_id: null,
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: [],
        },
      ],
    });
    fleetClientMocks.createHierarchyNode.mockReset();
    fleetClientMocks.createHierarchyNode.mockResolvedValueOnce({ success: true });

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    await user.click(screen.getByRole("button", { name: "Pull from Fleet" }));

    await waitFor(() => {
      expect(screen.getByText("Fleet Snapshot")).toBeInTheDocument();
    });

    fleetClientMocks.createHierarchyNode.mockReset();
    fleetClientMocks.createHierarchyNode.mockResolvedValueOnce({ success: true });

    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    await waitFor(() => {
      expect(screen.getByText("Pushed 0 nodes, 1 incomplete")).toBeInTheDocument();
    });

    expect(screen.getByText("Pushed 0 nodes, 1 incomplete")).toHaveClass("text-[#c45c5c]");
  });

  it("surfaces root responses without ids as an error when descendants are skipped", async () => {
    const user = userEvent.setup();

    fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
      root_id: "local-root",
      nodes: [
        {
          id: "local-root",
          name: "Fleet Fixture Org",
          node_type: "org",
          parent_id: null,
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["local-team"],
        },
        {
          id: "local-team",
          name: "Platform Team",
          node_type: "team",
          parent_id: "local-root",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: [],
        },
      ],
    });
    fleetClientMocks.createHierarchyNode.mockReset();
    fleetClientMocks.createHierarchyNode.mockResolvedValueOnce({ success: true });

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    await user.click(screen.getByRole("button", { name: "Pull from Fleet" }));

    await waitFor(() => {
      expect(screen.getByText("Fleet Snapshot")).toBeInTheDocument();
    });

    fleetClientMocks.createHierarchyNode.mockReset();
    fleetClientMocks.createHierarchyNode.mockResolvedValueOnce({ success: true });

    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    await waitFor(() => {
      expect(
        screen.getByText(
          "Pushed 0 nodes, 1 incomplete, 1 skipped (root response omitted an id, descendants skipped)",
        ),
      ).toBeInTheDocument();
    });

    expect(
      screen.getByText(
        "Pushed 0 nodes, 1 incomplete, 1 skipped (root response omitted an id, descendants skipped)",
      ),
    ).toHaveClass("text-[#c45c5c]");
  });
});
