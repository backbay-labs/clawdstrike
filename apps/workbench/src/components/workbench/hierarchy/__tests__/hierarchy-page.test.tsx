import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
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
    vi.spyOn(window, "confirm").mockReturnValue(true);
    fleetClientMocks.fetchHierarchyTree.mockResolvedValue({
      root_id: null,
      nodes: [],
    });
    fleetClientMocks.fetchScopedPolicies.mockResolvedValue([]);
    fleetClientMocks.fetchPolicyAssignments.mockResolvedValue([]);
    fleetClientMocks.createHierarchyNode.mockImplementation(async (_connection, input) => ({
      success: true,
      id: `server-${input.name.toLowerCase().replace(/\s+/g, "-")}`,
    }));
    fleetClientMocks.updateHierarchyNode.mockResolvedValue({ success: true });
    fleetClientMocks.deleteHierarchyNode.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    vi.restoreAllMocks();
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

  it("keeps legacy agent nodes as validation leaves after a live hierarchy pull", async () => {
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
          children: ["agent-1"],
        },
        {
          id: "agent-1",
          name: "Legacy Agent",
          node_type: "agent",
          parent_id: "team-1",
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

    expect(screen.getByText("1 leaf node")).toBeInTheDocument();
    await user.click(screen.getAllByText("Legacy Agent")[0]);
    expect(screen.getByText("Agent")).toBeInTheDocument();
  });

  it("counts runtime nodes as leaves after a live hierarchy pull", async () => {
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
          name: "Builder Host",
          node_type: "endpoint",
          parent_id: "team-1",
          policy_id: null,
          policy_name: null,
          metadata: {},
          children: ["runtime-1"],
        },
        {
          id: "runtime-1",
          name: "Claude Runtime",
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

    expect(screen.getByText("1 leaf node")).toBeInTheDocument();
    await user.click(screen.getAllByText("Claude Runtime")[0]);
    expect(screen.getByText("Runtime Agent")).toBeInTheDocument();
  });

  it("preserves child-only links when legacy scoped-policy pulls omit parent ids", async () => {
    const user = userEvent.setup();

    fleetClientMocks.fetchHierarchyTree.mockResolvedValue(null);
    fleetClientMocks.fetchScopedPolicies.mockResolvedValue([
      {
        scope_id: "root-1",
        scope_name: "Fleet Fixture Org",
        scope_type: "org",
        parent_scope_id: null,
        children: ["team-1"],
      },
      {
        scope_id: "team-1",
        scope_name: "Platform Team",
        scope_type: "team",
        parent_scope_id: null,
        children: ["agent-1"],
      },
      {
        scope_id: "agent-1",
        scope_name: "Legacy Agent",
        scope_type: "agent",
        parent_scope_id: null,
        children: [],
      },
    ]);

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    await user.click(screen.getByRole("button", { name: "Pull from Fleet" }));

    await waitFor(() => {
      expect(screen.getByText("Fleet Snapshot")).toBeInTheDocument();
    });

    expect(screen.getByText("Platform Team")).toBeInTheDocument();
    expect(screen.getAllByText("Legacy Agent").length).toBeGreaterThan(0);
    expect(screen.getByText("1 leaf node")).toBeInTheDocument();
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
          name: "Builder Host",
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
          name: "Claude Runtime",
          node_type: "runtime",
          external_id: "agent-123/runtime/claude",
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
    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    await waitFor(() => {
      expect(fleetClientMocks.createHierarchyNode).toHaveBeenCalledTimes(4);
    });

    const createInputs = fleetClientMocks.createHierarchyNode.mock.calls.map(([, input]) => input);
    expect(createInputs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "Builder Host", external_id: "agent-123" }),
        expect.objectContaining({
          name: "Claude Runtime",
          external_id: "agent-123/runtime/claude",
        }),
      ]),
    );
  });

  it("surfaces an incomplete push when a parent create succeeds without returning an id", async () => {
    const user = userEvent.setup();

    fleetClientMocks.createHierarchyNode
      .mockResolvedValueOnce({ success: true, id: "server-root" })
      .mockResolvedValueOnce({ success: true });

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    await waitFor(() => {
      expect(
        screen.getByText(/was created without an id, so 3 descendant nodes/),
      ).toBeInTheDocument();
    });
    expect(fleetClientMocks.createHierarchyNode).toHaveBeenCalledTimes(2);
  });

  it("confirms before push when leaf validation reports warnings", async () => {
    const user = userEvent.setup();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValueOnce(false);

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    expect(confirmSpy).toHaveBeenCalledWith(
      expect.stringContaining("validation warning(s)"),
    );
    expect(fleetClientMocks.createHierarchyNode).not.toHaveBeenCalled();
  });

  it("still allows dragging legacy agent leaves onto teams", async () => {
    const user = userEvent.setup();

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));

    const source = screen
      .getAllByText("agent-coder-01")[0]
      .closest("div[draggable='true']");
    const target = screen.getAllByText("Security")[0].closest("div");

    expect(source).not.toBeNull();
    expect(target).not.toBeNull();

    fireEvent.dragStart(source!);
    fireEvent.dragOver(target!);
    fireEvent.drop(target!);

    await waitFor(() => {
      expect(fleetClientMocks.updateHierarchyNode).toHaveBeenCalledTimes(1);
    });
  });

  it("keeps the green selection ring for legacy agent nodes", async () => {
    const user = userEvent.setup();

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));

    const agentLabel = screen.getAllByText("agent-coder-01")[0];
    const agentRow = agentLabel.closest("div[draggable='true']");

    expect(agentRow).not.toBeNull();

    await user.click(agentLabel);

    expect(agentRow?.className).toContain("ring-[#3dbf84]/30");
  });

  it("rolls back optimistic hierarchy versions in order when live sync failures resolve out of order", async () => {
    const user = userEvent.setup();
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const createDeferred = () => {
      let resolve!: (value: { success: boolean; error?: string }) => void;
      const promise = new Promise<{ success: boolean; error?: string }>((res) => {
        resolve = res;
      });
      return { promise, resolve };
    };

    const firstUpdate = createDeferred();
    const secondUpdate = createDeferred();
    fleetClientMocks.updateHierarchyNode
      .mockImplementationOnce(() => firstUpdate.promise)
      .mockImplementationOnce(() => secondUpdate.promise);

    const getAgentParentName = () => {
      const raw = localStorageState.clawdstrike_policy_hierarchy;
      expect(raw).toBeDefined();
      const hierarchy = JSON.parse(raw!);
      const agentEntry = Object.values(hierarchy.nodes).find(
        (node) =>
          typeof node === "object" &&
          node !== null &&
          "name" in node &&
          node.name === "agent-coder-01",
      ) as { parentId: string };
      const parent = hierarchy.nodes[agentEntry.parentId] as { name: string };
      return parent.name;
    };

    const moveAgent = (targetTeamName: string) => {
      const source = screen
        .getAllByText("agent-coder-01")[0]
        .closest("div[draggable='true']");
      const target = screen.getAllByText(targetTeamName)[0].closest("div");

      expect(source).not.toBeNull();
      expect(target).not.toBeNull();

      fireEvent.dragStart(source!);
      fireEvent.dragOver(target!);
      fireEvent.drop(target!);
    };

    try {
      renderWithProviders(<HierarchyPage />);

      await user.click(screen.getByRole("button", { name: "DEMO" }));

      moveAgent("Security");
      await waitFor(() => {
        expect(fleetClientMocks.updateHierarchyNode).toHaveBeenCalledTimes(1);
        expect(getAgentParentName()).toBe("Security");
      });

      moveAgent("Customer Support");
      await waitFor(() => {
        expect(fleetClientMocks.updateHierarchyNode).toHaveBeenCalledTimes(2);
        expect(getAgentParentName()).toBe("Customer Support");
      });

      await act(async () => {
        secondUpdate.resolve({ success: false, error: "second failure" });
        await secondUpdate.promise;
      });

      await waitFor(() => {
        expect(getAgentParentName()).toBe("Security");
      });

      await act(async () => {
        firstUpdate.resolve({ success: false, error: "first failure" });
        await firstUpdate.promise;
      });

      await waitFor(() => {
        expect(getAgentParentName()).toBe("Engineering");
      });
    } finally {
      warnSpy.mockRestore();
    }
  });
});
