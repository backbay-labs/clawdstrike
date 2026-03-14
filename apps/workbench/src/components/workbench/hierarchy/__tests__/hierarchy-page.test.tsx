import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import * as hierarchyEngine from "@/lib/workbench/hierarchy-engine";
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
      getCredentials: () => ({ apiKey: "test-api-key", controlApiToken: "test-control-token" }),
      getAuthenticatedConnection: () => ({ connected: true, hushdUrl: "http://localhost:9876", controlApiUrl: "http://localhost:9877", apiKey: "test-api-key", controlApiToken: "test-control-token", hushdHealth: null, agentCount: 0 }),
    }),
  };
});

import { HierarchyPage, resolvePendingHierarchyParentId } from "../hierarchy-page";

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

  it("preserves explicit child order when normalizing a hierarchy", () => {
    const normalized = hierarchyEngine.normalizeHierarchy({
      rootId: "root",
      nodes: {
        root: {
          id: "root",
          name: "Root",
          type: "org",
          parentId: null,
          children: ["child-b", "child-a"],
          metadata: {},
        },
        "child-a": {
          id: "child-a",
          name: "Child A",
          type: "team",
          parentId: "root",
          children: [],
          metadata: {},
        },
        "child-b": {
          id: "child-b",
          name: "Child B",
          type: "team",
          parentId: "root",
          children: [],
          metadata: {},
        },
      },
    });

    expect(normalized.nodes.root.children).toEqual(["child-b", "child-a"]);
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

  it("does not render metadata leaf badges on legacy agent leaves", async () => {
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

    expect(screen.queryByText(/^1 leaf$/)).not.toBeInTheDocument();
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
    expect(fleetClientMocks.createHierarchyNode).toHaveBeenCalledTimes(8);
    const pushedNames = fleetClientMocks.createHierarchyNode.mock.calls.map(([, input]) => input.name);
    expect(pushedNames).toEqual(
      expect.arrayContaining([
        "Security",
        "Customer Support",
        "agent-scanner-01",
        "agent-support-02",
      ]),
    );
    expect(pushedNames).not.toEqual(
      expect.arrayContaining([
        "agent-coder-01",
        "agent-reviewer-01",
        "agent-deployer-01",
      ]),
    );
  });

  it("confirms before push when leaf validation reports warnings", async () => {
    const user = userEvent.setup();
    localStorageState.clawdstrike_policy_hierarchy = JSON.stringify(
      hierarchyEngine.createDefaultHierarchy(),
    );
    const confirmSpy = vi.mocked(window.confirm);
    confirmSpy.mockReturnValueOnce(false);

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    expect(confirmSpy).toHaveBeenCalledWith(
      expect.stringContaining("validation warning(s)"),
    );
    expect(fleetClientMocks.createHierarchyNode).not.toHaveBeenCalled();
  });

  it("counts both errors and warnings in the push confirmation message", async () => {
    const user = userEvent.setup();
    localStorageState.clawdstrike_policy_hierarchy = JSON.stringify(
      hierarchyEngine.createDefaultHierarchy(),
    );
    const confirmSpy = vi.mocked(window.confirm);
    confirmSpy.mockReturnValueOnce(false);
    const validateAllLeavesSpy = vi
      .spyOn(hierarchyEngine, "validateAllLeaves")
      .mockReturnValue([
        {
          nodeId: "node-1",
          nodeName: "Leaf 1",
          message: "bad",
          severity: "error",
        },
        {
          nodeId: "node-2",
          nodeName: "Leaf 2",
          message: "warn",
          severity: "warning",
        },
        {
          nodeId: "node-3",
          nodeName: "Leaf 3",
          message: "warn",
          severity: "warning",
        },
      ]);

    try {
      renderWithProviders(<HierarchyPage />);

      await user.click(screen.getByRole("button", { name: "DEMO" }));
      await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

      expect(validateAllLeavesSpy).toHaveBeenCalled();
      expect(confirmSpy).toHaveBeenCalledWith(
        "There are 3 validation issue(s) in the hierarchy (1 error(s), 2 warning(s)). Push anyway?",
      );
      expect(fleetClientMocks.createHierarchyNode).not.toHaveBeenCalled();
    } finally {
      validateAllLeavesSpy.mockRestore();
    }
  });

  it("remaps local hierarchy ids to server-assigned ids after a successful push", async () => {
    const user = userEvent.setup();

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));

    const beforePush = JSON.parse(localStorageState.clawdstrike_policy_hierarchy) as {
      rootId: string;
      nodes: Record<string, { id: string; parentId: string | null }>;
    };
    const localRootId = beforePush.rootId;

    await user.click(screen.getByRole("button", { name: "Push to Fleet" }));

    await waitFor(() => {
      expect(screen.getByText("Pushed 11 nodes to fleet")).toBeInTheDocument();
    });

    await waitFor(() => {
      const afterPush = JSON.parse(localStorageState.clawdstrike_policy_hierarchy) as {
        rootId: string;
        nodes: Record<string, { id: string; parentId: string | null }>;
      };

      expect(afterPush.rootId).toBe("server-acme-corp");
      expect(afterPush.nodes[localRootId]).toBeUndefined();
      expect(afterPush.nodes["server-engineering"]?.parentId).toBe("server-acme-corp");
      expect(afterPush.nodes["server-agent-coder-01"]?.parentId).toBe("server-engineering");
    });
  });

  it("waits for pending parent ids to resolve before using them", async () => {
    let resolveParentId!: (value: string | null) => void;
    const pendingParentId = new Promise<string | null>((resolve) => {
      resolveParentId = resolve;
    });

    const resolvedParentIdPromise = resolvePendingHierarchyParentId(
      "local-endpoint",
      new Map([["local-endpoint", pendingParentId]]),
    );

    let settled = false;
    resolvedParentIdPromise.then(() => {
      settled = true;
    });

    await Promise.resolve();
    expect(settled).toBe(false);

    resolveParentId("remote-endpoint");

    await expect(resolvedParentIdPromise).resolves.toBe("remote-endpoint");
  });

  it("returns null for pending parent ids that never got a fleet id", async () => {
    await expect(
      resolvePendingHierarchyParentId(
        "local-endpoint",
        new Map([["local-endpoint", Promise.resolve(null)]]),
      ),
    ).resolves.toBeNull();
  });

  it("waits for pending backend ids before syncing drag-drop moves", async () => {
    const user = userEvent.setup();
    let resolveCreate!: (value: { success: boolean; id?: string }) => void;
    const pendingCreate = new Promise<{ success: boolean; id?: string }>((resolve) => {
      resolveCreate = resolve;
    });

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

    fleetClientMocks.createHierarchyNode.mockReset();
    fleetClientMocks.createHierarchyNode.mockImplementationOnce(() => pendingCreate);

    const teamRow = screen
      .getAllByText("Platform Team")[0]
      .closest("[draggable='true']") as HTMLElement | null;
    expect(teamRow).not.toBeNull();

    await user.hover(teamRow!);
    await waitFor(() => {
      expect(within(teamRow!).getByTitle("Add Endpoint")).toBeInTheDocument();
    });
    fireEvent.click(within(teamRow!).getByTitle("Add Endpoint"));
    await user.click(await screen.findByRole("button", { name: "Cancel" }));

    const runtimeRow = screen
      .getAllByText("Claude Runtime")[0]
      .closest("[draggable='true']") as HTMLElement | null;
    const newEndpointRow = screen
      .getAllByText(/endpoint-/)
      .find((element) => element.textContent?.startsWith("endpoint-"))
      ?.closest("[draggable='true']") as HTMLElement | null;

    expect(runtimeRow).not.toBeNull();
    expect(newEndpointRow).not.toBeNull();

    fireEvent.dragStart(runtimeRow!);
    fireEvent.dragOver(newEndpointRow!);
    fireEvent.drop(newEndpointRow!);

    expect(fleetClientMocks.updateHierarchyNode).not.toHaveBeenCalled();

    resolveCreate({ success: true, id: "remote-endpoint-2" });

    await waitFor(() => {
      expect(fleetClientMocks.updateHierarchyNode).toHaveBeenCalledWith(
        expect.objectContaining({ controlApiUrl: "http://localhost:9877" }),
        "runtime-1",
        { parent_id: "remote-endpoint-2" },
      );
    });
  });

  it("still allows dragging legacy agent leaves onto teams", async () => {
    const user = userEvent.setup();

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));
    expect(screen.getByRole("button", { name: "LIVE" })).toBeInTheDocument();

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

  it("still allows creating legacy agent leaves under teams", async () => {
    const user = userEvent.setup();

    renderWithProviders(<HierarchyPage />);

    await user.click(screen.getByRole("button", { name: "DEMO" }));

    const teamLabel = screen.getAllByText("Engineering")[0];
    const teamRow = teamLabel.closest("div[draggable='true']");
    expect(teamRow).not.toBeNull();

    fireEvent.mouseEnter(teamRow!);
    await user.click(screen.getByTitle("Add Agent"));

    await waitFor(() => {
      const storedHierarchy = JSON.parse(localStorageState.clawdstrike_policy_hierarchy) as {
        nodes: Record<string, { id: string; name: string; parentId: string | null; type: string }>;
      };
      const engineeringId = Object.values(storedHierarchy.nodes).find(
        (node) => node.name === "Engineering",
      )?.id;
      expect(engineeringId).toBeDefined();
      expect(
        Object.values(storedHierarchy.nodes).some(
          (node) =>
            node.type === "agent" &&
            node.parentId === engineeringId &&
            node.name.startsWith("agent-new-"),
        ),
      ).toBe(true);
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

  it("keeps the latest rollback when live sync failures resolve out of order", async () => {
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
        expect(getAgentParentName()).toBe("Security");
      });
    } finally {
      warnSpy.mockRestore();
    }
  });
});
