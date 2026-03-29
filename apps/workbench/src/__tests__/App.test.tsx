import React from "react";
import { describe, it, expect, vi, afterEach } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { App } from "../App";
import * as tauriBridge from "@/lib/tauri-bridge";
import { useProjectStore } from "@/features/project/stores/project-store";
import { usePaneStore } from "@/features/panes/pane-store";

const READY_ROOTS = {
  ready: true,
  settled: true,
  pendingRootIds: [] as string[],
  blockedRootIds: [] as string[],
  elapsedMs: 0,
};

const {
  bootstrapWorkspaceRegistryNativeMock,
  bootstrapDefaultWorkspaceContentMock,
  readDetectionDirMock,
} = vi.hoisted(() => ({
  bootstrapWorkspaceRegistryNativeMock: vi.fn(),
  bootstrapDefaultWorkspaceContentMock: vi.fn(),
  readDetectionDirMock: vi.fn(async () => []),
}));

// Mock tauri bridge
vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

vi.mock("@/lib/tauri-commands", async () => {
  const actual = await vi.importActual<typeof import("@/lib/tauri-commands")>(
    "@/lib/tauri-commands",
  );
  return {
    ...actual,
    bootstrapWorkspaceRegistryNative: bootstrapWorkspaceRegistryNativeMock,
  };
});

vi.mock("@/features/project/workspace-bootstrap", async () => {
  const actual = await vi.importActual<typeof import("@/features/project/workspace-bootstrap")>(
    "@/features/project/workspace-bootstrap",
  );
  return {
    ...actual,
    bootstrapDefaultWorkspaceContent: bootstrapDefaultWorkspaceContentMock,
  };
});

vi.mock("@/lib/workbench/e2e-bridge", () => ({
  getWorkbenchE2EBridge: () => ({
    readDetectionDir: readDetectionDirMock,
    invoke: undefined,
  }),
  hasWorkbenchE2EInvoke: () => false,
}));

// Mock page components to avoid pulling in heavy dependency trees.
// Each mock renders a simple div with a data-testid for identification.
vi.mock("@/components/workbench/home/home-page", () => ({
  HomePage: () => <div data-testid="page-home">HomePage</div>,
}));

vi.mock("@/components/workbench/lab/lab-layout", () => ({
  LabLayout: () => <div data-testid="page-lab">LabLayout</div>,
}));

vi.mock("@/components/workbench/compare/compare-layout", () => ({
  CompareLayout: () => <div data-testid="page-compare">CompareLayout</div>,
}));

vi.mock("@/components/workbench/compliance/compliance-dashboard", () => ({
  ComplianceDashboard: () => <div data-testid="page-compliance">ComplianceDashboard</div>,
}));

vi.mock("@/components/workbench/receipts/receipt-inspector", () => ({
  ReceiptInspector: () => <div data-testid="page-receipts">ReceiptInspector</div>,
}));

vi.mock("@/components/workbench/library/library-gallery", () => ({
  LibraryGallery: () => <div data-testid="page-library">LibraryGallery</div>,
}));

vi.mock("@/components/workbench/missions/mission-control-page", () => ({
  MissionControlPage: () => <div data-testid="page-missions">MissionControlPage</div>,
}));

vi.mock("@/components/workbench/identity/identity-prompt", () => ({
  IdentityPrompt: () => null,
}));

// Mock DesktopLayout to avoid deep dependency chains while providing route-based rendering.
// The real DesktopLayout renders routes through PaneRoot -> PaneRouteRenderer -> useRoutes.
// We replace it with a simple shell that renders routes directly using the same route definitions.
vi.mock("@/components/desktop/desktop-layout", async () => {
  const { useRoutes, Navigate } = await import("react-router-dom");
  const { HomePage } = await import("@/components/workbench/home/home-page");
  const { LabLayout } = await import("@/components/workbench/lab/lab-layout");
  const { CompareLayout } = await import("@/components/workbench/compare/compare-layout");
  const { ComplianceDashboard } = await import("@/components/workbench/compliance/compliance-dashboard");
  const { ReceiptInspector } = await import("@/components/workbench/receipts/receipt-inspector");
  const { LibraryGallery } = await import("@/components/workbench/library/library-gallery");
  const { MissionControlPage } = await import("@/components/workbench/missions/mission-control-page");

  return {
    DesktopLayout: () => {
      const element = useRoutes([
        { index: true, element: <Navigate to="/home" replace /> },
        { path: "home", element: <HomePage /> },
        { path: "editor", element: <Navigate to="/home" replace /> },
        { path: "lab", element: <LabLayout /> },
        { path: "simulator", element: <Navigate to="/lab?tab=simulate" replace /> },
        { path: "compare", element: <CompareLayout /> },
        { path: "compliance", element: <ComplianceDashboard /> },
        { path: "receipts", element: <ReceiptInspector /> },
        { path: "library", element: <LibraryGallery /> },
        { path: "missions", element: <MissionControlPage /> },
        { path: "*", element: <Navigate to="/home" replace /> },
      ]);
      return (
        <div className="flex flex-col h-screen w-screen">
          <header>
            <span>Clawdstrike</span>
            <span>Workbench</span>
          </header>
          <div className="flex flex-1 min-h-0">
            <aside role="complementary">
              <span>Editor</span>
              <span>Lab</span>
              <span>Mission Control</span>
            </aside>
            <main>{element}</main>
          </div>
        </div>
      );
    },
  };
});

// Mock WorkbenchBootstraps transitive deps
vi.mock("@/features/operator/stores/operator-store", () => ({
  useOperator: () => ({ currentOperator: null, setOperator: vi.fn() }),
  useOperatorStore: Object.assign(
    () => ({
      currentOperator: null,
      actions: {
        setCurrentOperator: vi.fn(),
      },
    }),
    {
      use: {
        currentOperator: () => null,
        actions: () => ({
          setCurrentOperator: vi.fn(),
        }),
      },
      getState: () => ({
        currentOperator: null,
      }),
    },
  ),
}));

vi.mock("@/features/fleet/use-fleet-connection", () => ({
  useFleetConnection: () => ({ connection: { connected: false }, connect: vi.fn(), disconnect: vi.fn() }),
  useFleetConnectionStore: Object.assign(
    () => ({
      connection: { connected: false, hushdUrl: "", controlApiUrl: "", hushdHealth: null, agentCount: 0 },
      agents: [],
      error: null,
      sseState: "idle" as const,
      remotePolicyInfo: null,
      actions: {
        connect: vi.fn(),
        disconnect: vi.fn(),
        testConnection: vi.fn(),
        refreshAgents: vi.fn(),
        refreshRemotePolicy: vi.fn(),
        getCredentials: vi.fn(() => ({ apiKey: "", controlApiToken: "" })),
        getAuthenticatedConnection: vi.fn(() => ({
          connected: false,
          hushdUrl: "",
          controlApiUrl: "",
          apiKey: "",
          controlApiToken: "",
          hushdHealth: null,
          agentCount: 0,
        })),
      },
    }),
    {
      use: {
        connection: () => ({
          connected: false,
          hushdUrl: "",
          controlApiUrl: "",
          hushdHealth: null,
          agentCount: 0,
        }),
        agents: () => [],
        error: () => null,
        sseState: () => "idle" as const,
        remotePolicyInfo: () => null,
        actions: () => ({
          connect: vi.fn(),
          disconnect: vi.fn(),
          testConnection: vi.fn(),
          refreshAgents: vi.fn(),
          refreshRemotePolicy: vi.fn(),
          getCredentials: vi.fn(() => ({ apiKey: "", controlApiToken: "" })),
          getAuthenticatedConnection: vi.fn(() => ({
            connected: false,
            hushdUrl: "",
            controlApiUrl: "",
            apiKey: "",
            controlApiToken: "",
            hushdHealth: null,
            agentCount: 0,
          })),
        }),
      },
      getState: () => ({
        connection: {
          connected: false,
          hushdUrl: "",
          controlApiUrl: "",
          hushdHealth: null,
          agentCount: 0,
        },
        agents: [],
        error: null,
        sseState: "idle" as const,
        remotePolicyInfo: null,
      }),
    },
  ),
}));

vi.mock("@/features/presence/use-presence-file-tracking", () => ({
  usePresenceFileTracking: () => {},
}));

vi.mock("@/features/settings/use-hint-settings", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/features/settings/use-hint-settings")>();
  return {
    ...actual,
    useHintSettingsSafe: () => ({}),
  };
});

vi.mock("@/features/settings/secure-store", () => ({
  secureStore: {
    init: () => Promise.resolve(),
    get: () => Promise.resolve(null),
    set: () => Promise.resolve(),
    delete: () => Promise.resolve(),
    has: () => Promise.resolve(false),
  },
  migrateCredentialsToStronghold: () => Promise.resolve(),
}));

vi.mock("@/lib/plugins/threat-intel/bootstrap", () => ({
  bootstrapThreatIntelPlugins: () => Promise.resolve(),
}));

vi.mock("@/features/findings/hooks/use-signal-correlator", () => ({
  useSignalCorrelator: () => {},
}));

vi.mock("@/features/presence/use-presence-connection", () => ({
  usePresenceConnection: () => {},
  getPresenceSocket: () => null,
}));

vi.mock("@/features/policy/hooks/use-policy-bootstrap", () => ({
  usePolicyBootstrap: () => {},
}));

vi.mock("@/features/panes/pane-session", () => ({
  savePaneSession: vi.fn(),
  loadPaneSession: () => null,
  loadPaneSessionWithRouteMapper: () => null,
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.mocked(tauriBridge.isDesktop).mockReturnValue(false);
  localStorage.clear();
  window.location.hash = "";
});

describe("App", () => {
  it("renders the desktop layout shell", () => {
    render(<App />);

    // Brand should be visible in the titlebar (split into two spans)
    return waitFor(() => {
      expect(screen.getByText("Clawdstrike")).toBeTruthy();
      expect(screen.getByText("Workbench")).toBeTruthy();
    });
  });

  it("default route redirects to /home", async () => {
    render(<App />);

    // The HashRouter starts at #/ which should redirect to /home
    await waitFor(() => {
      expect(screen.getByTestId("page-home")).toBeTruthy();
    });
  });

  it("redirects /editor to /home", async () => {
    // HashRouter uses window.location.hash, set it before render
    window.location.hash = "#/editor";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-home")).toBeTruthy();
    });
  });

  it("redirects simulator legacy route to /lab?tab=simulate", async () => {
    window.location.hash = "#/simulator";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-lab")).toBeTruthy();
      expect(window.location.hash).toContain("/lab?tab=simulate");
    });
  });

  it("renders the compare route", async () => {
    window.location.hash = "#/compare";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-compare")).toBeTruthy();
    });
  });

  it("renders the compliance route", async () => {
    window.location.hash = "#/compliance";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-compliance")).toBeTruthy();
    });
  });

  it("renders the receipts route", async () => {
    window.location.hash = "#/receipts";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-receipts")).toBeTruthy();
    });
  });

  it("renders the library route", async () => {
    window.location.hash = "#/library";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-library")).toBeTruthy();
    });
  });

  it("renders the mission control route", async () => {
    window.location.hash = "#/missions";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-missions")).toBeTruthy();
    });
  });

  it("redirects unknown routes to /home", async () => {
    window.location.hash = "#/nonexistent-route";
    render(<App />);

    await waitFor(() => {
      expect(screen.getByTestId("page-home")).toBeTruthy();
    });
  });

  it("keeps workbench state available to the shell", async () => {
    render(<App />);

    // This test uses a lightweight DesktopLayout mock, so assert the shell it
    // renders instead of the real activity bar internals.
    await waitFor(() => {
      expect(screen.getByText("Clawdstrike")).toBeTruthy();
      expect(screen.getByText("Workbench")).toBeTruthy();
      expect(screen.getByText("Mission Control")).toBeTruthy();
    });
  });

  it("hydrates the workspace store from the backend registry and clears legacy roots on success", async () => {
    vi.mocked(tauriBridge.isDesktop).mockReturnValue(true);
    localStorage.setItem(
      "clawdstrike_workspace_roots",
      JSON.stringify(["/Users/test/.clawdstrike/workspace"]),
    );
    const originalActions = useProjectStore.getState().actions;
    const initFromWorkspaceRegistry = vi.fn(async () => {});
    const waitForRootsReady = vi.fn(async () => READY_ROOTS);
    const loadRoot = vi.fn(async () => {});
    useProjectStore.setState({
      project: null,
      loading: false,
      error: null,
      filter: "",
      formatFilter: null,
      fileStatuses: new Map(),
      defaultRootId: null,
      orderedRootIds: [],
      rootsById: new Map(),
      rootStatusById: new Map(),
      rootErrorById: new Map(),
      rootRequestedVersionById: new Map(),
      rootCommittedVersionById: new Map(),
      projectsById: new Map(),
      projectRoots: [],
      projects: new Map(),
      actions: {
        ...originalActions,
        initFromWorkspaceRegistry,
        waitForRootsReady,
        loadRoot,
      },
    });
    bootstrapWorkspaceRegistryNativeMock.mockResolvedValue({
      snapshot: {
        version: 1,
        defaultRootId: "root-default",
        orderedRootIds: ["root-default"],
        roots: [
          {
            rootId: "root-default",
            canonicalPath: "/Users/test/.clawdstrike",
            displayPath: "/Users/test/.clawdstrike",
            label: ".clawdstrike",
            kind: "default_home",
            provenance: "bootstrap",
            isDefault: true,
            aliases: ["/Users/test/.clawdstrike/workspace"],
          },
        ],
      },
      migratedLegacyRoots: ["/Users/test/.clawdstrike/workspace"],
      droppedLegacyRoots: [],
    });
    bootstrapDefaultWorkspaceContentMock.mockResolvedValue(true);

    render(<App />);

    await waitFor(() => {
      expect(bootstrapWorkspaceRegistryNativeMock).toHaveBeenCalledWith([
        "/Users/test/.clawdstrike/workspace",
      ]);
    });

    await waitFor(() => {
      expect(useProjectStore.getState().defaultRootId).toBe("root-default");
    });

    expect(localStorage.getItem("clawdstrike_workspace_roots")).toBeNull();
    expect(initFromWorkspaceRegistry).toHaveBeenCalledTimes(1);
    expect(waitForRootsReady).toHaveBeenCalled();
    expect(bootstrapDefaultWorkspaceContentMock).toHaveBeenCalledWith(
      "root-default",
    );
    expect(loadRoot).toHaveBeenCalledWith("root-default");
  });

  it("leaves legacy roots intact when backend registry bootstrap fails", async () => {
    vi.mocked(tauriBridge.isDesktop).mockReturnValue(true);
    localStorage.setItem(
      "clawdstrike_workspace_roots",
      JSON.stringify(["/Users/test/.clawdstrike/workspace"]),
    );
    bootstrapWorkspaceRegistryNativeMock.mockResolvedValue(null);

    render(<App />);

    await waitFor(() => {
      expect(bootstrapWorkspaceRegistryNativeMock).toHaveBeenCalledWith([
        "/Users/test/.clawdstrike/workspace",
      ]);
    });

    expect(localStorage.getItem("clawdstrike_workspace_roots")).toBe(
      JSON.stringify(["/Users/test/.clawdstrike/workspace"]),
    );
    expect(bootstrapDefaultWorkspaceContentMock).not.toHaveBeenCalled();
  });

  it("waits for workspace readiness before restoring the pane session", async () => {
    vi.mocked(tauriBridge.isDesktop).mockReturnValue(true);
    const originalActions = useProjectStore.getState().actions;
    let resolveReady: (() => void) | null = null;
    const readinessGate = new Promise<{
      ready: boolean;
      settled: boolean;
      pendingRootIds: string[];
      blockedRootIds: string[];
      elapsedMs: number;
    }>((resolve) => {
      resolveReady = () => resolve({
        ready: true,
        settled: true,
        pendingRootIds: [],
        blockedRootIds: [],
        elapsedMs: 25,
      });
    });
    const initFromWorkspaceRegistry = vi.fn(async () => {});
    const waitForRootsReady = vi.fn(() => readinessGate);
    const restoreSessionSpy = vi
      .spyOn(usePaneStore.getState(), "restoreSession")
      .mockReturnValue(0);

    useProjectStore.setState((state) => ({
      ...state,
      actions: {
        ...originalActions,
        initFromWorkspaceRegistry,
        waitForRootsReady,
        loadRoot: vi.fn(async () => {}),
      },
    }));
    bootstrapWorkspaceRegistryNativeMock.mockResolvedValue({
      snapshot: {
        version: 1,
        defaultRootId: "root-default",
        orderedRootIds: ["root-default"],
        roots: [
          {
            rootId: "root-default",
            canonicalPath: "/Users/test/.clawdstrike",
            displayPath: "/Users/test/.clawdstrike",
            label: ".clawdstrike",
            kind: "default_home",
            provenance: "bootstrap",
            isDefault: true,
            aliases: ["/Users/test/.clawdstrike/workspace"],
          },
        ],
      },
      migratedLegacyRoots: [],
      droppedLegacyRoots: [],
    });
    bootstrapDefaultWorkspaceContentMock.mockResolvedValue(false);

    render(<App />);

    await waitFor(() => {
      expect(initFromWorkspaceRegistry).toHaveBeenCalledTimes(1);
      expect(waitForRootsReady).toHaveBeenCalledTimes(1);
    });
    expect(restoreSessionSpy).not.toHaveBeenCalled();

    expect(resolveReady).not.toBeNull();
    resolveReady!();

    await waitFor(() => {
      expect(restoreSessionSpy).toHaveBeenCalledTimes(1);
    });
    restoreSessionSpy.mockRestore();
  });

  it("skips session restore when workspace roots settle without becoming usable", async () => {
    vi.mocked(tauriBridge.isDesktop).mockReturnValue(true);
    const originalActions = useProjectStore.getState().actions;
    const initFromWorkspaceRegistry = vi.fn(async () => {});
    const waitForRootsReady = vi.fn(async () => ({
      ready: false,
      settled: true,
      pendingRootIds: [],
      blockedRootIds: ["root-default"],
      elapsedMs: 4_000,
    }));
    const restoreSessionSpy = vi
      .spyOn(usePaneStore.getState(), "restoreSession")
      .mockReturnValue(0);
    const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    useProjectStore.setState((state) => ({
      ...state,
      actions: {
        ...originalActions,
        initFromWorkspaceRegistry,
        waitForRootsReady,
        loadRoot: vi.fn(async () => {}),
      },
    }));
    bootstrapWorkspaceRegistryNativeMock.mockResolvedValue({
      snapshot: {
        version: 1,
        defaultRootId: "root-default",
        orderedRootIds: ["root-default"],
        roots: [
          {
            rootId: "root-default",
            canonicalPath: "/Users/test/.clawdstrike",
            displayPath: "/Users/test/.clawdstrike",
            label: ".clawdstrike",
            kind: "default_home",
            provenance: "bootstrap",
            isDefault: true,
            aliases: [],
          },
        ],
      },
      migratedLegacyRoots: [],
      droppedLegacyRoots: [],
    });
    bootstrapDefaultWorkspaceContentMock.mockResolvedValue(false);

    render(<App />);

    await waitFor(() => {
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        "[workspace-bootstrap]",
        expect.objectContaining({
          event: "roots_ready_timeout",
          stage: "initial",
          pendingRootIds: [],
          blockedRootIds: ["root-default"],
          elapsedMs: 4_000,
        }),
      );
    });
    await waitFor(() => {
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        "[workspace-bootstrap]",
        expect.objectContaining({
          event: "session_restore_skipped_unready_roots",
          pendingRootIds: [],
          blockedRootIds: ["root-default"],
          elapsedMs: 4_000,
        }),
      );
    });
    expect(restoreSessionSpy).not.toHaveBeenCalled();

    consoleWarnSpy.mockRestore();
    restoreSessionSpy.mockRestore();
  });
});
