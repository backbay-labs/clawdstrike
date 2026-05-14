import React from "react";
import { describe, it, expect, vi, afterEach } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { App } from "../App";

// Mock tauri bridge
vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
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
}));

afterEach(() => {
  cleanup();
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
});
