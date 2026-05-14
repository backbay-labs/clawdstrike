import React from "react";
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useNavigate } from "react-router-dom";
import {
  DesktopLayout,
  shouldSyncLocationToActivePane,
} from "../desktop-layout";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { setActivePluginView } from "../active-plugin-view";
import { registerView } from "@/lib/plugins/view-registry";

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

vi.mock("@/lib/commands/init-commands", () => ({
  InitCommands: () => null,
}));

vi.mock("@/features/policy/stores/policy-store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/features/policy/stores/policy-store")>();
  return { ...actual };
});

vi.mock("@/lib/workbench/use-auto-save", () => ({
  useAutoSave: () => ({
    pendingRecovery: [],
    dismissRecovery: vi.fn(),
    restoreRecovery: vi.fn(),
  }),
}));

vi.mock("@/components/desktop/titlebar", () => ({
  Titlebar: () => (
    <header>
      <span>Clawdstrike</span>
      <span>Workbench</span>
    </header>
  ),
}));

vi.mock("@/features/activity-bar/components/activity-bar", () => ({
  ActivityBar: () => (
    <aside role="complementary">
      <span>Editor</span>
      <span>Lab</span>
    </aside>
  ),
}));

vi.mock("@/features/activity-bar/components/sidebar-panel", () => ({
  SidebarPanel: () => null,
}));

vi.mock("@/features/activity-bar/components/sidebar-resize-handle", () => ({
  SidebarResizeHandle: () => null,
}));

vi.mock("@/features/navigation/quick-open-dialog", () => ({
  QuickOpenDialog: () => null,
}));

vi.mock("@/features/right-sidebar/components/right-sidebar", () => ({
  RightSidebar: () => null,
}));

vi.mock("@/features/right-sidebar/components/right-sidebar-resize-handle", () => ({
  RightSidebarResizeHandle: () => null,
}));

vi.mock("@/features/spirit/components/spirit-field-injector", () => ({
  SpiritFieldInjector: () => null,
}));

vi.mock("@/features/spirit/components/spirit-mood-reactor", () => ({
  SpiritMoodReactor: () => null,
}));

vi.mock("@/features/spirit/components/spirit-experience-tracker", () => ({
  SpiritExperienceTracker: () => null,
}));

vi.mock("@/features/hunt/components/HuntTelemetryBridge", () => ({
  HuntTelemetryBridge: () => null,
}));

vi.mock("@/features/observatory/components/ObservatoryTelemetryBridge", () => ({
  ObservatoryTelemetryBridge: () => null,
}));

vi.mock("@/features/right-sidebar/stores/right-sidebar-store", () => ({
  useRightSidebarStore: vi.fn((selector) => selector({ visible: false })),
}));

vi.mock("@/components/ui/resizable", () => ({
  ResizableHandle: () => null,
  ResizablePanel: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  ResizablePanelGroup: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

vi.mock("@/features/panes/pane-session", () => ({
  savePaneSession: vi.fn(),
  loadPaneSession: () => null,
}));

vi.mock("@/features/bottom-pane/bottom-pane-store", () => ({
  useBottomPaneStore: Object.assign(
    vi.fn((selector) => selector({ isOpen: false, size: 30, setSize: vi.fn() })),
    {
      getState: vi.fn(() => ({ isOpen: false, size: 30, setSize: vi.fn() })),
      subscribe: vi.fn(() => () => {}),
    },
  ),
}));

vi.mock("@/components/desktop/status-bar", () => ({
  StatusBar: () => <footer role="contentinfo">Status</footer>,
}));

vi.mock("@/components/desktop/shortcut-provider", () => ({
  ShortcutProvider: () => null,
}));

vi.mock("@/components/desktop/command-palette", () => ({
  CommandPalette: () => null,
}));

vi.mock("@/components/desktop/crash-recovery-banner", () => ({
  CrashRecoveryBanner: () => null,
}));

vi.mock("@/features/bottom-pane/bottom-pane", () => ({
  BottomPane: () => <div data-testid="bottom-pane">Bottom Pane</div>,
}));

vi.mock("@/features/panes/pane-root", () => ({
  PaneRoot: () => <div data-testid="pane-root">Pane Root</div>,
}));

vi.mock("@/features/panes/pane-store", () => ({
  getActivePaneRoute: vi.fn(() => ""),
  usePaneStore: Object.assign(
    vi.fn((selector) => selector({ root: {}, activePaneId: "main" })),
    {
      getState: vi.fn(() => ({
        root: {},
        activePaneId: "main",
        syncRoute: vi.fn(),
      })),
    },
  ),
}));

vi.mock("@/components/desktop/workbench-routes", () => ({
  normalizeWorkbenchRoute: (route: string) => route,
}));

afterEach(() => {
  usePolicyTabsStore.getState()._reset();
  setActivePluginView(null);
  cleanup();
});

function NavigateHarness() {
  const navigate = useNavigate();

  return (
    <button type="button" onClick={() => navigate("/guards")}>
      navigate-guards
    </button>
  );
}

function renderLayout(route = "/editor", withDirtyBackgroundTab = false) {
  if (withDirtyBackgroundTab) {
    const { tabs } = usePolicyTabsStore.getState();
    if (tabs.length > 0) {
      usePolicyTabsStore.getState().setDirty(tabs[0].id, true);
    }
  }

  return render(
    <MemoryRouter initialEntries={[route]}>
      <DesktopLayout />
    </MemoryRouter>,
  );
}

describe("DesktopLayout", () => {
  it("renders the titlebar", () => {
    renderLayout();

    expect(screen.getByText("Clawdstrike")).toBeInTheDocument();
    expect(screen.getByText("Workbench")).toBeInTheDocument();
  });

  it("renders the sidebar", () => {
    renderLayout();

    expect(screen.getByRole("complementary")).toBeInTheDocument();
    expect(screen.getByText("Editor")).toBeInTheDocument();
    expect(screen.getByText("Lab")).toBeInTheDocument();
  });

  it("renders the status bar", () => {
    renderLayout();

    expect(screen.getByRole("contentinfo")).toBeInTheDocument();
  });

  it("renders the pane root", () => {
    renderLayout("/editor");

    expect(screen.getByTestId("pane-root")).toBeInTheDocument();
    expect(screen.getByText("Pane Root")).toBeInTheDocument();
  });

  it("keeps the pane root mounted across routes", () => {
    renderLayout("/simulator");

    expect(screen.getByTestId("pane-root")).toBeInTheDocument();
  });

  it("has a flex column layout structure", () => {
    renderLayout();

    const root = screen.getByText("Clawdstrike").closest("div.flex.flex-col");
    expect(root).toBeInTheDocument();
  });

  it("has a flex row section for sidebar + content", () => {
    renderLayout();

    const sidebar = screen.getByRole("complementary");
    const flexRow = sidebar.parentElement;
    expect(flexRow).toBeInTheDocument();
    expect(flexRow!.className).toContain("flex");
    expect(flexRow!.className).toContain("flex-1");
  });

  it("warns before unload when a background tab is dirty", () => {
    renderLayout("/editor", true);

    const event = new Event("beforeunload", { cancelable: true });
    const preventDefault = vi.spyOn(event, "preventDefault");

    window.dispatchEvent(event);

    expect(preventDefault).toHaveBeenCalled();
  });

  it("clears the active plugin panel when navigation changes routes", async () => {
    const disposeView = registerView({
      id: "test-plugin.panel",
      slot: "activityBarPanel",
      label: "Plugin Panel",
      component: () => <div data-testid="plugin-view">Plugin View</div>,
    });
    setActivePluginView("test-plugin.panel");

    render(
      <MemoryRouter initialEntries={["/home"]}>
        <NavigateHarness />
        <DesktopLayout />
      </MemoryRouter>,
    );

    expect(screen.getByTestId("plugin-view")).toBeInTheDocument();
    expect(screen.queryByTestId("pane-root")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "navigate-guards" }));

    await waitFor(() => {
      expect(screen.queryByTestId("plugin-view")).not.toBeInTheDocument();
    });
    expect(screen.getByTestId("pane-root")).toBeInTheDocument();

    disposeView();
  });

  it("skips syncing a stale browser route into a pane that already switched views", () => {
    expect(
      shouldSyncLocationToActivePane("/overview", "/home", "/home", "/editor"),
    ).toBe(false);
    expect(
      shouldSyncLocationToActivePane(
        "/editor",
        "/lab?tab=simulate",
        "/lab?tab=simulate",
        "/editor",
      ),
    ).toBe(true);
  });
});
