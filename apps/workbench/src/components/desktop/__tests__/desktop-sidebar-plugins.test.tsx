/**
 * Tests for plugin activity bar integration in DesktopSidebar.
 *
 * These tests verify that plugin-contributed activity bar panel views
 * appear in the sidebar alongside built-in items, and that clicking
 * them activates the plugin view while clicking built-in items clears it.
 *
 * Note: The DesktopSidebar has deep dependencies (multi-policy-store ->
 * tauri-bridge -> @tauri-apps/*) that cannot be resolved in the test
 * environment. All heavy dependencies are mocked at the module level.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { createElement } from "react";
import type { ViewRegistration } from "@/lib/plugins/view-registry";

// ---------------------------------------------------------------------------
// Mock useViewsBySlot so we control plugin registrations
// ---------------------------------------------------------------------------

let mockPluginViews: ViewRegistration[] = [];

vi.mock("@/lib/plugins/view-registry", () => ({
  useViewsBySlot: (slot: string) => {
    if (slot === "activityBarPanel") return mockPluginViews;
    return [];
  },
  getView: (id: string) =>
    mockPluginViews.find((v) => v.id === id),
}));

// ---------------------------------------------------------------------------
// Mock active-plugin-view module
// ---------------------------------------------------------------------------

let mockActivePluginViewId: string | null = null;
const mockSetActivePluginView = vi.fn((id: string | null) => {
  mockActivePluginViewId = id;
});

vi.mock("../active-plugin-view", () => ({
  useActivePluginView: () => mockActivePluginViewId,
  setActivePluginView: (id: string | null) => mockSetActivePluginView(id),
}));

// ---------------------------------------------------------------------------
// Mock workbench stores and heavy dependencies to avoid tauri-bridge imports
// ---------------------------------------------------------------------------

const mockSidebarCollapsed = { current: false };

vi.mock("@/lib/workbench/multi-policy-store", () => ({
  useWorkbench: () => ({
    state: { ui: { sidebarCollapsed: mockSidebarCollapsed.current } },
    dispatch: vi.fn(),
  }),
  useMultiPolicy: () => ({ tabs: [], multiDispatch: vi.fn() }),
  MultiPolicyProvider: ({ children }: any) => children,
}));

vi.mock("@/lib/workbench/operator-store", () => ({
  useOperator: () => ({ currentOperator: null }),
  OperatorProvider: ({ children }: any) => children,
}));

vi.mock("@/lib/workbench/use-fleet-connection", () => ({
  useFleetConnection: () => ({
    connection: { connected: false, controlApiUrl: "" },
  }),
  FleetConnectionProvider: ({ children }: any) => children,
}));

vi.mock("@/lib/workbench/sentinel-store", () => ({
  useSentinels: () => ({ sentinels: [] }),
  SentinelProvider: ({ children }: any) => children,
}));

vi.mock("@/lib/workbench/finding-store", () => ({
  useFindings: () => ({ findings: [] }),
  FindingProvider: ({ children }: any) => children,
}));

vi.mock("@/lib/workbench/fleet-client", () => ({
  fleetClient: { fetchApprovals: vi.fn() },
}));

vi.mock("@/lib/workbench/approval-demo-data", () => ({
  DEMO_APPROVAL_REQUESTS: [],
}));

vi.mock("@/components/workbench/settings/identity-settings", () => ({
  SIGIL_SYMBOLS: {},
}));

vi.mock("@/lib/workbench/sentinel-manager", () => ({}));

vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
  isMacOS: vi.fn(() => false),
  minimizeWindow: vi.fn(),
  maximizeWindow: vi.fn(),
  closeWindow: vi.fn(),
}));

// Mock react-router-dom to avoid router context requirements
let mockPathname = "/editor";
vi.mock("react-router-dom", () => ({
  useLocation: () => ({ pathname: mockPathname }),
  Link: ({ children, to, onClick, ...rest }: any) =>
    createElement("a", { href: to, onClick, ...rest }, children),
}));

// ---------------------------------------------------------------------------
// Import after mocks
// ---------------------------------------------------------------------------

import { DesktopSidebar } from "../desktop-sidebar";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function PluginComponent(props: any) {
  return createElement("div", { "data-testid": "plugin-rendered" },
    `plugin isCollapsed=${props.isCollapsed ?? "undefined"}`);
}

function makePluginRegistration(overrides?: Partial<ViewRegistration>): ViewRegistration {
  return {
    id: "my-plugin.security-panel",
    slot: "activityBarPanel",
    label: "Security Scanner",
    icon: "shield",
    component: PluginComponent,
    priority: 200,
    meta: { section: "Security" },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("DesktopSidebar plugin activity bar integration", () => {
  beforeEach(() => {
    mockPluginViews = [];
    mockActivePluginViewId = null;
    mockSidebarCollapsed.current = false;
    mockPathname = "/editor";
    mockSetActivePluginView.mockClear();
  });

  it("does not render Plugins section when no plugins are registered", () => {
    render(createElement(DesktopSidebar));

    // Built-in sections should still render
    expect(screen.getByText("Detect & Respond")).toBeTruthy();
    expect(screen.getByText("Author & Test")).toBeTruthy();
    expect(screen.getByText("Platform")).toBeTruthy();

    // Plugins section should not render
    expect(screen.queryByText("Plugins")).toBeNull();
  });

  it("renders plugin item in sidebar when a plugin view is registered", () => {
    mockPluginViews = [makePluginRegistration()];

    render(createElement(DesktopSidebar));

    // Plugin section header should appear
    expect(screen.getByText("Plugins")).toBeTruthy();
    // Plugin item label should appear
    expect(screen.getByText("Security Scanner")).toBeTruthy();
  });

  it("clicking a plugin item calls setActivePluginView with the view id", () => {
    mockPluginViews = [makePluginRegistration()];

    render(createElement(DesktopSidebar));

    const pluginButton = screen.getByText("Security Scanner").closest("button");
    expect(pluginButton).toBeTruthy();

    fireEvent.click(pluginButton!);
    expect(mockSetActivePluginView).toHaveBeenCalledWith("my-plugin.security-panel");
  });

  it("clicking a built-in link calls setActivePluginView(null)", () => {
    mockPluginViews = [makePluginRegistration()];
    mockActivePluginViewId = "my-plugin.security-panel";

    render(createElement(DesktopSidebar));

    // Click a built-in item (Editor link)
    const editorLink = screen.getByText("Editor").closest("a");
    expect(editorLink).toBeTruthy();

    fireEvent.click(editorLink!);
    expect(mockSetActivePluginView).toHaveBeenCalledWith(null);
  });

  it("plugin item disappears when removed from registry (rerender)", () => {
    mockPluginViews = [makePluginRegistration()];

    const { rerender } = render(createElement(DesktopSidebar));

    // Plugin should be visible
    expect(screen.getByText("Security Scanner")).toBeTruthy();
    expect(screen.getByText("Plugins")).toBeTruthy();

    // Simulate plugin removal
    mockPluginViews = [];

    rerender(createElement(DesktopSidebar));

    // Plugin section and item should be gone
    expect(screen.queryByText("Security Scanner")).toBeNull();
    expect(screen.queryByText("Plugins")).toBeNull();
  });

  it("plugin item shows active styling when it is the active plugin view", () => {
    mockPluginViews = [makePluginRegistration()];
    mockActivePluginViewId = "my-plugin.security-panel";

    render(createElement(DesktopSidebar));

    const pluginButton = screen.getByText("Security Scanner").closest("button");
    expect(pluginButton).toBeTruthy();

    // Active plugin item should have the active text color
    expect(pluginButton!.className).toContain("text-[#ece7dc]");
  });

  it("plugin item shows inactive styling when no plugin view is active", () => {
    mockPluginViews = [makePluginRegistration()];
    mockActivePluginViewId = null;

    render(createElement(DesktopSidebar));

    const pluginButton = screen.getByText("Security Scanner").closest("button");
    expect(pluginButton).toBeTruthy();

    // Inactive plugin item should have the muted text color
    expect(pluginButton!.className).toContain("text-[#6f7f9a]");
  });

  it("renders multiple plugin items", () => {
    mockPluginViews = [
      makePluginRegistration({ id: "plugin-a.panel", label: "Plugin A", priority: 300 }),
      makePluginRegistration({ id: "plugin-b.panel", label: "Plugin B", priority: 100 }),
    ];

    render(createElement(DesktopSidebar));

    const pluginA = screen.getByText("Plugin A");
    const pluginB = screen.getByText("Plugin B");

    // Both should be present
    expect(pluginA).toBeTruthy();
    expect(pluginB).toBeTruthy();
  });

  it("built-in items show inactive styling when a plugin view is active", () => {
    mockPluginViews = [makePluginRegistration()];
    mockActivePluginViewId = "my-plugin.security-panel";
    mockPathname = "/editor";

    render(createElement(DesktopSidebar));

    // Even though the route matches /editor, the Editor link should not show active styling
    // because a plugin view is active
    const editorLink = screen.getByText("Editor").closest("a");
    expect(editorLink).toBeTruthy();
    expect(editorLink!.className).toContain("text-[#6f7f9a]");
  });
});
