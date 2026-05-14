import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { createElement } from "react";
import type { ViewRegistration } from "@/lib/plugins/view-registry";

// ---------------------------------------------------------------------------
// Mock useViewsBySlot so we control plugin registrations
// ---------------------------------------------------------------------------

let mockPluginPanels: ViewRegistration[] = [];

vi.mock("@/lib/plugins/view-registry", () => ({
  useViewsBySlot: (slot: string) => {
    if (slot === "rightSidebarPanel") return mockPluginPanels;
    return [];
  },
}));

// Mock ViewContainer as a simple div showing the viewId
vi.mock("@/components/plugins/view-container", () => ({
  ViewContainer: ({ registration, isActive }: any) =>
    createElement("div", { "data-testid": `view-container-${registration.id}` },
      `viewId=${registration.id} active=${String(isActive ?? true)}`),
}));

import { RightSidebarPanels, type BuiltInPanel } from "../right-sidebar-panels";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function TestContent({ label }: { label: string }) {
  return createElement("div", { "data-testid": `content-${label}` }, label);
}

function makeBuiltInPanels(): BuiltInPanel[] {
  return [
    {
      id: "version-history",
      label: "Version History",
      icon: () => createElement("span", null, "VH"),
      content: createElement(TestContent, { label: "version-history-content" }),
    },
    {
      id: "guard-config",
      label: "Guard Config",
      icon: () => createElement("span", null, "GC"),
      content: createElement(TestContent, { label: "guard-config-content" }),
    },
  ];
}

function PluginComponent(props: any) {
  return createElement("div", { "data-testid": "plugin-sidebar-rendered" },
    `plugin sidebarWidth=${props.sidebarWidth ?? "undefined"}`);
}

function makePluginRegistration(overrides?: Partial<ViewRegistration>): ViewRegistration {
  return {
    id: "my-plugin.sidebar",
    slot: "rightSidebarPanel",
    label: "Plugin Sidebar",
    icon: "plug",
    component: PluginComponent,
    priority: 200,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("RightSidebarPanels", () => {
  beforeEach(() => {
    mockPluginPanels = [];
  });

  it("renders built-in panel buttons in the selector", () => {
    const panels = makeBuiltInPanels();
    render(
      createElement(RightSidebarPanels, {
        builtInPanels: panels,
        sidebarWidth: 280,
        activePanelId: null,
        onPanelChange: vi.fn(),
      }),
    );

    // Button labels should appear (using aria-label or title)
    expect(screen.getByLabelText("Version History")).toBeDefined();
    expect(screen.getByLabelText("Guard Config")).toBeDefined();
  });

  it("renders plugin panel buttons from useViewsBySlot alongside built-in buttons", () => {
    mockPluginPanels = [makePluginRegistration()];
    const panels = makeBuiltInPanels();

    render(
      createElement(RightSidebarPanels, {
        builtInPanels: panels,
        sidebarWidth: 280,
        activePanelId: null,
        onPanelChange: vi.fn(),
      }),
    );

    expect(screen.getByLabelText("Version History")).toBeDefined();
    expect(screen.getByLabelText("Guard Config")).toBeDefined();
    expect(screen.getByLabelText("Plugin Sidebar")).toBeDefined();
  });

  it("clicking a panel button calls onPanelChange with the panel id", () => {
    const onPanelChange = vi.fn();
    const panels = makeBuiltInPanels();

    render(
      createElement(RightSidebarPanels, {
        builtInPanels: panels,
        sidebarWidth: 280,
        activePanelId: null,
        onPanelChange,
      }),
    );

    fireEvent.click(screen.getByLabelText("Guard Config"));
    expect(onPanelChange).toHaveBeenCalledWith("guard-config");
  });

  it("active plugin panel renders ViewContainer with the registration", () => {
    const pluginReg = makePluginRegistration();
    mockPluginPanels = [pluginReg];
    const panels = makeBuiltInPanels();

    render(
      createElement(RightSidebarPanels, {
        builtInPanels: panels,
        sidebarWidth: 280,
        activePanelId: "my-plugin.sidebar",
        onPanelChange: vi.fn(),
      }),
    );

    expect(screen.getByTestId("view-container-my-plugin.sidebar")).toBeDefined();
  });

  it("when a plugin panel is removed from registry, its button disappears", () => {
    mockPluginPanels = [makePluginRegistration()];
    const panels = makeBuiltInPanels();
    const onPanelChange = vi.fn();

    const { rerender } = render(
      createElement(RightSidebarPanels, {
        builtInPanels: panels,
        sidebarWidth: 280,
        activePanelId: null,
        onPanelChange,
      }),
    );

    expect(screen.getByLabelText("Plugin Sidebar")).toBeDefined();

    // Simulate plugin removal
    mockPluginPanels = [];

    rerender(
      createElement(RightSidebarPanels, {
        builtInPanels: panels,
        sidebarWidth: 280,
        activePanelId: null,
        onPanelChange,
      }),
    );

    expect(screen.queryByLabelText("Plugin Sidebar")).toBeNull();
  });

  it("sidebarWidth prop is passed through to plugin components", () => {
    const pluginReg = makePluginRegistration();
    mockPluginPanels = [pluginReg];
    const panels = makeBuiltInPanels();

    render(
      createElement(RightSidebarPanels, {
        builtInPanels: panels,
        sidebarWidth: 320,
        activePanelId: "my-plugin.sidebar",
        onPanelChange: vi.fn(),
      }),
    );

    // ViewContainer is rendered with the plugin's registration
    const container = screen.getByTestId("view-container-my-plugin.sidebar");
    expect(container).toBeDefined();
  });

  it("clicking the active panel button again calls onPanelChange(null) to close", () => {
    const onPanelChange = vi.fn();
    const panels = makeBuiltInPanels();

    render(
      createElement(RightSidebarPanels, {
        builtInPanels: panels,
        sidebarWidth: 280,
        activePanelId: "version-history",
        onPanelChange,
      }),
    );

    // Click the already-active button
    fireEvent.click(screen.getByLabelText("Version History"));
    expect(onPanelChange).toHaveBeenCalledWith(null);
  });
});
