import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { createElement } from "react";
import { registerView } from "../../../lib/plugins/view-registry";
import type { ViewRegistration } from "../../../lib/plugins/view-registry";
import {
  openPluginViewTab,
  closePluginViewTab,
  activatePluginViewTab,
  getOpenPluginViewTabs,
  getActivePluginViewTabId,
  setPluginViewTabTitle,
  setPluginViewTabDirty,
} from "../../../lib/plugins/plugin-view-tab-store";
import { ViewTabRenderer } from "../view-tab-renderer";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function PluginViewA(props: {
  viewId: string;
  isActive: boolean;
  storage: any;
  setTitle: (t: string) => void;
  setDirty: (d: boolean) => void;
}) {
  return createElement(
    "div",
    { "data-testid": "plugin-view-a" },
    `viewA active=${String(props.isActive)}`,
  );
}

function PluginViewB(props: {
  viewId: string;
  isActive: boolean;
  storage: any;
  setTitle: (t: string) => void;
  setDirty: (d: boolean) => void;
}) {
  return createElement(
    "div",
    { "data-testid": "plugin-view-b" },
    `viewB active=${String(props.isActive)}`,
  );
}

function SetTitleView(props: {
  viewId: string;
  isActive: boolean;
  storage: any;
  setTitle: (t: string) => void;
  setDirty: (d: boolean) => void;
}) {
  return createElement(
    "div",
    { "data-testid": "set-title-view" },
    createElement(
      "button",
      {
        "data-testid": "set-title-btn",
        onClick: () => props.setTitle("Updated Title"),
      },
      "Set Title",
    ),
    createElement(
      "button",
      {
        "data-testid": "set-dirty-btn",
        onClick: () => props.setDirty(true),
      },
      "Set Dirty",
    ),
  );
}

function makeView(
  overrides: Partial<ViewRegistration> & { id: string },
): ViewRegistration {
  return {
    slot: "editorTab",
    label: overrides.label ?? overrides.id,
    component: PluginViewA,
    ...overrides,
  };
}

describe("ViewTabRenderer", () => {
  const disposers: Array<() => void> = [];

  beforeEach(() => {
    disposers.push(registerView(makeView({ id: "p.viewA", label: "View A", component: PluginViewA })));
    disposers.push(registerView(makeView({ id: "p.viewB", label: "View B", component: PluginViewB })));
    disposers.push(registerView(makeView({ id: "p.settitle", label: "SetTitle", component: SetTitleView })));
  });

  afterEach(() => {
    // Close any open tabs
    for (const tab of getOpenPluginViewTabs()) {
      closePluginViewTab(tab.viewId);
    }
    // Unregister views
    for (const d of disposers) d();
    disposers.length = 0;
  });

  it("renders nothing when no plugin view tabs are open", () => {
    const { container } = render(createElement(ViewTabRenderer));
    expect(container.innerHTML).toBe("");
  });

  it("renders the plugin component when a tab is open and active", () => {
    openPluginViewTab("p.viewA");
    render(createElement(ViewTabRenderer));

    expect(screen.getByTestId("plugin-view-a")).toBeDefined();
    expect(screen.getByTestId("plugin-view-a").textContent).toContain("active=true");
  });

  it("passes isActive=true to the active tab and isActive=false to hidden tabs", () => {
    openPluginViewTab("p.viewA");
    openPluginViewTab("p.viewB");
    // viewB is now active
    render(createElement(ViewTabRenderer));

    expect(screen.getByTestId("plugin-view-a").textContent).toContain("active=false");
    expect(screen.getByTestId("plugin-view-b").textContent).toContain("active=true");
  });

  it("hidden tabs have display:none style", () => {
    openPluginViewTab("p.viewA");
    openPluginViewTab("p.viewB");
    // viewB is active, viewA is hidden
    render(createElement(ViewTabRenderer));

    const viewAWrapper = screen.getByTestId("plugin-view-a").closest("[data-plugin-tab-id]");
    const viewBWrapper = screen.getByTestId("plugin-view-b").closest("[data-plugin-tab-id]");

    expect(viewAWrapper).toBeDefined();
    expect(viewBWrapper).toBeDefined();
    expect((viewAWrapper as HTMLElement).style.display).toBe("none");
    expect((viewBWrapper as HTMLElement).style.display).toBe("block");
  });

  it("setTitle callback updates the tab store label", () => {
    openPluginViewTab("p.settitle");
    render(createElement(ViewTabRenderer));

    const btn = screen.getByTestId("set-title-btn");
    btn.click();

    const tabs = getOpenPluginViewTabs();
    expect(tabs[0].label).toBe("Updated Title");
  });

  it("setDirty callback updates the tab store dirty flag", () => {
    openPluginViewTab("p.settitle");
    render(createElement(ViewTabRenderer));

    const btn = screen.getByTestId("set-dirty-btn");
    btn.click();

    const tabs = getOpenPluginViewTabs();
    expect(tabs[0].dirty).toBe(true);
  });
});
