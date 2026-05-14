import { describe, it, expect, afterEach, vi, beforeEach } from "vitest";
import { createElement } from "react";
import {
  registerView,
  getView,
} from "../view-registry";
import type { ViewRegistration } from "../view-registry";
import {
  openPluginViewTab,
  closePluginViewTab,
  activatePluginViewTab,
  getOpenPluginViewTabs,
  getActivePluginViewTabId,
  onPluginViewTabChange,
  setPluginViewTabTitle,
  setPluginViewTabDirty,
} from "../plugin-view-tab-store";
import type { PluginViewTab } from "../plugin-view-tab-store";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function TestComponent() {
  return createElement("div", null, "test");
}

function makeView(
  overrides: Partial<ViewRegistration> & { id: string },
): ViewRegistration {
  return {
    slot: "editorTab",
    label: overrides.label ?? overrides.id,
    component: TestComponent,
    ...overrides,
  };
}

describe("plugin-view-tab-store", () => {
  const disposers: Array<() => void> = [];

  // Register some test views for each test
  beforeEach(() => {
    disposers.push(registerView(makeView({ id: "p.view1", label: "View 1" })));
    disposers.push(registerView(makeView({ id: "p.view2", label: "View 2" })));
    disposers.push(registerView(makeView({ id: "p.view3", label: "View 3", icon: "star" })));
  });

  afterEach(() => {
    // Close any open tabs
    for (const tab of getOpenPluginViewTabs()) {
      closePluginViewTab(tab.viewId);
    }
    // Unregister all test views
    for (const d of disposers) d();
    disposers.length = 0;
  });

  // ---- openPluginViewTab ----

  it("opens a tab by viewId, looking up ViewRegistration", () => {
    openPluginViewTab("p.view1");

    const tabs = getOpenPluginViewTabs();
    expect(tabs).toHaveLength(1);
    expect(tabs[0].viewId).toBe("p.view1");
    expect(tabs[0].label).toBe("View 1");
    expect(tabs[0].dirty).toBe(false);
  });

  it("sets the opened tab as active", () => {
    openPluginViewTab("p.view1");
    expect(getActivePluginViewTabId()).toBe("p.view1");
  });

  it("copies icon from ViewRegistration", () => {
    openPluginViewTab("p.view3");

    const tabs = getOpenPluginViewTabs();
    expect(tabs[0].icon).toBe("star");
  });

  it("throws when viewId is not registered", () => {
    expect(() => openPluginViewTab("nonexistent.view")).toThrow(
      'View "nonexistent.view" not registered',
    );
  });

  it("duplicate openPluginViewTab just activates the existing tab", () => {
    openPluginViewTab("p.view1");
    openPluginViewTab("p.view2");
    expect(getActivePluginViewTabId()).toBe("p.view2");

    // Re-open view1 should just activate it, not create a duplicate
    openPluginViewTab("p.view1");
    expect(getActivePluginViewTabId()).toBe("p.view1");

    const tabs = getOpenPluginViewTabs();
    expect(tabs).toHaveLength(2);
  });

  // ---- closePluginViewTab ----

  it("closes a tab and removes it from the list", () => {
    openPluginViewTab("p.view1");
    openPluginViewTab("p.view2");
    closePluginViewTab("p.view1");

    const tabs = getOpenPluginViewTabs();
    expect(tabs).toHaveLength(1);
    expect(tabs[0].viewId).toBe("p.view2");
  });

  it("closing the active tab activates the most recently active remaining tab", () => {
    openPluginViewTab("p.view1");
    openPluginViewTab("p.view2");
    openPluginViewTab("p.view3");

    // Active is view3. Closing view3 should activate view2 (next most recent)
    closePluginViewTab("p.view3");
    expect(getActivePluginViewTabId()).toBe("p.view2");
  });

  it("closing the last tab sets active to null", () => {
    openPluginViewTab("p.view1");
    closePluginViewTab("p.view1");
    expect(getActivePluginViewTabId()).toBeNull();
    expect(getOpenPluginViewTabs()).toHaveLength(0);
  });

  // ---- activatePluginViewTab ----

  it("activatePluginViewTab sets the active tab", () => {
    openPluginViewTab("p.view1");
    openPluginViewTab("p.view2");

    activatePluginViewTab("p.view1");
    expect(getActivePluginViewTabId()).toBe("p.view1");
  });

  it("activatePluginViewTab(null) clears the active tab", () => {
    openPluginViewTab("p.view1");
    activatePluginViewTab(null);
    expect(getActivePluginViewTabId()).toBeNull();
  });

  it("activatePluginViewTab throws for unknown viewId", () => {
    expect(() => activatePluginViewTab("nonexistent")).toThrow();
  });

  // ---- onPluginViewTabChange ----

  it("notifies listeners on open, close, and activate", () => {
    const listener = vi.fn();
    const unsub = onPluginViewTabChange(listener);

    openPluginViewTab("p.view1");
    expect(listener).toHaveBeenCalledTimes(1);

    openPluginViewTab("p.view2");
    expect(listener).toHaveBeenCalledTimes(2);

    activatePluginViewTab("p.view1");
    expect(listener).toHaveBeenCalledTimes(3);

    closePluginViewTab("p.view1");
    expect(listener).toHaveBeenCalledTimes(4);

    unsub();
  });

  it("unsubscribe stops notifications", () => {
    const listener = vi.fn();
    const unsub = onPluginViewTabChange(listener);
    unsub();

    openPluginViewTab("p.view1");
    expect(listener).not.toHaveBeenCalled();
  });

  // ---- getOpenPluginViewTabs snapshot ----

  it("returns tabs sorted by openedAt ascending", () => {
    openPluginViewTab("p.view1");
    openPluginViewTab("p.view2");
    openPluginViewTab("p.view3");

    const tabs = getOpenPluginViewTabs();
    expect(tabs[0].viewId).toBe("p.view1");
    expect(tabs[1].viewId).toBe("p.view2");
    expect(tabs[2].viewId).toBe("p.view3");
  });

  it("returns frozen empty array when no tabs open", () => {
    const tabs = getOpenPluginViewTabs();
    expect(tabs).toHaveLength(0);
    expect(Object.isFrozen(tabs)).toBe(true);
  });

  it("returns stable snapshot reference when no changes occur", () => {
    openPluginViewTab("p.view1");
    const snap1 = getOpenPluginViewTabs();
    const snap2 = getOpenPluginViewTabs();
    expect(snap1).toBe(snap2); // same identity
  });

  // ---- setPluginViewTabTitle / setPluginViewTabDirty ----

  it("setPluginViewTabTitle updates the tab label", () => {
    openPluginViewTab("p.view1");
    setPluginViewTabTitle("p.view1", "New Title");

    const tabs = getOpenPluginViewTabs();
    expect(tabs[0].label).toBe("New Title");
  });

  it("setPluginViewTabDirty updates the dirty flag", () => {
    openPluginViewTab("p.view1");
    setPluginViewTabDirty("p.view1", true);

    const tabs = getOpenPluginViewTabs();
    expect(tabs[0].dirty).toBe(true);

    setPluginViewTabDirty("p.view1", false);
    expect(getOpenPluginViewTabs()[0].dirty).toBe(false);
  });

  // ---- LRU eviction ----

  it("evicts the oldest hidden tab when hidden count exceeds MAX_KEPT_ALIVE (5)", () => {
    // Register additional test views for LRU
    for (let i = 4; i <= 8; i++) {
      disposers.push(registerView(makeView({ id: `p.view${i}`, label: `View ${i}` })));
    }

    // Open 7 tabs (view1..view7)
    for (let i = 1; i <= 7; i++) {
      openPluginViewTab(`p.view${i}`);
    }

    // After opening view7 (active), hidden tabs are view1-view6 (6 hidden).
    // MAX_KEPT_ALIVE = 5, so the oldest hidden tab (view1) should be evicted.
    const tabs = getOpenPluginViewTabs();
    const viewIds = tabs.map((t) => t.viewId);

    // view1 should have been evicted (oldest lastActiveAt among hidden)
    expect(viewIds).not.toContain("p.view1");
    // The active tab (view7) and 5 most recently active hidden tabs remain
    expect(tabs).toHaveLength(6);
    expect(getActivePluginViewTabId()).toBe("p.view7");
  });

  it("does not evict the active tab during LRU", () => {
    for (let i = 4; i <= 8; i++) {
      disposers.push(registerView(makeView({ id: `p.view${i}`, label: `View ${i}` })));
    }

    // Open 7 tabs
    for (let i = 1; i <= 7; i++) {
      openPluginViewTab(`p.view${i}`);
    }

    // Active tab (view7) should always remain
    expect(getActivePluginViewTabId()).toBe("p.view7");
    expect(getOpenPluginViewTabs().some((t) => t.viewId === "p.view7")).toBe(true);
  });
});
