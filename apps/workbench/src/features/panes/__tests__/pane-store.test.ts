import { beforeEach, describe, expect, it } from "vitest";
import { getActivePaneRoute, usePaneStore } from "../pane-store";
import { findPaneGroup, getAllPaneGroups, getPaneActiveView } from "../pane-tree";
import { normalizeWorkbenchRoute } from "@/components/desktop/workbench-routes";

describe("pane-store", () => {
  beforeEach(() => {
    usePaneStore.getState()._reset();
  });

  it("syncs the current route into the active pane", () => {
    usePaneStore.getState().syncRoute("/lab?tab=simulate");

    const state = usePaneStore.getState();
    expect(getActivePaneRoute(state.root, state.activePaneId)).toBe("/lab?tab=simulate");
  });

  it("splits and closes panes", () => {
    const originalPaneId = usePaneStore.getState().activePaneId;

    usePaneStore.getState().splitPane(originalPaneId, "vertical");
    expect(usePaneStore.getState().paneCount()).toBe(2);

    const activePaneId = usePaneStore.getState().activePaneId;
    usePaneStore.getState().closePane(activePaneId);

    expect(usePaneStore.getState().paneCount()).toBe(1);
  });

  it("focuses the adjacent pane in flattened order", () => {
    const originalPaneId = usePaneStore.getState().activePaneId;
    usePaneStore.getState().splitPane(originalPaneId, "vertical");

    const rightPaneId = usePaneStore.getState().activePaneId;
    usePaneStore.getState().focusPane("left");
    expect(usePaneStore.getState().activePaneId).toBe(originalPaneId);

    usePaneStore.getState().focusPane("right");
    expect(usePaneStore.getState().activePaneId).toBe(rightPaneId);
  });

  describe("openApp", () => {
    it("adds a new tab to the active pane group", () => {
      usePaneStore.getState().openApp("/settings", "Settings");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId);
      expect(pane).not.toBeNull();
      expect(pane!.views).toHaveLength(2);
      expect(pane!.views[1].route).toBe("/settings");
      expect(pane!.views[1].label).toBe("Settings");
      // New tab should be the active view
      expect(pane!.activeViewId).toBe(pane!.views[1].id);
    });

    it("focuses existing tab instead of adding duplicate when route already open in any pane", () => {
      // Open guards in the active pane
      usePaneStore.getState().openApp("/guards", "Guards");
      const state1 = usePaneStore.getState();
      const pane1 = findPaneGroup(state1.root, state1.activePaneId)!;
      const guardsViewId = pane1.views[1].id;

      // Switch active view back to Home before splitting, so the sibling clones Home (not Guards)
      usePaneStore.getState().setActiveView(pane1.id, pane1.views[0].id);

      // Split to create a second pane (focus moves to new pane, which clones Home)
      usePaneStore.getState().splitPane(pane1.id, "vertical");

      // Verify the new pane has Home, not Guards
      const stateAfterSplit = usePaneStore.getState();
      const siblingPane = findPaneGroup(stateAfterSplit.root, stateAfterSplit.activePaneId)!;
      expect(siblingPane.views[0].route).toBe("/home");

      // Now try to open /guards from the new pane -- should focus the first pane's existing guards tab
      usePaneStore.getState().openApp("/guards");

      const state2 = usePaneStore.getState();
      // Should have focused back to the original pane that had guards
      const originalPane = findPaneGroup(state2.root, pane1.id)!;
      expect(originalPane.activeViewId).toBe(guardsViewId);
      expect(state2.activePaneId).toBe(pane1.id);
      // Should NOT have added a duplicate
      const allGroups = getAllPaneGroups(state2.root);
      const totalGuardsViews = allGroups.flatMap((g) => g.views).filter((v) => v.route === "/guards");
      expect(totalGuardsViews).toHaveLength(1);
    });

    it("normalizes routes before comparing", () => {
      usePaneStore.getState().openApp("/overview");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      // /overview normalizes to /home, which is already the default tab
      // So it should NOT add a new tab, just focus the existing Home tab
      expect(pane.views).toHaveLength(1);
      expect(pane.views[0].route).toBe("/home");
    });

    it("uses getWorkbenchRouteLabel fallback when label is not provided", () => {
      usePaneStore.getState().openApp("/settings");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      const settingsView = pane.views.find((v) => v.route === "/settings");
      expect(settingsView).toBeDefined();
      expect(settingsView!.label).toBe("Settings");
    });
  });

  describe("lab decomposition routes", () => {
    it("opens swarm-board as independent tab", () => {
      usePaneStore.getState().openApp("/swarm-board");
      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      expect(pane.views).toHaveLength(2); // Home + Swarm Board
      expect(pane.views[1].route).toBe("/swarm-board");
      expect(pane.views[1].label).toBe("Swarm Board");
    });

    it("opens hunt as independent tab", () => {
      usePaneStore.getState().openApp("/hunt");
      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      expect(pane.views).toHaveLength(2);
      expect(pane.views[1].route).toBe("/hunt");
      expect(pane.views[1].label).toBe("Hunt");
    });

    it("opens simulator as independent tab", () => {
      usePaneStore.getState().openApp("/simulator");
      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      expect(pane.views).toHaveLength(2);
      expect(pane.views[1].route).toBe("/simulator");
      expect(pane.views[1].label).toBe("Simulator");
    });

    it("swarm-board and lab are distinct tabs", () => {
      usePaneStore.getState().openApp("/swarm-board");
      usePaneStore.getState().openApp("/lab");
      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      expect(pane.views).toHaveLength(3); // Home + Swarm Board + Lab
      expect(pane.views[1].route).toBe("/swarm-board");
      expect(pane.views[2].route).toBe("/lab");
    });

    it("hunt is not folded into lab tab query param", () => {
      usePaneStore.getState().openApp("/hunt");
      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      // Route should be /hunt, NOT /lab?tab=hunt
      expect(pane.views[1].route).toBe("/hunt");
      expect(pane.views[1].route).not.toContain("lab");
    });
  });

  describe("closeView", () => {
    it("removes the specified view from the pane group", () => {
      usePaneStore.getState().openApp("/guards", "Guards");
      usePaneStore.getState().openApp("/settings", "Settings");

      const state1 = usePaneStore.getState();
      const pane1 = findPaneGroup(state1.root, state1.activePaneId)!;
      expect(pane1.views).toHaveLength(3); // Home + Guards + Settings

      const guardsViewId = pane1.views[1].id;
      usePaneStore.getState().closeView(pane1.id, guardsViewId);

      const state2 = usePaneStore.getState();
      const pane2 = findPaneGroup(state2.root, state2.activePaneId)!;
      expect(pane2.views).toHaveLength(2);
      expect(pane2.views.find((v) => v.id === guardsViewId)).toBeUndefined();
    });

    it("selects the right neighbor when closing the active view; falls back to left", () => {
      usePaneStore.getState().openApp("/guards", "Guards");
      usePaneStore.getState().openApp("/settings", "Settings");

      const state1 = usePaneStore.getState();
      const pane1 = findPaneGroup(state1.root, state1.activePaneId)!;
      // Views: [Home, Guards, Settings], active is Settings (last opened)

      // Set Guards as active, then close it -- should select Settings (right neighbor)
      usePaneStore.getState().setActiveView(pane1.id, pane1.views[1].id);
      usePaneStore.getState().closeView(pane1.id, pane1.views[1].id);

      const state2 = usePaneStore.getState();
      const pane2 = findPaneGroup(state2.root, state2.activePaneId)!;
      expect(pane2.views).toHaveLength(2); // Home + Settings
      expect(pane2.activeViewId).toBe(pane2.views[1].id); // Settings (right neighbor)
    });

    it("resets to Home when closing the last view in the only pane", () => {
      const state1 = usePaneStore.getState();
      const pane1 = findPaneGroup(state1.root, state1.activePaneId)!;
      const homeViewId = pane1.views[0].id;

      usePaneStore.getState().closeView(pane1.id, homeViewId);

      const state2 = usePaneStore.getState();
      const pane2 = findPaneGroup(state2.root, state2.activePaneId)!;
      expect(pane2.views).toHaveLength(1);
      expect(pane2.views[0].route).toBe("/home");
      // Should be a NEW Home view (different id)
      expect(pane2.views[0].id).not.toBe(homeViewId);
    });

    it("closes the entire pane when closing the last view in a pane with siblings", () => {
      const originalPaneId = usePaneStore.getState().activePaneId;
      usePaneStore.getState().splitPane(originalPaneId, "vertical");
      expect(usePaneStore.getState().paneCount()).toBe(2);

      // The new sibling pane has one view (cloned from original)
      const state1 = usePaneStore.getState();
      const siblingPane = findPaneGroup(state1.root, state1.activePaneId)!;
      const siblingViewId = siblingPane.views[0].id;

      usePaneStore.getState().closeView(siblingPane.id, siblingViewId);

      const state2 = usePaneStore.getState();
      expect(usePaneStore.getState().paneCount()).toBe(1);
      // Should be left with original pane
      const remaining = getAllPaneGroups(state2.root);
      expect(remaining).toHaveLength(1);
    });
  });

  describe("openFile", () => {
    it("opens a file route via openFile", () => {
      usePaneStore.getState().openFile("policies/test.yaml", "test.yaml");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      expect(pane.views).toHaveLength(2); // Home + file
      expect(pane.views[1].route).toBe("/file/policies/test.yaml");
      expect(pane.views[1].label).toBe("test.yaml");
    });

    it("normalizes /file/ routes without collapsing path", () => {
      usePaneStore.getState().openApp("/file/policies/deep/nested.yaml");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      expect(pane.views).toHaveLength(2);
      expect(pane.views[1].route).toBe("/file/policies/deep/nested.yaml");
    });

    it("deduplicates file tabs by route", () => {
      usePaneStore.getState().openFile("policies/test.yaml", "test.yaml");
      usePaneStore.getState().openFile("policies/test.yaml", "test.yaml");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      const fileViews = pane.views.filter((v) =>
        v.route === "/file/policies/test.yaml",
      );
      expect(fileViews).toHaveLength(1);
    });

    it("deduplicates file tabs across panes", () => {
      // Open a file in the first pane
      usePaneStore.getState().openFile("policies/test.yaml", "test.yaml");
      const state1 = usePaneStore.getState();
      const firstPaneId = state1.activePaneId;
      const firstPane = findPaneGroup(state1.root, firstPaneId)!;
      const fileViewId = firstPane.views.find(
        (v) => v.route === "/file/policies/test.yaml",
      )!.id;

      // Switch active view back to Home so split clones Home
      usePaneStore.getState().setActiveView(firstPaneId, firstPane.views[0].id);

      // Split to create a second pane
      usePaneStore.getState().splitPane(firstPaneId, "vertical");
      expect(usePaneStore.getState().paneCount()).toBe(2);

      // From the new pane, open the same file -- should focus the existing tab in the first pane
      usePaneStore.getState().openFile("policies/test.yaml", "test.yaml");

      const state2 = usePaneStore.getState();
      // Should have switched back to the first pane
      expect(state2.activePaneId).toBe(firstPaneId);
      const originalPane = findPaneGroup(state2.root, firstPaneId)!;
      expect(originalPane.activeViewId).toBe(fileViewId);

      // No duplicate file views across all panes
      const allGroups = getAllPaneGroups(state2.root);
      const allFileViews = allGroups
        .flatMap((g) => g.views)
        .filter((v) => v.route === "/file/policies/test.yaml");
      expect(allFileViews).toHaveLength(1);
    });
  });

  describe("setActiveView", () => {
    it("updates activeViewId within the specified pane group", () => {
      usePaneStore.getState().openApp("/settings", "Settings");

      const state1 = usePaneStore.getState();
      const pane1 = findPaneGroup(state1.root, state1.activePaneId)!;
      const homeViewId = pane1.views[0].id;
      const settingsViewId = pane1.views[1].id;

      // Active should be settings (last opened)
      expect(pane1.activeViewId).toBe(settingsViewId);

      // Switch to home
      usePaneStore.getState().setActiveView(pane1.id, homeViewId);

      const state2 = usePaneStore.getState();
      const pane2 = findPaneGroup(state2.root, state2.activePaneId)!;
      expect(pane2.activeViewId).toBe(homeViewId);
    });

    it("also sets the pane as the active pane", () => {
      const originalPaneId = usePaneStore.getState().activePaneId;
      usePaneStore.getState().splitPane(originalPaneId, "vertical");

      // Active pane is now the sibling
      expect(usePaneStore.getState().activePaneId).not.toBe(originalPaneId);

      // setActiveView on original pane should make it the active pane
      const state1 = usePaneStore.getState();
      const originalPane = findPaneGroup(state1.root, originalPaneId)!;
      usePaneStore.getState().setActiveView(originalPaneId, originalPane.views[0].id);

      expect(usePaneStore.getState().activePaneId).toBe(originalPaneId);
    });
  });

  describe("syncRoute dedup", () => {
    it("does not create a second Home tab on fresh store", () => {
      // Fresh store already has one /home view.
      // syncRoute("/home") should be a no-op, not add or replace anything.
      usePaneStore.getState().syncRoute("/home");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      expect(pane.views).toHaveLength(1);
      expect(pane.views[0].route).toBe("/home");
    });

    it("focuses existing tab in active pane instead of overwriting current view", () => {
      // Start with Home. Open Settings as a second tab.
      usePaneStore.getState().openApp("/settings", "Settings");

      const state1 = usePaneStore.getState();
      const pane1 = findPaneGroup(state1.root, state1.activePaneId)!;
      expect(pane1.views).toHaveLength(2); // Home + Settings
      // Active view should be Settings (last opened)
      expect(pane1.activeViewId).toBe(pane1.views[1].id);
      const homeViewId = pane1.views[0].id;

      // syncRoute("/home") should focus the existing Home tab, NOT overwrite Settings
      usePaneStore.getState().syncRoute("/home");

      const state2 = usePaneStore.getState();
      const pane2 = findPaneGroup(state2.root, state2.activePaneId)!;
      expect(pane2.views).toHaveLength(2); // Still 2 tabs
      expect(pane2.activeViewId).toBe(homeViewId); // Home is now active
      expect(pane2.views[0].route).toBe("/home");
      expect(pane2.views[1].route).toBe("/settings"); // Settings preserved
    });

    it("produces exactly one Home view after _reset() + syncRoute('/home')", () => {
      usePaneStore.getState()._reset();
      usePaneStore.getState().syncRoute("/home");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      expect(pane.views).toHaveLength(1);
      expect(pane.views[0].route).toBe("/home");
    });

    it("syncRoute with a /file/ route does not collapse the file path", () => {
      usePaneStore.getState().syncRoute("/file/policies/deep/nested.yaml");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      // Should have replaced the Home view with the file route
      const activeView = getPaneActiveView(pane);
      expect(activeView).not.toBeNull();
      expect(activeView!.route).toBe("/file/policies/deep/nested.yaml");
    });
  });

  describe("normalizeWorkbenchRoute", () => {
    it("redirects /editor to /home", () => {
      expect(normalizeWorkbenchRoute("/editor")).toBe("/home");
    });

    it("redirects /editor?panel=guards to /guards", () => {
      expect(normalizeWorkbenchRoute("/editor?panel=guards")).toBe("/guards");
    });

    it("redirects /editor?panel=compare to /compare", () => {
      expect(normalizeWorkbenchRoute("/editor?panel=compare")).toBe("/compare");
    });

    it("openApp /editor resolves to existing /home tab (no duplicate)", () => {
      usePaneStore.getState().openApp("/editor", "Editor");

      const state = usePaneStore.getState();
      const pane = findPaneGroup(state.root, state.activePaneId)!;
      // /editor normalizes to /home, which is already the default tab
      expect(pane.views).toHaveLength(1);
      expect(pane.views[0].route).toBe("/home");
    });
  });
});
