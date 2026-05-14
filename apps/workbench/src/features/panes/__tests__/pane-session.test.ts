import { beforeEach, describe, expect, it } from "vitest";
import {
  savePaneSession,
  loadPaneSession,
  countFileViews,
  clearPaneSession,
} from "../pane-session";
import { createPaneGroup } from "../pane-tree";
import type { PaneGroup, PaneNode, PaneSplit, PaneView } from "../pane-types";

function makeView(overrides: Partial<PaneView> = {}): PaneView {
  return {
    id: crypto.randomUUID(),
    route: "/home",
    label: "Home",
    ...overrides,
  };
}

function makeGroup(views: PaneView[], activeViewId?: string): PaneGroup {
  return {
    id: crypto.randomUUID(),
    type: "group",
    views,
    activeViewId: activeViewId ?? views[0]?.id ?? null,
  };
}

function makeSplit(
  left: PaneNode,
  right: PaneNode,
  direction: "horizontal" | "vertical" = "vertical",
): PaneSplit {
  return {
    id: crypto.randomUUID(),
    type: "split",
    direction,
    children: [left, right],
    sizes: [50, 50],
  };
}

describe("pane-session", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  describe("savePaneSession", () => {
    it("serializes root + activePaneId to localStorage key 'clawdstrike_pane_layout'", () => {
      const view = makeView();
      const group = makeGroup([view]);

      savePaneSession(group, group.id);

      const raw = localStorage.getItem("clawdstrike_pane_layout");
      expect(raw).not.toBeNull();
      const parsed = JSON.parse(raw!);
      expect(parsed).toHaveProperty("root");
      expect(parsed).toHaveProperty("activePaneId", group.id);
      expect(parsed.root.type).toBe("group");
    });
  });

  describe("loadPaneSession", () => {
    it("returns null when localStorage is empty", () => {
      expect(loadPaneSession()).toBeNull();
    });

    it("returns null when localStorage contains invalid JSON", () => {
      localStorage.setItem("clawdstrike_pane_layout", "not-json{{{");
      expect(loadPaneSession()).toBeNull();
    });

    it("round-trip: save then load returns identical root + activePaneId structure", () => {
      const view = makeView({ route: "/settings", label: "Settings" });
      const group = makeGroup([view]);

      savePaneSession(group, group.id);
      const restored = loadPaneSession();

      expect(restored).not.toBeNull();
      expect(restored!.activePaneId).toBe(group.id);
      expect(restored!.root.type).toBe("group");
      const restoredGroup = restored!.root as PaneGroup;
      expect(restoredGroup.views).toHaveLength(1);
      expect(restoredGroup.views[0].route).toBe("/settings");
      expect(restoredGroup.views[0].label).toBe("Settings");
    });

    it("round-trip with split pane tree (PaneSplit with two PaneGroup children)", () => {
      const leftView = makeView({ route: "/home", label: "Home" });
      const rightView = makeView({ route: "/file/test.yaml", label: "test.yaml" });
      const leftGroup = makeGroup([leftView]);
      const rightGroup = makeGroup([rightView]);
      const splitRoot = makeSplit(leftGroup, rightGroup);

      savePaneSession(splitRoot, rightGroup.id);
      const restored = loadPaneSession();

      expect(restored).not.toBeNull();
      expect(restored!.activePaneId).toBe(rightGroup.id);
      expect(restored!.root.type).toBe("split");
      const split = restored!.root as PaneSplit;
      expect(split.children).toHaveLength(2);
      expect(split.children[0].type).toBe("group");
      expect(split.children[1].type).toBe("group");
      const restoredRight = split.children[1] as PaneGroup;
      expect(restoredRight.views[0].route).toBe("/file/test.yaml");
    });

    it("strips dirty flag from all views on load (restored files are not dirty)", () => {
      const cleanView = makeView({ route: "/home", label: "Home" });
      const dirtyView = makeView({
        route: "/file/policy.yaml",
        label: "policy.yaml",
        dirty: true,
      });
      const group = makeGroup([cleanView, dirtyView]);

      savePaneSession(group, group.id);
      const restored = loadPaneSession();

      expect(restored).not.toBeNull();
      const restoredGroup = restored!.root as PaneGroup;
      for (const view of restoredGroup.views) {
        expect(view.dirty).toBeFalsy();
      }
    });
  });

  describe("countFileViews", () => {
    it("returns correct count of views with routes starting with /file/", () => {
      const v1 = makeView({ route: "/home", label: "Home" });
      const v2 = makeView({ route: "/file/a.yaml", label: "a.yaml" });
      const v3 = makeView({ route: "/file/b.yaml", label: "b.yaml" });
      const group = makeGroup([v1, v2, v3]);

      expect(countFileViews(group)).toBe(2);
    });

    it("returns 0 for tree with only non-file routes", () => {
      const v1 = makeView({ route: "/home", label: "Home" });
      const v2 = makeView({ route: "/settings", label: "Settings" });
      const group = makeGroup([v1, v2]);

      expect(countFileViews(group)).toBe(0);
    });

    it("counts file views across split pane trees", () => {
      const leftView = makeView({ route: "/file/x.yaml", label: "x.yaml" });
      const rightView = makeView({ route: "/file/y.yaml", label: "y.yaml" });
      const leftGroup = makeGroup([leftView]);
      const rightGroup = makeGroup([rightView]);
      const splitRoot = makeSplit(leftGroup, rightGroup);

      expect(countFileViews(splitRoot)).toBe(2);
    });
  });

  describe("clearPaneSession", () => {
    it("removes the session key from localStorage", () => {
      const view = makeView();
      const group = makeGroup([view]);
      savePaneSession(group, group.id);
      expect(localStorage.getItem("clawdstrike_pane_layout")).not.toBeNull();

      clearPaneSession();
      expect(localStorage.getItem("clawdstrike_pane_layout")).toBeNull();
    });
  });
});
