// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  NexusStateProvider,
  initialNexusState,
  nexusReducer,
  type NexusAction,
  useEscClosePriority,
  useNexusState,
} from "./NexusStateContext";

(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

function reduce(actions: NexusAction[]) {
  return actions.reduce((state, action) => nexusReducer(state, action), initialNexusState);
}

describe("nexusReducer", () => {
  it("syncs strikecells and sets first active strikecell", () => {
    const state = reduce([
      {
        type: "SYNC_STRIKECELLS",
        strikecellIds: ["events", "policies"],
      },
    ]);

    expect(state.strikecellOrder).toEqual(["events", "policies"]);
    expect(state.selection.activeStrikecellId).toBe("events");
  });

  it("navigates carousel with wraparound", () => {
    const state = reduce([
      {
        type: "SYNC_STRIKECELLS",
        strikecellIds: ["events", "policies", "workflows"],
      },
      { type: "SET_ACTIVE_STRIKECELL", id: "events" },
      { type: "NAVIGATE_CAROUSEL", direction: "prev" },
    ]);

    expect(state.keyboardHighlightedStrikecellId).toBe("workflows");
  });

  it("supports hud state transitions", () => {
    const state = reduce([
      { type: "SET_VIEW_MODE", mode: "grid" },
      { type: "TOGGLE_FIELD_VISIBILITY" },
      { type: "SET_LAYOUT_DROPDOWN_OPEN", open: true },
      { type: "SET_DETAIL_PANEL_OPEN", open: false },
    ]);

    expect(state.hud.viewMode).toBe("grid");
    expect(state.hud.fieldVisible).toBe(false);
    expect(state.hud.layoutDropdownOpen).toBe(true);
    expect(state.hud.detailPanelOpen).toBe(false);
  });

  it("reorders strikecells deterministically", () => {
    const state = reduce([
      {
        type: "SYNC_STRIKECELLS",
        strikecellIds: ["events", "policies", "workflows"],
      },
      { type: "REORDER_STRIKECELL", id: "policies", direction: "up" },
    ]);

    expect(state.strikecellOrder).toEqual(["policies", "events", "workflows"]);
  });
});

describe("useEscClosePriority", () => {
  let container: HTMLDivElement;
  let root: Root;

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("closes layers in deterministic priority order", () => {
    let api: any = null;

    function Harness() {
      const ctx = useNexusState();
      const escClose = useEscClosePriority();
      api = { ...ctx, escClose };
      return null;
    }

    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);

    act(() => {
      root.render(
        <NexusStateProvider>
          <Harness />
        </NexusStateProvider>
      );
    });

    if (!api) throw new Error("Harness not initialized");

    act(() => {
      api?.syncStrikecells(["events", "policies"]);
      api?.toggleExpanded("events");
      api?.setSelectedNodes(["node-1"]);
      api?.setFocusedNode("node-1");
      api?.setCarouselFocused(true);
      api?.setDrawerApp("events");
      api?.setLayoutDropdownOpen(true);
      api?.setContextMenu({
        x: 1,
        y: 1,
        targetId: "events",
        targetType: "strikecell",
        strikecellId: "events",
      });
      api?.setSearchOpen(true);
    });

    const layers: Array<string | null> = [];

    for (let index = 0; index < 9; index += 1) {
      act(() => {
        api?.escClose();
      });
      layers.push(api?.state.lastEscLayer ?? null);
    }

    expect(layers).toEqual([
      "search",
      "context-menu",
      "layout-dropdown",
      "drawer",
      "carousel-focus",
      "expanded",
      "selection",
      "selection",
      null,
    ]);
  });
});
