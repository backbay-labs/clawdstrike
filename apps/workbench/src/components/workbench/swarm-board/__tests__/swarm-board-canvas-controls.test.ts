import { describe, expect, it } from "vitest";

import { createBoardNode } from "@/features/swarm/stores/swarm-board-store";
import {
  SWARM_BOARD_GRID_GAP,
  SWARM_BOARD_GRID_MAJOR_GAP,
  SWARM_BOARD_PAN_ON_DRAG_BUTTONS,
  SWARM_BOARD_SHORTCUT_HINT,
  SWARM_BOARD_ZOOM_ACTIVATION_KEY_CODE,
  nudgeSelectedBoardNodes,
} from "../swarm-board-canvas-controls";

describe("swarm-board canvas controls", () => {
  it("nudges the inspector-selected node by the grid step", () => {
    const selected = createBoardNode({
      nodeType: "note",
      title: "Selected",
      position: { x: 100, y: 200 },
    });
    const untouched = createBoardNode({
      nodeType: "note",
      title: "Untouched",
      position: { x: 300, y: 400 },
    });

    const next = nudgeSelectedBoardNodes(
      [selected, untouched],
      selected.id,
      "ArrowRight",
    );

    expect(next).not.toBeNull();
    expect(next?.[0]?.position).toEqual({ x: 100 + SWARM_BOARD_GRID_GAP, y: 200 });
    expect(next?.[1]?.position).toEqual({ x: 300, y: 400 });
  });

  it("nudges all React Flow-selected nodes together", () => {
    const first = {
      ...createBoardNode({
        nodeType: "note",
        title: "First",
        position: { x: 40, y: 50 },
      }),
      selected: true,
    };
    const second = {
      ...createBoardNode({
        nodeType: "note",
        title: "Second",
        position: { x: 140, y: 150 },
      }),
      selected: true,
    };

    const next = nudgeSelectedBoardNodes(
      [first, second],
      null,
      "ArrowUp",
    );

    expect(next?.[0]?.position).toEqual({ x: 40, y: 50 - SWARM_BOARD_GRID_GAP });
    expect(next?.[1]?.position).toEqual({ x: 140, y: 150 - SWARM_BOARD_GRID_GAP });
  });

  it("ignores non-arrow keys and empty selections", () => {
    const node = createBoardNode({
      nodeType: "note",
      title: "Idle",
      position: { x: 10, y: 20 },
    });

    expect(nudgeSelectedBoardNodes([node], null, "a")).toBeNull();
    expect(nudgeSelectedBoardNodes([node], null, "ArrowLeft")).toBeNull();
  });

  it("nudges by SWARM_BOARD_GRID_MAJOR_GAP when given a major step", () => {
    const selected = createBoardNode({
      nodeType: "note",
      title: "S",
      position: { x: 100, y: 200 },
    });
    const next = nudgeSelectedBoardNodes(
      [selected],
      selected.id,
      "ArrowRight",
      SWARM_BOARD_GRID_MAJOR_GAP,
    );
    expect(next?.[0]?.position).toEqual({ x: 100 + SWARM_BOARD_GRID_MAJOR_GAP, y: 200 });
  });

  it("pins the intended quick-win interaction config", () => {
    expect(SWARM_BOARD_PAN_ON_DRAG_BUTTONS).toEqual([1]);
    expect(SWARM_BOARD_ZOOM_ACTIVATION_KEY_CODE).toEqual(["Meta", "Control"]);
    expect(SWARM_BOARD_SHORTCUT_HINT).toContain("arrows nudge");
    expect(SWARM_BOARD_SHORTCUT_HINT).toContain("G follow");
  });
});
