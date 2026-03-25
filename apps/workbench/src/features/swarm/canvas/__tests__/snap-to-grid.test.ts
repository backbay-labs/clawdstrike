import { describe, expect, it } from "vitest";

import {
  SNAP_GRID_SIZE,
  snapToGrid,
  snapPositionToGrid,
  positionNeedsSnap,
} from "../snap-to-grid";

import { SWARM_BOARD_GRID_GAP } from "@/components/workbench/swarm-board/swarm-board-canvas-controls";

describe("snap-to-grid", () => {
  it("returns the same value when already aligned", () => {
    expect(snapToGrid(100, 20)).toBe(100);
    expect(snapToGrid(0, 20)).toBe(0);
    expect(snapToGrid(60, 20)).toBe(60);
  });

  it("rounds down when closer to the lower grid line", () => {
    expect(snapToGrid(107, 20)).toBe(100);
    expect(snapToGrid(49, 20)).toBe(40);
  });

  it("rounds up when closer to the upper grid line", () => {
    expect(snapToGrid(113, 20)).toBe(120);
    expect(snapToGrid(91, 20)).toBe(80);
  });

  it("snaps zero correctly", () => {
    expect(snapToGrid(0, 20)).toBe(0);
  });

  it("handles negative coordinates", () => {
    expect(snapToGrid(-13, 20)).toBe(-20);
    expect(snapToGrid(-7, 20)).toBe(0);
    expect(snapToGrid(-100, 20)).toBe(-100);
    expect(snapToGrid(-31, 20)).toBe(-40);
  });

  it("snaps positions (x, y) to grid", () => {
    expect(snapPositionToGrid({ x: 107, y: 213 })).toEqual({ x: 100, y: 220 });
    expect(snapPositionToGrid({ x: 0, y: 0 })).toEqual({ x: 0, y: 0 });
    expect(snapPositionToGrid({ x: -13, y: 47 })).toEqual({ x: -20, y: 40 });
  });

  it("detects when a position needs snapping", () => {
    expect(positionNeedsSnap({ x: 100, y: 200 })).toBe(false);
    expect(positionNeedsSnap({ x: 107, y: 200 })).toBe(true);
    expect(positionNeedsSnap({ x: 100, y: 201 })).toBe(true);
  });

  it("handles floating-point positions", () => {
    // 99.9999 rounds to 100 (on-grid after snap)
    expect(snapToGrid(99.9999, 20)).toBe(100);
    // 100.0001 rounds to 100 (on-grid after snap)
    expect(snapToGrid(100.0001, 20)).toBe(100);
    // float that is clearly off-grid
    expect(snapToGrid(107.5, 20)).toBe(100);
    expect(snapToGrid(112.5, 20)).toBe(120);
  });

  it("uses default grid size matching SWARM_BOARD_GRID_GAP", () => {
    expect(SNAP_GRID_SIZE).toBe(SWARM_BOARD_GRID_GAP);
    // Default grid usage
    expect(snapToGrid(107)).toBe(100);
    expect(snapPositionToGrid({ x: 113, y: 47 })).toEqual({ x: 120, y: 40 });
    expect(positionNeedsSnap({ x: 120, y: 40 })).toBe(false);
    expect(positionNeedsSnap({ x: 113, y: 47 })).toBe(true);
  });

  it("supports custom grid sizes", () => {
    expect(snapToGrid(33, 10)).toBe(30);
    expect(snapToGrid(37, 10)).toBe(40);
    expect(snapPositionToGrid({ x: 33, y: 77 }, 10)).toEqual({ x: 30, y: 80 });
    expect(positionNeedsSnap({ x: 30, y: 80 }, 10)).toBe(false);
    expect(positionNeedsSnap({ x: 33, y: 77 }, 10)).toBe(true);
  });
});
