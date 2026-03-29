import { describe, expect, it } from "vitest";

import {
  SWARM_VIEWPORT_TARGET_MAX_ZOOM,
  SWARM_VIEWPORT_TARGET_MIN_ZOOM,
  applyViewportWheelPan,
  applyViewportWheelZoom,
  areViewportsEqual,
  clampViewportZoom,
  getZoomIndicatorLabel,
  shouldSyncControlledViewport,
  shouldZoomCanvasWheel,
  stepViewportSnapback,
  viewportNeedsSnapback,
  zoomViewportAroundPoint,
} from "../viewport-controller";

describe("viewport-controller", () => {
  it("detects modifier-based zoom correctly across platforms", () => {
    expect(shouldZoomCanvasWheel({ ctrlKey: false, metaKey: true }, true)).toBe(true);
    expect(shouldZoomCanvasWheel({ ctrlKey: true, metaKey: false }, false)).toBe(true);
    expect(shouldZoomCanvasWheel({ ctrlKey: false, metaKey: true }, false)).toBe(false);
  });

  it("zooms around the provided screen focal point", () => {
    const next = zoomViewportAroundPoint(
      { x: 0, y: 0, zoom: 1 },
      2,
      { x: 100, y: 50 },
    );

    expect(next).toEqual({ x: -100, y: -50, zoom: 2 });
  });

  it("applies exponential zoom and rubber-band damping once already beyond the soft limits", () => {
    const regular = applyViewportWheelZoom(
      { x: 0, y: 0, zoom: 1 },
      -100,
      { x: 0, y: 0 },
    );
    const overshooting = applyViewportWheelZoom(
      { x: 0, y: 0, zoom: SWARM_VIEWPORT_TARGET_MAX_ZOOM + 0.05 },
      -100,
      { x: 0, y: 0 },
    );

    expect(regular.zoom).toBeGreaterThan(1);
    expect(overshooting.zoom).toBeGreaterThan(SWARM_VIEWPORT_TARGET_MAX_ZOOM + 0.05);
    expect(overshooting.zoom / (SWARM_VIEWPORT_TARGET_MAX_ZOOM + 0.05)).toBeLessThan(
      regular.zoom,
    );
  });

  it("pans with the collab-public multiplier", () => {
    expect(
      applyViewportWheelPan({ x: 10, y: 20, zoom: 1 }, 5, -10),
    ).toEqual({
      x: 4,
      y: 32,
      zoom: 1,
    });
  });

  it("steps snapback toward the target range and clamps when close enough", () => {
    const snapped = stepViewportSnapback(
      { x: 0, y: 0, zoom: SWARM_VIEWPORT_TARGET_MAX_ZOOM + 0.2 },
      { x: 400, y: 300 },
    );

    expect(snapped.zoom).toBeLessThan(SWARM_VIEWPORT_TARGET_MAX_ZOOM + 0.2);
    expect(viewportNeedsSnapback(snapped)).toBe(true);

    const clamped = clampViewportZoom(
      { x: 0, y: 0, zoom: SWARM_VIEWPORT_TARGET_MIN_ZOOM - 0.01 },
      { x: 400, y: 300 },
    );
    expect(clamped.zoom).toBe(SWARM_VIEWPORT_TARGET_MIN_ZOOM);
  });

  it("exposes controlled-sync and label helpers", () => {
    expect(shouldSyncControlledViewport("pointer")).toBe(true);
    expect(shouldSyncControlledViewport("imperative")).toBe(true);
    expect(shouldSyncControlledViewport("idle")).toBe(false);
    expect(shouldSyncControlledViewport("wheel")).toBe(false);
    expect(shouldSyncControlledViewport("snapback")).toBe(false);
    expect(areViewportsEqual(
      { x: 1, y: 2, zoom: 3 },
      { x: 1.00001, y: 2.00001, zoom: 3.00001 },
    )).toBe(true);
    expect(getZoomIndicatorLabel(1.234)).toBe("123%");
  });
});
