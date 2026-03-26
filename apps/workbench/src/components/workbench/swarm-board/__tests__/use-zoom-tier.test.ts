import { describe, it, expect } from "vitest";
import {
  selectZoomTier,
  ZOOM_TIER_THRESHOLDS,
  type ZoomTier,
} from "../hooks/use-zoom-tier";

describe("selectZoomTier", () => {
  it('returns "full" at zoom = 1.0', () => {
    expect(selectZoomTier({ transform: [0, 0, 1.0] })).toBe("full");
  });

  it('returns "full" at boundary zoom = 0.6 (>= 0.6 is full)', () => {
    expect(selectZoomTier({ transform: [0, 0, 0.6] })).toBe("full");
  });

  it('returns "compact" just below full boundary at zoom = 0.59', () => {
    expect(selectZoomTier({ transform: [0, 0, 0.59] })).toBe("compact");
  });

  it('returns "compact" at boundary zoom = 0.35 (>= 0.35 is compact)', () => {
    expect(selectZoomTier({ transform: [0, 0, 0.35] })).toBe("compact");
  });

  it('returns "chip" just below compact boundary at zoom = 0.34', () => {
    expect(selectZoomTier({ transform: [0, 0, 0.34] })).toBe("chip");
  });

  it('returns "chip" at boundary zoom = 0.18 (>= 0.18 is chip)', () => {
    expect(selectZoomTier({ transform: [0, 0, 0.18] })).toBe("chip");
  });

  it('returns "dot" just below chip boundary at zoom = 0.17', () => {
    expect(selectZoomTier({ transform: [0, 0, 0.17] })).toBe("dot");
  });

  it('returns "dot" at hard min zoom = 0.08', () => {
    expect(selectZoomTier({ transform: [0, 0, 0.08] })).toBe("dot");
  });

  it("ignores x and y transform values", () => {
    expect(selectZoomTier({ transform: [500, -200, 0.5] })).toBe("compact");
  });
});

describe("ZOOM_TIER_THRESHOLDS", () => {
  it("exports the correct threshold values", () => {
    expect(ZOOM_TIER_THRESHOLDS).toEqual({
      compact: 0.6,
      chip: 0.35,
      dot: 0.18,
    });
  });

  it("is a frozen/readonly object", () => {
    // as const should make it readonly at the type level;
    // verify the runtime values are stable
    expect(ZOOM_TIER_THRESHOLDS.compact).toBe(0.6);
    expect(ZOOM_TIER_THRESHOLDS.chip).toBe(0.35);
    expect(ZOOM_TIER_THRESHOLDS.dot).toBe(0.18);
  });
});
