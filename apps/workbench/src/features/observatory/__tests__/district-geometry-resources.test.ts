import { describe, expect, it } from "vitest";
import { mulberry32, createSpaceStationSeed } from "@/features/observatory/world/districtGeometryResources";
import { createSpaceStationLayout } from "@/features/observatory/world/districtGeometry";

describe("districtGeometryResources", () => {
  it("mulberry32 produces deterministic sequences", () => {
    const rng1 = mulberry32(42);
    const rng2 = mulberry32(42);
    expect(rng1()).toBe(rng2());
    expect(rng1()).toBe(rng2());
    expect(rng1()).toBe(rng2());
  });

  it("createSpaceStationSeed returns positive integer", () => {
    const seed = createSpaceStationSeed(150, -80);
    expect(seed).toBeGreaterThan(0);
    expect(Number.isInteger(seed)).toBe(true);
  });

  it("createSpaceStationSeed is deterministic", () => {
    expect(createSpaceStationSeed(100, 200)).toBe(createSpaceStationSeed(100, 200));
  });
});

describe("createSpaceStationLayout", () => {
  it("produces deterministic layout for same seed", () => {
    const a = createSpaceStationLayout(42);
    const b = createSpaceStationLayout(42);
    expect(a).toEqual(b);
  });

  it("ring radius is in range 2-4", () => {
    const layout = createSpaceStationLayout(123);
    expect(layout.ringRadius).toBeGreaterThanOrEqual(2);
    expect(layout.ringRadius).toBeLessThanOrEqual(4);
  });

  it("hub height is in range 1-3", () => {
    const layout = createSpaceStationLayout(456);
    expect(layout.hubHeight).toBeGreaterThanOrEqual(1);
    expect(layout.hubHeight).toBeLessThanOrEqual(3);
  });

  it("panel count is in range 2-6", () => {
    const layout = createSpaceStationLayout(789);
    expect(layout.panelCount).toBeGreaterThanOrEqual(2);
    expect(layout.panelCount).toBeLessThanOrEqual(6);
  });

  it("antenna count is in range 1-3", () => {
    const layout = createSpaceStationLayout(321);
    expect(layout.antennaCount).toBeGreaterThanOrEqual(1);
    expect(layout.antennaCount).toBeLessThanOrEqual(3);
  });

  it("different seeds produce different layouts", () => {
    const a = createSpaceStationLayout(1);
    const b = createSpaceStationLayout(999);
    expect(a.ringRadius).not.toBe(b.ringRadius);
  });
});
