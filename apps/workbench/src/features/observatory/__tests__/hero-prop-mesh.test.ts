import { describe, expect, it } from "vitest";
import { OBSERVATORY_HERO_PROP_ASSETS } from "@/features/observatory/world/propAssets";

describe("hero prop mesh — propAssets availability", () => {
  it("all 7 assets have availability 'ready'", () => {
    const allReady = Object.values(OBSERVATORY_HERO_PROP_ASSETS).every(
      (a) => a.availability === "ready",
    );
    expect(allReady).toBe(true);
  });

  it("OBSERVATORY_HERO_PROP_ASSETS has exactly 7 entries", () => {
    expect(Object.keys(OBSERVATORY_HERO_PROP_ASSETS).length).toBe(7);
  });

  it("every asset url starts with '/observatory-props/'", () => {
    const allPrefixed = Object.values(OBSERVATORY_HERO_PROP_ASSETS).every((a) =>
      a.url.startsWith("/observatory-props/"),
    );
    expect(allPrefixed).toBe(true);
  });
});

describe("hero prop mesh — bob animation math", () => {
  it("bobOffset is 0 at elapsed=0", () => {
    const amplitude = 0.06;
    const speed = 0.24;
    const elapsed = 0.0;
    const bobOffset = amplitude * Math.sin(elapsed * speed);
    expect(bobOffset).toBe(0);
  });

  it("bobOffset is within ±0.001 of -amplitude at the negative peak elapsed", () => {
    const amplitude = 0.06;
    const speed = 0.24;
    // Negative peak: sin = -1 occurs when (elapsed * speed) = 3π/2
    // i.e. elapsed = 3π / (2 * speed)
    const elapsed = (3 * Math.PI) / (2 * speed);
    const bobOffset = amplitude * Math.sin(elapsed * speed);
    expect(Math.abs(bobOffset - -amplitude)).toBeLessThan(0.001);
  });
});
