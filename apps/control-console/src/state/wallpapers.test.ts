import { describe, expect, it } from "vitest";
import { WALLPAPERS } from "./wallpapers";

describe("WALLPAPERS", () => {
  it("has at least 6 presets", () => {
    expect(WALLPAPERS.length).toBeGreaterThanOrEqual(6);
  });

  it("each wallpaper has required fields", () => {
    for (const wp of WALLPAPERS) {
      expect(wp.id).toBeTruthy();
      expect(wp.name).toBeTruthy();
      expect(wp.gradient).toBeTruthy();
    }
  });

  it("has a default wallpaper", () => {
    const def = WALLPAPERS.find((w) => w.id === "default");
    expect(def).toBeDefined();
  });

  it("has unique ids", () => {
    const ids = WALLPAPERS.map((w) => w.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
