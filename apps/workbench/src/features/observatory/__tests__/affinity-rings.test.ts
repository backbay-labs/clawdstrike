import { describe, expect, it } from "vitest";
import { blendHex, STATION_AFFINITY_MAP } from "@/features/spirit/scene-math";

describe("blendHex color interpolation", () => {
  it("t=0 returns base color exactly", () => {
    expect(blendHex("#000000", "#ffffff", 0)).toBe("#000000");
  });

  it("t=1 returns target color exactly", () => {
    expect(blendHex("#000000", "#ffffff", 1)).toBe("#ffffff");
  });

  it("t=0.5 returns midpoint (linear RGB average)", () => {
    // Math.round(255*0.5) = Math.round(127.5) = 128 = 0x80
    expect(blendHex("#000000", "#ffffff", 0.5)).toBe("#808080");
  });

  it("arbitrary blend result starts with # and is 7 characters", () => {
    const result = blendHex("#3dbf84", "#7b68ee", 0.35);
    expect(result).toMatch(/^#[0-9a-f]{6}$/);
  });
});

describe("affinity ring opacity formula", () => {
  it("opacity at mid affinity (0.5) equals 0.19", () => {
    const affinity = 0.5;
    const opacity = 0.08 + affinity * 0.22;
    expect(opacity).toBeCloseTo(0.19, 10);
  });
});

describe("STATION_AFFINITY_MAP", () => {
  it("sentinel signal affinity equals 0.82", () => {
    expect(STATION_AFFINITY_MAP.sentinel.signal).toBe(0.82);
  });
});
