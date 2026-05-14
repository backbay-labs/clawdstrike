import { describe, expect, it } from "vitest";
import * as THREE from "three";
import { SPIRIT_LUT_SIZE, buildSpiritLut } from "@/features/observatory/utils/buildSpiritLut";

describe("buildSpiritLut", () => {
  it("returns a cached Data3DTexture per spirit kind", () => {
    const first = buildSpiritLut("sentinel");
    const second = buildSpiritLut("sentinel");

    expect(first).toBe(second);
  });

  it("creates a 17x17x17 RGBA texture with linear sampling", () => {
    const texture = buildSpiritLut("oracle");

    expect(texture).toBeInstanceOf(THREE.Data3DTexture);
    expect(texture.image.width).toBe(SPIRIT_LUT_SIZE);
    expect(texture.image.height).toBe(SPIRIT_LUT_SIZE);
    expect(texture.image.depth).toBe(SPIRIT_LUT_SIZE);
    expect(texture.format).toBe(THREE.RGBAFormat);
    expect(texture.minFilter).toBe(THREE.LinearFilter);
    expect(texture.magFilter).toBe(THREE.LinearFilter);
  });
});
