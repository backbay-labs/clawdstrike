import * as THREE from "three";
import type { SpiritKind } from "@/features/spirit/types";

export const SPIRIT_LUT_SIZE = 17; // 17×17×17 — sufficient quality, low memory
const SPIRIT_LUT_CACHE = new Map<SpiritKind, THREE.Data3DTexture>();

/**
 * Color transform functions — one per spirit kind.
 * Input/output: r, g, b in [0, 1] normalized linear color space.
 *
 * Each function applies a characteristic color shift:
 * - sentinel: cool teal (boost blue-green, reduce red warmth)
 * - oracle:   warm violet (boost red+blue, reduce green)
 * - witness:  warm gold (boost red+green, reduce blue, lift shadows)
 * - specter:  deep red (high contrast red, crush shadows, desaturate green/blue)
 */
type ColorTransform = (r: number, g: number, b: number) => [number, number, number];

const SPIRIT_LUT_TRANSFORMS: Record<SpiritKind, ColorTransform> = {
  // Sentinel: cool teal — scientific, precise, cold
  // Reduce warm reds, boost blue-greens, slight desaturation of hot tones
  sentinel: (r, g, b) => {
    const newR = r * 0.72 + g * 0.06 + b * 0.04;
    const newG = r * 0.04 + g * 0.88 + b * 0.12;
    const newB = r * 0.08 + g * 0.14 + b * 1.08;
    return [
      Math.min(1, Math.max(0, newR)),
      Math.min(1, Math.max(0, newG)),
      Math.min(1, Math.max(0, newB)),
    ];
  },

  // Oracle: warm violet — mystical, deep, otherworldly
  // Boost reds and blues equally, suppress greens, slight shadow lift
  oracle: (r, g, b) => {
    const newR = r * 1.06 + g * 0.02 + b * 0.08 + 0.04;
    const newG = r * 0.02 + g * 0.76 + b * 0.04;
    const newB = r * 0.14 + g * 0.04 + b * 1.10 + 0.04;
    return [
      Math.min(1, Math.max(0, newR)),
      Math.min(1, Math.max(0, newG)),
      Math.min(1, Math.max(0, newB)),
    ];
  },

  // Witness: warm gold — investigative, amber, archival
  // Boost reds and greens (amber), reduce blues, lift midtone shadows
  witness: (r, g, b) => {
    const lift = 0.03; // shadow lift for that warm film look
    const newR = r * 1.10 + g * 0.08 + b * 0.02 + lift;
    const newG = r * 0.06 + g * 1.02 + b * 0.0 + lift;
    const newB = r * 0.0 + g * 0.02 + b * 0.72 + lift * 0.5;
    return [
      Math.min(1, Math.max(0, newR)),
      Math.min(1, Math.max(0, newG)),
      Math.min(1, Math.max(0, newB)),
    ];
  },

  // Specter: deep red — threatening, high contrast, shadow crush
  // Crush shadows aggressively, boost red channel, desaturate green and blue
  specter: (r, g, b) => {
    // Shadow crush: darks go darker (gamma compress)
    const luma = r * 0.299 + g * 0.587 + b * 0.114;
    const crushFactor = Math.pow(luma, 1.4); // crush shadows
    const newR = crushFactor * 0.18 + r * 1.08 + g * 0.04;
    const newG = crushFactor * 0.08 + r * 0.02 + g * 0.68 + b * 0.04;
    const newB = crushFactor * 0.06 + r * 0.04 + g * 0.06 + b * 0.58;
    return [
      Math.min(1, Math.max(0, newR)),
      Math.min(1, Math.max(0, newG)),
      Math.min(1, Math.max(0, newB)),
    ];
  },
};

/**
 * Builds a THREE.Data3DTexture encoding a 3D LUT for the given spirit kind.
 *
 * The texture is SIZE×SIZE×SIZE with RGBA format.
 * Layout: index = (b * SIZE * SIZE + g * SIZE + r) * 4
 *
 * Uses THREE.Data3DTexture (available in three >= 0.155, workbench uses 0.170).
 * The <LUT> component from @react-three/postprocessing accepts this directly.
 *
 * Call once per spirit kind and cache the result (textures are not memoized
 * internally — callers should memoize with useMemo keyed on spiritKind).
 */
export function buildSpiritLut(kind: SpiritKind): THREE.Data3DTexture {
  const cached = SPIRIT_LUT_CACHE.get(kind);
  if (cached) {
    return cached;
  }

  const SIZE = SPIRIT_LUT_SIZE;
  const data = new Uint8Array(SIZE * SIZE * SIZE * 4);
  const transform = SPIRIT_LUT_TRANSFORMS[kind];

  for (let b = 0; b < SIZE; b++) {
    for (let g = 0; g < SIZE; g++) {
      for (let r = 0; r < SIZE; r++) {
        // Convert LUT grid coordinates to normalized [0, 1] color values
        const rNorm = r / (SIZE - 1);
        const gNorm = g / (SIZE - 1);
        const bNorm = b / (SIZE - 1);

        const [newR, newG, newB] = transform(rNorm, gNorm, bNorm);

        const index = (b * SIZE * SIZE + g * SIZE + r) * 4;
        data[index + 0] = Math.round(newR * 255);
        data[index + 1] = Math.round(newG * 255);
        data[index + 2] = Math.round(newB * 255);
        data[index + 3] = 255;
      }
    }
  }

  const texture = new THREE.Data3DTexture(data, SIZE, SIZE, SIZE);
  texture.format = THREE.RGBAFormat;
  texture.type = THREE.UnsignedByteType;
  texture.minFilter = THREE.LinearFilter;
  texture.magFilter = THREE.LinearFilter;
  texture.wrapS = THREE.ClampToEdgeWrapping;
  texture.wrapT = THREE.ClampToEdgeWrapping;
  texture.wrapR = THREE.ClampToEdgeWrapping;
  texture.needsUpdate = true;
  SPIRIT_LUT_CACHE.set(kind, texture);
  return texture;
}
