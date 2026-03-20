import { Billboard } from "@react-three/drei";
import { useMemo } from "react";
import * as THREE from "three";
import { HUNT_PRIMARY_STATION_ORDER, HUNT_STATION_ORDER } from "../../world/stations";
import type { HuntStationId } from "../../world/types";
import { OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";

const STATION_COLORS: Record<HuntStationId, string> = {
  signal: "#7cc8ff",
  targets: "#9df2dd",
  run: "#f4d982",
  receipts: "#7ee6f2",
  "case-notes": "#f0b87b",
  watch: "#d3b56e",
};

const PATCHES_PER_STATION = 3;

/** Mulberry32 seeded PRNG — deterministic, no per-frame allocations */
function mulberry32(seed: number): () => number {
  let s = seed;
  return () => {
    s |= 0;
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function stationSeed(stationId: HuntStationId): number {
  let hash = 0;
  for (let i = 0; i < stationId.length; i += 1) {
    hash = (Math.imul(31, hash) + stationId.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

function buildRadialGradientTexture(): THREE.CanvasTexture {
  const size = 128;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d");
  if (ctx) {
    const gradient = ctx.createRadialGradient(
      size / 2, size / 2, 0,
      size / 2, size / 2, size / 2,
    );
    gradient.addColorStop(0, "rgba(255,255,255,1)");
    gradient.addColorStop(0.4, "rgba(255,255,255,0.6)");
    gradient.addColorStop(1, "rgba(255,255,255,0)");
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, size, size);
  }
  const texture = new THREE.CanvasTexture(canvas);
  return texture;
}

interface PatchData {
  stationId: HuntStationId;
  color: string;
  position: [number, number, number];
  rotationZ: number;
  opacity: number;
  width: number;
  height: number;
}

interface StationLightData {
  stationId: HuntStationId;
  color: string;
  position: [number, number, number];
}

export function ObservatoryNebulaClouds() {
  const { patches, stationLights, texture } = useMemo(() => {
    const allStationIds: HuntStationId[] = HUNT_STATION_ORDER;
    const cloudPatches: PatchData[] = [];
    const lights: StationLightData[] = [];

    for (const stationId of allStationIds) {
      const stationPos = OBSERVATORY_STATION_POSITIONS[stationId];
      const color = STATION_COLORS[stationId];
      const seed = stationSeed(stationId);
      const rand = mulberry32(seed);

      lights.push({
        stationId,
        color,
        position: [stationPos[0], stationPos[1], stationPos[2]],
      });

      for (let index = 0; index < PATCHES_PER_STATION; index += 1) {
        const patchSeed = seed + index * 7919;
        const pr = mulberry32(patchSeed);

        const offsetX = (pr() - 0.5) * 40; // +/- 20
        const offsetY = (pr() - 0.5) * 20; // +/- 10
        const offsetZ = (pr() - 0.5) * 40; // +/- 20
        const opacity = 0.4 + pr() * 0.2; // 0.4 to 0.6
        const rotationZ = rand() * Math.PI * 2;
        const patchSize = 8 + rand() * 4; // 8–12 units

        cloudPatches.push({
          stationId,
          color,
          position: [
            stationPos[0] + offsetX,
            stationPos[1] + offsetY,
            stationPos[2] + offsetZ,
          ],
          rotationZ,
          opacity,
          width: patchSize,
          height: patchSize,
        });
      }
    }

    const gradientTexture = typeof document !== "undefined"
      ? buildRadialGradientTexture()
      : null;

    return { patches: cloudPatches, stationLights: lights, texture: gradientTexture };
  }, []);

  return (
    <>
      {stationLights.map((light) => (
        <pointLight
          key={`nebula-light-${light.stationId}`}
          position={light.position}
          color={light.color}
          intensity={2.0}
          distance={60}
          decay={2}
        />
      ))}
      {patches.map((patch, index) => (
        <Billboard
          key={`nebula-patch-${patch.stationId}-${index}`}
          position={patch.position}
        >
          <mesh rotation-z={patch.rotationZ}>
            <planeGeometry args={[patch.width, patch.height]} />
            <meshBasicMaterial
              color={patch.color}
              transparent
              opacity={patch.opacity}
              blending={THREE.AdditiveBlending}
              depthWrite={false}
              toneMapped={false}
              map={texture}
            />
          </mesh>
        </Billboard>
      ))}
    </>
  );
}
