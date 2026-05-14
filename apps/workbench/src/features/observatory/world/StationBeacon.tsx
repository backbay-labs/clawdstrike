/**
 * StationBeacon.tsx — STN-03
 *
 * Pulsing beacon sprite + point light for stations at extreme distance (500+ units).
 * Uses AdditiveBlending radial gradient sprite for visibility through fog.
 * Animates opacity + light intensity via useFrame without per-frame allocations.
 */

import { useRef, useMemo, type ReactElement } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

export interface StationBeaconProps {
  position: [number, number, number];
  colorHex: string;
  /** Base opacity for the beacon sprite. Default: 0.7. Pass 0.15 for uncharted dim marker. */
  opacity?: number;
}

function buildBeaconTexture(): THREE.CanvasTexture {
  const size = 64;
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
    gradient.addColorStop(0.35, "rgba(255,255,255,0.7)");
    gradient.addColorStop(1, "rgba(255,255,255,0)");
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, size, size);
  }
  return new THREE.CanvasTexture(canvas);
}

/**
 * Pulsing beacon sprite + point light visible at extreme distances.
 * Pre-allocates refs at component level — no allocations in useFrame.
 */
export function StationBeacon({ position, colorHex, opacity = 0.7 }: StationBeaconProps): ReactElement {
  const spriteRef = useRef<THREE.Sprite>(null);
  const lightRef = useRef<THREE.PointLight>(null);
  const baseOpacity = opacity;

  const texture = useMemo(
    () => (typeof document !== "undefined" ? buildBeaconTexture() : null),
    [],
  );

  const material = useMemo(
    () =>
      new THREE.SpriteMaterial({
        map: texture,
        transparent: true,
        blending: THREE.AdditiveBlending,
        toneMapped: false,
        depthWrite: false,
        color: new THREE.Color(colorHex),
        opacity: baseOpacity,
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [colorHex, texture, baseOpacity],
  );

  useFrame(({ clock }) => {
    const pulse = Math.sin(clock.elapsedTime * 1.5);
    if (spriteRef.current) {
      // For normal beacons (opacity 0.7): pulse 0.7±0.3
      // For dim uncharted markers (opacity 0.15): gentle pulse 0.15±0.05
      const pulseRange = baseOpacity * 0.43;
      spriteRef.current.material.opacity = baseOpacity + pulse * pulseRange;
    }
    if (lightRef.current) {
      lightRef.current.intensity = 2.5 + pulse * 0.5;
    }
  });

  return (
    <group position={position}>
      <sprite ref={spriteRef} material={material} scale={[4, 4, 1]} />
      <pointLight
        ref={lightRef}
        color={colorHex}
        intensity={3.0}
        distance={100}
        decay={2}
      />
    </group>
  );
}
