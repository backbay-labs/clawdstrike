/**
 * GhostTraceLayer.tsx — Phase 35, Plan 01 (GHO-01, GHO-02)
 *
 * Renders translucent holographic marker meshes at observatory station positions.
 * Each station with ghost traces shows:
 *   - A pulsing torus ring at the base (emissive cyan, AdditiveBlending)
 *   - A glyph mesh above it per trace:
 *       sourceKind="receipt"  → sphere  (gold)
 *       sourceKind="finding"  → octahedron  (violet)
 *
 * Markers use MeshBasicMaterial with toneMapped: false so they bloom in post-processing.
 * All THREE objects are allocated in useMemo/mount — zero allocations inside useFrame.
 * opacityScale multiplies all material opacities (1.0 = full, 0.2 = dimmed inactive preset).
 */

import { useRef, useMemo, useEffect, type ReactElement } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import type { ObservatoryGhostTrace } from "../world/observatory-ghost-memory";
import { OBSERVATORY_STATION_POSITIONS } from "../world/observatory-world-template";
import type { HuntStationId } from "../world/types";

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

const BASE_RING_OPACITY = 0.72;

/** Y offsets for stacking multiple glyphs per station */
const GLYPH_Y_OFFSETS = [0.9, 1.7, 2.5, 3.3, 4.1] as const;

// ──────────────────────────────────────────────────────────────────────────────
// Public interface
// ──────────────────────────────────────────────────────────────────────────────

export interface GhostTraceLayerProps {
  traces: ObservatoryGhostTrace[];
  /** 0.0–1.0 scalar applied to all material opacities. 1.0 = full, 0.2 = dimmed (inactive preset) */
  opacityScale: number;
}

// ──────────────────────────────────────────────────────────────────────────────
// Sub-component: GhostStationMarkers
// ──────────────────────────────────────────────────────────────────────────────

interface GhostStationMarkersProps {
  position: [number, number, number];
  traces: ObservatoryGhostTrace[];
  opacityScale: number;
}

function GhostStationMarkers({ position, traces, opacityScale }: GhostStationMarkersProps): ReactElement {
  const floatRef = useRef<THREE.Group>(null);
  const ringMatRef = useRef<THREE.MeshBasicMaterial>(null);
  const glyphMatRefs = useRef<THREE.MeshBasicMaterial[]>([]);

  // Keep opacityScale accessible inside useFrame without stale closure
  const opacityScaleRef = useRef(opacityScale);
  useEffect(() => {
    opacityScaleRef.current = opacityScale;
  }, [opacityScale]);

  // Stagger animations by station position so markers don't float in sync
  const phaseOffset = useMemo(() => {
    return (position[0] * 17 + position[2] * 31) % (Math.PI * 2);
  }, [position]);

  useFrame(({ clock }) => {
    const t = clock.elapsedTime;
    if (floatRef.current) {
      floatRef.current.position.y = Math.sin(t * 0.9 + phaseOffset) * 0.4;
    }
    const opacity = BASE_RING_OPACITY * opacityScaleRef.current;
    if (ringMatRef.current) {
      ringMatRef.current.opacity = opacity;
    }
    for (const mat of glyphMatRefs.current) {
      if (mat) {
        mat.opacity = opacity;
      }
    }
  });

  return (
    <group position={position}>
      {/* Floating animation group */}
      <group ref={floatRef}>
        {/* Base ring */}
        <mesh>
          <torusGeometry args={[0.55, 0.04, 8, 32]} />
          <meshBasicMaterial
            ref={ringMatRef}
            color="#7ad7d0"
            transparent
            toneMapped={false}
            depthWrite={false}
            blending={THREE.AdditiveBlending}
            opacity={BASE_RING_OPACITY * opacityScale}
          />
        </mesh>
        {/* Per-trace glyph meshes */}
        {traces.map((trace, index) => {
          const yOffset = GLYPH_Y_OFFSETS[index] ?? (0.9 + index * 0.8);
          return (
            <mesh
              key={trace.id}
              position={[0, yOffset, 0]}
              ref={(node) => {
                if (node) {
                  const mat = node.material as THREE.MeshBasicMaterial;
                  glyphMatRefs.current[index] = mat;
                }
              }}
            >
              {trace.sourceKind === "receipt" ? (
                <sphereGeometry args={[0.12, 8, 6]} />
              ) : (
                <octahedronGeometry args={[0.14]} />
              )}
              <meshBasicMaterial
                color={trace.sourceKind === "receipt" ? "#b88f4d" : "#b49cff"}
                transparent
                toneMapped={false}
                depthWrite={false}
                blending={THREE.AdditiveBlending}
                opacity={BASE_RING_OPACITY * opacityScale}
              />
            </mesh>
          );
        })}
      </group>
    </group>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Main export: GhostTraceLayer
// ──────────────────────────────────────────────────────────────────────────────

export function GhostTraceLayer({ traces, opacityScale }: GhostTraceLayerProps): ReactElement | null {
  const byStation = useMemo(() => {
    const map = new Map<HuntStationId, ObservatoryGhostTrace[]>();
    for (const trace of traces) {
      const list = map.get(trace.stationId) ?? [];
      list.push(trace);
      map.set(trace.stationId, list);
    }
    return map;
  }, [traces]);

  if (byStation.size === 0) return null;

  return (
    <>
      {Array.from(byStation.entries()).map(([stationId, stationTraces]) => {
        const pos = OBSERVATORY_STATION_POSITIONS[stationId];
        if (!pos) return null;
        return (
          <GhostStationMarkers
            key={stationId}
            position={[pos[0], pos[1] + 1.2, pos[2]]}
            traces={stationTraces}
            opacityScale={opacityScale}
          />
        );
      })}
    </>
  );
}
