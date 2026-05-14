/** EvidencePresetOverlay.tsx — Phase 37, Plan 01 (APR-02) */

import { useRef, type ReactElement } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import type { ObservatoryGhostTrace } from "../world/observatory-ghost-memory";
import { OBSERVATORY_STATION_POSITIONS } from "../world/observatory-world-template";
import type { HuntStationId } from "../world/types";

// ──────────────────────────────────────────────────────────────────────────────
// Pure helper (exported for unit tests)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Returns unique stationIds from traces where sourceKind === "receipt".
 * Insertion order of first occurrence is preserved.
 */
export function getEvidenceStationIds(traces: ObservatoryGhostTrace[]): HuntStationId[] {
  const seen = new Set<HuntStationId>();
  const result: HuntStationId[] = [];
  for (const trace of traces) {
    if (trace.sourceKind === "receipt" && !seen.has(trace.stationId)) {
      seen.add(trace.stationId);
      result.push(trace.stationId);
    }
  }
  return result;
}

// ──────────────────────────────────────────────────────────────────────────────
// Sub-component: EvidenceStationHalo
// ──────────────────────────────────────────────────────────────────────────────

interface EvidenceStationHaloProps {
  position: [number, number, number];
}

function EvidenceStationHalo({ position }: EvidenceStationHaloProps): ReactElement {
  const groupRef = useRef<THREE.Group>(null);

  useFrame(({ clock: _clock }, delta) => {
    if (groupRef.current) {
      groupRef.current.rotation.y += delta * 0.4;
    }
  });

  return (
    <group
      ref={groupRef}
      position={[position[0], position[1] + 1.0, position[2]]}
    >
      <mesh>
        {/* innerRadius=1.8, tube=0.06, radialSegments=8, tubularSegments=64 */}
        <torusGeometry args={[1.8, 0.06, 8, 64]} />
        <meshBasicMaterial
          color="#d4a93a"
          transparent
          toneMapped={false}
          depthWrite={false}
          blending={THREE.AdditiveBlending}
          opacity={0.7}
        />
      </mesh>
    </group>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Main export: EvidencePresetOverlay
// ──────────────────────────────────────────────────────────────────────────────

export interface EvidencePresetOverlayProps {
  traces: ObservatoryGhostTrace[];
}

/**
 * Renders a gold spinning torus ring at each station that has receipt traces (APR-02).
 * Returns null when no receipt traces exist.
 */
export function EvidencePresetOverlay({ traces }: EvidencePresetOverlayProps): ReactElement | null {
  const stationIds = getEvidenceStationIds(traces);
  if (stationIds.length === 0) return null;

  return (
    <>
      {stationIds.map((stationId) => {
        const pos = OBSERVATORY_STATION_POSITIONS[stationId];
        if (!pos) return null;
        return (
          <EvidenceStationHalo
            key={stationId}
            position={[pos[0], pos[1], pos[2]]}
          />
        );
      })}
    </>
  );
}
