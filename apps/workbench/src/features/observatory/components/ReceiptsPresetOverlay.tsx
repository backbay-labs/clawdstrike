/** ReceiptsPresetOverlay.tsx — Phase 37, Plan 01 (APR-03) */

import { useRef, type ReactElement } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import type { ObservatoryGhostTrace } from "../world/observatory-ghost-memory";
import { OBSERVATORY_STATION_POSITIONS } from "../world/observatory-world-template";
import type { HuntStationId } from "../world/types";

// ──────────────────────────────────────────────────────────────────────────────
// Pure helpers (exported for unit tests)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Groups receipt traces by stationId. Only stations with at least one receipt
 * trace appear in the result. Insertion order of first occurrence is preserved.
 */
export function groupReceiptTracesByStation(
  traces: ObservatoryGhostTrace[],
): Map<HuntStationId, ObservatoryGhostTrace[]> {
  const map = new Map<HuntStationId, ObservatoryGhostTrace[]>();
  for (const trace of traces) {
    if (trace.sourceKind !== "receipt") continue;
    const list = map.get(trace.stationId) ?? [];
    list.push(trace);
    map.set(trace.stationId, list);
  }
  return map;
}

/**
 * Derives a verdict color from a ghost trace:
 *   - Headline includes "denied" (case-insensitive) → red DENY  (#ef4444)
 *   - Detail includes "audit" (case-insensitive) OR score < 0  → amber AUDIT (#f59e0b)
 *   - Otherwise                                                 → green ALLOW (#22c55e)
 */
export function verdictColor(trace: ObservatoryGhostTrace): string {
  if (trace.headline.toLowerCase().includes("denied")) {
    return "#ef4444";
  }
  if (trace.detail.toLowerCase().includes("audit") || trace.score < 0) {
    return "#f59e0b";
  }
  return "#22c55e";
}

// ──────────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────────

/** Y positions for up to 3 stacked badge meshes */
const BADGE_Y_OFFSETS = [1.4, 1.9, 2.4] as const;
const BADGE_BOB_SPEED = 1.1;
const BADGE_BOB_AMPLITUDE = 0.12;

// ──────────────────────────────────────────────────────────────────────────────
// Sub-component: ReceiptBadge
// ──────────────────────────────────────────────────────────────────────────────

interface ReceiptBadgeProps {
  basePosition: [number, number, number];
  color: string;
  phase: number;
}

function ReceiptBadge({ basePosition, color, phase }: ReceiptBadgeProps): ReactElement {
  const meshRef = useRef<THREE.Mesh>(null);
  const baseY = basePosition[1];

  useFrame(({ clock }) => {
    const mesh = meshRef.current;
    if (!mesh) return;
    mesh.position.y = baseY + Math.sin(clock.elapsedTime * BADGE_BOB_SPEED + phase) * BADGE_BOB_AMPLITUDE;
  });

  return (
    <mesh
      ref={meshRef}
      position={basePosition}
    >
      <boxGeometry args={[0.28, 0.28, 0.04]} />
      <meshBasicMaterial
        color={color}
        transparent
        toneMapped={false}
        depthWrite={false}
        blending={THREE.AdditiveBlending}
        opacity={0.8}
      />
    </mesh>
  );
}

// ──────────────────────────────────────────────────────────────────────────────
// Main export: ReceiptsPresetOverlay
// ──────────────────────────────────────────────────────────────────────────────

export interface ReceiptsPresetOverlayProps {
  traces: ObservatoryGhostTrace[];
}

/**
 * Renders verdict-colored badge meshes (ALLOW=green, DENY=red, AUDIT=amber)
 * stacked vertically at each station that has receipt trace history (APR-03).
 * Up to 3 badges per station. Returns null when no receipt traces exist.
 */
export function ReceiptsPresetOverlay({ traces }: ReceiptsPresetOverlayProps): ReactElement | null {
  const byStation = groupReceiptTracesByStation(traces);
  if (byStation.size === 0) return null;

  return (
    <>
      {Array.from(byStation.entries()).map(([stationId, stationTraces]) => {
        const pos = OBSERVATORY_STATION_POSITIONS[stationId];
        if (!pos) return null;
        const capped = stationTraces.slice(0, 3);
        return (
          <group key={stationId}>
            {capped.map((trace, index) => {
              const yOffset = BADGE_Y_OFFSETS[index] ?? 1.4 + index * 0.5;
              const phase = (index / 3) * Math.PI * 2;
              return (
                <ReceiptBadge
                  key={trace.id}
                  basePosition={[pos[0], yOffset, pos[2]]}
                  color={verdictColor(trace)}
                  phase={phase}
                />
              );
            })}
          </group>
        );
      })}
    </>
  );
}
