// scene-math.ts — pure math utilities for spirit-driven 3D scene computations.
// No React, no Three.js — pure TypeScript for testability.
// Ported from: apps/workbench/src/components/ui/yaml-editor.tsx (blendHex)
// Reference: NexusSpiritCompanion.tsx (huntronomer) for affinity ring patterns.

import type { SpiritKind } from "./types";
import type { HuntStationId } from "@/features/observatory/world/types";

/**
 * Linear RGB interpolation between two 6-digit hex colors.
 * t=0 returns base exactly, t=1 returns target exactly.
 */
export function blendHex(base: string, target: string, t: number): string {
  const parse = (h: string) => [
    parseInt(h.slice(1, 3), 16),
    parseInt(h.slice(3, 5), 16),
    parseInt(h.slice(5, 7), 16),
  ];
  const [br, bg, bb] = parse(base);
  const [tr, tg, tb] = parse(target);
  const r = Math.round(br + (tr - br) * t).toString(16).padStart(2, "0");
  const g = Math.round(bg + (tg - bg) * t).toString(16).padStart(2, "0");
  const b = Math.round(bb + (tb - bb) * t).toString(16).padStart(2, "0");
  return `#${r}${g}${b}`;
}

/**
 * Per-spirit-kind per-station affinity values in [0, 1].
 * Used to set floor ring opacity and outer radius in ObservatoryWorldCanvas.
 * Sentinel: favors signal + receipts; Oracle: favors receipts + targets;
 * Witness: favors case-notes + targets; Specter: favors run + watch.
 */
export const STATION_AFFINITY_MAP: Record<SpiritKind, Record<HuntStationId, number>> = {
  sentinel: {
    signal: 0.82,
    targets: 0.44,
    run: 0.36,
    receipts: 0.68,
    "case-notes": 0.52,
    watch: 0.30,
  },
  oracle: {
    signal: 0.48,
    targets: 0.72,
    run: 0.28,
    receipts: 0.90,
    "case-notes": 0.56,
    watch: 0.34,
  },
  witness: {
    signal: 0.38,
    targets: 0.76,
    run: 0.32,
    receipts: 0.52,
    "case-notes": 0.88,
    watch: 0.42,
  },
  specter: {
    signal: 0.54,
    targets: 0.38,
    run: 0.84,
    receipts: 0.40,
    "case-notes": 0.44,
    watch: 0.78,
  },
};
