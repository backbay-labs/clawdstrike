import type { SpiritKind, SpiritMood } from "./types";

export interface SpiritMoodSignals {
  kind: SpiritKind | null;
  hasLintErrors: boolean; // true when any policy tab has validation.errors.length > 0
  probeActive: boolean; // true when observatory activeProbes > 0
}

/**
 * Pure function — derives SpiritMood from observable workbench signals.
 * Priority: dormant > alert > active > idle
 */
export function deriveSpiritMood(signals: SpiritMoodSignals): SpiritMood {
  if (signals.kind === null) return "dormant";
  if (signals.hasLintErrors) return "alert";
  if (signals.probeActive) return "active";
  return "idle";
}
