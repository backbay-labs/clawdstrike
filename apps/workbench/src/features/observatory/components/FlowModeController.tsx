// FlowModeController — OBS-06 Easter-egg character controller wrapper.
// Phase 3 Plan 03-01: minimal implementation satisfying test contract.
// Full Rapier physics controller ported in Phase 3 Plan 03-02 (character controller task).

export interface FlowModeControllerProps {
  characterControllerEnabled: boolean;
  onEnable: () => void;
}

// When characterControllerEnabled is false, renders null.
// When true, renders a placeholder that will be replaced with Rapier physics in 03-02.
// The double-click Easter-egg is handled at the ObservatoryTab level (event dispatch via onEnable).
export function FlowModeController({ characterControllerEnabled }: FlowModeControllerProps) {
  if (!characterControllerEnabled) {
    return null;
  }

  // Placeholder — Rapier-based character controller implemented in 03-02.
  // Returns null in jsdom (no WebGL context) — fine for testing.
  return null;
}
