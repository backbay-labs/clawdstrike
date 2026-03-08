import {
  getHuntSpiritMeta,
} from "./defaults";
import type {
  HuntSpiritMotionEnvelope,
  HuntSpiritRuntimeInput,
  HuntSpiritRuntimeState,
  HuntSpiritStance,
  HuntSpiritState,
} from "./types";

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function resolveStance(
  spirit: HuntSpiritState,
  input: HuntSpiritRuntimeInput,
): HuntSpiritStance {
  if (input.isAttachMode) return "absorb";
  if (input.likelyIntent === "cite" || input.likelyIntent === "compare") return "witness";
  if (input.likelyIntent === "mount" || input.likelyIntent === "run-input") return "absorb";
  if (input.likelyIntent === "attach-target" || input.likelyIntent === "watch") return "focus";

  switch (spirit.liveMood) {
    case "witnessing":
      return "witness";
    case "transit":
      return "transit";
    case "focused":
    case "pressured":
      return "focus";
    case "attuned":
      return "attune";
    case "dormant":
    default:
      return "idle";
  }
}

function deriveMotionEnvelope(
  spirit: HuntSpiritState,
  stance: HuntSpiritStance,
  fieldStrength: number,
): HuntSpiritMotionEnvelope {
  const confidence = clamp01(spirit.confidenceScore / 100);
  const field = clamp01(fieldStrength);
  const base: HuntSpiritMotionEnvelope = {
    arousal: 0.18 + confidence * 0.44,
    valence: 0.46 + field * 0.26,
    openness: 0.32 + confidence * 0.3,
    aura: 0.16 + field * 0.52,
    pulse: 0.12 + confidence * 0.34,
    tilt: 0.08 + field * 0.22,
  };

  switch (stance) {
    case "transit":
      return { ...base, arousal: 0.9, aura: 0.88, pulse: 0.82, tilt: 0.3 };
    case "absorb":
      return { ...base, arousal: 0.72, aura: 0.78, pulse: 0.7, openness: 0.38 };
    case "witness":
      return { ...base, arousal: 0.62, aura: 0.66, pulse: 0.52, openness: 0.44 };
    case "focus":
      return { ...base, arousal: 0.58, aura: 0.56, pulse: 0.48, tilt: 0.16 };
    case "attune":
      return { ...base, arousal: 0.44, aura: 0.42, pulse: 0.28 };
    case "idle":
    default:
      return { ...base, arousal: 0.24, aura: 0.24, pulse: 0.16, tilt: 0.06 };
  }
}

export function deriveHuntSpiritRuntimeState(
  spirit: HuntSpiritState | null,
  input: HuntSpiritRuntimeInput = {},
): HuntSpiritRuntimeState {
  if (!spirit) {
    return {
      kind: null,
      label: null,
      accentColor: null,
      contour: null,
      mood: "dormant",
      stance: "idle",
      reason: null,
      emphasis: [],
      fieldStrength: 0,
      shouldRender: false,
      motion: {
        arousal: 0,
        valence: 0,
        openness: 0,
        aura: 0,
        pulse: 0,
        tilt: 0,
      },
      activeStationId: input.activeStationId ?? null,
      currentShell: input.currentShell ?? null,
      currentLens: input.currentLens ?? null,
    };
  }

  const meta = getHuntSpiritMeta(spirit.kind);
  const stance = resolveStance(spirit, input);
  const upstreamConfidence = clamp01((input.confidenceScore ?? spirit.confidenceScore) / 100);
  const fieldStrength = clamp01(
    upstreamConfidence * 0.7
      + (input.isActive === false ? 0 : 0.15)
      + (input.isAttachMode ? 0.15 : 0)
      + (input.activeStationId ? 0.08 : 0),
  );
  const emphasis = Array.from(
    new Set([
      ...(meta?.defaultBiases ?? []),
      ...(input.currentLens ? [input.currentLens] : []),
      ...(input.likelyIntent ? [input.likelyIntent] : []),
    ]),
  );

  return {
    kind: spirit.kind,
    label: meta?.label ?? spirit.kind,
    accentColor: meta?.accentColor ?? null,
    contour: meta?.contour ?? null,
    mood: spirit.liveMood,
    stance,
    reason: spirit.bindReason ?? null,
    emphasis,
    fieldStrength,
    shouldRender: input.isActive !== false,
    motion: deriveMotionEnvelope(spirit, stance, fieldStrength),
    activeStationId: input.activeStationId ?? null,
    currentShell: input.currentShell ?? null,
    currentLens: input.currentLens ?? null,
  };
}
