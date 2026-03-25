import type {
  ReceiptPostureSummary,
  ReceiptPostureState,
} from "@/features/swarm/stores/swarm-board-store";

export interface SwarmBoardAtmosphere {
  state: ReceiptPostureState;
  vignette: string;
  glow: string;
  noiseOpacity: number;
}

const ATMOSPHERE_PALETTE: Record<
  ReceiptPostureState,
  { glow: string; mid: string; outer: string }
> = {
  neutral: { glow: "38, 47, 64", mid: "8, 10, 16", outer: "2, 3, 5" },
  allow: { glow: "56, 168, 118", mid: "6, 14, 11", outer: "2, 4, 3" },
  warn: { glow: "212, 168, 75", mid: "16, 12, 6", outer: "5, 4, 2" },
  deny: { glow: "184, 84, 80", mid: "18, 8, 9", outer: "5, 2, 3" },
};

export function buildSwarmBoardAtmosphere(
  posture: ReceiptPostureSummary,
): SwarmBoardAtmosphere {
  const palette = ATMOSPHERE_PALETTE[posture.dominantState];
  const intensity = Math.min(
    1,
    posture.denyRatio * 1.2 + posture.warnRatio * 0.8 + posture.allowRatio * 0.35,
  );
  const glowAlpha = posture.dominantState === "neutral" ? 0.04 : 0.06 + intensity * 0.12;
  const midAlpha = 0.2 + intensity * 0.18;
  const outerAlpha = 0.72 + intensity * 0.16;

  return {
    state: posture.dominantState,
    glow: `radial-gradient(circle at 50% 38%, rgba(${palette.glow}, ${glowAlpha.toFixed(3)}) 0%, rgba(${palette.glow}, 0) 58%)`,
    vignette: `radial-gradient(ellipse at 50% 50%, rgba(12,14,20,0) 0%, rgba(${palette.mid}, ${midAlpha.toFixed(3)}) 62%, rgba(${palette.outer}, ${outerAlpha.toFixed(3)}) 100%)`,
    noiseOpacity: Number((0.32 + intensity * 0.14).toFixed(3)),
  };
}
