// ---------------------------------------------------------------------------
// Posture — shared utility for deriving system posture state.
//
// Extracted from home-page.tsx so both HomePage and HeartbeatPanel can reuse
// the same derivation logic without duplication.
// ---------------------------------------------------------------------------

export type Posture = "nominal" | "attention" | "critical" | "offline";

export function derivePosture(
  fleetConnected: boolean,
  criticalFindings: number,
  emergingFindings: number,
  enabledGuards: number,
): Posture {
  if (!fleetConnected && enabledGuards === 0) return "offline";
  if (criticalFindings > 0) return "critical";
  if (emergingFindings > 0) return "attention";
  return "nominal";
}

export const POSTURE_CONFIG: Record<Posture, {
  label: string;
  color: string;
  glow: string;
  breathMs: number;
  ringStroke: string;
}> = {
  nominal: {
    label: "NOMINAL",
    color: "#4ade80",
    glow: "rgba(74,222,128,0.15)",
    breathMs: 5000,
    ringStroke: "#4ade80",
  },
  attention: {
    label: "ATTENTION",
    color: "#d4a84b",
    glow: "rgba(212,168,75,0.2)",
    breathMs: 2800,
    ringStroke: "#d4a84b",
  },
  critical: {
    label: "CRITICAL",
    color: "#ef4444",
    glow: "rgba(239,68,68,0.25)",
    breathMs: 1600,
    ringStroke: "#ef4444",
  },
  offline: {
    label: "OFFLINE",
    color: "#6f7f9a",
    glow: "rgba(111,127,154,0.08)",
    breathMs: 0,
    ringStroke: "#6f7f9a",
  },
};
