/**
 * ProbeDeltaCard.tsx — Phase 40 PRBI-01, PRBI-02, PRBI-03, PRBI-04
 *
 * A floating glassmorphism DOM card rendered via drei Html that appears
 * above a station after a probe fires and completes.
 *
 * Shows:
 *   - Station label + pressure shift direction arrow
 *   - Delta summary sentence (what changed)
 *   - Why-it-matters sentence (why it's significant)
 *   - Clickable recommended action button (one-click navigation)
 *
 * Dismisses on outer div click. Action button navigates to the relevant
 * workbench route and then dismisses.
 */

import type { JSX } from "react";
import type {
  ObservatoryProbeGuidance,
  ObservatoryRecommendation,
} from "../../world/observatory-recommendations";
import { openObservatoryRecommendationRoute } from "../../commands/observatory-command-actions";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ProbeDeltaCardProps {
  /** Probe guidance data including delta, whyItMatters, and recommendation. */
  guidance: ObservatoryProbeGuidance;
  /** Called when the card should be dismissed (outer click or action button). */
  onDismiss: () => void;
  /**
   * Optional override for the action button click handler.
   * Defaults to openObservatoryRecommendationRoute.
   */
  onActionClick?: (recommendation: ObservatoryRecommendation) => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface ShiftArrowConfig {
  symbol: string;
  color: string;
}

function getShiftArrow(kind: ObservatoryProbeGuidance["delta"]["kind"]): ShiftArrowConfig {
  switch (kind) {
    case "lane-up":
    case "pressure-shift":
      return { symbol: "↑", color: "#f87171" }; // text-red-400
    case "cause-shift":
      return { symbol: "→", color: "#fbbf24" }; // text-amber-400
    case "steady":
    default:
      return { symbol: "—", color: "#60a5fa" }; // text-blue-400
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ProbeDeltaCard({
  guidance,
  onDismiss,
  onActionClick,
}: ProbeDeltaCardProps): JSX.Element {
  const shiftArrow = getShiftArrow(guidance.delta.kind);
  const handleActionClick = onActionClick ?? openObservatoryRecommendationRoute;

  return (
    <div
      data-testid="probe-delta-card"
      onClick={onDismiss}
      style={{
        background: "var(--hud-bg, rgba(8, 12, 24, 0.75))",
        border: "var(--hud-border, 1px solid rgba(255, 255, 255, 0.06))",
        backdropFilter: "var(--hud-blur, blur(12px))",
        WebkitBackdropFilter: "var(--hud-blur, blur(12px))",
        borderRadius: "8px",
        padding: "10px 14px",
        maxWidth: "260px",
        pointerEvents: "auto",
        cursor: "pointer",
        fontFamily: "'JetBrains Mono', 'Fira Mono', 'Consolas', monospace",
        userSelect: "none",
      }}
    >
      {/* Header: station label + shift arrow */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "6px",
          marginBottom: "4px",
        }}
      >
        <span
          style={{
            color: "var(--hud-text, rgba(255, 255, 255, 0.85))",
            fontSize: "11px",
            fontWeight: "bold",
            letterSpacing: "0.06em",
            textTransform: "uppercase",
          }}
        >
          {guidance.stationLabel}
        </span>
        <span
          style={{
            fontSize: "14px",
            color: shiftArrow.color,
            lineHeight: 1,
          }}
        >
          {shiftArrow.symbol}
        </span>
      </div>

      {/* Delta summary (PRBI-02) */}
      <div
        style={{
          color: "var(--hud-text, rgba(255, 255, 255, 0.85))",
          fontSize: "10px",
          lineHeight: "1.4",
          marginBottom: "4px",
        }}
      >
        {guidance.delta.summary}
      </div>

      {/* Why it matters (PRBI-03) */}
      <div
        style={{
          color: "var(--hud-text-muted, rgba(255, 255, 255, 0.45))",
          fontSize: "9px",
          lineHeight: "1.3",
          marginBottom: guidance.recommendation ? "6px" : "0",
        }}
      >
        {guidance.whyItMatters}
      </div>

      {/* Recommended action button (PRBI-04) */}
      {guidance.recommendation && (
        <button
          data-testid="probe-delta-action"
          onClick={(e) => {
            e.stopPropagation();
            handleActionClick(guidance.recommendation!);
            onDismiss();
          }}
          style={{
            background: "rgba(61, 191, 132, 0.15)",
            border: "1px solid rgba(61, 191, 132, 0.3)",
            borderRadius: "4px",
            color: "#3dbf84",
            fontSize: "9px",
            fontFamily: "inherit",
            fontWeight: "bold",
            letterSpacing: "0.04em",
            padding: "3px 8px",
            cursor: "pointer",
            width: "100%",
            textAlign: "left",
          }}
        >
          {guidance.recommendation.title}
        </button>
      )}
    </div>
  );
}
