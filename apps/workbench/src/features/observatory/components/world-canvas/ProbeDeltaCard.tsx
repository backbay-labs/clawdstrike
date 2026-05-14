import type { JSX } from "react";
import type {
  ObservatoryProbeGuidance,
  ObservatoryRecommendation,
} from "../../world/observatory-recommendations";
import { openObservatoryRecommendationRoute } from "../../commands/observatory-command-actions";

export interface ProbeDeltaCardProps {
  guidance: ObservatoryProbeGuidance;
  onDismiss: () => void;
  onActionClick?: (recommendation: ObservatoryRecommendation) => void;
}

function getShiftArrow(kind: ObservatoryProbeGuidance["delta"]["kind"]): { symbol: string; color: string } {
  switch (kind) {
    case "lane-up":
    case "pressure-shift":
      return { symbol: "↑", color: "#f87171" };
    case "cause-shift":
      return { symbol: "→", color: "#fbbf24" };
    case "steady":
      return { symbol: "—", color: "#60a5fa" };
    default: {
      const _exhaustive: never = kind;
      void _exhaustive;
      return { symbol: "→", color: "#60a5fa" };
    }
  }
}

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
