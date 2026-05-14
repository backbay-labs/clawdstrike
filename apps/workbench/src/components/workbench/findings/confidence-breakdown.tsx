/**
 * ConfidenceBreakdown -- 5-factor confidence score decomposition.
 *
 * Renders a compact card showing how the composite confidence score
 * is assembled from five weighted factors:
 *   Source Reliability (35%), Anomaly Score (25%), Pattern Match (20%),
 *   Correlation Boost (15%), Reputation Factor (5%).
 *
 * Designed to embed in FindingDetail as a collapsible section.
 */

import type { Finding } from "@/lib/workbench/finding-engine";
import type { Signal } from "@/lib/workbench/signal-pipeline";

export interface ConfidenceBreakdownProps {
  finding: Finding;
  signals: Signal[];
}

/** Confidence weight constants (mirroring signal-pipeline.ts W_* constants). */
const WEIGHTS = {
  sourceConfidence: 0.35,
  anomalyScore: 0.25,
  patternMatchScore: 0.2,
  correlationBoost: 0.15,
  reputationFactor: 0.05,
} as const;

/** Human-readable display names for each factor. */
const FACTOR_LABELS: Record<keyof typeof WEIGHTS, string> = {
  sourceConfidence: "Source Reliability",
  anomalyScore: "Anomaly Score",
  patternMatchScore: "Pattern Match",
  correlationBoost: "Correlation Boost",
  reputationFactor: "Reputation Factor",
};

/** Weight percentages for the label column. */
const WEIGHT_LABELS: Record<keyof typeof WEIGHTS, string> = {
  sourceConfidence: "35%",
  anomalyScore: "25%",
  patternMatchScore: "20%",
  correlationBoost: "15%",
  reputationFactor: "5%",
};

/** Factor ordering for consistent display. */
const FACTOR_ORDER: (keyof typeof WEIGHTS)[] = [
  "sourceConfidence",
  "anomalyScore",
  "patternMatchScore",
  "correlationBoost",
  "reputationFactor",
];

interface ComputedFactors {
  sourceConfidence: number;
  anomalyScore: number;
  patternMatchScore: number;
  correlationBoost: number;
  reputationFactor: number;
}

/**
 * Derive aggregate factor values from a finding's signals.
 *
 * - sourceConfidence: average of signal.confidence across all signals
 * - anomalyScore: max anomaly score from signals with anomaly data
 * - patternMatchScore: 1.0 if any signal has data.patternId, else 0
 * - correlationBoost: scales by signal count (2 = 0.3, 5+ = 0.8, capped at 1.0)
 * - reputationFactor: 1.0 for local signals, attenuated if swarm signals present
 */
function computeFactors(signals: Signal[]): ComputedFactors {
  if (signals.length === 0) {
    return {
      sourceConfidence: 0,
      anomalyScore: 0,
      patternMatchScore: 0,
      correlationBoost: 0,
      reputationFactor: 0,
    };
  }

  // sourceConfidence: average of signal.confidence
  const sourceConfidence =
    signals.reduce((sum, s) => sum + s.confidence, 0) / signals.length;

  // anomalyScore: max anomaly score from anomaly-type signals
  let anomalyScore = 0;
  for (const s of signals) {
    const score = s.data.anomaly?.score;
    if (typeof score === "number" && score > anomalyScore) {
      anomalyScore = score;
    }
  }

  // patternMatchScore: 1.0 if any signal has patternId
  const patternMatchScore = signals.some((s) => s.data.patternId) ? 1.0 : 0;

  // correlationBoost: scale by signal count
  let correlationBoost = 0;
  if (signals.length >= 5) {
    correlationBoost = 0.8;
  } else if (signals.length >= 2) {
    // Linear interpolation: 2 signals = 0.3, 5 signals = 0.8
    correlationBoost = 0.3 + ((signals.length - 2) / 3) * 0.5;
  }
  correlationBoost = Math.min(1.0, correlationBoost);

  // reputationFactor: 1.0 for local, attenuated if swarm signals present
  const swarmCount = signals.filter(
    (s) => s.source.provenance === "swarm_intel",
  ).length;
  const reputationFactor =
    swarmCount > 0 ? 1.0 - (swarmCount / signals.length) * 0.3 : 1.0;

  return {
    sourceConfidence,
    anomalyScore,
    patternMatchScore,
    correlationBoost,
    reputationFactor,
  };
}

/**
 * Color for a weighted contribution value:
 * - >= 0.15: green (strong signal)
 * - 0.05-0.15: amber (moderate)
 * - < 0.05: muted (weak)
 */
function contributionColor(weightedValue: number): string {
  if (weightedValue >= 0.15) return "#3dbf84";
  if (weightedValue >= 0.05) return "#d4a84b";
  return "#6f7f9a";
}

export function ConfidenceBreakdown({
  finding,
  signals,
}: ConfidenceBreakdownProps) {
  // Filter signals to only those belonging to this finding
  const findingSignals = signals.filter((s) =>
    finding.signalIds.includes(s.id),
  );

  const factors = computeFactors(findingSignals);
  const confidencePct = Math.round(finding.confidence * 100);

  return (
    <div
      style={{
        borderRadius: 8,
        border: "1px solid rgba(45, 50, 64, 0.4)",
        backgroundColor: "#0b0d13",
        padding: "10px 12px",
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 8,
        }}
      >
        <span
          style={{
            fontSize: 10,
            fontWeight: 600,
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            color: "rgba(236, 231, 220, 0.8)",
          }}
        >
          Confidence Breakdown
        </span>
        <span
          style={{
            fontSize: 10,
            fontWeight: 600,
            fontFamily: "monospace",
            color:
              confidencePct >= 80
                ? "#3dbf84"
                : confidencePct >= 50
                  ? "#d4a84b"
                  : "#6f7f9a",
            backgroundColor:
              confidencePct >= 80
                ? "rgba(61, 191, 132, 0.12)"
                : confidencePct >= 50
                  ? "rgba(212, 168, 75, 0.12)"
                  : "rgba(111, 127, 154, 0.12)",
            borderRadius: 4,
            padding: "2px 6px",
          }}
        >
          {confidencePct}%
        </span>
      </div>

      {/* Factor rows */}
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        {FACTOR_ORDER.map((key) => {
          const rawValue = factors[key];
          const weight = WEIGHTS[key];
          const weighted = weight * rawValue;
          const color = contributionColor(weighted);

          return (
            <div
              key={key}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
              }}
            >
              {/* Factor name */}
              <span
                style={{
                  width: 110,
                  flexShrink: 0,
                  fontSize: 10,
                  color: "rgba(200, 208, 219, 0.7)",
                }}
              >
                {FACTOR_LABELS[key]}
              </span>

              {/* Weight label */}
              <span
                style={{
                  width: 28,
                  flexShrink: 0,
                  fontSize: 9,
                  fontFamily: "monospace",
                  color: "rgba(111, 127, 154, 0.5)",
                  textAlign: "right",
                }}
              >
                {WEIGHT_LABELS[key]}
              </span>

              {/* Horizontal bar */}
              <div
                style={{
                  flex: 1,
                  height: 6,
                  borderRadius: 3,
                  backgroundColor: "rgba(45, 50, 64, 0.4)",
                  overflow: "hidden",
                  minWidth: 40,
                }}
              >
                <div
                  style={{
                    width: `${Math.round(rawValue * 100)}%`,
                    height: "100%",
                    borderRadius: 3,
                    backgroundColor: color,
                    transition: "width 0.3s ease",
                  }}
                />
              </div>

              {/* Weighted contribution */}
              <span
                style={{
                  width: 36,
                  flexShrink: 0,
                  fontSize: 9,
                  fontFamily: "monospace",
                  textAlign: "right",
                  color,
                }}
              >
                {(weighted * 100).toFixed(1)}%
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
