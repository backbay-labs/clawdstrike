import { useEffect, useMemo, useRef, useState } from "react";
import { cn } from "@/lib/utils";


export interface StageScores {
  perception: number;
  cognition: number;
  action: number;
  feedback: number;
}

export interface TrustprintRadarProps {
  /** Scores per stage, 0.0-1.0 (top cosine similarity score from screening) */
  scores: StageScores;
  /** The configured threshold (draws threshold ring) */
  threshold: number;
  /** Ambiguity band (draws ambiguity zone ring) */
  ambiguityBand: number;
  /** Optional: previous scores for comparison overlay (ghost trace) */
  previousScores?: StageScores;
  /** Size variant */
  size?: "sm" | "md" | "lg";
  /** Whether to animate the initial render */
  animated?: boolean;
  /** Click handler for a stage axis */
  onStageClick?: (stage: string) => void;
}


const STAGES = ["perception", "action", "feedback", "cognition"] as const;
type Stage = (typeof STAGES)[number];

/** Axis angles: top=Perception, right=Action, bottom=Feedback, left=Cognition */
const STAGE_ANGLES: Record<Stage, number> = {
  perception: -Math.PI / 2,
  action: 0,
  feedback: Math.PI / 2,
  cognition: Math.PI,
};

const STAGE_LABELS: Record<Stage, string> = {
  perception: "Perception",
  action: "Action",
  feedback: "Feedback",
  cognition: "Cognition",
};

const RING_LEVELS = [0.25, 0.5, 0.75, 1.0];

const SIZE_MAP: Record<NonNullable<TrustprintRadarProps["size"]>, number> = {
  sm: 160,
  md: 240,
  lg: 320,
};

const COLORS = {
  green: "#3dbf84",
  gold: "#d4a84b",
  red: "#c45c5c",
  grid: "#2d3240",
  steel: "#6f7f9a",
  cream: "#ece7dc",
} as const;


function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/** Return the point on an axis at a given normalized radius (0-1). */
function axisPoint(
  stage: Stage,
  normalizedRadius: number,
  chartRadius: number,
  center: number,
): { x: number; y: number } {
  const angle = STAGE_ANGLES[stage];
  const r = normalizedRadius * chartRadius;
  return {
    x: center + Math.cos(angle) * r,
    y: center + Math.sin(angle) * r,
  };
}

/** Determine the zone color for a single score. */
function zoneColor(
  score: number,
  threshold: number,
  band: number,
): string {
  const upper = threshold + band;
  const lower = threshold - band;
  if (score >= upper) return COLORS.red;
  if (score <= lower) return COLORS.green;
  return COLORS.gold;
}

type Zone = "green" | "gold" | "red";

function zoneKey(
  score: number,
  threshold: number,
  band: number,
): Zone {
  const upper = threshold + band;
  const lower = threshold - band;
  if (score >= upper) return "red";
  if (score <= lower) return "green";
  return "gold";
}

/** Determine the overall polygon zone (worst = highest threat). */
function overallZone(
  scores: StageScores,
  threshold: number,
  band: number,
): Zone {
  const zones = STAGES.map((s) => zoneKey(scores[s], threshold, band));
  if (zones.includes("red")) return "red";
  if (zones.includes("gold")) return "gold";
  return "green";
}

/** Build SVG polygon points string from scores. */
function polygonPoints(
  scores: StageScores,
  chartRadius: number,
  center: number,
): string {
  return STAGES.map((stage) => {
    const pt = axisPoint(stage, clamp(scores[stage], 0, 1), chartRadius, center);
    return `${pt.x},${pt.y}`;
  }).join(" ");
}

/** Generate a unique ID prefix for SVG defs to avoid collisions. */
function useUniqueId(prefix: string): string {
  const ref = useRef<string>("");
  if (ref.current === "") {
    ref.current = `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
  }
  return ref.current;
}

/** Label position offset for each axis so labels don't overlap the chart. */
function labelPosition(
  stage: Stage,
  chartRadius: number,
  center: number,
): { x: number; y: number; anchor: "start" | "middle" | "end"; baseline: "auto" | "middle" | "hanging" } {
  const offset = 20;
  const angle = STAGE_ANGLES[stage];
  const r = chartRadius + offset;
  const x = center + Math.cos(angle) * r;
  const y = center + Math.sin(angle) * r;

  switch (stage) {
    case "perception":
      return { x, y: y - 4, anchor: "middle", baseline: "auto" };
    case "action":
      return { x: x + 4, y, anchor: "start", baseline: "middle" };
    case "feedback":
      return { x, y: y + 4, anchor: "middle", baseline: "hanging" };
    case "cognition":
      return { x: x - 4, y, anchor: "end", baseline: "middle" };
  }
}


export function TrustprintRadar({
  scores,
  threshold,
  ambiguityBand,
  previousScores,
  size = "md",
  animated = false,
  onStageClick,
}: TrustprintRadarProps) {
  const svgSize = SIZE_MAP[size];
  const viewBox = svgSize;
  const center = viewBox / 2;
  const chartRadius = viewBox * 0.35;

  const idPrefix = useUniqueId("trustprint-radar");

  const [animProgress, setAnimProgress] = useState(animated ? 0 : 1);
  const animStartRef = useRef<number | null>(null);

  useEffect(() => {
    if (!animated) {
      setAnimProgress(1);
      return;
    }

    setAnimProgress(0);
    animStartRef.current = null;

    let frameId: number;
    const duration = 600;

    const step = (timestamp: number) => {
      if (animStartRef.current === null) {
        animStartRef.current = timestamp;
      }
      const elapsed = timestamp - animStartRef.current;
      const t = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      const eased = 1 - (1 - t) ** 3;
      setAnimProgress(eased);

      if (t < 1) {
        frameId = requestAnimationFrame(step);
      }
    };

    frameId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frameId);
  }, [animated, scores]);

  const animatedScores: StageScores = useMemo(
    () => ({
      perception: scores.perception * animProgress,
      cognition: scores.cognition * animProgress,
      action: scores.action * animProgress,
      feedback: scores.feedback * animProgress,
    }),
    [scores, animProgress],
  );

  const zone = overallZone(scores, threshold, ambiguityBand);
  const fillColor = COLORS[zone];

  const thresholdRadius = clamp(threshold, 0, 1) * chartRadius;
  const lowerBound = clamp(threshold - ambiguityBand, 0, 1) * chartRadius;
  const upperBound = clamp(threshold + ambiguityBand, 0, 1) * chartRadius;

  const ariaLabel = useMemo(() => {
    const parts = STAGES.map(
      (s) => `${STAGE_LABELS[s]}: ${scores[s].toFixed(2)}`,
    );
    return `Trustprint Radar chart. ${parts.join(", ")}. Threshold: ${threshold.toFixed(2)}, ambiguity band: ${ambiguityBand.toFixed(2)}.`;
  }, [scores, threshold, ambiguityBand]);

  return (
    <svg
      width={svgSize}
      height={svgSize}
      viewBox={`0 0 ${viewBox} ${viewBox}`}
      role="img"
      aria-label={ariaLabel}
      className={cn(
        "select-none",
        size === "sm" && "w-40 h-40",
        size === "md" && "w-60 h-60",
        size === "lg" && "w-80 h-80",
      )}
      data-testid="trustprint-radar"
    >
      <defs>
        {/* Gradient for the score polygon fill */}
        <radialGradient id={`${idPrefix}-fill`}>
          <stop offset="0%" stopColor={fillColor} stopOpacity={0.15} />
          <stop offset="100%" stopColor={fillColor} stopOpacity={0.05} />
        </radialGradient>
      </defs>

      {/* ---- Concentric grid rings ---- */}
      {RING_LEVELS.map((level) => (
        <circle
          key={level}
          cx={center}
          cy={center}
          r={level * chartRadius}
          fill="none"
          stroke={COLORS.grid}
          strokeWidth={1}
          data-testid={`ring-${level}`}
        />
      ))}

      {/* ---- Axis lines ---- */}
      {STAGES.map((stage) => {
        const pt = axisPoint(stage, 1, chartRadius, center);
        return (
          <line
            key={stage}
            x1={center}
            y1={center}
            x2={pt.x}
            y2={pt.y}
            stroke={COLORS.grid}
            strokeWidth={1}
          />
        );
      })}

      {/* ---- Ambiguity zone (filled band) ---- */}
      {ambiguityBand > 0 && (
        <circle
          cx={center}
          cy={center}
          r={(lowerBound + upperBound) / 2}
          fill="none"
          stroke={COLORS.gold}
          strokeWidth={upperBound - lowerBound}
          strokeOpacity={0.12}
          data-testid="ambiguity-zone"
        />
      )}

      {/* ---- Threshold ring (dashed) ---- */}
      <circle
        cx={center}
        cy={center}
        r={thresholdRadius}
        fill="none"
        stroke={COLORS.gold}
        strokeWidth={1.5}
        strokeDasharray="6 4"
        data-testid="threshold-ring"
      />

      {/* ---- Ghost trace (previous scores) ---- */}
      {previousScores && (
        <polygon
          points={polygonPoints(previousScores, chartRadius, center)}
          fill="none"
          stroke={COLORS.steel}
          strokeWidth={1.5}
          strokeDasharray="4 3"
          strokeOpacity={0.3}
          fillOpacity={0}
          data-testid="ghost-trace"
        />
      )}

      {/* ---- Score polygon ---- */}
      <polygon
        points={polygonPoints(animatedScores, chartRadius, center)}
        fill={`url(#${idPrefix}-fill)`}
        stroke={fillColor}
        strokeWidth={2}
        strokeLinejoin="round"
        data-testid="score-polygon"
      />

      {/* ---- Score dots ---- */}
      {STAGES.map((stage, idx) => {
        const dotScore = animatedScores[stage];
        const pt = axisPoint(stage, clamp(dotScore, 0, 1), chartRadius, center);
        const dotColor = zoneColor(scores[stage], threshold, ambiguityBand);
        const staggerDelay = animated ? idx * 100 : 0;

        return (
          <circle
            key={`dot-${stage}`}
            cx={pt.x}
            cy={pt.y}
            r={6}
            fill={dotColor}
            stroke={dotColor}
            strokeWidth={1}
            style={{
              opacity: animated ? (animProgress > 0 ? 1 : 0) : 1,
              transition: animated
                ? `opacity 200ms ease-out ${staggerDelay}ms`
                : "none",
            }}
            data-testid={`dot-${stage}`}
          />
        );
      })}

      {/* ---- Score value labels (next to dots) ---- */}
      {STAGES.map((stage) => {
        const dotScore = animatedScores[stage];
        const pt = axisPoint(stage, clamp(dotScore, 0, 1), chartRadius, center);
        const labelOffset = 12;
        const angle = STAGE_ANGLES[stage];
        const lx = pt.x + Math.cos(angle) * labelOffset;
        const ly = pt.y + Math.sin(angle) * labelOffset;

        return (
          <text
            key={`score-label-${stage}`}
            x={lx}
            y={ly}
            fill={COLORS.cream}
            fontSize={9}
            fontFamily="'JetBrains Mono', monospace"
            textAnchor="middle"
            dominantBaseline="middle"
            style={{
              opacity: animated ? (animProgress > 0 ? 1 : 0) : 1,
              transition: animated ? "opacity 200ms ease-out 400ms" : "none",
            }}
            data-testid={`score-label-${stage}`}
          >
            {scores[stage].toFixed(2)}
          </text>
        );
      })}

      {/* ---- Stage labels (outside the chart) ---- */}
      {STAGES.map((stage) => {
        const pos = labelPosition(stage, chartRadius, center);
        const hasScore = scores[stage] !== undefined;
        const labelColor = hasScore ? COLORS.cream : COLORS.steel;

        return (
          <text
            key={`label-${stage}`}
            x={pos.x}
            y={pos.y}
            fill={labelColor}
            fontSize={10}
            fontFamily="Syne, sans-serif"
            textAnchor={pos.anchor}
            dominantBaseline={pos.baseline}
            style={{ cursor: onStageClick ? "pointer" : "default" }}
            onClick={
              onStageClick
                ? (e) => {
                    e.stopPropagation();
                    onStageClick(stage);
                  }
                : undefined
            }
            data-testid={`stage-label-${stage}`}
          >
            {STAGE_LABELS[stage]}
          </text>
        );
      })}
    </svg>
  );
}
