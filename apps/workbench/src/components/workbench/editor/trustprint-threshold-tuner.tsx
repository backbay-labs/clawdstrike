import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TrustprintThresholdTunerProps {
  threshold: number;
  ambiguityBand: number;
  onThresholdChange: (value: number) => void;
  onAmbiguityBandChange: (value: number) => void;
  /** Optional: highlight a score on the bar (e.g. from a live screening) */
  highlightScore?: number;
  /** Optional: show distribution of pattern scores */
  patternScores?: number[];
  /** Compact mode for inline use in guard card */
  compact?: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COLORS = {
  allow: "#3dbf84",
  ambiguous: "#d4a84b",
  deny: "#c45c5c",
  bg: "#0b0d13",
  surface: "#131721",
  border: "#2d3240",
  steel: "#6f7f9a",
  cream: "#ece7dc",
  gold: "#d4a84b",
} as const;

const PRESETS: { label: string; threshold: number; band: number }[] = [
  // Higher thresholds are stricter in the screening engine: a score must climb
  // further before it crosses into the deny zone, and a smaller band reduces
  // the amount of "ambiguous" review surface.
  { label: "Permissive", threshold: 0.7, band: 0.15 },
  { label: "Balanced", threshold: 0.85, band: 0.1 },
  { label: "Strict", threshold: 0.95, band: 0.05 },
];

// Full-mode layout constants
const FULL_SVG_HEIGHT = 120;
const FULL_BAR_Y = 24;
const FULL_BAR_HEIGHT = 16;
const FULL_BAR_RX = 4;
const FULL_PADDING_X = 24;

// Compact-mode layout constants
const COMPACT_SVG_HEIGHT = 40;
const COMPACT_BAR_Y = 8;
const COMPACT_BAR_HEIGHT = 12;
const COMPACT_BAR_RX = 3;
const COMPACT_PADDING_X = 8;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Round a number to 2 decimal places for display */
function fmt(n: number): string {
  return n.toFixed(2);
}

/** Clamp a value to [min, max] */
function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

/** Compute the maximum valid ambiguity band for a given threshold */
function maxBand(threshold: number): number {
  return Math.min(threshold, 1 - threshold);
}

/** Compute zone boundaries from threshold and band */
function zoneBounds(threshold: number, band: number) {
  const lowerBound = clamp(threshold - band, 0, 1);
  const upperBound = clamp(threshold + band, 0, 1);
  return { lowerBound, upperBound };
}

// ---------------------------------------------------------------------------
// Drag state machine
// ---------------------------------------------------------------------------

type DragTarget = "threshold" | "lower" | "upper" | null;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function TrustprintThresholdTuner({
  threshold,
  ambiguityBand,
  onThresholdChange,
  onAmbiguityBandChange,
  highlightScore,
  patternScores,
  compact = false,
}: TrustprintThresholdTunerProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [dragTarget, setDragTarget] = useState<DragTarget>(null);
  const [svgWidth, setSvgWidth] = useState(400);

  // Observe SVG width for responsive layout
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setSvgWidth(entry.contentRect.width);
      }
    });
    observer.observe(svg);
    return () => observer.disconnect();
  }, []);

  // Layout parameters
  const paddingX = compact ? COMPACT_PADDING_X : FULL_PADDING_X;
  const barY = compact ? COMPACT_BAR_Y : FULL_BAR_Y;
  const barHeight = compact ? COMPACT_BAR_HEIGHT : FULL_BAR_HEIGHT;
  const barRx = compact ? COMPACT_BAR_RX : FULL_BAR_RX;
  const barWidth = Math.max(svgWidth - paddingX * 2, 0);

  // Zone boundaries
  const { lowerBound, upperBound } = useMemo(
    () => zoneBounds(threshold, ambiguityBand),
    [threshold, ambiguityBand],
  );

  // Pixel conversions
  const toX = useCallback(
    (value: number) => paddingX + value * barWidth,
    [paddingX, barWidth],
  );

  const fromX = useCallback(
    (px: number) => {
      if (barWidth <= 0) return 0;
      return clamp((px - paddingX) / barWidth, 0, 1);
    },
    [paddingX, barWidth],
  );

  // --- Drag handlers ---

  const handlePointerDown = useCallback(
    (target: DragTarget) => (e: React.PointerEvent) => {
      e.preventDefault();
      e.stopPropagation();
      (e.target as SVGElement).setPointerCapture?.(e.pointerId);
      setDragTarget(target);
    },
    [],
  );

  const handlePointerMove = useCallback(
    (e: React.PointerEvent) => {
      if (!dragTarget || !svgRef.current) return;
      const rect = svgRef.current.getBoundingClientRect();
      const clientX = e.clientX - rect.left;
      const value = fromX(clientX);

      if (dragTarget === "threshold") {
        const clamped = clamp(value, 0, 1);
        onThresholdChange(Math.round(clamped * 100) / 100);
        // Shrink band if it no longer fits
        const mb = maxBand(clamped);
        if (ambiguityBand > mb) {
          onAmbiguityBandChange(Math.round(mb * 100) / 100);
        }
      } else if (dragTarget === "lower") {
        // Moving the lower edge: adjusts band, keeps threshold fixed
        const newLower = clamp(value, 0, threshold);
        const newBand = clamp(threshold - newLower, 0, maxBand(threshold));
        onAmbiguityBandChange(Math.round(newBand * 100) / 100);
      } else if (dragTarget === "upper") {
        // Moving the upper edge: adjusts band, keeps threshold fixed
        const newUpper = clamp(value, threshold, 1);
        const newBand = clamp(newUpper - threshold, 0, maxBand(threshold));
        onAmbiguityBandChange(Math.round(newBand * 100) / 100);
      }
    },
    [dragTarget, fromX, threshold, ambiguityBand, onThresholdChange, onAmbiguityBandChange],
  );

  const handlePointerUp = useCallback(() => {
    setDragTarget(null);
  }, []);

  // --- Keyboard handlers for accessibility ---

  const handleThresholdKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const step = e.shiftKey ? 0.05 : 0.01;
      if (e.key === "ArrowRight" || e.key === "ArrowUp") {
        e.preventDefault();
        const next = clamp(threshold + step, 0, 1);
        onThresholdChange(Math.round(next * 100) / 100);
        const mb = maxBand(next);
        if (ambiguityBand > mb) {
          onAmbiguityBandChange(Math.round(mb * 100) / 100);
        }
      } else if (e.key === "ArrowLeft" || e.key === "ArrowDown") {
        e.preventDefault();
        const next = clamp(threshold - step, 0, 1);
        onThresholdChange(Math.round(next * 100) / 100);
        const mb = maxBand(next);
        if (ambiguityBand > mb) {
          onAmbiguityBandChange(Math.round(mb * 100) / 100);
        }
      }
    },
    [threshold, ambiguityBand, onThresholdChange, onAmbiguityBandChange],
  );

  const handleBandKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const step = e.shiftKey ? 0.05 : 0.01;
      if (e.key === "ArrowRight" || e.key === "ArrowUp") {
        e.preventDefault();
        const next = clamp(ambiguityBand + step, 0, maxBand(threshold));
        onAmbiguityBandChange(Math.round(next * 100) / 100);
      } else if (e.key === "ArrowLeft" || e.key === "ArrowDown") {
        e.preventDefault();
        const next = clamp(ambiguityBand - step, 0, maxBand(threshold));
        onAmbiguityBandChange(Math.round(next * 100) / 100);
      }
    },
    [threshold, ambiguityBand, onAmbiguityBandChange],
  );

  // --- Preset handler ---

  const applyPreset = useCallback(
    (preset: (typeof PRESETS)[number]) => {
      onThresholdChange(preset.threshold);
      onAmbiguityBandChange(preset.band);
    },
    [onThresholdChange, onAmbiguityBandChange],
  );

  // --- Render ---

  if (compact) {
    return (
      <div className="w-full" data-testid="threshold-tuner-compact">
        <svg
          ref={svgRef}
          width="100%"
          height={COMPACT_SVG_HEIGHT}
          className="select-none"
          role="img"
          aria-label="Spider Sense threshold zones"
        >
          {/* Clip path for rounded bar */}
          <defs>
            <clipPath id="bar-clip-compact">
              <rect
                x={paddingX}
                y={barY}
                width={barWidth}
                height={barHeight}
                rx={barRx}
              />
            </clipPath>
          </defs>

          {/* Background bar */}
          <rect
            x={paddingX}
            y={barY}
            width={barWidth}
            height={barHeight}
            rx={barRx}
            fill={COLORS.surface}
            stroke={COLORS.border}
            strokeWidth={0.5}
          />

          {/* Zones clipped to bar shape */}
          <g clipPath="url(#bar-clip-compact)">
            {/* Allow zone */}
            <rect
              x={paddingX}
              y={barY}
              width={lowerBound * barWidth}
              height={barHeight}
              fill={COLORS.allow}
              opacity={0.35}
              data-testid="zone-allow"
            />
            {/* Ambiguous zone */}
            <rect
              x={toX(lowerBound)}
              y={barY}
              width={(upperBound - lowerBound) * barWidth}
              height={barHeight}
              fill={COLORS.ambiguous}
              opacity={0.35}
              data-testid="zone-ambiguous"
            />
            {/* Deny zone */}
            <rect
              x={toX(upperBound)}
              y={barY}
              width={(1 - upperBound) * barWidth}
              height={barHeight}
              fill={COLORS.deny}
              opacity={0.35}
              data-testid="zone-deny"
            />
          </g>

          {/* Threshold center line */}
          <line
            x1={toX(threshold)}
            y1={barY - 1}
            x2={toX(threshold)}
            y2={barY + barHeight + 1}
            stroke={COLORS.gold}
            strokeWidth={1.5}
          />

          {/* Zone labels */}
          {lowerBound > 0.08 && (
            <text
              x={toX(lowerBound / 2)}
              y={barY + barHeight + 12}
              textAnchor="middle"
              fill={COLORS.allow}
              fontSize={8}
              fontFamily="Syne, sans-serif"
              fontWeight={600}
              letterSpacing="0.05em"
            >
              ALLOW
            </text>
          )}
          {(upperBound - lowerBound) > 0.06 && (
            <text
              x={toX((lowerBound + upperBound) / 2)}
              y={barY + barHeight + 12}
              textAnchor="middle"
              fill={COLORS.ambiguous}
              fontSize={8}
              fontFamily="Syne, sans-serif"
              fontWeight={600}
              letterSpacing="0.05em"
            >
              AMB
            </text>
          )}
          {(1 - upperBound) > 0.08 && (
            <text
              x={toX((1 + upperBound) / 2)}
              y={barY + barHeight + 12}
              textAnchor="middle"
              fill={COLORS.deny}
              fontSize={8}
              fontFamily="Syne, sans-serif"
              fontWeight={600}
              letterSpacing="0.05em"
            >
              DENY
            </text>
          )}

          {/* Boundary values */}
          <text
            x={toX(lowerBound)}
            y={barY - 2}
            textAnchor="middle"
            fill={COLORS.steel}
            fontSize={8}
            fontFamily="monospace"
          >
            {fmt(lowerBound)}
          </text>
          <text
            x={toX(upperBound)}
            y={barY - 2}
            textAnchor="middle"
            fill={COLORS.steel}
            fontSize={8}
            fontFamily="monospace"
          >
            {fmt(upperBound)}
          </text>

          {/* Highlight score marker */}
          {highlightScore != null && (
            <g data-testid="highlight-marker">
              <polygon
                points={`${toX(highlightScore)},${barY - 3} ${toX(highlightScore) - 3},${barY - 7} ${toX(highlightScore) + 3},${barY - 7}`}
                fill={COLORS.cream}
              />
            </g>
          )}
        </svg>
      </div>
    );
  }

  // --- Full mode ---

  const labelY = barY + barHeight + 18;
  const boundaryLabelY = barY - 6;
  const handleHeight = barHeight + 12;
  const handleY = barY - 6;

  return (
    <div className="w-full flex flex-col gap-2" data-testid="threshold-tuner-full">
      <svg
        ref={svgRef}
        width="100%"
        height={FULL_SVG_HEIGHT}
        className={cn("select-none", dragTarget ? "cursor-grabbing" : "cursor-default")}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerLeave={handlePointerUp}
        role="img"
        aria-label="Spider Sense threshold tuner"
      >
        <defs>
          <clipPath id="bar-clip-full">
            <rect
              x={paddingX}
              y={barY}
              width={barWidth}
              height={barHeight}
              rx={barRx}
            />
          </clipPath>
        </defs>

        {/* Background bar */}
        <rect
          x={paddingX}
          y={barY}
          width={barWidth}
          height={barHeight}
          rx={barRx}
          fill={COLORS.surface}
          stroke={COLORS.border}
          strokeWidth={0.5}
        />

        {/* Zones clipped to bar shape */}
        <g clipPath="url(#bar-clip-full)">
          {/* Allow zone */}
          <rect
            x={paddingX}
            y={barY}
            width={lowerBound * barWidth}
            height={barHeight}
            fill={COLORS.allow}
            opacity={0.4}
            data-testid="zone-allow"
          />
          {/* Ambiguous zone */}
          <rect
            x={toX(lowerBound)}
            y={barY}
            width={(upperBound - lowerBound) * barWidth}
            height={barHeight}
            fill={COLORS.ambiguous}
            opacity={0.4}
            data-testid="zone-ambiguous"
          />
          {/* Deny zone */}
          <rect
            x={toX(upperBound)}
            y={barY}
            width={(1 - upperBound) * barWidth}
            height={barHeight}
            fill={COLORS.deny}
            opacity={0.4}
            data-testid="zone-deny"
          />
        </g>

        {/* Pattern score ticks */}
        {patternScores && patternScores.length > 0 && (
          <g data-testid="pattern-scores">
            {patternScores.map((score, i) => (
              <circle
                key={i}
                cx={toX(clamp(score, 0, 1))}
                cy={barY + barHeight - 2}
                r={1.5}
                fill={COLORS.cream}
                opacity={0.6}
              />
            ))}
          </g>
        )}

        {/* Lower boundary handle */}
        <g
          className="cursor-ew-resize"
          onPointerDown={handlePointerDown("lower")}
          tabIndex={0}
          onKeyDown={handleBandKeyDown}
          role="slider"
          aria-label="Ambiguity band lower bound"
          aria-valuemin={0}
          aria-valuemax={threshold}
          aria-valuenow={lowerBound}
          data-testid="handle-lower"
        >
          <line
            x1={toX(lowerBound)}
            y1={handleY}
            x2={toX(lowerBound)}
            y2={handleY + handleHeight}
            stroke={COLORS.steel}
            strokeWidth={1.5}
            strokeDasharray="2 2"
            className={cn(
              !dragTarget && "transition-all duration-150",
            )}
          />
          <rect
            x={toX(lowerBound) - 4}
            y={handleY}
            width={8}
            height={handleHeight}
            fill="transparent"
          />
          <circle
            cx={toX(lowerBound)}
            cy={barY + barHeight / 2}
            r={4}
            fill={COLORS.surface}
            stroke={COLORS.steel}
            strokeWidth={1.5}
          />
        </g>

        {/* Upper boundary handle */}
        <g
          className="cursor-ew-resize"
          onPointerDown={handlePointerDown("upper")}
          tabIndex={0}
          onKeyDown={handleBandKeyDown}
          role="slider"
          aria-label="Ambiguity band upper bound"
          aria-valuemin={threshold}
          aria-valuemax={1}
          aria-valuenow={upperBound}
          data-testid="handle-upper"
        >
          <line
            x1={toX(upperBound)}
            y1={handleY}
            x2={toX(upperBound)}
            y2={handleY + handleHeight}
            stroke={COLORS.steel}
            strokeWidth={1.5}
            strokeDasharray="2 2"
            className={cn(
              !dragTarget && "transition-all duration-150",
            )}
          />
          <rect
            x={toX(upperBound) - 4}
            y={handleY}
            width={8}
            height={handleHeight}
            fill="transparent"
          />
          <circle
            cx={toX(upperBound)}
            cy={barY + barHeight / 2}
            r={4}
            fill={COLORS.surface}
            stroke={COLORS.steel}
            strokeWidth={1.5}
          />
        </g>

        {/* Threshold center handle (gold diamond) */}
        <g
          className="cursor-ew-resize"
          onPointerDown={handlePointerDown("threshold")}
          tabIndex={0}
          onKeyDown={handleThresholdKeyDown}
          role="slider"
          aria-label="Similarity threshold"
          aria-valuemin={0}
          aria-valuemax={1}
          aria-valuenow={threshold}
          data-testid="handle-threshold"
        >
          <line
            x1={toX(threshold)}
            y1={handleY - 2}
            x2={toX(threshold)}
            y2={handleY + handleHeight + 2}
            stroke={COLORS.gold}
            strokeWidth={2}
            className={cn(
              !dragTarget && "transition-all duration-150",
            )}
          />
          {/* Wider invisible hit target */}
          <rect
            x={toX(threshold) - 6}
            y={handleY - 2}
            width={12}
            height={handleHeight + 4}
            fill="transparent"
          />
          {/* Diamond grip */}
          <polygon
            points={`${toX(threshold)},${barY + barHeight / 2 - 6} ${toX(threshold) + 5},${barY + barHeight / 2} ${toX(threshold)},${barY + barHeight / 2 + 6} ${toX(threshold) - 5},${barY + barHeight / 2}`}
            fill={COLORS.gold}
            stroke={COLORS.bg}
            strokeWidth={1}
          />
        </g>

        {/* Boundary value labels */}
        <text
          x={toX(0)}
          y={boundaryLabelY}
          textAnchor="start"
          fill={COLORS.steel}
          fontSize={9}
          fontFamily="monospace"
        >
          0.00
        </text>
        <text
          x={toX(1)}
          y={boundaryLabelY}
          textAnchor="end"
          fill={COLORS.steel}
          fontSize={9}
          fontFamily="monospace"
        >
          1.00
        </text>

        {/* Lower bound label */}
        <text
          x={toX(lowerBound)}
          y={boundaryLabelY}
          textAnchor="middle"
          fill={COLORS.allow}
          fontSize={9}
          fontFamily="monospace"
          fontWeight={600}
          data-testid="label-lower"
        >
          {fmt(lowerBound)}
        </text>
        {/* Threshold label */}
        <text
          x={toX(threshold)}
          y={barY + barHeight + 14}
          textAnchor="middle"
          fill={COLORS.gold}
          fontSize={10}
          fontFamily="monospace"
          fontWeight={700}
          data-testid="label-threshold"
        >
          {fmt(threshold)}
        </text>
        {/* Upper bound label */}
        <text
          x={toX(upperBound)}
          y={boundaryLabelY}
          textAnchor="middle"
          fill={COLORS.deny}
          fontSize={9}
          fontFamily="monospace"
          fontWeight={600}
          data-testid="label-upper"
        >
          {fmt(upperBound)}
        </text>

        {/* Zone name labels */}
        {lowerBound > 0.06 && (
          <text
            x={toX(lowerBound / 2)}
            y={labelY}
            textAnchor="middle"
            fill={COLORS.allow}
            fontSize={10}
            fontFamily="Syne, sans-serif"
            fontWeight={700}
            letterSpacing="0.08em"
            data-testid="zone-label-allow"
          >
            ALLOW
          </text>
        )}
        {(upperBound - lowerBound) > 0.04 && (
          <text
            x={toX((lowerBound + upperBound) / 2)}
            y={labelY}
            textAnchor="middle"
            fill={COLORS.ambiguous}
            fontSize={10}
            fontFamily="Syne, sans-serif"
            fontWeight={700}
            letterSpacing="0.08em"
            data-testid="zone-label-ambiguous"
          >
            AMBIGUOUS
          </text>
        )}
        {(1 - upperBound) > 0.06 && (
          <text
            x={toX((1 + upperBound) / 2)}
            y={labelY}
            textAnchor="middle"
            fill={COLORS.deny}
            fontSize={10}
            fontFamily="Syne, sans-serif"
            fontWeight={700}
            letterSpacing="0.08em"
            data-testid="zone-label-deny"
          >
            DENY
          </text>
        )}

        {/* Highlight score marker */}
        {highlightScore != null && (
          <g data-testid="highlight-marker">
            {/* Triangle pointing down at the bar */}
            <polygon
              points={`${toX(highlightScore)},${barY - 2} ${toX(highlightScore) - 4},${barY - 8} ${toX(highlightScore) + 4},${barY - 8}`}
              fill={COLORS.cream}
            />
            {/* Score label above */}
            <text
              x={toX(highlightScore)}
              y={barY - 11}
              textAnchor="middle"
              fill={COLORS.cream}
              fontSize={9}
              fontFamily="monospace"
              fontWeight={600}
            >
              {fmt(highlightScore)}
            </text>
          </g>
        )}

        {/* Scale ticks at 0.0, 0.25, 0.5, 0.75, 1.0 */}
        {[0, 0.25, 0.5, 0.75, 1].map((tick) => (
          <line
            key={tick}
            x1={toX(tick)}
            y1={barY + barHeight}
            x2={toX(tick)}
            y2={barY + barHeight + 3}
            stroke={COLORS.border}
            strokeWidth={0.5}
          />
        ))}
      </svg>

      {/* Preset buttons */}
      <div className="flex items-center gap-2 px-1" data-testid="presets">
        <span className="text-[10px] font-mono text-[#6f7f9a] mr-1">Presets</span>
        {PRESETS.map((preset) => {
          const isActive =
            Math.abs(threshold - preset.threshold) < 0.005 &&
            Math.abs(ambiguityBand - preset.band) < 0.005;
          return (
            <button
              key={preset.label}
              type="button"
              onClick={() => applyPreset(preset)}
              className={cn(
                "px-2 py-0.5 text-[10px] font-mono rounded border transition-colors",
                isActive
                  ? "border-[#d4a84b] bg-[#d4a84b]/15 text-[#d4a84b]"
                  : "border-[#2d3240] bg-[#131721] text-[#6f7f9a] hover:border-[#d4a84b]/40 hover:text-[#ece7dc]",
              )}
              data-testid={`preset-${preset.label.toLowerCase()}`}
            >
              {preset.label}
            </button>
          );
        })}
        <span className="text-[9px] font-mono text-[#6f7f9a]/60 ml-auto">
          thresh {fmt(threshold)} / band {fmt(ambiguityBand)}
        </span>
      </div>
    </div>
  );
}
