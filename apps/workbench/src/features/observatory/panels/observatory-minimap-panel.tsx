/**
 * ObservatoryMinimapPanel — SVG overview of observatory stations.
 * Reads HUNT_STATION_PLACEMENTS for positions, observatory-store for artifact counts.
 * Rendered in the "Observatory" activity bar sidebar panel.
 *
 * Coordinate mapping:
 *   svgX = cx + radius * RING_R * cos(angleDeg * PI / 180)
 *   svgY = cy + radius * RING_R * sin(angleDeg * PI / 180)
 *   cx=100, cy=100 (center of 200x200 viewBox), RING_R=70
 */
import { useMemo } from "react";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { HUNT_STATION_PLACEMENTS } from "@/features/observatory/world/stations";

const VIEWBOX_SIZE = 200;
const CX = 100;
const CY = 100;
const RING_R = 70;

/** Exported for unit testing: maps polar observatory coordinates to 200x200 SVG space. */
export function polarToSvg(angleDeg: number, radius: number): { x: number; y: number } {
  const rad = (angleDeg * Math.PI) / 180;
  return {
    x: CX + radius * RING_R * Math.cos(rad),
    y: CY + radius * RING_R * Math.sin(rad),
  };
}

export function ObservatoryMinimapPanel() {
  const stations = useObservatoryStore.use.stations();
  const seamSummary = useObservatoryStore.use.seamSummary();

  const artifactByStation = useMemo(() => {
    const map = new Map<string, number>();
    for (const s of stations) {
      map.set(s.id, s.artifactCount);
    }
    return map;
  }, [stations]);

  const hasActiveProbe = seamSummary.activeProbes > 0;

  return (
    <div className="flex flex-col h-full bg-[#0b0d13]">
      {/* Panel header */}
      <div className="px-3 py-2 border-b border-[#1a1d28]/60">
        <span className="text-[11px] font-medium text-[#6f7f9a] uppercase tracking-wider">
          Observatory
        </span>
      </div>

      {/* SVG minimap */}
      <div className="flex-1 flex items-center justify-center p-4">
        <svg
          viewBox={`0 0 ${VIEWBOX_SIZE} ${VIEWBOX_SIZE}`}
          width="160"
          height="160"
          aria-label="Observatory station map"
        >
          {/* Outer ring guide */}
          <circle
            cx={CX}
            cy={CY}
            r={RING_R}
            fill="none"
            stroke="#1a1d28"
            strokeWidth="1"
          />
          {/* Center core */}
          <circle cx={CX} cy={CY} r={5} fill="#2d3240" />
          <circle cx={CX} cy={CY} r={2} fill="#6f7f9a" />

          {/* Station dots */}
          {HUNT_STATION_PLACEMENTS.map((placement) => {
            const { x, y } = polarToSvg(placement.angleDeg, placement.radius);
            const artifactCount = artifactByStation.get(placement.id) ?? 0;
            const isActive = hasActiveProbe && artifactCount > 0;
            const dotColor = isActive
              ? "var(--spirit-accent, #d4a84b)"
              : "#6f7f9a";

            return (
              <g key={placement.id}>
                {/* Station dot */}
                <circle cx={x} cy={y} r={5} fill={dotColor} opacity={0.9} />
                {/* Station label */}
                <text
                  x={x}
                  y={y + 14}
                  textAnchor="middle"
                  fill="#6f7f9a"
                  fontSize="7"
                  fontFamily="ui-monospace, monospace"
                >
                  {placement.label}
                </text>
                {/* Artifact count badge — only when count > 0 */}
                {artifactCount > 0 && (
                  <text
                    x={x + 7}
                    y={y - 5}
                    textAnchor="middle"
                    fill="#d4a84b"
                    fontSize="7"
                    fontWeight="bold"
                  >
                    {artifactCount}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Seam summary footer */}
      <div className="px-3 py-2 border-t border-[#1a1d28]/60 flex gap-3">
        <span className="text-[10px] text-[#6f7f9a]">
          {seamSummary.artifactCount} artifacts
        </span>
        {hasActiveProbe && (
          <span className="text-[10px] text-[#3dbf84]">probe active</span>
        )}
      </div>
    </div>
  );
}
