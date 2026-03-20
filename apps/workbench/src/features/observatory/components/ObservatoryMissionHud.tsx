// ObservatoryMissionHud — HUD overlay showing active mission objective.
// Positioned as absolute bottom-16 left-4 overlay, above ObservatoryProbeHud (bottom-4).
// Renders null when mission is null or mission.status === "completed".
//
// Plan 08-02: OBS-11 — mission HUD overlay with objective title, hint, and action label.
// Plan 26-02: DSC-04 — flight-mode narrative directives per station (#44ff88 text).

import { getCurrentObservatoryMissionObjective } from "../world/missionLoop";
import type { ObservatoryMissionLoopState } from "../world/missionLoop";
import { HUNT_STATION_LABELS } from "../world/stations";
import type { HuntStationId } from "../world/types";

// ---------------------------------------------------------------------------
// DSC-04: Station-specific narrative directives for flight mode
// Displayed in green (#44ff88) to match the waypoint trail color.
// ---------------------------------------------------------------------------

export const FLIGHT_NARRATIVES: Record<HuntStationId, string> = {
  signal: "Investigate Horizon Station \u2014 anomalous signal detected",
  targets: "Scan Subjects Cluster \u2014 identify threat actors",
  run: "Arm Operations Scan Rig \u2014 prepare countermeasures",
  receipts: "Inspect Evidence Vault \u2014 verify receipt chain",
  "case-notes": "Seal Judgment Dais \u2014 finalize case findings",
  watch: "Raise Watchfield Perimeter \u2014 secure outer boundary",
};

export function ObservatoryMissionHud({
  mission,
  inFlightMode = false,
}: {
  mission: ObservatoryMissionLoopState | null;
  inFlightMode?: boolean;
}) {
  const objective = getCurrentObservatoryMissionObjective(mission);
  if (!mission || mission.status === "completed" || !objective) return null;

  return (
    <div
      className="absolute bottom-16 left-4 z-10 pointer-events-none w-[260px] rounded-md overflow-hidden bg-[#0a0d14]/90 border border-[#202531] backdrop-blur-sm"
      data-testid="mission-hud"
    >
      <div className="px-3 py-2 space-y-1.5">
        {/* Mission label header */}
        <div className="flex items-center gap-2">
          <span
            className="h-1.5 w-1.5 rounded-full bg-[#3dbf84] animate-pulse shrink-0"
            aria-hidden="true"
          />
          <span className="text-[9px] font-mono text-[#3dbf84] uppercase tracking-wider">
            Mission Active
          </span>
        </div>
        {/* DSC-04: Flight-mode narrative directive — shown above title when flying */}
        {inFlightMode && FLIGHT_NARRATIVES[objective.stationId] ? (
          <p
            key={objective.stationId}
            className="text-[11px] font-mono text-[#44ff88] leading-tight font-medium transition-opacity duration-300"
            data-testid="mission-narrative"
          >
            {FLIGHT_NARRATIVES[objective.stationId]}
          </p>
        ) : null}
        {/* Objective title */}
        <p
          className="text-[11px] font-mono text-[#c8d2e0] leading-tight"
          data-testid="mission-objective-title"
        >
          {objective.title}
        </p>
        {/* Hint text */}
        <p
          className="text-[10px] font-mono text-[#6f7f9a] leading-snug"
          data-testid="mission-hint"
        >
          {objective.hint}
        </p>
        {objective.supportingStationIds?.length ? (
          <div className="flex flex-wrap gap-1" data-testid="mission-supporting-stations">
            {objective.supportingStationIds.map((stationId) => (
              <span
                key={stationId}
                className="rounded-full border border-[#2d3240] bg-[#0f131d]/80 px-2 py-0.5 text-[9px] font-mono uppercase tracking-[0.12em] text-[#d9e2f1]"
              >
                {HUNT_STATION_LABELS[stationId]}
              </span>
            ))}
          </div>
        ) : null}
        {objective.rationale ? (
          <p
            className="text-[10px] font-mono text-[#8ea9c2] leading-snug"
            data-testid="mission-rationale"
          >
            {objective.rationale}
          </p>
        ) : null}
        {typeof objective.confidence === "number" ? (
          <div
            className="pt-0.5 text-[9px] font-mono uppercase tracking-wide text-[#d4a84b]"
            data-testid="mission-confidence"
          >
            Confidence {(objective.confidence * 100).toFixed(0)}%
          </div>
        ) : null}
        {/* Action label */}
        <div className="pt-0.5 border-t border-[#202531]">
          <span className="text-[9px] font-mono text-[#f4a84b] uppercase tracking-wide">
            {objective.actionLabel}
          </span>
        </div>
      </div>
    </div>
  );
}
