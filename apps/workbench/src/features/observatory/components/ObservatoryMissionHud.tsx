// ObservatoryMissionHud — HUD overlay showing active mission objective.
// Positioned as absolute bottom-16 left-4 overlay, above ObservatoryProbeHud (bottom-4).
// Renders null when mission is null or mission.status === "completed".
//
// Plan 08-02: OBS-11 — mission HUD overlay with objective title, hint, and action label.

import { getCurrentObservatoryMissionObjective } from "../world/missionLoop";
import type { ObservatoryMissionLoopState } from "../world/missionLoop";

export function ObservatoryMissionHud({
  mission,
}: {
  mission: ObservatoryMissionLoopState | null;
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
