import { clsx } from "clsx";
import type { Strikecell, StrikecellDomainId } from "../types";

interface NexusAppRailProps {
  strikecells: Strikecell[];
  openAppId: StrikecellDomainId | null;
  onToggleApp: (id: StrikecellDomainId) => void;
  mode?: "drawer" | "station";
  title?: string;
  transitioningId?: StrikecellDomainId | null;
}

function glyphFor(id: StrikecellDomainId): string {
  switch (id) {
    case "security-overview":
      return "◉";
    case "threat-radar":
      return "◌";
    case "attack-graph":
      return "⌬";
    case "network-map":
      return "◎";
    case "workflows":
      return "⇆";
    case "marketplace":
      return "◈";
    case "events":
      return "⋯";
    case "policies":
      return "⛨";
    case "forensics-river":
      return "〰";
    default:
      return "•";
  }
}

function stationCodeFor(id: StrikecellDomainId): string {
  switch (id) {
    case "security-overview":
      return "SEC";
    case "attack-graph":
      return "ATK";
    case "threat-radar":
      return "THR";
    case "network-map":
      return "ARE";
    default:
      return "NEX";
  }
}

export function NexusAppRail({
  strikecells,
  openAppId,
  onToggleApp,
  mode = "drawer",
  title,
  transitioningId = null,
}: NexusAppRailProps) {
  const railTitle = title ?? (mode === "station" ? "Stations" : "Glyphs");

  return (
    <aside className="nexus-app-rail absolute right-0 top-[calc(var(--nexus-header-height,72px)+12px)] bottom-4 z-30 pointer-events-auto">
      <div className="nexus-app-rail-panel premium-panel premium-panel--rail h-full overflow-y-auto rounded-l-2xl border-r-0 px-2 py-3">
        <div className="origin-label mb-2 text-center text-[9px] tracking-[0.16em]">
          {railTitle}
        </div>
        <div className="space-y-2">
          {strikecells.map((strikecell) => {
            const active = strikecell.id === openAppId;
            const transitioning = mode === "station" && strikecell.id === transitioningId;
            return (
              <button
                key={strikecell.id}
                type="button"
                onClick={() => onToggleApp(strikecell.id)}
                title={strikecell.name}
                data-active={active ? "true" : "false"}
                data-mode={mode}
                data-transitioning={transitioning ? "true" : "false"}
                className={clsx(
                  "nexus-app-rail-btn premium-rail-button origin-focus-ring relative flex w-11 flex-col items-center justify-center rounded-lg border transition-colors",
                  mode === "station" ? "h-[58px] gap-0.5 py-1" : "h-11",
                  active
                    ? "bg-sdr-accent-amber/10 text-[color:var(--origin-gold)]"
                    : "text-sdr-text-secondary hover:text-sdr-text-primary hover:bg-[rgba(213,173,87,0.1)]",
                )}
              >
                {active ? (
                  <span
                    className="absolute -top-1.5 -right-1.5 h-2.5 w-2.5 rounded-full bg-[color:var(--origin-gold)] shadow-[0_0_8px_rgba(213,173,87,0.75)]"
                    aria-hidden="true"
                  />
                ) : null}
                <span className="nexus-app-rail-btn-glyph text-sm leading-none">
                  {glyphFor(strikecell.id)}
                </span>
                <span className="nexus-app-rail-btn-label mt-0.5 text-[8px] font-mono uppercase">
                  {mode === "station"
                    ? stationCodeFor(strikecell.id)
                    : strikecell.name.split(" ")[0]}
                </span>
                {mode === "station" ? (
                  <span className="nexus-app-rail-btn-status text-[7px] font-mono uppercase tracking-[0.12em]">
                    {active ? "Arrived" : transitioning ? "Transit" : "Navigate"}
                  </span>
                ) : null}
              </button>
            );
          })}
        </div>
      </div>
    </aside>
  );
}
