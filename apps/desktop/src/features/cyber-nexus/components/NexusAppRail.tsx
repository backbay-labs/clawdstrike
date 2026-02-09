import { clsx } from "clsx";
import type { Strikecell, StrikecellDomainId } from "../types";

interface NexusAppRailProps {
  strikecells: Strikecell[];
  openAppId: StrikecellDomainId | null;
  onToggleApp: (id: StrikecellDomainId) => void;
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

export function NexusAppRail({ strikecells, openAppId, onToggleApp }: NexusAppRailProps) {
  return (
    <aside className="nexus-app-rail absolute right-0 top-1/2 z-30 -translate-y-1/2 pointer-events-auto">
      <div className="nexus-app-rail-panel premium-panel premium-panel--rail rounded-l-2xl border-r-0 px-2 py-3">
        <div className="origin-label mb-2 text-center text-[9px] tracking-[0.16em]">Glyphs</div>
        <div className="space-y-2">
          {strikecells.map((strikecell) => {
            const active = strikecell.id === openAppId;
            return (
              <button
                key={strikecell.id}
                type="button"
                onClick={() => onToggleApp(strikecell.id)}
                title={strikecell.name}
                data-active={active ? "true" : "false"}
                className={clsx(
                  "nexus-app-rail-btn premium-rail-button origin-focus-ring relative flex h-11 w-11 flex-col items-center justify-center rounded-lg border transition-colors",
                  active
                    ? "bg-sdr-accent-amber/10 text-[color:var(--origin-gold)]"
                    : "text-sdr-text-secondary hover:text-sdr-text-primary hover:bg-[rgba(213,173,87,0.1)]"
                )}
              >
                {active ? (
                  <span
                    className="absolute -top-1.5 -right-1.5 h-2.5 w-2.5 rounded-full bg-[color:var(--origin-gold)] shadow-[0_0_8px_rgba(213,173,87,0.75)]"
                    aria-hidden="true"
                  />
                ) : null}
                <span className="text-sm leading-none">{glyphFor(strikecell.id)}</span>
                <span className="mt-0.5 text-[8px] font-mono uppercase">{strikecell.name.split(" ")[0]}</span>
              </button>
            );
          })}
        </div>
      </div>
    </aside>
  );
}
