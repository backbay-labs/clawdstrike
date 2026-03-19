import { clsx } from "clsx";
import { HUNT_PERIMETER_STATION_ID } from "@/features/observatory/world/stations";
import { getNexusStationCode, getNexusStationLabel, resolveNexusObservatoryStationId } from "../observatory";
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
      return "\u25C9";
    case "threat-radar":
      return "\u25CC";
    case "attack-graph":
      return "\u232C";
    case "network-map":
      return "\u25CE";
    case "workflows":
      return "\u21C6";
    case "marketplace":
      return "\u25C8";
    case "events":
      return "\u22EF";
    case "policies":
      return "\u26E8";
    case "forensics-river":
      return "\u3030";
    default:
      return "\u2022";
  }
}

function stationCodeFor(id: StrikecellDomainId): string {
  return getNexusStationCode(resolveNexusObservatoryStationId(id));
}

export function NexusAppRail({
  strikecells,
  openAppId,
  onToggleApp,
  mode = "drawer",
  title,
  transitioningId = null,
}: NexusAppRailProps) {
  const railTitle = title ?? "Stations";
  const primaryStrikecells = strikecells.filter(
    (strikecell) => resolveNexusObservatoryStationId(strikecell.id) !== HUNT_PERIMETER_STATION_ID,
  );
  const perimeterStrikecell =
    strikecells.find(
      (strikecell) =>
        resolveNexusObservatoryStationId(strikecell.id) === HUNT_PERIMETER_STATION_ID,
    ) ?? null;

  return (
    <aside className="nexus-app-rail absolute right-4 top-1/2 z-30 -translate-y-1/2 pointer-events-auto">
      <div className="relative flex flex-col items-center gap-3 py-6">
        <div className="origin-label mb-1 text-center text-[8px] tracking-[0.18em] text-[rgba(213,173,87,0.72)]">
          {railTitle}
        </div>
        <span
          aria-hidden="true"
          className="absolute top-8 bottom-8 left-1/2 w-px -translate-x-1/2 bg-[linear-gradient(180deg,rgba(213,173,87,0.04)_0%,rgba(213,173,87,0.18)_50%,rgba(213,173,87,0.04)_100%)]"
        />
        {primaryStrikecells.map((strikecell) => {
          const active = strikecell.id === openAppId;
          const transitioning = mode === "station" && strikecell.id === transitioningId;
          return (
            <button
              key={strikecell.id}
              type="button"
              onClick={() => onToggleApp(strikecell.id)}
              title={`${getNexusStationLabel(resolveNexusObservatoryStationId(strikecell.id))} \u00B7 ${strikecell.name}`}
              data-active={active ? "true" : "false"}
              data-mode={mode}
              data-transitioning={transitioning ? "true" : "false"}
              className={clsx(
                "nexus-app-rail-btn origin-focus-ring relative flex h-12 w-12 flex-col items-center justify-center rounded-full border transition-all duration-200",
                active
                  ? "border-[rgba(213,173,87,0.38)] bg-[rgba(213,173,87,0.12)] text-[color:var(--origin-gold)] shadow-[0_0_18px_rgba(213,173,87,0.18)]"
                  : transitioning
                    ? "border-[rgba(124,184,255,0.28)] bg-[rgba(124,184,255,0.08)] text-sdr-text-primary"
                    : "border-[rgba(255,255,255,0.08)] bg-[rgba(7,10,16,0.72)] text-sdr-text-secondary hover:border-[rgba(213,173,87,0.22)] hover:text-sdr-text-primary",
              )}
            >
              <span className="text-sm leading-none">{glyphFor(strikecell.id)}</span>
              <span className="mt-0.5 text-[8px] font-mono uppercase tracking-[0.14em]">
                {stationCodeFor(strikecell.id)}
              </span>
              {active ? (
                <span
                  aria-hidden="true"
                  className="absolute -right-1.5 top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full bg-[color:var(--origin-gold)] shadow-[0_0_10px_rgba(213,173,87,0.8)]"
                />
              ) : null}
            </button>
          );
        })}
        {perimeterStrikecell ? (
          <div className="mt-4 flex flex-col items-center gap-2">
            <div className="text-[8px] font-mono uppercase tracking-[0.18em] text-[rgba(213,173,87,0.5)]">
              Watchfield
            </div>
            <button
              type="button"
              onClick={() => onToggleApp(perimeterStrikecell.id)}
              title={`${getNexusStationLabel(resolveNexusObservatoryStationId(perimeterStrikecell.id))} \u00B7 ${perimeterStrikecell.name}`}
              data-active={perimeterStrikecell.id === openAppId ? "true" : "false"}
              data-mode={mode}
              className={clsx(
                "origin-focus-ring relative flex h-14 w-14 items-center justify-center rounded-full border transition-all duration-200",
                perimeterStrikecell.id === openAppId
                  ? "border-[rgba(213,173,87,0.38)] bg-[rgba(213,173,87,0.12)] text-[color:var(--origin-gold)] shadow-[0_0_18px_rgba(213,173,87,0.18)]"
                  : "border-[rgba(255,255,255,0.08)] bg-[rgba(7,10,16,0.56)] text-sdr-text-secondary hover:border-[rgba(213,173,87,0.22)] hover:text-sdr-text-primary",
              )}
            >
              <span
                aria-hidden="true"
                className="absolute inset-[6px] rounded-full border border-dashed border-[rgba(213,173,87,0.2)]"
              />
              <div className="relative z-10 flex flex-col items-center">
                <span className="text-sm leading-none">{glyphFor(perimeterStrikecell.id)}</span>
                <span className="mt-0.5 text-[8px] font-mono uppercase tracking-[0.14em]">
                  {stationCodeFor(perimeterStrikecell.id)}
                </span>
              </div>
            </button>
          </div>
        ) : null}
      </div>
    </aside>
  );
}
