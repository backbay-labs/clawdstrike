import { useEffect, useRef, useState } from "react";
import type { HuntStationId } from "../world/types";
import type { ObservatorySpikeCue } from "../world/observatory-presence";
import { HUNT_STATION_LABELS } from "../world/stations";
import { STATION_COLORS_HEX } from "./hud/hud-constants";

export interface ObservatoryCinematicOverlayProps {
  cue: ObservatorySpikeCue | null;
  visible: boolean;
  onDismiss: () => void;
  onOpenRoute: (stationId: HuntStationId) => void;
}

export function ObservatoryCinematicOverlay({
  cue,
  visible,
  onDismiss,
  onOpenRoute,
}: ObservatoryCinematicOverlayProps) {
  useEffect(() => {
    if (!visible || !cue) {
      return;
    }
    const timer = window.setTimeout(() => {
      onDismiss();
    }, 3200);
    return () => window.clearTimeout(timer);
  }, [cue, onDismiss, visible]);

  if (!visible || !cue) {
    return null;
  }

  return (
    <div
      className="absolute inset-x-0 top-16 z-30 flex justify-center px-4"
      data-testid="observatory-cinematic-overlay"
    >
      <div className="w-full max-w-[540px] rounded-xl border border-[#d4a84b]/30 bg-[#070b12]/92 px-4 py-4 shadow-[0_20px_80px_rgba(0,0,0,0.45)] backdrop-blur-md">
        <div className="text-[10px] font-mono uppercase tracking-[0.28em] text-[#d4a84b]">
          Why this matters
        </div>
        <div className="mt-2 text-[18px] font-mono text-[#edf2fb]">{cue.title}</div>
        <div className="mt-1 text-[11px] font-mono uppercase tracking-[0.18em] text-[#8ea9c2]">
          {cue.stationLabel} · {cue.recommendation.routeLabel}
        </div>
        <div className="mt-4 space-y-2">
          {cue.causes.map((cause) => (
            <div
              key={`${cause.label}:${cause.detail}`}
              className="rounded-md border border-[#202531] bg-[#0d131d]/80 px-3 py-2"
            >
              <div className="text-[9px] font-mono uppercase tracking-[0.18em] text-[#6f7f9a]">
                {cause.label}
              </div>
              <div className="mt-1 text-[11px] leading-relaxed text-[#d6deec]">
                {cause.detail}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-4 flex items-center justify-between gap-3">
          <button
            type="button"
            className="rounded-md border border-[#2d3240] px-3 py-2 text-[10px] font-mono uppercase tracking-[0.16em] text-[#f0e5b0] transition-colors hover:border-[#d4a84b]/50"
            onClick={() => {
              onOpenRoute(cue.recommendation.stationId);
              onDismiss();
            }}
          >
            {cue.recommendation.actionLabel}
          </button>
          <button
            type="button"
            className="rounded-md border border-transparent px-2 py-2 text-[10px] font-mono uppercase tracking-[0.16em] text-[#8ea9c2] transition-colors hover:border-[#2d3240]"
            onClick={onDismiss}
          >
            Skip
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Station arrival name card (TRN-03)
// ---------------------------------------------------------------------------

type ArrivalCardPhase = "bars-in" | "name-in" | "hold" | "name-out" | "bars-out" | "done";

export interface StationArrivalCardProps {
  stationId: HuntStationId | null;
  visible: boolean;
  onComplete: () => void;
}

export function StationArrivalCard({ stationId, visible, onComplete }: StationArrivalCardProps) {
  const [phase, setPhase] = useState<ArrivalCardPhase>("bars-in");
  const onCompleteRef = useRef(onComplete);
  onCompleteRef.current = onComplete;

  // Reset and run the state machine whenever the card becomes visible with a station
  useEffect(() => {
    if (!visible || !stationId) return;

    setPhase("bars-in");

    // Phase durations (ms):
    // bars-in: 300 → name-in: 300 → hold: 1200 → name-out: 300 → bars-out: 300
    const t1 = window.setTimeout(() => setPhase("name-in"), 300);
    const t2 = window.setTimeout(() => setPhase("hold"), 600);
    const t3 = window.setTimeout(() => setPhase("name-out"), 1800);
    const t4 = window.setTimeout(() => setPhase("bars-out"), 2100);
    const t5 = window.setTimeout(() => {
      setPhase("done");
      onCompleteRef.current();
    }, 2400);

    return () => {
      window.clearTimeout(t1);
      window.clearTimeout(t2);
      window.clearTimeout(t3);
      window.clearTimeout(t4);
      window.clearTimeout(t5);
    };
  }, [visible, stationId]);

  if (!visible || !stationId || phase === "done") {
    return null;
  }

  const stationColor = STATION_COLORS_HEX[stationId];
  const stationLabel = HUNT_STATION_LABELS[stationId];

  // Letterbox bar transform — slides in from outside (bars-in/hold/name-in), retracts on bars-out
  const barsVisible = phase === "bars-in" || phase === "name-in" || phase === "hold" || phase === "name-out";
  const barTransform = barsVisible ? "translateY(0)" : undefined;
  const topBarTransform = barsVisible ? "translateY(0)" : "translateY(-100%)";
  const bottomBarTransform = barsVisible ? "translateY(0)" : "translateY(100%)";

  // Name opacity
  const nameVisible = phase === "hold" || phase === "name-in";
  const nameOpacity = nameVisible ? 1 : 0;

  return (
    <div
      className="absolute inset-0 z-40 pointer-events-none"
      data-testid="station-arrival-card"
      data-arrival-station={stationId}
      data-arrival-phase={phase}
    >
      {/* Top letterbox bar */}
      <div
        className="absolute top-0 left-0 right-0 h-10 bg-black"
        style={{
          transform: topBarTransform,
          transition: "transform 0.3s ease-in-out",
        }}
      />

      {/* Bottom letterbox bar */}
      <div
        className="absolute bottom-0 left-0 right-0 h-10 bg-black"
        style={{
          transform: bottomBarTransform,
          transition: "transform 0.3s ease-in-out",
        }}
      />

      {/* Station name card — centered vertically/horizontally */}
      <div
        className="absolute inset-0 flex flex-col items-center justify-center"
        style={{
          opacity: nameOpacity,
          transition: "opacity 0.3s ease-in-out",
        }}
      >
        <div
          className="font-mono text-[32px] uppercase tracking-widest"
          style={{ color: stationColor }}
          data-testid="arrival-station-name"
        >
          {stationId.toUpperCase()}
        </div>
        <div
          className="mt-2 font-mono text-[14px] uppercase tracking-wide text-[#8ea9c2]"
          data-testid="arrival-station-label"
        >
          {stationLabel}
        </div>
      </div>
    </div>
  );
}
