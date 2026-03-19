// ObservatoryProbeHud — HUD overlay showing probe status, charge bar, scan result text.
// Positioned as absolute bottom-4 right-4 overlay on top of the Canvas (z-10).
// Renders null when probeState.status === "ready" (no active probe).
//
// Plan 03-02: OBS-04 — probe lifecycle HUD.
// Plan 14-03: UIP-02 — circular SVG charge ring replaces linear bar in cooldown phase.
// SCOPE: This charge ring is minimal probe lifecycle feedback, not the full OBS-08
//   cooldown timer (deferred). The ring animation in the canvas is the primary visual;
//   this ring supplements it within the HUD.

import { useState, useEffect } from "react";
import type { ObservatoryProbeState } from "../world/probeRuntime";
import {
  getObservatoryProbeCharge,
  getObservatoryProbeRemainingMs,
} from "../world/probeRuntime";

export interface ObservatoryProbeHudProps {
  probeState: ObservatoryProbeState;
}

// UIP-02: Circular SVG arc ring replacing the linear charge bar.
// stroke-dashoffset encodes fill progress; rotated -90deg so arc starts at 12-o'clock.
function ProbeChargeRingsvg({ charge }: { charge: number }) {
  const r = 22;
  const cx = 28;
  const cy = 28;
  const circumference = 2 * Math.PI * r;
  const filled = Math.max(0, Math.min(1, charge));
  const dashoffset = circumference * (1 - filled);
  const accentColor = "var(--spirit-accent, #3dbf84)";
  return (
    <svg width={56} height={56} style={{ overflow: 'visible' }}>
      {/* Background ring */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1a2035" strokeWidth={3} />
      {/* Charge arc — strokeDashoffset animates fill */}
      <circle
        cx={cx} cy={cy} r={r}
        fill="none"
        stroke={accentColor}
        strokeWidth={3}
        strokeDasharray={circumference}
        strokeDashoffset={dashoffset}
        strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: 'stroke-dashoffset 0.1s linear' }}
      />
      {/* Charge percent label */}
      <text
        x={cx} y={cy + 4}
        textAnchor="middle"
        fontSize={9}
        fontFamily="monospace"
        fill={accentColor}
      >
        {Math.round(filled * 100)}%
      </text>
    </svg>
  );
}

function cn(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(" ");
}

export function ObservatoryProbeHud({ probeState }: ObservatoryProbeHudProps) {
  // Tick every 100ms while probe is active or in cooldown so charge bar animates
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (probeState.status === "ready") return;
    const interval = setInterval(() => setTick((prev) => prev + 1), 100);
    return () => clearInterval(interval);
  }, [probeState.status]);

  // Void tick to use it (keeps the re-render cycle going for charge bar updates)
  void tick;

  if (probeState.status === "ready") {
    return null;
  }

  const now = performance.now();
  const charge = getObservatoryProbeCharge(probeState, now);
  const remainingMs = getObservatoryProbeRemainingMs(probeState, now);

  return (
    <div
      className={cn(
        "absolute bottom-4 right-4 z-10 pointer-events-none",
        "w-[220px] rounded-md overflow-hidden",
        "bg-[#0a0d14]/90 border border-[#202531]",
        "backdrop-blur-sm",
      )}
    >
      <div className="px-3 py-2 space-y-1.5">
        {probeState.status === "active" && (
          <div className="flex items-center gap-2">
            {/* Pulsing indicator */}
            <span
              className="h-2 w-2 rounded-full bg-[#f4a84b] animate-pulse shrink-0"
              aria-hidden="true"
            />
            <span className="text-[10px] font-mono text-[#f4a84b] leading-none truncate">
              PROBING {probeState.targetStationId?.toUpperCase() ?? "..."}
            </span>
          </div>
        )}

        {probeState.status === "cooldown" && (
          <>
            <div className="flex items-center justify-between gap-2">
              <span className="text-[10px] font-mono text-[#6f7f9a] leading-none">
                COOLDOWN
              </span>
              <span className="text-[10px] font-mono text-[#6f7f9a] leading-none">
                {Math.ceil(remainingMs / 1000)}s
              </span>
            </div>
            {/* UIP-02: Circular probe charge ring — SVG arc */}
            <div className="flex justify-center py-1">
              <ProbeChargeRingsvg charge={charge} />
            </div>
          </>
        )}
      </div>
    </div>
  );
}
