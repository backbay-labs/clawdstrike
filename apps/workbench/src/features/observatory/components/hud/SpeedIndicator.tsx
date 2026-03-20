/**
 * SpeedIndicator.tsx — Phase 24 HUD-01
 *
 * Vertical speed bar that reflects the ship's current speed relative to the
 * active speed tier cap. Updates via requestAnimationFrame + ref mutation at 60fps.
 *
 * Performance contract:
 *   - ZERO useState calls — state reads happen in the rAF loop via getState()
 *   - ZERO useSelector calls — no Zustand subscriptions in the frame loop
 *   - DOM mutations happen via ref.current.style — React re-renders never triggered
 *   - rAF started on mount, cancelled on unmount via cleanup
 *
 * Visual design (Elite Dangerous cockpit feel):
 *   - Narrow vertical bar, bottom-left corner of viewport
 *   - Fill grows upward proportional to currentSpeed / tierCap
 *   - Bar color changes with speed tier (cruise=white, boost=orange, dock=blue)
 *   - Numeric readout below bar
 *   - Pulsing dot above bar indicates boost cooldown
 */

import { useEffect, useRef } from "react";
import { useObservatoryStore } from "../../stores/observatory-store";
import { DEFAULT_FLIGHT_CONFIG } from "../../character/ship/flight-types";
import {
  HUD_COLORS,
  HUD_SPEED_BAR_HEIGHT,
  HUD_SPEED_BAR_WIDTH,
  SPEED_TIER_COLORS,
} from "./hud-constants";

// ---------------------------------------------------------------------------
// Speed tier cap lookup (pure function, no allocations)
// ---------------------------------------------------------------------------

function getSpeedTierCap(speedTier: string): number {
  switch (speedTier) {
    case "boost":
      return DEFAULT_FLIGHT_CONFIG.cruiseSpeed * DEFAULT_FLIGHT_CONFIG.boostMultiplier;
    case "dock":
      return DEFAULT_FLIGHT_CONFIG.dockSpeed;
    default:
      return DEFAULT_FLIGHT_CONFIG.cruiseSpeed;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SpeedIndicator() {
  const fillRef = useRef<HTMLDivElement>(null);
  const readoutRef = useRef<HTMLSpanElement>(null);
  const cooldownDotRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let rafId: number;

    function loop() {
      const { flightState } = useObservatoryStore.getState();
      const { currentSpeed, speedTier, boostOnCooldown } = flightState;

      if (fillRef.current) {
        const cap = getSpeedTierCap(speedTier);
        const fillPercent = Math.min(100, (currentSpeed / cap) * 100);
        fillRef.current.style.height = `${fillPercent}%`;
        fillRef.current.style.backgroundColor = SPEED_TIER_COLORS[speedTier];
      }

      if (readoutRef.current) {
        readoutRef.current.textContent = `${Math.round(currentSpeed)}`;
      }

      if (cooldownDotRef.current) {
        cooldownDotRef.current.style.display = boostOnCooldown ? "block" : "none";
      }

      rafId = requestAnimationFrame(loop);
    }

    rafId = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(rafId);
  }, []);

  return (
    <div
      data-testid="hud-speed-indicator"
      style={{
        position: "absolute",
        left: 16,
        bottom: 80,
        width: HUD_SPEED_BAR_WIDTH,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 4,
      }}
    >
      {/* Boost cooldown pulsing dot — above the bar */}
      <div
        ref={cooldownDotRef}
        style={{
          display: "none",
          width: 6,
          height: 6,
          borderRadius: "50%",
          backgroundColor: SPEED_TIER_COLORS.boost,
          animation: "hud-cooldown-pulse 0.8s ease-in-out infinite alternate",
        }}
      />

      {/* Speed bar track */}
      <div
        style={{
          position: "relative",
          width: HUD_SPEED_BAR_WIDTH,
          height: HUD_SPEED_BAR_HEIGHT,
          backgroundColor: "#1a2035",
          borderRadius: 3,
          border: `1px solid ${HUD_COLORS.hudBorder}`,
          overflow: "hidden",
        }}
      >
        {/* Fill bar — grows upward from bottom */}
        <div
          ref={fillRef}
          data-testid="hud-speed-fill"
          style={{
            position: "absolute",
            bottom: 0,
            left: 0,
            right: 0,
            height: "0%",
            backgroundColor: SPEED_TIER_COLORS.cruise,
            borderRadius: 2,
            transition: "background-color 0.2s ease",
          }}
        />
      </div>

      {/* Numeric speed readout */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          lineHeight: 1.1,
        }}
      >
        <span
          ref={readoutRef}
          data-testid="hud-speed-readout"
          style={{
            fontSize: 10,
            color: HUD_COLORS.hudText,
            fontVariantNumeric: "tabular-nums",
          }}
        >
          0
        </span>
        <span
          style={{
            fontSize: 7,
            color: HUD_COLORS.hudTextDim,
          }}
        >
          u/s
        </span>
      </div>

      {/* CSS keyframe injection for boost cooldown pulse */}
      <style>{`
        @keyframes hud-cooldown-pulse {
          from { opacity: 1; transform: scale(1); }
          to   { opacity: 0.3; transform: scale(0.7); }
        }
      `}</style>
    </div>
  );
}
