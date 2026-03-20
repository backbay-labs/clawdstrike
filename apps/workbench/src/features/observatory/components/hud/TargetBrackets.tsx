/**
 * TargetBrackets.tsx — Phase 24 HUD-03, HUD-05
 *
 * Renders L-corner bracket markers around in-frustum stations, plus distance
 * readouts that fade in during docking approach.
 *
 * Design contract:
 *   - Pre-renders 6 bracket containers (one per station) — never mount/unmount.
 *   - Positions and colors updated each frame via ref mutation in a rAF loop.
 *   - ZERO useState, ZERO useSelector. All frame work goes through refs.
 *   - pointer-events:none — display only.
 *
 * Bracket colors:
 *   - Green (#3dbf84): unvisited / default
 *   - Gold (#f4d982): selected or mission target
 *   - Cyan (#5ab4f0): docked
 */

import { useEffect, useRef, type RefObject } from "react";
import { HUNT_STATION_ORDER } from "../../world/stations";
import type { HudStationProjection } from "./useHudProjection";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const COLOR_DEFAULT = "#3dbf84";
const COLOR_SELECTED = "#f4d982";
const COLOR_DOCKED = "#5ab4f0";
/** Corner leg size in px */
const CORNER_LEG = 10;

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface TargetBracketsProps {
  projectionsRef: RefObject<HudStationProjection[]>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function TargetBrackets({ projectionsRef }: TargetBracketsProps) {
  // One ref per station bracket container
  const bracketRefs = useRef<Array<HTMLDivElement | null>>(
    Array.from({ length: HUNT_STATION_ORDER.length }, () => null),
  );
  // One ref per distance readout span
  const distanceRefs = useRef<Array<HTMLSpanElement | null>>(
    Array.from({ length: HUNT_STATION_ORDER.length }, () => null),
  );

  useEffect(() => {
    let rafId = 0;

    function loop() {
      rafId = requestAnimationFrame(loop);

      const projections = projectionsRef.current;
      if (!projections) {
        return;
      }

      for (let i = 0; i < projections.length; i += 1) {
        const p = projections[i];
        const bracket = bracketRefs.current[i];
        const distSpan = distanceRefs.current[i];

        if (!bracket) {
          continue;
        }

        if (p.isOffScreen) {
          bracket.style.visibility = "hidden";
          continue;
        }

        bracket.style.visibility = "visible";

        // Position: center the bracket on the projected screen coords
        const half = p.bracketSize / 2;
        bracket.style.transform = `translate(${p.screenX - half}px, ${p.screenY - half}px)`;
        bracket.style.width = `${p.bracketSize}px`;
        bracket.style.height = `${p.bracketSize}px`;

        // Corner color
        const color = p.isDocked ? COLOR_DOCKED : p.isSelected ? COLOR_SELECTED : COLOR_DEFAULT;
        // Set CSS custom property for corner color — all 4 corners share it
        bracket.style.setProperty("--bracket-color", color);

        // Pulse animation for selected mission target
        if (p.isSelected) {
          bracket.classList.add("hud-bracket-pulse");
        } else {
          bracket.classList.remove("hud-bracket-pulse");
        }

        // Distance readout
        if (distSpan) {
          distSpan.textContent = `${Math.round(p.distance)}m`;
          distSpan.style.opacity = String(p.distanceOpacity);
          distSpan.style.color = color;
        }
      }
    }

    rafId = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(rafId);
    };
  }, [projectionsRef]);

  return (
    <>
      {/* Pulse keyframe — injected once as a style tag */}
      <style>{`
        @keyframes hudBracketPulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.7; }
        }
        .hud-bracket-pulse {
          animation: hudBracketPulse 1.5s ease-in-out infinite;
        }
      `}</style>

      <div
        data-testid="hud-target-brackets"
        style={{ position: "absolute", inset: 0, pointerEvents: "none" }}
      >
        {HUNT_STATION_ORDER.map((stationId, i) => (
          <div
            key={stationId}
            ref={(el) => {
              bracketRefs.current[i] = el;
            }}
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              visibility: "hidden",
              // Use CSS custom property for dynamic corner color
              "--bracket-color": COLOR_DEFAULT,
            } as React.CSSProperties}
          >
            {/* Top-left corner: border-top + border-left */}
            <div
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: CORNER_LEG,
                height: CORNER_LEG,
                borderTop: `2px solid var(--bracket-color)`,
                borderLeft: `2px solid var(--bracket-color)`,
              }}
            />
            {/* Top-right corner: border-top + border-right */}
            <div
              style={{
                position: "absolute",
                top: 0,
                right: 0,
                width: CORNER_LEG,
                height: CORNER_LEG,
                borderTop: `2px solid var(--bracket-color)`,
                borderRight: `2px solid var(--bracket-color)`,
              }}
            />
            {/* Bottom-left corner: border-bottom + border-left */}
            <div
              style={{
                position: "absolute",
                bottom: 0,
                left: 0,
                width: CORNER_LEG,
                height: CORNER_LEG,
                borderBottom: `2px solid var(--bracket-color)`,
                borderLeft: `2px solid var(--bracket-color)`,
              }}
            />
            {/* Bottom-right corner: border-bottom + border-right */}
            <div
              style={{
                position: "absolute",
                bottom: 0,
                right: 0,
                width: CORNER_LEG,
                height: CORNER_LEG,
                borderBottom: `2px solid var(--bracket-color)`,
                borderRight: `2px solid var(--bracket-color)`,
              }}
            />
            {/* Distance readout — centered below bracket */}
            <span
              ref={(el) => {
                distanceRefs.current[i] = el;
              }}
              data-testid="hud-distance-readout"
              style={{
                position: "absolute",
                bottom: -16,
                left: "50%",
                transform: "translateX(-50%)",
                fontSize: "9px",
                fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                letterSpacing: "0.08em",
                whiteSpace: "nowrap",
                opacity: 0,
                transition: "opacity 0.2s ease",
                color: COLOR_DEFAULT,
              }}
            />
          </div>
        ))}
      </div>
    </>
  );
}
