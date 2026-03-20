/**
 * OffScreenArrows.tsx — Phase 24 HUD-04, HUD-05
 *
 * Directional arrow indicators shown at screen edges when a station is outside
 * the camera frustum. Each arrow points toward the off-screen station and shows
 * the station name + distance.
 *
 * Design contract:
 *   - Pre-renders 6 arrow containers (one per station) — never mount/unmount.
 *   - Positions, rotations and labels updated each frame via ref mutation in a rAF loop.
 *   - ZERO useState, ZERO useSelector. All frame work goes through refs.
 *   - pointer-events:none — display only.
 *   - drop-shadow filter for visibility against bright nebula backgrounds.
 */

import { useEffect, useRef, type RefObject } from "react";
import { HUNT_STATION_ORDER } from "../../world/stations";
import type { HudStationProjection } from "./useHudProjection";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface OffScreenArrowsProps {
  projectionsRef: RefObject<HudStationProjection[]>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function OffScreenArrows({ projectionsRef }: OffScreenArrowsProps) {
  // One ref per arrow container div
  const arrowRefs = useRef<Array<HTMLDivElement | null>>(
    Array.from({ length: HUNT_STATION_ORDER.length }, () => null),
  );
  // One ref per SVG arrow element (for rotation)
  const svgRefs = useRef<Array<SVGSVGElement | null>>(
    Array.from({ length: HUNT_STATION_ORDER.length }, () => null),
  );
  // One ref per station name label
  const nameLabelRefs = useRef<Array<HTMLSpanElement | null>>(
    Array.from({ length: HUNT_STATION_ORDER.length }, () => null),
  );
  // One ref per distance label
  const distanceLabelRefs = useRef<Array<HTMLSpanElement | null>>(
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
        const container = arrowRefs.current[i];
        const svg = svgRefs.current[i];
        const nameLabel = nameLabelRefs.current[i];
        const distLabel = distanceLabelRefs.current[i];

        if (!container) {
          continue;
        }

        if (!p.isOffScreen) {
          container.style.visibility = "hidden";
          continue;
        }

        container.style.visibility = "visible";

        // Position at edge-clamped coordinates, offset to center the arrow glyph
        container.style.transform = `translate(${p.edgeX - 12}px, ${p.edgeY - 12}px)`;

        // Rotate SVG arrow to point toward station
        // Arrow SVG points right (0 rad) by default — atan2 offset gives direction
        if (svg) {
          svg.style.transform = `rotate(${p.arrowRotation}rad)`;
          // Tint arrow to station color
          const path = svg.querySelector("polygon");
          if (path) {
            (path as SVGPolygonElement).style.fill = p.colorHex;
          }
        }

        // Station name label
        if (nameLabel) {
          nameLabel.textContent = p.label;
        }

        // Distance label with opacity based on approach distance
        if (distLabel) {
          distLabel.textContent = `${Math.round(p.distance)}m`;
          distLabel.style.opacity = String(p.distanceOpacity);
        }
      }
    }

    rafId = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(rafId);
    };
  }, [projectionsRef]);

  return (
    <div
      data-testid="hud-offscreen-arrows"
      style={{ position: "absolute", inset: 0, pointerEvents: "none" }}
    >
      {HUNT_STATION_ORDER.map((stationId, i) => (
        <div
          key={stationId}
          ref={(el) => {
            arrowRefs.current[i] = el;
          }}
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            visibility: "hidden",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 2,
            filter: "drop-shadow(0 0 4px rgba(0,0,0,0.8))",
          }}
        >
          {/* SVG equilateral triangle arrow — points right by default */}
          <svg
            ref={(el) => {
              svgRefs.current[i] = el;
            }}
            width={14}
            height={12}
            viewBox="0 0 14 12"
            style={{ display: "block", flexShrink: 0 }}
          >
            {/* Equilateral-ish triangle pointing right */}
            <polygon
              points="0,0 14,6 0,12"
              style={{ fill: "#c8d2e0" }}
            />
          </svg>

          {/* Station name */}
          <span
            ref={(el) => {
              nameLabelRefs.current[i] = el;
            }}
            style={{
              fontSize: "8px",
              fontFamily: '"JetBrains Mono", "Fira Code", monospace',
              letterSpacing: "0.1em",
              textTransform: "uppercase",
              color: "#c8d2e0",
              whiteSpace: "nowrap",
              lineHeight: 1,
            }}
          >
            {HUNT_STATION_ORDER[i]}
          </span>

          {/* Distance */}
          <span
            ref={(el) => {
              distanceLabelRefs.current[i] = el;
            }}
            style={{
              fontSize: "10px",
              fontFamily: '"JetBrains Mono", "Fira Code", monospace',
              fontWeight: "bold",
              color: "#c8d2e0",
              whiteSpace: "nowrap",
              lineHeight: 1,
              opacity: 0,
            }}
          />
        </div>
      ))}
    </div>
  );
}
