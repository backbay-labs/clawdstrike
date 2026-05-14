/**
 * HeadingCompass.tsx — Phase 24 HUD-02
 *
 * Horizontal compass strip showing cardinal directions (N/E/S/W), tick marks,
 * and station labels at their angular heading positions.
 *
 * Architecture:
 *   - Inner strip (1200px = 360°) rendered once with all labels baked in as absolute children
 *   - Outer container clips the strip to 400px visible window
 *   - translateX on the inner strip scrolls to the current heading each frame
 *   - The strip is repeated 3x (via translateX wrapping logic) for seamless looping
 *   - Quaternion → yaw extraction and Euler/Quaternion objects are pre-allocated OUTSIDE
 *     the rAF loop to eliminate allocations at 60fps
 *
 * Performance contract:
 *   - ZERO useState calls — heading read via getState() in rAF loop
 *   - ZERO useSelector calls — no Zustand subscriptions in the frame loop
 *   - Pre-allocated THREE.Quaternion and THREE.Euler for yaw extraction (module-level)
 *   - translateX set directly on inner strip ref — no React re-renders
 *
 * Visual design:
 *   - Top-center, 400px wide, 28px tall
 *   - N/E/S/W cardinal labels in white
 *   - Station labels in their station color (STATION_COLORS_HEX)
 *   - Fixed center indicator triangle at bottom-center of visible window
 *   - Tick marks every 30°
 */

import { useEffect, useRef } from "react";
import * as THREE from "three";
import { useObservatoryStore } from "../../stores/observatory-store";
import {
  HUNT_STATION_LABELS,
  HUNT_STATION_PLACEMENTS,
} from "../../world/stations";
import {
  HUD_COMPASS_WIDTH,
  HUD_COMPASS_INNER_WIDTH,
  STATION_COLORS_HEX,
} from "./hud-constants";

// ---------------------------------------------------------------------------
// Pre-allocated math objects — never recreated in the rAF loop
// ---------------------------------------------------------------------------

const _quaternion = new THREE.Quaternion();
const _euler = new THREE.Euler();

// ---------------------------------------------------------------------------
// Static layout helpers
// ---------------------------------------------------------------------------

/**
 * Convert a compass degree (0–360) to a pixel offset on the 1200px inner strip.
 * 0° = 0px (leftmost), 360° = 1200px (rightmost, wraps to 0).
 */
function degToPixel(deg: number): number {
  return ((deg % 360) / 360) * HUD_COMPASS_INNER_WIDTH;
}

// Cardinal markers: label, degree
const CARDINALS: Array<{ label: string; deg: number }> = [
  { label: "N", deg: 0 },
  { label: "E", deg: 90 },
  { label: "S", deg: 180 },
  { label: "W", deg: 270 },
];

// Tick marks every 30°
const TICKS: number[] = Array.from({ length: 12 }, (_, i) => i * 30);

// ---------------------------------------------------------------------------
// Render the inner strip contents (static — rendered once)
// ---------------------------------------------------------------------------

function CompassStripContents({ offsetX = 0 }: { offsetX?: number }) {
  return (
    <>
      {/* Tick marks */}
      {TICKS.map((deg) => (
        <div
          key={`tick-${deg}`}
          style={{
            position: "absolute",
            left: degToPixel(deg) + offsetX,
            bottom: 0,
            width: 1,
            height: 4,
            backgroundColor: "var(--hud-text-muted, #6f7f9a)",
            transform: "translateX(-50%)",
          }}
        />
      ))}

      {/* Cardinal labels */}
      {CARDINALS.map(({ label, deg }) => (
        <div
          key={`cardinal-${label}`}
          style={{
            position: "absolute",
            left: degToPixel(deg) + offsetX,
            top: 4,
            fontSize: 10,
            color: "#ffffff",
            transform: "translateX(-50%)",
            lineHeight: 1,
            fontWeight: 500,
          }}
        >
          {label}
        </div>
      ))}

      {/* Station labels at their angular heading positions */}
      {HUNT_STATION_PLACEMENTS.map((placement) => {
        // angleDeg in HUNT_STATION_PLACEMENTS is relative to the world layout
        // We normalize to 0–360 for compass positioning
        const compassDeg = ((placement.angleDeg % 360) + 360) % 360;
        return (
          <div
            key={`station-${placement.id}`}
            style={{
              position: "absolute",
              left: degToPixel(compassDeg) + offsetX,
              bottom: 6,
              fontSize: 8,
              color: STATION_COLORS_HEX[placement.id],
              transform: "translateX(-50%)",
              lineHeight: 1,
              whiteSpace: "nowrap",
            }}
          >
            {HUNT_STATION_LABELS[placement.id]}
          </div>
        );
      })}
    </>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function HeadingCompass() {
  const innerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let rafId: number;

    function loop() {
      const { flightState } = useObservatoryStore.getState();
      const q = flightState.quaternion;

      // Extract yaw from quaternion — pre-allocated objects, no `new` in loop
      _quaternion.set(q[0], q[1], q[2], q[3]);
      _euler.setFromQuaternion(_quaternion, "YXZ");

      // yaw in radians → degrees (0–360), inverted for compass convention
      const yawRad = _euler.y;
      const yawDeg = ((-yawRad * 180) / Math.PI + 360) % 360;

      // Compute translateX:
      // - Strip is 1200px for 360°
      // - We offset by -400px to center the visible 400px window
      // - We add 1200px to put the window in the middle repeat for seamless wrapping
      const stripOffset = (yawDeg / 360) * HUD_COMPASS_INNER_WIDTH;
      const translateX = -stripOffset - HUD_COMPASS_WIDTH / 2 + HUD_COMPASS_INNER_WIDTH;

      if (innerRef.current) {
        innerRef.current.style.transform = `translateX(${translateX}px)`;
      }

      rafId = requestAnimationFrame(loop);
    }

    rafId = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(rafId);
  }, []);

  return (
    <div
      data-testid="hud-heading-compass"
      style={{
        position: "absolute",
        top: 16,
        left: "50%",
        transform: "translateX(-50%)",
        width: HUD_COMPASS_WIDTH,
        height: 28,
        overflow: "hidden",
        background: "var(--hud-bg, rgba(10, 13, 20, 0.7))",
        borderBottom: "var(--hud-border, 1px solid #202531)",
        backdropFilter: "var(--hud-blur, blur(12px))",
        WebkitBackdropFilter: "var(--hud-blur, blur(12px))",
        borderRadius: "var(--hud-radius, 8px)",
      }}
    >
      {/* Inner scrolling strip — 3x width for seamless wrapping */}
      <div
        ref={innerRef}
        style={{
          position: "absolute",
          width: HUD_COMPASS_INNER_WIDTH * 3,
          height: "100%",
          willChange: "transform",
          // Default: start in middle repeat (1200px offset) so wrapping works immediately
          transform: `translateX(${HUD_COMPASS_INNER_WIDTH - HUD_COMPASS_WIDTH / 2}px)`,
        }}
      >
        {/* Repeat the strip contents 3 times for seamless looping */}
        <CompassStripContents offsetX={0} />
        <CompassStripContents offsetX={HUD_COMPASS_INNER_WIDTH} />
        <CompassStripContents offsetX={HUD_COMPASS_INNER_WIDTH * 2} />
      </div>

      {/* Center heading indicator — fixed triangle at bottom-center of visible window */}
      <div
        style={{
          position: "absolute",
          bottom: 0,
          left: "50%",
          transform: "translateX(-50%)",
          width: 0,
          height: 0,
          borderLeft: "6px solid transparent",
          borderRight: "6px solid transparent",
          borderBottom: "6px solid #e0e6ef",
          pointerEvents: "none",
        }}
      />
    </div>
  );
}
