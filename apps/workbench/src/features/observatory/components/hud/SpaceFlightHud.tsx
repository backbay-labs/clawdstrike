/**
 * SpaceFlightHud.tsx — Phase 24 HUD-01, HUD-02, HUD-03, HUD-04, HUD-05, HUD-06
 *
 * Root HUD overlay component. Wraps all Space Flight HUD instruments in a single
 * absolute-positioned overlay div that sits on top of the R3F Canvas.
 *
 * Design contract (HUD-06):
 *   - Always mounted (never null-returned) so DOM nodes are pre-created.
 *   - Visibility toggled via opacity:0, NOT by unmounting — prevents rAF teardown on hide.
 *   - pointer-events:none — HUD is display-only, does not intercept user input.
 *   - z-index:15 — above Canvas (z-index:0) but below modal layers.
 *
 * Child components communicate with the store via requestAnimationFrame + getState(),
 * never via useState or useSelector. This keeps re-render count at zero in the frame loop.
 */

import { useRef } from "react";
import { SpeedIndicator } from "./SpeedIndicator";
import { HeadingCompass } from "./HeadingCompass";
import { TargetBrackets } from "./TargetBrackets";
import { OffScreenArrows } from "./OffScreenArrows";
import { useHudProjection } from "./useHudProjection";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface SpaceFlightHudProps {
  /**
   * When false, the HUD is visually hidden (opacity:0) but remains mounted.
   * Keeping the DOM nodes alive avoids the cost of recreating them on re-entry
   * to flight mode and prevents rAF loops from being torn down unnecessarily.
   */
  visible: boolean;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SpaceFlightHud({ visible }: SpaceFlightHudProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const { projectionsRef } = useHudProjection(containerRef);

  return (
    <div
      ref={containerRef}
      style={{
        position: "absolute",
        inset: 0,
        pointerEvents: "none",
        zIndex: 15,
        opacity: visible ? 1 : 0,
        // Elite Dangerous instrument typography
        fontFamily: '"JetBrains Mono", "Fira Code", "Menlo", monospace',
        fontSize: "10px",
        color: "var(--hud-text, #c8d2e0)",
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        // Smooth hide/show transitions to avoid jarring cuts
        transition: "opacity 0.25s ease",
      }}
    >
      {/* HUD-01: Vertical speed indicator — bottom-left */}
      <SpeedIndicator />

      {/* HUD-02: Horizontal heading compass — top-center */}
      <HeadingCompass />

      {/* HUD-03: L-corner target brackets for in-frustum stations */}
      <TargetBrackets projectionsRef={projectionsRef} />

      {/* HUD-04: Off-screen directional arrows at screen edges */}
      <OffScreenArrows projectionsRef={projectionsRef} />
    </div>
  );
}
