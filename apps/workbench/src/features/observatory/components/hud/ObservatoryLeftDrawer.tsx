/**
 * ObservatoryLeftDrawer.tsx — Phase 30 HUD-13, VIS-03
 *
 * A 360px wide glassmorphism panel that slides in from the left edge of the
 * observatory canvas when `activePanel` is non-null.
 *
 * Layout:
 *   - Always mounted (like SpaceFlightHud) — visibility driven by CSS transform
 *   - Positioned absolute, top 0 → bottom HUD_STATUS_STRIP_HEIGHT (clears footer)
 *   - z-index 18 — above SpaceFlightHud (z:15), below StatusStrip (z:20)
 *
 * Transitions (VIS-03):
 *   - Slide: translateX(-100%) → translateX(0), 250ms ease-out
 *   - Content fade: opacity 0 → 1, 200ms ease-out with 100ms delay (fades in after
 *     drawer is partially slid into position)
 *
 * Content:
 *   - Phase 30: placeholder — shows active panel name in uppercase monospace text
 *   - Phase 31+: placeholder replaced with real panel content
 *
 * Performance:
 *   - Subscribes to activePanel via useObservatoryStore.use.activePanel() — panel
 *     changes are rare user actions, React subscription is appropriate here.
 */

import { useObservatoryStore } from "../../stores/observatory-store";
import {
  HUD_LEFT_DRAWER_WIDTH,
  HUD_STATUS_STRIP_HEIGHT,
} from "./hud-constants";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ObservatoryLeftDrawer() {
  // React subscription — panel opens/closes are rare user actions, not per-frame
  const activePanel = useObservatoryStore.use.activePanel();

  const isOpen = activePanel !== null;

  return (
    <div
      data-testid="observatory-left-drawer"
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        bottom: HUD_STATUS_STRIP_HEIGHT,
        width: HUD_LEFT_DRAWER_WIDTH,
        zIndex: 18,
        // Glassmorphism treatment (VIS-01 tokens)
        background: "var(--hud-bg, rgba(8, 12, 24, 0.75))",
        backdropFilter: "var(--hud-blur, blur(12px))",
        WebkitBackdropFilter: "var(--hud-blur, blur(12px))",
        borderRight: "var(--hud-border, 1px solid rgba(255, 255, 255, 0.06))",
        boxShadow: "var(--hud-shadow, 0 8px 32px rgba(0, 0, 0, 0.4))",
        // Slide transition (VIS-03): translateX(-100%) when hidden, translateX(0) when open
        transform: isOpen ? "translateX(0)" : "translateX(-100%)",
        transition: "transform 250ms ease-out",
        // Hidden drawer must not intercept pointer events
        pointerEvents: isOpen ? "auto" : "none",
        fontFamily: "'JetBrains Mono', 'Fira Mono', 'Consolas', monospace",
      }}
    >
      {/* Content wrapper: fade-in after slide partially completes (100ms delay) */}
      <div
        style={{
          opacity: isOpen ? 1 : 0,
          transition: "opacity 200ms ease-out 100ms",
          padding: 16,
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 8,
        }}
      >
        {/* Phase 30 placeholder — panel name in uppercase monospace */}
        {activePanel !== null && (
          <span
            data-testid="observatory-left-drawer-panel-name"
            style={{
              color: "var(--hud-text-muted, rgba(255, 255, 255, 0.45))",
              fontSize: 12,
              fontFamily: "inherit",
              textTransform: "uppercase",
              letterSpacing: "0.1em",
              textAlign: "center",
            }}
          >
            {activePanel}
          </span>
        )}
      </div>
    </div>
  );
}
