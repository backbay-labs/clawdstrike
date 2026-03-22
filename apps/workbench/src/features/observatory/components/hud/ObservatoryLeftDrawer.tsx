/**
 * ObservatoryLeftDrawer.tsx — Phase 31 HUD-13, VIS-03; Phase 33 GLS-01, GLS-02
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
 * Content (Phase 31):
 *   - Routes to ExplainabilityDrawerPanel, MissionDrawerPanel,
 *     ReplayDrawerPanel, or GhostMemoryDrawerPanel based on activePanel value
 *
 * Performance:
 *   - Subscribes to activePanel via useObservatoryStore.use.activePanel() — panel
 *     changes are rare user actions, React subscription is appropriate here.
 */

import type { JSX } from "react";
import { useObservatoryStore } from "../../stores/observatory-store";
import type { HudPanelId } from "../../types";
import {
  HUD_LEFT_DRAWER_WIDTH,
  HUD_STATUS_STRIP_HEIGHT,
} from "./hud-constants";
import { ExplainabilityDrawerPanel } from "./panels/ExplainabilityDrawerPanel";
import { MissionDrawerPanel } from "./panels/MissionDrawerPanel";
import { ReplayDrawerPanel } from "./panels/ReplayDrawerPanel";
import { GhostMemoryDrawerPanel } from "./panels/GhostMemoryDrawerPanel";

// ---------------------------------------------------------------------------
// Panel router
// ---------------------------------------------------------------------------

function renderPanel(panelId: HudPanelId): JSX.Element {
  switch (panelId) {
    case "explainability":
      return <ExplainabilityDrawerPanel />;
    case "mission":
      return <MissionDrawerPanel />;
    case "replay":
      return <ReplayDrawerPanel />;
    case "ghost":
      return <GhostMemoryDrawerPanel />;
  }
}

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
        // Glassmorphism treatment (Phase 33 GLS-01/GLS-02: drawer-specific tokens)
        // --hud-drawer-bg at 0.55 opacity lets 3D scene bleed through the blur
        background: "var(--hud-drawer-bg, rgba(8, 12, 24, 0.55))",
        backdropFilter: "var(--hud-blur, blur(12px))",
        WebkitBackdropFilter: "var(--hud-blur, blur(12px))",
        // Right-edge border at 0.12 opacity (up from 0.06) — perceptible glass edge
        borderRight: "var(--hud-drawer-edge, 1px solid rgba(255, 255, 255, 0.12))",
        // Depth shadow + subtle right-edge glow (GLS-02)
        boxShadow: "var(--hud-shadow, 0 8px 32px rgba(0, 0, 0, 0.4)), var(--hud-drawer-glow, 0 0 12px rgba(100, 160, 255, 0.06))",
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
          gap: 8,
          overflow: "hidden",
        }}
      >
        {activePanel !== null && renderPanel(activePanel)}
      </div>
    </div>
  );
}
