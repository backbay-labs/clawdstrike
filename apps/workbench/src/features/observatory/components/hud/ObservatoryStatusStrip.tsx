/**
 * ObservatoryStatusStrip.tsx — Phase 29 HUD-10, HUD-11, HUD-12, VIS-02, VIS-04
 *
 * Persistent glassmorphism footer bar at the bottom of the observatory canvas.
 * Always mounted, always visible — the cockpit footer for constant situational awareness.
 *
 * Layout (flexbox row, space-between):
 *   LEFT   — speed readout (u/s), heading cardinal (N/NE/…), station count
 *   RIGHT  — four analyst preset pill buttons (THREAT, EVIDENCE, RECEIPTS, GHOST)
 *   FAR-RIGHT — minimap indicator dot (placeholder, future work)
 *
 * Performance contract (HUD-11):
 *   - Telemetry section (speed, heading, station count) updated via rAF + getState() + ref.textContent
 *     mutation — ZERO React re-renders in the frame loop.
 *   - Pre-allocated THREE.Quaternion and THREE.Euler at module level (no allocations per frame).
 *   - Analyst preset buttons use useObservatoryStore.use.* subscriptions — only re-render on
 *     preset/panel changes (rare, not per-frame).
 *
 * Glassmorphism styling (VIS-02):
 *   - background: rgba(8, 12, 24, 0.88) — above 0.85 minimum opacity threshold for readability
 *   - backdropFilter: blur(12px)
 *   - border-top: 1px solid rgba(255, 255, 255, 0.06)
 *   - boxShadow: 0 8px 32px rgba(0, 0, 0, 0.4) (inverted, shows above canvas)
 *
 * Active indicator (VIS-04):
 *   - Active preset button: borderBottom: 2px solid var(--hud-accent)
 *   - Subtle glow: boxShadow with hud-accent at 40% opacity
 */

import { useEffect, useRef } from "react";
import * as THREE from "three";
import { useObservatoryStore } from "../../stores/observatory-store";
import { ANALYST_PRESETS } from "./hud-constants";

// ---------------------------------------------------------------------------
// Pre-allocated math objects — never recreated in the rAF loop
// ---------------------------------------------------------------------------

const _quaternion = new THREE.Quaternion();
const _euler = new THREE.Euler();

// ---------------------------------------------------------------------------
// Cardinal direction lookup
// ---------------------------------------------------------------------------

const CARDINALS = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"] as const;

function yawDegToCardinal(yawDeg: number): string {
  const index = Math.round(yawDeg / 45) % 8;
  return CARDINALS[index] ?? "N";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ObservatoryStatusStrip() {
  const speedRef = useRef<HTMLSpanElement>(null);
  const headingRef = useRef<HTMLSpanElement>(null);
  const stationCountRef = useRef<HTMLSpanElement>(null);

  // React subscriptions for preset buttons (rare updates — not per-frame)
  const analystPresetId = useObservatoryStore.use.analystPresetId();
  const actions = useObservatoryStore.use.actions();

  // rAF loop: read flightState + seamSummary, mutate DOM refs — no React setState
  useEffect(() => {
    let rafId: number;

    function loop() {
      const { flightState, seamSummary } = useObservatoryStore.getState();
      const q = flightState.quaternion;

      // Extract yaw from quaternion (pre-allocated objects, no `new` in loop)
      _quaternion.set(q[0], q[1], q[2], q[3]);
      _euler.setFromQuaternion(_quaternion, "YXZ");
      const yawRad = _euler.y;
      const yawDeg = ((-yawRad * 180) / Math.PI + 360) % 360;

      if (speedRef.current) {
        speedRef.current.textContent = String(Math.round(flightState.currentSpeed));
      }

      if (headingRef.current) {
        headingRef.current.textContent = yawDegToCardinal(yawDeg);
      }

      if (stationCountRef.current) {
        stationCountRef.current.textContent = String(seamSummary.stationCount);
      }

      rafId = requestAnimationFrame(loop);
    }

    rafId = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(rafId);
  }, []);

  return (
    <div
      data-testid="observatory-status-strip"
      style={{
        position: "absolute",
        bottom: 0,
        left: 0,
        right: 0,
        height: 28,
        zIndex: 20,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 12px",
        gap: 8,
        // Glassmorphism treatment — VIS-02: >= 0.85 opacity for readability
        background: "rgba(8, 12, 24, 0.88)",
        backdropFilter: "var(--hud-blur, blur(12px))",
        WebkitBackdropFilter: "var(--hud-blur, blur(12px))",
        borderTop: "var(--hud-border, 1px solid rgba(255, 255, 255, 0.06))",
        boxShadow: "0 -4px 16px rgba(0, 0, 0, 0.3)",
        // Allow pointer events so preset buttons are clickable
        pointerEvents: "auto",
        fontFamily: "'JetBrains Mono', 'Fira Mono', 'Consolas', monospace",
        fontSize: 10,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        color: "var(--hud-text, rgba(255, 255, 255, 0.85))",
      }}
    >
      {/* LEFT SECTION — telemetry readouts (updated via rAF ref mutation) */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          flex: "0 0 auto",
        }}
      >
        {/* Speed readout */}
        <div style={{ display: "flex", alignItems: "baseline", gap: 3 }}>
          <span
            ref={speedRef}
            data-testid="status-strip-speed"
            style={{
              color: "var(--hud-text, rgba(255, 255, 255, 0.85))",
              fontVariantNumeric: "tabular-nums",
              minWidth: "2.5ch",
              textAlign: "right",
            }}
          >
            0
          </span>
          <span style={{ color: "var(--hud-text-muted, rgba(255, 255, 255, 0.45))", fontSize: 8 }}>
            u/s
          </span>
        </div>

        {/* Separator */}
        <span style={{ color: "var(--hud-text-muted, rgba(255, 255, 255, 0.45))", fontSize: 8 }}>
          ·
        </span>

        {/* Heading cardinal */}
        <div style={{ display: "flex", alignItems: "baseline", gap: 3 }}>
          <span
            ref={headingRef}
            data-testid="status-strip-heading"
            style={{
              color: "var(--hud-text, rgba(255, 255, 255, 0.85))",
              minWidth: "2ch",
              textAlign: "center",
            }}
          >
            N
          </span>
        </div>

        {/* Separator */}
        <span style={{ color: "var(--hud-text-muted, rgba(255, 255, 255, 0.45))", fontSize: 8 }}>
          ·
        </span>

        {/* Station count */}
        <div style={{ display: "flex", alignItems: "baseline", gap: 3 }}>
          <span
            ref={stationCountRef}
            data-testid="status-strip-station-count"
            style={{
              color: "var(--hud-text, rgba(255, 255, 255, 0.85))",
              fontVariantNumeric: "tabular-nums",
              minWidth: "1.5ch",
              textAlign: "right",
            }}
          >
            0
          </span>
          <span style={{ color: "var(--hud-text-muted, rgba(255, 255, 255, 0.45))", fontSize: 8 }}>
            sta
          </span>
        </div>
      </div>

      {/* CENTER-RIGHT SECTION — analyst preset pill buttons */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 4,
          flex: "0 0 auto",
        }}
      >
        {ANALYST_PRESETS.map((preset) => {
          const isActive = analystPresetId === preset.id;
          return (
            <button
              key={preset.id}
              type="button"
              data-testid={`status-strip-preset-${preset.id}`}
              onClick={() => {
                // Radio-toggle: clicking active preset deactivates it; clicking another activates it
                actions.setAnalystPreset(isActive ? null : preset.id);
              }}
              style={{
                padding: "1px 8px",
                fontSize: 9,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                fontFamily: "inherit",
                cursor: "pointer",
                borderRadius: 4,
                border: "1px solid rgba(255, 255, 255, 0.08)",
                borderBottom: isActive
                  ? "2px solid var(--hud-accent, #4af)"
                  : "1px solid rgba(255, 255, 255, 0.08)",
                background: isActive
                  ? "rgba(68, 170, 255, 0.10)"
                  : "rgba(255, 255, 255, 0.03)",
                color: isActive
                  ? "var(--hud-accent, #4af)"
                  : "var(--hud-text-muted, rgba(255, 255, 255, 0.45))",
                boxShadow: isActive
                  ? "0 2px 8px rgba(68, 170, 255, 0.40)"
                  : "none",
                outline: "none",
                transition: "color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease, border-bottom 0.15s ease",
                minWidth: 60,
                height: 18,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {preset.label}
            </button>
          );
        })}
      </div>

      {/* RIGHT SECTION — minimap indicator dot (placeholder) */}
      <div
        data-testid="status-strip-minimap-dot"
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          background: "rgba(255, 255, 255, 0.12)",
          border: "1px solid rgba(255, 255, 255, 0.18)",
          flex: "0 0 auto",
        }}
      />
    </div>
  );
}
