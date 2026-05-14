import { useEffect, useRef } from "react";
import * as THREE from "three";
import { useObservatoryStore } from "../../stores/observatory-store";
import { ANALYST_PRESETS } from "./hud-constants";

const _quaternion = new THREE.Quaternion();
const _euler = new THREE.Euler();

const CARDINALS = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"] as const;

function yawDegToCardinal(yawDeg: number): string {
  const index = Math.round(yawDeg / 45) % 8;
  return CARDINALS[index] ?? "N";
}

const separatorStyle: React.CSSProperties = {
  color: "var(--hud-text-muted, rgba(255, 255, 255, 0.45))",
  fontSize: 9,
};

interface ObservatoryStatusStripProps {
  mode: "atlas" | "flow";
  onModeToggle: () => void;
  interiorActive?: boolean;
  onExitInterior?: () => void;
}

export function ObservatoryStatusStrip({
  mode,
  onModeToggle,
  interiorActive = false,
  onExitInterior,
}: ObservatoryStatusStripProps) {
  const speedRef = useRef<HTMLSpanElement>(null);
  const headingRef = useRef<HTMLSpanElement>(null);
  const stationCountRef = useRef<HTMLSpanElement>(null);

  const analystPresetId = useObservatoryStore.use.analystPresetId();
  const actions = useObservatoryStore.use.actions();

  useEffect(() => {
    let rafId: number;

    function loop() {
      const { flightState, seamSummary } = useObservatoryStore.getState();
      const q = flightState.quaternion;

      _quaternion.set(q[0], q[1], q[2], q[3]);
      _euler.setFromQuaternion(_quaternion, "YXZ");
      const yawDeg = ((-_euler.y * 180) / Math.PI + 360) % 360;

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
        background: "rgba(8, 12, 24, 0.88)",
        backdropFilter: "var(--hud-blur, blur(12px))",
        WebkitBackdropFilter: "var(--hud-blur, blur(12px))",
        borderTop: "1px solid rgba(255, 255, 255, 0.12)",
        boxShadow: "0 -4px 16px rgba(0, 0, 0, 0.3)",
        pointerEvents: "auto",
        fontFamily: "'JetBrains Mono', 'Fira Mono', 'Consolas', monospace",
        fontSize: 11,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        color: "var(--hud-text, rgba(255, 255, 255, 0.85))",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          flex: "0 0 auto",
        }}
      >
        {interiorActive && onExitInterior && (
          <>
            <button
              type="button"
              data-testid="status-strip-exit-interior"
              onClick={onExitInterior}
              style={{
                padding: "1px 10px",
                fontSize: 9,
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                fontFamily: "inherit",
                cursor: "pointer",
                borderRadius: 4,
                border: "1px solid rgba(255, 100, 100, 0.3)",
                background: "rgba(255, 100, 100, 0.08)",
                color: "#ff8888",
                outline: "none",
                height: 18,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                transition: "background 0.15s ease",
              }}
            >
              EXIT INTERIOR
            </button>
            <span style={separatorStyle}>·</span>
          </>
        )}

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
          <span style={separatorStyle}>u/s</span>
        </div>

        <span style={separatorStyle}>·</span>

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

        <span style={separatorStyle}>·</span>

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
          <span style={separatorStyle}>sta</span>
        </div>
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 4,
          flex: "0 0 auto",
        }}
      >
        <button
          type="button"
          data-testid="status-strip-mode-toggle"
          onClick={onModeToggle}
          style={{
            padding: "1px 8px",
            fontSize: 9,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            fontFamily: "inherit",
            cursor: "pointer",
            borderRadius: 4,
            border: "1px solid rgba(255, 255, 255, 0.08)",
            borderBottom: mode === "flow"
              ? "2px solid #3dbf84"
              : "1px solid rgba(255, 255, 255, 0.08)",
            background: mode === "flow"
              ? "rgba(61, 191, 132, 0.10)"
              : "rgba(255, 255, 255, 0.03)",
            color: mode === "flow"
              ? "#3dbf84"
              : "var(--hud-text-muted, rgba(255, 255, 255, 0.45))",
            boxShadow: mode === "flow"
              ? "0 2px 8px rgba(61, 191, 132, 0.40)"
              : "none",
            outline: "none",
            transition: "color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease, border-bottom 0.15s ease",
            minWidth: 52,
            height: 18,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            marginRight: 4,
            borderLeft: "1px solid rgba(255, 255, 255, 0.08)",
          }}
        >
          {mode === "flow" ? "FLOW" : "ATLAS"}
        </button>

        <span
          style={{
            width: 1,
            height: 12,
            background: "rgba(255, 255, 255, 0.15)",
            flex: "0 0 auto",
            marginRight: 4,
          }}
        />

        {ANALYST_PRESETS.map((preset) => {
          const isActive = analystPresetId === preset.id;
          return (
            <button
              key={preset.id}
              type="button"
              data-testid={`status-strip-preset-${preset.id}`}
              onClick={() => actions.setAnalystPreset(isActive ? null : preset.id)}
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
