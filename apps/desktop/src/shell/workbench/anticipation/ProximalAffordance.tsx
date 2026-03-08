/**
 * ProximalAffordance — renders a tiny affordance strip near a hovered object.
 *
 * Appears after hover activation and shows context-aware actions as small
 * pills. The promoted action gets slightly brighter styling. Fades in/out
 * using CSS transitions keyed to TIMING constants.
 */
import { useCallback, useEffect, useState } from "react";
import { createPortal } from "react-dom";
import type { CSSProperties } from "react";
import type { ProximalAction } from "./types";
import { TIMING } from "./types";

interface ProximalAffordanceProps {
  actions: ProximalAction[];
  position: { x: number; y: number };
  visible: boolean;
  onAction: (actionId: string) => void;
  onMouseLeave?: () => void;
}

// ── Styles ───────────────────────────────────────────────────────

const STRIP_STYLE: CSSProperties = {
  position: "fixed",
  display: "flex",
  flexDirection: "row",
  gap: 4,
  padding: "2px 4px",
  borderRadius: 6,
  background: "rgba(6,8,13,0.85)",
  border: "1px solid rgba(213,173,87,0.15)",
  zIndex: 1000,
  pointerEvents: "auto",
  whiteSpace: "nowrap",
};

const PILL_BASE: CSSProperties = {
  height: 20,
  minWidth: 50,
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
  padding: "0 8px",
  borderRadius: 4,
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 10,
  lineHeight: "20px",
  color: "rgba(232,230,222,0.7)",
  background: "transparent",
  border: "none",
  cursor: "pointer",
  userSelect: "none",
  transition: "background 100ms ease",
};

const PILL_PROMOTED: CSSProperties = {
  ...PILL_BASE,
  background: "rgba(213,173,87,0.1)",
};

// ── Component ────────────────────────────────────────────────────

export function ProximalAffordance({
  actions,
  position,
  visible,
  onAction,
  onMouseLeave,
}: ProximalAffordanceProps) {
  // Deferred opacity for transition — starts at 0, rises to 1 on next frame
  const [opacity, setOpacity] = useState(0);

  useEffect(() => {
    if (visible && actions.length > 0) {
      // Trigger fade-in on the next frame so the transition fires
      const raf = requestAnimationFrame(() => setOpacity(1));
      return () => cancelAnimationFrame(raf);
    }
    // Fade out
    setOpacity(0);
    return undefined;
  }, [visible, actions.length]);

  const handleClick = useCallback(
    (actionId: string) => (e: React.MouseEvent) => {
      e.stopPropagation();
      onAction(actionId);
    },
    [onAction],
  );

  if (actions.length === 0) return null;

  const transitionDuration = opacity === 1
    ? TIMING.PROXIMAL_FADE_IN_MS
    : TIMING.PROXIMAL_FADE_OUT_MS;

  const containerStyle: CSSProperties = {
    ...STRIP_STYLE,
    left: position.x,
    top: position.y,
    opacity,
    transition: `opacity ${transitionDuration}ms ease`,
  };

  // Render via portal to escape overflow-hidden ancestors
  return createPortal(
    <div style={containerStyle} onMouseLeave={onMouseLeave}>
      {actions.map((action) => (
        <button
          key={action.id}
          type="button"
          style={action.promoted ? PILL_PROMOTED : PILL_BASE}
          onClick={handleClick(action.id)}
        >
          {action.label}
        </button>
      ))}
    </div>,
    document.body,
  );
}
