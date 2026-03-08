/**
 * DropIntentLabel — floating label showing the predicted drop action.
 *
 * Renders a small overlay with the primary predicted intent and a secondary
 * explanatory reason line. Fades in/out over 100ms. Designed to appear near
 * the drag ghost to give the operator immediate feedback on what will happen.
 */
import { useEffect, useState } from "react";
import type { CSSProperties } from "react";
import type { DropPrediction } from "./useDropPrediction";

interface DropIntentLabelProps {
  prediction: DropPrediction | null;
  visible: boolean;
}

const CONTAINER_STYLE: CSSProperties = {
  maxWidth: 200,
  padding: "6px 10px",
  borderRadius: 6,
  background: "rgba(6,8,13,0.9)",
  border: "1px solid rgba(213,173,87,0.15)",
  boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
  pointerEvents: "none",
  userSelect: "none",
};

const PRIMARY_STYLE: CSSProperties = {
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 11,
  lineHeight: "14px",
  color: "rgba(213,173,87,0.8)",
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};

const SECONDARY_STYLE: CSSProperties = {
  fontFamily: "ui-monospace, 'Fira Code', 'Cascadia Code', monospace",
  fontSize: 9,
  lineHeight: "12px",
  fontStyle: "italic",
  color: "rgba(182,183,193,0.4)",
  marginTop: 2,
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};

export function DropIntentLabel({ prediction, visible }: DropIntentLabelProps) {
  const [opacity, setOpacity] = useState(0);

  useEffect(() => {
    if (visible && prediction) {
      const raf = requestAnimationFrame(() => setOpacity(1));
      return () => cancelAnimationFrame(raf);
    }
    setOpacity(0);
    return undefined;
  }, [visible, prediction]);

  if (!visible || !prediction) return null;

  const style: CSSProperties = {
    ...CONTAINER_STYLE,
    opacity,
    transition: "opacity 100ms ease",
  };

  return (
    <div style={style}>
      <div style={PRIMARY_STYLE}>{prediction.defaultLabel}</div>
      <div style={SECONDARY_STYLE}>{prediction.explanation.reason}</div>
    </div>
  );
}
