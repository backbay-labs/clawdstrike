import { useEffect, useRef } from "react";
import type { ContextMenuState } from "../../hooks/useContextMenu";

export function ContextMenu({ state, onClose }: { state: ContextMenuState; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!state.visible) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const keyHandler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("mousedown", handler);
    document.addEventListener("keydown", keyHandler);
    return () => { document.removeEventListener("mousedown", handler); document.removeEventListener("keydown", keyHandler); };
  }, [state.visible, onClose]);

  if (!state.visible) return null;

  return (
    <div
      ref={ref}
      className="glass-panel"
      style={{
        position: "fixed",
        left: state.x,
        top: state.y,
        zIndex: 10000,
        padding: "4px 0",
        minWidth: 160,
      }}
    >
      {state.items.map((item, i) =>
        item.separator ? (
          <div key={i} style={{ height: 1, margin: "4px 8px", background: "var(--slate)" }} />
        ) : (
          <button
            key={i}
            type="button"
            onClick={() => { item.action(); onClose(); }}
            className="hover-row font-mono"
            style={{
              display: "block",
              width: "100%",
              textAlign: "left",
              background: "none",
              border: "none",
              padding: "6px 16px",
              fontSize: 12,
              color: "var(--text)",
              cursor: "pointer",
            }}
          >
            {item.label}
          </button>
        ),
      )}
    </div>
  );
}
