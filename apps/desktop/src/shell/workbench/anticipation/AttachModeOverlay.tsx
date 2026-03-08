/**
 * AttachModeOverlay — subtle viewport overlay indicating Attach Mode is active.
 *
 * Renders a nearly-invisible gold-tinted layer (pointer-events: none) with:
 *   - Top-left floating label: "Attach Mode . {draggedKind}"
 *   - Bottom-right default action hint: "Drop -> {defaultAction}"
 *
 * The overlay itself never captures interaction — it is purely informational.
 */

export interface AttachModeOverlayProps {
  active: boolean;
  draggedKind: string | null;
  defaultAction: string | null;
}

export function AttachModeOverlay({
  active,
  draggedKind,
  defaultAction,
}: AttachModeOverlayProps) {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 40,
        pointerEvents: "none",
        background: active ? "rgba(213,173,87,0.02)" : "transparent",
        opacity: active ? 1 : 0,
        transition: "opacity 100ms ease, background 100ms ease",
      }}
    >
      {/* Top label */}
      {active && draggedKind && (
        <div
          style={{
            position: "absolute",
            top: 10,
            left: 52,
            fontFamily: "monospace",
            fontSize: 10,
            color: "rgba(213,173,87,0.45)",
            letterSpacing: "0.02em",
            userSelect: "none",
          }}
        >
          <div>Attach Mode &middot; {draggedKind}</div>
          <div style={{ color: "rgba(182,183,193,0.45)" }}>
            Drop on hunt pills, the smart bucket, or the stage shelf.
          </div>
        </div>
      )}

      {/* Bottom-right default action hint */}
      {active && defaultAction && (
        <div
          style={{
            position: "absolute",
            bottom: 6,
            right: 12,
            fontFamily: "monospace",
            fontSize: 9,
            color: "rgba(213,173,87,0.35)",
            userSelect: "none",
          }}
        >
          Drop &rarr; {defaultAction}
        </div>
      )}
    </div>
  );
}
