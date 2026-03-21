/**
 * GhostMemoryDrawerPanel.tsx — Phase 31 PNL-04
 *
 * Renders derived ghost traces in the left drawer:
 *   - GHOST MEMORY heading + trace count
 *   - Scrollable list of ghost traces with source kind badge,
 *     headline, detail text, and formatted timestamp
 *
 * Reads from: stations, selectedStationId, likelyStationId (direct selector)
 * Derives: ghost traces via deriveObservatoryGhostMemories()
 */

import { useMemo } from "react";
import { useObservatoryStore } from "../../../stores/observatory-store";
import { deriveObservatoryGhostMemories } from "../../../world/observatory-ghost-memory";
import type { ObservatoryGhostSourceKind } from "../../../world/observatory-ghost-memory";

// ---------------------------------------------------------------------------
// Source kind badge styles
// ---------------------------------------------------------------------------

function getSourceKindStyle(sourceKind: ObservatoryGhostSourceKind): React.CSSProperties {
  if (sourceKind === "finding") {
    return {
      background: "rgba(77,175,255,0.15)",
      color: "#4dafff",
    };
  }
  // receipt
  return {
    background: "rgba(126,230,242,0.15)",
    color: "#7ee6f2",
  };
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function GhostMemoryDrawerPanel() {
  const stations = useObservatoryStore.use.stations();
  const selectedStationId = useObservatoryStore.use.selectedStationId();
  const likelyStationId = useObservatoryStore((s) => s.likelyStationId);

  const traces = useMemo(
    () =>
      deriveObservatoryGhostMemories({
        stations,
        selectedStationId,
        likelyStationId,
        nowMs: Date.now(),
      }),
    [stations, selectedStationId, likelyStationId],
  );

  return (
    <div
      data-testid="ghost-memory-drawer-panel"
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 0,
        padding: 0,
        height: "100%",
        overflowY: "auto",
        fontFamily: "inherit",
      }}
    >
      {/* Header */}
      <div style={{ marginBottom: 12 }}>
        <div
          style={{
            fontSize: 10,
            textTransform: "uppercase",
            letterSpacing: "0.12em",
            color: "var(--hud-text-muted)",
            marginBottom: 4,
          }}
        >
          Ghost Memory
        </div>
        <div
          style={{
            fontSize: 11,
            color: "var(--hud-text-muted)",
          }}
        >
          {traces.length} trace{traces.length !== 1 ? "s" : ""}
        </div>
      </div>

      {/* Empty state */}
      {traces.length === 0 ? (
        <div
          data-testid="ghost-memory-empty-state"
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flex: 1,
            color: "var(--hud-text-muted)",
            fontSize: 13,
            fontStyle: "italic",
            textAlign: "center",
            padding: "0 16px",
          }}
        >
          No prior findings or receipts
        </div>
      ) : (
        /* Traces list */
        <div style={{ display: "flex", flexDirection: "column" }}>
          {traces.map((trace) => (
            <div
              key={trace.id}
              data-testid={`ghost-trace-${trace.id}`}
              style={{
                padding: "10px 0",
                borderBottom: "1px solid rgba(255,255,255,0.04)",
              }}
            >
              {/* Source kind badge */}
              <span
                style={{
                  fontSize: 9,
                  textTransform: "uppercase",
                  padding: "1px 6px",
                  borderRadius: 6,
                  fontFamily: "inherit",
                  ...getSourceKindStyle(trace.sourceKind),
                }}
              >
                {trace.sourceKind}
              </span>

              {/* Headline */}
              <div
                style={{
                  fontSize: 13,
                  fontWeight: 500,
                  color: "var(--hud-text)",
                  marginTop: 4,
                  lineHeight: 1.3,
                }}
              >
                {trace.headline}
              </div>

              {/* Detail */}
              <div
                style={{
                  fontSize: 12,
                  color: "var(--hud-text-muted)",
                  marginTop: 2,
                  lineHeight: 1.4,
                }}
              >
                {trace.detail}
              </div>

              {/* Timestamp + author */}
              <div
                style={{
                  fontSize: 10,
                  color: "var(--hud-text-muted)",
                  marginTop: 4,
                }}
              >
                {new Date(trace.timestampMs).toLocaleString()}
                {trace.authorLabel ? ` - ${trace.authorLabel}` : ""}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
