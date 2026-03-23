/**
 * ReplayDrawerPanel.tsx — Phase 31 PNL-03
 *
 * Renders the replay control panel in the left drawer:
 *   - Timeline scrubber (range input) with frame readout
 *   - Bookmark list (click to jump)
 *   - Jump-to-spike button
 *   - Compare toggle (now vs then)
 *
 * Reads from: replay (ObservatoryReplayState)
 * Actions: setReplayState (imperative via getState())
 */

import { useObservatoryStore } from "../../../stores/observatory-store";
import type { ObservatoryAnnotationPin } from "../../../types";

// ---------------------------------------------------------------------------
// Section heading style (shared pattern)
// ---------------------------------------------------------------------------

const sectionHeadingStyle: React.CSSProperties = {
  fontSize: 10,
  textTransform: "uppercase",
  letterSpacing: "0.12em",
  color: "var(--hud-text-muted)",
  marginBottom: 8,
  marginTop: 0,
};

const buttonBaseStyle: React.CSSProperties = {
  width: "100%",
  height: 36,
  fontFamily: "inherit",
  fontSize: 12,
  fontWeight: 600,
  border: "none",
  borderRadius: "var(--hud-radius, 8px)",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  cursor: "pointer",
  transition: "opacity 150ms ease",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ReplayDrawerPanel() {
  const replay = useObservatoryStore.use.replay();
  const annotationPins = useObservatoryStore((state) => state.annotationPins);

  const bookmarks = replay.bookmarks ?? [];
  const sortedPins = [...annotationPins].sort((a, b) => a.frameIndex - b.frameIndex);
  const hasSpikeSelected =
    replay.selectedSpikeTimestampMs !== null &&
    replay.selectedSpikeTimestampMs !== undefined;

  function handleRangeChange(e: React.ChangeEvent<HTMLInputElement>) {
    useObservatoryStore
      .getState()
      .actions.setReplayState({ frameIndex: Number(e.target.value) });
  }

  function handleBookmarkClick(frameIndex: number) {
    useObservatoryStore
      .getState()
      .actions.setReplayState({ frameIndex });
  }

  function handleJumpToSpike() {
    useObservatoryStore
      .getState()
      .actions.setReplayState({ frameIndex: 0 });
  }

  function handleCompareToggle() {
    useObservatoryStore
      .getState()
      .actions.setReplayState({ enabled: !replay.enabled });
  }

  // ANNO-05: Jump replay timeline to pin's frame and dispatch camera focus event
  function handlePinClick(pin: ObservatoryAnnotationPin) {
    useObservatoryStore.getState().actions.setReplayState({ frameIndex: pin.frameIndex });
    window.dispatchEvent(
      new CustomEvent("observatory:camera-focus", {
        detail: { target: pin.worldPosition, duration: 0.8 },
      }),
    );
  }

  // ANNO-04: Delete a pin — stop propagation to avoid triggering jump
  function handlePinDelete(e: React.MouseEvent, pinId: string) {
    e.stopPropagation();
    useObservatoryStore.getState().actions.removeAnnotationPin(pinId);
  }

  return (
    <div
      data-testid="replay-drawer-panel"
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 16,
        padding: 0,
        height: "100%",
        overflowY: "auto",
        fontFamily: "inherit",
      }}
    >
      {/* Timeline scrubber section */}
      <div>
        <div style={sectionHeadingStyle}>Timeline</div>
        <input
          type="range"
          min={0}
          max={1000}
          value={Math.min(replay.frameIndex, 1000)}
          onChange={handleRangeChange}
          style={{
            width: "100%",
            accentColor: "var(--hud-accent)",
            cursor: "pointer",
          }}
        />
        <div
          style={{
            fontSize: 11,
            color: "var(--hud-text-muted)",
            textAlign: "right",
            marginTop: 4,
          }}
        >
          Frame {replay.frameIndex}
        </div>
      </div>

      {/* Bookmark list section */}
      <div>
        <div style={sectionHeadingStyle}>Bookmarks</div>
        {bookmarks.length === 0 ? (
          <div
            style={{
              fontSize: 12,
              color: "var(--hud-text-muted)",
              fontStyle: "italic",
            }}
          >
            No bookmarks yet
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column" }}>
            {bookmarks.map((bookmark) => (
              <div
                key={bookmark.id}
                data-testid={`replay-bookmark-${bookmark.id}`}
                onClick={() => handleBookmarkClick(bookmark.frameIndex)}
                style={{
                  padding: "6px 0",
                  borderBottom: "1px solid rgba(255,255,255,0.04)",
                  cursor: "pointer",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "baseline",
                  gap: 8,
                }}
              >
                <span
                  style={{
                    fontSize: 13,
                    color: "var(--hud-text)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    flex: 1,
                  }}
                >
                  {bookmark.label}
                </span>
                <span
                  style={{
                    fontSize: 10,
                    color: "var(--hud-text-muted)",
                    flexShrink: 0,
                  }}
                >
                  {new Date(bookmark.timestampMs).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Annotations section — ANNO-04 */}
      <div>
        <div style={sectionHeadingStyle}>Annotations</div>
        {sortedPins.length === 0 ? (
          <div
            style={{
              fontSize: 12,
              color: "var(--hud-text-muted)",
              fontStyle: "italic",
            }}
          >
            No pins yet
          </div>
        ) : (
          <div
            data-testid="annotation-pin-list"
            style={{ display: "flex", flexDirection: "column", maxHeight: 200, overflowY: "auto" }}
          >
            {sortedPins.map((pin) => (
              <div
                key={pin.id}
                data-testid={`annotation-pin-${pin.id}`}
                onClick={() => handlePinClick(pin)}
                style={{
                  padding: "6px 0",
                  borderBottom: "1px solid rgba(255,255,255,0.04)",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                }}
              >
                {/* Pin icon — small diamond SVG */}
                <svg width="10" height="14" viewBox="0 0 10 14" style={{ flexShrink: 0 }}>
                  <path d="M5 0 L10 7 L5 14 L0 7 Z" fill="var(--hud-accent)" opacity="0.7" />
                </svg>
                <span
                  style={{
                    fontSize: 13,
                    color: "var(--hud-text)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                    flex: 1,
                  }}
                >
                  {pin.note || "Untitled pin"}
                </span>
                <span
                  style={{
                    fontSize: 10,
                    color: "var(--hud-text-muted)",
                    flexShrink: 0,
                  }}
                >
                  F{pin.frameIndex}
                </span>
                <button
                  type="button"
                  data-testid={`annotation-pin-delete-${pin.id}`}
                  onClick={(e) => handlePinDelete(e, pin.id)}
                  style={{
                    background: "none",
                    border: "none",
                    color: "var(--hud-text-muted)",
                    cursor: "pointer",
                    fontSize: 14,
                    lineHeight: 1,
                    padding: "0 2px",
                    flexShrink: 0,
                  }}
                >
                  x
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Spacer */}
      <div style={{ flex: 1 }} />

      {/* Jump-to-spike button */}
      {hasSpikeSelected ? (
        <button
          type="button"
          onClick={handleJumpToSpike}
          style={{
            ...buttonBaseStyle,
            background: "var(--hud-accent)",
            color: "#000",
          }}
        >
          JUMP TO SPIKE
        </button>
      ) : (
        <button
          type="button"
          disabled
          style={{
            ...buttonBaseStyle,
            background: "rgba(255,255,255,0.06)",
            color: "var(--hud-text-muted)",
            opacity: 0.3,
            cursor: "not-allowed",
          }}
        >
          NO SPIKE SELECTED
        </button>
      )}

      {/* Compare toggle */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 8,
        }}
      >
        <span
          style={{
            fontSize: 12,
            color: "var(--hud-text)",
            fontFamily: "inherit",
          }}
        >
          Compare Now vs Then
        </span>
        <button
          type="button"
          data-testid="replay-compare-toggle"
          onClick={handleCompareToggle}
          style={{
            height: 24,
            minWidth: 48,
            padding: "0 10px",
            border: "none",
            borderRadius: 12,
            fontFamily: "inherit",
            fontSize: 11,
            fontWeight: 600,
            cursor: "pointer",
            background: replay.enabled
              ? "var(--hud-accent)"
              : "rgba(255,255,255,0.08)",
            color: replay.enabled ? "#000" : "var(--hud-text-muted)",
            transition: "background 150ms ease, color 150ms ease",
          }}
        >
          {replay.enabled ? "ON" : "OFF"}
        </button>
      </div>
    </div>
  );
}
