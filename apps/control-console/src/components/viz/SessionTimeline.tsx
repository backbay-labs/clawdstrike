import { useMemo, useState } from "react";
import type { SSEEvent } from "../../hooks/useSSE";

function dotColor(event: SSEEvent): string {
  if (event.allowed === true) return "var(--stamp-allowed)";
  if (event.allowed === false) return "var(--stamp-blocked)";
  return "var(--gold)";
}

export function SessionTimeline({ events, sessionId }: { events: SSEEvent[]; sessionId?: string }) {
  const filtered = useMemo(
    () => (sessionId ? events.filter((e) => e.session_id === sessionId) : events).slice().reverse(),
    [events, sessionId],
  );
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  if (filtered.length === 0) {
    return (
      <div
        className="glass-panel font-mono"
        style={{ padding: "12px 16px", fontSize: 11, color: "rgba(154,167,181,0.4)" }}
      >
        No session events
      </div>
    );
  }

  return (
    <div className="glass-panel" style={{ padding: "12px 16px", overflowX: "auto" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 2,
          minWidth: filtered.length * 20,
          position: "relative",
        }}
      >
        {filtered.map((event, i) => (
          <div
            key={event._id}
            style={{ display: "flex", alignItems: "center" }}
            onMouseEnter={() => setHoveredIdx(i)}
            onMouseLeave={() => setHoveredIdx(null)}
          >
            {i > 0 && <div style={{ width: 8, height: 1, background: "var(--slate)" }} />}
            <div
              style={{
                width: 12,
                height: 12,
                borderRadius: "50%",
                background: dotColor(event),
                cursor: "pointer",
                position: "relative",
                boxShadow: `0 0 4px ${dotColor(event)}`,
              }}
            >
              {hoveredIdx === i && (
                <div
                  className="glass-panel font-mono"
                  style={{
                    position: "absolute",
                    bottom: "calc(100% + 6px)",
                    left: "50%",
                    transform: "translateX(-50%)",
                    padding: "6px 8px",
                    fontSize: 10,
                    whiteSpace: "nowrap",
                    zIndex: 10,
                    color: "var(--text)",
                    pointerEvents: "none",
                  }}
                >
                  <div>{new Date(event.timestamp).toLocaleTimeString()}</div>
                  <div style={{ color: "var(--muted)" }}>
                    {event.action_type ?? event.event_type}
                  </div>
                  {event.guard && <div style={{ color: "var(--gold)" }}>{event.guard}</div>}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
