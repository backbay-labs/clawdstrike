import { useState } from "react";
import { useSharedSSE } from "../context/SSEContext";
import { NoiseGrain } from "../components/ui";
import type { SSEEvent } from "../hooks/useSSE";

const DISPLAY_LIMIT = 100;

export function Events(_props: { windowId?: string }) {
  const { events, connected } = useSharedSSE();
  const [showAll, setShowAll] = useState(false);

  const displayed = showAll ? events : events.slice(0, DISPLAY_LIMIT);
  const hasMore = !showAll && events.length > DISPLAY_LIMIT;

  return (
    <div className="space-y-5" style={{ color: "#e2e8f0" }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1
          className="font-display text-2xl font-bold tracking-wide"
          style={{ color: "#f0f4f8" }}
        >
          Event Stream
        </h1>
        <div className="flex items-center gap-3">
          <span
            className="inline-block h-2 w-2 rounded-full"
            style={{
              backgroundColor: connected ? "#10b981" : "#ef4444",
              color: connected ? "#10b981" : "#ef4444",
              animation: "sseBreathingPulse 2s ease-in-out infinite",
            }}
          />
          <span
            className="font-mono text-xs uppercase"
            style={{
              letterSpacing: "0.1em",
              color: "rgba(148,163,184,0.8)",
            }}
          >
            {connected ? "Connected" : "Disconnected"}
          </span>
          <span
            className="font-mono text-xs"
            style={{
              letterSpacing: "0.08em",
              color: "#22d3ee",
            }}
          >
            {events.length}
          </span>
          <span className="text-xs" style={{ color: "rgba(148,163,184,0.5)" }}>
            events
          </span>
        </div>
      </div>

      {/* Glass table panel */}
      <div className="glass-panel">
        <NoiseGrain />
        <div className="overflow-x-auto" style={{ position: "relative", zIndex: 2 }}>
          <table className="w-full text-left text-sm">
            <thead>
              <tr>
                {["Type", "Action", "Target", "Guard", "Decision", "Session", "Agent", "Time"].map(
                  (label) => (
                    <th
                      key={label}
                      className="font-mono px-4 py-3 text-[11px]"
                      style={{
                        textTransform: "uppercase",
                        letterSpacing: "0.12em",
                        color: "rgba(148,163,184,0.6)",
                        fontWeight: 500,
                      }}
                    >
                      {label}
                    </th>
                  ),
                )}
              </tr>
              <tr>
                <td colSpan={8} className="p-0">
                  <div
                    style={{
                      height: 1,
                      background: "linear-gradient(90deg, transparent 0%, rgba(34,211,238,0.25) 30%, rgba(34,211,238,0.25) 70%, transparent 100%)",
                    }}
                  />
                </td>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td
                    colSpan={8}
                    className="font-mono px-4 py-12 text-center text-sm"
                    style={{
                      color: "rgba(148,163,184,0.35)",
                      letterSpacing: "0.05em",
                    }}
                  >
                    Waiting for events…
                  </td>
                </tr>
              ) : (
                displayed.map((event) => <EventTableRow key={event._id} event={event} />)
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Show more */}
      {hasMore && (
        <div className="flex justify-center">
          <button
            type="button"
            onClick={() => setShowAll(true)}
            className="glass-panel hover-glass-button font-mono rounded-md px-5 py-2 text-xs uppercase"
            style={{
              color: "#22d3ee",
              letterSpacing: "0.08em",
              cursor: "pointer",
            }}
          >
            Show all {events.length} events
          </button>
        </div>
      )}
    </div>
  );
}

function EventTableRow({ event }: { event: SSEEvent }) {
  const isViolation = event.event_type === "violation" || event.allowed === false;

  return (
    <tr
      className={isViolation ? "hover-row-violation" : "hover-row"}
      style={{
        borderLeft: isViolation ? "2px solid rgba(239,68,68,0.3)" : "2px solid transparent",
      }}
    >
      {/* Type badge */}
      <td className="whitespace-nowrap px-4 py-2.5">
        <span
          className="font-mono inline-block rounded px-2 py-0.5 text-[11px] font-medium"
          style={
            isViolation
              ? {
                  background: "rgba(239,68,68,0.12)",
                  border: "1px solid rgba(239,68,68,0.25)",
                  color: "#fca5a5",
                  boxShadow: "0 0 8px rgba(239,68,68,0.15)",
                  letterSpacing: "0.05em",
                }
              : {
                  background: "rgba(34,211,238,0.08)",
                  border: "1px solid rgba(34,211,238,0.2)",
                  color: "#67e8f9",
                  letterSpacing: "0.05em",
                }
          }
        >
          {event.event_type}
        </span>
      </td>

      {/* Action */}
      <td
        className="font-mono whitespace-nowrap px-4 py-2.5 text-sm"
        style={{ color: "#cbd5e1" }}
      >
        {event.action_type ?? "-"}
      </td>

      {/* Target */}
      <td
        className="max-w-xs truncate px-4 py-2.5 text-sm"
        style={{ color: "rgba(148,163,184,0.7)" }}
      >
        {event.target ?? "-"}
      </td>

      {/* Guard */}
      <td className="whitespace-nowrap px-4 py-2.5 text-sm" style={{ color: "#cbd5e1" }}>
        {event.guard ?? "-"}
      </td>

      {/* Decision */}
      <td className="whitespace-nowrap px-4 py-2.5 text-sm">
        {event.allowed === false ? (
          <span
            className="font-mono"
            style={{
              color: "#ef4444",
              textShadow: "0 0 6px rgba(239,68,68,0.4)",
              fontWeight: 600,
              letterSpacing: "0.05em",
            }}
          >
            blocked
          </span>
        ) : event.allowed === true ? (
          <span
            className="font-mono"
            style={{
              color: "#10b981",
              fontWeight: 500,
              letterSpacing: "0.05em",
            }}
          >
            allowed
          </span>
        ) : (
          <span style={{ color: "rgba(148,163,184,0.3)" }}>-</span>
        )}
      </td>

      {/* Session */}
      <td
        className="font-mono whitespace-nowrap px-4 py-2.5 text-xs"
        style={{ color: "rgba(148,163,184,0.45)" }}
      >
        {event.session_id ? event.session_id.slice(0, 12) : "-"}
      </td>

      {/* Agent */}
      <td
        className="font-mono whitespace-nowrap px-4 py-2.5 text-xs"
        style={{ color: "rgba(148,163,184,0.45)" }}
      >
        {event.agent_id ? event.agent_id.slice(0, 12) : "-"}
      </td>

      {/* Time */}
      <td
        className="font-mono whitespace-nowrap px-4 py-2.5 text-xs"
        style={{ color: "rgba(148,163,184,0.45)" }}
      >
        {new Date(event.timestamp).toLocaleTimeString()}
      </td>
    </tr>
  );
}
