import { useState } from "react";
import { useSharedSSE } from "../context/SSEContext";
import { NoiseGrain, Stamp } from "../components/ui";
import { EventDetailDrawer } from "../components/events/EventDetailDrawer";
import { EventBookmarks } from "../components/events/EventBookmarks";
import type { SSEEvent } from "../hooks/useSSE";

const DISPLAY_LIMIT = 100;

/** Stable bookmark key that survives SSE reconnections (timestamp + type + target + guard). */
function stableEventKey(e: SSEEvent): string {
  return `${e.timestamp}|${e.event_type}|${e.target ?? ""}|${e.guard ?? ""}`;
}

export function Events(_props: { windowId?: string }) {
  const { events, connected } = useSharedSSE();
  const [showAll, setShowAll] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<SSEEvent | null>(null);

  const displayed = showAll ? events : events.slice(0, DISPLAY_LIMIT);
  const hasMore = !showAll && events.length > DISPLAY_LIMIT;

  return (
    <div className="space-y-5" style={{ padding: 20, color: "#e2e8f0", overflow: "auto", height: "100%" }}>
      {/* Status bar */}
      <div className="flex items-center gap-3">
        <span
          className="inline-block h-2 w-2 rounded-full"
          style={{
            backgroundColor: connected ? "#2fa7a0" : "#c23b3b",
            color: connected ? "#2fa7a0" : "#c23b3b",
            animation: "sseBreathingPulse 2s ease-in-out infinite",
          }}
        />
        <span
          className="font-mono text-xs uppercase"
          style={{
            letterSpacing: "0.1em",
            color: "rgba(154,167,181,0.8)",
          }}
        >
          {connected ? "Connected" : "Disconnected"}
        </span>
        <span
          className="font-mono text-xs"
          style={{
            letterSpacing: "0.08em",
            color: "#d6b15a",
          }}
        >
          {events.length}
        </span>
        <span className="text-xs" style={{ color: "rgba(154,167,181,0.5)" }}>
          events
        </span>
      </div>

      {/* Glass table panel + drawer wrapper */}
      <div style={{ position: "relative" }}>
        <div className="glass-panel">
          <NoiseGrain />
          <div className="overflow-x-auto" style={{ position: "relative", zIndex: 2 }}>
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {["\u2606", "Type", "Action", "Target", "Guard", "Decision", "Session", "Agent", "Time"].map(
                    (label) => (
                      <th
                        key={label}
                        className="font-mono px-4 py-3 text-[11px]"
                        style={{
                          textTransform: "uppercase",
                          letterSpacing: "0.12em",
                          color: "rgba(154,167,181,0.6)",
                          fontWeight: 500,
                          width: label === "\u2606" ? "40px" : undefined,
                        }}
                      >
                        {label}
                      </th>
                    ),
                  )}
                </tr>
                <tr>
                  <td colSpan={9} className="p-0">
                    <div
                      style={{
                        height: 1,
                        background: "linear-gradient(90deg, transparent 0%, rgba(27,34,48,0.6) 30%, rgba(27,34,48,0.6) 70%, transparent 100%)",
                      }}
                    />
                  </td>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td
                      colSpan={9}
                      className="font-mono px-4 py-12 text-center text-sm"
                      style={{
                        color: "rgba(154,167,181,0.35)",
                        letterSpacing: "0.05em",
                      }}
                    >
                      Waiting for events…
                    </td>
                  </tr>
                ) : (
                  displayed.map((event) => (
                    <EventTableRow
                      key={event._id}
                      event={event}
                      onClick={() => setSelectedEvent(event)}
                    />
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <EventDetailDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      </div>

      {/* Show more */}
      {hasMore && (
        <div className="flex justify-center">
          <button
            type="button"
            onClick={() => setShowAll(true)}
            className="glass-panel hover-glass-button font-mono rounded-md px-5 py-2 text-xs uppercase"
            style={{
              color: "#d6b15a",
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

function EventTableRow({ event, onClick }: { event: SSEEvent; onClick: () => void }) {
  const isViolation = event.event_type === "violation" || event.allowed === false;

  return (
    <tr
      className={isViolation ? "hover-row-violation" : "hover-row"}
      style={{
        borderLeft: isViolation ? "2px solid rgba(194,59,59,0.3)" : "2px solid transparent",
        cursor: "pointer",
      }}
      onClick={onClick}
      tabIndex={0}
      role="button"
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(); } }}
    >
      {/* Bookmark */}
      <td className="whitespace-nowrap px-4 py-2.5" style={{ width: "40px" }}>
        <EventBookmarks eventId={stableEventKey(event)} />
      </td>

      {/* Type badge */}
      <td className="whitespace-nowrap px-4 py-2.5">
        <span
          className="font-mono inline-block rounded px-2 py-0.5 text-[11px] font-medium"
          style={
            isViolation
              ? {
                  background: "rgba(194,59,59,0.12)",
                  border: "1px solid rgba(194,59,59,0.25)",
                  color: "#c23b3b",
                  letterSpacing: "0.05em",
                }
              : {
                  background: "rgba(214,177,90,0.08)",
                  border: "1px solid rgba(214,177,90,0.2)",
                  color: "#d6b15a",
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
        style={{ color: "rgba(154,167,181,0.7)" }}
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
          <Stamp variant="blocked">BLOCKED</Stamp>
        ) : event.allowed === true ? (
          <Stamp variant="allowed">ALLOWED</Stamp>
        ) : (
          <span style={{ color: "rgba(154,167,181,0.3)" }}>-</span>
        )}
      </td>

      {/* Session */}
      <td
        className="font-mono whitespace-nowrap px-4 py-2.5 text-xs"
        style={{ color: "rgba(154,167,181,0.45)" }}
      >
        {event.session_id ? event.session_id.slice(0, 12) : "-"}
      </td>

      {/* Agent */}
      <td
        className="font-mono whitespace-nowrap px-4 py-2.5 text-xs"
        style={{ color: "rgba(154,167,181,0.45)" }}
      >
        {event.agent_id ? event.agent_id.slice(0, 12) : "-"}
      </td>

      {/* Time */}
      <td
        className="font-mono whitespace-nowrap px-4 py-2.5 text-xs"
        style={{ color: "rgba(154,167,181,0.45)" }}
      >
        {new Date(event.timestamp).toLocaleTimeString()}
      </td>
    </tr>
  );
}
