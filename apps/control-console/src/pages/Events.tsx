import { useDesktopOS } from "@backbay/glia-desktop";
import { useEffect, useMemo, useRef, useState } from "react";
import { EventBookmarks } from "../components/events/EventBookmarks";
import { EventDetailDrawer } from "../components/events/EventDetailDrawer";
import { NoiseGrain, Stamp } from "../components/ui";
import { useSharedSSE } from "../context/SSEContext";
import type { SSEEvent } from "../hooks/useSSE";

const ROW_HEIGHT_PX = 42;
const ROW_OVERSCAN = 12;

/** Stable bookmark key that survives SSE reconnections (timestamp + type + target + guard). */
function stableEventKey(e: SSEEvent): string {
  return `${e.timestamp}|${e.event_type}|${e.target ?? ""}|${e.guard ?? ""}`;
}

function includesFilterValue(actual: string | undefined, expected: unknown): boolean {
  if (typeof expected !== "string" || !expected.trim()) return true;
  if (!actual) return false;
  return actual.toLowerCase().includes(expected.trim().toLowerCase());
}

export function Events(props: { windowId?: string }) {
  const { processes } = useDesktopOS();
  const {
    events,
    connected,
    paused,
    setPaused,
    maxEvents,
    setMaxEvents,
    droppedEvents,
    clearEvents,
  } = useSharedSSE();
  const [selectedEvent, setSelectedEvent] = useState<SSEEvent | null>(null);
  const [viewportHeight, setViewportHeight] = useState(600);
  const [scrollTop, setScrollTop] = useState(0);
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const drilldownFilters = useMemo(() => {
    if (!props.windowId) return null;
    const instance = processes.getInstanceByWindow(props.windowId);
    const filters = instance?.args?.filters;
    if (!filters || typeof filters !== "object") return null;
    return filters as Record<string, unknown>;
  }, [processes, processes.instances, props.windowId]);

  const filteredEvents = useMemo(() => {
    if (!drilldownFilters) return events;
    return events.filter((event) => {
      const endpointAgentId = event.endpoint_agent_id ?? event.agent_id;
      return (
        includesFilterValue(event.session_id, drilldownFilters.session_id) &&
        includesFilterValue(endpointAgentId, drilldownFilters.endpoint_agent_id) &&
        includesFilterValue(endpointAgentId, drilldownFilters.agent_id) &&
        includesFilterValue(event.runtime_agent_id, drilldownFilters.runtime_agent_id) &&
        includesFilterValue(event.runtime_agent_kind, drilldownFilters.runtime_agent_kind)
      );
    });
  }, [drilldownFilters, events]);

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;

    const handleScroll = () => {
      setScrollTop(viewport.scrollTop);
    };
    const handleResize = () => {
      setViewportHeight(viewport.clientHeight);
    };

    handleResize();
    viewport.addEventListener("scroll", handleScroll, { passive: true });
    window.addEventListener("resize", handleResize);
    return () => {
      viewport.removeEventListener("scroll", handleScroll);
      window.removeEventListener("resize", handleResize);
    };
  }, []);

  const rowWindow = useMemo(() => {
    if (filteredEvents.length === 0) {
      return {
        start: 0,
        end: 0,
        topPad: 0,
        bottomPad: 0,
      };
    }

    const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT_PX) - ROW_OVERSCAN);
    const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT_PX) + ROW_OVERSCAN * 2;
    const end = Math.min(filteredEvents.length, start + visibleCount);
    const topPad = start * ROW_HEIGHT_PX;
    const bottomPad = Math.max(0, (filteredEvents.length - end) * ROW_HEIGHT_PX);
    return { start, end, topPad, bottomPad };
  }, [filteredEvents.length, scrollTop, viewportHeight]);
  const displayed = filteredEvents.slice(rowWindow.start, rowWindow.end);

  return (
    <div
      className="space-y-5"
      style={{ padding: 20, color: "#e2e8f0", overflow: "auto", height: "100%" }}
    >
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
          {filteredEvents.length}
        </span>
        <span className="text-xs" style={{ color: "rgba(154,167,181,0.5)" }}>
          events
        </span>
        <span className="text-xs" style={{ color: "rgba(154,167,181,0.5)" }}>
          buffer {events.length}/{maxEvents}
        </span>
        <span className="text-xs" style={{ color: "rgba(194,59,59,0.65)" }}>
          dropped {droppedEvents}
        </span>
        {drilldownFilters && (
          <span className="font-mono text-xs" style={{ color: "rgba(47,167,160,0.8)" }}>
            filtered
          </span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          className="glass-panel hover-glass-button font-mono rounded-md px-3 py-1.5 text-[11px] uppercase"
          onClick={() => setPaused(!paused)}
          style={{ color: paused ? "#c23b3b" : "#2fa7a0", letterSpacing: "0.08em" }}
        >
          {paused ? "Resume Stream" : "Pause Stream"}
        </button>
        <button
          type="button"
          className="glass-panel hover-glass-button font-mono rounded-md px-3 py-1.5 text-[11px] uppercase"
          onClick={clearEvents}
          style={{ color: "rgba(154,167,181,0.8)", letterSpacing: "0.08em" }}
        >
          Clear Buffer
        </button>
        <label className="font-mono text-[11px]" style={{ color: "rgba(154,167,181,0.8)" }}>
          Max buffer
        </label>
        <select
          className="glass-input font-mono rounded-md px-2 py-1 text-[11px]"
          value={maxEvents}
          onChange={(event) => setMaxEvents(Number(event.target.value))}
          style={{ color: "var(--text)" }}
        >
          {[200, 500, 1000, 2500, 5000].map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </div>

      {/* Glass table panel + drawer wrapper */}
      <div style={{ position: "relative" }}>
        <div className="glass-panel">
          <NoiseGrain />
          <div
            ref={viewportRef}
            className="overflow-auto"
            style={{ position: "relative", zIndex: 2, maxHeight: "62vh" }}
          >
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {[
                    "\u2606",
                    "Type",
                    "Action",
                    "Target",
                    "Guard",
                    "Decision",
                    "Session",
                    "Agent",
                    "Time",
                  ].map((label) => (
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
                  ))}
                </tr>
                <tr>
                  <td colSpan={9} className="p-0">
                    <div
                      style={{
                        height: 1,
                        background:
                          "linear-gradient(90deg, transparent 0%, rgba(27,34,48,0.6) 30%, rgba(27,34,48,0.6) 70%, transparent 100%)",
                      }}
                    />
                  </td>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.length === 0 ? (
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
                  <>
                    {rowWindow.topPad > 0 && (
                      <tr>
                        <td colSpan={9} style={{ height: rowWindow.topPad, padding: 0 }} />
                      </tr>
                    )}
                    {displayed.map((event) => (
                      <EventTableRow
                        key={event._id}
                        event={event}
                        onClick={() => setSelectedEvent(event)}
                      />
                    ))}
                    {rowWindow.bottomPad > 0 && (
                      <tr>
                        <td colSpan={9} style={{ height: rowWindow.bottomPad, padding: 0 }} />
                      </tr>
                    )}
                  </>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <EventDetailDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      </div>

      <div className="flex justify-center">
        <span className="font-mono text-xs" style={{ color: "rgba(214,177,90,0.75)" }}>
          Rendering {displayed.length} / {filteredEvents.length} rows
        </span>
      </div>
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
        height: ROW_HEIGHT_PX,
      }}
      onClick={onClick}
      tabIndex={0}
      role="button"
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onClick();
        }
      }}
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
      <td className="font-mono whitespace-nowrap px-4 py-2.5 text-sm" style={{ color: "#cbd5e1" }}>
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
