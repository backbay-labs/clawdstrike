import { useSharedSSE } from "../context/SSEContext";
import type { SSEEvent } from "../hooks/useSSE";

const NOISE_SVG = `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`;

const glassPanel: React.CSSProperties = {
  background: "rgba(4,8,16,0.94)",
  border: "1px solid rgba(34,211,238,0.12)",
  backdropFilter: "blur(24px)",
  WebkitBackdropFilter: "blur(24px)",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02)",
  borderRadius: 12,
  position: "relative",
  overflow: "hidden",
};

const noiseOverlay: React.CSSProperties = {
  position: "absolute",
  inset: 0,
  backgroundImage: NOISE_SVG,
  backgroundRepeat: "repeat",
  opacity: 0.04,
  pointerEvents: "none",
  zIndex: 1,
};

const gradientBorder: React.CSSProperties = {
  height: 1,
  background: "linear-gradient(90deg, transparent 0%, rgba(34,211,238,0.25) 30%, rgba(34,211,238,0.25) 70%, transparent 100%)",
};

const pulseKeyframes = `
@keyframes sseBreathingPulse {
  0%, 100% { box-shadow: 0 0 4px 1px currentColor; opacity: 1; }
  50% { box-shadow: 0 0 10px 3px currentColor; opacity: 0.7; }
}
`;

export function Events(_props: { windowId?: string }) {
  const { events, connected } = useSharedSSE();

  return (
    <div className="space-y-5" style={{ color: "#e2e8f0" }}>
      <style>{pulseKeyframes}</style>

      {/* Header */}
      <div className="flex items-center justify-between">
        <h1
          className="text-2xl font-bold tracking-wide"
          style={{ fontFamily: "var(--glia-font-display, 'Cinzel', serif)", color: "#f0f4f8" }}
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
            className="text-xs uppercase"
            style={{
              fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
              letterSpacing: "0.1em",
              color: "rgba(148,163,184,0.8)",
            }}
          >
            {connected ? "Connected" : "Disconnected"}
          </span>
          <span
            className="text-xs"
            style={{
              fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
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
      <div style={glassPanel}>
        <div style={noiseOverlay} />
        <div className="overflow-x-auto" style={{ position: "relative", zIndex: 2 }}>
          <table className="w-full text-left text-sm">
            <thead>
              <tr>
                {["Type", "Action", "Target", "Guard", "Decision", "Session", "Agent", "Time"].map(
                  (label) => (
                    <th
                      key={label}
                      className="px-4 py-3 text-[11px]"
                      style={{
                        fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
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
                  <div style={gradientBorder} />
                </td>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td
                    colSpan={8}
                    className="px-4 py-12 text-center text-sm"
                    style={{
                      fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
                      color: "rgba(148,163,184,0.35)",
                      letterSpacing: "0.05em",
                    }}
                  >
                    Waiting for events…
                  </td>
                </tr>
              ) : (
                events.map((event, i) => <EventTableRow key={i} event={event} />)
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function EventTableRow({ event }: { event: SSEEvent }) {
  const isViolation = event.event_type === "violation" || event.allowed === false;

  const rowStyle: React.CSSProperties = isViolation
    ? {
        background: "rgba(239,68,68,0.04)",
        borderLeft: "2px solid rgba(239,68,68,0.3)",
      }
    : {
        borderLeft: "2px solid transparent",
      };

  return (
    <tr
      className="transition-colors duration-150"
      style={rowStyle}
      onMouseEnter={(e) => {
        (e.currentTarget as HTMLElement).style.background = isViolation
          ? "rgba(239,68,68,0.07)"
          : "rgba(34,211,238,0.04)";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLElement).style.background = isViolation
          ? "rgba(239,68,68,0.04)"
          : "transparent";
      }}
    >
      {/* Type badge */}
      <td className="whitespace-nowrap px-4 py-2.5">
        <span
          className="inline-block rounded px-2 py-0.5 text-[11px] font-medium"
          style={
            isViolation
              ? {
                  background: "rgba(239,68,68,0.12)",
                  border: "1px solid rgba(239,68,68,0.25)",
                  color: "#fca5a5",
                  boxShadow: "0 0 8px rgba(239,68,68,0.15)",
                  fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
                  letterSpacing: "0.05em",
                }
              : {
                  background: "rgba(34,211,238,0.08)",
                  border: "1px solid rgba(34,211,238,0.2)",
                  color: "#67e8f9",
                  fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
                  letterSpacing: "0.05em",
                }
          }
        >
          {event.event_type}
        </span>
      </td>

      {/* Action */}
      <td
        className="whitespace-nowrap px-4 py-2.5 text-sm"
        style={{
          fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
          color: "#cbd5e1",
        }}
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
            style={{
              color: "#ef4444",
              textShadow: "0 0 6px rgba(239,68,68,0.4)",
              fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
              fontWeight: 600,
              letterSpacing: "0.05em",
            }}
          >
            blocked
          </span>
        ) : event.allowed === true ? (
          <span
            style={{
              color: "#10b981",
              fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
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
        className="whitespace-nowrap px-4 py-2.5 text-xs"
        style={{
          fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
          color: "rgba(148,163,184,0.45)",
        }}
      >
        {event.session_id ? event.session_id.slice(0, 12) : "-"}
      </td>

      {/* Agent */}
      <td
        className="whitespace-nowrap px-4 py-2.5 text-xs"
        style={{
          fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
          color: "rgba(148,163,184,0.45)",
        }}
      >
        {event.agent_id ? event.agent_id.slice(0, 12) : "-"}
      </td>

      {/* Time */}
      <td
        className="whitespace-nowrap px-4 py-2.5 text-xs"
        style={{
          fontFamily: "var(--glia-font-mono, 'JetBrains Mono', monospace)",
          color: "rgba(148,163,184,0.45)",
        }}
      >
        {new Date(event.timestamp).toLocaleTimeString()}
      </td>
    </tr>
  );
}
