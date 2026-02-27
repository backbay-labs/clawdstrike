import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchHealth, fetchAuditStats, type HealthResponse, type AuditStats } from "../api/client";
import { useSharedSSE } from "../context/SSEContext";
import { NoiseGrain } from "../components/ui";
import { DashboardCharts } from "../components/viz/DashboardCharts";
import { EventDetailDrawer } from "../components/events/EventDetailDrawer";
import { formatUptime } from "../utils/format";
import type { SSEEvent } from "../hooks/useSSE";

export function Dashboard(_props: { windowId?: string }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SSEEvent | null>(null);
  const { events, connected } = useSharedSSE();

  const refresh = useCallback(async () => {
    try {
      const [h, s] = await Promise.all([fetchHealth(), fetchAuditStats()]);
      setHealth(h);
      setStats(s);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 10_000);
    return () => clearInterval(interval);
  }, [refresh]);

  const violations = useMemo(
    () => events.filter((e) => e.event_type === "violation"),
    [events],
  );

  return (
    <div className="space-y-6" style={{ padding: 20, color: "#e2e8f0", overflow: "auto", height: "100%" }}>
      {/* SSE status bar */}
      <div className="flex items-center gap-2.5">
        <span
          className="h-2 w-2 rounded-full"
          style={{
            background: connected ? "#2fa7a0" : "#c23b3b",
            animation: connected ? "breathe-teal 2.4s ease-in-out infinite" : "breathe-crimson 1.6s ease-in-out infinite",
          }}
        />
        <span
          className="font-mono"
          style={{
            fontSize: "0.7rem",
            textTransform: "uppercase",
            letterSpacing: "0.12em",
            color: connected ? "rgba(154,167,181,0.7)" : "rgba(194,59,59,0.8)",
          }}
        >
          {connected ? "SSE Connected" : "Disconnected"}
        </span>
      </div>

      {/* Error banner */}
      {error && (
        <div
          className="glass-panel"
          style={{
            background: "rgba(194,59,59,0.08)",
            border: "1px solid rgba(194,59,59,0.3)",
            padding: "0.625rem 1rem",
            boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02), 0 0 20px rgba(194,59,59,0.1)",
          }}
        >
          <NoiseGrain />
          <p
            className="font-mono"
            style={{
              position: "relative",
              fontSize: "0.8rem",
              color: "#c23b3b",
              letterSpacing: "0.04em",
            }}
          >
            {error}
          </p>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card title="Status" value={health?.status ?? "..."} sub={health?.version} />
        <Card title="Uptime" value={stats ? formatUptime(stats.uptime_secs) : "..."} />
        <Card title="Total Events" value={stats?.total_events ?? "..."} />
        <Card
          title="Violations"
          value={stats?.violations ?? "..."}
          highlight={!!stats && stats.violations > 0}
        />
      </div>

      {/* Data visualization charts */}
      <DashboardCharts events={events} />

      {/* Feed panels + drawer */}
      <div style={{ position: "relative" }}>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <section>
            <h2
              className="font-mono mb-3"
              style={{
                fontSize: "0.75rem",
                fontWeight: 600,
                textTransform: "uppercase",
                letterSpacing: "0.14em",
                color: "rgba(214,177,90,0.7)",
              }}
            >
              Live Feed
            </h2>
            <div
              className="glass-panel max-h-96 space-y-0.5 overflow-y-auto p-3"
              style={{ scrollbarColor: "rgba(214,177,90,0.15) transparent" }}
            >
              <NoiseGrain />
              {events.length === 0 ? (
                <p
                  className="font-mono text-sm"
                  style={{
                    position: "relative",
                    color: "rgba(154,167,181,0.5)",
                    fontSize: "0.75rem",
                    letterSpacing: "0.08em",
                  }}
                >
                  Waiting for events…
                </p>
              ) : (
                events.slice(0, 50).map((event) => (
                  <EventRow key={event._id} event={event} onClick={() => setSelectedEvent(event)} />
                ))
              )}
            </div>
          </section>

          <section>
            <h2
              className="font-mono mb-3"
              style={{
                fontSize: "0.75rem",
                fontWeight: 600,
                textTransform: "uppercase",
                letterSpacing: "0.14em",
                color: "rgba(214,177,90,0.7)",
              }}
            >
              Recent Violations
            </h2>
            <div
              className="glass-panel max-h-96 space-y-0.5 overflow-y-auto p-3"
              style={{ scrollbarColor: "rgba(214,177,90,0.15) transparent" }}
            >
              <NoiseGrain />
              {violations.length === 0 ? (
                <p
                  className="font-mono text-sm"
                  style={{
                    position: "relative",
                    color: "rgba(154,167,181,0.5)",
                    fontSize: "0.75rem",
                    letterSpacing: "0.08em",
                  }}
                >
                  No violations
                </p>
              ) : (
                violations.slice(0, 20).map((event) => (
                  <EventRow key={event._id} event={event} onClick={() => setSelectedEvent(event)} />
                ))
              )}
            </div>
          </section>
        </div>

        <EventDetailDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      </div>
    </div>
  );
}

function Card({
  title,
  value,
  sub,
  highlight,
}: {
  title: string;
  value: string | number;
  sub?: string;
  highlight?: boolean;
}) {
  const accentColor = highlight ? "rgba(194,59,59,0.25)" : "rgba(27,34,48,0.8)";
  const valueColor = highlight ? "#c23b3b" : "#fff";

  return (
    <div
      className="glass-panel p-4"
      style={{
        border: `1px solid ${accentColor}`,
        boxShadow: highlight
          ? "inset 0 1px 0 rgba(255,255,255,0.02), 0 0 24px rgba(194,59,59,0.08)"
          : undefined,
      }}
    >
      <NoiseGrain />
      <p
        className="font-mono"
        style={{
          position: "relative",
          fontSize: "0.65rem",
          textTransform: "uppercase",
          letterSpacing: "0.14em",
          color: "rgba(154,167,181,0.6)",
          marginBottom: "0.375rem",
        }}
      >
        {title}
      </p>
      <p
        className="font-display"
        style={{
          position: "relative",
          fontSize: "1.625rem",
          fontWeight: 700,
          color: valueColor,
          textShadow: highlight ? "0 0 16px rgba(194,59,59,0.5)" : undefined,
          lineHeight: 1.2,
        }}
      >
        {String(value)}
      </p>
      {sub && (
        <p
          className="font-mono"
          style={{
            position: "relative",
            fontSize: "0.65rem",
            color: "rgba(154,167,181,0.4)",
            marginTop: "0.25rem",
            letterSpacing: "0.06em",
          }}
        >
          {sub}
        </p>
      )}
    </div>
  );
}

function EventRow({ event, onClick }: { event: SSEEvent; onClick?: () => void }) {
  const isViolation = event.event_type === "violation" || event.allowed === false;

  return (
    <div
      className={`flex items-center gap-2 px-2.5 py-1.5 text-sm ${isViolation ? "hover-row-violation" : "hover-row"}`}
      style={{
        position: "relative",
        borderRadius: "6px",
        borderLeft: `2px solid ${isViolation ? "rgba(194,59,59,0.5)" : "rgba(27,34,48,0.6)"}`,
        cursor: onClick ? "pointer" : undefined,
      }}
      onClick={onClick}
      tabIndex={onClick ? 0 : undefined}
      role={onClick ? "button" : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onClick(); } } : undefined}
    >
      <span
        className="h-1.5 w-1.5 flex-shrink-0 rounded-full"
        style={{
          background: isViolation ? "#c23b3b" : "var(--gold)",
          boxShadow: isViolation
            ? "0 0 6px rgba(194,59,59,0.5)"
            : "0 0 4px rgba(214,177,90,0.3)",
        }}
      />
      <span
        className="font-mono flex-shrink-0"
        style={{
          fontSize: "0.65rem",
          color: "rgba(154,167,181,0.45)",
          letterSpacing: "0.04em",
        }}
      >
        {new Date(event.timestamp).toLocaleTimeString()}
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: "0.8rem",
          color: isViolation ? "var(--crimson)" : "var(--text)",
          letterSpacing: "0.02em",
        }}
      >
        {event.action_type ?? event.event_type}
      </span>
      <span
        className="font-body truncate"
        style={{
          fontSize: "0.8rem",
          color: "rgba(154,167,181,0.4)",
        }}
      >
        {event.target ?? ""}
      </span>
      {event.guard && (
        <span
          className="font-mono ml-auto flex-shrink-0"
          style={{
            fontSize: "0.6rem",
            textTransform: "uppercase",
            letterSpacing: "0.08em",
            color: "rgba(214,177,90,0.6)",
            background: "rgba(214,177,90,0.08)",
            border: "1px solid rgba(214,177,90,0.15)",
            borderRadius: "4px",
            padding: "2px 6px",
          }}
        >
          {event.guard}
        </span>
      )}
      {event.agent_id && (
        <span
          className="font-mono flex-shrink-0"
          style={{
            fontSize: "0.6rem",
            color: "rgba(154,167,181,0.35)",
            letterSpacing: "0.04em",
          }}
        >
          [{event.agent_id.slice(0, 8)}]
        </span>
      )}
    </div>
  );
}
