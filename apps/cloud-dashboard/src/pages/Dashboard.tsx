import { useCallback, useEffect, useState } from "react";
import { fetchHealth, fetchAuditStats, type HealthResponse, type AuditStats } from "../api/client";
import { useSharedSSE } from "../context/SSEContext";
import type { SSEEvent } from "../hooks/useSSE";

const GLASS_PANEL = {
  background: "rgba(4,8,16,0.94)",
  backdropFilter: "blur(24px)",
  WebkitBackdropFilter: "blur(24px)",
  border: "1px solid rgba(34,211,238,0.12)",
  borderRadius: "12px",
  boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02)",
  position: "relative" as const,
  overflow: "hidden" as const,
};

const NOISE_OVERLAY = (
  <div
    aria-hidden
    style={{
      position: "absolute",
      inset: 0,
      pointerEvents: "none",
      opacity: 0.04,
      backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`,
      backgroundRepeat: "repeat",
      mixBlendMode: "overlay",
    }}
  />
);

const BREATHING_KEYFRAMES = `
@keyframes breathe {
  0%, 100% { box-shadow: 0 0 4px 1px rgba(16,185,129,0.4); }
  50% { box-shadow: 0 0 10px 3px rgba(16,185,129,0.7); }
}
@keyframes breathe-red {
  0%, 100% { box-shadow: 0 0 4px 1px rgba(239,68,68,0.4); }
  50% { box-shadow: 0 0 10px 3px rgba(239,68,68,0.7); }
}
`;

export function Dashboard(_props: { windowId?: string }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [error, setError] = useState<string | null>(null);
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

  const violations = events.filter((e) => e.event_type === "violation");

  return (
    <div className="space-y-6" style={{ color: "#e2e8f0" }}>
      <style>{BREATHING_KEYFRAMES}</style>

      {/* Header */}
      <div className="flex items-center justify-between">
        <h1
          style={{
            fontFamily: "var(--glia-font-display, 'Cinzel', serif)",
            fontSize: "1.75rem",
            fontWeight: 700,
            letterSpacing: "0.05em",
            color: "#fff",
          }}
        >
          Dashboard
        </h1>
        <div className="flex items-center gap-2.5">
          <span
            className="h-2 w-2 rounded-full"
            style={{
              background: connected ? "#10b981" : "#ef4444",
              animation: connected ? "breathe 2.4s ease-in-out infinite" : "breathe-red 1.6s ease-in-out infinite",
            }}
          />
          <span
            style={{
              fontFamily: "var(--glia-font-mono, monospace)",
              fontSize: "0.7rem",
              textTransform: "uppercase",
              letterSpacing: "0.12em",
              color: connected ? "rgba(16,185,129,0.8)" : "rgba(239,68,68,0.8)",
            }}
          >
            {connected ? "SSE Connected" : "Disconnected"}
          </span>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div
          style={{
            ...GLASS_PANEL,
            background: "rgba(239,68,68,0.08)",
            border: "1px solid rgba(239,68,68,0.3)",
            padding: "0.625rem 1rem",
            boxShadow: "inset 0 1px 0 rgba(255,255,255,0.02), 0 0 20px rgba(239,68,68,0.1)",
          }}
        >
          {NOISE_OVERLAY}
          <p
            style={{
              position: "relative",
              fontFamily: "var(--glia-font-mono, monospace)",
              fontSize: "0.8rem",
              color: "#f87171",
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

      {/* Feed panels */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section>
          <h2
            className="mb-3"
            style={{
              fontFamily: "var(--glia-font-mono, monospace)",
              fontSize: "0.75rem",
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.14em",
              color: "rgba(34,211,238,0.7)",
            }}
          >
            Live Feed
          </h2>
          <div
            className="max-h-96 space-y-0.5 overflow-y-auto p-3"
            style={{
              ...GLASS_PANEL,
              scrollbarColor: "rgba(34,211,238,0.2) transparent",
            }}
          >
            {NOISE_OVERLAY}
            {events.length === 0 ? (
              <p
                className="text-sm"
                style={{
                  position: "relative",
                  fontFamily: "var(--glia-font-mono, monospace)",
                  color: "rgba(148,163,184,0.5)",
                  fontSize: "0.75rem",
                  letterSpacing: "0.08em",
                }}
              >
                Waiting for events…
              </p>
            ) : (
              events.slice(0, 50).map((event, i) => <EventRow key={i} event={event} />)
            )}
          </div>
        </section>

        <section>
          <h2
            className="mb-3"
            style={{
              fontFamily: "var(--glia-font-mono, monospace)",
              fontSize: "0.75rem",
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.14em",
              color: "rgba(244,63,94,0.7)",
            }}
          >
            Recent Violations
          </h2>
          <div
            className="max-h-96 space-y-0.5 overflow-y-auto p-3"
            style={{
              ...GLASS_PANEL,
              scrollbarColor: "rgba(244,63,94,0.2) transparent",
            }}
          >
            {NOISE_OVERLAY}
            {violations.length === 0 ? (
              <p
                className="text-sm"
                style={{
                  position: "relative",
                  fontFamily: "var(--glia-font-mono, monospace)",
                  color: "rgba(148,163,184,0.5)",
                  fontSize: "0.75rem",
                  letterSpacing: "0.08em",
                }}
              >
                No violations
              </p>
            ) : (
              violations.slice(0, 20).map((event, i) => <EventRow key={i} event={event} />)
            )}
          </div>
        </section>
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
  const accentColor = highlight ? "rgba(244,63,94,0.25)" : "rgba(34,211,238,0.12)";
  const valueColor = highlight ? "#f43f5e" : "#fff";

  return (
    <div
      className="p-4"
      style={{
        ...GLASS_PANEL,
        border: `1px solid ${accentColor}`,
        boxShadow: highlight
          ? "inset 0 1px 0 rgba(255,255,255,0.02), 0 0 24px rgba(244,63,94,0.08)"
          : GLASS_PANEL.boxShadow,
      }}
    >
      {NOISE_OVERLAY}
      <p
        style={{
          position: "relative",
          fontFamily: "var(--glia-font-mono, monospace)",
          fontSize: "0.65rem",
          textTransform: "uppercase",
          letterSpacing: "0.14em",
          color: "rgba(148,163,184,0.6)",
          marginBottom: "0.375rem",
        }}
      >
        {title}
      </p>
      <p
        style={{
          position: "relative",
          fontSize: "1.625rem",
          fontWeight: 700,
          fontFamily: "var(--glia-font-display, 'Cinzel', serif)",
          color: valueColor,
          textShadow: highlight ? "0 0 16px rgba(244,63,94,0.5)" : undefined,
          lineHeight: 1.2,
        }}
      >
        {String(value)}
      </p>
      {sub && (
        <p
          style={{
            position: "relative",
            fontFamily: "var(--glia-font-mono, monospace)",
            fontSize: "0.65rem",
            color: "rgba(148,163,184,0.4)",
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

function EventRow({ event }: { event: SSEEvent }) {
  const isViolation = event.event_type === "violation" || event.allowed === false;

  return (
    <div
      className="flex items-center gap-2 px-2.5 py-1.5 text-sm"
      style={{
        position: "relative",
        borderRadius: "6px",
        borderLeft: `2px solid ${isViolation ? "rgba(244,63,94,0.5)" : "rgba(34,211,238,0.25)"}`,
        background: isViolation ? "rgba(244,63,94,0.06)" : "transparent",
        transition: "background 0.15s ease",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.background = isViolation ? "rgba(244,63,94,0.1)" : "rgba(34,211,238,0.06)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.background = isViolation ? "rgba(244,63,94,0.06)" : "transparent";
      }}
    >
      <span
        className="h-1.5 w-1.5 flex-shrink-0 rounded-full"
        style={{
          background: isViolation ? "#f43f5e" : "#10b981",
          boxShadow: isViolation
            ? "0 0 6px rgba(244,63,94,0.5)"
            : "0 0 6px rgba(16,185,129,0.4)",
        }}
      />
      <span
        className="flex-shrink-0"
        style={{
          fontFamily: "var(--glia-font-mono, monospace)",
          fontSize: "0.65rem",
          color: "rgba(148,163,184,0.45)",
          letterSpacing: "0.04em",
        }}
      >
        {new Date(event.timestamp).toLocaleTimeString()}
      </span>
      <span
        style={{
          fontFamily: "var(--glia-font-mono, monospace)",
          fontSize: "0.8rem",
          color: isViolation ? "#f87171" : "rgba(34,211,238,0.85)",
          letterSpacing: "0.02em",
        }}
      >
        {event.action_type ?? event.event_type}
      </span>
      <span
        className="truncate"
        style={{
          fontFamily: "var(--glia-font-body, sans-serif)",
          fontSize: "0.8rem",
          color: "rgba(148,163,184,0.4)",
        }}
      >
        {event.target ?? ""}
      </span>
      {event.guard && (
        <span
          className="ml-auto flex-shrink-0"
          style={{
            fontFamily: "var(--glia-font-mono, monospace)",
            fontSize: "0.6rem",
            textTransform: "uppercase",
            letterSpacing: "0.08em",
            color: "rgba(34,211,238,0.6)",
            background: "rgba(34,211,238,0.08)",
            border: "1px solid rgba(34,211,238,0.15)",
            borderRadius: "4px",
            padding: "2px 6px",
          }}
        >
          {event.guard}
        </span>
      )}
      {event.agent_id && (
        <span
          className="flex-shrink-0"
          style={{
            fontFamily: "var(--glia-font-mono, monospace)",
            fontSize: "0.6rem",
            color: "rgba(148,163,184,0.35)",
            letterSpacing: "0.04em",
          }}
        >
          [{event.agent_id.slice(0, 8)}]
        </span>
      )}
    </div>
  );
}

function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}
