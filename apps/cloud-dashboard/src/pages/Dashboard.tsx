import { useCallback, useEffect, useState } from "react";
import { fetchHealth, fetchAuditStats, type HealthResponse, type AuditStats } from "../api/client";
import { useSharedSSE } from "../context/SSEContext";
import type { SSEEvent } from "../hooks/useSSE";

export function Dashboard() {
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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${connected ? "bg-green-500" : "bg-red-500"}`} />
          <span className="text-sm text-gray-400">{connected ? "SSE Connected" : "Disconnected"}</span>
        </div>
      </div>

      {error && <p className="rounded bg-red-900/50 px-4 py-2 text-red-300">{error}</p>}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card title="Status" value={health?.status ?? "..."} sub={health?.version} />
        <Card
          title="Uptime"
          value={stats ? formatUptime(stats.uptime_secs) : "..."}
        />
        <Card title="Total Events" value={stats?.total_events ?? "..."} />
        <Card
          title="Violations"
          value={stats?.violations ?? "..."}
          highlight={!!stats && stats.violations > 0}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section>
          <h2 className="mb-3 text-lg font-semibold">Live Feed</h2>
          <div className="max-h-96 space-y-1 overflow-y-auto rounded-lg border border-gray-800 bg-gray-900 p-3">
            {events.length === 0 ? (
              <p className="text-sm text-gray-500">Waiting for events...</p>
            ) : (
              events.slice(0, 50).map((event, i) => (
                <EventRow key={i} event={event} />
              ))
            )}
          </div>
        </section>

        <section>
          <h2 className="mb-3 text-lg font-semibold">Recent Violations</h2>
          <div className="max-h-96 space-y-1 overflow-y-auto rounded-lg border border-gray-800 bg-gray-900 p-3">
            {violations.length === 0 ? (
              <p className="text-sm text-gray-500">No violations</p>
            ) : (
              violations.slice(0, 20).map((event, i) => (
                <EventRow key={i} event={event} />
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

function Card({ title, value, sub, highlight }: { title: string; value: string | number; sub?: string; highlight?: boolean }) {
  return (
    <div className={`rounded-lg border p-4 ${highlight ? "border-red-700 bg-red-950/30" : "border-gray-800 bg-gray-900"}`}>
      <p className="text-sm text-gray-400">{title}</p>
      <p className={`mt-1 text-2xl font-bold ${highlight ? "text-red-400" : "text-white"}`}>{String(value)}</p>
      {sub && <p className="mt-0.5 text-xs text-gray-500">{sub}</p>}
    </div>
  );
}

function EventRow({ event }: { event: SSEEvent }) {
  const isViolation = event.event_type === "violation" || event.allowed === false;
  return (
    <div className={`flex items-center gap-2 rounded px-2 py-1 text-sm ${isViolation ? "bg-red-950/30 text-red-300" : "text-gray-300"}`}>
      <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${isViolation ? "bg-red-500" : "bg-green-500"}`} />
      <span className="flex-shrink-0 text-xs text-gray-500">{new Date(event.timestamp).toLocaleTimeString()}</span>
      <span className="font-mono">{event.action_type ?? event.event_type}</span>
      <span className="truncate text-gray-500">{event.target ?? ""}</span>
      {event.guard && <span className="ml-auto flex-shrink-0 rounded bg-gray-800 px-1.5 py-0.5 text-xs">{event.guard}</span>}
      {event.agent_id && <span className="flex-shrink-0 text-xs text-gray-500">[{event.agent_id.slice(0, 8)}]</span>}
    </div>
  );
}

function formatUptime(secs: number): string {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}
