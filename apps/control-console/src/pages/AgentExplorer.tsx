import { useDesktopOS } from "@backbay/glia-desktop";
import { useEffect, useMemo, useState } from "react";
import { type AgentStatusResponse, fetchAgentStatus } from "../api/client";
import { AgentSessionCard } from "../components/agents/AgentSessionCard";
import { NoiseGrain, Stamp } from "../components/ui";
import { useSharedSSE } from "../context/SSEContext";
import { useAgentSessions, type RuntimeAgentInfo } from "../hooks/useAgentSessions";
import type { SSEEvent } from "../hooks/useSSE";

type ExplorerView = "endpoints" | "runtime-agents";
type PostureFilter = "all" | "nominal" | "elevated" | "critical";
type ActivityFilter = "all" | "active" | "inactive";
type ViolationFilter = "all" | "with-violations" | "critical-only";
type LastSeenFilter = "all" | "15m" | "1h" | "24h";

function withinLastSeenWindow(timestamp: string, filter: LastSeenFilter): boolean {
  if (filter === "all") return true;
  const now = Date.now();
  const at = new Date(timestamp).getTime();
  if (Number.isNaN(at)) return false;
  const elapsedMs = now - at;
  const windowMs =
    filter === "15m"
      ? 15 * 60_000
      : filter === "1h"
        ? 60 * 60_000
        : 24 * 60 * 60_000;
  return elapsedMs <= windowMs;
}

function runtimeDecisionStamp(runtime: RuntimeAgentInfo) {
  if (runtime.posture === "critical") return <Stamp variant="blocked">CRITICAL</Stamp>;
  if (runtime.posture === "elevated") return <Stamp variant="warn">ELEVATED</Stamp>;
  return <Stamp variant="allowed">NOMINAL</Stamp>;
}

export function AgentExplorer(_props: { windowId?: string }) {
  const { processes } = useDesktopOS();
  const { events, connected } = useSharedSSE();
  const endpoints = useAgentSessions(events);
  const [view, setView] = useState<ExplorerView>("endpoints");
  const [search, setSearch] = useState("");
  const [postureFilter, setPostureFilter] = useState<PostureFilter>("all");
  const [activityFilter, setActivityFilter] = useState<ActivityFilter>("all");
  const [violationFilter, setViolationFilter] = useState<ViolationFilter>("all");
  const [lastSeenFilter, setLastSeenFilter] = useState<LastSeenFilter>("all");
  const [selectedSession, setSelectedSession] = useState<{
    sessionId: string;
    label: string;
    events: SSEEvent[];
  } | null>(null);
  const [liveness, setLiveness] = useState<AgentStatusResponse | null>(null);

  const runtimeAgents = useMemo(
    () => endpoints.flatMap((endpoint) => endpoint.runtimeAgents),
    [endpoints],
  );

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const next = await fetchAgentStatus({ include_stale: true, limit: 1000 });
        if (!cancelled) setLiveness(next);
      } catch {
        if (!cancelled) setLiveness(null);
      }
    };
    void load();
    const timer = window.setInterval(load, 20_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const runtimeLiveness = useMemo(
    () => new Map((liveness?.runtimes ?? []).map((status) => [status.runtime_agent_id, status])),
    [liveness],
  );

  const filteredEndpoints = useMemo(() => {
    const query = search.trim().toLowerCase();
    return endpoints.filter((endpoint) => {
      const matchesSearch =
        !query ||
        endpoint.endpointAgentId.toLowerCase().includes(query) ||
        endpoint.runtimeAgents.some(
          (runtime) =>
            runtime.runtimeAgentId.toLowerCase().includes(query) ||
            runtime.runtimeAgentKind.toLowerCase().includes(query),
        );
      const matchesPosture = postureFilter === "all" || endpoint.posture === postureFilter;
      const isActive = endpoint.activeSessionCount > 0;
      const matchesActivity =
        activityFilter === "all" ||
        (activityFilter === "active" && isActive) ||
        (activityFilter === "inactive" && !isActive);
      const matchesViolations =
        violationFilter === "all" ||
        (violationFilter === "with-violations" && endpoint.violationCount > 0) ||
        (violationFilter === "critical-only" && endpoint.posture === "critical");
      const matchesLastSeen = withinLastSeenWindow(endpoint.lastEvent, lastSeenFilter);

      return (
        matchesSearch &&
        matchesPosture &&
        matchesActivity &&
        matchesViolations &&
        matchesLastSeen
      );
    });
  }, [activityFilter, endpoints, lastSeenFilter, postureFilter, search, violationFilter]);

  const filteredRuntimeAgents = useMemo(() => {
    const query = search.trim().toLowerCase();
    return runtimeAgents.filter((runtime) => {
      const matchesSearch =
        !query ||
        runtime.runtimeAgentId.toLowerCase().includes(query) ||
        runtime.runtimeAgentKind.toLowerCase().includes(query) ||
        runtime.endpointAgentId.toLowerCase().includes(query);
      const matchesPosture = postureFilter === "all" || runtime.posture === postureFilter;
      const isActive = runtime.activeSessionCount > 0;
      const matchesActivity =
        activityFilter === "all" ||
        (activityFilter === "active" && isActive) ||
        (activityFilter === "inactive" && !isActive);
      const matchesViolations =
        violationFilter === "all" ||
        (violationFilter === "with-violations" && runtime.violationCount > 0) ||
        (violationFilter === "critical-only" && runtime.posture === "critical");
      const matchesLastSeen = withinLastSeenWindow(runtime.lastEvent, lastSeenFilter);

      return (
        matchesSearch &&
        matchesPosture &&
        matchesActivity &&
        matchesViolations &&
        matchesLastSeen
      );
    });
  }, [activityFilter, lastSeenFilter, postureFilter, runtimeAgents, search, violationFilter]);

  const sessionEvents = selectedSession?.events ?? [];
  const unattributedRuntimeEvents = useMemo(
    () => endpoints.reduce((sum, endpoint) => sum + endpoint.unattributedRuntimeEvents, 0),
    [endpoints],
  );
  const onlineEndpoints = (Array.isArray(liveness?.endpoints) ? liveness.endpoints : []).filter(
    (endpoint) => endpoint.online,
  ).length;
  const onlineRuntimes = (Array.isArray(liveness?.runtimes) ? liveness.runtimes : []).filter(
    (runtime) => runtime.online,
  ).length;

  const selectedSessionDrilldown = useMemo(() => {
    if (!selectedSession) return null;
    const first = selectedSession.events[0];
    const runtimeAgentId = first?.runtime_agent_id;
    const runtimeAgentKind = first?.runtime_agent_kind;
    const endpointAgentId = first?.endpoint_agent_id ?? first?.agent_id;
    return {
      session_id: selectedSession.sessionId,
      endpoint_agent_id: endpointAgentId,
      agent_id: endpointAgentId,
      runtime_agent_id: runtimeAgentId,
      runtime_agent_kind: runtimeAgentKind,
    };
  }, [selectedSession]);

  const openEventStream = (filters: Record<string, unknown>) => {
    processes.launch("event-stream", { filters, source: "agent_explorer" });
  };

  const openAuditLog = (filters: Record<string, unknown>) => {
    processes.launch("audit", { filters, source: "agent_explorer" });
  };

  return (
    <div
      className="space-y-5"
      style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}
    >
      <div className="flex items-center gap-3">
        <span
          className="inline-block h-2 w-2 rounded-full"
          style={{ background: connected ? "var(--teal)" : "var(--crimson)" }}
        />
        <span
          className="font-mono"
          style={{
            fontSize: 12,
            textTransform: "uppercase",
            letterSpacing: "0.1em",
            color: "var(--muted)",
          }}
        >
          {endpoints.length} endpoint agents · {runtimeAgents.length} runtime agents ·{" "}
          {onlineEndpoints} online endpoints · {onlineRuntimes} online runtimes
        </span>
      </div>

      {unattributedRuntimeEvents > 0 && (
        <div
          className="glass-panel font-mono"
          style={{ padding: "10px 12px", fontSize: 11, color: "var(--stamp-warn)" }}
        >
          <NoiseGrain />
          <div style={{ position: "relative", zIndex: 2 }}>
            {unattributedRuntimeEvents} events look runtime-originated but are missing
            <code style={{ marginLeft: 4 }}>runtime_agent_id</code> attribution.
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <label className="font-mono" style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: 10, letterSpacing: "0.1em", color: "var(--muted)" }}>View</span>
          <select
            value={view}
            onChange={(event) => setView(event.target.value as ExplorerView)}
            className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
            style={{ color: "var(--text)", minWidth: 190 }}
          >
            <option value="endpoints">Endpoint Agents</option>
            <option value="runtime-agents">Runtime Agents</option>
          </select>
        </label>

        <label className="font-mono" style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: 10, letterSpacing: "0.1em", color: "var(--muted)" }}>Posture</span>
          <select
            value={postureFilter}
            onChange={(event) => setPostureFilter(event.target.value as PostureFilter)}
            className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
            style={{ color: "var(--text)", minWidth: 140 }}
          >
            <option value="all">All</option>
            <option value="nominal">Nominal</option>
            <option value="elevated">Elevated</option>
            <option value="critical">Critical</option>
          </select>
        </label>

        <label className="font-mono" style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: 10, letterSpacing: "0.1em", color: "var(--muted)" }}>Sessions</span>
          <select
            value={activityFilter}
            onChange={(event) => setActivityFilter(event.target.value as ActivityFilter)}
            className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
            style={{ color: "var(--text)", minWidth: 130 }}
          >
            <option value="all">All</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
        </label>

        <label className="font-mono" style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: 10, letterSpacing: "0.1em", color: "var(--muted)" }}>
            Violations
          </span>
          <select
            value={violationFilter}
            onChange={(event) => setViolationFilter(event.target.value as ViolationFilter)}
            className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
            style={{ color: "var(--text)", minWidth: 170 }}
          >
            <option value="all">All</option>
            <option value="with-violations">With Violations</option>
            <option value="critical-only">Critical Only</option>
          </select>
        </label>

        <label className="font-mono" style={{ display: "grid", gap: 4 }}>
          <span style={{ fontSize: 10, letterSpacing: "0.1em", color: "var(--muted)" }}>Last Seen</span>
          <select
            value={lastSeenFilter}
            onChange={(event) => setLastSeenFilter(event.target.value as LastSeenFilter)}
            className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
            style={{ color: "var(--text)", minWidth: 140 }}
          >
            <option value="all">All</option>
            <option value="15m">Last 15m</option>
            <option value="1h">Last 1h</option>
            <option value="24h">Last 24h</option>
          </select>
        </label>
      </div>

      <input
        type="text"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        placeholder="Search endpoint IDs, runtime IDs, kinds..."
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)", width: "100%", maxWidth: 540 }}
      />

      {view === "endpoints" ? (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(420px, 1fr))",
            gap: 12,
          }}
        >
          {filteredEndpoints.map((endpoint) => (
            <AgentSessionCard
              key={endpoint.endpointAgentId}
              endpoint={endpoint}
              onSessionClick={(sessionId, sessionEvents, label) =>
                setSelectedSession((current) =>
                  current && current.sessionId === sessionId && current.label === label
                    ? null
                    : {
                        sessionId,
                        label,
                        events: sessionEvents,
                      },
                )
              }
            />
          ))}
        </div>
      ) : (
        <div className="glass-panel overflow-x-auto" style={{ position: "relative" }}>
          <NoiseGrain />
          <table className="relative w-full text-left text-sm" style={{ borderCollapse: "separate" }}>
            <thead>
              <tr>
                {[
                  "Runtime ID",
                  "Kind",
                  "Endpoint",
                  "Liveness",
                  "Sessions",
                  "Violations",
                  "Last Seen",
                  "Posture",
                  "Drilldown",
                ].map((heading) => (
                  <th
                    key={heading}
                    className="font-mono px-4 py-3 text-[10px] uppercase"
                    style={{ letterSpacing: "0.1em", color: "rgba(154,167,181,0.65)", fontWeight: 500 }}
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredRuntimeAgents.map((runtime) => {
                const status = runtimeLiveness.get(runtime.runtimeAgentId);
                const seconds = status?.seconds_since_heartbeat;
                const heartbeatAge = typeof seconds === "number" ? `${seconds}s` : "unknown";
                return (
                  <tr key={runtime.runtimeAgentId} className="hover-row">
                  <td className="font-mono px-4 py-2 text-xs" style={{ color: "var(--text)" }}>
                    {runtime.runtimeAgentId}
                  </td>
                  <td className="font-mono px-4 py-2 text-xs" style={{ color: "var(--muted)" }}>
                    {runtime.runtimeAgentKind}
                  </td>
                  <td className="font-mono px-4 py-2 text-xs" style={{ color: "var(--muted)" }}>
                    {runtime.endpointAgentId}
                  </td>
                  <td className="font-mono px-4 py-2 text-xs" style={{ color: "var(--muted)" }}>
                    {status?.online ? (
                      <span style={{ color: "var(--teal)" }}>online · {heartbeatAge}</span>
                    ) : (
                      <span style={{ color: "var(--stamp-blocked)" }}>offline · {heartbeatAge}</span>
                    )}
                  </td>
                  <td className="font-mono px-4 py-2 text-xs" style={{ color: "var(--text)" }}>
                    {runtime.activeSessionCount}
                  </td>
                  <td className="font-mono px-4 py-2 text-xs" style={{ color: "var(--stamp-blocked)" }}>
                    {runtime.violationCount}
                  </td>
                  <td className="font-mono px-4 py-2 text-xs" style={{ color: "var(--muted)" }}>
                    {new Date(runtime.lastEvent).toLocaleString()}
                  </td>
                  <td className="px-4 py-2">{runtimeDecisionStamp(runtime)}</td>
                  <td className="px-4 py-2">
                    <div className="flex gap-2">
                      <button
                        type="button"
                        className="font-mono"
                        onClick={() =>
                          openEventStream({
                            endpoint_agent_id: runtime.endpointAgentId,
                            agent_id: runtime.endpointAgentId,
                            runtime_agent_id: runtime.runtimeAgentId,
                            runtime_agent_kind: runtime.runtimeAgentKind,
                          })
                        }
                        style={{
                          border: "1px solid rgba(27,34,48,0.7)",
                          background: "rgba(8,12,20,0.6)",
                          color: "var(--teal)",
                          borderRadius: 6,
                          padding: "4px 8px",
                          fontSize: 10,
                          cursor: "pointer",
                        }}
                      >
                        Event Stream
                      </button>
                      <button
                        type="button"
                        className="font-mono"
                        onClick={() =>
                          openAuditLog({
                            agent_id: runtime.endpointAgentId,
                            endpoint_agent_id: runtime.endpointAgentId,
                            runtime_agent_id: runtime.runtimeAgentId,
                            runtime_agent_kind: runtime.runtimeAgentKind,
                          })
                        }
                        style={{
                          border: "1px solid rgba(27,34,48,0.7)",
                          background: "rgba(8,12,20,0.6)",
                          color: "var(--gold)",
                          borderRadius: 6,
                          padding: "4px 8px",
                          fontSize: 10,
                          cursor: "pointer",
                        }}
                      >
                        Audit Log
                      </button>
                    </div>
                  </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {(view === "endpoints" ? filteredEndpoints.length === 0 : filteredRuntimeAgents.length === 0) && (
        <p
          className="font-mono"
          style={{ fontSize: 12, color: "rgba(154,167,181,0.4)", letterSpacing: "0.08em" }}
        >
          {search ? "No matching agent records" : "Waiting for agent events..."}
        </p>
      )}

      {selectedSession && sessionEvents.length > 0 && (
        <div>
          <div className="flex items-center gap-3" style={{ marginBottom: 8 }}>
            <span
              className="font-mono"
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: "0.1em",
                color: "var(--gold)",
              }}
            >
              {selectedSession.label}
            </span>
            <button
              type="button"
              onClick={() => setSelectedSession(null)}
              className="font-mono"
              style={{
                background: "none",
                border: "none",
                color: "var(--muted)",
                cursor: "pointer",
                fontSize: 11,
              }}
            >
              ✕ Close
            </button>
            {selectedSessionDrilldown && (
              <>
                <button
                  type="button"
                  onClick={() => openEventStream(selectedSessionDrilldown)}
                  className="font-mono"
                  style={{
                    border: "1px solid rgba(27,34,48,0.7)",
                    background: "rgba(8,12,20,0.6)",
                    color: "var(--teal)",
                    borderRadius: 6,
                    padding: "4px 8px",
                    fontSize: 10,
                    cursor: "pointer",
                  }}
                >
                  Event Stream
                </button>
                <button
                  type="button"
                  onClick={() => openAuditLog(selectedSessionDrilldown)}
                  className="font-mono"
                  style={{
                    border: "1px solid rgba(27,34,48,0.7)",
                    background: "rgba(8,12,20,0.6)",
                    color: "var(--gold)",
                    borderRadius: 6,
                    padding: "4px 8px",
                    fontSize: 10,
                    cursor: "pointer",
                  }}
                >
                  Audit Log
                </button>
              </>
            )}
          </div>
          <div className="glass-panel overflow-x-auto">
            <NoiseGrain />
            <table className="relative w-full text-left text-sm" style={{ borderCollapse: "separate" }}>
              <thead>
                <tr>
                  {["Time", "Action", "Target", "Guard", "Decision", "Runtime Kind"].map((heading) => (
                    <th
                      key={heading}
                      className="font-mono px-4 py-2 text-[10px] uppercase"
                      style={{
                        letterSpacing: "0.1em",
                        color: "rgba(154,167,181,0.6)",
                        fontWeight: 500,
                      }}
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sessionEvents.map((event) => (
                  <tr key={event._id} className="hover-row">
                    <td className="font-mono px-4 py-2 text-xs" style={{ color: "rgba(154,167,181,0.45)" }}>
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="font-mono px-4 py-2 text-sm" style={{ color: "var(--text)" }}>
                      {event.action_type ?? "-"}
                    </td>
                    <td className="px-4 py-2 text-sm" style={{ color: "rgba(154,167,181,0.6)" }}>
                      {event.target ?? "-"}
                    </td>
                    <td className="px-4 py-2 text-sm" style={{ color: "var(--text)" }}>
                      {event.guard ?? "-"}
                    </td>
                    <td className="px-4 py-2">
                      {event.allowed === false ? (
                        <Stamp variant="blocked">BLOCKED</Stamp>
                      ) : event.allowed === true ? (
                        <Stamp variant="allowed">ALLOWED</Stamp>
                      ) : (
                        <span style={{ color: "rgba(154,167,181,0.3)" }}>-</span>
                      )}
                    </td>
                    <td className="font-mono px-4 py-2 text-xs" style={{ color: "rgba(154,167,181,0.45)" }}>
                      {event.runtime_agent_kind ?? "desktop"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
