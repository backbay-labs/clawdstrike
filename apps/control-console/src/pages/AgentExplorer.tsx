import { useMemo, useState } from "react";
import { AgentSessionCard } from "../components/agents/AgentSessionCard";
import { NoiseGrain, Stamp } from "../components/ui";
import { useSharedSSE } from "../context/SSEContext";
import { useAgentSessions } from "../hooks/useAgentSessions";

export function AgentExplorer(_props: { windowId?: string }) {
  const { events, connected } = useSharedSSE();
  const agents = useAgentSessions(events);
  const [search, setSearch] = useState("");
  const [selectedSession, setSelectedSession] = useState<string | null>(null);

  const filtered = useMemo(
    () =>
      search
        ? agents.filter((a) => a.agentId.toLowerCase().includes(search.toLowerCase()))
        : agents,
    [agents, search],
  );

  const sessionEvents = useMemo(
    () => (selectedSession ? events.filter((e) => e.session_id === selectedSession) : []),
    [events, selectedSession],
  );

  return (
    <div
      className="space-y-5"
      style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}
    >
      {/* Header */}
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
          {agents.length} agents
        </span>
      </div>

      {/* Search */}
      <input
        type="text"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search agents..."
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)", width: "100%", maxWidth: 320 }}
      />

      {/* Agent grid */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))",
          gap: 12,
        }}
      >
        {filtered.map((agent) => (
          <AgentSessionCard
            key={agent.agentId}
            agent={agent}
            onSessionClick={(sid) => setSelectedSession(selectedSession === sid ? null : sid)}
          />
        ))}
      </div>

      {filtered.length === 0 && (
        <p
          className="font-mono"
          style={{ fontSize: 12, color: "rgba(154,167,181,0.4)", letterSpacing: "0.08em" }}
        >
          {search ? "No matching agents" : "Waiting for agent events..."}
        </p>
      )}

      {/* Session detail */}
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
              Session {selectedSession.slice(0, 12)}
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
          </div>
          <div className="glass-panel overflow-x-auto">
            <NoiseGrain />
            <table
              className="relative w-full text-left text-sm"
              style={{ borderCollapse: "separate" }}
            >
              <thead>
                <tr>
                  {["Time", "Action", "Target", "Guard", "Decision"].map((h) => (
                    <th
                      key={h}
                      className="font-mono px-4 py-2 text-[10px] uppercase"
                      style={{
                        letterSpacing: "0.1em",
                        color: "rgba(154,167,181,0.6)",
                        fontWeight: 500,
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sessionEvents.map((e) => (
                  <tr key={e._id} className="hover-row">
                    <td
                      className="font-mono px-4 py-2 text-xs"
                      style={{ color: "rgba(154,167,181,0.45)" }}
                    >
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="font-mono px-4 py-2 text-sm" style={{ color: "var(--text)" }}>
                      {e.action_type ?? "-"}
                    </td>
                    <td className="px-4 py-2 text-sm" style={{ color: "rgba(154,167,181,0.6)" }}>
                      {e.target ?? "-"}
                    </td>
                    <td className="px-4 py-2 text-sm" style={{ color: "var(--text)" }}>
                      {e.guard ?? "-"}
                    </td>
                    <td className="px-4 py-2">
                      {e.allowed === false ? (
                        <Stamp variant="blocked">BLOCKED</Stamp>
                      ) : e.allowed === true ? (
                        <Stamp variant="allowed">ALLOWED</Stamp>
                      ) : (
                        <span style={{ color: "rgba(154,167,181,0.3)" }}>-</span>
                      )}
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
