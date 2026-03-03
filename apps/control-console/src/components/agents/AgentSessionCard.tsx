import { useState } from "react";
import type { AgentInfo } from "../../hooks/useAgentSessions";
import { NoiseGrain } from "../ui";
import { AgentPostureBadge } from "./AgentPostureBadge";

function relativeTime(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function AgentSessionCard({
  agent,
  onSessionClick,
}: {
  agent: AgentInfo;
  onSessionClick?: (sessionId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="glass-panel" style={{ padding: 16 }}>
      <NoiseGrain />
      <div style={{ position: "relative", zIndex: 2 }}>
        {/* Header */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 8,
          }}
        >
          <span
            className="font-mono"
            style={{ fontSize: 13, color: "var(--gold)", fontWeight: 500 }}
          >
            {agent.agentId.slice(0, 12)}
          </span>
          <AgentPostureBadge posture={agent.posture} />
        </div>

        {/* Stats */}
        <div style={{ display: "flex", gap: 16, marginBottom: 8 }}>
          <Stat label="Sessions" value={agent.sessions.length} />
          <Stat label="Actions" value={agent.totalActions} />
          <Stat label="Last Active" value={relativeTime(agent.lastEvent)} />
        </div>

        {/* Expand toggle */}
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="font-mono"
          style={{
            background: "none",
            border: "none",
            color: "var(--muted)",
            fontSize: 10,
            cursor: "pointer",
            textTransform: "uppercase",
            letterSpacing: "0.08em",
            padding: 0,
          }}
        >
          {expanded ? "\u25BE Hide Sessions" : "\u25B8 Show Sessions"}
        </button>

        {/* Session list */}
        {expanded && (
          <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 2 }}>
            {agent.sessions.map((session) => (
              <div
                key={session.sessionId}
                className="hover-row"
                onClick={() => onSessionClick?.(session.sessionId)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "6px 8px",
                  borderRadius: 6,
                  cursor: onSessionClick ? "pointer" : "default",
                }}
              >
                <span className="font-mono" style={{ fontSize: 11, color: "var(--text)" }}>
                  {session.sessionId.slice(0, 12)}
                </span>
                <span className="font-mono" style={{ fontSize: 10, color: "var(--muted)" }}>
                  {session.events.length} events
                </span>
                <span
                  className="font-mono"
                  style={{ fontSize: 10, color: "rgba(154,167,181,0.4)", marginLeft: "auto" }}
                >
                  {new Date(session.startTime).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <div
        className="font-mono"
        style={{
          fontSize: 9,
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          color: "rgba(154,167,181,0.5)",
        }}
      >
        {label}
      </div>
      <div className="font-mono" style={{ fontSize: 13, color: "var(--text)" }}>
        {String(value)}
      </div>
    </div>
  );
}
