import { useState, type CSSProperties } from "react";
import type { EndpointAgentInfo, SessionInfo } from "../../hooks/useAgentSessions";
import type { SSEEvent } from "../../hooks/useSSE";
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
  endpoint,
  onSessionClick,
}: {
  endpoint: EndpointAgentInfo;
  onSessionClick?: (sessionId: string, events: SSEEvent[], label: string) => void;
}) {
  const [showDesktopSessions, setShowDesktopSessions] = useState(false);
  const [showRuntimeAgents, setShowRuntimeAgents] = useState(true);
  const shortId = endpoint.endpointAgentId.slice(0, 16);

  return (
    <div className="glass-panel" style={{ padding: 16 }}>
      <NoiseGrain />
      <div style={{ position: "relative", zIndex: 2 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 8,
          }}
        >
          <div>
            <div className="font-mono" style={{ fontSize: 13, color: "var(--gold)", fontWeight: 500 }}>
              {shortId}
            </div>
            <div
              className="font-mono"
              style={{
                fontSize: 10,
                color: "rgba(154,167,181,0.5)",
                textTransform: "uppercase",
                letterSpacing: "0.08em",
              }}
            >
              Desktop Endpoint
            </div>
          </div>
          <AgentPostureBadge posture={endpoint.posture} />
        </div>

        <div style={{ display: "flex", gap: 16, marginBottom: 8 }}>
          <Stat label="Runtime Agents" value={endpoint.runtimeAgents.length} />
          <Stat label="Actions" value={endpoint.totalActions} />
          <Stat label="Last Active" value={relativeTime(endpoint.lastEvent)} />
        </div>

        {endpoint.unattributedRuntimeEvents > 0 && (
          <div
            className="font-mono"
            style={{
              fontSize: 10,
              color: "var(--stamp-warn)",
              marginBottom: 8,
              letterSpacing: "0.06em",
              textTransform: "uppercase",
            }}
          >
            {endpoint.unattributedRuntimeEvents} runtime events missing runtime_agent_id
          </div>
        )}

        <button
          type="button"
          onClick={() => setShowRuntimeAgents((current) => !current)}
          className="font-mono"
          style={toggleStyle}
        >
          {showRuntimeAgents ? "▾ Hide Runtime Agents" : "▸ Show Runtime Agents"}
        </button>

        {showRuntimeAgents && (
          <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 6 }}>
            {endpoint.runtimeAgents.length === 0 && (
              <div className="font-mono" style={{ fontSize: 11, color: "rgba(154,167,181,0.4)" }}>
                No runtime agents observed.
              </div>
            )}

            {endpoint.runtimeAgents.map((runtime) => (
              <div
                key={runtime.runtimeAgentId}
                style={{
                  border: "1px solid rgba(27,34,48,0.7)",
                  borderRadius: 8,
                  padding: "8px 10px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ minWidth: 0 }}>
                    <div
                      className="font-mono"
                      style={{ fontSize: 11, color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis" }}
                    >
                      {runtime.runtimeAgentId}
                    </div>
                    <div
                      className="font-mono"
                      style={{
                        fontSize: 9,
                        color: "rgba(154,167,181,0.45)",
                        textTransform: "uppercase",
                        letterSpacing: "0.08em",
                      }}
                    >
                      {runtime.runtimeAgentKind}
                    </div>
                  </div>
                  <AgentPostureBadge posture={runtime.posture} />
                </div>
                <div style={{ marginTop: 4, display: "flex", flexDirection: "column", gap: 2 }}>
                  {runtime.sessions.map((session) => (
                    <SessionRow
                      key={`${runtime.runtimeAgentId}:${session.sessionId}`}
                      prefix="Runtime"
                      session={session}
                      onClick={onSessionClick}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        <button
          type="button"
          onClick={() => setShowDesktopSessions((current) => !current)}
          className="font-mono"
          style={{ ...toggleStyle, marginTop: 10 }}
        >
          {showDesktopSessions ? "▾ Hide Desktop Sessions" : "▸ Show Desktop Sessions"}
        </button>

        {showDesktopSessions && (
          <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 2 }}>
            {endpoint.desktopSessions.length === 0 && (
              <div className="font-mono" style={{ fontSize: 11, color: "rgba(154,167,181,0.4)" }}>
                No desktop-only sessions.
              </div>
            )}
            {endpoint.desktopSessions.map((session) => (
              <SessionRow
                key={`desktop:${session.sessionId}`}
                prefix="Desktop"
                session={session}
                onClick={onSessionClick}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SessionRow({
  prefix,
  session,
  onClick,
}: {
  prefix: string;
  session: SessionInfo;
  onClick?: (sessionId: string, events: SSEEvent[], label: string) => void;
}) {
  return (
    <button
      type="button"
      className="hover-row"
      onClick={() => onClick?.(session.sessionId, session.events, `${prefix} session ${session.sessionId}`)}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "6px 8px",
        borderRadius: 6,
        cursor: onClick ? "pointer" : "default",
        border: "none",
        background: "transparent",
        width: "100%",
        textAlign: "left",
      }}
    >
      <span className="font-mono" style={{ fontSize: 11, color: "var(--text)" }}>
        {session.sessionId.slice(0, 16)}
      </span>
      <span className="font-mono" style={{ fontSize: 10, color: "var(--muted)" }}>
        {session.events.length} events
      </span>
      <span className="font-mono" style={{ fontSize: 10, color: "var(--stamp-blocked)" }}>
        {session.violationCount} violations
      </span>
      <span
        className="font-mono"
        style={{ fontSize: 10, color: "rgba(154,167,181,0.4)", marginLeft: "auto" }}
      >
        {new Date(session.startTime).toLocaleTimeString()}
      </span>
    </button>
  );
}

const toggleStyle: CSSProperties = {
  background: "none",
  border: "none",
  color: "var(--muted)",
  fontSize: 10,
  cursor: "pointer",
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  padding: 0,
};

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
