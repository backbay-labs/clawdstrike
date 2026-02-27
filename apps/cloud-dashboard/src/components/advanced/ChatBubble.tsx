import { Stamp } from "../ui";
import type { SSEEvent } from "../../hooks/useSSE";

export function ChatBubble({ event, agentColor }: { event: SSEEvent; agentColor: string }) {
  const initial = ((event.agent_id || "?")[0] ?? "?").toUpperCase();

  return (
    <div style={{ display: "flex", gap: 10, padding: "6px 0" }}>
      <div
        style={{
          width: 28,
          height: 28,
          borderRadius: "50%",
          background: agentColor,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
          fontSize: 12,
          fontWeight: 700,
          color: "#000",
        }}
      >
        {initial}
      </div>
      <div
        className="glass-panel"
        style={{
          padding: "8px 12px",
          flex: 1,
          borderLeft: `2px solid ${agentColor}`,
        }}
      >
        <div className="font-mono" style={{ fontSize: 12, color: "var(--text)" }}>
          {event.action_type ?? event.event_type}
          {event.target && <span style={{ color: "var(--muted)" }}> &rarr; {event.target}</span>}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
          {event.guard && (
            <span className="font-mono" style={{ fontSize: 10, color: "var(--gold)", background: "var(--gold-bloom)", border: "1px solid var(--gold-edge)", borderRadius: 4, padding: "1px 6px" }}>
              {event.guard}
            </span>
          )}
          {event.allowed != null && (
            <Stamp variant={event.allowed ? "allowed" : "blocked"}>
              {event.allowed ? "ALLOWED" : "BLOCKED"}
            </Stamp>
          )}
          <span className="font-mono" style={{ fontSize: 9, color: "rgba(154,167,181,0.4)", marginLeft: "auto" }}>
            {new Date(event.timestamp).toLocaleTimeString()}
          </span>
        </div>
      </div>
    </div>
  );
}
