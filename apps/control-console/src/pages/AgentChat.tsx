import { useEffect, useMemo, useRef } from "react";
import { ChatBubble } from "../components/advanced/ChatBubble";
import { NoiseGrain } from "../components/ui";
import { useSharedSSE } from "../context/SSEContext";

const COLORS = ["#d6b15a", "#2fa7a0", "#c23b3b", "#9aa7b5", "#8b5cf6", "#ec4899"];

export function AgentChat(_props: { windowId?: string }) {
  const { events } = useSharedSSE();
  const bottomRef = useRef<HTMLDivElement>(null);

  const agentColors = useMemo(() => {
    const map = new Map<string, string>();
    let idx = 0;
    for (const e of events) {
      if (e.agent_id && !map.has(e.agent_id)) {
        map.set(e.agent_id, COLORS[idx % COLORS.length]);
        idx++;
      }
    }
    return map;
  }, [events]);

  const chronological = useMemo(() => [...events].reverse(), [events.length]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", color: "var(--text)" }}>
      {/* Agent legend */}
      {agentColors.size > 0 && (
        <div
          style={{
            padding: "8px 20px",
            borderBottom: "1px solid var(--slate)",
            display: "flex",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          {[...agentColors].map(([id, color]) => (
            <div key={id} style={{ display: "flex", alignItems: "center", gap: 4 }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: color }} />
              <span className="font-mono" style={{ fontSize: 10, color: "var(--muted)" }}>
                {id.slice(0, 12)}
              </span>
            </div>
          ))}
        </div>
      )}
      {/* Chat feed */}
      <div
        className="glass-panel"
        style={{
          flex: 1,
          margin: 12,
          overflow: "auto",
          padding: "12px 16px",
          position: "relative",
        }}
      >
        <NoiseGrain />
        <div style={{ position: "relative", zIndex: 2 }}>
          {chronological.length === 0 ? (
            <p
              className="font-mono"
              style={{
                fontSize: 12,
                color: "rgba(154,167,181,0.4)",
                textAlign: "center",
                padding: 40,
              }}
            >
              Waiting for agent activity...
            </p>
          ) : (
            chronological.map((e) => (
              <ChatBubble
                key={e._id}
                event={e}
                agentColor={agentColors.get(e.agent_id || "") || "var(--muted)"}
              />
            ))
          )}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
}
