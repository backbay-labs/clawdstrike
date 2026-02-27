import { useRef, useState, useEffect } from "react";
import { useSharedSSE } from "../context/SSEContext";
import { ForceGraph } from "../components/advanced/ForceGraph";
import { NoiseGrain } from "../components/ui";

export function PostureMap(_props: { windowId?: string }) {
  const { events, connected } = useSharedSSE();
  const containerRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 800, height: 500 });

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => {
      setSize({ width: entry.contentRect.width, height: entry.contentRect.height });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const agents = new Set(events.map((e) => e.agent_id).filter(Boolean));
  const sessions = new Set(events.map((e) => e.session_id).filter(Boolean));

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", color: "var(--text)" }}>
      <div style={{ padding: "12px 20px", display: "flex", alignItems: "center", gap: 12, borderBottom: "1px solid var(--slate)" }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: connected ? "var(--teal)" : "var(--crimson)" }} />
        <span className="font-mono" style={{ fontSize: 11, color: "var(--muted)" }}>
          {agents.size} agents · {sessions.size} sessions
        </span>
      </div>
      <div ref={containerRef} className="glass-panel" style={{ flex: 1, margin: 12, overflow: "hidden", position: "relative" }}>
        <NoiseGrain />
        <div style={{ position: "relative", zIndex: 2, width: "100%", height: "100%" }}>
          <ForceGraph events={events} width={size.width} height={size.height} />
        </div>
      </div>
    </div>
  );
}
