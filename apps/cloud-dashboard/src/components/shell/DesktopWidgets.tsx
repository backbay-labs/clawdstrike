import { useState, useEffect, useRef, useCallback } from "react";
import { Plate } from "../ui";
import type { SSEEvent } from "../../hooks/useSSE";

interface WidgetPos { x: number; y: number }

const STORAGE_KEY = "cs_widget_positions";

function loadPositions(): Record<string, WidgetPos> {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}"); }
  catch { return {}; }
}

function savePositions(pos: Record<string, WidgetPos>) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(pos));
}

const DEFAULT_POSITIONS: Record<string, WidgetPos> = {
  violations: { x: -180, y: 24 },
  status: { x: -180, y: 100 },
  uptime: { x: -180, y: 176 },
};

export function DesktopWidgets({ events, connected }: { events: SSEEvent[]; connected: boolean }) {
  const [positions, setPositions] = useState<Record<string, WidgetPos>>(() => {
    const saved = loadPositions();
    return { ...DEFAULT_POSITIONS, ...saved };
  });
  const dragRef = useRef<{ id: string; startX: number; startY: number; origX: number; origY: number } | null>(null);
  const positionsRef = useRef(positions);
  positionsRef.current = positions;

  const violationCount = events.filter((e) => e.allowed === false || e.event_type === "violation").length;

  // Uptime clock — only depend on the oldest event timestamp, not the whole array
  const oldestTimestamp = events.length > 0 ? events[events.length - 1].timestamp : null;
  const [elapsed, setElapsed] = useState("00:00:00");
  useEffect(() => {
    if (!oldestTimestamp) return;
    const start = new Date(oldestTimestamp).getTime();
    const tick = () => {
      const diff = Math.floor((Date.now() - start) / 1000);
      const h = String(Math.floor(diff / 3600)).padStart(2, "0");
      const m = String(Math.floor((diff % 3600) / 60)).padStart(2, "0");
      const s = String(diff % 60).padStart(2, "0");
      setElapsed(`${h}:${m}:${s}`);
    };
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, [oldestTimestamp]);

  const handleMouseDown = useCallback((id: string, e: React.MouseEvent) => {
    const pos = positionsRef.current[id] || DEFAULT_POSITIONS[id];
    dragRef.current = { id, startX: e.clientX, startY: e.clientY, origX: pos.x, origY: pos.y };
    const onMove = (ev: MouseEvent) => {
      if (!dragRef.current) return;
      const dx = ev.clientX - dragRef.current.startX;
      const dy = ev.clientY - dragRef.current.startY;
      setPositions((p) => {
        const next = { ...p, [dragRef.current!.id]: { x: dragRef.current!.origX + dx, y: dragRef.current!.origY + dy } };
        savePositions(next);
        return next;
      });
    };
    const onUp = () => { dragRef.current = null; document.removeEventListener("mousemove", onMove); document.removeEventListener("mouseup", onUp); };
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, []);

  const resolvePos = (id: string): React.CSSProperties => {
    const pos = positions[id] || DEFAULT_POSITIONS[id];
    if (pos.x < 0) return { position: "absolute", right: -pos.x, top: pos.y };
    return { position: "absolute", left: pos.x, top: pos.y };
  };

  return (
    <>
      <div style={{ ...resolvePos("violations"), cursor: "grab", userSelect: "none", zIndex: 2 }} onMouseDown={(e) => handleMouseDown("violations", e)}>
        <Plate className="p-3" style={{ width: 120 }}>
          <div className="font-mono relative z-10" style={{ fontSize: 9, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)" }}>Violations</div>
          <div className="font-display relative z-10" style={{ fontSize: 22, fontWeight: 700, color: violationCount > 0 ? "var(--crimson)" : "var(--teal)" }}>{violationCount}</div>
        </Plate>
      </div>

      <div style={{ ...resolvePos("status"), cursor: "grab", userSelect: "none", zIndex: 2 }} onMouseDown={(e) => handleMouseDown("status", e)}>
        <Plate className="p-3" style={{ width: 120 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: connected ? "var(--teal)" : "var(--crimson)" }} />
            <span className="font-mono relative z-10" style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "0.06em", color: connected ? "var(--teal)" : "var(--crimson)" }}>
              {connected ? "Connected" : "Disconnected"}
            </span>
          </div>
        </Plate>
      </div>

      <div style={{ ...resolvePos("uptime"), cursor: "grab", userSelect: "none", zIndex: 2 }} onMouseDown={(e) => handleMouseDown("uptime", e)}>
        <Plate className="p-3" style={{ width: 120 }}>
          <div className="font-mono relative z-10" style={{ fontSize: 9, textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--muted)" }}>Uptime</div>
          <div className="font-mono relative z-10" style={{ fontSize: 16, color: "var(--text)", letterSpacing: "0.04em" }}>{elapsed}</div>
        </Plate>
      </div>
    </>
  );
}
