import { useState, useEffect, useRef, useCallback } from "react";
import { fetchAuditEvents, type AuditEvent } from "../api/client";
import { PlaybackControls } from "../components/advanced/PlaybackControls";
import { NoiseGrain, Stamp } from "../components/ui";

export function ReplayMode(_props: { windowId?: string }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [position, setPosition] = useState(0);
  const intervalRef = useRef<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchAuditEvents({ limit: 500 });
      setEvents(data.events.reverse());
      setPosition(0);
      setPlaying(false);
    } catch (err) { console.debug("[ReplayMode] error:", err); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!playing || events.length === 0) return;
    intervalRef.current = window.setInterval(() => {
      setPosition((p) => { if (p >= events.length - 1) { setPlaying(false); return p; } return p + 1; });
    }, 1000 / speed);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [playing, speed, events.length]);

  const displayed = events.slice(0, position + 1);

  return (
    <div className="space-y-4" style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%", display: "flex", flexDirection: "column" }}>
      <PlaybackControls
        playing={playing}
        onPlayPause={() => setPlaying((p) => !p)}
        speed={speed}
        onSpeedChange={setSpeed}
        position={position}
        total={events.length}
        onSeek={(p) => { setPosition(p); setPlaying(false); }}
      />
      <div className="glass-panel" style={{ flex: 1, overflow: "auto" }}>
        <NoiseGrain />
        <table className="relative w-full text-left text-sm">
          <thead>
            <tr>{["Time", "Action", "Target", "Guard", "Decision"].map((h) => (
              <th key={h} className="font-mono px-4 py-2 text-[10px] uppercase" style={{ letterSpacing: "0.1em", color: "rgba(154,167,181,0.6)", fontWeight: 500 }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="font-mono px-4 py-8 text-center" style={{ color: "var(--muted)" }}>Loading...</td></tr>
            ) : displayed.length === 0 ? (
              <tr><td colSpan={5} className="font-mono px-4 py-8 text-center" style={{ color: "var(--muted)" }}>No events loaded</td></tr>
            ) : (
              displayed.map((e) => (
                <tr key={e.id} className="hover-row">
                  <td className="font-mono px-4 py-2 text-xs" style={{ color: "rgba(154,167,181,0.45)" }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td className="font-mono px-4 py-2 text-sm" style={{ color: "var(--text)" }}>{e.action_type}</td>
                  <td className="px-4 py-2 text-sm" style={{ color: "rgba(154,167,181,0.6)" }}>{e.target ?? "-"}</td>
                  <td className="px-4 py-2 text-sm" style={{ color: "var(--text)" }}>{e.guard ?? "-"}</td>
                  <td className="px-4 py-2"><Stamp variant={e.decision === "blocked" ? "blocked" : "allowed"}>{e.decision}</Stamp></td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
