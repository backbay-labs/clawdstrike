import { useEffect, useMemo, useState } from "react";
import type { SSEEvent } from "./useSSE";

// Sourced from package.json — do not hardcode a different value.
export const APP_VERSION = "0.2.0";

export interface ConsoleStatus {
  sseLive: boolean;
  violations: number;
  uptime: string;
  build: string;
}

function formatElapsed(startMs: number): string {
  const diff = Math.max(0, Math.floor((Date.now() - startMs) / 1000));
  const h = String(Math.floor(diff / 3600)).padStart(2, "0");
  const m = String(Math.floor((diff % 3600) / 60)).padStart(2, "0");
  const s = String(diff % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

export function useConsoleStatus(events: SSEEvent[], connected: boolean): ConsoleStatus {
  const violations = useMemo(
    () => events.filter((e) => e.allowed === false || e.event_type === "violation").length,
    [events],
  );

  // Match DesktopWidgets: oldest event is last in the array (newest-first ordering from useSSE).
  const oldestTimestamp = events.length > 0 ? events[events.length - 1].timestamp : null;
  const startMs = useMemo(
    () => (oldestTimestamp ? new Date(oldestTimestamp).getTime() : null),
    [oldestTimestamp],
  );

  const [uptime, setUptime] = useState("00:00:00");

  useEffect(() => {
    if (startMs === null) {
      setUptime("00:00:00");
      return;
    }
    const tick = () => setUptime(formatElapsed(startMs));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startMs]);

  return useMemo(
    () => ({ sseLive: connected, violations, uptime, build: APP_VERSION }),
    [connected, violations, uptime],
  );
}
