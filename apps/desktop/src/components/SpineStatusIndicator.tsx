/**
 * SpineStatusIndicator - Shows live/demo/connecting/offline status for spine data.
 *
 * Shared across ThreatRadarView, AttackGraphView, and NetworkMapView.
 */
import { useState, useEffect, useRef } from "react";
import type { SpineConnectionStatus } from "@/types/spine";
import { getSpineConnectionStatus, type SpineConnectionStatusDetail } from "@/services/spineEventSource";

const STATUS_CONFIG: Record<SpineConnectionStatus, { color: string; label: string }> = {
  connected: { color: "bg-green-500", label: "Live" },
  demo: { color: "bg-amber-500", label: "Demo" },
  connecting: { color: "bg-blue-500 animate-pulse", label: "Connecting" },
  disconnected: { color: "bg-red-500", label: "Offline" },
};

export function SpineStatusIndicator({ status }: { status: SpineConnectionStatus }) {
  const { color, label } = STATUS_CONFIG[status];
  const [showDetail, setShowDetail] = useState(false);
  const [detail, setDetail] = useState<SpineConnectionStatusDetail | null>(null);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!showDetail) return;
    // Fetch detailed status when tooltip opens
    getSpineConnectionStatus().then(setDetail).catch(() => {});
    // Poll while open
    timerRef.current = window.setInterval(() => {
      getSpineConnectionStatus().then(setDetail).catch(() => {});
    }, 3000);
    return () => {
      if (timerRef.current !== null) clearInterval(timerRef.current);
    };
  }, [showDetail]);

  return (
    <span
      className="relative flex items-center gap-1.5 text-xs text-white/60 cursor-default pointer-events-auto"
      onMouseEnter={() => setShowDetail(true)}
      onMouseLeave={() => setShowDetail(false)}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${color}`} />
      {label}

      {showDetail && detail && (
        <div className="absolute top-full right-0 mt-1 w-56 rounded-lg border border-white/10 bg-[#111118]/95 backdrop-blur-md p-3 text-xs text-white/70 shadow-xl z-50">
          <div className="flex justify-between mb-1.5">
            <span className="text-white/40">Status</span>
            <span className={detail.connected ? "text-green-400" : "text-red-400"}>
              {detail.connected ? "Connected" : "Disconnected"}
            </span>
          </div>
          {detail.natsUrl && (
            <div className="flex justify-between mb-1.5">
              <span className="text-white/40">NATS</span>
              <span className="font-mono truncate ml-2">{detail.natsUrl}</span>
            </div>
          )}
          <div className="flex justify-between mb-1.5">
            <span className="text-white/40">Events</span>
            <span className="font-mono">{detail.eventCount.toLocaleString()}</span>
          </div>
          {detail.lastEventAt && (
            <div className="flex justify-between mb-1.5">
              <span className="text-white/40">Last event</span>
              <span className="font-mono">{formatRelative(detail.lastEventAt)}</span>
            </div>
          )}
          {detail.lastError && (
            <div className="mt-1.5 pt-1.5 border-t border-white/5 text-red-400/80 truncate">
              {detail.lastError}
            </div>
          )}
        </div>
      )}
    </span>
  );
}

function formatRelative(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const secs = Math.floor(ms / 1000);
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  return `${mins}m ago`;
}
