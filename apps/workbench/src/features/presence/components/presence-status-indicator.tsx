// PresenceStatusIndicator — Status bar widget showing connection state dot
// (green/amber/red) and online analyst count. Clicking toggles the People
// sidebar panel via the activity bar store.

import { usePresenceStore } from "../stores/presence-store";
import { useActivityBarStore } from "@/features/activity-bar/stores/activity-bar-store";
import type { PresenceConnectionState } from "../types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function dotColor(state: PresenceConnectionState): string {
  switch (state) {
    case "connected":
      return "#3dbf84"; // green — same as fleet dot
    case "reconnecting":
    case "connecting":
      return "#d4a84b"; // amber/gold
    case "disconnected":
    case "idle":
    default:
      return "#c45c5c"; // red
  }
}

function statusLabel(state: PresenceConnectionState, count: number): string {
  switch (state) {
    case "connected":
      return `${count} online`;
    case "reconnecting":
    case "connecting":
      return "Reconnecting...";
    case "disconnected":
    case "idle":
    default:
      return "Offline";
  }
}

function titleText(state: PresenceConnectionState, count: number): string {
  switch (state) {
    case "connected":
      return `Presence: ${count} analyst${count !== 1 ? "s" : ""} online`;
    case "reconnecting":
    case "connecting":
      return "Presence: reconnecting";
    case "disconnected":
    case "idle":
    default:
      return "Presence: offline";
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function PresenceStatusIndicator() {
  // Granular selectors — connectionState is a scalar, analysts.size is a
  // number. Neither subscribes to the full analysts Map to avoid re-render
  // storms when cursor/selection updates flow through.
  const connectionState = usePresenceStore((s) => s.connectionState);
  const onlineCount = usePresenceStore((s) => s.analysts.size);

  const connected = connectionState === "connected";
  const color = dotColor(connectionState);

  return (
    <button
      className="flex items-center gap-1.5 hover:text-[#ece7dc] transition-colors"
      title={titleText(connectionState, onlineCount)}
      onClick={() =>
        useActivityBarStore
          .getState()
          .actions.toggleItem("people")
      }
    >
      <span
        className="inline-block w-[6px] h-[6px] rounded-full"
        style={{ backgroundColor: color }}
      />
      <span className={connected ? "text-[#6f7f9a]" : "text-[#6f7f9a]/50"}>
        {statusLabel(connectionState, onlineCount)}
      </span>
    </button>
  );
}
