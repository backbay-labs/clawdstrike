// apps/workbench/src/features/forensics/components/ForensicsTapePanel.tsx
import type { TapeEvent } from "../types";

// ---------------------------------------------------------------------------
// Mock data — live telemetry deferred pending Tauri bridge work
// ---------------------------------------------------------------------------

const MOCK_EVENTS: TapeEvent[] = [
  { id: "1", timestamp: Date.now() - 12000, kind: "allow", label: "file_read /etc/hosts" },
  { id: "2", timestamp: Date.now() - 8000, kind: "deny", label: "shell_exec rm -rf" },
  { id: "3", timestamp: Date.now() - 4000, kind: "receipt", label: "Ed25519 signed" },
  { id: "4", timestamp: Date.now() - 1000, kind: "probe", label: "station:run scanned" },
];

const KIND_COLOR: Record<TapeEvent["kind"], string> = {
  allow: "#3dbf84",
  deny: "#c45c5c",
  probe: "#7b68ee",
  receipt: "#d4a84b",
};

// ---------------------------------------------------------------------------
// TapeEventCard
// ---------------------------------------------------------------------------

function relativeSeconds(timestamp: number): string {
  const diff = Math.floor((Date.now() - timestamp) / 1000);
  return `${diff}s ago`;
}

function TapeEventCard({ event }: { event: TapeEvent }) {
  const color = KIND_COLOR[event.kind];

  return (
    <article
      className="shrink-0 rounded-md border border-[#202531] bg-[#0f1219] px-3 py-2"
      style={{ width: "160px", minWidth: "160px" }}
    >
      {/* Top row: colored dot + kind label */}
      <div className="flex items-center gap-1.5 mb-1">
        <span
          className="shrink-0 rounded-full"
          style={{
            width: "7px",
            height: "7px",
            backgroundColor: color,
          }}
        />
        <span
          className="text-[9px] font-mono uppercase"
          style={{ color }}
        >
          {event.kind}
        </span>
      </div>

      {/* Event label */}
      <p className="text-[10px] text-[#ece7dc] truncate">{event.label}</p>

      {/* Relative timestamp */}
      <p className="text-[9px] font-mono text-[#6f7f9a]/40 mt-1">
        {relativeSeconds(event.timestamp)}
      </p>
    </article>
  );
}

// ---------------------------------------------------------------------------
// ForensicsTapePanel
// ---------------------------------------------------------------------------

export function ForensicsTapePanel() {
  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Horizontal scrolling timeline row — overscroll-x-contain prevents WebKit rubber-band bounce */}
      <div
        className="flex flex-1 min-h-0 items-center gap-3 overflow-x-auto px-4 overscroll-x-contain"
        style={{ scrollbarWidth: "thin" }}
      >
        {MOCK_EVENTS.map((event) => (
          <TapeEventCard key={event.id} event={event} />
        ))}
      </div>

      {/* Footer deferred notice */}
      <div className="flex h-6 shrink-0 items-center border-t border-[#202531] px-4">
        <span className="text-[9px] font-mono text-[#6f7f9a]/40">
          forensics tape — mock data — live telemetry deferred
        </span>
      </div>
    </div>
  );
}
