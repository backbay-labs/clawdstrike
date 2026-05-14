import { useState } from "react";
import { useLocalAudit, type LocalAuditEvent } from "@/lib/workbench/local-audit";
import { usePaneStore } from "@/features/panes/pane-store";
import {
  IconFileAnalytics,
  IconTrash,
  IconPlayerPause,
  IconPlayerPlay,
  IconExternalLink,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Color constants (duplicated from audit-log.tsx -- module-private there)
// ---------------------------------------------------------------------------

const SOURCE_COLORS: Record<string, string> = {
  simulator: "#d4a84b",
  receipt: "#3dbf84",
  deploy: "#c45c5c",
  editor: "#6f7f9a",
  settings: "#6f7f9a",
};

const EVENT_TYPE_COLORS: Record<string, string> = {
  "policy.validation.success": "#3dbf84",
  "policy.validation.failure": "#c45c5c",
  "policy.validation.warnings": "#d4a84b",
  "simulation.run": "#d4a84b",
  "simulation.batch": "#d4a84b",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

// ---------------------------------------------------------------------------
// AuditTailPanel
// ---------------------------------------------------------------------------

export function AuditTailPanel() {
  const { events, clear } = useLocalAudit();

  const [paused, setPaused] = useState(false);
  const [pausedEvents, setPausedEvents] = useState<LocalAuditEvent[] | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const handlePauseToggle = () => {
    if (paused) {
      setPaused(false);
      setPausedEvents(null);
    } else {
      setPaused(true);
      setPausedEvents(events.slice(0, 50));
    }
  };

  const displayEvents = paused && pausedEvents ? pausedEvents : events.slice(0, 50);

  // Empty state
  if (displayEvents.length === 0) {
    return (
      <div className="flex flex-col h-full min-h-0">
        <div className="flex-1 flex flex-col items-center justify-center">
          <IconFileAnalytics size={24} className="text-[#6f7f9a]/30" />
          <p className="text-[11px] font-mono text-[#6f7f9a]/40 text-center mt-2">
            No audit events recorded yet. Events appear here as you use the workbench.
          </p>
        </div>
        <Footer eventCount={0} paused={paused} onPauseToggle={handlePauseToggle} onClear={clear} />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Event list */}
      <div
        className="flex-1 min-h-0 overflow-y-auto"
        role="log"
        aria-label="Audit events"
        aria-live={paused ? "off" : "polite"}
      >
        {displayEvents.map((event) => {
          const isExpanded = expandedId === event.id;
          return (
            <EventRow
              key={event.id}
              event={event}
              isExpanded={isExpanded}
              onToggle={() => setExpandedId(isExpanded ? null : event.id)}
            />
          );
        })}
      </div>

      <Footer
        eventCount={events.length}
        paused={paused}
        onPauseToggle={handlePauseToggle}
        onClear={clear}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// EventRow
// ---------------------------------------------------------------------------

function EventRow({
  event,
  isExpanded,
  onToggle,
}: {
  event: LocalAuditEvent;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const sourceColor = SOURCE_COLORS[event.source] ?? "#6f7f9a";
  const eventColor = EVENT_TYPE_COLORS[event.eventType] ?? "#6f7f9a";

  return (
    <>
      <div
        role="row"
        aria-expanded={isExpanded}
        className="flex h-7 items-center gap-2 px-4 cursor-pointer hover:bg-[#131721]/40 transition-colors"
        onClick={onToggle}
      >
        {/* Source badge */}
        <span
          className="shrink-0 rounded px-1.5 py-0.5 text-[9px] font-mono font-semibold uppercase tracking-wider"
          style={{ backgroundColor: `${sourceColor}15`, color: sourceColor }}
        >
          {event.source}
        </span>

        {/* Event type badge */}
        <span
          className="shrink-0 rounded px-1.5 py-0.5 text-[9px] font-mono font-semibold uppercase tracking-wider"
          style={{ backgroundColor: `${eventColor}15`, color: eventColor }}
        >
          {event.eventType}
        </span>

        {/* Summary */}
        <span className="text-[10px] font-mono text-[#ece7dc]/60 truncate flex-1">
          {event.summary}
        </span>

        {/* Relative timestamp */}
        <span className="text-[9px] font-mono text-[#6f7f9a]/40 shrink-0">
          {relativeTime(event.timestamp)}
        </span>
      </div>

      {/* Expanded detail */}
      {isExpanded && event.details && Object.keys(event.details).length > 0 && (
        <pre className="max-h-[calc(3*1.5em)] overflow-hidden text-[9px] font-mono text-[#6f7f9a]/40 px-4 py-1 bg-[#0b0d13]">
          {JSON.stringify(event.details, null, 2)}
        </pre>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

function Footer({
  eventCount,
  paused,
  onPauseToggle,
  onClear,
}: {
  eventCount: number;
  paused: boolean;
  onPauseToggle: () => void;
  onClear: () => void;
}) {
  return (
    <div className="flex h-7 shrink-0 items-center justify-between border-t border-[#202531] bg-[#07090f] px-4">
      {/* Left: counts + status */}
      <div className="flex items-center gap-3">
        <span className="text-[10px] font-mono text-[#6f7f9a]/60">
          {eventCount} events
        </span>
        <span className="text-[10px] font-mono text-[#6f7f9a]/40">
          {paused ? "paused" : "auto-refresh: on"}
        </span>
      </div>

      {/* Right: action buttons */}
      <div className="flex items-center gap-2">
        <button
          type="button"
          aria-label="Clear audit events"
          title="Clear all events"
          className="text-[#6f7f9a]/60 hover:text-[#ece7dc] transition-colors"
          onClick={onClear}
        >
          <IconTrash size={12} stroke={1.8} />
        </button>
        <button
          type="button"
          aria-label={paused ? "Resume auto-refresh" : "Pause auto-refresh"}
          title={paused ? "Resume auto-refresh" : "Pause auto-refresh"}
          className="text-[#6f7f9a]/60 hover:text-[#ece7dc] transition-colors"
          onClick={onPauseToggle}
        >
          {paused ? (
            <IconPlayerPlay size={12} stroke={1.8} />
          ) : (
            <IconPlayerPause size={12} stroke={1.8} />
          )}
        </button>
        <button
          type="button"
          aria-label="Open full Audit Log"
          title="Open full Audit Log"
          className="text-[#6f7f9a]/60 hover:text-[#ece7dc] transition-colors"
          onClick={() => usePaneStore.getState().openApp("/audit", "Audit Log")}
        >
          <IconExternalLink size={12} stroke={1.8} />
        </button>
      </div>
    </div>
  );
}
