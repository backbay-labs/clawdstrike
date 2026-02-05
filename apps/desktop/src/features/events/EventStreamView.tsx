/**
 * EventStreamView - Real-time policy decisions and audit log
 */
import { useState, useMemo } from "react";
import { clsx } from "clsx";
import { useConnection } from "@/context/ConnectionContext";
import { useEventStream } from "@/services/eventStream";
import type { AuditEvent, ActionType, Decision, Severity, DaemonEvent } from "@/types/events";
import { EventRow } from "./components/EventRow";
import { EventFilters } from "./components/EventFilters";
import { ReceiptPanel } from "./components/ReceiptPanel";

export interface EventFilter {
  actionType?: ActionType;
  decision?: Decision;
  severity?: Severity;
  guard?: string;
  search?: string;
}

export function EventStreamView() {
  const { status, daemonUrl } = useConnection();
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [filter, setFilter] = useState<EventFilter>({});

  const { events, isConnected, isLive, toggleLive, clearEvents } = useEventStream({
    baseUrl: daemonUrl,
    enabled: status === "connected",
  });

  // Extract audit events from daemon events
  const auditEvents = useMemo(() => {
    return events
      .map((event, index) => toAuditEvent(event, index))
      .filter((event): event is AuditEvent => event !== null);
  }, [events]);

  // Apply filters
  const filteredEvents = useMemo(() => {
    return auditEvents.filter((event) => {
      if (filter.actionType && event.action_type !== filter.actionType) return false;
      if (filter.decision && event.decision !== filter.decision) return false;
      if (filter.severity && event.severity !== filter.severity) return false;
      if (filter.guard && event.guard !== filter.guard) return false;
      if (filter.search) {
        const search = filter.search.toLowerCase();
        const matchTarget = event.target?.toLowerCase().includes(search);
        const matchMessage = event.message?.toLowerCase().includes(search);
        const matchAgent = event.agent_id?.toLowerCase().includes(search);
        if (!matchTarget && !matchMessage && !matchAgent) return false;
      }
      return true;
    });
  }, [auditEvents, filter]);

  // Get unique guards for filter dropdown
  const guards = useMemo(() => {
    const guardSet = new Set(auditEvents.map((e) => e.guard).filter(Boolean));
    return Array.from(guardSet) as string[];
  }, [auditEvents]);

  if (status !== "connected") {
    return (
      <div className="flex flex-col items-center justify-center h-full text-sdr-text-secondary">
        <DisconnectedIcon />
        <p className="mt-4 text-lg">Not connected to daemon</p>
        <p className="mt-2 text-sm text-sdr-text-muted">
          Go to Settings to configure the connection
        </p>
      </div>
    );
  }

  return (
    <div className="flex h-full">
      {/* Main event list */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-sdr-border bg-sdr-bg-secondary">
          <div className="flex items-center gap-3">
            <h1 className="text-lg font-semibold text-sdr-text-primary">Event Stream</h1>
            <StatusBadge isConnected={isConnected} isLive={isLive} />
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={toggleLive}
              className={clsx(
                "px-3 py-1.5 text-sm font-medium rounded-md transition-colors",
                isLive
                  ? "bg-sdr-accent-green/20 text-sdr-accent-green"
                  : "bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary"
              )}
            >
              {isLive ? "Live" : "Paused"}
            </button>
            <button
              onClick={clearEvents}
              className="px-3 py-1.5 text-sm text-sdr-text-secondary hover:text-sdr-text-primary bg-sdr-bg-tertiary rounded-md transition-colors"
            >
              Clear
            </button>
          </div>
        </div>

        {/* Filters */}
        <EventFilters filter={filter} onFilterChange={setFilter} guards={guards} />

        {/* Event list */}
        <div className="flex-1 overflow-y-auto">
          {filteredEvents.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-sdr-text-muted">
              <p>No events yet</p>
              <p className="text-sm mt-1">Waiting for policy checks...</p>
            </div>
          ) : (
            <div className="divide-y divide-sdr-border-subtle">
              {filteredEvents.map((event) => (
                <EventRow
                  key={event.id}
                  event={event}
                  isSelected={selectedEvent?.id === event.id}
                  onSelect={() => setSelectedEvent(event)}
                />
              ))}
            </div>
          )}
        </div>

        {/* Stats footer */}
        <div className="flex items-center justify-between px-4 py-2 border-t border-sdr-border bg-sdr-bg-secondary text-xs text-sdr-text-muted">
          <span>{filteredEvents.length} events</span>
          <span>
            {auditEvents.filter((e) => e.decision === "allowed").length} allowed /{" "}
            {auditEvents.filter((e) => e.decision === "blocked").length} blocked
          </span>
        </div>
      </div>

      {/* Receipt detail panel */}
      {selectedEvent && (
        <ReceiptPanel event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  );
}

function StatusBadge({ isConnected, isLive }: { isConnected: boolean; isLive: boolean }) {
  if (!isConnected) {
    return (
      <span className="flex items-center gap-1.5 px-2 py-1 text-xs bg-sdr-accent-red/20 text-sdr-accent-red rounded-full">
        <span className="w-1.5 h-1.5 rounded-full bg-current" />
        Disconnected
      </span>
    );
  }

  return (
    <span
      className={clsx(
        "flex items-center gap-1.5 px-2 py-1 text-xs rounded-full",
        isLive
          ? "bg-sdr-accent-green/20 text-sdr-accent-green"
          : "bg-sdr-accent-amber/20 text-sdr-accent-amber"
      )}
    >
      <span className={clsx("w-1.5 h-1.5 rounded-full bg-current", isLive && "animate-pulse")} />
      {isLive ? "Streaming" : "Paused"}
    </span>
  );
}

function DisconnectedIcon() {
  return (
    <svg
      width="48"
      height="48"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M16.72 11.06A10.94 10.94 0 0119 12.55" />
      <path d="M5 12.55a10.94 10.94 0 015.17-2.39" />
      <path d="M10.71 5.05A16 16 0 0122 8.05" />
      <path d="M2 8.05a16 16 0 015.68-1.77" />
      <path d="M12 20h.01" />
      <path d="M2 2l20 20" />
    </svg>
  );
}

function toAuditEvent(event: DaemonEvent, index: number): AuditEvent | null {
  if (event.type !== "check" && event.type !== "violation" && event.type !== "eval") {
    return null;
  }

  const payload = event.data;
  if (!payload || typeof payload !== "object") {
    return null;
  }

  const data = payload as Record<string, unknown>;
  const allowed = typeof data.allowed === "boolean" ? data.allowed : event.type !== "violation";
  const severity = normalizeSeverity(data.severity, allowed);

  return {
    id:
      (typeof data.event_id === "string" && data.event_id) ||
      `${event.type}-${event.timestamp}-${index}`,
    timestamp: event.timestamp,
    event_type: event.type,
    action_type: normalizeActionType(data.action_type ?? data.event_type),
    target: typeof data.target === "string" ? data.target : undefined,
    decision: allowed ? "allowed" : "blocked",
    guard: typeof data.guard === "string" ? data.guard : undefined,
    severity,
    message: typeof data.message === "string" ? data.message : undefined,
    metadata: data,
  };
}

function normalizeActionType(value: unknown): ActionType {
  if (value === "file_access") return "file_access";
  if (value === "file_write") return "file_write";
  if (value === "egress" || value === "network_egress") return "egress";
  if (value === "shell" || value === "shell_command") return "shell";
  if (value === "mcp_tool" || value === "tool_call") return "mcp_tool";
  if (value === "patch") return "patch";
  if (value === "secret_access") return "secret_access";
  return "custom";
}

function normalizeSeverity(value: unknown, allowed: boolean): Severity {
  if (value === "info" || value === "warning" || value === "error" || value === "critical") {
    return value;
  }
  return allowed ? "info" : "error";
}
