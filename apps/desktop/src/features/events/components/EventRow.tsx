/**
 * EventRow - Single event row in the event stream
 */
import { clsx } from "clsx";
import type { ReactNode } from "react";
import type { AuditEvent } from "@/types/events";

interface EventRowProps {
  event: AuditEvent;
  isSelected: boolean;
  onSelect: () => void;
}

export function EventRow({ event, isSelected, onSelect }: EventRowProps) {
  const time = new Date(event.timestamp).toLocaleTimeString();

  return (
    <button
      onClick={onSelect}
      className={clsx(
        "w-full flex items-center gap-3 px-4 py-3 text-left transition-colors",
        isSelected
          ? "bg-sdr-accent-blue/10 border-l-2 border-sdr-accent-blue"
          : "hover:bg-sdr-bg-tertiary border-l-2 border-transparent"
      )}
    >
      {/* Timestamp */}
      <span className="text-xs text-sdr-text-muted font-mono w-20 shrink-0">{time}</span>

      {/* Action type icon */}
      <ActionTypeIcon type={event.action_type} />

      {/* Decision badge */}
      <DecisionBadge decision={event.decision} />

      {/* Target */}
      <span className="flex-1 truncate text-sm text-sdr-text-primary font-mono">
        {event.target ?? event.event_type}
      </span>

      {/* Guard */}
      {event.guard && (
        <span className="text-xs text-sdr-text-muted bg-sdr-bg-tertiary px-2 py-0.5 rounded">
          {event.guard}
        </span>
      )}

      {/* Severity */}
      {event.severity && event.severity !== "info" && (
        <SeverityBadge severity={event.severity} />
      )}

      {/* Agent */}
      {event.agent_id && (
        <span className="text-xs text-sdr-text-muted truncate max-w-24">
          {event.agent_id}
        </span>
      )}
    </button>
  );
}

function ActionTypeIcon({ type }: { type: string }) {
  const icons: Record<string, ReactNode> = {
    file_access: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
        <path d="M14 2v6h6M16 13H8M16 17H8M10 9H8" />
      </svg>
    ),
    file_write: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7" />
        <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z" />
      </svg>
    ),
    egress: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10" />
        <path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
      </svg>
    ),
    shell: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="4 17 10 11 4 5" />
        <line x1="12" y1="19" x2="20" y2="19" />
      </svg>
    ),
    mcp_tool: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z" />
      </svg>
    ),
    patch: (
      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 3v18M3 12h18" />
        <rect x="3" y="3" width="18" height="18" rx="2" />
      </svg>
    ),
  };

  return (
    <span className="text-sdr-text-muted" title={type}>
      {icons[type] ?? icons.file_access}
    </span>
  );
}

function DecisionBadge({ decision }: { decision: string }) {
  const isAllowed = decision === "allowed";

  return (
    <span
      className={clsx(
        "shrink-0 px-2 py-0.5 text-xs font-medium rounded",
        isAllowed ? "bg-verdict-allowed/20 text-verdict-allowed" : "bg-verdict-blocked/20 text-verdict-blocked"
      )}
    >
      {isAllowed ? "ALLOW" : "BLOCK"}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    warning: "bg-severity-warning/20 text-severity-warning",
    error: "bg-severity-error/20 text-severity-error",
    critical: "bg-severity-critical/20 text-severity-critical",
  };

  return (
    <span className={clsx("px-2 py-0.5 text-xs font-medium rounded uppercase", colors[severity])}>
      {severity}
    </span>
  );
}
