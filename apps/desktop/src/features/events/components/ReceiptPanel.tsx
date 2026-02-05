/**
 * ReceiptPanel - Detailed view of an audit event with receipt
 */
import { useState } from "react";
import { clsx } from "clsx";
import type { AuditEvent } from "@/types/events";

interface ReceiptPanelProps {
  event: AuditEvent;
  onClose: () => void;
}

export function ReceiptPanel({ event, onClose }: ReceiptPanelProps) {
  const [activeTab, setActiveTab] = useState<"details" | "json">("details");

  return (
    <div className="w-96 border-l border-sdr-border bg-sdr-bg-secondary flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-sdr-border">
        <h2 className="font-medium text-sdr-text-primary">Event Details</h2>
        <button
          onClick={onClose}
          className="p-1 text-sdr-text-muted hover:text-sdr-text-primary rounded"
        >
          <CloseIcon />
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-sdr-border">
        <TabButton
          active={activeTab === "details"}
          onClick={() => setActiveTab("details")}
          label="Details"
        />
        <TabButton
          active={activeTab === "json"}
          onClick={() => setActiveTab("json")}
          label="JSON"
        />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {activeTab === "details" ? (
          <DetailsTab event={event} />
        ) : (
          <JsonTab event={event} />
        )}
      </div>

      {/* Footer actions */}
      <div className="flex items-center gap-2 px-4 py-3 border-t border-sdr-border">
        <button className="flex-1 px-3 py-2 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors">
          Copy JSON
        </button>
        <button className="flex-1 px-3 py-2 text-sm bg-sdr-bg-tertiary text-sdr-text-secondary hover:text-sdr-text-primary rounded-md transition-colors">
          Export
        </button>
      </div>
    </div>
  );
}

function DetailsTab({ event }: { event: AuditEvent }) {
  const time = new Date(event.timestamp);

  return (
    <div className="space-y-4">
      {/* Decision */}
      <Section title="Decision">
        <div className="flex items-center gap-2">
          <span
            className={clsx(
              "px-2 py-1 text-sm font-medium rounded",
              event.decision === "allowed"
                ? "bg-verdict-allowed/20 text-verdict-allowed"
                : "bg-verdict-blocked/20 text-verdict-blocked"
            )}
          >
            {event.decision.toUpperCase()}
          </span>
          {event.severity && event.severity !== "info" && (
            <span
              className={clsx(
                "px-2 py-1 text-sm rounded uppercase",
                event.severity === "critical"
                  ? "bg-severity-critical/20 text-severity-critical"
                  : event.severity === "error"
                    ? "bg-severity-error/20 text-severity-error"
                    : "bg-severity-warning/20 text-severity-warning"
              )}
            >
              {event.severity}
            </span>
          )}
        </div>
      </Section>

      {/* Guard */}
      {event.guard && (
        <Section title="Guard">
          <code className="text-sm text-sdr-accent-blue">{event.guard}</code>
        </Section>
      )}

      {/* Message */}
      {event.message && (
        <Section title="Message">
          <p className="text-sm text-sdr-text-secondary">{event.message}</p>
        </Section>
      )}

      {/* Action */}
      <Section title="Action">
        <div className="space-y-2">
          <Row label="Type" value={event.action_type} />
          {event.target && <Row label="Target" value={event.target} mono />}
        </div>
      </Section>

      {/* Timestamp */}
      <Section title="Timestamp">
        <div className="space-y-1">
          <p className="text-sm text-sdr-text-primary font-mono">{time.toISOString()}</p>
          <p className="text-xs text-sdr-text-muted">{time.toLocaleString()}</p>
        </div>
      </Section>

      {/* Session/Agent */}
      {(event.session_id || event.agent_id) && (
        <Section title="Context">
          <div className="space-y-2">
            {event.session_id && <Row label="Session" value={event.session_id} mono />}
            {event.agent_id && <Row label="Agent" value={event.agent_id} mono />}
          </div>
        </Section>
      )}

      {/* Verification placeholder */}
      <Section title="Verification">
        <div className="flex items-center gap-2 text-sm">
          <VerifiedIcon className="w-4 h-4 text-sdr-accent-green" />
          <span className="text-sdr-text-secondary">Signature valid</span>
        </div>
      </Section>
    </div>
  );
}

function JsonTab({ event }: { event: AuditEvent }) {
  const json = JSON.stringify(event, null, 2);

  return (
    <pre className="text-xs font-mono text-sdr-text-secondary whitespace-pre-wrap break-all">
      {json}
    </pre>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-medium text-sdr-text-muted uppercase tracking-wide mb-2">
        {title}
      </h3>
      {children}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-2">
      <span className="text-xs text-sdr-text-muted w-16 shrink-0">{label}</span>
      <span
        className={clsx(
          "text-sm text-sdr-text-primary break-all",
          mono && "font-mono"
        )}
      >
        {value}
      </span>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  label,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        "flex-1 px-4 py-2 text-sm font-medium transition-colors",
        active
          ? "text-sdr-accent-blue border-b-2 border-sdr-accent-blue"
          : "text-sdr-text-muted hover:text-sdr-text-primary"
      )}
    >
      {label}
    </button>
  );
}

function CloseIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  );
}

function VerifiedIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
      <path d="M22 4L12 14.01l-3-3" />
    </svg>
  );
}
