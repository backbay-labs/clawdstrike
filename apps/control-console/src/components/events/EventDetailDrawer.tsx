import { AnimatePresence, motion } from "framer-motion";
import { useEffect } from "react";
import type { SSEEvent } from "../../hooks/useSSE";
import { NoiseGrain, Stamp } from "../ui";

interface AuditEventLike {
  id?: string;
  _id?: number;
  event_type?: string;
  action_type?: string;
  target?: string;
  allowed?: boolean;
  decision?: string;
  guard?: string;
  policy_hash?: string;
  session_id?: string;
  agent_id?: string;
  timestamp: string;
  severity?: string;
  message?: string;
}

type DrawerEvent = SSEEvent | AuditEventLike;

function getDecision(event: DrawerEvent): "allowed" | "blocked" | "warn" | null {
  if ("decision" in event && event.decision) {
    if (event.decision === "blocked") return "blocked";
    if (event.decision === "warn") return "warn";
    if (event.decision === "allowed") return "allowed";
    return null;
  }
  if ("allowed" in event) {
    if (event.allowed === true) return "allowed";
    if (event.allowed === false) return "blocked";
  }
  return null;
}

function getEventId(event: DrawerEvent): string {
  if ("id" in event && event.id) return event.id;
  if ("_id" in event && event._id != null) return String(event._id);
  return event.timestamp;
}

export function EventDetailDrawer({
  event,
  onClose,
}: {
  event: DrawerEvent | null;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!event) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [event, onClose]);

  const decision = event ? getDecision(event) : null;

  return (
    <AnimatePresence>
      {event && (
        <motion.div
          key={getEventId(event)}
          initial={{ x: "100%" }}
          animate={{ x: 0 }}
          exit={{ x: "100%" }}
          transition={{ type: "spring", damping: 25, stiffness: 300 }}
          className="glass-panel"
          style={{
            position: "absolute",
            top: 0,
            right: 0,
            bottom: 0,
            width: 420,
            zIndex: 50,
            overflow: "auto",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <NoiseGrain />
          {/* Header */}
          <div
            style={{
              position: "relative",
              zIndex: 2,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "16px 20px",
              borderBottom: "1px solid var(--slate)",
            }}
          >
            <span
              className="font-mono"
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: "0.1em",
                color: "var(--gold)",
              }}
            >
              Event Detail
            </span>
            <button
              type="button"
              onClick={onClose}
              style={{
                background: "none",
                border: "none",
                color: "var(--muted)",
                cursor: "pointer",
                fontSize: 18,
                lineHeight: 1,
              }}
            >
              &#10005;
            </button>
          </div>

          {/* Summary */}
          <div
            style={{
              position: "relative",
              zIndex: 2,
              padding: "16px 20px",
              display: "flex",
              flexDirection: "column",
              gap: 10,
            }}
          >
            <Row label="Type" value={event.event_type ?? "-"} />
            <Row label="Action" value={event.action_type ?? "-"} />
            <Row label="Target" value={event.target ?? "-"} />
            <Row label="Guard" value={event.guard ?? "-"} />
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span
                className="font-mono"
                style={{
                  fontSize: 10,
                  textTransform: "uppercase",
                  letterSpacing: "0.1em",
                  color: "rgba(214,177,90,0.55)",
                  width: 80,
                  flexShrink: 0,
                }}
              >
                Decision
              </span>
              {decision ? (
                <Stamp variant={decision}>{decision.toUpperCase()}</Stamp>
              ) : (
                <span style={{ color: "rgba(154,167,181,0.3)", fontSize: 13 }}>-</span>
              )}
            </div>
            <Row label="Timestamp" value={new Date(event.timestamp).toLocaleString()} />
            {event.session_id && <Row label="Session" value={event.session_id} />}
            {event.agent_id && <Row label="Agent" value={event.agent_id} />}
            {event.policy_hash && <Row label="Policy Hash" value={event.policy_hash} />}
            {"severity" in event && event.severity && (
              <Row label="Severity" value={event.severity} />
            )}
            {"message" in event && event.message && <Row label="Message" value={event.message} />}
          </div>

          {/* Raw JSON */}
          <div
            style={{
              position: "relative",
              zIndex: 2,
              padding: "0 20px 20px",
              flex: 1,
            }}
          >
            <span
              className="font-mono"
              style={{
                fontSize: 10,
                textTransform: "uppercase",
                letterSpacing: "0.1em",
                color: "rgba(214,177,90,0.55)",
                display: "block",
                marginBottom: 8,
              }}
            >
              Raw JSON
            </span>
            <pre
              className="font-mono"
              style={{
                fontSize: 11,
                color: "rgba(229,231,235,0.7)",
                background: "rgba(0,0,0,0.3)",
                borderRadius: 8,
                padding: 12,
                overflow: "auto",
                maxHeight: 300,
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
      <span
        className="font-mono"
        style={{
          fontSize: 10,
          textTransform: "uppercase",
          letterSpacing: "0.1em",
          color: "rgba(214,177,90,0.55)",
          width: 80,
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{ fontSize: 13, color: "var(--text)", wordBreak: "break-all" }}
      >
        {value}
      </span>
    </div>
  );
}
