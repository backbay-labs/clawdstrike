import { AnimatePresence, motion } from "framer-motion";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { SSEEvent } from "../../hooks/useSSE";
import { exportAsJSON } from "../../utils/exportData";
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
type IncidentStatus = "open" | "acknowledged" | "resolved";

interface IncidentNote {
  id: string;
  created_at: string;
  note: string;
}

interface IncidentRecord {
  incident_id: string;
  event_id: string;
  status: IncidentStatus;
  owner?: string;
  notes: IncidentNote[];
  created_at: string;
  updated_at: string;
  acknowledged_at?: string;
  resolved_at?: string;
}

const INCIDENT_STORE_KEY = "cs.incident.workflow.v1";

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

function buildDefaultIncident(eventId: string, event: DrawerEvent): IncidentRecord {
  const now = new Date().toISOString();
  const seed = eventId.replace(/[^a-zA-Z0-9_-]+/g, "").slice(0, 24) || "event";
  return {
    incident_id: `inc-${seed}`,
    event_id: eventId,
    status: "open",
    notes: [],
    created_at: now,
    updated_at: now,
  };
}

function readIncidentStore(): Record<string, IncidentRecord> {
  try {
    const raw = localStorage.getItem(INCIDENT_STORE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, IncidentRecord>) : {};
  } catch {
    return {};
  }
}

function writeIncidentStore(store: Record<string, IncidentRecord>) {
  localStorage.setItem(INCIDENT_STORE_KEY, JSON.stringify(store));
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

  const eventId = useMemo(() => (event ? getEventId(event) : null), [event]);
  const [incident, setIncident] = useState<IncidentRecord | null>(null);
  const [ownerDraft, setOwnerDraft] = useState("");
  const [noteDraft, setNoteDraft] = useState("");

  useEffect(() => {
    if (!event || !eventId) {
      setIncident(null);
      setOwnerDraft("");
      setNoteDraft("");
      return;
    }

    const store = readIncidentStore();
    const existing = store[eventId] ?? buildDefaultIncident(eventId, event);
    if (!store[eventId]) {
      store[eventId] = existing;
      writeIncidentStore(store);
    }

    setIncident(existing);
    setOwnerDraft(existing.owner ?? "");
    setNoteDraft("");
  }, [event, eventId]);

  const persistIncident = useCallback(
    (next: IncidentRecord) => {
      setIncident(next);
      if (!eventId) return;
      const store = readIncidentStore();
      store[eventId] = next;
      writeIncidentStore(store);
    },
    [eventId],
  );

  const updateIncident = useCallback(
    (mutate: (current: IncidentRecord) => IncidentRecord) => {
      if (!incident) return;
      const next = mutate(incident);
      persistIncident({
        ...next,
        updated_at: new Date().toISOString(),
      });
    },
    [incident, persistIncident],
  );

  const acknowledgeIncident = useCallback(() => {
    updateIncident((current) => {
      if (current.status === "acknowledged" || current.status === "resolved") return current;
      return {
        ...current,
        status: "acknowledged",
        acknowledged_at: new Date().toISOString(),
      };
    });
  }, [updateIncident]);

  const resolveIncident = useCallback(() => {
    updateIncident((current) => ({
      ...current,
      status: "resolved",
      resolved_at: new Date().toISOString(),
    }));
  }, [updateIncident]);

  const assignOwner = useCallback(() => {
    const owner = ownerDraft.trim();
    updateIncident((current) => ({
      ...current,
      owner: owner || undefined,
    }));
  }, [ownerDraft, updateIncident]);

  const addNote = useCallback(() => {
    const note = noteDraft.trim();
    if (!note) return;
    updateIncident((current) => ({
      ...current,
      notes: [
        {
          id: `note-${Date.now()}`,
          created_at: new Date().toISOString(),
          note,
        },
        ...current.notes,
      ].slice(0, 25),
    }));
    setNoteDraft("");
  }, [noteDraft, updateIncident]);

  const exportIncidentBundle = useCallback(() => {
    if (!event || !incident) return;
    const bundle = {
      exported_at: new Date().toISOString(),
      incident,
      event,
    };
    exportAsJSON(
      [bundle],
      `incident-${incident.incident_id}-${incident.status}-${Date.now().toString().slice(-6)}`,
    );
  }, [event, incident]);

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

          {/* Incident workflow */}
          {incident && (
            <div
              style={{
                position: "relative",
                zIndex: 2,
                padding: "0 20px 20px",
                borderTop: "1px solid var(--slate)",
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
                  margin: "12px 0 10px",
                }}
              >
                Incident Workflow
              </span>

              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <span className="font-mono" style={{ fontSize: 11, color: "rgba(154,167,181,0.7)" }}>
                  Status
                </span>
                <Stamp variant={incident.status === "resolved" ? "allowed" : incident.status === "acknowledged" ? "warn" : "blocked"}>
                  {incident.status.toUpperCase()}
                </Stamp>
                {incident.owner && (
                  <span className="font-mono" style={{ fontSize: 10, color: "rgba(154,167,181,0.75)" }}>
                    owner: {incident.owner}
                  </span>
                )}
              </div>

              <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
                <button
                  type="button"
                  onClick={acknowledgeIncident}
                  disabled={incident.status !== "open"}
                  style={incidentButtonStyle(incident.status === "open")}
                >
                  Acknowledge
                </button>
                <button
                  type="button"
                  onClick={resolveIncident}
                  disabled={incident.status === "resolved"}
                  style={incidentButtonStyle(incident.status !== "resolved")}
                >
                  Mark Resolved
                </button>
                <button type="button" onClick={exportIncidentBundle} style={incidentButtonStyle(true)}>
                  Export Bundle
                </button>
              </div>

              <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
                <input
                  type="text"
                  value={ownerDraft}
                  onChange={(e) => setOwnerDraft(e.target.value)}
                  placeholder="Assign owner (name or @handle)"
                  className="glass-input font-mono"
                  style={{ flex: 1, fontSize: 11, padding: "6px 8px" }}
                />
                <button type="button" onClick={assignOwner} style={incidentButtonStyle(true)}>
                  Assign
                </button>
              </div>

              <div style={{ display: "grid", gap: 6 }}>
                <textarea
                  value={noteDraft}
                  onChange={(e) => setNoteDraft(e.target.value)}
                  placeholder="Add incident note..."
                  className="glass-input font-mono"
                  style={{
                    minHeight: 58,
                    resize: "vertical",
                    fontSize: 11,
                    padding: "7px 8px",
                  }}
                />
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <button type="button" onClick={addNote} style={incidentButtonStyle(Boolean(noteDraft.trim()))}>
                    Add Note
                  </button>
                </div>
              </div>

              <div
                style={{
                  marginTop: 10,
                  border: "1px solid rgba(27,34,48,0.75)",
                  borderRadius: 8,
                  maxHeight: 130,
                  overflow: "auto",
                }}
              >
                {incident.notes.length === 0 ? (
                  <div className="font-mono" style={{ padding: 10, fontSize: 11, color: "rgba(154,167,181,0.45)" }}>
                    No notes yet.
                  </div>
                ) : (
                  incident.notes.map((note) => (
                    <div
                      key={note.id}
                      style={{
                        padding: "8px 10px",
                        borderTop: "1px solid rgba(27,34,48,0.55)",
                        display: "grid",
                        gap: 2,
                      }}
                    >
                      <span className="font-mono" style={{ fontSize: 10, color: "rgba(154,167,181,0.55)" }}>
                        {new Date(note.created_at).toLocaleString()}
                      </span>
                      <span className="font-body" style={{ fontSize: 12, color: "rgba(229,231,235,0.82)" }}>
                        {note.note}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

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

function incidentButtonStyle(enabled: boolean): React.CSSProperties {
  return {
    border: "1px solid rgba(214,177,90,0.3)",
    borderRadius: 6,
    background: enabled ? "rgba(214,177,90,0.09)" : "rgba(27,34,48,0.3)",
    color: enabled ? "var(--gold)" : "rgba(154,167,181,0.45)",
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 10,
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    padding: "6px 8px",
    cursor: enabled ? "pointer" : "not-allowed",
  };
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
