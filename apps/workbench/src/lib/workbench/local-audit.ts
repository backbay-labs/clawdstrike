// ---------------------------------------------------------------------------
// Local Audit Trail — localStorage-backed event store for workbench actions
// ---------------------------------------------------------------------------
// P1-6: Captures workbench events locally so the audit log is useful even
// when disconnected from a fleet hushd instance.
// ---------------------------------------------------------------------------

import { useCallback, useSyncExternalStore } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AuditSource =
  | "simulator"
  | "receipt"
  | "deploy"
  | "editor"
  | "settings";

export interface LocalAuditEvent {
  id: string;
  timestamp: string;
  eventType: string;
  source: AuditSource;
  summary: string;
  details?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LS_KEY = "clawdstrike_workbench_audit";
const MAX_EVENTS = 5000;

// ---------------------------------------------------------------------------
// Internal store (singleton, survives across React re-renders)
// ---------------------------------------------------------------------------

let cachedEvents: LocalAuditEvent[] | null = null;
const listeners = new Set<() => void>();

function notifyListeners() {
  for (const fn of listeners) {
    fn();
  }
}

function readFromStorage(): LocalAuditEvent[] {
  if (cachedEvents !== null) return cachedEvents;
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) {
      cachedEvents = [];
      return cachedEvents;
    }
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      console.warn("[local-audit] stored data is not an array, resetting");
      cachedEvents = [];
      return cachedEvents;
    }
    cachedEvents = parsed as LocalAuditEvent[];
    return cachedEvents;
  } catch (e) {
    console.warn("[local-audit] localStorage read failed:", e);
    cachedEvents = [];
    return cachedEvents;
  }
}

function writeToStorage(events: LocalAuditEvent[]) {
  cachedEvents = events;
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(events));
  } catch (e) {
    console.warn("[local-audit] localStorage write failed:", e);
  }
  notifyListeners();
}

// ---------------------------------------------------------------------------
// Public API (non-React)
// ---------------------------------------------------------------------------

/**
 * Emit a new audit event. Prepends to the store (newest first) and
 * enforces the FIFO cap at MAX_EVENTS.
 */
export function emitAuditEvent(
  event: Omit<LocalAuditEvent, "id" | "timestamp">,
): LocalAuditEvent {
  const full: LocalAuditEvent = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    ...event,
  };
  const current = readFromStorage();
  const updated = [full, ...current].slice(0, MAX_EVENTS);
  writeToStorage(updated);
  return full;
}

/** Return all stored events (newest first). */
export function getAuditEvents(): LocalAuditEvent[] {
  return readFromStorage();
}

/** Clear all local audit events. */
export function clearAuditEvents(): void {
  writeToStorage([]);
}

// ---------------------------------------------------------------------------
// React hook
// ---------------------------------------------------------------------------

function subscribe(callback: () => void): () => void {
  listeners.add(callback);
  return () => {
    listeners.delete(callback);
  };
}

function getSnapshot(): LocalAuditEvent[] {
  return readFromStorage();
}

/**
 * React hook that provides the local audit event list and an emit function.
 * Re-renders automatically when events are added or cleared.
 */
export function useLocalAudit() {
  const events = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);

  const emit = useCallback(
    (event: Omit<LocalAuditEvent, "id" | "timestamp">) => {
      return emitAuditEvent(event);
    },
    [],
  );

  const clear = useCallback(() => {
    clearAuditEvents();
  }, []);

  return { events, emit, clear } as const;
}
