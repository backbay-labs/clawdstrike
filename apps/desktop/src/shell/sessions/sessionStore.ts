/**
 * Session Store - In-memory store with localStorage persistence
 */
import type { AppId } from "../plugins/types";
import type { Session, SessionFilter, SessionStatus, StrikecellSessionKind } from "./types";

const STORAGE_KEY = "sdr:sessions";
const DATA_VERSION = 1;

function generateId(): string {
  return `sess_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

const KNOWN_APP_IDS = new Set<AppId>([
  "nexus",
  "operations",
  "events",
  "policies",
  "policy-tester",
  "swarm",
  "marketplace",
  "workflows",
  "threat-radar",
  "attack-graph",
  "network-map",
  "security-overview",
]);

/** Map legacy persisted app IDs from prior versions to current equivalents. */
const LEGACY_APP_ID_MAP: Record<string, AppId> = {
  "cyber-nexus": "nexus",
  settings: "operations",
  forensics: "events",
  "forensics-river": "events",
  "policy-workbench": "policies",
  strikecell: "swarm",
};

const KNOWN_SESSION_STATUSES = new Set<SessionStatus>(["idle", "running", "error", "completed"]);
const KNOWN_STRIKECELL_KINDS = new Set<StrikecellSessionKind>(["chat", "experiment", "red-team"]);

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function asBoolean(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function asNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function asSessionStatus(value: unknown): SessionStatus {
  return typeof value === "string" && KNOWN_SESSION_STATUSES.has(value as SessionStatus)
    ? (value as SessionStatus)
    : "idle";
}

function asStrikecellKind(value: unknown): StrikecellSessionKind | undefined {
  return typeof value === "string" && KNOWN_STRIKECELL_KINDS.has(value as StrikecellSessionKind)
    ? (value as StrikecellSessionKind)
    : undefined;
}

function asAppId(value: unknown): AppId | null {
  if (typeof value !== "string") return null;
  if (KNOWN_APP_IDS.has(value as AppId)) return value as AppId;
  // Fall back to legacy mapping so persisted sessions from prior versions are preserved.
  const mapped = LEGACY_APP_ID_MAP[value];
  return mapped ?? null;
}

function normalizeStoredSession(raw: unknown): Session | null {
  if (!raw || typeof raw !== "object") return null;
  const record = raw as Record<string, unknown>;

  const id = asString(record.id);
  const appId = asAppId(record.appId);
  if (!id || !appId) return null;

  const now = Date.now();
  return {
    id,
    appId,
    title: asString(record.title) ?? `New ${appId} session`,
    subtitle: asString(record.subtitle) ?? undefined,
    strikecellId: asString(record.strikecellId) ?? undefined,
    strikecellKind: asStrikecellKind(record.strikecellKind),
    pinned: asBoolean(record.pinned),
    archived: asBoolean(record.archived),
    status: asSessionStatus(record.status),
    data: record.data ?? null,
    createdAt: asNumber(record.createdAt, now),
    updatedAt: asNumber(record.updatedAt, now),
    lastOpenedAt: asNumber(record.lastOpenedAt, now),
  };
}

export class SessionStore {
  private sessions: Map<string, Session> = new Map();
  private activeSessionId: string | null = null;
  private activeAppId: AppId | null = null;
  private listeners: Set<() => void> = new Set();
  private saveScheduled = false;
  // Cache for getSessions to satisfy useSyncExternalStore's referential equality requirement
  private sessionsCache: Map<string, Session[]> = new Map();

  constructor() {
    this.load();
  }

  // === Persistence ===

  private load(): void {
    if (typeof localStorage === "undefined") return;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const data = JSON.parse(raw) as {
          version?: number;
          sessions?: unknown[];
          activeSessionId?: unknown;
          activeAppId?: unknown;
        };
        if (data.version === DATA_VERSION && Array.isArray(data.sessions)) {
          const normalizedSessions = data.sessions
            .map((entry) => normalizeStoredSession(entry))
            .filter((entry): entry is Session => entry !== null);
          this.sessions = new Map(normalizedSessions.map((session) => [session.id, session]));

          const activeSessionId = asString(data.activeSessionId);
          this.activeSessionId =
            activeSessionId && this.sessions.has(activeSessionId) ? activeSessionId : null;

          const activeAppId = asAppId(data.activeAppId);
          this.activeAppId = activeAppId ?? null;
        }
      }
    } catch (e) {
      console.warn("[SessionStore] Failed to load:", e);
    }
  }

  private scheduleSave(): void {
    if (this.saveScheduled) return;
    this.saveScheduled = true;
    setTimeout(() => {
      this.saveNow();
      this.saveScheduled = false;
    }, 500);
  }

  private saveNow(): void {
    if (typeof localStorage === "undefined") return;
    try {
      const data = {
        version: DATA_VERSION,
        sessions: Array.from(this.sessions.values()),
        activeSessionId: this.activeSessionId,
        activeAppId: this.activeAppId,
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
    } catch (e) {
      console.warn("[SessionStore] Failed to save:", e);
    }
  }

  // === Subscriptions ===

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify(): void {
    // Invalidate cache on any state change
    this.sessionsCache.clear();
    this.listeners.forEach((fn) => fn());
  }

  // === State Getters ===

  getActiveSessionId(): string | null {
    return this.activeSessionId;
  }

  getActiveAppId(): AppId | null {
    return this.activeAppId;
  }

  getSession(id: string): Session | null {
    return this.sessions.get(id) ?? null;
  }

  getSessions(filter?: SessionFilter): Session[] {
    // Create a cache key from filter
    const cacheKey = filter
      ? `${filter.appId ?? ""}_${filter.pinned ?? ""}_${filter.archived ?? ""}_${filter.status ?? ""}`
      : "__all__";

    // Return cached result if available (maintains referential equality for useSyncExternalStore)
    const cached = this.sessionsCache.get(cacheKey);
    if (cached) return cached;

    let result = Array.from(this.sessions.values());

    if (filter?.appId) {
      result = result.filter((s) => s.appId === filter.appId);
    }
    if (filter?.pinned !== undefined) {
      result = result.filter((s) => s.pinned === filter.pinned);
    }
    if (filter?.archived !== undefined) {
      result = result.filter((s) => s.archived === filter.archived);
    }
    if (filter?.status) {
      result = result.filter((s) => s.status === filter.status);
    }

    // Sort by pinned first, then by lastOpenedAt desc
    result = result.sort((a, b) => {
      if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
      return b.lastOpenedAt - a.lastOpenedAt;
    });

    // Cache and return
    this.sessionsCache.set(cacheKey, result);
    return result;
  }

  // === Mutations ===

  createSession(
    appId: AppId,
    title?: string,
    data?: unknown,
    options?: { strikecellId?: string; strikecellKind?: StrikecellSessionKind },
  ): Session {
    const now = Date.now();
    const session: Session = {
      id: generateId(),
      appId,
      title: title || `New ${appId} session`,
      strikecellId: options?.strikecellId,
      strikecellKind: options?.strikecellKind,
      pinned: false,
      archived: false,
      status: "idle" as SessionStatus,
      data: data ?? null,
      createdAt: now,
      updatedAt: now,
      lastOpenedAt: now,
    };
    this.sessions.set(session.id, session);
    this.activeSessionId = session.id;
    this.scheduleSave();
    this.notify();
    return session;
  }

  updateSession(id: string, updates: Partial<Session>): void {
    const session = this.sessions.get(id);
    if (!session) return;

    const updated = {
      ...session,
      ...updates,
      updatedAt: Date.now(),
    };
    this.sessions.set(id, updated);
    this.scheduleSave();
    this.notify();
  }

  deleteSession(id: string): void {
    if (!this.sessions.has(id)) return;
    this.sessions.delete(id);
    if (this.activeSessionId === id) {
      this.activeSessionId = null;
    }
    this.scheduleSave();
    this.notify();
  }

  setActiveSession(id: string | null): void {
    if (id && !this.sessions.has(id)) return;
    if (this.activeSessionId === id) return;

    this.activeSessionId = id;
    if (id) {
      const session = this.sessions.get(id);
      if (session) {
        const updated: Session = { ...session, lastOpenedAt: Date.now(), updatedAt: Date.now() };
        this.sessions.set(id, updated);
      }
    }
    this.scheduleSave();
    this.notify();
  }

  setActiveApp(appId: AppId): void {
    if (this.activeAppId === appId) return;
    this.activeAppId = appId;
    // Clear active session if it's from a different app
    if (this.activeSessionId) {
      const session = this.sessions.get(this.activeSessionId);
      if (session && session.appId !== appId) {
        this.activeSessionId = null;
      }
    }
    this.scheduleSave();
    this.notify();
  }

  togglePin(id: string): void {
    const session = this.sessions.get(id);
    if (!session) return;
    this.updateSession(id, { pinned: !session.pinned });
  }

  archiveSession(id: string): void {
    this.updateSession(id, { archived: true });
    if (this.activeSessionId === id) {
      this.activeSessionId = null;
    }
    this.notify();
  }
}

// Singleton instance
export const sessionStore = new SessionStore();
