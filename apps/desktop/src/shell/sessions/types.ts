/**
 * Session Types - Core data model for app sessions
 */
import type { AppId } from "../plugins/types";

export type SessionStatus = "idle" | "running" | "error" | "completed";

export interface Session {
  id: string;
  appId: AppId;
  title: string;
  subtitle?: string;
  pinned: boolean;
  archived: boolean;
  status: SessionStatus;
  data: unknown;
  createdAt: number;
  updatedAt: number;
  lastOpenedAt: number;
}

export interface SessionFilter {
  appId?: AppId;
  pinned?: boolean;
  archived?: boolean;
  status?: SessionStatus;
}

export interface SessionsState {
  sessions: Map<string, Session>;
  activeSessionId: string | null;
  activeAppId: AppId | null;
}

export interface SessionActions {
  createSession: (appId: AppId, title?: string, data?: unknown) => Session;
  updateSession: (id: string, updates: Partial<Session>) => void;
  deleteSession: (id: string) => void;
  setActiveSession: (id: string | null) => void;
  setActiveApp: (appId: AppId) => void;
  togglePin: (id: string) => void;
  archiveSession: (id: string) => void;
  getSessions: (filter?: SessionFilter) => Session[];
  getSession: (id: string) => Session | null;
}
