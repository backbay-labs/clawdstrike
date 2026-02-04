/**
 * useSessions - React hook for session state
 */
import { useSyncExternalStore, useCallback, useMemo } from "react";
import { sessionStore } from "./sessionStore";
import type { Session, SessionFilter } from "./types";
import type { AppId } from "../plugins/types";

// Stable subscribe function (bound once, not per-render)
const subscribe = sessionStore.subscribe.bind(sessionStore);

export function useSessions(filter?: SessionFilter) {
  const filterAppId = filter?.appId;
  const filterPinned = filter?.pinned;
  const filterArchived = filter?.archived;
  const filterStatus = filter?.status;

  const stableFilter = useMemo<SessionFilter | undefined>(() => {
    if (
      filterAppId === undefined &&
      filterPinned === undefined &&
      filterArchived === undefined &&
      filterStatus === undefined
    ) {
      return undefined;
    }

    return {
      appId: filterAppId,
      pinned: filterPinned,
      archived: filterArchived,
      status: filterStatus,
    };
  }, [filterAppId, filterPinned, filterArchived, filterStatus]);

  // getSnapshot must return the same reference for the same state
  const getSnapshot = useCallback(() => sessionStore.getSessions(stableFilter), [stableFilter]);

  const sessions = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);

  return sessions;
}

export function useActiveSession() {
  const activeId = useSyncExternalStore(
    subscribe,
    () => sessionStore.getActiveSessionId(),
    () => sessionStore.getActiveSessionId()
  );

  const getSession = useCallback(
    () => (activeId ? sessionStore.getSession(activeId) : null),
    [activeId]
  );

  const session = useSyncExternalStore(subscribe, getSession, getSession);

  return session;
}

export function useSession(sessionId: string | null | undefined) {
  const getSession = useCallback(
    () => (sessionId ? sessionStore.getSession(sessionId) : null),
    [sessionId]
  );

  const session = useSyncExternalStore(subscribe, getSession, getSession);
  return session;
}

export function useActiveApp() {
  const activeAppId = useSyncExternalStore(
    subscribe,
    () => sessionStore.getActiveAppId(),
    () => sessionStore.getActiveAppId()
  );

  return activeAppId;
}

export function useSessionActions() {
  const createSession = useCallback((appId: AppId, title?: string, data?: unknown): Session => {
    return sessionStore.createSession(appId, title, data);
  }, []);

  const updateSession = useCallback((id: string, updates: Partial<Session>): void => {
    sessionStore.updateSession(id, updates);
  }, []);

  const deleteSession = useCallback((id: string): void => {
    sessionStore.deleteSession(id);
  }, []);

  const setActiveSession = useCallback((id: string | null): void => {
    sessionStore.setActiveSession(id);
  }, []);

  const setActiveApp = useCallback((appId: AppId): void => {
    sessionStore.setActiveApp(appId);
  }, []);

  const togglePin = useCallback((id: string): void => {
    sessionStore.togglePin(id);
  }, []);

  const archiveSession = useCallback((id: string): void => {
    sessionStore.archiveSession(id);
  }, []);

  const getSession = useCallback((id: string): Session | null => {
    return sessionStore.getSession(id);
  }, []);

  return {
    createSession,
    updateSession,
    deleteSession,
    setActiveSession,
    setActiveApp,
    togglePin,
    archiveSession,
    getSession,
  };
}
