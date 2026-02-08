/**
 * useSessionState - Persist per-view state in the active session
 *
 * Stores typed key-value pairs in the session's `data` field (as a Record).
 * On session change, restores stored state or falls back to the provided default.
 * Persists automatically via the existing SessionStore localStorage mechanism.
 */
import { useCallback, useSyncExternalStore } from "react";
import { sessionStore } from "./sessionStore";

const subscribe = sessionStore.subscribe.bind(sessionStore);

function getStateValue<T>(key: string, defaultValue: T): T {
  const activeId = sessionStore.getActiveSessionId();
  if (!activeId) return defaultValue;

  const session = sessionStore.getSession(activeId);
  if (!session) return defaultValue;

  const data = session.data;
  if (data === null || data === undefined || typeof data !== "object") {
    return defaultValue;
  }

  const record = data as Record<string, unknown>;
  if (!(key in record)) return defaultValue;

  return record[key] as T;
}

export function useSessionState<T>(key: string, defaultValue: T): [T, (value: T) => void] {
  const getSnapshot = useCallback(() => {
    return getStateValue(key, defaultValue);
  }, [key, defaultValue]);

  const value = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);

  const setValue = useCallback(
    (newValue: T) => {
      const activeId = sessionStore.getActiveSessionId();
      if (!activeId) return;

      const session = sessionStore.getSession(activeId);
      if (!session) return;

      const existing =
        session.data !== null && session.data !== undefined && typeof session.data === "object"
          ? (session.data as Record<string, unknown>)
          : {};

      sessionStore.updateSession(activeId, {
        data: { ...existing, [key]: newValue },
      });
    },
    [key]
  );

  return [value, setValue];
}
