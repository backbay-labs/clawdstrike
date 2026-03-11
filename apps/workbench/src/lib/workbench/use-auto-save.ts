import { useCallback, useEffect, useRef, useState } from "react";
import { useMultiPolicy } from "./multi-policy-store";

const AUTOSAVE_KEY = "clawdstrike_workbench_autosave";
const PERIODIC_INTERVAL_MS = 30_000;
const DEBOUNCE_DELAY_MS = 2_000;

export interface AutosaveEntry {
  tabId?: string;
  yaml: string;
  filePath: string | null;
  timestamp: number;
  policyName: string;
}

interface AutosavePayload {
  entries: AutosaveEntry[];
}

function isAutosaveEntry(value: unknown): value is AutosaveEntry {
  if (typeof value !== "object" || value === null) return false;

  const entry = value as Record<string, unknown>;
  const hasValidTabId = entry.tabId === undefined || typeof entry.tabId === "string";

  return (
    hasValidTabId &&
    typeof entry.yaml === "string" &&
    typeof entry.timestamp === "number" &&
    typeof entry.policyName === "string" &&
    (entry.filePath === null || typeof entry.filePath === "string")
  );
}

function writeAutosaves(entries: AutosaveEntry[]): void {
  try {
    const payload: AutosavePayload = { entries };
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(payload));
  } catch {
    // Storage full or unavailable — ignore
  }
}

export function readAutosaves(): AutosaveEntry[] {
  try {
    const raw = localStorage.getItem(AUTOSAVE_KEY);
    if (!raw) return [];

    const parsed = JSON.parse(raw) as unknown;

    if (isAutosaveEntry(parsed)) {
      return [parsed];
    }

    if (
      typeof parsed === "object" &&
      parsed !== null &&
      Array.isArray((parsed as { entries?: unknown[] }).entries)
    ) {
      return (parsed as { entries: unknown[] }).entries
        .filter(isAutosaveEntry)
        .sort((a, b) => b.timestamp - a.timestamp);
    }

    return [];
  } catch {
    return [];
  }
}

export function readAutosave(): AutosaveEntry | null {
  return readAutosaves()[0] ?? null;
}

export function clearAutosave(): void {
  try {
    localStorage.removeItem(AUTOSAVE_KEY);
  } catch {
    // ignore
  }
}

export function useAutoSave() {
  const { tabs, multiDispatch } = useMultiPolicy();
  const dirtyTabs = tabs.filter((tab) => tab.dirty);

  const [pendingRecovery, setPendingRecovery] = useState<AutosaveEntry[] | null>(
    null,
  );

  const checkedRef = useRef(false);
  useEffect(() => {
    if (checkedRef.current) return;
    checkedRef.current = true;

    const entries = readAutosaves();
    if (entries.length === 0) return;
    setPendingRecovery(entries);
  }, []);

  const lastWriteRef = useRef(0);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const persistDirtyTabs = useCallback(() => {
    if (dirtyTabs.length === 0) return;

    const timestamp = Date.now();
    writeAutosaves(
      dirtyTabs.map((tab) => ({
        tabId: tab.id,
        yaml: tab.yaml,
        filePath: tab.filePath,
        timestamp,
        policyName: tab.policy.name || tab.name,
      })),
    );
    lastWriteRef.current = timestamp;
  }, [dirtyTabs]);

  useEffect(() => {
    if (dirtyTabs.length === 0) return;

    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    debounceRef.current = setTimeout(() => {
      persistDirtyTabs();
    }, DEBOUNCE_DELAY_MS);

    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
        debounceRef.current = null;
      }
    };
  }, [dirtyTabs, persistDirtyTabs]);

  useEffect(() => {
    const interval = setInterval(() => {
      if (Date.now() - lastWriteRef.current < 5000) return;
      if (dirtyTabs.length > 0) {
        persistDirtyTabs();
      }
    }, PERIODIC_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [dirtyTabs.length, persistDirtyTabs]);

  const hadDirtyTabsRef = useRef(dirtyTabs.length > 0);
  useEffect(() => {
    const hasDirtyTabs = dirtyTabs.length > 0;
    if (hadDirtyTabsRef.current && !hasDirtyTabs) {
      clearAutosave();
      setPendingRecovery(null);
    }
    hadDirtyTabsRef.current = hasDirtyTabs;
  }, [dirtyTabs.length]);

  const dismissRecovery = useCallback(() => {
    clearAutosave();
    setPendingRecovery(null);
  }, []);

  const restoreRecovery = useCallback(() => {
    if (!pendingRecovery || pendingRecovery.length === 0) return;
    multiDispatch({ type: "RESTORE_AUTOSAVE_ENTRIES", entries: pendingRecovery });
    clearAutosave();
    setPendingRecovery(null);
  }, [multiDispatch, pendingRecovery]);

  return {
    pendingRecovery,
    dismissRecovery,
    restoreRecovery,
  };
}
