import { useEffect, useRef, useCallback, useState } from "react";
import { useWorkbench } from "./multi-policy-store";

const AUTOSAVE_KEY = "clawdstrike_workbench_autosave";
const PERIODIC_INTERVAL_MS = 30_000; // 30 seconds
const DEBOUNCE_DELAY_MS = 2_000; // 2 seconds after last edit

export interface AutosaveEntry {
  yaml: string;
  filePath: string | null;
  timestamp: number;
  policyName: string;
}

function writeAutosave(entry: AutosaveEntry): void {
  try {
    localStorage.setItem(AUTOSAVE_KEY, JSON.stringify(entry));
  } catch {
    // Storage full or unavailable — ignore
  }
}

export function readAutosave(): AutosaveEntry | null {
  try {
    const raw = localStorage.getItem(AUTOSAVE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    // Basic shape validation
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      typeof parsed.yaml === "string" &&
      typeof parsed.timestamp === "number" &&
      typeof parsed.policyName === "string"
    ) {
      return parsed as AutosaveEntry;
    }
    return null;
  } catch {
    return null;
  }
}

export function clearAutosave(): void {
  try {
    localStorage.removeItem(AUTOSAVE_KEY);
  } catch {
    // ignore
  }
}

export function useAutoSave() {
  const { state } = useWorkbench();
  const { yaml, dirty, filePath, activePolicy } = state;

  const [pendingRecovery, setPendingRecovery] = useState<AutosaveEntry | null>(
    null,
  );

  // Check for recoverable autosave on mount (once)
  const checkedRef = useRef(false);
  useEffect(() => {
    if (checkedRef.current) return;
    checkedRef.current = true;

    const entry = readAutosave();
    if (!entry) return;

    // Only offer recovery if the autosave is newer than what we just loaded.
    // The ACTIVE_KEY is always written on yaml change, so if we're loading from
    // it the autosave is only meaningful if it was written *after* the last
    // explicit save (i.e., the user crashed while dirty).
    // Heuristic: if the entry exists at all, the previous session ended without
    // a clean save (because explicit save clears it). Offer recovery.
    setPendingRecovery(entry);
  }, []);

  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!dirty) return;

    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    debounceRef.current = setTimeout(() => {
      writeAutosave({
        yaml,
        filePath,
        timestamp: Date.now(),
        policyName: activePolicy.name,
      });
    }, DEBOUNCE_DELAY_MS);

    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
        debounceRef.current = null;
      }
    };
  }, [yaml, dirty, filePath, activePolicy.name]);

  // Periodic auto-save
  useEffect(() => {
    const interval = setInterval(() => {
      if (dirty) {
        writeAutosave({
          yaml,
          filePath,
          timestamp: Date.now(),
          policyName: activePolicy.name,
        });
      }
    }, PERIODIC_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [yaml, dirty, filePath, activePolicy.name]);

  // Clear autosave when state becomes clean (explicit save)
  const wasDirtyRef = useRef(dirty);
  useEffect(() => {
    // Detect transition from dirty → clean (explicit save happened)
    if (wasDirtyRef.current && !dirty) {
      clearAutosave();
      // Also dismiss any pending recovery banner since the user just saved
      setPendingRecovery(null);
    }
    wasDirtyRef.current = dirty;
  }, [dirty]);

  const dismissRecovery = useCallback(() => {
    clearAutosave();
    setPendingRecovery(null);
  }, []);

  return {
    /** Non-null when a recoverable autosave was found on startup. */
    pendingRecovery,
    /** Call after restoring the autosaved YAML into the editor. */
    dismissRecovery,
  };
}
