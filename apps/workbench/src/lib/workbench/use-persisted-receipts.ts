import { useState, useEffect, useRef, useCallback } from "react";
import type { Receipt } from "./types";

const STORAGE_KEY = "clawdstrike_workbench_receipts";
const MAX_RECEIPTS = 1000;
const DEBOUNCE_MS = 500;

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

function readReceipts(): Receipt[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // Lightweight shape check — only keep entries that look like receipts
    return (parsed as unknown[]).filter(
      (r): r is Receipt =>
        typeof r === "object" &&
        r !== null &&
        typeof (r as Receipt).id === "string" &&
        typeof (r as Receipt).verdict === "string" &&
        typeof (r as Receipt).guard === "string",
    );
  } catch {
    return [];
  }
}

function writeReceipts(receipts: Receipt[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(receipts));
  } catch {
    // Storage full or unavailable — ignore
  }
}

/**
 * Enforce the FIFO cap: keep the newest `max` receipts.
 * Receipts are stored newest-first, so we simply truncate.
 */
function enforceCap(receipts: Receipt[], max: number): Receipt[] {
  if (receipts.length <= max) return receipts;
  return receipts.slice(0, max);
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Drop-in replacement for `useState<Receipt[]>([])` that persists receipts
 * to localStorage.
 *
 * - Hydrates from localStorage on mount.
 * - Debounces writes (500 ms) to avoid thrashing on rapid updates.
 * - Caps the list at 1 000 entries with FIFO eviction (oldest removed first).
 */
export function usePersistedReceipts() {
  // Lazy initialiser — only reads localStorage once on mount
  const [receipts, setReceiptsRaw] = useState<Receipt[]>(() => readReceipts());

  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Persist to localStorage whenever `receipts` changes (debounced).
  useEffect(() => {
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }
    debounceRef.current = setTimeout(() => {
      writeReceipts(receipts);
    }, DEBOUNCE_MS);

    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
        debounceRef.current = null;
      }
    };
  }, [receipts]);

  // Wrapped setter that enforces the FIFO cap.
  const setReceipts: typeof setReceiptsRaw = useCallback(
    (action) => {
      setReceiptsRaw((prev) => {
        const next = typeof action === "function" ? action(prev) : action;
        return enforceCap(next, MAX_RECEIPTS);
      });
    },
    [],
  );

  // Convenience: clear both state and storage immediately (no debounce).
  const clearReceipts = useCallback(() => {
    setReceiptsRaw([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
  }, []);

  return { receipts, setReceipts, clearReceipts };
}
