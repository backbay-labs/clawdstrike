import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { LensId } from "../workbenchState";
import type { SidebarWakeAnchorKind, SidebarWakeAnchorSource } from "./types";

export interface SidebarWakeAnchor {
  id: string;
  kind: SidebarWakeAnchorKind;
  left: number;
  width: number;
  right: number;
  top: number;
  height: number;
  label?: string | null;
  objectType?: string | null;
  lensHint?: LensId | null;
  source: SidebarWakeAnchorSource;
  updatedAt: number;
}

export interface SidebarWakeAnchorRegistration {
  id: string;
  kind: SidebarWakeAnchorKind;
  element: HTMLElement;
  label?: string | null;
  objectType?: string | null;
  lensHint?: LensId | null;
  source?: SidebarWakeAnchorSource;
}

interface SidebarWakeAnchorContextValue {
  anchor: SidebarWakeAnchor | null;
  setAnchorFromElement: (registration: SidebarWakeAnchorRegistration) => void;
  clearAnchor: (id?: string | null) => void;
}

const CLEAR_LINGER_MS = 260;

const SidebarWakeAnchorCtx = createContext<SidebarWakeAnchorContextValue | null>(null);

export function SidebarWakeAnchorProvider({ children }: { children: ReactNode }) {
  const [anchor, setAnchor] = useState<SidebarWakeAnchor | null>(null);
  const clearTimerRef = useRef<number | null>(null);

  const clearPendingClear = useCallback(() => {
    if (clearTimerRef.current !== null) {
      window.clearTimeout(clearTimerRef.current);
      clearTimerRef.current = null;
    }
  }, []);

  const setAnchorFromElement = useCallback((registration: SidebarWakeAnchorRegistration) => {
    const rect = registration.element.getBoundingClientRect();
    clearPendingClear();
    setAnchor((current) => {
      const next = {
        id: registration.id,
        kind: registration.kind,
        left: rect.left,
        width: rect.width,
        right: rect.right,
        top: rect.top,
        height: rect.height,
        label: registration.label ?? null,
        objectType: registration.objectType ?? null,
        lensHint: registration.lensHint ?? null,
        source: registration.source ?? "hover",
        updatedAt: Date.now(),
      } satisfies SidebarWakeAnchor;

      if (
        current
        && current.id === next.id
        && current.kind === next.kind
        && current.label === next.label
        && current.objectType === next.objectType
        && current.lensHint === next.lensHint
        && current.source === next.source
        && Math.abs(current.left - next.left) < 1
        && Math.abs(current.width - next.width) < 1
        && Math.abs(current.right - next.right) < 1
        && Math.abs(current.top - next.top) < 1
        && Math.abs(current.height - next.height) < 1
      ) {
        return current;
      }

      return next;
    });
  }, [clearPendingClear]);

  const clearAnchor = useCallback((id?: string | null) => {
    if (!id) {
      clearPendingClear();
      setAnchor(null);
      return;
    }

    setAnchor((current) => {
      if (!current || current.id !== id) return current;
      clearPendingClear();
      clearTimerRef.current = window.setTimeout(() => {
        clearTimerRef.current = null;
        setAnchor((latest) => (latest?.id === id ? null : latest));
      }, CLEAR_LINGER_MS);
      return current;
    });
  }, [clearPendingClear]);

  const value = useMemo(() => ({
    anchor,
    setAnchorFromElement,
    clearAnchor,
  }), [anchor, clearAnchor, setAnchorFromElement]);

  return (
    <SidebarWakeAnchorCtx.Provider value={value}>
      {children}
    </SidebarWakeAnchorCtx.Provider>
  );
}

export function useSidebarWakeAnchor() {
  const ctx = useContext(SidebarWakeAnchorCtx);
  if (!ctx) {
    throw new Error("useSidebarWakeAnchor must be used within SidebarWakeAnchorProvider");
  }
  return ctx;
}
