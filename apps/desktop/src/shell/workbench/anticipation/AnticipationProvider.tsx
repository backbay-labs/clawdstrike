/**
 * AnticipationProvider — React context provider for the master anticipation
 * state. Wraps the workbench so any descendant can read the current
 * AnticipationContext without recomputing the signal fusion.
 */
import { createContext, useContext } from "react";
import type { ReactNode } from "react";
import type { AnticipationContext } from "./types";
import { useAnticipation } from "./useAnticipation";

const AnticipationCtx = createContext<AnticipationContext | null>(null);

/**
 * Place inside WorkbenchStateProvider + DragDropProvider so all signals
 * are available.
 */
export function AnticipationProvider({ children }: { children: ReactNode }) {
  const ctx = useAnticipation();

  return (
    <AnticipationCtx.Provider value={ctx}>
      {children}
    </AnticipationCtx.Provider>
  );
}

/**
 * Read the current AnticipationContext. Must be called within an
 * AnticipationProvider — throws otherwise.
 */
export function useAnticipationContext(): AnticipationContext {
  const ctx = useContext(AnticipationCtx);
  if (!ctx) {
    throw new Error(
      "useAnticipationContext must be used within an AnticipationProvider",
    );
  }
  return ctx;
}
