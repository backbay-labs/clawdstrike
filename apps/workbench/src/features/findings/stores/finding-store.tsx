import { useLayoutEffect } from "react";
import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";
import type { Annotation } from "@/lib/workbench/hunt-types";
import type { Signal, SignalCluster } from "@/lib/workbench/signal-pipeline";
import type {
  Finding,
  FindingVerdict,
  Enrichment,
} from "@/lib/workbench/finding-engine";
import {
  createFromCluster as engineCreateFromCluster,
  confirm as engineConfirm,
  dismiss as engineDismiss,
  markFalsePositive as engineMarkFP,
  promote as enginePromote,
  addEnrichment as engineAddEnrichment,
  addAnnotation as engineAddAnnotation,
  setVerdict as engineSetVerdict,
  archiveExpiredFindings as engineArchiveExpired,
} from "@/lib/workbench/finding-engine";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FindingState {
  findings: Finding[];
  activeFindingId: string | null;
  actions: FindingActions;
}

interface FindingActions {
  createFromCluster: (
    cluster: SignalCluster,
    signals: Signal[],
    createdBy: string,
  ) => Finding | null;
  confirm: (findingId: string, actor: string) => void;
  dismiss: (findingId: string, actor: string, reason?: string) => void;
  markFalsePositive: (findingId: string, actor: string, reason?: string) => void;
  promote: (findingId: string, actor: string, intelId: string) => void;
  addEnrichment: (findingId: string, enrichment: Enrichment, actor: string) => void;
  addAnnotation: (findingId: string, annotation: Annotation) => void;
  setVerdict: (findingId: string, verdict: FindingVerdict, actor: string) => void;
  setActiveFinding: (findingId: string | null) => void;
  archiveExpired: (ttlMs?: number) => void;
  load: (findings: Finding[]) => void;
}

// ---------------------------------------------------------------------------
// localStorage persistence helpers
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_findings";

let persistTimer: ReturnType<typeof setTimeout> | null = null;
let lastFindingStorageSnapshot =
  typeof window === "undefined" ? null : readFindingStorageSnapshot();

function readFindingStorageSnapshot(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function schedulePersist(state: FindingState): void {
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    try {
      const persisted = {
        findings: state.findings,
        activeFindingId: state.activeFindingId,
      };
      const raw = JSON.stringify(persisted);
      localStorage.setItem(STORAGE_KEY, raw);
      lastFindingStorageSnapshot = raw;
    } catch (e) {
      console.error("[finding-store] persistFindings failed:", e);
    }
    persistTimer = null;
  }, 500);
}

/** Flush any pending debounced persist immediately (e.g. on beforeunload). */
function flushPersist(state: FindingState): void {
  if (persistTimer) {
    clearTimeout(persistTimer);
    persistTimer = null;
    try {
      const persisted = {
        findings: state.findings,
        activeFindingId: state.activeFindingId,
      };
      const raw = JSON.stringify(persisted);
      localStorage.setItem(STORAGE_KEY, raw);
      lastFindingStorageSnapshot = raw;
    } catch (e) {
      console.error("[finding-store] flushPersist failed:", e);
    }
  }
}

function loadPersistedFindings(): Pick<FindingState, "findings" | "activeFindingId"> | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.findings)) {
      console.warn("[finding-store] Invalid persisted finding data, using defaults");
      return null;
    }

    const validFindings: Finding[] = parsed.findings.filter(
      (f: unknown): f is Finding =>
        typeof f === "object" &&
        f !== null &&
        typeof (f as Record<string, unknown>).id === "string" &&
        typeof (f as Record<string, unknown>).title === "string" &&
        typeof (f as Record<string, unknown>).status === "string" &&
        typeof (f as Record<string, unknown>).confidence === "number",
    );

    if (validFindings.length === 0) return null;

    const activeFindingId =
      typeof parsed.activeFindingId === "string" &&
      validFindings.some((f) => f.id === parsed.activeFindingId)
        ? parsed.activeFindingId
        : validFindings[0].id;

    return {
      findings: validFindings,
      activeFindingId,
    };
  } catch (e) {
    console.warn("[finding-store] loadPersistedFindings failed:", e);
    return null;
  }
}

function getInitialData(): Pick<FindingState, "findings" | "activeFindingId"> {
  const restored = loadPersistedFindings();
  if (restored) return restored;

  return {
    findings: [],
    activeFindingId: null,
  };
}

function syncFindingStoreWithStorage(): void {
  const snapshot = readFindingStorageSnapshot();
  if (snapshot === lastFindingStorageSnapshot) {
    return;
  }

  const restored = loadPersistedFindings();
  lastFindingStorageSnapshot = snapshot;
  useFindingStoreBase.setState({
    findings: restored?.findings ?? [],
    activeFindingId: restored?.activeFindingId ?? null,
  });
}

// ---------------------------------------------------------------------------
// beforeunload handler -- mirrors the old Provider's effect
// ---------------------------------------------------------------------------

if (typeof window !== "undefined") {
  window.addEventListener("beforeunload", () => {
    // useFindingStoreBase may not yet be created at module evaluation time,
    // but by the time beforeunload fires it will be.
    try {
      const state = useFindingStoreBase.getState();
      flushPersist(state);
    } catch {
      // Store not initialised yet -- nothing to flush.
    }
  });
}

// ---------------------------------------------------------------------------
// Zustand store
// ---------------------------------------------------------------------------

const useFindingStoreBase = create<FindingState>()(
  immer((set, get) => {
    const initial = getInitialData();

    return {
      findings: initial.findings,
      activeFindingId: initial.activeFindingId,

      actions: {
        createFromCluster: (
          cluster: SignalCluster,
          signals: Signal[],
          createdBy: string,
        ): Finding | null => {
          const finding = engineCreateFromCluster(cluster, signals, createdBy);
          if (!finding) return null;
          set((state) => {
            state.findings.push(finding);
            state.activeFindingId = finding.id;
          });
          schedulePersist(get());
          return finding;
        },

        confirm: (findingId: string, actor: string) => {
          set((state) => {
            const idx = state.findings.findIndex((f) => f.id === findingId);
            if (idx !== -1) {
              const result = engineConfirm(state.findings[idx] as Finding, actor);
              if (!("error" in result)) {
                state.findings[idx] = result as any;
              }
            }
          });
          schedulePersist(get());
        },

        dismiss: (findingId: string, actor: string, reason?: string) => {
          set((state) => {
            const idx = state.findings.findIndex((f) => f.id === findingId);
            if (idx !== -1) {
              const result = engineDismiss(state.findings[idx] as Finding, actor, reason);
              if (!("error" in result)) {
                state.findings[idx] = result as any;
              }
            }
          });
          schedulePersist(get());
        },

        markFalsePositive: (findingId: string, actor: string, reason?: string) => {
          set((state) => {
            const idx = state.findings.findIndex((f) => f.id === findingId);
            if (idx !== -1) {
              const result = engineMarkFP(state.findings[idx] as Finding, actor, reason);
              if (!("error" in result)) {
                state.findings[idx] = result as any;
              }
            }
          });
          schedulePersist(get());
        },

        promote: (findingId: string, actor: string, intelId: string) => {
          set((state) => {
            const idx = state.findings.findIndex((f) => f.id === findingId);
            if (idx !== -1) {
              const result = enginePromote(state.findings[idx] as Finding, actor, intelId);
              if (!("error" in result)) {
                state.findings[idx] = result as any;
              }
            }
          });
          schedulePersist(get());
        },

        addEnrichment: (findingId: string, enrichment: Enrichment, actor: string) => {
          set((state) => {
            const idx = state.findings.findIndex((f) => f.id === findingId);
            if (idx !== -1) {
              const result = engineAddEnrichment(
                state.findings[idx] as Finding,
                enrichment,
                actor,
              );
              state.findings[idx] = result as any;
            }
          });
          schedulePersist(get());
        },

        addAnnotation: (findingId: string, annotation: Annotation) => {
          set((state) => {
            const idx = state.findings.findIndex((f) => f.id === findingId);
            if (idx !== -1) {
              const result = engineAddAnnotation(
                state.findings[idx] as Finding,
                annotation,
              );
              state.findings[idx] = result as any;
            }
          });
          schedulePersist(get());
        },

        setVerdict: (findingId: string, verdict: FindingVerdict, actor: string) => {
          set((state) => {
            const idx = state.findings.findIndex((f) => f.id === findingId);
            if (idx !== -1) {
              const result = engineSetVerdict(
                state.findings[idx] as Finding,
                verdict,
                actor,
              );
              state.findings[idx] = result as any;
            }
          });
          schedulePersist(get());
        },

        setActiveFinding: (findingId: string | null) => {
          set((state) => {
            if (
              findingId !== null &&
              !state.findings.some((f) => f.id === findingId)
            ) {
              return;
            }
            state.activeFindingId = findingId;
          });
          schedulePersist(get());
        },

        archiveExpired: (ttlMs?: number) => {
          set((state) => {
            const archived = engineArchiveExpired(state.findings as Finding[], ttlMs);
            const changed = archived.some(
              (f, i) => f.status !== (state.findings[i] as Finding | undefined)?.status,
            );
            if (changed) {
              state.findings = archived as any;
            }
          });
          schedulePersist(get());
        },

        load: (findings: Finding[]) => {
          set((state) => {
            const activeId =
              state.activeFindingId &&
              findings.some((f) => f.id === state.activeFindingId)
                ? state.activeFindingId
                : findings.length > 0
                  ? findings[0].id
                  : null;
            state.findings = findings as any;
            state.activeFindingId = activeId;
          });
          schedulePersist(get());
        },
      },
    };
  }),
);

export const useFindingStore = createSelectors(useFindingStoreBase);

// ---------------------------------------------------------------------------
// Backward-compatible hook -- same shape the old Context-based hook returned
// ---------------------------------------------------------------------------

interface FindingContextValue {
  findings: Finding[];
  activeFinding: Finding | undefined;
  createFromCluster: (
    cluster: SignalCluster,
    signals: Signal[],
    createdBy: string,
  ) => Finding | null;
  confirm: (findingId: string, actor: string) => void;
  dismiss: (findingId: string, actor: string, reason?: string) => void;
  markFalsePositive: (findingId: string, actor: string, reason?: string) => void;
  promote: (findingId: string, actor: string, intelId: string) => void;
  addEnrichment: (findingId: string, enrichment: Enrichment, actor: string) => void;
  addAnnotation: (findingId: string, annotation: Annotation) => void;
  setVerdict: (findingId: string, verdict: FindingVerdict, actor: string) => void;
  setActiveFinding: (findingId: string | null) => void;
  archiveExpired: (ttlMs?: number) => void;
}

/** @deprecated Use useFindingStore directly */
export function useFindings(): FindingContextValue {
  useLayoutEffect(() => {
    syncFindingStoreWithStorage();
  }, []);

  const findings = useFindingStore((s) => s.findings);
  const activeFindingId = useFindingStore((s) => s.activeFindingId);
  const actions = useFindingStore((s) => s.actions);

  const activeFinding = findings.find((f) => f.id === activeFindingId);

  return {
    findings,
    activeFinding,
    createFromCluster: actions.createFromCluster,
    confirm: actions.confirm,
    dismiss: actions.dismiss,
    markFalsePositive: actions.markFalsePositive,
    promote: actions.promote,
    addEnrichment: actions.addEnrichment,
    addAnnotation: actions.addAnnotation,
    setVerdict: actions.setVerdict,
    setActiveFinding: actions.setActiveFinding,
    archiveExpired: actions.archiveExpired,
  };
}
