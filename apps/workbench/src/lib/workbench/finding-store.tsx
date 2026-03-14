import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
import type { Annotation } from "./hunt-types";
import type { Signal, SignalCluster } from "./signal-pipeline";
import type {
  Finding,
  FindingVerdict,
  Enrichment,
} from "./finding-engine";
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
} from "./finding-engine";

export interface FindingState {
  findings: Finding[];
  activeFindingId: string | null;
}

export type FindingAction =
  | { type: "CREATE"; finding: Finding }
  | { type: "CREATE_FROM_CLUSTER"; cluster: SignalCluster; signals: Signal[]; createdBy: string }
  | { type: "CONFIRM"; findingId: string; actor: string }
  | { type: "DISMISS"; findingId: string; actor: string; reason?: string }
  | { type: "MARK_FP"; findingId: string; actor: string; reason?: string }
  | { type: "PROMOTE"; findingId: string; actor: string; intelId: string }
  | { type: "ADD_ENRICHMENT"; findingId: string; enrichment: Enrichment; actor: string }
  | { type: "ADD_ANNOTATION"; findingId: string; annotation: Annotation }
  | { type: "SET_VERDICT"; findingId: string; verdict: FindingVerdict; actor: string }
  | { type: "SET_ACTIVE"; findingId: string | null }
  | { type: "ARCHIVE_EXPIRED"; ttlMs?: number }
  | { type: "LOAD"; findings: Finding[] };

function findingReducer(state: FindingState, action: FindingAction): FindingState {
  switch (action.type) {
    case "CREATE": {
      return {
        ...state,
        findings: [...state.findings, action.finding],
        activeFindingId: action.finding.id,
      };
    }

    case "CREATE_FROM_CLUSTER": {
      const finding = engineCreateFromCluster(
        action.cluster,
        action.signals,
        action.createdBy,
      );
      if (!finding) return state;

      return {
        ...state,
        findings: [...state.findings, finding],
        activeFindingId: finding.id,
      };
    }

    case "CONFIRM": {
      return {
        ...state,
        findings: state.findings.map((f) => {
          if (f.id !== action.findingId) return f;
          const result = engineConfirm(f, action.actor);
          return "error" in result ? f : result;
        }),
      };
    }

    case "DISMISS": {
      return {
        ...state,
        findings: state.findings.map((f) => {
          if (f.id !== action.findingId) return f;
          const result = engineDismiss(f, action.actor, action.reason);
          return "error" in result ? f : result;
        }),
      };
    }

    case "MARK_FP": {
      return {
        ...state,
        findings: state.findings.map((f) => {
          if (f.id !== action.findingId) return f;
          const result = engineMarkFP(f, action.actor, action.reason);
          return "error" in result ? f : result;
        }),
      };
    }

    case "PROMOTE": {
      return {
        ...state,
        findings: state.findings.map((f) => {
          if (f.id !== action.findingId) return f;
          const result = enginePromote(f, action.actor, action.intelId);
          return "error" in result ? f : result;
        }),
      };
    }

    case "ADD_ENRICHMENT": {
      return {
        ...state,
        findings: state.findings.map((f) =>
          f.id === action.findingId
            ? engineAddEnrichment(f, action.enrichment, action.actor)
            : f,
        ),
      };
    }

    case "ADD_ANNOTATION": {
      return {
        ...state,
        findings: state.findings.map((f) =>
          f.id === action.findingId
            ? engineAddAnnotation(f, action.annotation)
            : f,
        ),
      };
    }

    case "SET_VERDICT": {
      return {
        ...state,
        findings: state.findings.map((f) =>
          f.id === action.findingId
            ? engineSetVerdict(f, action.verdict, action.actor)
            : f,
        ),
      };
    }

    case "SET_ACTIVE": {
      if (
        action.findingId !== null &&
        !state.findings.some((f) => f.id === action.findingId)
      ) {
        return state;
      }
      return { ...state, activeFindingId: action.findingId };
    }

    case "ARCHIVE_EXPIRED": {
      const archived = engineArchiveExpired(state.findings, action.ttlMs);
      const changed = archived.some(
        (f, i) => f.status !== state.findings[i]?.status,
      );
      return changed ? { ...state, findings: archived } : state;
    }

    case "LOAD": {
      const activeId =
        state.activeFindingId &&
        action.findings.some((f) => f.id === state.activeFindingId)
          ? state.activeFindingId
          : action.findings.length > 0
            ? action.findings[0].id
            : null;
      return {
        ...state,
        findings: action.findings,
        activeFindingId: activeId,
      };
    }

    default:
      return state;
  }
}

const STORAGE_KEY = "clawdstrike_workbench_findings";

function persistFindings(state: FindingState): void {
  try {
    const persisted = {
      findings: state.findings,
      activeFindingId: state.activeFindingId,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
  } catch (e) {
    console.error("[finding-store] persistFindings failed:", e);
  }
}

function loadPersistedFindings(): FindingState | null {
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

function getInitialState(): FindingState {
  const restored = loadPersistedFindings();
  if (restored) return restored;

  return {
    findings: [],
    activeFindingId: null,
  };
}

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

const FindingContext = createContext<FindingContextValue | null>(null);

export function useFindings(): FindingContextValue {
  const ctx = useContext(FindingContext);
  if (!ctx) throw new Error("useFindings must be used within FindingProvider");
  return ctx;
}

export function FindingProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(findingReducer, undefined, getInitialState);
  const stateRef = useRef(state);
  stateRef.current = state;

  const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      persistFindings(state);
      persistRef.current = null;
    }, 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [state.findings, state.activeFindingId]);

  useEffect(() => {
    const handleBeforeUnload = () => {
      if (persistRef.current) {
        clearTimeout(persistRef.current);
        persistRef.current = null;
        persistFindings(stateRef.current);
      }
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
    };
  }, []);

  const activeFinding = state.findings.find((f) => f.id === state.activeFindingId);

  const createFromCluster = useCallback(
    (cluster: SignalCluster, signals: Signal[], createdBy: string) => {
      const finding = engineCreateFromCluster(cluster, signals, createdBy);
      if (!finding) return null;
      dispatch({ type: "CREATE", finding });
      return finding;
    },
    [],
  );

  const confirmAction = useCallback((findingId: string, actor: string) => {
    dispatch({ type: "CONFIRM", findingId, actor });
  }, []);

  const dismissAction = useCallback(
    (findingId: string, actor: string, reason?: string) => {
      dispatch({ type: "DISMISS", findingId, actor, reason });
    },
    [],
  );

  const markFalsePositive = useCallback(
    (findingId: string, actor: string, reason?: string) => {
      dispatch({ type: "MARK_FP", findingId, actor, reason });
    },
    [],
  );

  const promoteAction = useCallback(
    (findingId: string, actor: string, intelId: string) => {
      dispatch({ type: "PROMOTE", findingId, actor, intelId });
    },
    [],
  );

  const addEnrichmentAction = useCallback(
    (findingId: string, enrichment: Enrichment, actor: string) => {
      dispatch({ type: "ADD_ENRICHMENT", findingId, enrichment, actor });
    },
    [],
  );

  const addAnnotationAction = useCallback(
    (findingId: string, annotation: Annotation) => {
      dispatch({ type: "ADD_ANNOTATION", findingId, annotation });
    },
    [],
  );

  const setVerdictAction = useCallback(
    (findingId: string, verdict: FindingVerdict, actor: string) => {
      dispatch({ type: "SET_VERDICT", findingId, verdict, actor });
    },
    [],
  );

  const setActiveFinding = useCallback((findingId: string | null) => {
    dispatch({ type: "SET_ACTIVE", findingId });
  }, []);

  const archiveExpired = useCallback((ttlMs?: number) => {
    dispatch({ type: "ARCHIVE_EXPIRED", ttlMs });
  }, []);

  const value: FindingContextValue = {
    findings: state.findings,
    activeFinding,
    createFromCluster,
    confirm: confirmAction,
    dismiss: dismissAction,
    markFalsePositive,
    promote: promoteAction,
    addEnrichment: addEnrichmentAction,
    addAnnotation: addAnnotationAction,
    setVerdict: setVerdictAction,
    setActiveFinding,
    archiveExpired,
  };

  return (
    <FindingContext.Provider value={value}>
      {children}
    </FindingContext.Provider>
  );
}
