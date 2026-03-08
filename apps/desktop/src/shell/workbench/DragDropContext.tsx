/**
 * DragDropContext — Pointer-based drag-and-drop for artifacts between hunts.
 *
 * Provides:
 *   DragDropProvider  — wraps WorkbenchShellInner, holds DragState
 *   useDragSource     — makes an element draggable
 *   useDropTarget     — makes an element a drop target
 *   DragGhost         — fixed-position ghost following the pointer
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { createArtifactId, type Artifact, type ArtifactKind } from "./huntTypes";
import {
  useHuntStore,
  useWorkbenchDispatch,
} from "./WorkbenchStateProvider";
import { ARTIFACT_KIND_ICONS } from "./lenses/LensIcons";
import { useStagingShelf } from "./anticipation/useStagingShelf";
import { useDropPrediction } from "./anticipation/useDropPrediction";
import type { DropSemantic, IntentType } from "./anticipation/types";

// ── Types ────────────────────────────────────────────────────────

export interface DragPayload {
  kind: "artifact" | "artifact-ref";
  artifactId: string;
  sourceHuntId: string | null;
  artifact: Artifact;
}

export interface DragState {
  active: boolean;
  payload: DragPayload | null;
  position: { x: number; y: number };
  overDropTargetId: string | null;
  overDropTargetType: "hunt" | "staging" | null;
  selectedSemantic: DropSemantic | null;
}

interface DragDropContextValue {
  drag: DragState;
  startDrag: (payload: DragPayload, position: { x: number; y: number }) => void;
  cancelDrag: () => void;
  setOverTarget: (target: { id: string; type: "hunt" | "staging" } | null) => void;
  setSelectedSemantic: (semantic: DropSemantic | null) => void;
  completeDrop: () => void;
}

const INITIAL_DRAG: DragState = {
  active: false,
  payload: null,
  position: { x: 0, y: 0 },
  overDropTargetId: null,
  overDropTargetType: null,
  selectedSemantic: null,
};

const DragDropCtx = createContext<DragDropContextValue | null>(null);

// ── Provider ─────────────────────────────────────────────────────

const DEAD_ZONE = 5;
const SPRING_LOAD_MS = 300;

function intentToSemantic(intent: IntentType | null): DropSemantic | null {
  switch (intent) {
    case "attach-target":
      return "target";
    case "attach-evidence":
      return "evidence";
    case "run-input":
      return "run-input";
    case "watch":
      return "watch";
    case "mount":
      return "mount";
    case "compare":
      return "compare";
    case "cite":
      return "cite";
    default:
      return null;
  }
}

export function DragDropProvider({ children }: { children: ReactNode }) {
  const [drag, setDrag] = useState<DragState>(INITIAL_DRAG);
  const dispatch = useWorkbenchDispatch();
  const huntStore = useHuntStore();
  const stagingShelf = useStagingShelf();
  const springTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingRef = useRef<{ payload: DragPayload; origin: { x: number; y: number } } | null>(null);
  const draggedKind = drag.active && drag.payload ? drag.payload.artifact.kind : null;
  const dropPrediction = useDropPrediction(draggedKind);
  const defaultSemantic = useMemo(
    () => intentToSemantic(dropPrediction?.defaultAction ?? null),
    [dropPrediction],
  );

  const clearSpring = useCallback(() => {
    if (springTimerRef.current) {
      clearTimeout(springTimerRef.current);
      springTimerRef.current = null;
    }
  }, []);

  const cancelDrag = useCallback(() => {
    setDrag(INITIAL_DRAG);
    pendingRef.current = null;
    clearSpring();
  }, [clearSpring]);

  const startDrag = useCallback(
    (payload: DragPayload, position: { x: number; y: number }) => {
      pendingRef.current = { payload, origin: position };
    },
    [],
  );

  const setSelectedSemantic = useCallback((semantic: DropSemantic | null) => {
    setDrag((prev) => (
      prev.active
        ? { ...prev, selectedSemantic: semantic }
        : prev
    ));
  }, []);

  const setOverTarget = useCallback(
    (target: { id: string; type: "hunt" | "staging" } | null) => {
      setDrag((prev) => {
        if (!prev.active) return prev;
        return {
          ...prev,
          overDropTargetId: target?.id ?? null,
          overDropTargetType: target?.type ?? null,
          selectedSemantic: target ? prev.selectedSemantic : null,
        };
      });

      clearSpring();
      if (target?.type === "hunt") {
        springTimerRef.current = setTimeout(() => {
          dispatch({ type: "HUNT_SET_ACTIVE", payload: { id: target.id } });
        }, SPRING_LOAD_MS);
      }
    },
    [dispatch, clearSpring],
  );

  const completeDrop = useCallback(() => {
    setDrag((prev) => {
      if (!prev.active || !prev.payload || !prev.overDropTargetId) return INITIAL_DRAG;
      const { artifactId, sourceHuntId, artifact } = prev.payload;
      const semantic = prev.selectedSemantic ?? defaultSemantic;
      const dropReason = dropPrediction?.explanation.reason ?? null;

      if (prev.overDropTargetType === "staging") {
        stagingShelf.stageItem({
          id: artifactId,
          kind: artifact.kind,
          title: artifact.title,
          sourceUri: artifact.sourceUri,
          sourceHuntId: sourceHuntId ?? undefined,
        });
        return INITIAL_DRAG;
      }

      const toHuntId = prev.overDropTargetId;
      const toHunt = huntStore.hunts[toHuntId];
      const targetArtifactId = sourceHuntId
        ? artifactId
        : (huntStore.artifacts[artifactId] ? createArtifactId() : artifactId);

      if (sourceHuntId && sourceHuntId !== toHuntId) {
        dispatch({
          type: "HUNT_MOVE_ARTIFACT",
          payload: { fromHuntId: sourceHuntId, toHuntId, artifactId: targetArtifactId },
        });
      } else if (!sourceHuntId) {
        dispatch({
          type: "HUNT_ADD_ARTIFACT",
          payload: {
            huntId: toHuntId,
            artifact: {
              id: targetArtifactId,
              kind: artifact.kind,
              title: artifact.title,
              sourceUri: artifact.sourceUri,
              metadata: artifact.metadata,
            },
          },
        });
      }

      if (semantic) {
        dispatch({
          type: "HUNT_ASSIGN_ARTIFACT_SEMANTIC",
          payload: {
            huntId: toHuntId,
            artifactId: targetArtifactId,
            semantic,
          },
        });
        dispatch({
          type: "HUNT_SET_ARTIFACT_METADATA",
          payload: {
            artifactId: targetArtifactId,
            patch: {
              semanticAttachment: semantic,
              dropReason,
              attachedToHuntId: toHuntId,
              attachedVia: prev.selectedSemantic ? "explicit-semantic" : "predicted-default",
            },
          },
        });
      }

      const activeRunId =
        toHunt?.runIds.find((runId) => huntStore.runs[runId]?.status === "running") ?? null;
      if (semantic && activeRunId && (semantic === "run-input" || semantic === "mount")) {
        dispatch({
          type: "HUNT_ATTACH_ARTIFACT_TO_RUN",
          payload: {
            runId: activeRunId,
            artifactId: targetArtifactId,
            semantic,
          },
        });
      }

      if (semantic === "cite" && toHunt?.caseId) {
        dispatch({
          type: "HUNT_ATTACH_ARTIFACT_TO_CASE",
          payload: {
            caseId: toHunt.caseId,
            artifactId: targetArtifactId,
            semantic,
          },
        });
      }

      return INITIAL_DRAG;
    });
    clearSpring();
  }, [clearSpring, defaultSemantic, dispatch, dropPrediction, huntStore, stagingShelf]);

  // Window-level pointermove / pointerup when drag is pending or active
  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      // Pending — check dead zone
      if (pendingRef.current && !drag.active) {
        const dx = e.clientX - pendingRef.current.origin.x;
        const dy = e.clientY - pendingRef.current.origin.y;
        if (Math.abs(dx) > DEAD_ZONE || Math.abs(dy) > DEAD_ZONE) {
          setDrag({
            active: true,
            payload: pendingRef.current.payload,
            position: { x: e.clientX, y: e.clientY },
            overDropTargetId: null,
            overDropTargetType: null,
            selectedSemantic: null,
          });
          pendingRef.current = null;
        }
        return;
      }
      // Active — update position
      if (drag.active) {
        setDrag((prev) => ({ ...prev, position: { x: e.clientX, y: e.clientY } }));
      }
    };

    const onUp = () => {
      if (pendingRef.current) {
        pendingRef.current = null;
        return;
      }
      if (drag.active) {
        if (drag.overDropTargetId) {
          completeDrop();
        } else {
          cancelDrag();
        }
      }
    };

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") cancelDrag();
    };

    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [drag.active, drag.overDropTargetId, completeDrop, cancelDrag]);

  return (
    <DragDropCtx.Provider
      value={{
        drag,
        startDrag,
        cancelDrag,
        setOverTarget,
        setSelectedSemantic,
        completeDrop,
      }}
    >
      {children}
      {drag.active && drag.payload && <DragGhost drag={drag} />}
    </DragDropCtx.Provider>
  );
}

// ── Hooks ────────────────────────────────────────────────────────

function useDragDrop(): DragDropContextValue {
  const ctx = useContext(DragDropCtx);
  if (!ctx) throw new Error("useDragDrop must be used within DragDropProvider");
  return ctx;
}

export function useDragSource(payload: DragPayload | null) {
  const { startDrag, drag } = useDragDrop();
  const isDragging =
    drag.active && drag.payload?.artifactId === payload?.artifactId;

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      if (!payload || e.button !== 0) return;
      e.preventDefault();
      startDrag(payload, { x: e.clientX, y: e.clientY });
    },
    [payload, startDrag],
  );

  return {
    dragSourceProps: {
      onPointerDown,
      style: {
        cursor: isDragging ? "grabbing" : payload ? "grab" : undefined,
        opacity: isDragging ? 0.4 : undefined,
      } as React.CSSProperties,
    },
    isDragging,
  };
}

/** Read-only access to the current drag state. */
export function useDragState(): DragState {
  const ctx = useContext(DragDropCtx);
  if (!ctx) throw new Error("useDragState must be used within DragDropProvider");
  return ctx.drag;
}

export function useDragSemanticSelection(): {
  selectedSemantic: DropSemantic | null;
  setSelectedSemantic: (semantic: DropSemantic | null) => void;
} {
  const ctx = useDragDrop();
  return {
    selectedSemantic: ctx.drag.selectedSemantic,
    setSelectedSemantic: ctx.setSelectedSemantic,
  };
}

export function useDropTarget(targetId: string, targetType: "hunt" | "staging" = "hunt") {
  const { drag, setOverTarget } = useDragDrop();
  const isOver =
    drag.active &&
    drag.overDropTargetId === targetId &&
    drag.overDropTargetType === targetType;
  const canDrop =
    drag.active &&
    (targetType === "staging" || drag.payload?.sourceHuntId !== targetId);

  const onPointerEnter = useCallback(() => {
    if (drag.active) {
      setOverTarget({ id: targetId, type: targetType });
    }
  }, [drag.active, targetId, targetType, setOverTarget]);

  const onPointerLeave = useCallback(() => {
    if (
      drag.active &&
      drag.overDropTargetId === targetId &&
      drag.overDropTargetType === targetType
    ) {
      setOverTarget(null);
    }
  }, [drag.active, drag.overDropTargetId, drag.overDropTargetType, targetId, targetType, setOverTarget]);

  return {
    dropTargetProps: { onPointerEnter, onPointerLeave },
    isOver,
    canDrop,
  };
}

// ── Ghost ────────────────────────────────────────────────────────

function DragGhost({ drag }: { drag: DragState }) {
  if (!drag.payload) return null;
  const IconComponent = ARTIFACT_KIND_ICONS[drag.payload.artifact.kind];
  return (
    <div
      className="drag-ghost"
      style={{ left: drag.position.x + 12, top: drag.position.y - 14 }}
    >
      {IconComponent && (
        <span className="drag-ghost__icon">
          <IconComponent />
        </span>
      )}
      <span>{drag.payload.artifact.title}</span>
    </div>
  );
}
