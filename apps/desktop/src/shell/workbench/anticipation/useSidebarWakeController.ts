import { useEffect, useMemo, useRef, useState } from "react";
import { useWorkbench } from "@/shell/workbench/WorkbenchStateProvider";
import { useDragState } from "../DragDropContext";
import type {
  AnticipationContext,
  SidebarDirectorState,
  SidebarWakeAnchorKind,
  SidebarWakeDirective,
  SidebarWakePeekVariant,
  SidebarWakeState,
} from "./types";
import { useAnticipationContext } from "./AnticipationProvider";
import { useSidebarDirector } from "./useSidebarDirector";
import { useSidebarWakeAnchor } from "./SidebarWakeAnchorProvider";
import type { SidebarWakeAnchor } from "./SidebarWakeAnchorProvider";
import type { LensId } from "../workbenchState";

const DOCK_PROXIMITY_CORRIDOR_PX = 152;
const PREWAKE_DELAY_MS = 92;
const GHOST_PEEK_DELAY_MS = 126;
const RETRACT_DELAY_MS = 180;
const DEFAULT_ANCHOR_TOP = 96;
const GHOST_PEEK_HEIGHT = 68;
const GHOST_PEEK_TOP_MARGIN = 56;
const GHOST_PEEK_BOTTOM_MARGIN = 80;
const DEFAULT_PEEK_LEFT = 18;
const DEFAULT_SEAM_LEFT = 4;
const DEFAULT_SEAM_WIDTH = 14;

const LENS_ACTION_FALLBACKS: Record<LensId, string> = {
  scopes: "Review live scopes",
  history: "Resume recent pivots",
  files: "Open likely file surfaces",
  sandboxes: "Open live sandbox context",
  entities: "Pivot through related entities",
  swarms: "Coordinate live runs",
  notes: "Continue note proof",
};

const LENS_REASON_FALLBACKS: Record<LensId, string> = {
  scopes: "scope activity is the strongest active signal",
  history: "recent pivots are the best next move",
  files: "file context is active in the current shell",
  sandboxes: "sandbox work is close to the current run context",
  entities: "entity context is leading the current hunt",
  swarms: "swarm coordination fits the current hunt phase",
  notes: "notes are the likeliest proof surface right now",
};

interface SidebarWakePreview {
  anchorLens: LensId;
  predictedActionLabel: string;
  predictedReason: string | null;
  peekWidth: number;
  shouldWarmDock: boolean;
  allowGhostPeek: boolean;
}

interface SidebarWakeGeometry {
  peekLeft: number;
  peekWidth: number;
  peekVariant: SidebarWakePeekVariant;
  seamLeft: number;
  seamWidth: number;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}

export function buildSidebarWakePreview(
  anticipation: AnticipationContext,
  director: SidebarDirectorState,
  sidebarCollapsed: boolean,
): SidebarWakePreview {
  const anchorLens =
    director.targetLens
    ?? anticipation.suggestedLens
    ?? anticipation.currentLens;
  const predictedActionLabel =
    anticipation.dropPrediction?.defaultLabel
    ?? anticipation.pathSuggestedAction?.label
    ?? LENS_ACTION_FALLBACKS[anchorLens];
  const predictedReason =
    director.globalReason
    ?? anticipation.pathSuggestedAction?.label
    ?? anticipation.lensChangeReason
    ?? anticipation.openModeReason
    ?? LENS_REASON_FALLBACKS[anchorLens];
  const allowGhostPeek =
    anticipation.confidence !== "low"
    || anticipation.isAttachMode
    || anticipation.dropPrediction !== null
    || anticipation.pathSuggestedAction !== null;

  return {
    anchorLens,
    predictedActionLabel,
    predictedReason,
    peekWidth:
      anticipation.confidence === "high" || anticipation.isAttachMode
        ? 188
        : 168,
    shouldWarmDock:
      sidebarCollapsed
      && (
        anticipation.confidence !== "low"
        || anticipation.isAttachMode
        || director.targetLens !== null
        || anticipation.dropPrediction !== null
      ),
    allowGhostPeek,
  };
}

export function clampSidebarWakeTop(
  pointerY: number | null,
  viewportHeight: number,
): number {
  const effectiveHeight = viewportHeight > 0 ? viewportHeight : 900;
  const rawTop = pointerY === null
    ? DEFAULT_ANCHOR_TOP
    : pointerY - GHOST_PEEK_HEIGHT / 2;
  const minTop = GHOST_PEEK_TOP_MARGIN;
  const maxTop = Math.max(minTop, effectiveHeight - GHOST_PEEK_BOTTOM_MARGIN - GHOST_PEEK_HEIGHT);
  return Math.min(Math.max(rawTop, minTop), maxTop);
}

export function resolveSidebarWakeTop(
  anchor: { top: number; height: number } | null,
  pointerY: number | null,
  viewportHeight: number,
): number {
  const anchoredPointerY = anchor
    ? anchor.top + anchor.height / 2
    : pointerY;
  return clampSidebarWakeTop(anchoredPointerY, viewportHeight);
}

export function resolveSidebarWakeGeometry(
  anchor: Pick<SidebarWakeAnchor, "kind" | "left" | "width" | "right"> | null,
  basePeekWidth: number,
  viewportWidth: number,
): SidebarWakeGeometry {
  const safeViewportWidth = viewportWidth > 0 ? viewportWidth : 1440;

  const buildGeometry = (
    preferredLeft: number,
    preferredWidth: number,
    variant: SidebarWakePeekVariant,
    minLeft: number,
    kindMaxLeft: number,
    seamInset: number,
    seamWidth: number,
  ): SidebarWakeGeometry => {
    const boundedWidth = Math.max(148, Math.min(preferredWidth, safeViewportWidth - 32));
    const maxLeft = Math.max(minLeft, Math.min(kindMaxLeft, safeViewportWidth - boundedWidth - 24));
    const peekLeft = clamp(preferredLeft, minLeft, maxLeft);
    return {
      peekLeft,
      peekWidth: boundedWidth,
      peekVariant: variant,
      seamLeft: Math.max(0, peekLeft - seamInset),
      seamWidth,
    };
  };

  if (!anchor) {
    return {
      peekLeft: DEFAULT_PEEK_LEFT,
      peekWidth: basePeekWidth,
      peekVariant: "generic",
      seamLeft: DEFAULT_SEAM_LEFT,
      seamWidth: DEFAULT_SEAM_WIDTH,
    };
  }

  const kind: SidebarWakeAnchorKind = anchor.kind;

  if (kind === "row") {
    return buildGeometry(
      36 + Math.min(20, Math.max(10, anchor.width * 0.08)),
      basePeekWidth + 18,
      "row-card",
      24,
      72,
      18,
      22,
    );
  }

  if (kind === "hunt-pill") {
    return buildGeometry(
      14 + Math.min(12, Math.max(6, anchor.width * 0.3)),
      Math.max(152, basePeekWidth - 14),
      "hunt-pill-chip",
      8,
      34,
      8,
      12,
    );
  }

  return buildGeometry(
    18 + Math.min(14, Math.max(8, anchor.width * 0.36)),
    basePeekWidth,
    "dock-icon-chip",
    10,
    52,
    10,
    14,
  );
}

export function shouldSuppressSidebarWakeForAnchor(
  anchorKind: SidebarWakeAnchorKind | null,
): boolean {
  return anchorKind === "hunt-pill";
}

export function useSidebarWakeController(): SidebarWakeDirective {
  const anticipation = useAnticipationContext();
  const director = useSidebarDirector();
  const { state } = useWorkbench();
  const dragState = useDragState();
  const { anchor } = useSidebarWakeAnchor();
  const { sidebarCollapsed } = state;
  const preview = useMemo(
    () => buildSidebarWakePreview(anticipation, director, sidebarCollapsed),
    [anticipation, director, sidebarCollapsed],
  );

  const [wakeState, setWakeState] = useState<SidebarWakeState>(
    sidebarCollapsed ? "idle" : "committed",
  );
  const [inDockCorridor, setInDockCorridor] = useState(false);
  const [pointerY, setPointerY] = useState<number | null>(null);
  const lastActiveWakeRef = useRef<"prewake" | "ghost-peek" | null>(null);
  const prewakeTimerRef = useRef<number | null>(null);
  const ghostTimerRef = useRef<number | null>(null);
  const retractTimerRef = useRef<number | null>(null);

  const clearTimer = (timerRef: { current: number | null }) => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  };

  useEffect(() => {
    const handlePointerMove = (event: PointerEvent) => {
      setInDockCorridor(event.clientX <= DOCK_PROXIMITY_CORRIDOR_PX);
      setPointerY((current) => (
        current === null || Math.abs(current - event.clientY) > 1
          ? event.clientY
          : current
      ));
    };
    const handlePointerLeave = () => {
      setInDockCorridor(false);
    };

    window.addEventListener("pointermove", handlePointerMove, { passive: true });
    window.addEventListener("pointerleave", handlePointerLeave);

    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerleave", handlePointerLeave);
    };
  }, []);

  useEffect(() => {
    return () => {
      clearTimer(prewakeTimerRef);
      clearTimer(ghostTimerRef);
      clearTimer(retractTimerRef);
    };
  }, []);

  useEffect(() => {
    clearTimer(retractTimerRef);

    if (!sidebarCollapsed || director.shouldOpenSidebar) {
      clearTimer(prewakeTimerRef);
      clearTimer(ghostTimerRef);
      setWakeState("committed");
      return;
    }

    if (!inDockCorridor) {
      clearTimer(prewakeTimerRef);
      clearTimer(ghostTimerRef);
      if (wakeState === "prewake" || wakeState === "ghost-peek") {
        setWakeState("retracting");
        retractTimerRef.current = window.setTimeout(() => {
          retractTimerRef.current = null;
          setWakeState("idle");
          lastActiveWakeRef.current = null;
        }, RETRACT_DELAY_MS);
        return;
      }

      setWakeState("idle");
      lastActiveWakeRef.current = null;
      return;
    }

    if (wakeState === "idle" || wakeState === "retracting") {
      clearTimer(prewakeTimerRef);
      prewakeTimerRef.current = window.setTimeout(() => {
        prewakeTimerRef.current = null;
        lastActiveWakeRef.current = "prewake";
        setWakeState("prewake");
      }, PREWAKE_DELAY_MS);
      return;
    }

    if (wakeState === "prewake" && preview.allowGhostPeek && ghostTimerRef.current === null) {
      ghostTimerRef.current = window.setTimeout(() => {
        ghostTimerRef.current = null;
        lastActiveWakeRef.current = "ghost-peek";
        setWakeState("ghost-peek");
      }, Math.max(0, GHOST_PEEK_DELAY_MS - PREWAKE_DELAY_MS));
      return;
    }

    if (wakeState === "prewake" && !preview.allowGhostPeek) {
      clearTimer(ghostTimerRef);
    }
  }, [
    director.shouldOpenSidebar,
    inDockCorridor,
    preview.allowGhostPeek,
    sidebarCollapsed,
    wakeState,
  ]);

  const anchorTop = useMemo(() => {
    const viewportHeight = typeof window === "undefined" ? 900 : window.innerHeight;
    const interactionY = dragState.active ? dragState.position.y : pointerY;
    const concreteAnchor = anchor
      ? { top: anchor.top, height: anchor.height }
      : null;
    return resolveSidebarWakeTop(concreteAnchor, interactionY, viewportHeight);
  }, [anchor, dragState.active, dragState.position.y, pointerY]);
  const geometry = useMemo(() => {
    const viewportWidth = typeof window === "undefined" ? 1440 : window.innerWidth;
    const concreteAnchor = anchor
      ? {
          kind: anchor.kind,
          left: anchor.left,
          width: anchor.width,
          right: anchor.right,
        }
      : null;
    return resolveSidebarWakeGeometry(concreteAnchor, preview.peekWidth, viewportWidth);
  }, [anchor, preview.peekWidth]);
  const suppressWakePeek = shouldSuppressSidebarWakeForAnchor(anchor?.kind ?? null);

  if (!sidebarCollapsed) {
    return {
      wakeState: "committed",
      anchorLens: anchor?.lensHint ?? preview.anchorLens,
      anchorTop,
      peekLeft: geometry.peekLeft,
      peekVariant: geometry.peekVariant,
      seamLeft: geometry.seamLeft,
      seamWidth: geometry.seamWidth,
      sourceKind: anchor?.kind ?? null,
      sourceLabel: anchor?.label ?? null,
      sourceObjectType: anchor?.objectType ?? null,
      predictedActionLabel: preview.predictedActionLabel,
      predictedReason: preview.predictedReason,
      peekWidth: geometry.peekWidth,
      shouldWarmDock: false,
      shouldShowSeam: false,
      shouldShowGhostPeek: false,
    };
  }

  return {
    wakeState,
    anchorLens: anchor?.lensHint ?? preview.anchorLens,
    anchorTop,
    peekLeft: geometry.peekLeft,
    peekVariant: geometry.peekVariant,
    seamLeft: geometry.seamLeft,
    seamWidth: geometry.seamWidth,
    sourceKind: anchor?.kind ?? null,
    sourceLabel: anchor?.label ?? null,
    sourceObjectType: anchor?.objectType ?? null,
    predictedActionLabel: preview.predictedActionLabel,
    predictedReason: preview.predictedReason,
    peekWidth: geometry.peekWidth,
    shouldWarmDock: preview.shouldWarmDock || wakeState !== "idle",
    shouldShowSeam:
      !suppressWakePeek
      && (
        wakeState === "prewake"
        || wakeState === "ghost-peek"
        || wakeState === "retracting"
      ),
    shouldShowGhostPeek:
      !suppressWakePeek
      && (
        wakeState === "ghost-peek"
        || (wakeState === "retracting" && lastActiveWakeRef.current === "ghost-peek")
      ),
  };
}
