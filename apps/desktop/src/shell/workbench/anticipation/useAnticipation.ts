/**
 * useAnticipation — master hook that fuses the workbench's predictive signals
 * into one context object.
 *
 * The hook composes the lower-level anticipation helpers instead of asking
 * sidebar and overlay surfaces to each derive their own version of intent.
 */
import { useEffect, useMemo, useRef } from "react";
import {
  useShell,
  useLens,
  useActiveHunt,
  useHuntStore,
  useActiveTab,
  useSelection,
} from "../WorkbenchStateProvider";
import { useDragState } from "../DragDropContext";
import type { ArtifactKind } from "../huntTypes";
import type { LensId, TabKind } from "../workbenchState";
import type {
  AnticipationContext,
  DropSemantic,
  IntentType,
} from "./types";
import { confidenceLevel } from "./types";
import { useAdaptiveSidebar } from "./useAdaptiveSidebar";
import { useConfidence } from "./useConfidence";
import { useDragAnticipation } from "./useDragAnticipation";
import { useDropPrediction } from "./useDropPrediction";
import { usePathMemory } from "./usePathMemory";
import { usePredictiveLayout } from "./usePredictiveLayout";
import { useStagingShelf } from "./useStagingShelf";

const MAX_RECENT = 10;

function semanticToIntent(semantic: DropSemantic): IntentType {
  switch (semantic) {
    case "target":
      return "attach-target";
    case "evidence":
      return "attach-evidence";
    case "run-input":
      return "run-input";
    case "watch":
      return "watch";
    case "mount":
      return "mount";
    case "compare":
      return "compare";
    case "cite":
    case "notes":
      return "cite";
  }
}

function inferSelectionIntent(
  entityType: string | null,
): { intent: IntentType; confidence: number } | null {
  if (!entityType) return null;
  if (entityType === "receipt") return { intent: "compare", confidence: 55 };
  if (entityType === "file") return { intent: "mount", confidence: 50 };
  if (entityType === "policy" || entityType === "guard") {
    return { intent: "open", confidence: 35 };
  }
  return { intent: "attach-target", confidence: 45 };
}

export function useAnticipation(): AnticipationContext {
  const shell = useShell();
  const { lens } = useLens();
  const activeHunt = useActiveHunt();
  const huntStore = useHuntStore();
  const activeTab = useActiveTab();
  const selection = useSelection();
  const drag = useDragState();

  const adaptiveSidebar = useAdaptiveSidebar();
  const confidence = useConfidence();
  const pathMemory = usePathMemory();
  const predictiveLayout = usePredictiveLayout();
  const stagingShelf = useStagingShelf();
  const dragAnticipation = useDragAnticipation(drag.active, drag.payload);

  const draggedObjectKind: ArtifactKind | TabKind | null =
    drag.active && drag.payload
      ? (drag.payload.artifact.kind as ArtifactKind)
      : null;
  const dropPrediction = useDropPrediction(
    draggedObjectKind ? (draggedObjectKind as ArtifactKind) : null,
  );

  const activeHuntId = activeHunt?.id ?? null;
  const activeRunId = useMemo(() => {
    if (!activeHunt) return null;
    for (const runId of activeHunt.runIds) {
      const run = huntStore.runs[runId];
      if (run?.status === "running") return runId;
    }
    return null;
  }, [activeHunt, huntStore.runs]);
  const activeCaseId = activeHunt?.caseId ?? null;

  const recentPivotsRef = useRef<LensId[]>([]);
  useEffect(() => {
    const pivots = recentPivotsRef.current;
    if (pivots.length === 0 || pivots[pivots.length - 1] !== lens) {
      recentPivotsRef.current = [...pivots.slice(-(MAX_RECENT - 1)), lens];
    }
  }, [lens]);

  const recentActionsRef = useRef<string[]>([]);
  useEffect(() => {
    if (!activeTab) return;
    const chain = recentActionsRef.current;
    if (chain.length === 0 || chain[chain.length - 1] !== activeTab.kind) {
      recentActionsRef.current = [...chain.slice(-(MAX_RECENT - 1)), activeTab.kind];
    }
  }, [activeTab]);

  return useMemo(() => {
    const selectionIntent = inferSelectionIntent(selection.entityType);
    const dragIntent = dropPrediction?.defaultAction
      ?? (dragAnticipation.defaultRole
        ? semanticToIntent(dragAnticipation.defaultRole.semantic)
        : null);
    const likelyIntent = drag.active
      ? dragIntent
      : selectionIntent?.intent ?? null;

    const confidenceScore = Math.min(
      100,
      Math.max(
        confidence.score,
        selectionIntent?.confidence ?? 0,
        dragAnticipation.defaultRole?.confidence ?? 0,
      ) + (drag.active ? 10 : 0),
    );

    return {
      currentShell: shell,
      currentLens: lens,
      activeHuntId,
      activeRunId,
      activeCaseId,
      selectedObjectType: selection.entityType,
      hoveredObjectType: null,
      draggedObjectKind,
      recentActionChain: recentActionsRef.current,
      recentPivots: recentPivotsRef.current,
      likelyIntent,
      confidence: confidenceLevel(confidenceScore),
      confidenceScore,
      dropRoles: dragAnticipation.dropRoles,
      defaultDropRole: dragAnticipation.defaultRole,
      phase: adaptiveSidebar.phase,
      phaseScore: predictiveLayout.phaseConfidence,
      suggestedLens: predictiveLayout.suggestedLens,
      shouldChangeLens: predictiveLayout.shouldChangeLens,
      lensChangeReason: predictiveLayout.lensChangeReason,
      suggestedOpenMode: predictiveLayout.suggestedOpenMode,
      openModeReason: predictiveLayout.openModeReason,
      sidebarSections: adaptiveSidebar.sections,
      pathBreadcrumbs: pathMemory.breadcrumbs,
      pathSuggestedAction: pathMemory.suggestedAction
        ? {
            label: pathMemory.suggestedAction.label,
            action: pathMemory.suggestedAction.action,
            confidence: pathMemory.suggestedAction.confidence,
          }
        : null,
      dropPrediction: dropPrediction
        ? {
            defaultAction: dropPrediction.defaultAction,
            defaultLabel: dropPrediction.defaultLabel,
            reason: dropPrediction.explanation.reason,
            alternateActions: dropPrediction.alternateActions,
          }
        : null,
      compatibleTargets: dragAnticipation.compatibleTargets.map((target) => ({
        id: target.id,
        type: target.type,
        label: target.label,
        emphasis: target.emphasis,
      })),
      modifierOverride: dragAnticipation.modifierOverride,
      stagingItemCount: stagingShelf.items.length,
      stagingSuggestions: stagingShelf.suggestions,
      isAttachMode: drag.active,
      isSpringLoaded: dragAnticipation.springLoadedId !== null,
      springLoadedTargetId: dragAnticipation.springLoadedId,
    } satisfies AnticipationContext;
  }, [
    shell,
    lens,
    activeHuntId,
    activeRunId,
    activeCaseId,
    selection.entityType,
    draggedObjectKind,
    confidence.score,
    adaptiveSidebar.phase,
    adaptiveSidebar.sections,
    predictiveLayout.phaseConfidence,
    predictiveLayout.suggestedLens,
    predictiveLayout.shouldChangeLens,
    predictiveLayout.lensChangeReason,
    predictiveLayout.suggestedOpenMode,
    predictiveLayout.openModeReason,
    pathMemory.breadcrumbs,
    pathMemory.suggestedAction,
    dropPrediction,
    dragAnticipation.dropRoles,
    dragAnticipation.defaultRole,
    dragAnticipation.compatibleTargets,
    dragAnticipation.modifierOverride,
    dragAnticipation.springLoadedId,
    stagingShelf.items.length,
    stagingShelf.suggestions,
    drag.active,
  ]);
}
