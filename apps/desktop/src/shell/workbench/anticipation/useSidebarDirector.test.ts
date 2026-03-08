import { describe, expect, it } from "vitest";
import type { AnticipationContext } from "./types";
import { buildSidebarDirectorState } from "./useSidebarDirector";

function makeContext(
  overrides: Partial<AnticipationContext> = {},
): AnticipationContext {
  return {
    currentShell: "hunt",
    currentLens: "notes",
    activeHuntId: "hunt-1",
    activeRunId: null,
    activeCaseId: null,
    selectedObjectType: null,
    hoveredObjectType: null,
    draggedObjectKind: null,
    recentActionChain: [],
    recentPivots: [],
    likelyIntent: null,
    confidence: "medium",
    confidenceScore: 50,
    dropRoles: [],
    defaultDropRole: null,
    phase: "triage",
    phaseScore: 55,
    suggestedLens: null,
    shouldChangeLens: false,
    lensChangeReason: null,
    suggestedOpenMode: "replace",
    openModeReason: "default",
    sidebarSections: [],
    pathBreadcrumbs: [],
    pathSuggestedAction: null,
    dropPrediction: null,
    compatibleTargets: [],
    modifierOverride: null,
    stagingItemCount: 0,
    stagingSuggestions: [],
    isAttachMode: false,
    isSpringLoaded: false,
    springLoadedTargetId: null,
    ...overrides,
  };
}

describe("buildSidebarDirectorState", () => {
  it("opens the sidebar and targets the entities lens for entity drag", () => {
    const state = buildSidebarDirectorState(
      makeContext({
        draggedObjectKind: "entity",
        isAttachMode: true,
        confidence: "high",
        dropPrediction: {
          defaultAction: "attach-target",
          defaultLabel: "Attach as target",
          reason: "current hunt + entity type",
          alternateActions: [],
        },
      }),
    );

    expect(state.shouldOpenSidebar).toBe(true);
    expect(state.targetLens).toBe("entities");
    expect(state.shouldSwitchLens).toBe(true);
    expect(state.lensSections.entities?.promotedSectionIds).toContain("hunt-entities");
    expect(state.lensSections.entities?.expandedSectionIds).toContain("hunt-entities");
  });

  it("falls back to quick actions when there is no active hunt", () => {
    const state = buildSidebarDirectorState(
      makeContext({
        currentLens: "entities",
        activeHuntId: null,
        suggestedLens: "entities",
      }),
    );

    expect(state.lensSections.entities?.hiddenSectionIds).toContain("hunt-entities");
    expect(state.lensSections.entities?.promotedSectionIds).toContain("quick-actions");
  });

  it("promotes notes sections for receipt drag in case reporting flow", () => {
    const state = buildSidebarDirectorState(
      makeContext({
        currentShell: "case",
        currentLens: "entities",
        phase: "reporting",
        draggedObjectKind: "receipt",
        isAttachMode: true,
        confidence: "high",
        dropPrediction: {
          defaultAction: "cite",
          defaultLabel: "Cite in case",
          reason: "current case + receipt context",
          alternateActions: [],
        },
      }),
    );

    expect(state.targetLens).toBe("notes");
    expect(state.shouldSwitchLens).toBe(true);
    expect(state.lensSections.notes?.promotedSectionIds).toContain("hunt-notes");
    expect(state.lensSections.notes?.promotedSectionIds).toContain("templates");
    expect(state.lensSections.notes?.expandedSectionIds).toContain("current-shell");
    expect(state.adjacentSurfacePromotion.bottomPanelTab).toBe("receipts");
    expect(state.adjacentSurfacePromotion.inspectorTab).toBe("proof");
  });

  it("promotes mounts and proof-preserving surfaces for file drag with an active run", () => {
    const state = buildSidebarDirectorState(
      makeContext({
        currentLens: "entities",
        draggedObjectKind: "file",
        isAttachMode: true,
        activeRunId: "run-1",
        confidence: "high",
        likelyIntent: "mount",
        dropPrediction: {
          defaultAction: "mount",
          defaultLabel: "Mount to active run",
          reason: "active run context",
          alternateActions: [],
        },
      }),
    );

    expect(state.targetLens).toBe("files");
    expect(state.lensSections.files?.preferredView).toBe("mounts");
    expect(state.lensSections.files?.promotedSectionIds).toContain("mounts");
    expect(state.adjacentSurfacePromotion.bottomPanelTab).toBe("terminal");
    expect(state.adjacentSurfacePromotion.shouldOpenBottomPanel).toBe(true);
  });

  it("promotes scopes and graph context for signal drag", () => {
    const state = buildSidebarDirectorState(
      makeContext({
        currentLens: "entities",
        draggedObjectKind: "signal",
        isAttachMode: true,
        confidence: "high",
        likelyIntent: "watch",
        dropPrediction: {
          defaultAction: "watch",
          defaultLabel: "Add to watchlist",
          reason: "scopes lens active",
          alternateActions: [],
        },
      }),
    );

    expect(state.targetLens).toBe("scopes");
    expect(state.lensSections.scopes?.promotedSectionIds).toContain("watchlists");
    expect(state.adjacentSurfacePromotion.inspectorTab).toBe("graph");
  });

  it("promotes recent history for compare work", () => {
    const state = buildSidebarDirectorState(
      makeContext({
        currentLens: "files",
        draggedObjectKind: "receipt",
        isAttachMode: true,
        confidence: "high",
        likelyIntent: "compare",
        suggestedOpenMode: "compare",
        dropPrediction: {
          defaultAction: "compare",
          defaultLabel: "Compare",
          reason: "receipt comparison",
          alternateActions: [],
        },
      }),
    );

    expect(state.adjacentSurfacePromotion.bottomPanelTab).toBe("diff");
    expect(state.adjacentSurfacePromotion.inspectorTab).toBe("proof");
  });
});
