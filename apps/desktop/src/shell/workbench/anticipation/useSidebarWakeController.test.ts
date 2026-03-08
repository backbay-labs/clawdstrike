import { describe, expect, it } from "vitest";
import type { AnticipationContext, SidebarDirectorState } from "./types";
import {
  buildSidebarWakePreview,
  clampSidebarWakeTop,
  resolveSidebarWakeGeometry,
  resolveSidebarWakeTop,
  shouldSuppressSidebarWakeForAnchor,
} from "./useSidebarWakeController";

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

function makeDirector(
  overrides: Partial<SidebarDirectorState> = {},
): SidebarDirectorState {
  return {
    shouldOpenSidebar: false,
    shouldAutoCollapseSidebar: false,
    targetLens: null,
    shouldSwitchLens: false,
    autoSwitchDelayMs: null,
    globalReason: null,
    lensSections: {},
    adjacentSurfacePromotion: {
      bottomPanelTab: null,
      inspectorTab: null,
      shouldOpenBottomPanel: false,
      shouldShowInspector: false,
      reason: null,
    },
    ...overrides,
  };
}

describe("buildSidebarWakePreview", () => {
  it("uses predicted drop copy and target lens when context is strong", () => {
    const preview = buildSidebarWakePreview(
      makeContext({
        confidence: "high",
        isAttachMode: true,
        dropPrediction: {
          defaultAction: "attach-target",
          defaultLabel: "Attach to Hunt 26",
          reason: "current hunt is active",
          alternateActions: [],
        },
      }),
      makeDirector({
        targetLens: "entities",
        globalReason: "current hunt is active",
      }),
      true,
    );

    expect(preview.anchorLens).toBe("entities");
    expect(preview.predictedActionLabel).toBe("Attach to Hunt 26");
    expect(preview.predictedReason).toBe("current hunt is active");
    expect(preview.shouldWarmDock).toBe(true);
    expect(preview.allowGhostPeek).toBe(true);
  });

  it("falls back to action-first lens copy when no drop prediction exists", () => {
    const preview = buildSidebarWakePreview(
      makeContext({
        currentLens: "files",
        confidence: "medium",
      }),
      makeDirector(),
      true,
    );

    expect(preview.anchorLens).toBe("files");
    expect(preview.predictedActionLabel).toBe("Open likely file surfaces");
    expect(preview.predictedReason).toBe("default");
  });

  it("does not warm the dock once the sidebar is already open", () => {
    const preview = buildSidebarWakePreview(
      makeContext({
        confidence: "high",
        dropPrediction: {
          defaultAction: "cite",
          defaultLabel: "Cite in current note",
          reason: "reporting flow is active",
          alternateActions: [],
        },
      }),
      makeDirector({
        targetLens: "notes",
        globalReason: "reporting flow is active",
      }),
      false,
    );

    expect(preview.shouldWarmDock).toBe(false);
  });

  it("clamps the wake anchor into the visible viewport", () => {
    expect(clampSidebarWakeTop(8, 900)).toBe(56);
    expect(clampSidebarWakeTop(880, 900)).toBe(752);
    expect(clampSidebarWakeTop(240, 900)).toBe(206);
  });

  it("prefers a concrete source anchor over pointer position when available", () => {
    expect(resolveSidebarWakeTop({ top: 300, height: 30 }, 620, 900)).toBe(281);
    expect(resolveSidebarWakeTop(null, 620, 900)).toBe(586);
  });

  it("uses a flatter row-card geometry for row-originated wakes", () => {
    const geometry = resolveSidebarWakeGeometry(
      { kind: "row", left: 72, width: 220, right: 292 },
      168,
      1440,
    );

    expect(geometry.peekLeft).toBeCloseTo(53.6);
    expect(geometry.peekWidth).toBe(186);
    expect(geometry.peekVariant).toBe("row-card");
    expect(geometry.seamLeft).toBeCloseTo(35.6);
    expect(geometry.seamWidth).toBe(22);
  });

  it("keeps hunt-pill wakes tighter to the dock edge", () => {
    const geometry = resolveSidebarWakeGeometry(
      { kind: "hunt-pill", left: 14, width: 32, right: 46 },
      188,
      1440,
    );

    expect(geometry.peekLeft).toBeCloseTo(23.6);
    expect(geometry.peekWidth).toBe(174);
    expect(geometry.peekVariant).toBe("hunt-pill-chip");
    expect(geometry.seamLeft).toBeCloseTo(15.6);
    expect(geometry.seamWidth).toBe(12);
  });

  it("suppresses sidebar wake cards when a hunt pill is already teaching", () => {
    expect(shouldSuppressSidebarWakeForAnchor("hunt-pill")).toBe(true);
    expect(shouldSuppressSidebarWakeForAnchor("row")).toBe(false);
    expect(shouldSuppressSidebarWakeForAnchor(null)).toBe(false);
  });
});
