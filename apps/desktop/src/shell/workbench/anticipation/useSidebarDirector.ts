/**
 * useSidebarDirector — derives native sidebar behavior from the shared
 * anticipation context.
 *
 * The director does not render anything itself. It answers:
 * - should the sidebar spring open
 * - should a different lens spring load
 * - which sections inside a lens should move, expand, hide, or explain why
 * - which adjacent surfaces should wake up to preserve context and proof flow
 */
import { useMemo } from "react";
import type {
  AdjacentSurfacePromotion,
  AnticipationContext,
  LensSectionDirective,
  SidebarDirectorState,
} from "./types";
import { TIMING } from "./types";
import { useAnticipationContext } from "./AnticipationProvider";
import type { LensId } from "../workbenchState";

const DRAG_LENS_MAP: Partial<Record<string, LensId>> = {
  entity: "entities",
  signal: "scopes",
  "signal-thread": "scopes",
  file: "files",
  receipt: "notes",
  note: "notes",
  evidence: "notes",
  query: "history",
  snapshot: "history",
};

function dedupe<T>(values: T[]): T[] {
  return Array.from(new Set(values));
}

function baseDirective(sectionOrder: string[], expandedSectionIds: string[] = []): LensSectionDirective {
  return {
    sectionOrder,
    promotedSectionIds: [],
    expandedSectionIds,
    hiddenSectionIds: [],
    reasonsBySectionId: {},
    previewReason: null,
    retractPolicy: "manual",
  };
}

function prioritizeSections(directive: LensSectionDirective, ids: string[]) {
  directive.sectionOrder = dedupe([
    ...ids,
    ...directive.sectionOrder.filter((id) => !ids.includes(id)),
  ]);
}

function promoteSection(
  directive: LensSectionDirective,
  id: string,
  reason?: string | null,
  options: { expand?: boolean; prioritize?: boolean } = {},
) {
  directive.promotedSectionIds.push(id);
  if (options.expand !== false) {
    directive.expandedSectionIds.push(id);
  }
  if (options.prioritize !== false) {
    prioritizeSections(directive, [id]);
  }
  if (reason) {
    directive.reasonsBySectionId[id] = reason;
  }
}

function hideSection(directive: LensSectionDirective, id: string) {
  directive.hiddenSectionIds.push(id);
  directive.sectionOrder = directive.sectionOrder.filter((sectionId) => sectionId !== id);
}

function finalizeDirective(directive: LensSectionDirective): LensSectionDirective {
  return {
    ...directive,
    sectionOrder: dedupe(directive.sectionOrder),
    promotedSectionIds: dedupe(directive.promotedSectionIds),
    expandedSectionIds: dedupe(directive.expandedSectionIds),
    hiddenSectionIds: dedupe(directive.hiddenSectionIds),
  };
}

function resolveReason(
  anticipation: AnticipationContext,
  fallback: string,
): string {
  const openModeReason = anticipation.openModeReason !== "default"
    ? anticipation.openModeReason
    : null;
  return (
    anticipation.dropPrediction?.reason
    ?? anticipation.lensChangeReason
    ?? openModeReason
    ?? (
      anticipation.spiritBias?.confidenceGatePassed
        ? anticipation.spiritBias.reason
        : null
    )
    ?? fallback
  );
}

function promoteSpiritBiasSection(
  directive: LensSectionDirective,
  anticipation: AnticipationContext,
  preferredLens: LensId,
  targetLens: LensId | null,
  sectionId: string,
  fallback: string,
  options: { expand?: boolean; prioritize?: boolean } = {},
) {
  if (!anticipation.spiritBias?.confidenceGatePassed) return;
  if (anticipation.spiritBias.preferredLens !== preferredLens && targetLens !== preferredLens) {
    return;
  }

  promoteSection(
    directive,
    sectionId,
    anticipation.spiritBias.reason ?? fallback,
    {
      expand: anticipation.confidence === "high" || options.expand === true,
      prioritize: options.prioritize,
    },
  );
}

function buildEntitiesDirective(
  anticipation: AnticipationContext,
  targetLens: LensId | null,
): LensSectionDirective {
  const directive = baseDirective(["hunt-entities", "hosts", "identities", "quick-actions"], ["hunt-entities"]);

  if (!anticipation.activeHuntId) {
    hideSection(directive, "hunt-entities");
    promoteSection(directive, "quick-actions", "No active hunt yet.");
    promoteSection(directive, "identities", "Identity pivots are still a strong starting point.", {
      expand: false,
      prioritize: false,
    });
    directive.retractPolicy = "spring";
    return finalizeDirective(directive);
  }

  const entityAttach =
    anticipation.draggedObjectKind === "entity"
    || anticipation.likelyIntent === "attach-target"
    || targetLens === "entities";

  if (entityAttach) {
    promoteSection(
      directive,
      "hunt-entities",
      resolveReason(anticipation, "Current hunt is the likely attach target."),
    );
    promoteSection(
      directive,
      "quick-actions",
      "Follow-up entity actions stay one move away.",
      { expand: anticipation.phase === "investigation", prioritize: false },
    );
  }

  if (anticipation.likelyIntent === "watch" || anticipation.draggedObjectKind === "signal") {
    promoteSection(directive, "identities", "Watch intent usually starts with identity context.");
  }

  if (anticipation.phase === "investigation") {
    promoteSection(
      directive,
      "hosts",
      "Investigation mode favors expanding infrastructure pivots.",
      { expand: anticipation.confidence === "high", prioritize: false },
    );
  }

  promoteSpiritBiasSection(
    directive,
    anticipation,
    "entities",
    targetLens,
    "hunt-entities",
    "Spirit stance is leaning toward target context.",
  );

  if (anticipation.confidence === "high" && anticipation.isAttachMode) {
    directive.expandedSectionIds.push("hosts", "identities", "quick-actions");
    directive.retractPolicy = "spring";
  }

  directive.previewReason = anticipation.lensChangeReason;
  return finalizeDirective(directive);
}

function buildNotesDirective(
  anticipation: AnticipationContext,
  targetLens: LensId | null,
): LensSectionDirective {
  const directive = baseDirective(
    ["hunt-notes", "current-shell", "quick-actions", "templates"],
    ["quick-actions"],
  );

  if (!anticipation.activeHuntId) {
    hideSection(directive, "hunt-notes");
    promoteSection(
      directive,
      "templates",
      "No active hunt yet, so templates are the fastest way to start writing.",
    );
    directive.retractPolicy = "spring";
    return finalizeDirective(directive);
  }

  const noteAttach =
    anticipation.draggedObjectKind === "receipt"
    || anticipation.draggedObjectKind === "note"
    || anticipation.draggedObjectKind === "evidence"
    || anticipation.likelyIntent === "cite"
    || targetLens === "notes";

  if (noteAttach) {
    promoteSection(
      directive,
      "hunt-notes",
      resolveReason(anticipation, "Notes are the likely proof surface for this artifact."),
    );
  }

  if (anticipation.currentShell === "case" || anticipation.phase === "reporting") {
    promoteSection(directive, "current-shell", "Case reporting keeps proof context close.");
    promoteSection(directive, "templates", "Reporting flow benefits from fast note templates.");
  }

  promoteSpiritBiasSection(
    directive,
    anticipation,
    "notes",
    targetLens,
    "hunt-notes",
    "Spirit stance is leaning toward proof and note surfaces.",
  );

  if (anticipation.confidence === "high" && anticipation.isAttachMode) {
    directive.expandedSectionIds.push("current-shell", "templates");
    directive.retractPolicy = "spring";
  }

  directive.previewReason = anticipation.lensChangeReason;
  return finalizeDirective(directive);
}

function buildFilesDirective(
  anticipation: AnticipationContext,
  targetLens: LensId | null,
): LensSectionDirective {
  const directive = baseDirective(
    ["hunt-files", "current-shell", "workspace", "mounts"],
    ["current-shell"],
  );

  if (!anticipation.activeHuntId) {
    hideSection(directive, "hunt-files");
    promoteSection(directive, "workspace", "Browse the workspace until a hunt is active.");
    directive.preferredView = "files";
    directive.retractPolicy = "spring";
    directive.previewReason = anticipation.lensChangeReason ?? "Workspace browsing is the safest default.";
    return finalizeDirective(directive);
  }

  const fileIntent =
    anticipation.draggedObjectKind === "file"
    || anticipation.likelyIntent === "mount"
    || anticipation.likelyIntent === "run-input"
    || anticipation.likelyIntent === "attach-evidence"
    || targetLens === "files";

  if (anticipation.likelyIntent === "mount" || anticipation.likelyIntent === "run-input") {
    directive.preferredView = "mounts";
    promoteSection(
      directive,
      "mounts",
      resolveReason(anticipation, "Active run context favors mounts and inputs."),
    );
    promoteSection(
      directive,
      "current-shell",
      anticipation.currentShell === "lab"
        ? "Lab shell keeps file execution surfaces close."
        : "Current shell has the active mount surface.",
      { prioritize: false },
    );
  } else if (fileIntent) {
    directive.preferredView = anticipation.currentShell === "lab" ? "files" : "assets";
    promoteSection(
      directive,
      "hunt-files",
      resolveReason(anticipation, "Current hunt is the likely evidence destination."),
    );
    promoteSection(
      directive,
      "workspace",
      "Workspace files remain close for fast pivoting.",
      { expand: anticipation.confidence === "high", prioritize: false },
    );
  }

  if (anticipation.currentShell === "lab" && anticipation.confidence !== "low") {
    promoteSection(directive, "current-shell", "Lab shell prefers live file surfaces.");
  }

  promoteSpiritBiasSection(
    directive,
    anticipation,
    "files",
    targetLens,
    anticipation.spiritBias?.preferredIntent === "mount" ? "mounts" : "hunt-files",
    "Spirit stance is leaning toward file intake and execution surfaces.",
  );

  if (anticipation.confidence === "high" && anticipation.isAttachMode) {
    directive.expandedSectionIds.push("workspace", "mounts", "hunt-files");
    directive.retractPolicy = "spring";
  }

  directive.previewReason = anticipation.lensChangeReason ?? anticipation.openModeReason;
  return finalizeDirective(directive);
}

function buildScopesDirective(
  anticipation: AnticipationContext,
  targetLens: LensId | null,
): LensSectionDirective {
  const directive = baseDirective(["hunt-scopes", "watchlists", "feeds", "quick-actions"], ["watchlists"]);

  if (!anticipation.activeHuntId) {
    hideSection(directive, "hunt-scopes");
    promoteSection(directive, "watchlists", "No active hunt yet, so persistent scopes are the best landing zone.");
    promoteSection(directive, "quick-actions", "Create a watchlist or follow a technique first.", {
      prioritize: false,
    });
    directive.retractPolicy = "spring";
    return finalizeDirective(directive);
  }

  const scopeIntent =
    anticipation.draggedObjectKind === "signal"
    || anticipation.draggedObjectKind === "signal-thread"
    || anticipation.likelyIntent === "watch"
    || targetLens === "scopes";

  if (scopeIntent) {
    promoteSection(
      directive,
      "watchlists",
      resolveReason(anticipation, "Scopes and watchlists are the likely destination."),
    );
    promoteSection(
      directive,
      "hunt-scopes",
      "Current hunt scope is ready for a live watch pivot.",
      { expand: anticipation.confidence === "high" },
    );
  }

  if (anticipation.phase === "discovery" || anticipation.phase === "triage") {
    promoteSection(
      directive,
      "feeds",
      "Early-phase work benefits from upstream scope feeds staying visible.",
      { expand: false, prioritize: false },
    );
  }

  promoteSpiritBiasSection(
    directive,
    anticipation,
    "scopes",
    targetLens,
    "watchlists",
    "Spirit stance is leaning toward scope and watch work.",
  );

  if (anticipation.confidence === "high" && anticipation.isAttachMode) {
    directive.expandedSectionIds.push("feeds", "quick-actions");
    directive.retractPolicy = "spring";
  }

  directive.previewReason = anticipation.lensChangeReason;
  return finalizeDirective(directive);
}

function buildHistoryDirective(
  anticipation: AnticipationContext,
  targetLens: LensId | null,
): LensSectionDirective {
  const directive = baseDirective(["hunt-runs", "current-session", "today"], ["current-session"]);

  if (!anticipation.activeHuntId) {
    hideSection(directive, "hunt-runs");
    promoteSection(directive, "current-session", "Session history is the only strong signal without an active hunt.");
    directive.retractPolicy = "spring";
    return finalizeDirective(directive);
  }

  const historyIntent =
    anticipation.draggedObjectKind === "query"
    || anticipation.draggedObjectKind === "snapshot"
    || anticipation.likelyIntent === "compare"
    || targetLens === "history";

  if (historyIntent) {
    promoteSection(
      directive,
      "current-session",
      resolveReason(anticipation, "Recent pivots matter more than older history here."),
    );
    promoteSection(
      directive,
      "today",
      anticipation.likelyIntent === "compare"
        ? "Comparison work benefits from recent sibling history."
        : "Today keeps the freshest pivots visible.",
      { expand: anticipation.confidence === "high", prioritize: false },
    );
  }

  if (anticipation.activeRunId) {
    promoteSection(directive, "hunt-runs", "Active runs should stay visible during investigation.");
  }

  promoteSpiritBiasSection(
    directive,
    anticipation,
    "history",
    targetLens,
    "current-session",
    "Spirit stance is leaning toward recent pivots and comparison history.",
    { expand: false },
  );

  if (anticipation.confidence === "high" && anticipation.isAttachMode) {
    directive.expandedSectionIds.push("hunt-runs", "today");
    directive.retractPolicy = "spring";
  }

  directive.previewReason = anticipation.openModeReason;
  return finalizeDirective(directive);
}

function buildSandboxesDirective(
  anticipation: AnticipationContext,
  targetLens: LensId | null,
): LensSectionDirective {
  const directive = baseDirective(["hunt-sandboxes", "live", "quick-actions"], ["live", "quick-actions"]);

  if (!anticipation.activeHuntId) {
    hideSection(directive, "hunt-sandboxes");
    promoteSection(directive, "quick-actions", "No active hunt yet, so quick-start sandbox actions lead.");
    directive.retractPolicy = "spring";
    return finalizeDirective(directive);
  }

  const sandboxIntent =
    anticipation.draggedObjectKind === "file"
    && (anticipation.likelyIntent === "mount" || anticipation.likelyIntent === "run-input");

  if (sandboxIntent || targetLens === "sandboxes" || anticipation.currentShell === "lab") {
    promoteSection(
      directive,
      "live",
      resolveReason(anticipation, "Live sandbox surfaces should absorb mounted evidence."),
    );
    promoteSection(
      directive,
      "hunt-sandboxes",
      "Current hunt can stage sandbox work without leaving the shell.",
      { prioritize: false },
    );
  }

  promoteSpiritBiasSection(
    directive,
    anticipation,
    "sandboxes",
    targetLens,
    "live",
    "Spirit stance is leaning toward live sandbox absorption.",
    { prioritize: false },
  );

  if (anticipation.confidence === "high" && anticipation.isAttachMode) {
    directive.expandedSectionIds.push("hunt-sandboxes");
    directive.retractPolicy = "spring";
  }

  directive.previewReason = anticipation.lensChangeReason;
  return finalizeDirective(directive);
}

function buildSwarmsDirective(
  anticipation: AnticipationContext,
  targetLens: LensId | null,
): LensSectionDirective {
  const directive = baseDirective(["hunt-swarms", "live-runs", "quick-actions"], ["quick-actions"]);

  if (!anticipation.activeHuntId) {
    hideSection(directive, "hunt-swarms");
    promoteSection(directive, "quick-actions", "No active hunt yet, so swarm setup stays at the edge.");
    directive.retractPolicy = "spring";
    return finalizeDirective(directive);
  }

  if (targetLens === "swarms" || anticipation.currentShell === "hunt") {
    promoteSection(
      directive,
      "hunt-swarms",
      anticipation.phase === "investigation"
        ? "Investigation mode favors swarm execution."
        : "Current hunt is ready for coordinated automation.",
    );
  }

  if (anticipation.phase === "investigation") {
    promoteSection(directive, "live-runs", "Automation status matters more during investigation.");
  }

  if (anticipation.confidence === "high" && anticipation.isAttachMode) {
    directive.expandedSectionIds.push("live-runs", "hunt-swarms");
    directive.retractPolicy = "spring";
  }

  directive.previewReason = anticipation.lensChangeReason;
  return finalizeDirective(directive);
}

function buildAdjacentSurfacePromotion(
  anticipation: AnticipationContext,
  targetLens: LensId | null,
): AdjacentSurfacePromotion {
  const resolvedIntent = anticipation.likelyIntent ?? anticipation.dropPrediction?.defaultAction ?? null;

  if (resolvedIntent === "compare" || anticipation.suggestedOpenMode === "compare") {
    return {
      bottomPanelTab: "diff",
      inspectorTab: "proof",
      shouldOpenBottomPanel: anticipation.confidence !== "low",
      shouldShowInspector: true,
      reason: resolveReason(anticipation, "Comparison work benefits from diff and proof surfaces."),
    };
  }

  if (resolvedIntent === "cite" || resolvedIntent === "attach-evidence") {
    return {
      bottomPanelTab: "receipts",
      inspectorTab: "proof",
      shouldOpenBottomPanel: anticipation.isAttachMode && anticipation.confidence !== "low",
      shouldShowInspector: anticipation.phase === "reporting" || anticipation.confidence !== "low",
      reason: resolveReason(anticipation, "Receipts and proof should stay visible while attaching evidence."),
    };
  }

  if (resolvedIntent === "mount" || resolvedIntent === "run-input") {
    return {
      bottomPanelTab: "terminal",
      inspectorTab: "context",
      shouldOpenBottomPanel: anticipation.confidence !== "low",
      shouldShowInspector: true,
      reason: resolveReason(anticipation, "Mounting files works best with run and context surfaces open."),
    };
  }

  if (targetLens === "history") {
    return {
      bottomPanelTab: "tape",
      inspectorTab: "context",
      shouldOpenBottomPanel: anticipation.confidence === "high",
      shouldShowInspector: anticipation.confidence !== "low",
      reason: resolveReason(anticipation, "Recent history keeps the current pivot chain understandable."),
    };
  }

  if (targetLens === "scopes") {
    return {
      bottomPanelTab: null,
      inspectorTab: "graph",
      shouldOpenBottomPanel: false,
      shouldShowInspector: anticipation.confidence !== "low",
      reason: resolveReason(anticipation, "Scope work benefits from graph context staying visible."),
    };
  }

  return {
    bottomPanelTab: null,
    inspectorTab: "context",
    shouldOpenBottomPanel: false,
    shouldShowInspector: anticipation.confidence === "high" && targetLens === "entities",
    reason: anticipation.lensChangeReason ?? anticipation.dropPrediction?.reason ?? null,
  };
}

export function buildSidebarDirectorState(
  anticipation: AnticipationContext,
): SidebarDirectorState {
  const dragTargetLens = anticipation.draggedObjectKind
    ? (DRAG_LENS_MAP[anticipation.draggedObjectKind] ?? null)
    : null;

  const targetLens =
    dragTargetLens
    ?? anticipation.suggestedLens
    ?? (anticipation.spiritBias?.confidenceGatePassed ? anticipation.spiritBias.preferredLens : null);
  const shouldOpenSidebar =
    (anticipation.isAttachMode && anticipation.confidence !== "low")
    || (anticipation.shouldChangeLens && anticipation.confidence === "high");
  const shouldSwitchLens =
    targetLens !== null
    && targetLens !== anticipation.currentLens
    && (
      (anticipation.isAttachMode && anticipation.confidence === "high")
      || anticipation.shouldChangeLens
    );

  return {
    shouldOpenSidebar,
    shouldAutoCollapseSidebar: !anticipation.isAttachMode && !anticipation.shouldChangeLens,
    targetLens,
    shouldSwitchLens,
    autoSwitchDelayMs: shouldSwitchLens ? TIMING.SPRING_LOAD_MS : null,
    globalReason:
      anticipation.dropPrediction?.reason
      ?? anticipation.lensChangeReason
      ?? (anticipation.openModeReason !== "default" ? anticipation.openModeReason : null)
      ?? (
        anticipation.spiritBias?.confidenceGatePassed
          ? anticipation.spiritBias.reason
          : null
      )
      ?? anticipation.pathSuggestedAction?.label
      ?? null,
    lensSections: {
      entities: buildEntitiesDirective(anticipation, targetLens),
      notes: buildNotesDirective(anticipation, targetLens),
      files: buildFilesDirective(anticipation, targetLens),
      scopes: buildScopesDirective(anticipation, targetLens),
      history: buildHistoryDirective(anticipation, targetLens),
      sandboxes: buildSandboxesDirective(anticipation, targetLens),
      swarms: buildSwarmsDirective(anticipation, targetLens),
    },
    adjacentSurfacePromotion: buildAdjacentSurfacePromotion(anticipation, targetLens),
  };
}

export function useSidebarDirector(): SidebarDirectorState {
  const anticipation = useAnticipationContext();

  return useMemo(() => buildSidebarDirectorState(anticipation), [anticipation]);
}
