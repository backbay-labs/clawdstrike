import { detectPhase } from "../../anticipation/phaseDetection";
import type { IntentType, WorkPhase } from "../../anticipation/types";
import type {
  Artifact,
  ArtifactKind,
  Hunt,
  HuntStore,
  SemanticAssignmentIndex,
  SemanticAttachment,
} from "../../huntTypes";
import type { LensId, ShellMode, TabKind, WorkbenchState } from "../../workbenchState";
import type { HuntSpiritState } from "../types";

export type HuntSpiritArtifactCounts = Partial<Record<ArtifactKind, number>>;
export type HuntSpiritSemanticCounts = Partial<Record<SemanticAttachment, number>>;

export interface HuntSpiritSelectorOverrides {
  activeRunId?: string | null;
  activeCaseId?: string | null;
  draggedObjectKind?: ArtifactKind | TabKind | null;
  likelyIntent?: IntentType | null;
  confidenceScore?: number | null;
  phase?: WorkPhase | null;
}

export interface HuntSpiritSignalSnapshot {
  huntId: string;
  huntTitle: string;
  currentShell: ShellMode;
  currentLens: LensId;
  activeRunId: string | null;
  activeCaseId: string | null;
  draggedObjectKind: ArtifactKind | TabKind | null;
  likelyIntent: IntentType | null;
  phase: WorkPhase;
  phaseScore: number;
  confidenceScore: number;
  totalArtifacts: number;
  totalRuns: number;
  runningRunCount: number;
  artifactCounts: HuntSpiritArtifactCounts;
  semanticCounts: HuntSpiritSemanticCounts;
  dominantArtifactKinds: ArtifactKind[];
  dominantSemantics: SemanticAttachment[];
  suggestedAnchorArtifactIds: string[];
  boundSpirit: HuntSpiritState | null;
}

const SEMANTIC_PRIORITY: Record<SemanticAttachment, number> = {
  target: 5,
  evidence: 4,
  "run-input": 4,
  notes: 3,
  watch: 4,
  mount: 4,
  cite: 3,
  compare: 3,
};

const ARTIFACT_PRIORITY: Record<ArtifactKind, number> = {
  receipt: 5,
  evidence: 5,
  file: 4,
  entity: 4,
  note: 4,
  signal: 3,
  query: 2,
  snapshot: 2,
};

function incrementCount<T extends string>(
  counts: Partial<Record<T, number>>,
  key: T,
  amount = 1,
): void {
  counts[key] = (counts[key] ?? 0) + amount;
}

function mergeCounts<T extends string>(
  target: Partial<Record<T, number>>,
  source: Partial<Record<T, number>>,
): Partial<Record<T, number>> {
  const merged = { ...target };

  for (const [key, value] of Object.entries(source) as Array<[T, number]>) {
    merged[key] = (merged[key] ?? 0) + value;
  }

  return merged;
}

function countArtifacts(
  artifactIds: string[],
  artifacts: Record<string, Artifact>,
): HuntSpiritArtifactCounts {
  const counts: HuntSpiritArtifactCounts = {};

  for (const artifactId of artifactIds) {
    const artifact = artifacts[artifactId];
    if (!artifact) continue;
    incrementCount(counts, artifact.kind);
  }

  return counts;
}

export function countSemanticAssignments(
  assignments: SemanticAssignmentIndex | null | undefined,
): HuntSpiritSemanticCounts {
  const counts: HuntSpiritSemanticCounts = {};
  if (!assignments || typeof assignments !== "object") {
    return counts;
  }

  for (const [semantic, artifactIds] of Object.entries(assignments) as Array<
    [SemanticAttachment, string[]]
  >) {
    if (Array.isArray(artifactIds) && artifactIds.length > 0) {
      incrementCount(counts, semantic, artifactIds.length);
    }
  }

  return counts;
}

function listDominantKeys<T extends string>(
  counts: Partial<Record<T, number>>,
  limit = 3,
): T[] {
  return (Object.entries(counts) as Array<[T, number | undefined]>)
    .filter(([, value]) => (value ?? 0) > 0)
    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))
    .slice(0, limit)
    .map(([key]) => key as T);
}

function resolveActiveRunId(
  hunt: Hunt,
  huntStore: HuntStore,
  activeRunId: string | null | undefined,
): string | null {
  if (activeRunId && hunt.runIds.includes(activeRunId)) {
    return activeRunId;
  }

  for (const runId of hunt.runIds) {
    const run = huntStore.runs[runId];
    if (run?.status === "running") {
      return runId;
    }
  }

  return null;
}

function deriveLikelyIntent(
  artifactCounts: HuntSpiritArtifactCounts,
  semanticCounts: HuntSpiritSemanticCounts,
  hasActiveRun: boolean,
  hasActiveCase: boolean,
): IntentType | null {
  if ((semanticCounts.mount ?? 0) > 0) return "mount";
  if ((semanticCounts["run-input"] ?? 0) > 0 || hasActiveRun) return "run-input";
  if ((semanticCounts.cite ?? 0) > 0 || (semanticCounts.compare ?? 0) > 0) {
    return hasActiveCase ? "cite" : "compare";
  }
  if ((semanticCounts.target ?? 0) > 0) return "attach-target";
  if ((semanticCounts.watch ?? 0) > 0) return "watch";
  if ((semanticCounts.evidence ?? 0) > 0) return "attach-evidence";
  if ((artifactCounts.file ?? 0) > 0) return "mount";
  if ((artifactCounts.receipt ?? 0) > 0) return hasActiveCase ? "cite" : "compare";
  if ((artifactCounts.entity ?? 0) > 0 || (artifactCounts.signal ?? 0) > 0) {
    return "attach-target";
  }
  return null;
}

function deriveConfidenceScore(input: {
  totalArtifacts: number;
  totalRuns: number;
  runningRunCount: number;
  hasActiveCase: boolean;
  dominantArtifactKinds: ArtifactKind[];
  dominantSemantics: SemanticAttachment[];
  likelyIntent: IntentType | null;
  draggedObjectKind: ArtifactKind | TabKind | null;
}): number {
  const artifactSignal = Math.min(32, input.totalArtifacts * 6);
  const runSignal = Math.min(18, input.totalRuns * 7);
  const activitySignal = input.runningRunCount > 0 ? 14 : 0;
  const caseSignal = input.hasActiveCase ? 10 : 0;
  const semanticSignal = Math.min(16, input.dominantSemantics.length * 6);
  const intentSignal = input.likelyIntent ? 8 : 0;
  const dragSignal = input.draggedObjectKind ? 6 : 0;
  const artifactVarietySignal = Math.min(10, input.dominantArtifactKinds.length * 3);

  return Math.max(
    18,
    Math.min(
      100,
      artifactSignal
        + runSignal
        + activitySignal
        + caseSignal
        + semanticSignal
        + intentSignal
        + dragSignal
        + artifactVarietySignal,
    ),
  );
}

export function selectSuggestedSpiritAnchorArtifactIds(
  hunt: Hunt,
  huntStore: HuntStore,
  limit = 3,
): string[] {
  if (hunt.spirit?.anchorArtifactIds.length) {
    return hunt.spirit.anchorArtifactIds
      .filter((artifactId) => Boolean(huntStore.artifacts[artifactId]))
      .slice(0, limit);
  }

  const scores = new Map<string, number>();

  const awardAssignments = (assignments: SemanticAssignmentIndex | null | undefined): void => {
    if (!assignments || typeof assignments !== "object") {
      return;
    }
    for (const [semantic, artifactIds] of Object.entries(assignments) as Array<
      [SemanticAttachment, string[]]
    >) {
      const semanticScore = SEMANTIC_PRIORITY[semantic] ?? 1;
      if (!Array.isArray(artifactIds)) continue;
      for (const artifactId of artifactIds) {
        scores.set(artifactId, (scores.get(artifactId) ?? 0) + semanticScore);
      }
    }
  };

  awardAssignments(hunt.semanticAssignments);

  for (const runId of hunt.runIds) {
    const run = huntStore.runs[runId];
    if (!run) continue;
    awardAssignments(run.semanticAssignments);
  }

  const linkedCase = hunt.caseId ? huntStore.cases[hunt.caseId] : null;
  if (linkedCase) {
    awardAssignments(linkedCase.semanticAssignments);
  }

  for (const artifactId of hunt.artifactIds) {
    const artifact = huntStore.artifacts[artifactId];
    if (!artifact) continue;
    scores.set(artifactId, (scores.get(artifactId) ?? 0) + (ARTIFACT_PRIORITY[artifact.kind] ?? 0));
  }

  return [...hunt.artifactIds]
    .filter((artifactId) => Boolean(huntStore.artifacts[artifactId]))
    .sort((leftId, rightId) => {
      const scoreDelta = (scores.get(rightId) ?? 0) - (scores.get(leftId) ?? 0);
      if (scoreDelta !== 0) return scoreDelta;
      const createdDelta =
        (huntStore.artifacts[rightId]?.createdAt ?? 0) - (huntStore.artifacts[leftId]?.createdAt ?? 0);
      if (createdDelta !== 0) return createdDelta;
      return leftId.localeCompare(rightId);
    })
    .slice(0, limit);
}

export function selectActiveHuntSpiritSignalSnapshot(
  state: WorkbenchState,
  overrides: HuntSpiritSelectorOverrides = {},
): HuntSpiritSignalSnapshot | null {
  const huntId = state.huntStore.dock.activeHuntId;
  if (!huntId) return null;

  const hunt = state.huntStore.hunts[huntId];
  if (!hunt) return null;

  const artifactCounts = countArtifacts(hunt.artifactIds, state.huntStore.artifacts);
  const runningRunCount = hunt.runIds.filter(
    (runId) => state.huntStore.runs[runId]?.status === "running",
  ).length;

  const activeRunId = resolveActiveRunId(hunt, state.huntStore, overrides.activeRunId);
  const activeCaseId = overrides.activeCaseId ?? hunt.caseId ?? null;
  const semanticCounts = hunt.runIds.reduce<HuntSpiritSemanticCounts>(
    (counts, runId) => {
      const run = state.huntStore.runs[runId];
      if (!run) return counts;
      return mergeCounts(counts, countSemanticAssignments(run.semanticAssignments));
    },
    countSemanticAssignments(hunt.semanticAssignments),
  );

  if (activeCaseId) {
    const linkedCase = state.huntStore.cases[activeCaseId];
    if (linkedCase) {
      Object.assign(
        semanticCounts,
        mergeCounts(semanticCounts, countSemanticAssignments(linkedCase.semanticAssignments)),
      );
    }
  }

  const dominantArtifactKinds = listDominantKeys(artifactCounts);
  const dominantSemantics = listDominantKeys(semanticCounts);
  const likelyIntent =
    overrides.likelyIntent
    ?? deriveLikelyIntent(
      artifactCounts,
      semanticCounts,
      activeRunId !== null,
      activeCaseId !== null,
    );

  const phaseResult = overrides.phase
    ? {
        phase: overrides.phase,
        score: Math.max(40, overrides.confidenceScore ?? 70),
      }
    : detectPhase(state.shell, state.lens, activeRunId !== null, activeCaseId !== null);

  const confidenceScore = Math.max(
    0,
    Math.min(
      100,
      overrides.confidenceScore
      ?? deriveConfidenceScore({
        totalArtifacts: hunt.artifactIds.length,
        totalRuns: hunt.runIds.length,
        runningRunCount,
        hasActiveCase: activeCaseId !== null,
        dominantArtifactKinds,
        dominantSemantics,
        likelyIntent,
        draggedObjectKind: overrides.draggedObjectKind ?? null,
      }),
    ),
  );

  return {
    huntId: hunt.id,
    huntTitle: hunt.title,
    currentShell: state.shell,
    currentLens: state.lens,
    activeRunId,
    activeCaseId,
    draggedObjectKind: overrides.draggedObjectKind ?? null,
    likelyIntent,
    phase: phaseResult.phase,
    phaseScore: phaseResult.score,
    confidenceScore,
    totalArtifacts: hunt.artifactIds.length,
    totalRuns: hunt.runIds.length,
    runningRunCount,
    artifactCounts,
    semanticCounts,
    dominantArtifactKinds,
    dominantSemantics,
    suggestedAnchorArtifactIds: selectSuggestedSpiritAnchorArtifactIds(hunt, state.huntStore),
    boundSpirit: hunt.spirit,
  };
}
