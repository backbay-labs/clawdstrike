import { groupArtifactsByKind, type ArtifactKind, type SemanticAssignmentIndex } from "../huntTypes";
import { createHuntSpiritState, getHuntSpiritMeta, HUNT_SPIRIT_KINDS, type HuntSpiritKind } from "../spirit";
import type {
  SpiritBindCandidate,
  SpiritBindCommit,
  SpiritBindContext,
  SpiritBindDraft,
} from "./types";

const ANCHOR_SEMANTIC_PRIORITY: Record<string, number> = {
  target: 5,
  evidence: 4,
  "run-input": 4,
  watch: 4,
  mount: 4,
  notes: 3,
  cite: 3,
  compare: 3,
};

const ANCHOR_ARTIFACT_PRIORITY: Record<ArtifactKind, number> = {
  receipt: 5,
  evidence: 5,
  file: 4,
  entity: 4,
  note: 4,
  signal: 3,
  query: 2,
  snapshot: 2,
};

const KEYWORD_BOOSTS: Array<{ pattern: RegExp; kind: HuntSpiritKind; weight: number }> = [
  { pattern: /\b(trace|track|watch|target|pivot)\b/i, kind: "tracker", weight: 2.2 },
  { pattern: /\b(receipt|cite|prove|proof|evidence)\b/i, kind: "lantern", weight: 2.2 },
  { pattern: /\b(file|mount|sandbox|build|payload|run)\b/i, kind: "forge", weight: 2.2 },
  { pattern: /\b(map|cluster|graph|thread|scope)\b/i, kind: "loom", weight: 2.2 },
  { pattern: /\b(policy|ledger|compare|audit|history)\b/i, kind: "ledger", weight: 2.2 },
];

const SURFACE_LABELS: Record<string, string> = {
  entities: "Entities",
  evidence: "Evidence",
  receipts: "Receipts",
  notes: "Notes",
  files: "Files",
  mounts: "Mounts",
  "run-input": "Run Input",
  history: "History",
  scopes: "Scopes",
  cite: "Citations",
  compare: "Compare",
  target: "Targets",
  watch: "Watch",
};

function normalizeModeSource(mode: SpiritBindDraft["mode"]): SpiritBindCommit["bindSource"] {
  switch (mode) {
    case "thesis":
      return "thesis";
    case "anchor-artifacts":
      return "anchor-artifacts";
    case "manual":
      return "manual";
    case "quick-configure":
    default:
      return "quick-configure";
  }
}

function scoreKinds(
  context: SpiritBindContext,
  draft: SpiritBindDraft,
): Record<HuntSpiritKind, number> {
  const scores = {
    tracker: 0,
    lantern: 0,
    forge: 0,
    loom: 0,
    ledger: 0,
  } satisfies Record<HuntSpiritKind, number>;

  const artifactIds =
    draft.mode === "anchor-artifacts" && draft.selectedAnchorArtifactIds.length > 0
      ? draft.selectedAnchorArtifactIds
      : context.hunt.artifactIds;
  const counts = groupArtifactsByKind(artifactIds, context.artifacts);
  const runCount = context.hunt.runIds.length;
  const semanticAssignments = context.hunt.semanticAssignments;

  scores.tracker += (counts.entity ?? 0) * 2.1 + (counts.signal ?? 0) * 1.5;
  scores.lantern += (counts.receipt ?? 0) * 2.1 + (counts.evidence ?? 0) * 1.8 + (counts.note ?? 0) * 1;
  scores.forge += (counts.file ?? 0) * 2.1 + (counts.query ?? 0) * 1 + runCount * 1.6;
  scores.loom += (counts.entity ?? 0) * 0.7 + (counts.snapshot ?? 0) * 1 + (counts.query ?? 0) * 1.4;
  scores.ledger += (counts.receipt ?? 0) * 1.2 + (counts.note ?? 0) * 1.7 + (counts.evidence ?? 0) * 1.1;

  scores.tracker += semanticWeight(semanticAssignments, "target", 2.4);
  scores.tracker += semanticWeight(semanticAssignments, "watch", 2.2);
  scores.lantern += semanticWeight(semanticAssignments, "cite", 2.2);
  scores.lantern += semanticWeight(semanticAssignments, "evidence", 1.3);
  scores.forge += semanticWeight(semanticAssignments, "run-input", 2.4);
  scores.forge += semanticWeight(semanticAssignments, "mount", 2.1);
  scores.loom += semanticWeight(semanticAssignments, "compare", 1.8);
  scores.ledger += semanticWeight(semanticAssignments, "compare", 2.1);
  scores.ledger += semanticWeight(semanticAssignments, "notes", 1.7);

  if (context.currentLens === "history" || context.currentLens === "scopes") {
    scores.loom += 1.8;
    scores.ledger += 1.1;
  }
  if (context.currentLens === "files" || context.currentLens === "sandboxes") {
    scores.forge += 1.8;
  }
  if (context.currentLens === "entities") {
    scores.tracker += 1.8;
  }
  if (context.currentLens === "notes") {
    scores.lantern += 1.1;
    scores.ledger += 1.4;
  }

  const title = `${context.hunt.title} ${draft.thesis}`.trim();
  for (const boost of KEYWORD_BOOSTS) {
    if (boost.pattern.test(title)) {
      scores[boost.kind] += boost.weight;
    }
  }

  if (draft.mode === "manual" && draft.manualKind) {
    scores[draft.manualKind] += 100;
  }
  if (draft.mode === "thesis" && draft.thesis.trim().length > 0) {
    scores.ledger += 0.8;
    scores.tracker += 0.4;
  }
  if (draft.mode === "anchor-artifacts" && draft.selectedAnchorArtifactIds.length > 0) {
    scores.lantern += 0.4;
    scores.ledger += 0.4;
  }

  return scores;
}

function semanticWeight(
  assignments: SemanticAssignmentIndex,
  key: string,
  weight: number,
): number {
  return (assignments[key]?.length ?? 0) * weight;
}

function collectDefaultAnchorArtifactIds(
  context: SpiritBindContext,
  limit = 3,
): string[] {
  const scores = new Map<string, number>();

  const awardAssignments = (assignments: SemanticAssignmentIndex): void => {
    for (const [semantic, artifactIds] of Object.entries(assignments)) {
      const weight = ANCHOR_SEMANTIC_PRIORITY[semantic] ?? 0;
      if (weight === 0) continue;
      for (const artifactId of artifactIds) {
        scores.set(artifactId, (scores.get(artifactId) ?? 0) + weight);
      }
    }
  };

  awardAssignments(context.hunt.semanticAssignments);

  for (const runId of context.hunt.runIds) {
    const run = context.runs[runId];
    if (!run) continue;
    awardAssignments(run.semanticAssignments);
  }

  for (const artifactId of context.hunt.artifactIds) {
    const artifact = context.artifacts[artifactId];
    if (!artifact) continue;
    scores.set(artifactId, (scores.get(artifactId) ?? 0) + (ANCHOR_ARTIFACT_PRIORITY[artifact.kind] ?? 0));
  }

  return [...context.hunt.artifactIds]
    .filter((artifactId) => Boolean(context.artifacts[artifactId]))
    .sort((leftId, rightId) => {
      const scoreDelta = (scores.get(rightId) ?? 0) - (scores.get(leftId) ?? 0);
      if (scoreDelta !== 0) return scoreDelta;
      const createdDelta =
        (context.artifacts[rightId]?.createdAt ?? 0) - (context.artifacts[leftId]?.createdAt ?? 0);
      if (createdDelta !== 0) return createdDelta;
      return leftId.localeCompare(rightId);
    })
    .slice(0, limit);
}

function describeReason(
  kind: HuntSpiritKind,
  context: SpiritBindContext,
  draft: SpiritBindDraft,
): string {
  const counts = groupArtifactsByKind(
    draft.mode === "anchor-artifacts" && draft.selectedAnchorArtifactIds.length > 0
      ? draft.selectedAnchorArtifactIds
      : context.hunt.artifactIds,
    context.artifacts,
  );

  switch (kind) {
    case "tracker":
      return counts.entity || counts.signal
        ? "Suggested because this hunt is target-led with active entity and watch pressure."
        : "Suggested because the current language points to trace, pursuit, and watch posture.";
    case "lantern":
      return counts.receipt || counts.evidence
        ? "Suggested because this hunt is receipt-heavy and citation-forward."
        : "Suggested because the hunt needs reveal, proof, and witness posture.";
    case "forge":
      return context.hunt.runIds.length > 0 || counts.file
        ? "Suggested because this hunt already centers runs, files, and mounted inputs."
        : "Suggested because the current material points toward build, execution, and sandbox pressure.";
    case "loom":
      return counts.query || counts.snapshot
        ? "Suggested because this hunt is clustering across multiple threads of evidence."
        : "Suggested because the hunt looks synthesis-heavy and relationship-driven.";
    case "ledger":
      return draft.thesis.trim().length > 0 || counts.note
        ? "Suggested because the authored thesis leans toward proof, comparison, and recorded judgment."
        : "Suggested because the hunt is reasoning across notes, receipts, and comparison work.";
    default:
      return "Suggested because the current hunt material supports this posture.";
  }
}

function derivePredictedFocus(kind: HuntSpiritKind, context: SpiritBindContext): string[] {
  const meta = getHuntSpiritMeta(kind);
  const focus = new Set(meta?.defaultBiases ?? []);

  if (context.currentLens) {
    focus.add(context.currentLens);
  }
  if (context.hunt.runIds.length > 0) {
    focus.add("run-input");
  }
  if (context.hunt.semanticAssignments.evidence?.length) {
    focus.add("evidence");
  }
  if (context.hunt.semanticAssignments.notes?.length) {
    focus.add("notes");
  }

  return Array.from(focus).slice(0, 3).map((key) => SURFACE_LABELS[key] ?? key);
}

function resolveMood(kind: HuntSpiritKind, confidenceScore: number): SpiritBindCommit["liveMood"] {
  if (confidenceScore >= 82) return "focused";
  if (kind === "lantern" || kind === "ledger") return "witnessing";
  return "attuned";
}

export function canBindSpiritDraft(draft: SpiritBindDraft): boolean {
  switch (draft.mode) {
    case "thesis":
      return draft.thesis.trim().length >= 8;
    case "anchor-artifacts":
      return draft.selectedAnchorArtifactIds.length > 0;
    case "manual":
      return draft.manualKind !== null;
    case "quick-configure":
    default:
      return true;
  }
}

export function deriveSpiritBindCandidate(
  context: SpiritBindContext,
  draft: SpiritBindDraft,
): SpiritBindCandidate {
  const scores = scoreKinds(context, draft);
  const ranking = [...HUNT_SPIRIT_KINDS]
    .map((kind) => ({ kind, score: scores[kind] }))
    .sort((a, b) => b.score - a.score);

  const top = ranking[0];
  const runnerUp = ranking[1];
  const confidenceScore = Math.max(
    48,
    Math.min(
      96,
      Math.round(56 + top.score * 4 + Math.max(0, (top.score - (runnerUp?.score ?? 0)) * 6)),
    ),
  );

  const bindSource = normalizeModeSource(draft.mode);
  const label = getHuntSpiritMeta(top.kind)?.label ?? top.kind;
  const predictedFocusSurfaces = derivePredictedFocus(top.kind, context);
  const rationale = describeReason(top.kind, context, draft);
  const biasLine = `Biases ${predictedFocusSurfaces.join(", ")} across dock, wake, and workspace.`;
  const anchorArtifactIds =
    draft.selectedAnchorArtifactIds.length > 0
      ? draft.selectedAnchorArtifactIds
      : collectDefaultAnchorArtifactIds(context);

  return {
    kind: top.kind,
    label,
    confidenceScore,
    rationale,
    biasLine,
    predictedFocusSurfaces,
    alternates: ranking.slice(1, 3).map(({ kind }) => ({
      kind,
      label: getHuntSpiritMeta(kind)?.label ?? kind,
    })),
    liveMood: resolveMood(top.kind, confidenceScore),
    bindSource,
    thesis: draft.thesis.trim() || null,
    anchorArtifactIds,
  };
}

export function buildSpiritBindCommit(
  context: SpiritBindContext,
  draft: SpiritBindDraft,
): SpiritBindCommit {
  const candidate = deriveSpiritBindCandidate(context, draft);
  const spirit = createHuntSpiritState({
    kind: candidate.kind,
    bindSource: candidate.bindSource,
    bindReason: candidate.rationale,
    thesis: candidate.thesis,
    anchorArtifactIds: candidate.anchorArtifactIds,
    isPinned: draft.isPinned,
    confidenceScore: candidate.confidenceScore,
    liveMood: candidate.liveMood,
  });

  return {
    kind: spirit.kind,
    bindSource: spirit.bindSource,
    bindReason: spirit.bindReason ?? candidate.rationale,
    thesis: spirit.thesis,
    anchorArtifactIds: spirit.anchorArtifactIds,
    isPinned: spirit.isPinned,
    confidenceScore: spirit.confidenceScore,
    liveMood: spirit.liveMood,
  };
}
