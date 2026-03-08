import type { ArtifactKind, SemanticAttachment } from "../../huntTypes";
import type { LensId, ShellMode } from "../../workbenchState";
import { createHuntSpiritState, getHuntSpiritMeta } from "../defaults";
import type {
  HuntSpiritBindSource,
  HuntSpiritKind,
  HuntSpiritMood,
  HuntSpiritState,
} from "../types";
import type { HuntSpiritSignalSnapshot } from "../selectors";

export interface HuntSpiritCandidate {
  kind: HuntSpiritKind;
  score: number;
  rationale: string;
  preferredLenses: LensId[];
  preferredShells: ShellMode[];
  preferredSemantics: SemanticAttachment[];
  predictedFocus: string[];
}

export interface HuntSpiritInferenceResult {
  baseSpirit: HuntSpiritCandidate;
  alternates: HuntSpiritCandidate[];
  liveMood: HuntSpiritMood;
  confidenceScore: number;
  shouldRespectPinnedSpirit: boolean;
  biasLine: string;
}

interface ScoredContribution {
  weight: number;
  label: string;
}

const SPIRIT_SURFACE_PREFERENCES: Record<
  HuntSpiritKind,
  {
    lenses: LensId[];
    shells: ShellMode[];
    semantics: SemanticAttachment[];
    focus: string[];
  }
> = {
  tracker: {
    lenses: ["entities", "scopes", "history"],
    shells: ["hunt", "wire"],
    semantics: ["target", "watch"],
    focus: ["Entities", "Watchlists", "live target surfaces"],
  },
  lantern: {
    lenses: ["notes", "history", "entities"],
    shells: ["hunt", "case"],
    semantics: ["evidence", "cite"],
    focus: ["Receipts", "Evidence", "citation surfaces"],
  },
  forge: {
    lenses: ["files", "sandboxes", "history"],
    shells: ["lab", "hunt"],
    semantics: ["mount", "run-input"],
    focus: ["Files", "Mounts", "sandbox surfaces"],
  },
  loom: {
    lenses: ["history", "entities", "scopes"],
    shells: ["hunt", "wire"],
    semantics: ["compare", "target"],
    focus: ["Entity threads", "history", "correlation surfaces"],
  },
  ledger: {
    lenses: ["notes", "history", "files"],
    shells: ["case", "hunt"],
    semantics: ["notes", "cite", "compare"],
    focus: ["Notes", "Proof stacks", "reporting surfaces"],
  },
};

function createContributionMap(): Record<HuntSpiritKind, ScoredContribution[]> {
  return {
    tracker: [],
    lantern: [],
    forge: [],
    loom: [],
    ledger: [],
  };
}

function addContribution(
  scores: Record<HuntSpiritKind, number>,
  reasons: Record<HuntSpiritKind, ScoredContribution[]>,
  kind: HuntSpiritKind,
  weight: number,
  label: string,
): void {
  scores[kind] += weight;
  reasons[kind].push({ weight, label });
}

function applyArtifactSignal(
  kind: ArtifactKind,
  count: number,
  scores: Record<HuntSpiritKind, number>,
  reasons: Record<HuntSpiritKind, ScoredContribution[]>,
): void {
  if (count <= 0) return;

  switch (kind) {
    case "file":
      addContribution(scores, reasons, "forge", count * 22, "this hunt is file-led");
      addContribution(scores, reasons, "tracker", count * 4, "the file trail still points at targets");
      break;
    case "receipt":
      addContribution(scores, reasons, "lantern", count * 20, "receipts are carrying the proof trail");
      addContribution(scores, reasons, "ledger", count * 14, "receipt history is building a proof stack");
      break;
    case "note":
      addContribution(scores, reasons, "ledger", count * 18, "notes are defining the record");
      addContribution(scores, reasons, "lantern", count * 8, "notes are clarifying the evidence line");
      break;
    case "entity":
      addContribution(scores, reasons, "tracker", count * 18, "the hunt is entity-forward");
      addContribution(scores, reasons, "loom", count * 10, "entity connections are starting to braid together");
      break;
    case "signal":
      addContribution(scores, reasons, "tracker", count * 14, "live signals are still setting direction");
      addContribution(scores, reasons, "loom", count * 12, "signal threads need correlation");
      break;
    case "evidence":
      addContribution(scores, reasons, "lantern", count * 12, "supporting evidence is accumulating");
      addContribution(scores, reasons, "ledger", count * 10, "evidence is settling into a durable record");
      addContribution(scores, reasons, "forge", count * 6, "evidence still needs hands-on handling");
      break;
    case "query":
      addContribution(scores, reasons, "loom", count * 14, "query output is exposing relationship patterns");
      addContribution(scores, reasons, "ledger", count * 8, "query trails need structured capture");
      break;
    case "snapshot":
      addContribution(scores, reasons, "forge", count * 12, "snapshots suggest active sandbox shaping");
      addContribution(scores, reasons, "lantern", count * 6, "snapshots preserve a visible proof edge");
      break;
  }
}

function applySemanticSignal(
  semantic: SemanticAttachment,
  count: number,
  scores: Record<HuntSpiritKind, number>,
  reasons: Record<HuntSpiritKind, ScoredContribution[]>,
): void {
  if (count <= 0) return;

  switch (semantic) {
    case "target":
      addContribution(scores, reasons, "tracker", count * 22, "target attachments are anchoring the hunt");
      addContribution(scores, reasons, "loom", count * 8, "targets are forming a broader graph");
      break;
    case "watch":
      addContribution(scores, reasons, "tracker", count * 18, "watch pressure favors a tracking posture");
      break;
    case "mount":
      addContribution(scores, reasons, "forge", count * 22, "mounted material points at an active workbench");
      break;
    case "run-input":
      addContribution(scores, reasons, "forge", count * 24, "run inputs are shaping the operative center");
      break;
    case "evidence":
      addContribution(scores, reasons, "lantern", count * 18, "evidence assignment keeps proof in view");
      addContribution(scores, reasons, "ledger", count * 10, "evidence assignment strengthens the case record");
      break;
    case "notes":
      addContribution(scores, reasons, "ledger", count * 18, "notes are becoming the durable narrative");
      break;
    case "cite":
      addContribution(scores, reasons, "lantern", count * 16, "citation work wants explicit proof handling");
      addContribution(scores, reasons, "ledger", count * 16, "citation work is building a record trail");
      break;
    case "compare":
      addContribution(scores, reasons, "loom", count * 18, "comparison work needs relationship weaving");
      addContribution(scores, reasons, "ledger", count * 14, "comparison work needs a stable record");
      break;
  }
}

function applyContextSignals(
  snapshot: HuntSpiritSignalSnapshot,
  scores: Record<HuntSpiritKind, number>,
  reasons: Record<HuntSpiritKind, ScoredContribution[]>,
): void {
  switch (snapshot.currentShell) {
    case "lab":
      addContribution(scores, reasons, "forge", 18, "the lab shell favors active handling");
      break;
    case "case":
      addContribution(scores, reasons, "ledger", 16, "casework favors a record-keeping posture");
      addContribution(scores, reasons, "lantern", 10, "casework keeps proof illumination close");
      break;
    case "wire":
      addContribution(scores, reasons, "tracker", 12, "wire work starts from signals and entities");
      addContribution(scores, reasons, "loom", 8, "wire work benefits from correlation");
      break;
    case "hunt":
      addContribution(scores, reasons, "tracker", 8, "the hunt shell keeps target posture close");
      addContribution(scores, reasons, "lantern", 6, "the hunt shell keeps evidence close");
      break;
  }

  switch (snapshot.currentLens) {
    case "files":
    case "sandboxes":
      addContribution(scores, reasons, "forge", 14, "the current lens is already centered on active material");
      break;
    case "notes":
      addContribution(scores, reasons, "ledger", 14, "the notes lens favors durable capture");
      addContribution(scores, reasons, "lantern", 8, "the notes lens keeps evidence explanation visible");
      break;
    case "history":
      addContribution(scores, reasons, "loom", 12, "the history lens favors pattern weaving");
      addContribution(scores, reasons, "ledger", 10, "the history lens supports proof continuity");
      break;
    case "entities":
    case "scopes":
      addContribution(scores, reasons, "tracker", 12, "the current lens is target-heavy");
      addContribution(scores, reasons, "loom", 8, "entity views still need correlation");
      break;
    case "swarms":
      addContribution(scores, reasons, "loom", 10, "swarm context emphasizes thread coordination");
      break;
  }

  switch (snapshot.phase) {
    case "discovery":
      addContribution(scores, reasons, "tracker", 14, "the hunt is still in discovery");
      addContribution(scores, reasons, "lantern", 8, "discovery still depends on evidence illumination");
      break;
    case "triage":
      addContribution(scores, reasons, "tracker", 10, "triage favors a quick target posture");
      addContribution(scores, reasons, "lantern", 10, "triage still needs proof clarity");
      break;
    case "investigation":
      addContribution(scores, reasons, "forge", 14, "investigation leans into active manipulation");
      addContribution(scores, reasons, "loom", 12, "investigation needs threads connected");
      break;
    case "reporting":
      addContribution(scores, reasons, "ledger", 18, "reporting needs a coherent proof record");
      addContribution(scores, reasons, "lantern", 10, "reporting still needs legible evidence");
      break;
  }

  if (snapshot.activeRunId) {
    addContribution(scores, reasons, "forge", 16, "an active run is shaping the next move");
  }

  if (snapshot.activeCaseId) {
    addContribution(scores, reasons, "ledger", 14, "case linkage favors record continuity");
    addContribution(scores, reasons, "lantern", 10, "case linkage keeps evidence traceable");
  }

  switch (snapshot.likelyIntent) {
    case "mount":
    case "run-input":
      addContribution(scores, reasons, "forge", 20, "the next move looks mount-oriented");
      break;
    case "attach-target":
    case "watch":
      addContribution(scores, reasons, "tracker", 18, "the next move is target-seeking");
      break;
    case "attach-evidence":
      addContribution(scores, reasons, "lantern", 14, "the next move keeps evidence centered");
      break;
    case "compare":
      addContribution(scores, reasons, "loom", 16, "the next move is comparison-heavy");
      addContribution(scores, reasons, "ledger", 10, "comparison still wants a proof trail");
      break;
    case "cite":
      addContribution(scores, reasons, "lantern", 14, "the next move is citation-heavy");
      addContribution(scores, reasons, "ledger", 14, "citation work strengthens the record");
      break;
    case "open":
    case "promote":
    case "split":
    case null:
      break;
  }

  switch (snapshot.draggedObjectKind) {
    case "file":
      addContribution(scores, reasons, "forge", 12, "the dragged material is file-heavy");
      break;
    case "receipt":
      addContribution(scores, reasons, "lantern", 12, "the dragged material is receipt-led");
      addContribution(scores, reasons, "ledger", 8, "the dragged material belongs in the proof stack");
      break;
    case "entity":
    case "signal":
      addContribution(scores, reasons, "tracker", 10, "the dragged material points back to targets");
      break;
    case "note":
      addContribution(scores, reasons, "ledger", 10, "the dragged material strengthens authored record");
      break;
    default:
      break;
  }

  if (snapshot.boundSpirit?.kind) {
    const continuityWeight = snapshot.boundSpirit.isPinned ? 1000 : 12;
    addContribution(
      scores,
      reasons,
      snapshot.boundSpirit.kind,
      continuityWeight,
      snapshot.boundSpirit.isPinned
        ? "the current spirit is pinned and should hold until explicitly rebound"
        : "the current spirit already matches recent posture",
    );
  }
}

function joinReasonLabels(labels: string[]): string {
  if (labels.length === 0) return "the hunt already has enough signal to infer a posture";
  if (labels.length === 1) return labels[0];
  if (labels.length === 2) return `${labels[0]} and ${labels[1]}`;
  return `${labels[0]}, ${labels[1]}, and ${labels[2]}`;
}

function buildCandidate(
  kind: HuntSpiritKind,
  score: number,
  reasons: Record<HuntSpiritKind, ScoredContribution[]>,
): HuntSpiritCandidate {
  const preferences = SPIRIT_SURFACE_PREFERENCES[kind];
  const reasonLabels = reasons[kind]
    .sort((left, right) => right.weight - left.weight)
    .slice(0, 3)
    .map((entry) => entry.label);

  return {
    kind,
    score,
    rationale: `Suggested because ${joinReasonLabels(reasonLabels)}.`,
    preferredLenses: preferences.lenses,
    preferredShells: preferences.shells,
    preferredSemantics: preferences.semantics,
    predictedFocus: preferences.focus,
  };
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function deriveConfidenceScore(
  snapshot: HuntSpiritSignalSnapshot,
  topScore: number,
  runnerUpScore: number,
): number {
  const margin = Math.max(0, topScore - runnerUpScore);
  const weighted =
    snapshot.confidenceScore * 0.55 + Math.min(25, margin * 0.45) + Math.min(20, topScore / 6);
  return clampScore(weighted);
}

function deriveLiveMood(
  snapshot: HuntSpiritSignalSnapshot,
  candidate: HuntSpiritCandidate,
  confidenceScore: number,
): HuntSpiritMood {
  if (snapshot.totalArtifacts === 0 && snapshot.totalRuns === 0 && !snapshot.activeCaseId) {
    return "dormant";
  }

  if (snapshot.draggedObjectKind || snapshot.likelyIntent === "mount" || snapshot.likelyIntent === "run-input") {
    return snapshot.activeRunId ? "pressured" : "focused";
  }

  if (
    snapshot.likelyIntent === "cite"
    || snapshot.likelyIntent === "compare"
    || snapshot.phase === "reporting"
  ) {
    return "witnessing";
  }

  if (
    confidenceScore >= 70
    && !candidate.preferredLenses.includes(snapshot.currentLens)
    && !candidate.preferredShells.includes(snapshot.currentShell)
  ) {
    return "transit";
  }

  if (snapshot.activeRunId || snapshot.phase === "investigation") {
    return "focused";
  }

  return "attuned";
}

function formatBiasLine(predictedFocus: string[]): string {
  if (predictedFocus.length === 0) return "Biases the surfaces already carrying the hunt.";
  if (predictedFocus.length === 1) return `Biases ${predictedFocus[0]}.`;
  if (predictedFocus.length === 2) return `Biases ${predictedFocus[0]} and ${predictedFocus[1]}.`;
  return `Biases ${predictedFocus[0]}, ${predictedFocus[1]}, and ${predictedFocus[2]}.`;
}

export function inferHuntSpirit(snapshot: HuntSpiritSignalSnapshot): HuntSpiritInferenceResult {
  const scores: Record<HuntSpiritKind, number> = {
    tracker: 0,
    lantern: 0,
    forge: 0,
    loom: 0,
    ledger: 0,
  };
  const reasons = createContributionMap();

  for (const [artifactKind, count] of Object.entries(snapshot.artifactCounts) as Array<
    [ArtifactKind, number]
  >) {
    applyArtifactSignal(artifactKind, count ?? 0, scores, reasons);
  }

  for (const [semantic, count] of Object.entries(snapshot.semanticCounts) as Array<
    [SemanticAttachment, number]
  >) {
    applySemanticSignal(semantic, count ?? 0, scores, reasons);
  }

  applyContextSignals(snapshot, scores, reasons);

  const ranked = (Object.entries(scores) as Array<[HuntSpiritKind, number]>)
    .sort((left, right) => right[1] - left[1])
    .map(([kind, score]) => buildCandidate(kind, score, reasons));

  const baseSpirit = ranked[0];
  const runnerUp = ranked[1];
  const confidenceScore = deriveConfidenceScore(
    snapshot,
    baseSpirit?.score ?? 0,
    runnerUp?.score ?? 0,
  );
  const liveMood = deriveLiveMood(snapshot, baseSpirit, confidenceScore);

  return {
    baseSpirit,
    alternates: ranked.slice(1, 3),
    liveMood,
    confidenceScore,
    shouldRespectPinnedSpirit: snapshot.boundSpirit?.isPinned === true,
    biasLine: formatBiasLine(baseSpirit.predictedFocus),
  };
}

export function createInferredHuntSpiritState(
  snapshot: HuntSpiritSignalSnapshot,
  input: {
    bindSource?: HuntSpiritBindSource;
    thesis?: string | null;
    anchorArtifactIds?: string[];
    isPinned?: boolean;
    boundAt?: number;
    reboundAt?: number | null;
  } = {},
): HuntSpiritState {
  const inferred = inferHuntSpirit(snapshot);
  const meta = getHuntSpiritMeta(inferred.baseSpirit.kind);
  const bindReason = meta
    ? `${inferred.baseSpirit.rationale} ${inferred.biasLine}`
    : inferred.baseSpirit.rationale;

  return createHuntSpiritState({
    kind: inferred.baseSpirit.kind,
    bindSource: input.bindSource ?? "system-inferred",
    bindReason,
    thesis: input.thesis ?? snapshot.boundSpirit?.thesis ?? null,
    anchorArtifactIds: input.anchorArtifactIds ?? snapshot.suggestedAnchorArtifactIds,
    isPinned: input.isPinned ?? snapshot.boundSpirit?.isPinned ?? false,
    liveMood: inferred.liveMood,
    confidenceScore: inferred.confidenceScore,
    boundAt: input.boundAt,
    reboundAt: input.reboundAt ?? null,
  });
}
