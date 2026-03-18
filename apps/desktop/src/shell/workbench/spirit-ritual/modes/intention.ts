import { groupArtifactsByKind } from "../../huntTypes";
import { HUNT_SPIRIT_KINDS, type HuntSpiritKind } from "../../spirit";
import type {
  SpiritRitualContext,
  SpiritRitualIntentionDraft,
  SpiritRitualModeAnalysis,
  SpiritRitualSuggestion,
} from "../state/types";
import {
  addKindScore,
  createKindScoreMap,
  deriveConfidenceScore,
  focusSurfacesForKind,
  makeSuggestionId,
  rankKindScores,
  uniqueStrings,
} from "./shared";

const INTENTION_PATTERNS: Array<{
  kind: HuntSpiritKind;
  pattern: RegExp;
  weight: number;
  rationale: string;
}> = [
  { kind: "tracker", pattern: /\b(trace|track|watch|target|pivot|operator)\b/i, weight: 16, rationale: "The language keeps leaning toward pursuit and live targets." },
  { kind: "lantern", pattern: /\b(receipt|cite|proof|prove|evidence|witness)\b/i, weight: 16, rationale: "The intention is asking the hunt to illuminate proof." },
  { kind: "forge", pattern: /\b(file|mount|sandbox|run|payload|execute|workflow)\b/i, weight: 16, rationale: "The intention is centered on files, runs, or mounted material." },
  { kind: "loom", pattern: /\b(cluster|graph|map|thread|weave|scope|relationship)\b/i, weight: 16, rationale: "The wording suggests a relationship-heavy investigative weave." },
  { kind: "ledger", pattern: /\b(report|record|compare|history|audit|brief|case)\b/i, weight: 16, rationale: "The intention is building toward a durable record." },
];

function createSuggestion(
  input: Omit<SpiritRitualSuggestion, "id"> & { seed: string },
): SpiritRitualSuggestion {
  return {
    ...input,
    id: makeSuggestionId(input.sourceMode, input.seed),
  };
}

function contextSuggestions(context: SpiritRitualContext): SpiritRitualSuggestion[] {
  const counts = groupArtifactsByKind(context.hunt.artifactIds, context.artifacts);
  const suggestions: SpiritRitualSuggestion[] = [];

  if ((counts.entity ?? 0) > 0 || (counts.signal ?? 0) > 0) {
    suggestions.push(
      createSuggestion({
        seed: "track-operator-path",
        label: "Track the operator path",
        detail: "Lean into entities, watched pivots, and live pursuit surfaces.",
        promptFragment: "Track the operator path through watched entities and pivot points",
        focusSurfaces: ["Entities", "Watch", "Targets"],
        keywords: ["track", "operator", "watch", "pivot"],
        sourceMode: "context",
        spiritKindHints: { tracker: 1, loom: 0.35 },
      }),
    );
  }

  if ((counts.receipt ?? 0) > 0 || (counts.evidence ?? 0) > 0) {
    suggestions.push(
      createSuggestion({
        seed: "prove-the-trail",
        label: "Prove the trail",
        detail: "Bias toward receipts, evidence, and witness posture.",
        promptFragment: "Build proof around the receipt and evidence trail",
        focusSurfaces: ["Receipts", "Evidence", "Citations"],
        keywords: ["proof", "receipt", "evidence", "cite"],
        sourceMode: "context",
        spiritKindHints: { lantern: 1, ledger: 0.45 },
      }),
    );
  }

  if ((counts.file ?? 0) > 0 || context.hunt.runIds.length > 0) {
    suggestions.push(
      createSuggestion({
        seed: "follow-mounted-material",
        label: "Follow the mounted material",
        detail: "Bias toward files, run inputs, and mounted execution paths.",
        promptFragment: "Follow the mounted material through active runs and file pivots",
        focusSurfaces: ["Files", "Mounts", "Run Input"],
        keywords: ["mount", "run", "file", "payload"],
        sourceMode: "context",
        spiritKindHints: { forge: 1 },
      }),
    );
  }

  if ((counts.note ?? 0) > 0 || context.currentLens === "notes") {
    suggestions.push(
      createSuggestion({
        seed: "assemble-the-record",
        label: "Assemble the record",
        detail: "Bias toward notes, citations, and compare surfaces.",
        promptFragment: "Assemble the record around citations, notes, and comparison",
        focusSurfaces: ["Notes", "Citations", "Compare"],
        keywords: ["record", "notes", "compare", "history"],
        sourceMode: "context",
        spiritKindHints: { ledger: 1, lantern: 0.3 },
      }),
    );
  }

  if ((counts.query ?? 0) > 0 || (counts.snapshot ?? 0) > 0) {
    suggestions.push(
      createSuggestion({
        seed: "weave-the-threads",
        label: "Weave the threads",
        detail: "Bias toward correlation, scopes, and history surfaces.",
        promptFragment: "Weave the evidence threads into a wider relationship map",
        focusSurfaces: ["History", "Scopes", "Entities"],
        keywords: ["weave", "thread", "scope", "graph"],
        sourceMode: "context",
        spiritKindHints: { loom: 1, tracker: 0.25 },
      }),
    );
  }

  return suggestions;
}

function applySuggestionHints(
  suggestions: SpiritRitualSuggestion[],
  selectedSuggestionIds: string[],
  scores: Record<HuntSpiritKind, number>,
): void {
  const selected = new Set(selectedSuggestionIds);
  for (const suggestion of suggestions) {
    if (!selected.has(suggestion.id)) continue;
    for (const kind of HUNT_SPIRIT_KINDS) {
      const hint = suggestion.spiritKindHints[kind];
      if (!hint) continue;
      addKindScore(scores, kind, hint * 14);
    }
  }
}

function buildThesis(
  draft: SpiritRitualIntentionDraft,
  suggestions: SpiritRitualSuggestion[],
): string | null {
  const base = draft.text.trim();
  if (base.length > 0) return base;

  const selected = suggestions.filter((suggestion) => draft.selectedSuggestionIds.includes(suggestion.id));
  if (selected.length === 0) return null;
  return selected.map((suggestion) => suggestion.promptFragment).join(". ");
}

export function analyzeIntentionMode(
  context: SpiritRitualContext,
  draft: SpiritRitualIntentionDraft,
): SpiritRitualModeAnalysis {
  const scores = createKindScoreMap();
  const suggestions = contextSuggestions(context);
  const thesis = buildThesis(draft, suggestions);
  const engaged = Boolean(thesis) || draft.selectedSuggestionIds.length > 0;
  const rationale: string[] = [];

  if (context.currentLens === "files" || context.currentLens === "sandboxes") {
    addKindScore(scores, "forge", 8);
  }
  if (context.currentLens === "notes") {
    addKindScore(scores, "ledger", 8);
    addKindScore(scores, "lantern", 4);
  }
  if (context.currentLens === "entities" || context.currentLens === "scopes") {
    addKindScore(scores, "tracker", 8);
    addKindScore(scores, "loom", 4);
  }

  if (thesis) {
    for (const entry of INTENTION_PATTERNS) {
      if (entry.pattern.test(thesis)) {
        addKindScore(scores, entry.kind, entry.weight);
        rationale.push(entry.rationale);
      }
    }

    if (rationale.length === 0) {
      addKindScore(scores, "ledger", 6);
      addKindScore(scores, "tracker", 4);
      rationale.push("The authored thesis is adding operator-authored direction even before anchors settle.");
    }
  }

  applySuggestionHints(suggestions, draft.selectedSuggestionIds, scores);
  const ranking = rankKindScores(scores);
  const topKinds = ranking.slice(0, 2).map((entry) => entry.kind);
  const focusSurfaces = uniqueStrings([
    ...topKinds.flatMap((kind) => focusSurfacesForKind(kind)),
    ...suggestions
      .filter((suggestion) => draft.selectedSuggestionIds.includes(suggestion.id))
      .flatMap((suggestion) => suggestion.focusSurfaces),
  ]);

  if (draft.selectedSuggestionIds.length > 0 && rationale.length === 0) {
    rationale.push("The selected suggestion chips are nudging the spirit toward a clearer posture.");
  }

  return {
    mode: "intention",
    engaged,
    confidence: deriveConfidenceScore(ranking, thesis ? 8 : draft.selectedSuggestionIds.length * 3),
    scoredKinds: ranking,
    rationale,
    focusSurfaces,
    emphasis: uniqueStrings(topKinds),
    suggestions,
    thesis,
    anchorArtifactIds: [],
  };
}

