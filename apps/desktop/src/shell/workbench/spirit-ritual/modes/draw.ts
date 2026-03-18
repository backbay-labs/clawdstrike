import type { SpiritRitualDrawDraft, SpiritRitualModeAnalysis, SpiritRitualSuggestion } from "../state/types";
import { analyzeSpiritDrawDraft } from "../draw";
import { deriveConfidenceScore, focusSurfacesForKind, makeSuggestionId, uniqueStrings } from "./shared";

function buildSuggestions(features: ReturnType<typeof analyzeSpiritDrawDraft>["features"]): SpiritRitualSuggestion[] {
  const suggestions: SpiritRitualSuggestion[] = [];

  if (features.closureRatio >= 0.4) {
    suggestions.push({
      id: makeSuggestionId("draw", "close-the-center"),
      label: "Close the center",
      detail: "The sketch is already circling inward toward a target or proof locus.",
      promptFragment: "Close the investigation around a defined center",
      focusSurfaces: ["Entities", "Receipts"],
      keywords: ["center", "close", "locus"],
      sourceMode: "draw",
      spiritKindHints: { tracker: 0.8, lantern: 0.6 },
    });
  }

  if (features.orthogonalRatio >= 0.45) {
    suggestions.push({
      id: makeSuggestionId("draw", "brace-the-workflow"),
      label: "Brace the workflow",
      detail: "The sketch is leaning into rails, brackets, and mounted structure.",
      promptFragment: "Brace the workflow around mounted inputs and file rails",
      focusSurfaces: ["Files", "Mounts", "Run Input"],
      keywords: ["brace", "workflow", "mount"],
      sourceMode: "draw",
      spiritKindHints: { forge: 1 },
    });
  }

  if (features.crossingRatio >= 0.3) {
    suggestions.push({
      id: makeSuggestionId("draw", "weave-the-relationships"),
      label: "Weave the relationships",
      detail: "The linework is crossing enough to suggest a wider map.",
      promptFragment: "Weave the relationships across the active evidence threads",
      focusSurfaces: ["History", "Scopes", "Entities"],
      keywords: ["weave", "relationships", "map"],
      sourceMode: "draw",
      spiritKindHints: { loom: 1 },
    });
  }

  if (features.horizontalRatio >= 0.3 && features.layeredness >= 0.2) {
    suggestions.push({
      id: makeSuggestionId("draw", "stack-the-record"),
      label: "Stack the record",
      detail: "The sketch reads like a set of proof bands or docket lines.",
      promptFragment: "Stack the proof into a durable investigative record",
      focusSurfaces: ["Notes", "Citations", "Compare"],
      keywords: ["stack", "record", "proof"],
      sourceMode: "draw",
      spiritKindHints: { ledger: 1, lantern: 0.2 },
    });
  }

  return suggestions;
}

export function analyzeDrawMode(
  draft: SpiritRitualDrawDraft,
): SpiritRitualModeAnalysis {
  const analysis = analyzeSpiritDrawDraft(draft);
  const topKinds = analysis.scoredKinds.slice(0, 2).map((entry) => entry.kind);

  return {
    mode: "draw",
    engaged: draft.strokes.length > 0,
    confidence: analysis.scoredKinds.length > 0
      ? deriveConfidenceScore(analysis.scoredKinds, analysis.confidence / 10)
      : 0,
    scoredKinds: analysis.scoredKinds,
    rationale: analysis.rationale,
    focusSurfaces: uniqueStrings([
      ...analysis.focusSurfaces,
      ...topKinds.flatMap((kind) => focusSurfacesForKind(kind)),
    ]),
    emphasis: uniqueStrings(topKinds),
    suggestions: buildSuggestions(analysis.features),
    thesis: null,
    anchorArtifactIds: [],
  };
}

