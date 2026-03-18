import type { HuntSpiritKind } from "../../spirit";
import type {
  SpiritRitualContext,
  SpiritRitualModeAnalysis,
  SpiritRitualUploadDraft,
} from "../state/types";
import { analyzeSpiritUploadDraft } from "../upload";
import { deriveConfidenceScore, focusSurfacesForKind, makeSuggestionId, uniqueStrings } from "./shared";

export function analyzeUploadMode(
  context: SpiritRitualContext,
  draft: SpiritRitualUploadDraft,
): SpiritRitualModeAnalysis {
  void context;
  const analysis = analyzeSpiritUploadDraft(draft);
  const topKinds = analysis.scoredKinds.slice(0, 2).map((entry) => entry.kind);
  const suggestions = analysis.anchorArtifactIds.length > 0
    ? [{
        id: makeSuggestionId("upload", "anchor-the-center"),
        label: "Anchor the center",
        detail: "These anchors are strong enough to become the hunt's center of gravity.",
        promptFragment: "Anchor the hunt around the selected material",
        focusSurfaces: analysis.focusSurfaces,
        keywords: ["anchor", "center", "material"],
        sourceMode: "upload" as const,
        spiritKindHints: topKinds.reduce<Partial<Record<HuntSpiritKind, number>>>((acc, kind, index) => {
          acc[kind] = index === 0 ? 1 : 0.45;
          return acc;
        }, {}),
      }]
    : [];

  return {
    mode: "upload",
    engaged: analysis.summary.selectedCount > 0,
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
    suggestions,
    thesis: null,
    anchorArtifactIds: analysis.anchorArtifactIds,
  };
}
