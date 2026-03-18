import type { SpiritRitualCommitPayload, SpiritRitualContext, SpiritRitualDraft, SpiritRitualLegacyBindSource, SpiritRitualSynthesis } from "./types";

function mapLegacyBindSource(synthesis: SpiritRitualSynthesis): SpiritRitualLegacyBindSource {
  if (synthesis.engagedModes.length === 0) return "quick-configure";
  if (synthesis.resolvedMode === "intention") return "thesis";
  if (synthesis.resolvedMode === "upload") return "anchor-artifacts";
  return null;
}

export function buildSpiritRitualCommitPayload(
  _context: SpiritRitualContext,
  draft: SpiritRitualDraft,
  synthesis: SpiritRitualSynthesis,
): SpiritRitualCommitPayload {
  return {
    kind: synthesis.recommendation.kind,
    ritualBindSource: synthesis.resolvedMode,
    legacyBindSource: mapLegacyBindSource(synthesis),
    bindReason: synthesis.recommendation.rationale,
    thesis: synthesis.thesis,
    anchorArtifactIds: synthesis.anchorArtifactIds,
    isPinned: draft.isPinned,
    confidenceScore: synthesis.recommendation.confidenceScore,
    liveMood: synthesis.recommendation.liveMood,
    engagedModes: synthesis.engagedModes,
    selectedSuggestionIds: draft.intention.selectedSuggestionIds,
  };
}

