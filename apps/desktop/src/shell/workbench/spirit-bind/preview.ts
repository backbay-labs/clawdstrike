import { createHuntSpiritState, deriveHuntSpiritRuntimeState, getHuntSpiritMeta } from "../spirit";
import type { SpiritBindCandidate, SpiritBindContext, SpiritBindPreviewModel } from "./types";

function formatFieldStrength(value: number): string {
  if (value >= 0.8) return "high field";
  if (value >= 0.55) return "steady field";
  return "quiet field";
}

export function buildSpiritBindPreviewModel(
  context: SpiritBindContext,
  candidate: SpiritBindCandidate,
): SpiritBindPreviewModel {
  const previewSpirit = createHuntSpiritState({
    kind: candidate.kind,
    bindSource: candidate.bindSource,
    bindReason: candidate.rationale,
    thesis: candidate.thesis,
    anchorArtifactIds: candidate.anchorArtifactIds,
    isPinned: false,
    confidenceScore: candidate.confidenceScore,
    liveMood: candidate.liveMood,
  });

  const runtime = deriveHuntSpiritRuntimeState(previewSpirit, {
    currentLens: context.currentLens,
    currentShell: context.currentShell,
    activeStationId: context.activeStationId,
    confidenceScore: candidate.confidenceScore,
    isActive: true,
  });
  const meta = getHuntSpiritMeta(candidate.kind);

  return {
    dock: {
      label: meta?.label ?? candidate.label,
      accentColor: runtime.accentColor ?? meta?.accentColor ?? "#d4a84b",
      contour: runtime.contour ?? meta?.contour ?? "reticle-vector",
      detail: candidate.predictedFocusSurfaces.join(" • "),
    },
    sidebar: {
      wakeTitle: `${candidate.label} wake`,
      wakeReason: candidate.rationale,
      biasLine: candidate.biasLine,
    },
    workspace: {
      title: context.activeStationId ? `Station ${context.activeStationId}` : "Workbench field",
      stance: runtime.stance,
      fieldStrength: runtime.fieldStrength,
      motionLabel: formatFieldStrength(runtime.fieldStrength),
    },
  };
}
