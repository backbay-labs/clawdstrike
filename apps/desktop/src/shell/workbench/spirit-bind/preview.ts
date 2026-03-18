import { buildSpiritManifestationModel } from "../spirit-ritual/canvas";
import type { SpiritBindCandidate, SpiritBindContext, SpiritBindPreviewModel } from "./types";

export function buildSpiritBindPreviewModel(
  context: SpiritBindContext,
  candidate: SpiritBindCandidate,
): SpiritBindPreviewModel {
  const manifestation = buildSpiritManifestationModel(context, candidate);

  return {
    dock: {
      label: manifestation.label,
      accentColor: manifestation.accentColor,
      contour: manifestation.contour,
      detail: manifestation.focusLine,
    },
    sidebar: {
      wakeTitle: `${manifestation.label} wake`,
      wakeReason: manifestation.reasonLine,
      biasLine: manifestation.biasLine,
    },
    workspace: {
      title: manifestation.release.title,
      stance: manifestation.stance,
      fieldStrength: manifestation.fieldStrength,
      motionLabel: manifestation.motionLabel,
    },
  };
}
