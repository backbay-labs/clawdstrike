import type { ArtifactKind, SemanticAttachment } from "../../huntTypes";

export interface SpiritUploadSelectionSummary {
  selectedCount: number;
  artifactKindCounts: Partial<Record<ArtifactKind, number>>;
  semanticCounts: Partial<Record<SemanticAttachment, number>>;
}

