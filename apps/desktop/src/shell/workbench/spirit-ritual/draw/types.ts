import type { HuntSpiritKind } from "../../spirit";

export interface SpiritDrawFeatures {
  strokeCount: number;
  pointCount: number;
  totalLength: number;
  coverageRatio: number;
  closureRatio: number;
  orthogonalRatio: number;
  horizontalRatio: number;
  diagonalRatio: number;
  crossingRatio: number;
  centeredness: number;
  jaggedness: number;
  layeredness: number;
}

export interface SpiritDrawAnalysis {
  features: SpiritDrawFeatures;
  scoredKinds: Array<{ kind: HuntSpiritKind; score: number }>;
  rationale: string[];
  focusSurfaces: string[];
  confidence: number;
}

