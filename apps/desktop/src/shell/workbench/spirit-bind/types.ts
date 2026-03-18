import type { Artifact, Hunt, Run } from "../huntTypes";
import type { HuntSpiritBindSource, HuntSpiritKind, HuntSpiritMood } from "../spirit";

export type SpiritBindMode = "quick-configure" | "thesis" | "anchor-artifacts" | "manual";

export interface SpiritBindContext {
  hunt: Hunt;
  artifacts: Record<string, Artifact>;
  runs: Record<string, Run>;
  currentLens?: string | null;
  currentShell?: string | null;
  activeStationId?: string | null;
}

export interface SpiritBindDraft {
  mode: SpiritBindMode;
  thesis: string;
  selectedAnchorArtifactIds: string[];
  manualKind: HuntSpiritKind | null;
  isPinned: boolean;
}

export interface SpiritBindAlternate {
  kind: HuntSpiritKind;
  label: string;
}

export interface SpiritBindCandidate {
  kind: HuntSpiritKind;
  label: string;
  confidenceScore: number;
  rationale: string;
  biasLine: string;
  predictedFocusSurfaces: string[];
  alternates: SpiritBindAlternate[];
  liveMood: HuntSpiritMood;
  bindSource: HuntSpiritBindSource;
  thesis: string | null;
  anchorArtifactIds: string[];
}

export interface SpiritBindCommit {
  kind: HuntSpiritKind;
  bindSource: HuntSpiritBindSource;
  bindReason: string;
  thesis: string | null;
  anchorArtifactIds: string[];
  isPinned: boolean;
  confidenceScore: number;
  liveMood: HuntSpiritMood;
}

export interface SpiritBindDockPreview {
  label: string;
  accentColor: string;
  contour: string;
  detail: string;
}

export interface SpiritBindSidebarPreview {
  wakeTitle: string;
  wakeReason: string;
  biasLine: string;
}

export interface SpiritBindWorkspacePreview {
  title: string;
  stance: string;
  fieldStrength: number;
  motionLabel: string;
}

export interface SpiritBindPreviewModel {
  dock: SpiritBindDockPreview;
  sidebar: SpiritBindSidebarPreview;
  workspace: SpiritBindWorkspacePreview;
}
