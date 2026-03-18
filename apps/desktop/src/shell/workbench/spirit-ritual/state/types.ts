import type {
  Artifact,
  ArtifactKind,
  Hunt,
  Run,
  SemanticAttachment,
} from "../../huntTypes";
import type { HuntSpiritKind, HuntSpiritMood } from "../../spirit";

export const SPIRIT_RITUAL_PANEL_MODES = ["intention", "draw", "upload"] as const;

export type SpiritRitualPanelMode = (typeof SPIRIT_RITUAL_PANEL_MODES)[number];
export type SpiritRitualResolvedMode = SpiritRitualPanelMode | "hybrid";
export type SpiritRitualLegacyBindSource =
  | "quick-configure"
  | "thesis"
  | "anchor-artifacts"
  | null;

export interface SpiritRitualContext {
  hunt: Hunt;
  artifacts: Record<string, Artifact>;
  runs: Record<string, Run>;
  currentLens?: string | null;
  currentShell?: string | null;
  activeStationId?: string | null;
}

export interface SpiritRitualSuggestion {
  id: string;
  label: string;
  detail: string;
  promptFragment: string;
  focusSurfaces: string[];
  keywords: string[];
  sourceMode: SpiritRitualPanelMode | "context" | "hybrid";
  spiritKindHints: Partial<Record<HuntSpiritKind, number>>;
}

export interface SpiritRitualIntentionDraft {
  text: string;
  selectedSuggestionIds: string[];
}

export interface SpiritRitualDrawPoint {
  x: number;
  y: number;
  t?: number;
  pressure?: number;
}

export interface SpiritRitualDrawStroke {
  id: string;
  points: SpiritRitualDrawPoint[];
}

export interface SpiritRitualDrawDraft {
  strokes: SpiritRitualDrawStroke[];
  canvasWidth: number;
  canvasHeight: number;
}

export type SpiritRitualUploadItemKind = "artifact-anchor" | "external-file";

export interface SpiritRitualUploadItem {
  id: string;
  kind: SpiritRitualUploadItemKind;
  label: string;
  artifactId: string | null;
  artifactKind: ArtifactKind | null;
  semanticHints: SemanticAttachment[];
  mimeType: string | null;
  extension: string | null;
  byteSize: number | null;
}

export interface SpiritRitualUploadDraft {
  items: SpiritRitualUploadItem[];
  selectedItemIds: string[];
  preferredAnchorIds: string[];
}

export interface SpiritRitualDraft {
  activePanel: SpiritRitualPanelMode;
  intention: SpiritRitualIntentionDraft;
  draw: SpiritRitualDrawDraft;
  upload: SpiritRitualUploadDraft;
  isPinned: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface SpiritRitualKindScore {
  kind: HuntSpiritKind;
  score: number;
}

export interface SpiritRitualModeAnalysis {
  mode: SpiritRitualResolvedMode;
  engaged: boolean;
  confidence: number;
  scoredKinds: SpiritRitualKindScore[];
  rationale: string[];
  focusSurfaces: string[];
  emphasis: string[];
  suggestions: SpiritRitualSuggestion[];
  thesis: string | null;
  anchorArtifactIds: string[];
}

export interface SpiritRitualRecommendation {
  kind: HuntSpiritKind;
  label: string;
  confidenceScore: number;
  rationale: string;
  alternates: HuntSpiritKind[];
  biasLine: string;
  focusSurfaces: string[];
  liveMood: HuntSpiritMood;
}

export interface SpiritRitualReadiness {
  canRelease: boolean;
  blockingReasons: string[];
}

export interface SpiritRitualSynthesis {
  resolvedMode: SpiritRitualResolvedMode;
  engagedModes: SpiritRitualPanelMode[];
  modeAnalyses: Partial<Record<SpiritRitualPanelMode, SpiritRitualModeAnalysis>>;
  suggestions: SpiritRitualSuggestion[];
  recommendation: SpiritRitualRecommendation;
  thesis: string | null;
  anchorArtifactIds: string[];
  readiness: SpiritRitualReadiness;
}

export interface SpiritRitualCommitPayload {
  kind: HuntSpiritKind;
  ritualBindSource: SpiritRitualResolvedMode;
  legacyBindSource: SpiritRitualLegacyBindSource;
  bindReason: string;
  thesis: string | null;
  anchorArtifactIds: string[];
  isPinned: boolean;
  confidenceScore: number;
  liveMood: HuntSpiritMood;
  engagedModes: SpiritRitualPanelMode[];
  selectedSuggestionIds: string[];
}

