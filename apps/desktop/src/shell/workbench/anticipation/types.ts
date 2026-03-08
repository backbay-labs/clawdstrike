/**
 * Intent Gravity — Core type system for anticipation-driven UI.
 *
 * The shell reads the operator's context (shell, lens, selection, drag,
 * recent pivots) and infers likely next actions so the UI can pre-shape
 * itself around them — without ever taking destructive action.
 */
import type {
  ShellMode,
  LensId,
  TabKind,
  BottomPanelTabId,
  InspectorTabId,
  OpenTabMode,
} from "../workbenchState";
import type { ArtifactKind, SemanticAttachment } from "../huntTypes";

// ── Intent ────────────────────────────────────────────────────────

export type IntentType =
  | "attach-target"
  | "attach-evidence"
  | "cite"
  | "mount"
  | "compare"
  | "watch"
  | "open"
  | "split"
  | "promote"
  | "run-input";

// ── Confidence ────────────────────────────────────────────────────

export type ConfidenceLevel = "low" | "medium" | "high";

export const CONFIDENCE_THRESHOLDS = {
  LOW:    { min: 0,  max: 33 },
  MEDIUM: { min: 34, max: 66 },
  HIGH:   { min: 67, max: 100 },
} as const;

export function confidenceLevel(score: number): ConfidenceLevel {
  if (score >= CONFIDENCE_THRESHOLDS.HIGH.min) return "high";
  if (score >= CONFIDENCE_THRESHOLDS.MEDIUM.min) return "medium";
  return "low";
}

// ── Semantic Drop Roles ───────────────────────────────────────────

export type DropSemantic = SemanticAttachment;

export interface DropRole {
  id: string;
  label: string;
  semantic: DropSemantic;
  isDefault: boolean;
  confidence: number;
}

export type CompatibleTargetType = "hunt" | "run" | "case" | "lens" | "staging";
export type CompatibleTargetEmphasis = "primary" | "secondary" | "tertiary";

export interface CompatibleTargetSummary {
  id: string;
  type: CompatibleTargetType;
  label: string;
  emphasis: CompatibleTargetEmphasis;
}

// ── Phase Detection ───────────────────────────────────────────────

export type WorkPhase = "discovery" | "investigation" | "triage" | "reporting";

export interface SidebarSectionSignal {
  id: string;
  title: string;
  visible: boolean;
  priority: number;
  promoted: boolean;
}

export interface BreadcrumbHint {
  label: string;
  objectId: string;
  objectType: string;
}

export interface SuggestedPathAction {
  label: string;
  action: string;
  confidence: number;
}

export interface DropPredictionSummary {
  defaultAction: IntentType;
  defaultLabel: string;
  reason: string;
  alternateActions: Array<{ intent: IntentType; label: string; confidence: number }>;
}

export type SuggestedOpenMode = OpenTabMode;

export interface LensSectionDirective {
  sectionOrder: string[];
  promotedSectionIds: string[];
  expandedSectionIds: string[];
  hiddenSectionIds: string[];
  reasonsBySectionId: Record<string, string>;
  preferredView?: string | null;
  previewReason?: string | null;
  retractPolicy?: "persist" | "spring" | "manual";
}

export interface AdjacentSurfacePromotion {
  bottomPanelTab: BottomPanelTabId | null;
  inspectorTab: InspectorTabId | null;
  shouldOpenBottomPanel: boolean;
  shouldShowInspector: boolean;
  reason: string | null;
}

export interface AnticipationSpiritBias {
  kind: string;
  label: string;
  mood: string;
  stance: string;
  preferredLens: LensId;
  preferredIntent: IntentType;
  preferredSemantics: DropSemantic[];
  wakeLabel: string;
  reason: string;
  confidenceGatePassed: boolean;
}

export type SidebarWakeAnchorKind = "row" | "hunt-pill" | "dock-icon";
export type SidebarWakeAnchorSource = "hover" | "drag";
export type SidebarWakePeekVariant =
  | "generic"
  | "row-card"
  | "hunt-pill-chip"
  | "dock-icon-chip";

export type SidebarWakeState =
  | "idle"
  | "prewake"
  | "ghost-peek"
  | "committed"
  | "retracting";

export interface SidebarWakeDirective {
  wakeState: SidebarWakeState;
  anchorLens: LensId;
  anchorTop: number;
  peekLeft: number;
  peekVariant: SidebarWakePeekVariant;
  seamLeft: number;
  seamWidth: number;
  sourceKind: SidebarWakeAnchorKind | null;
  sourceLabel: string | null;
  sourceObjectType: string | null;
  predictedActionLabel: string;
  predictedReason: string | null;
  peekWidth: number;
  shouldWarmDock: boolean;
  shouldShowSeam: boolean;
  shouldShowGhostPeek: boolean;
}

export interface SidebarDirectorState {
  shouldOpenSidebar: boolean;
  shouldAutoCollapseSidebar: boolean;
  targetLens: LensId | null;
  shouldSwitchLens: boolean;
  autoSwitchDelayMs: number | null;
  globalReason: string | null;
  lensSections: Partial<Record<LensId, LensSectionDirective>>;
  adjacentSurfacePromotion: AdjacentSurfacePromotion;
}

// ── Anticipation Context ──────────────────────────────────────────

export interface AnticipationContext {
  // Current shell state
  currentShell: ShellMode;
  currentLens: LensId;
  activeHuntId: string | null;
  activeRunId: string | null;
  activeCaseId: string | null;

  // Object focus
  selectedObjectType: string | null;
  hoveredObjectType: string | null;
  draggedObjectKind: ArtifactKind | TabKind | null;

  // Behavioral memory
  recentActionChain: string[];
  recentPivots: LensId[];

  // Inferred state
  likelyIntent: IntentType | null;
  confidence: ConfidenceLevel;
  confidenceScore: number;
  dropRoles: DropRole[];
  defaultDropRole: DropRole | null;
  phase: WorkPhase;
  phaseScore: number;
  suggestedLens: LensId | null;
  shouldChangeLens: boolean;
  lensChangeReason: string | null;
  suggestedOpenMode: SuggestedOpenMode;
  openModeReason: string;

  // Higher-order fused signals
  sidebarSections: SidebarSectionSignal[];
  pathBreadcrumbs: BreadcrumbHint[];
  pathSuggestedAction: SuggestedPathAction | null;
  dropPrediction: DropPredictionSummary | null;
  compatibleTargets: CompatibleTargetSummary[];
  modifierOverride: DropSemantic | null;
  stagingItemCount: number;
  stagingSuggestions: StagingSuggestion[];
  spiritBias: AnticipationSpiritBias | null;

  // Flags
  isAttachMode: boolean;
  isSpringLoaded: boolean;
  springLoadedTargetId: string | null;
}

// ── Hover Intent ──────────────────────────────────────────────────

export interface HoverIntent {
  targetId: string;
  targetType: string;
  enteredAt: number;
  isActivated: boolean;       // true after HOVER_ACTIVATION_MS
  subtargets: ProximalAction[];
}

export interface ProximalAction {
  id: string;
  label: string;
  icon?: string;
  action: string;
  promoted: boolean;          // true if inferred as most likely
}

// ── Path Memory ───────────────────────────────────────────────────

export interface PivotStep {
  objectType: string;
  objectId: string;
  objectTitle: string;
  timestamp: number;
}

export interface PivotChain {
  steps: PivotStep[];
  huntId?: string;
}

// ── Staging Shelf ─────────────────────────────────────────────────

export interface StagedItem {
  id: string;
  kind: ArtifactKind;
  title: string;
  sourceUri?: string;
  sourceHuntId?: string;
  stagedAt: number;
}

export interface StagingSuggestion {
  label: string;
  action: string;
  itemIds: string[];
  confidence: number;
}

// ── Explainability ────────────────────────────────────────────────

export interface IntentExplanation {
  shortLabel: string;       // "Attach as target"
  reason: string;           // "current hunt + entity type"
  alternates: string[];     // other possible interpretations
}

// ── Timing Constants ──────────────────────────────────────────────

export const TIMING = {
  HOVER_ACTIVATION_MS: 120,
  HOVER_MAX_MS: 140,
  SPRING_LOAD_MS: 300,
  SPRING_RETRACT_MS: 200,
  PROXIMAL_FADE_IN_MS: 80,
  PROXIMAL_FADE_OUT_MS: 150,
  DROP_ABSORB_MS: 250,
  UNDO_TOAST_MS: 4000,
} as const;

// ── Per-Object Drop Role Mappings ─────────────────────────────────

export const DRAG_ROLE_MAP: Record<string, DropSemantic[]> = {
  entity:          ["target", "watch", "evidence", "cite"],
  receipt:         ["evidence", "compare", "cite", "notes"],
  "signal-thread": ["target", "watch", "cite"],
  signal:          ["target", "watch", "cite"],
  file:            ["mount", "evidence", "run-input", "notes"],
  note:            ["cite", "notes", "evidence"],
  query:           ["run-input", "evidence"],
  snapshot:        ["evidence", "compare"],
  evidence:        ["evidence", "cite"],
};

// ── Shell → Default Lens Mapping ──────────────────────────────────

export const SHELL_DEFAULT_LENS: Record<ShellMode, LensId[]> = {
  wire: ["scopes", "entities"],
  hunt: ["entities", "notes"],
  lab:  ["files", "sandboxes"],
  case: ["notes", "files"],
};

// ── Phase Inference Signals ───────────────────────────────────────

export const PHASE_SIGNALS: Record<WorkPhase, { shells: ShellMode[]; lenses: LensId[]; hasRun: boolean | null; hasCase: boolean | null }> = {
  discovery:     { shells: ["wire"],       lenses: ["scopes", "entities"], hasRun: null,  hasCase: null },
  investigation: { shells: ["hunt"],       lenses: ["entities", "files", "sandboxes"], hasRun: true,  hasCase: null },
  triage:        { shells: ["hunt"],       lenses: ["history", "notes"],  hasRun: null,  hasCase: false },
  reporting:     { shells: ["case"],       lenses: ["notes", "files"],    hasRun: null,  hasCase: true },
};
