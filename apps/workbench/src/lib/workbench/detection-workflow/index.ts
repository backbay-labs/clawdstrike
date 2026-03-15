/**
 * Detection Workflow — barrel export.
 *
 * Organizes the detection engineering workflow module into logical categories:
 * types, adapters, stores, services, hooks, and swarm integration.
 */

// ---- Types ----

export type {
  DetectionDocumentRef,
  DraftSeedKind,
  DraftSeed,
  EvidenceDatasetKind,
  EvidenceItem,
  RedactionState,
  EvidencePack,
  LabRunSummary,
  LabCaseResult,
  LabRun,
  PublishTarget,
  PublicationManifest,
  CoverageGapCandidate,
  ExplainabilityTrace,
  EvaluationPathStep,
} from "./shared-types";

export { createEmptyDatasets } from "./shared-types";

export type {
  DetectionExecutionRequest,
  DetectionExecutionResult,
  ReportArtifact,
  CoverageReport,
  DraftBuildResult,
  PublicationRequest,
  PublicationBuildResult,
} from "./execution-types";

// ---- Adapters ----

export type { DetectionWorkflowAdapter } from "./adapters";
export {
  registerAdapter,
  getAdapter,
  hasAdapter,
  getRegisteredFileTypes,
} from "./adapters";

export { policyAdapter } from "./policy-adapter";
export { sigmaAdapter } from "./sigma-adapter";
export { yaraAdapter } from "./yara-adapter";
export { ocsfAdapter } from "./ocsf-adapter";

// ---- Stores ----

export {
  DocumentIdentityStore,
  getDocumentIdentityStore,
  normalizePath,
} from "./document-identity-store";

export {
  EvidencePackStore,
  getEvidencePackStore,
} from "./evidence-pack-store";

export {
  LabRunStore,
  getLabRunStore,
} from "./lab-run-store";

export {
  PublicationStore,
  getPublicationStore,
} from "./publication-store";

// ---- Services ----

// Draft mappers
export type { MapEventsOptions } from "./draft-mappers";
export {
  mapEventsToDraftSeed,
  mapInvestigationToDraftSeed,
  mapPatternToDraftSeed,
  inferDataSourceHints,
  inferTechniqueHints,
  recommendFormats,
} from "./draft-mappers";

// Draft generator
export type { DraftResult } from "./draft-generator";
export {
  generateDraft,
  generateDraftFromEvents,
  generateDraftFromInvestigation,
  generateDraftFromPattern,
} from "./draft-generator";

// Evidence redaction
export type { RedactionResult, PackRedactionResult } from "./evidence-redaction";
export {
  MAX_STRUCTURED_EVENT_SIZE,
  MAX_BYTE_SAMPLE_SIZE,
  redactEvidenceItem,
  redactEvidencePack,
} from "./evidence-redaction";

// Explainability
export type {
  TraceOutcome,
  EnrichedTrace,
  RunComparisonDelta,
  TraceGroups,
} from "./explainability";
export {
  extractTraces,
  compareRuns,
  groupTracesByOutcome,
  getSourceLineRange,
} from "./explainability";

// Coverage gap engine
export type {
  DocumentCoverageEntry,
  CoverageGapInput,
} from "./coverage-gap-engine";
export {
  discoverCoverageGaps,
  deduplicateGaps,
  rankGaps,
  suppressNoisyGaps,
} from "./coverage-gap-engine";

// ---- Hooks ----

export type {
  UseDraftDetectionOptions,
  UseDraftDetectionResult,
} from "./use-draft-detection";
export {
  useDraftDetection,
  buildSeedFromEvents,
  buildSeedFromInvestigation,
  buildSeedFromPattern,
  buildDraftFromSeed,
} from "./use-draft-detection";

export type { ImportFailure, ImportResult } from "./use-evidence-packs";
export { useEvidencePacks } from "./use-evidence-packs";

export type { UseLabExecutionReturn } from "./use-lab-execution";
export { useLabExecution } from "./use-lab-execution";

export type {
  PublishRequest,
  PublishResult,
  PublishGateStatus,
  UsePublicationReturn,
} from "./use-publication";
export { usePublication, getAvailableTargets } from "./use-publication";

export type {
  UseCoverageGapsResult,
  UseCoverageGapsOptions,
} from "./use-coverage-gaps";
export { useCoverageGaps } from "./use-coverage-gaps";

export type {
  SwarmLaunchActions,
  SwarmLaunchOptions,
  SwarmLaunchPayload,
} from "./use-swarm-launch";
export { useSwarmLaunch } from "./use-swarm-launch";

// ---- Swarm ----

export type {
  SwarmBoardNode,
  PublishStateVerification,
} from "./swarm-detection-nodes";
export {
  createDetectionRuleNode,
  createEvidencePackNode,
  createLabRunNode,
  createPublicationNode,
  verifyPublishState,
  countDatasetItems,
} from "./swarm-detection-nodes";

export type { SwarmSessionTemplate } from "./swarm-session-templates";
export {
  getSessionTemplates,
  getReviewTemplate,
  getPublishTemplate,
  getHardenTemplate,
  getConvertTemplate,
} from "./swarm-session-templates";

export { linkReceiptToPublication } from "./swarm-receipt-linking";

// ---- Side-effect imports ----
// These adapter modules call registerAdapter() on module load.
// Importing them above (via named exports) already triggers registration,
// but we list them explicitly here for clarity and to guarantee
// registration even if tree-shaking removes unused named exports.
import "./policy-adapter";
import "./sigma-adapter";
import "./yara-adapter";
import "./ocsf-adapter";
