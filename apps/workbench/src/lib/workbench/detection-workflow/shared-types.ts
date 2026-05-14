import type { FileType } from "../file-type-registry";
import type { Verdict, GuardSimResult, TestScenario } from "../types";

// ---- Document Reference ----

export interface DetectionDocumentRef {
  documentId: string;
  fileType: FileType;
  tabId?: string;
  filePath: string | null;
  name: string;
  sourceHash: string;
  versionId?: string | null;
}

// ---- Draft Seed ----

export type DraftSeedKind = "hunt_event" | "investigation" | "hunt_pattern" | "finding" | "manual";

export interface DraftSeed {
  id: string;
  kind: DraftSeedKind;
  sourceEventIds: string[];
  investigationId?: string;
  patternId?: string;
  findingId?: string;
  preferredFormats: FileType[];
  techniqueHints: string[];
  dataSourceHints: string[];
  extractedFields: Record<string, unknown>;
  createdAt: string;
  confidence: number;
}

// ---- Evidence Pack ----

export type EvidenceDatasetKind = "positive" | "negative" | "regression" | "false_positive";

export type EvidenceItem =
  | {
      id: string;
      kind: "structured_event";
      format: "json";
      payload: Record<string, unknown>;
      expected: "match" | "no_match";
      sourceEventId?: string;
    }
  | {
      id: string;
      kind: "bytes";
      encoding: "base64" | "hex" | "utf8";
      payload: string;
      expected: "match" | "no_match";
      sourceArtifactPath?: string;
    }
  | {
      id: string;
      kind: "ocsf_event";
      payload: Record<string, unknown>;
      expected: "valid" | "invalid";
      sourceEventId?: string;
    }
  | {
      id: string;
      kind: "policy_scenario";
      scenario: TestScenario;
      expected: Verdict;
    };

export type RedactionState = "clean" | "redacted" | "contains_sensitive_fields";

export interface EvidencePack {
  id: string;
  documentId: string;
  fileType: FileType;
  title: string;
  createdAt: string;
  derivedFromSeedId?: string;
  datasets: Record<EvidenceDatasetKind, EvidenceItem[]>;
  notes?: string;
  redactionState: RedactionState;
}

// ---- Lab Run ----

export interface LabRunSummary {
  totalCases: number;
  passed: number;
  failed: number;
  matched: number;
  missed: number;
  falsePositives: number;
  engine: "native" | "client" | "mixed";
}

export interface LabCaseResult {
  caseId: string;
  dataset: EvidenceDatasetKind;
  status: "pass" | "fail";
  expected: string;
  actual: string;
  explanationRefIds: string[];
}

export interface LabRun {
  id: string;
  documentId: string;
  evidencePackId: string;
  fileType: FileType;
  startedAt: string;
  completedAt: string;
  summary: LabRunSummary;
  results: LabCaseResult[];
  explainability: ExplainabilityTrace[];
  coverageDelta?: {
    techniquesAdded: string[];
    techniquesLost: string[];
  };
}

// ---- Publication Provenance ----

export interface PublicationCoverageSnapshot {
  techniques: string[];
  dataSources: string[];
}

export interface PublicationProvenance {
  algorithm: "tauri_signed_receipt" | "browser_ecdsa_p256";
  signature: string;
  signedAt: string;
  receiptHash: string;
  signedReceipt: Record<string, unknown> | null;
}

// ---- Publication Manifest ----

/**
 * Publish target identifier. Any string is accepted for plugin extensibility.
 * Built-in targets: "native_policy", "spl", "kql", "esql", "json_export", "fleet_deploy".
 */
export type PublishTarget = string;

/** The six built-in publish targets. */
export const BUILTIN_PUBLISH_TARGETS = [
  "native_policy",
  "spl",
  "kql",
  "esql",
  "json_export",
  "fleet_deploy",
] as const;

export type BuiltinPublishTarget = (typeof BUILTIN_PUBLISH_TARGETS)[number];

// ---- Publish Target Registry ----

/** Describes a publish target with display metadata. */
export interface PublishTargetDescriptor {
  /** Unique publish target identifier. */
  id: string;
  /** Human-readable label (e.g. "Splunk SPL"). */
  label: string;
  /** Optional format group for grouping in UI (e.g. "siem", "export"). */
  formatGroup?: string;
}

const publishTargetRegistry = new Map<string, PublishTargetDescriptor>();

/** Register a publish target descriptor. Returns a dispose function. */
export function registerPublishTarget(descriptor: PublishTargetDescriptor): () => void {
  publishTargetRegistry.set(descriptor.id, descriptor);
  return () => {
    publishTargetRegistry.delete(descriptor.id);
  };
}

/** Get a publish target descriptor by ID, or null if not registered. */
export function getPublishTarget(id: string): PublishTargetDescriptor | null {
  return publishTargetRegistry.get(id) ?? null;
}

/** Get all registered publish target descriptors. */
export function getAllPublishTargets(): PublishTargetDescriptor[] {
  return [...publishTargetRegistry.values()];
}

// Auto-register built-in publish targets at module load.
registerPublishTarget({ id: "native_policy", label: "Native Policy" });
registerPublishTarget({ id: "spl", label: "Splunk SPL", formatGroup: "siem" });
registerPublishTarget({ id: "kql", label: "Microsoft KQL", formatGroup: "siem" });
registerPublishTarget({ id: "esql", label: "Elastic ES|QL", formatGroup: "siem" });
registerPublishTarget({ id: "json_export", label: "JSON Export", formatGroup: "export" });
registerPublishTarget({ id: "fleet_deploy", label: "Fleet Deploy", formatGroup: "deploy" });

export interface PublicationManifest {
  id: string;
  documentId: string;
  sourceFileType: FileType;
  target: PublishTarget;
  createdAt: string;
  sourceHash: string;
  outputHash: string;
  validationSnapshot: {
    valid: boolean;
    diagnosticCount: number;
  };
  runSnapshot: {
    evidencePackId: string;
    labRunId: string;
    passed: boolean;
  } | null;
  coverageSnapshot: PublicationCoverageSnapshot | null;
  converter: {
    id: string;
    version: string;
  };
  signer: {
    publicKey: string;
    keyType: "persistent" | "ephemeral";
  } | null;
  provenance: PublicationProvenance | null;
  receiptId?: string;
  exportPath?: string;
  deployResponse?: {
    success: boolean;
    hash?: string;
    destination?: string;
  };
}

// ---- Coverage Gap ----

export interface CoverageGapCandidate {
  id: string;
  sourceKind: "event" | "investigation" | "pattern";
  sourceIds: string[];
  severity: "high" | "medium" | "low";
  confidence: number;
  suggestedFormats: FileType[];
  techniqueHints: string[];
  dataSourceHints: string[];
  rationale: string;
}

// ---- Explainability Trace ----

export type ExplainabilityTrace =
  | {
      id: string;
      kind: "sigma_match";
      caseId: string;
      matchedSelectors: Array<{ name: string; fields: string[] }>;
      matchedFields: Array<{ path: string; value: string }>;
      techniqueHints: string[];
      sourceLineHints: number[];
    }
  | {
      id: string;
      kind: "yara_match";
      caseId: string;
      matchedStrings: Array<{ name: string; offset: number; length: number }>;
      conditionSummary: string;
      sourceLineHints: number[];
    }
  | {
      id: string;
      kind: "ocsf_validation";
      caseId: string;
      classUid: number | null;
      missingFields: string[];
      invalidFields: string[];
      sourceLineHints: number[];
    }
  | {
      id: string;
      kind: "policy_evaluation";
      caseId: string;
      guardResults: GuardSimResult[];
      evaluationPath?: EvaluationPathStep[];
    }
  | {
      id: string;
      kind: "plugin_trace";
      caseId: string;
      /** The plugin-specific trace type, e.g. "snort_match" or "kql_result". */
      traceType: string;
      /** Arbitrary plugin-specific trace data. */
      data: Record<string, unknown>;
      /** Optional source line hints for editor highlighting. */
      sourceLineHints?: number[];
    };

export interface EvaluationPathStep {
  guardId: string;
  verdict: Verdict;
  durationMs: number;
  evidence?: Record<string, unknown>;
}

// ---- Visual Panel Props ----

/**
 * Props interface for detection visual panel components.
 * All visual panels (Sigma, YARA, OCSF, plugin-contributed) must accept
 * this contract so the editor can render them uniformly.
 */
export interface DetectionVisualPanelProps {
  /** The source text of the detection document. */
  source: string;
  /** Callback when the visual panel edits the source. */
  onSourceChange: (source: string) => void;
  /** Whether the panel is in read-only mode. */
  readOnly?: boolean;
  /** Accent color hex (e.g. "#ff5722") for theming the panel chrome. */
  accentColor: string;
}

// ---- Translation Types ----

/**
 * A translation provider can convert detection documents between file types.
 * Providers are registered into a global array; the first provider whose
 * canTranslate() returns true for a given (from, to) pair is used.
 */
export interface TranslationProvider {
  /** Check whether this provider can translate from one file type to another. */
  canTranslate(from: FileType, to: FileType): boolean;
  /** Perform translation. */
  translate(request: TranslationRequest): Promise<TranslationResult>;
}

/** Input to a translation operation. */
export interface TranslationRequest {
  /** Source text to translate. */
  source: string;
  /** File type of the source text. */
  sourceFileType: FileType;
  /** Target file type to translate into. */
  targetFileType: FileType;
}

/** Result of a translation operation. */
export interface TranslationResult {
  /** Whether the translation was successful. */
  success: boolean;
  /** The translated output text, or null on failure. */
  output: string | null;
  /** Diagnostics emitted during translation. */
  diagnostics: TranslationDiagnostic[];
  /** Field mappings used during translation. */
  fieldMappings: FieldMapping[];
  /** Features from the source that could not be translated. */
  untranslatableFeatures: string[];
}

/** A diagnostic message emitted during translation. */
export interface TranslationDiagnostic {
  /** Severity level. */
  severity: "error" | "warning" | "info";
  /** Human-readable diagnostic message. */
  message: string;
  /** Optional line number in the source text. */
  sourceLine?: number;
}

/** A field mapping used during translation. */
export interface FieldMapping {
  /** Source field name (Sigma field by convention). */
  sigmaField: string;
  /** Target field name in the output format. */
  targetField: string;
  /** Mapping confidence. */
  confidence: "exact" | "approximate" | "unmapped";
}

// ---- Helpers ----

export function createEmptyDatasets(): Record<EvidenceDatasetKind, EvidenceItem[]> {
  return {
    positive: [],
    negative: [],
    regression: [],
    false_positive: [],
  };
}
