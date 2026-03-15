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

export type DraftSeedKind = "hunt_event" | "investigation" | "hunt_pattern" | "manual";

export interface DraftSeed {
  id: string;
  kind: DraftSeedKind;
  sourceEventIds: string[];
  investigationId?: string;
  patternId?: string;
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

export type PublishTarget =
  | "native_policy"
  | "spl"
  | "kql"
  | "esql"
  | "json_export"
  | "fleet_deploy";

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
    };

export interface EvaluationPathStep {
  guardId: string;
  verdict: Verdict;
  durationMs: number;
  evidence?: Record<string, unknown>;
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
