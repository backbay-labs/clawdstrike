/**
 * Execution contract types for the Detection Validation Lab.
 *
 * These types define the interface between the Lab shell and per-format
 * execution adapters. The policy adapter implements this contract first;
 * Sigma, YARA, and OCSF adapters follow once policy parity is proven.
 */

import type { FileType } from "../file-type-registry";
import type {
  DetectionDocumentRef,
  EvidencePack,
  LabRun,
  ExplainabilityTrace,
  PublicationManifest,
  DraftSeed,
} from "./shared-types";

// ---- Execution Request / Result ----

export interface DetectionExecutionRequest {
  document: DetectionDocumentRef;
  evidencePack: EvidencePack;
  adapterRunConfig?: Record<string, unknown>;
}

export interface DetectionExecutionResult {
  run: LabRun;
  coverage?: CoverageReport | null;
  reportArtifacts: ReportArtifact[];
}

export interface ReportArtifact {
  id: string;
  kind: "summary" | "coverage_delta" | "guard_report" | "match_report";
  title: string;
  data?: Record<string, unknown>;
}

// ---- Coverage Report ----

export interface CoverageReport {
  techniquesCovered: string[];
  dataSourcesCovered: string[];
  delta?: {
    techniquesAdded: string[];
    techniquesLost: string[];
  };
}

// ---- Draft Build ----

export interface DraftBuildResult {
  source: string;
  fileType: FileType;
  name: string;
  techniqueHints: string[];
}

// ---- Publication Build ----

export interface PublicationRequest {
  document: DetectionDocumentRef;
  source: string;
  targetFormat: PublicationManifest["target"];
  evidencePackId?: string;
  labRunId?: string;
}

export interface PublicationBuildResult {
  manifest: Omit<PublicationManifest, "id" | "createdAt">;
  outputContent: string;
  outputHash: string;
}
