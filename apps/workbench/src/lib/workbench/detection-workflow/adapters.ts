/**
 * Detection workflow adapter registry.
 *
 * Each supported file type implements DetectionWorkflowAdapter to provide
 * format-specific behavior for drafting, lab execution, explainability,
 * and publication.
 *
 * The policy adapter is the reference implementation. Non-policy adapters
 * should not be registered until the policy adapter has parity tests
 * covering existing simulation behavior.
 */

import type { FileType } from "../file-type-registry";
import type {
  DraftSeed,
  DetectionDocumentRef,
  EvidencePack,
  LabRun,
  ExplainabilityTrace,
} from "./shared-types";
import type {
  DetectionExecutionRequest,
  DetectionExecutionResult,
  DraftBuildResult,
  PublicationRequest,
  PublicationBuildResult,
} from "./execution-types";

// ---- Adapter Interface ----

export interface DetectionWorkflowAdapter {
  /** The file type this adapter handles. */
  fileType: FileType;

  /** Whether this adapter can generate a draft from the given seed. */
  canDraftFrom(seed: DraftSeed): boolean;

  /** Build a draft detection document from a seed. */
  buildDraft(seed: DraftSeed): DraftBuildResult;

  /** Build a starter evidence pack from a seed and document reference. */
  buildStarterEvidence(seed: DraftSeed, document: DetectionDocumentRef): EvidencePack;

  /** Execute a lab run — run the document against an evidence pack. */
  runLab(request: DetectionExecutionRequest): Promise<DetectionExecutionResult>;

  /** Extract explainability traces from a completed lab run. */
  buildExplainability(run: LabRun): ExplainabilityTrace[];

  /** Build a publication artifact (manifest + output). */
  buildPublication(request: PublicationRequest): Promise<PublicationBuildResult>;
}

// ---- Registry ----

const adapters = new Map<FileType, DetectionWorkflowAdapter>();

export function registerAdapter(adapter: DetectionWorkflowAdapter): void {
  adapters.set(adapter.fileType, adapter);
}

export function getAdapter(fileType: FileType): DetectionWorkflowAdapter | null {
  return adapters.get(fileType) ?? null;
}

export function hasAdapter(fileType: FileType): boolean {
  return adapters.has(fileType);
}

export function getRegisteredFileTypes(): FileType[] {
  return [...adapters.keys()];
}
