/**
 * Detection artifact node factories and publish state verification
 * for the SwarmBoard.
 *
 * Creates properly-typed SwarmBoardNode instances from detection workflow
 * domain objects (DetectionDocumentRef, EvidencePack, LabRun,
 * PublicationManifest). Also provides verification of publish state claims.
 */

import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData, DetectionArtifactKind } from "../swarm-board-types";
import { createBoardNode } from "../swarm-board-store";
import type {
  DetectionDocumentRef,
  EvidencePack,
  LabRun,
  PublicationManifest,
  EvidenceDatasetKind,
} from "./shared-types";
import { getPublicationStore } from "./publication-store";
import { verifyPublicationProvenance } from "./publication-provenance";

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

// Re-export the type for convenience
export type SwarmBoardNode = Node<SwarmBoardNodeData>;

// ---------------------------------------------------------------------------
// Node creation helpers
// ---------------------------------------------------------------------------

/**
 * Create a SwarmBoard node representing a detection rule document.
 */
export function createDetectionRuleNode(
  doc: DetectionDocumentRef,
  position: { x: number; y: number },
): SwarmBoardNode {
  return createBoardNode({
    nodeType: "artifact",
    title: doc.name,
    position,
    data: {
      artifactKind: "detection_rule",
      documentId: doc.documentId,
      format: doc.fileType,
      filePath: doc.filePath ?? undefined,
      fileType: doc.fileType,
      publishState: "draft",
    },
  });
}

/**
 * Create a SwarmBoard node representing an evidence pack.
 */
export function createEvidencePackNode(
  pack: EvidencePack,
  position: { x: number; y: number },
): SwarmBoardNode {
  return createBoardNode({
    nodeType: "artifact",
    title: pack.title,
    position,
    data: {
      artifactKind: "evidence_pack",
      documentId: pack.documentId,
      evidencePackId: pack.id,
      format: pack.fileType,
    },
  });
}

/**
 * Create a SwarmBoard node representing a completed lab run.
 */
export function createLabRunNode(
  run: LabRun,
  position: { x: number; y: number },
): SwarmBoardNode {
  const { summary } = run;
  const title = `Lab: ${summary.passed}/${summary.totalCases} passed`;

  return createBoardNode({
    nodeType: "artifact",
    title,
    position,
    data: {
      artifactKind: "lab_run",
      documentId: run.documentId,
      labRunId: run.id,
      evidencePackId: run.evidencePackId,
      format: run.fileType,
      status: summary.failed > 0 ? "failed" : "completed",
    },
  });
}

/**
 * Create a SwarmBoard node representing a publication manifest.
 */
export function createPublicationNode(
  manifest: PublicationManifest,
  position: { x: number; y: number },
): SwarmBoardNode {
  const deployed = manifest.deployResponse?.success === true;
  const publishState = deployed ? "deployed" : "published";

  return createBoardNode({
    nodeType: "artifact",
    title: `Publish: ${manifest.target}`,
    position,
    data: {
      artifactKind: "publication_manifest",
      documentId: manifest.documentId,
      publicationId: manifest.id,
      format: manifest.sourceFileType,
      publishState,
    },
  });
}

export function createConversionOutputNode(
  manifest: PublicationManifest,
  position: { x: number; y: number },
): SwarmBoardNode {
  return createBoardNode({
    nodeType: "artifact",
    title: `Output: ${manifest.target}`,
    position,
    data: {
      artifactKind: "conversion_output",
      documentId: manifest.documentId,
      publicationId: manifest.id,
      format: manifest.sourceFileType,
      publishState: manifest.deployResponse?.success ? "deployed" : "published",
    },
  });
}

// ---------------------------------------------------------------------------
// Publish state verification
// ---------------------------------------------------------------------------

export interface PublishStateVerification {
  valid: boolean;
  reason?: string;
}

/**
 * Verify whether a node's publishState is valid by checking against the
 * publication store.
 *
 * Rules:
 * - "published" requires a valid publication manifest with matching hashes
 * - "deployed" requires a publication manifest with a successful deployResponse
 * - Nodes claiming published/deployed without verification fail
 */
export async function verifyPublishState(
  node: SwarmBoardNode,
): Promise<PublishStateVerification> {
  const data = node.data as SwarmBoardNodeData;
  const { publishState, publicationId, documentId } = data;

  // Nodes without a publishState or in draft/validated are trivially valid
  if (!publishState || publishState === "draft" || publishState === "validated") {
    return { valid: true };
  }

  // published or deployed require a publication manifest
  if (!publicationId) {
    return {
      valid: false,
      reason: `Node claims "${publishState}" but has no publicationId`,
    };
  }

  const store = getPublicationStore();
  try {
    await store.init();
  } catch {
    return {
      valid: false,
      reason: "Failed to initialize publication store for verification",
    };
  }

  const manifest = await store.getManifest(publicationId);
  if (!manifest) {
    return {
      valid: false,
      reason: `Publication manifest "${publicationId}" not found in store`,
    };
  }

  // Verify documentId matches
  if (documentId && manifest.documentId !== documentId) {
    return {
      valid: false,
      reason: `Manifest documentId "${manifest.documentId}" does not match node documentId "${documentId}"`,
    };
  }

  // Verify hashes are present
  if (!manifest.sourceHash || !manifest.outputHash) {
    return {
      valid: false,
      reason: "Publication manifest is missing sourceHash or outputHash",
    };
  }

  const outputContent = await store.getOutputContent(publicationId);
  if (!outputContent) {
    return {
      valid: false,
      reason: "Publication artifact output is missing from the store",
    };
  }

  const computedOutputHash = await sha256Hex(outputContent);
  if (computedOutputHash !== manifest.outputHash) {
    return {
      valid: false,
      reason: "Stored publication output hash does not match manifest output hash",
    };
  }

  const provenanceVerification = await verifyPublicationProvenance(manifest);
  if (!provenanceVerification.valid) {
    return {
      valid: false,
      reason: provenanceVerification.reason ?? "Publication provenance verification failed",
    };
  }

  // For "published", the manifest must have passing validation
  if (publishState === "published") {
    if (!manifest.validationSnapshot?.valid) {
      return {
        valid: false,
        reason: "Publication manifest validation snapshot is not valid",
      };
    }
    return { valid: true };
  }

  // For "deployed", additionally require a successful deployResponse
  if (publishState === "deployed") {
    if (!manifest.validationSnapshot?.valid) {
      return {
        valid: false,
        reason: "Publication manifest validation snapshot is not valid",
      };
    }
    if (!manifest.deployResponse) {
      return {
        valid: false,
        reason: "Node claims deployed but manifest has no deployResponse",
      };
    }
    if (!manifest.deployResponse.success) {
      return {
        valid: false,
        reason: "Manifest deployResponse indicates failure",
      };
    }
    return { valid: true };
  }

  return {
    valid: false,
    reason: `Unknown publishState "${publishState}"`,
  };
}

// ---------------------------------------------------------------------------
// Dataset count helper (used by inspector)
// ---------------------------------------------------------------------------

/**
 * Count total items across all datasets in an evidence pack.
 */
export function countDatasetItems(
  datasets: Record<EvidenceDatasetKind, unknown[]>,
): { total: number; byKind: Record<EvidenceDatasetKind, number> } {
  const byKind: Record<EvidenceDatasetKind, number> = {
    positive: 0,
    negative: 0,
    regression: 0,
    false_positive: 0,
  };

  let total = 0;
  for (const kind of Object.keys(byKind) as EvidenceDatasetKind[]) {
    const count = datasets[kind]?.length ?? 0;
    byKind[kind] = count;
    total += count;
  }

  return { total, byKind };
}
