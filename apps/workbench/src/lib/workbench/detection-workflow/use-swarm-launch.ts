/**
 * Hook for launching review swarm sessions from the editor and Lab.
 *
 * Creates artifact nodes on the SwarmBoard for detection documents,
 * evidence packs, and lab runs, then navigates the user to the board.
 */

import { useCallback, useMemo } from "react";
import type { FileType } from "../file-type-registry";
import {
  createBoardNode,
} from "../swarm-board-store";
import type { EvidencePack, LabRun, PublicationManifest } from "./shared-types";
import {
  createConversionOutputNode,
  createDetectionRuleNode,
  createEvidencePackNode,
  createLabRunNode,
  createPublicationNode,
} from "./swarm-detection-nodes";

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface SwarmLaunchActions {
  /** Open a review swarm with the current detection document */
  openReviewSwarm(): void;
  /** Open a swarm with the document + evidence pack */
  openReviewSwarmWithEvidence(evidencePackId: string): void;
  /** Open a swarm with the document + lab run results */
  openReviewSwarmWithRun(labRunId: string): void;
  /** Open a swarm with the document + publication chain. */
  openReviewSwarmWithPublication(publicationId: string): void;
  /** Whether swarm launch is available */
  canLaunch: boolean;
}

export interface SwarmLaunchOptions {
  documentId?: string;
  fileType?: FileType;
  tabId?: string;
  name?: string;
  filePath?: string | null;
  sourceHash?: string;
  evidencePack?: EvidencePack | null;
  labRun?: LabRun | null;
  publicationManifest?: PublicationManifest | null;
  onNavigate?: (path: string) => void;
}

// ---------------------------------------------------------------------------
// Node creation helpers
// ---------------------------------------------------------------------------

/** Position constants for a left-to-right layout on the board. */
const LAYOUT = {
  ruleX: 200,
  evidenceX: 520,
  runX: 840,
  publicationX: 1160,
  outputX: 1480,
  receiptX: 1800,
  baseY: 200,
} as const;

// ---------------------------------------------------------------------------
// Dispatch helper — pushes nodes into the store without requiring the
// React context (we import the factory only; the store context dispatch
// is called externally via a lightweight custom event).
//
// Because the SwarmBoardProvider may not be mounted in the editor/lab
// tree (it lives under LabLayout), we use a custom DOM event that the
// SwarmBoardProvider can listen for. If the provider is not mounted,
// we fall back to persisting directly into localStorage so the nodes
// appear when the user navigates to the board.
// ---------------------------------------------------------------------------

const SWARM_LAUNCH_EVENT = "workbench:swarm-launch-nodes";

export interface SwarmLaunchPayload {
  nodes: ReturnType<typeof createBoardNode>[];
  edges: Array<{
    id: string;
    source: string;
    target: string;
    type: "artifact" | "receipt";
    label?: string;
  }>;
}

function buildPayload(options: SwarmLaunchOptions): SwarmLaunchPayload {
  const {
    documentId,
    fileType,
    filePath,
    name,
    sourceHash,
    evidencePack,
    labRun,
    publicationManifest,
  } = options;

  if (!documentId || !fileType) {
    return { nodes: [], edges: [] };
  }

  const ruleNode = createDetectionRuleNode(
    {
      documentId,
      fileType,
      filePath: filePath ?? null,
      name: name ?? "Detection Rule",
      sourceHash: sourceHash ?? "",
    },
    { x: LAYOUT.ruleX, y: LAYOUT.baseY },
  );

  const nodes: SwarmLaunchPayload["nodes"] = [ruleNode];
  const edges: SwarmLaunchPayload["edges"] = [];

  if (evidencePack) {
    const evidenceNode = createEvidencePackNode(evidencePack, {
      x: LAYOUT.evidenceX,
      y: LAYOUT.baseY,
    });
    nodes.push(evidenceNode);
    edges.push({
      id: `edge-${ruleNode.id}-${evidenceNode.id}`,
      source: ruleNode.id,
      target: evidenceNode.id,
      type: "artifact",
      label: "evidence",
    });
  }

  if (labRun) {
    const runNode = createLabRunNode(labRun, { x: LAYOUT.runX, y: LAYOUT.baseY });
    nodes.push(runNode);
    edges.push({
      id: `edge-${ruleNode.id}-${runNode.id}`,
      source: ruleNode.id,
      target: runNode.id,
      type: "artifact",
      label: "run",
    });
  }

  if (publicationManifest) {
    const publicationNode = createPublicationNode(publicationManifest, {
      x: LAYOUT.publicationX,
      y: LAYOUT.baseY,
    });
    const outputNode = createConversionOutputNode(publicationManifest, {
      x: LAYOUT.outputX,
      y: LAYOUT.baseY,
    });
    nodes.push(publicationNode, outputNode);
    edges.push({
      id: `edge-${ruleNode.id}-${publicationNode.id}`,
      source: ruleNode.id,
      target: publicationNode.id,
      type: "artifact",
      label: "publication",
    });
    edges.push({
      id: `edge-${publicationNode.id}-${outputNode.id}`,
      source: publicationNode.id,
      target: outputNode.id,
      type: "artifact",
      label: "output",
    });

    if (publicationManifest.receiptId) {
      const receiptNode = createBoardNode({
        nodeType: "receipt",
        title: `Receipt: ${publicationManifest.target}`,
        position: { x: LAYOUT.receiptX, y: LAYOUT.baseY },
        data: {
          status: "completed",
          nodeType: "receipt",
          verdict: "allow",
          content: publicationManifest.receiptId,
        },
      });
      nodes.push(receiptNode);
      edges.push({
        id: `edge-${receiptNode.id}-${publicationNode.id}`,
        source: receiptNode.id,
        target: publicationNode.id,
        type: "receipt",
        label: "receipt",
      });
    }
  }

  return { nodes, edges };
}

function dispatchSwarmNodes(payload: SwarmLaunchPayload): void {
  // Fire custom event for any mounted SwarmBoardProvider
  window.dispatchEvent(
    new CustomEvent(SWARM_LAUNCH_EVENT, { detail: payload }),
  );

  // Also persist into localStorage so nodes are available even if
  // the board hasn't mounted yet. We merge into the existing persisted
  // state rather than overwriting.
  try {
    const STORAGE_KEY = "clawdstrike_workbench_swarm_board";
    const raw = localStorage.getItem(STORAGE_KEY);
    const existing = raw ? JSON.parse(raw) : null;

    const nodes = [
      ...(existing?.nodes ?? []),
      ...payload.nodes,
    ];
    const edges = [
      ...(existing?.edges ?? []),
      ...payload.edges,
    ];

    const state = {
      boardId: existing?.boardId ?? `board-${Date.now().toString(36)}`,
      repoRoot: existing?.repoRoot ?? "",
      nodes,
      edges,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (e) {
    console.warn("[use-swarm-launch] Failed to persist swarm nodes:", e);
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useSwarmLaunch(options: SwarmLaunchOptions): SwarmLaunchActions {
  const {
    documentId,
    fileType,
    tabId,
    name,
    filePath,
    sourceHash,
    evidencePack,
    labRun,
    publicationManifest,
    onNavigate,
  } = options;
  const canLaunch = Boolean(documentId);

  const openReviewSwarm = useCallback(() => {
    if (!documentId || !fileType) return;
    dispatchSwarmNodes(
      buildPayload({
        documentId,
        fileType,
        tabId,
        name,
        filePath,
        sourceHash,
        evidencePack,
        labRun,
        publicationManifest,
      }),
    );

    onNavigate?.("/lab");
  }, [
    documentId,
    evidencePack,
    filePath,
    fileType,
    labRun,
    name,
    onNavigate,
    publicationManifest,
    sourceHash,
    tabId,
  ]);

  const openReviewSwarmWithEvidence = useCallback(
    (evidencePackId: string) => {
      if (!documentId || !fileType) return;
      const nextEvidence =
        evidencePack && evidencePack.id === evidencePackId
          ? evidencePack
          : null;
      dispatchSwarmNodes(
        buildPayload({
          documentId,
          fileType,
          tabId,
          name,
          filePath,
          sourceHash,
          evidencePack: nextEvidence,
        }),
      );

      onNavigate?.("/lab");
    },
    [documentId, evidencePack, filePath, fileType, name, onNavigate, sourceHash, tabId],
  );

  const openReviewSwarmWithRun = useCallback(
    (labRunId: string) => {
      if (!documentId || !fileType) return;
      const nextRun = labRun && labRun.id === labRunId ? labRun : null;
      dispatchSwarmNodes(
        buildPayload({
          documentId,
          fileType,
          tabId,
          name,
          filePath,
          sourceHash,
          labRun: nextRun,
          evidencePack,
        }),
      );

      onNavigate?.("/lab");
    },
    [documentId, evidencePack, filePath, fileType, labRun, name, onNavigate, sourceHash, tabId],
  );

  const openReviewSwarmWithPublication = useCallback(
    (publicationId: string) => {
      if (!documentId || !fileType) return;
      const nextPublication =
        publicationManifest && publicationManifest.id === publicationId
          ? publicationManifest
          : null;
      dispatchSwarmNodes(
        buildPayload({
          documentId,
          fileType,
          tabId,
          name,
          filePath,
          sourceHash,
          evidencePack,
          labRun,
          publicationManifest: nextPublication,
        }),
      );

      onNavigate?.("/lab");
    },
    [
      documentId,
      evidencePack,
      filePath,
      fileType,
      labRun,
      name,
      onNavigate,
      publicationManifest,
      sourceHash,
      tabId,
    ],
  );

  return useMemo(
    () => ({
      openReviewSwarm,
      openReviewSwarmWithEvidence,
      openReviewSwarmWithRun,
      openReviewSwarmWithPublication,
      canLaunch,
    }),
    [
      canLaunch,
      openReviewSwarm,
      openReviewSwarmWithEvidence,
      openReviewSwarmWithPublication,
      openReviewSwarmWithRun,
    ],
  );
}
