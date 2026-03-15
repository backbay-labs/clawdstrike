/**
 * Hook for launching review swarm sessions from the editor and Lab.
 *
 * Creates artifact nodes on the SwarmBoard for detection documents,
 * evidence packs, and lab runs, then navigates the user to the board.
 */

import { useCallback, useMemo } from "react";
import type { FileType } from "../file-type-registry";
import type { SwarmBoardNodeData } from "../swarm-board-types";
import {
  createBoardNode,
  generateNodeId,
  type CreateNodeConfig,
} from "../swarm-board-store";

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
  onNavigate?: (path: string) => void;
}

// ---------------------------------------------------------------------------
// Node creation helpers (self-contained; does not modify swarm-board-types)
// ---------------------------------------------------------------------------

/** Position constants for a left-to-right layout on the board. */
const LAYOUT = {
  ruleX: 200,
  evidenceX: 520,
  runX: 840,
  baseY: 200,
} as const;

function buildRuleNode(opts: SwarmLaunchOptions): CreateNodeConfig {
  return {
    nodeType: "artifact",
    title: opts.name ?? "Detection Rule",
    position: { x: LAYOUT.ruleX, y: LAYOUT.baseY },
    data: {
      filePath: opts.filePath ?? undefined,
      fileType: opts.fileType ?? "sigma_rule",
      // Store document identity in the index-signature bucket so the
      // other agent's detection metadata extension can pick it up later
      // without requiring changes to the SwarmBoardNodeData interface.
      documentId: opts.documentId,
      tabId: opts.tabId,
      sourceHash: opts.sourceHash,
    } as Partial<SwarmBoardNodeData>,
  };
}

function buildEvidenceNode(evidencePackId: string): CreateNodeConfig {
  return {
    nodeType: "artifact",
    title: "Evidence Pack",
    position: { x: LAYOUT.evidenceX, y: LAYOUT.baseY },
    data: {
      fileType: "json",
      evidencePackId,
    } as Partial<SwarmBoardNodeData>,
  };
}

function buildRunNode(labRunId: string): CreateNodeConfig {
  return {
    nodeType: "artifact",
    title: "Lab Run",
    position: { x: LAYOUT.runX, y: LAYOUT.baseY },
    data: {
      fileType: "json",
      labRunId,
    } as Partial<SwarmBoardNodeData>,
  };
}

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
    type: "artifact";
    label?: string;
  }>;
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
  const { documentId, fileType, tabId, name, filePath, sourceHash, onNavigate } = options;
  const canLaunch = Boolean(documentId);

  const openReviewSwarm = useCallback(() => {
    if (!documentId) return;

    const ruleNode = createBoardNode(buildRuleNode({ documentId, fileType, tabId, name, filePath, sourceHash }));
    dispatchSwarmNodes({ nodes: [ruleNode], edges: [] });

    onNavigate?.("/lab");
  }, [documentId, fileType, tabId, name, filePath, sourceHash, onNavigate]);

  const openReviewSwarmWithEvidence = useCallback(
    (evidencePackId: string) => {
      if (!documentId) return;

      const ruleNode = createBoardNode(buildRuleNode({ documentId, fileType, tabId, name, filePath, sourceHash }));
      const evidenceNode = createBoardNode(buildEvidenceNode(evidencePackId));

      const edgeId = `edge-${ruleNode.id}-${evidenceNode.id}`;
      dispatchSwarmNodes({
        nodes: [ruleNode, evidenceNode],
        edges: [
          {
            id: edgeId,
            source: ruleNode.id,
            target: evidenceNode.id,
            type: "artifact",
            label: "evidence",
          },
        ],
      });

      onNavigate?.("/lab");
    },
    [documentId, fileType, tabId, name, filePath, sourceHash, onNavigate],
  );

  const openReviewSwarmWithRun = useCallback(
    (labRunId: string) => {
      if (!documentId) return;

      const ruleNode = createBoardNode(buildRuleNode({ documentId, fileType, tabId, name, filePath, sourceHash }));
      const runNode = createBoardNode(buildRunNode(labRunId));

      const edgeId = `edge-${ruleNode.id}-${runNode.id}`;
      dispatchSwarmNodes({
        nodes: [ruleNode, runNode],
        edges: [
          {
            id: edgeId,
            source: ruleNode.id,
            target: runNode.id,
            type: "artifact",
            label: "run",
          },
        ],
      });

      onNavigate?.("/lab");
    },
    [documentId, fileType, tabId, name, filePath, sourceHash, onNavigate],
  );

  return useMemo(
    () => ({
      openReviewSwarm,
      openReviewSwarmWithEvidence,
      openReviewSwarmWithRun,
      canLaunch,
    }),
    [openReviewSwarm, openReviewSwarmWithEvidence, openReviewSwarmWithRun, canLaunch],
  );
}
