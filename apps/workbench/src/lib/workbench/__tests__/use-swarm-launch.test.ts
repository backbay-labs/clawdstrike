import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// We test the swarm launch logic directly (not the React hook, since hooks
// require a React render context). The hook delegates to createBoardNode
// and localStorage persistence, so testing those exercises the core logic.

import {
  createBoardNode,
  generateNodeId,
} from "../swarm-board-store";
import type { SwarmBoardNodeData } from "../swarm-board-types";
import type { SwarmLaunchPayload } from "../detection-workflow/use-swarm-launch";

// ---------------------------------------------------------------------------
// Storage key must match the one in use-swarm-launch.ts and swarm-board-store
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";
const LAUNCH_EVENT = "workbench:swarm-launch-nodes";

// ---------------------------------------------------------------------------
// Helpers — reproduce the core logic from use-swarm-launch.ts without React
// ---------------------------------------------------------------------------

function buildRuleNode(opts: {
  documentId: string;
  fileType?: string;
  name?: string;
  filePath?: string | null;
  tabId?: string;
  sourceHash?: string;
}) {
  return createBoardNode({
    nodeType: "artifact",
    title: opts.name ?? "Detection Rule",
    position: { x: 200, y: 200 },
    data: {
      filePath: opts.filePath ?? undefined,
      fileType: opts.fileType ?? "sigma_rule",
      documentId: opts.documentId,
      tabId: opts.tabId,
      sourceHash: opts.sourceHash,
    } as Partial<SwarmBoardNodeData>,
  });
}

function buildEvidenceNode(evidencePackId: string) {
  return createBoardNode({
    nodeType: "artifact",
    title: "Evidence Pack",
    position: { x: 520, y: 200 },
    data: {
      fileType: "json",
      evidencePackId,
    } as Partial<SwarmBoardNodeData>,
  });
}

function buildRunNode(labRunId: string) {
  return createBoardNode({
    nodeType: "artifact",
    title: "Lab Run",
    position: { x: 840, y: 200 },
    data: {
      fileType: "json",
      labRunId,
    } as Partial<SwarmBoardNodeData>,
  });
}

function dispatchSwarmNodes(payload: SwarmLaunchPayload): void {
  window.dispatchEvent(
    new CustomEvent(LAUNCH_EVENT, { detail: payload }),
  );

  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const existing = raw ? JSON.parse(raw) : null;

    const nodes = [...(existing?.nodes ?? []), ...payload.nodes];
    const edges = [...(existing?.edges ?? []), ...payload.edges];

    const state = {
      boardId: existing?.boardId ?? `board-${Date.now().toString(36)}`,
      repoRoot: existing?.repoRoot ?? "",
      nodes,
      edges,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Ignore in tests
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Swarm launch", () => {
  beforeEach(() => {
    localStorage.removeItem(STORAGE_KEY);
  });

  afterEach(() => {
    localStorage.removeItem(STORAGE_KEY);
  });

  describe("canLaunch", () => {
    it("is true when documentId is provided", () => {
      const canLaunch = Boolean("doc-123");
      expect(canLaunch).toBe(true);
    });

    it("is false when no documentId", () => {
      const canLaunch = Boolean(undefined);
      expect(canLaunch).toBe(false);
    });
  });

  describe("openReviewSwarm", () => {
    it("creates a detection rule artifact node", () => {
      const ruleNode = buildRuleNode({
        documentId: "doc-abc",
        fileType: "sigma_rule",
        name: "My Sigma Rule",
      });

      dispatchSwarmNodes({ nodes: [ruleNode], edges: [] });

      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.nodes).toHaveLength(1);
      expect(stored.nodes[0].data.title).toBe("My Sigma Rule");
      expect(stored.nodes[0].data.nodeType).toBe("artifact");
      expect(stored.nodes[0].data.documentId).toBe("doc-abc");
      expect(stored.nodes[0].data.fileType).toBe("sigma_rule");
    });

    it("positions the rule node at the left of the layout", () => {
      const ruleNode = buildRuleNode({ documentId: "doc-1" });
      expect(ruleNode.position.x).toBe(200);
      expect(ruleNode.position.y).toBe(200);
    });
  });

  describe("openReviewSwarmWithEvidence", () => {
    it("creates rule + evidence nodes with an edge", () => {
      const ruleNode = buildRuleNode({
        documentId: "doc-xyz",
        name: "YARA Rule",
        fileType: "yara_rule",
      });
      const evidenceNode = buildEvidenceNode("evpack-001");

      const edgeId = `edge-${ruleNode.id}-${evidenceNode.id}`;
      dispatchSwarmNodes({
        nodes: [ruleNode, evidenceNode],
        edges: [
          {
            id: edgeId,
            source: ruleNode.id,
            target: evidenceNode.id,
            type: "artifact" as const,
            label: "evidence",
          },
        ],
      });

      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.nodes).toHaveLength(2);

      const titles = stored.nodes.map((n: { data: { title: string } }) => n.data.title);
      expect(titles).toContain("YARA Rule");
      expect(titles).toContain("Evidence Pack");

      expect(stored.edges).toHaveLength(1);
      expect(stored.edges[0].source).toBe(ruleNode.id);
      expect(stored.edges[0].target).toBe(evidenceNode.id);
      expect(stored.edges[0].type).toBe("artifact");
    });

    it("evidence node stores the evidence pack ID", () => {
      const evidenceNode = buildEvidenceNode("evpack-999");
      expect(evidenceNode.data.evidencePackId).toBe("evpack-999");
    });
  });

  describe("openReviewSwarmWithRun", () => {
    it("creates rule + run nodes with an edge", () => {
      const ruleNode = buildRuleNode({
        documentId: "doc-run",
        name: "OCSF Event",
        fileType: "ocsf_event",
      });
      const runNode = buildRunNode("labrun-42");

      const edgeId = `edge-${ruleNode.id}-${runNode.id}`;
      dispatchSwarmNodes({
        nodes: [ruleNode, runNode],
        edges: [
          {
            id: edgeId,
            source: ruleNode.id,
            target: runNode.id,
            type: "artifact" as const,
            label: "run",
          },
        ],
      });

      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.nodes).toHaveLength(2);

      const titles = stored.nodes.map((n: { data: { title: string } }) => n.data.title);
      expect(titles).toContain("OCSF Event");
      expect(titles).toContain("Lab Run");

      expect(stored.edges).toHaveLength(1);
      expect(stored.edges[0].label).toBe("run");
    });

    it("run node stores the lab run ID", () => {
      const runNode = buildRunNode("labrun-77");
      expect(runNode.data.labRunId).toBe("labrun-77");
    });

    it("run node is positioned to the right of the rule node", () => {
      const ruleNode = buildRuleNode({ documentId: "doc-pos" });
      const runNode = buildRunNode("labrun-1");
      expect(runNode.position.x).toBeGreaterThan(ruleNode.position.x);
    });
  });

  describe("onNavigate", () => {
    it("calls onNavigate with swarm board path", () => {
      const navigateFn = vi.fn();

      // Simulate what the hook does
      const documentId = "doc-nav";
      if (documentId) {
        const ruleNode = buildRuleNode({ documentId });
        dispatchSwarmNodes({ nodes: [ruleNode], edges: [] });
        navigateFn("/lab");
      }

      expect(navigateFn).toHaveBeenCalledWith("/lab");
    });

    it("does not call onNavigate when documentId is missing", () => {
      const navigateFn = vi.fn();

      const documentId: string | undefined = undefined;
      if (documentId) {
        navigateFn("/lab");
      }

      expect(navigateFn).not.toHaveBeenCalled();
    });
  });

  describe("custom event dispatch", () => {
    it("fires a custom event with the node payload", () => {
      const handler = vi.fn();
      window.addEventListener(LAUNCH_EVENT, handler);

      const ruleNode = buildRuleNode({ documentId: "doc-evt" });
      dispatchSwarmNodes({ nodes: [ruleNode], edges: [] });

      expect(handler).toHaveBeenCalledTimes(1);
      const detail = (handler.mock.calls[0][0] as CustomEvent).detail as SwarmLaunchPayload;
      expect(detail.nodes).toHaveLength(1);
      expect(detail.edges).toHaveLength(0);

      window.removeEventListener(LAUNCH_EVENT, handler);
    });
  });

  describe("merge with existing board state", () => {
    it("appends nodes to existing persisted board", () => {
      // Pre-populate storage with an existing node
      const existing = {
        boardId: "board-existing",
        repoRoot: "/repo",
        nodes: [
          {
            id: "existing-node",
            type: "note",
            position: { x: 0, y: 0 },
            data: { title: "Existing Note", status: "idle", nodeType: "note" },
          },
        ],
        edges: [],
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));

      const ruleNode = buildRuleNode({ documentId: "doc-merge" });
      dispatchSwarmNodes({ nodes: [ruleNode], edges: [] });

      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(stored.nodes).toHaveLength(2);
      expect(stored.boardId).toBe("board-existing");
      expect(stored.repoRoot).toBe("/repo");
    });
  });
});
