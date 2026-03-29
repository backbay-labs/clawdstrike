/**
 * Unit tests for swarm-board-persistence — pure helpers for normalization,
 * truncation, session recovery, and sanitization.
 */
import { describe, expect, it, vi } from "vitest";
import type { Node } from "@xyflow/react";
import type { SwarmBoardNodeData } from "@/features/swarm/swarm-board-types";

// Mock modules that swarm-board-persistence imports
vi.mock("@/lib/tauri-bridge", () => ({
  isDesktop: vi.fn(() => false),
}));

vi.mock("../swarm-file-watch", () => ({
  normalizeSwarmFileWatchPath: (p: string) => p,
}));

vi.mock("../swarm-persistence", () => ({
  SWARM_BOARD_PERSISTENCE_FILE: "swarm-board-state.v1.json",
  readSwarmPersistencePayload: vi.fn(),
  writeSwarmPersistencePayload: vi.fn(),
}));

import {
  normalizePersistedBoard,
  truncateConversationHistory,
  isRecoverableTmuxNode,
  sanitizePersistedNode,
  buildSessionMetadataPatch,
  generateBoardId,
} from "../swarm-board-persistence";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeNode(
  id: string,
  overrides: Partial<SwarmBoardNodeData> = {},
): Node<SwarmBoardNodeData> {
  return {
    id,
    type: "agentSession",
    position: { x: 0, y: 0 },
    data: {
      title: `Node ${id}`,
      status: "idle",
      nodeType: "agentSession",
      ...overrides,
    },
  };
}

// ---------------------------------------------------------------------------
// normalizePersistedBoard
// ---------------------------------------------------------------------------

describe("normalizePersistedBoard", () => {
  it("returns null for null input", () => {
    expect(normalizePersistedBoard(null)).toBeNull();
  });

  it("returns null for non-object input", () => {
    expect(normalizePersistedBoard("not-an-object")).toBeNull();
    expect(normalizePersistedBoard(42)).toBeNull();
    expect(normalizePersistedBoard(true)).toBeNull();
  });

  it("returns null for object missing nodes array", () => {
    expect(normalizePersistedBoard({ edges: [] })).toBeNull();
  });

  it("returns null for object missing edges array", () => {
    expect(normalizePersistedBoard({ nodes: [makeNode("n1")] })).toBeNull();
  });

  it("returns null when all nodes are invalid (no valid nodes)", () => {
    const parsed = {
      boardId: "b-1",
      repoRoot: "/test",
      nodes: [{ notANode: true }, null, 42],
      edges: [],
    };
    expect(normalizePersistedBoard(parsed)).toBeNull();
  });

  it("filters invalid nodes and keeps valid ones", () => {
    const validNode = makeNode("valid-1");
    const parsed = {
      boardId: "b-1",
      repoRoot: "/test",
      nodes: [validNode, { noId: true }, null],
      edges: [],
    };
    const result = normalizePersistedBoard(parsed);
    expect(result).not.toBeNull();
    expect(result!.nodes).toHaveLength(1);
    expect(result!.nodes![0].id).toBe("valid-1");
  });

  it("filters invalid edges", () => {
    const parsed = {
      boardId: "b-1",
      repoRoot: "/test",
      nodes: [makeNode("n1")],
      edges: [
        { id: "e1", source: "n1", target: "n2" },
        { noId: true },
        null,
      ],
    };
    const result = normalizePersistedBoard(parsed);
    expect(result).not.toBeNull();
    expect(result!.edges).toHaveLength(1);
  });

  it("marks tmux running sessions as recoverable", () => {
    const node = makeNode("tmux-1", {
      sessionId: "session-abc",
      sessionPersistence: "tmux",
      status: "running",
    });
    const parsed = {
      boardId: "b-1",
      repoRoot: "/test",
      nodes: [node],
      edges: [],
    };
    const result = normalizePersistedBoard(parsed);
    expect(result).not.toBeNull();
    const restoredNode = result!.nodes![0];
    expect(restoredNode.data.sessionRecoveryState).toBe("recoverable");
    expect(restoredNode.data.terminalAttached).toBe(false);
    expect(restoredNode.data.manualSession).toBe(true);
  });

  it("clears sessionId for non-tmux running sessions", () => {
    const node = makeNode("direct-1", {
      sessionId: "session-xyz",
      sessionPersistence: "direct",
      status: "running",
    });
    const parsed = {
      boardId: "b-1",
      repoRoot: "/test",
      nodes: [node],
      edges: [],
    };
    const result = normalizePersistedBoard(parsed);
    expect(result).not.toBeNull();
    const restoredNode = result!.nodes![0];
    expect(restoredNode.data.sessionId).toBeUndefined();
    expect(restoredNode.data.sessionPersistence).toBe("direct");
    expect(restoredNode.data.sessionRecoveryState).toBe("fresh");
    expect(restoredNode.data.status).toBe("idle");
  });

  it("generates boardId when missing", () => {
    const parsed = {
      repoRoot: "/test",
      nodes: [makeNode("n1")],
      edges: [],
    };
    const result = normalizePersistedBoard(parsed);
    expect(result).not.toBeNull();
    expect(result!.boardId).toBeDefined();
    expect(typeof result!.boardId).toBe("string");
    expect(result!.boardId!.startsWith("board-")).toBe(true);
  });

  it("preserves boardId when present", () => {
    const parsed = {
      boardId: "custom-board-id",
      repoRoot: "/test",
      nodes: [makeNode("n1")],
      edges: [],
    };
    const result = normalizePersistedBoard(parsed);
    expect(result!.boardId).toBe("custom-board-id");
  });

  it("defaults repoRoot to empty string when missing", () => {
    const parsed = {
      boardId: "b-1",
      nodes: [makeNode("n1")],
      edges: [],
    };
    const result = normalizePersistedBoard(parsed);
    expect(result!.repoRoot).toBe("");
  });
});

// ---------------------------------------------------------------------------
// truncateConversationHistory
// ---------------------------------------------------------------------------

describe("truncateConversationHistory", () => {
  it("returns undefined for non-array input", () => {
    expect(truncateConversationHistory(undefined)).toBeUndefined();
    expect(truncateConversationHistory(null as unknown as undefined)).toBeUndefined();
  });

  it("returns the same array when under the 200 limit", () => {
    const history = Array.from({ length: 50 }, (_, i) => ({
      role: "user" as const,
      content: `message-${i}`,
    }));
    const result = truncateConversationHistory(history as SwarmBoardNodeData["conversationHistory"]);
    expect(result).toBe(history);
    expect(result).toHaveLength(50);
  });

  it("truncates conversation history over 200 entries keeping the last 200", () => {
    const history = Array.from({ length: 250 }, (_, i) => ({
      role: "user" as const,
      content: `message-${i}`,
    }));
    const result = truncateConversationHistory(history as SwarmBoardNodeData["conversationHistory"]);
    expect(result).toHaveLength(200);
    // Should keep last 200 (indices 50-249)
    expect((result as Array<{ content: string }>)[0].content).toBe("message-50");
    expect((result as Array<{ content: string }>)[199].content).toBe("message-249");
  });

  it("returns the same array when exactly 200 entries", () => {
    const history = Array.from({ length: 200 }, (_, i) => ({
      role: "user" as const,
      content: `message-${i}`,
    }));
    const result = truncateConversationHistory(history as SwarmBoardNodeData["conversationHistory"]);
    expect(result).toBe(history);
    expect(result).toHaveLength(200);
  });
});

// ---------------------------------------------------------------------------
// isRecoverableTmuxNode
// ---------------------------------------------------------------------------

describe("isRecoverableTmuxNode", () => {
  it("returns true for a node with sessionId and tmux persistence", () => {
    expect(
      isRecoverableTmuxNode({
        title: "test",
        status: "running",
        nodeType: "agentSession",
        sessionId: "sess-1",
        sessionPersistence: "tmux",
      }),
    ).toBe(true);
  });

  it("returns false for a node with sessionId but direct persistence", () => {
    expect(
      isRecoverableTmuxNode({
        title: "test",
        status: "running",
        nodeType: "agentSession",
        sessionId: "sess-1",
        sessionPersistence: "direct",
      }),
    ).toBe(false);
  });

  it("returns false for a node without sessionId", () => {
    expect(
      isRecoverableTmuxNode({
        title: "test",
        status: "running",
        nodeType: "agentSession",
        sessionPersistence: "tmux",
      }),
    ).toBe(false);
  });

  it("returns false for undefined data", () => {
    expect(isRecoverableTmuxNode(undefined)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sanitizePersistedNode
// ---------------------------------------------------------------------------

describe("sanitizePersistedNode", () => {
  it("truncates conversation history in data", () => {
    const longHistory = Array.from({ length: 250 }, (_, i) => ({
      role: "user" as const,
      content: `msg-${i}`,
    }));
    const node = makeNode("n1", {
      conversationHistory: longHistory as SwarmBoardNodeData["conversationHistory"],
    });
    const result = sanitizePersistedNode(node);
    expect(
      (result.data.conversationHistory as unknown[]).length,
    ).toBe(200);
  });

  it("clears engine-managed transient fields", () => {
    const node = makeNode("n1", {
      engineManaged: true,
      branch: "feature/foo",
      worktreePath: "/tmp/wt",
      filesTouched: ["file.ts"],
      previewLines: ["line1"],
      taskPrompt: "do something",
    });
    const result = sanitizePersistedNode(node);
    expect(result.data.branch).toBeUndefined();
    expect(result.data.worktreePath).toBeUndefined();
    expect(result.data.filesTouched).toBeUndefined();
    expect(result.data.previewLines).toBeUndefined();
    expect(result.data.taskPrompt).toBeUndefined();
  });

  it("preserves non-engine-managed fields", () => {
    const node = makeNode("n1", {
      engineManaged: false,
      branch: "feature/bar",
      worktreePath: "/tmp/wt2",
    });
    const result = sanitizePersistedNode(node);
    expect(result.data.branch).toBe("feature/bar");
    expect(result.data.worktreePath).toBe("/tmp/wt2");
  });
});

// ---------------------------------------------------------------------------
// buildSessionMetadataPatch
// ---------------------------------------------------------------------------

describe("buildSessionMetadataPatch", () => {
  it("builds patch from session metadata", () => {
    const patch = buildSessionMetadataPatch({
      branch: "main",
      shell: "zsh",
      persistence_mode: "tmux",
      recovery_state: "fresh",
    });
    expect(patch.branch).toBe("main");
    expect(patch.sessionShell).toBe("zsh");
    expect(patch.sessionPersistence).toBe("tmux");
    expect(patch.sessionRecoveryState).toBe("fresh");
  });

  it("converts null branch to undefined", () => {
    const patch = buildSessionMetadataPatch({
      branch: null,
      shell: "bash",
      persistence_mode: "direct",
      recovery_state: "recoverable",
    });
    expect(patch.branch).toBeUndefined();
  });

  it("includes optional manualSession and terminalAttached when provided", () => {
    const patch = buildSessionMetadataPatch(
      {
        branch: "dev",
        shell: "fish",
        persistence_mode: "tmux",
        recovery_state: "recovered",
      },
      {
        manualSession: true,
        terminalAttached: false,
      },
    );
    expect(patch.manualSession).toBe(true);
    expect(patch.terminalAttached).toBe(false);
  });

  it("omits optional fields when not provided", () => {
    const patch = buildSessionMetadataPatch({
      branch: "main",
      shell: "zsh",
      persistence_mode: "tmux",
      recovery_state: "fresh",
    });
    expect("manualSession" in patch).toBe(false);
    expect("terminalAttached" in patch).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// generateBoardId
// ---------------------------------------------------------------------------

describe("generateBoardId", () => {
  it("returns a string starting with board-", () => {
    const id = generateBoardId();
    expect(id.startsWith("board-")).toBe(true);
  });
});
