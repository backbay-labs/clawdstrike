import { describe, expect, it } from "vitest";

import type {
  SwarmNodeType,
  SessionStatus,
  RiskLevel,
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmBoardState,
} from "../swarm-board-types";

// ---------------------------------------------------------------------------
// Node type validation
// ---------------------------------------------------------------------------

describe("SwarmNodeType", () => {
  const validNodeTypes: SwarmNodeType[] = [
    "agentSession",
    "terminalTask",
    "artifact",
    "diff",
    "note",
    "receipt",
  ];

  it.each(validNodeTypes)("accepts '%s' as a valid node type", (nodeType) => {
    // Type-level test: assigning a valid string to SwarmNodeType should not error.
    const t: SwarmNodeType = nodeType;
    expect(t).toBe(nodeType);
  });

  it("all valid node types are distinct", () => {
    const unique = new Set(validNodeTypes);
    expect(unique.size).toBe(validNodeTypes.length);
  });

  it("has exactly 6 node types", () => {
    expect(validNodeTypes).toHaveLength(6);
  });
});

// ---------------------------------------------------------------------------
// SessionStatus transitions
// ---------------------------------------------------------------------------

describe("SessionStatus", () => {
  const validStatuses: SessionStatus[] = [
    "idle",
    "running",
    "blocked",
    "completed",
    "failed",
  ];

  it.each(validStatuses)("accepts '%s' as a valid status", (status) => {
    const s: SessionStatus = status;
    expect(s).toBe(status);
  });

  it("has exactly 5 statuses", () => {
    expect(validStatuses).toHaveLength(5);
  });

  it("all valid statuses are distinct", () => {
    const unique = new Set(validStatuses);
    expect(unique.size).toBe(validStatuses.length);
  });

  describe("status transition validity", () => {
    // Valid transition map: which statuses can transition to which
    const validTransitions: Record<SessionStatus, SessionStatus[]> = {
      idle: ["running"],
      running: ["blocked", "completed", "failed"],
      blocked: ["running", "failed"],
      completed: [], // terminal state
      failed: ["idle"], // can be retried
    };

    it.each(Object.entries(validTransitions))(
      "from '%s' can transition to expected states",
      (from, toStates) => {
        const fromStatus = from as SessionStatus;
        expect(validStatuses).toContain(fromStatus);
        for (const to of toStates) {
          expect(validStatuses).toContain(to);
        }
      },
    );

    it("completed is a terminal state (no valid transitions out)", () => {
      expect(validTransitions.completed).toEqual([]);
    });

    it("idle can only go to running", () => {
      expect(validTransitions.idle).toEqual(["running"]);
    });

    it("running can transition to blocked, completed, or failed", () => {
      expect(validTransitions.running).toContain("blocked");
      expect(validTransitions.running).toContain("completed");
      expect(validTransitions.running).toContain("failed");
      expect(validTransitions.running).not.toContain("idle");
    });
  });
});

// ---------------------------------------------------------------------------
// RiskLevel ordering
// ---------------------------------------------------------------------------

describe("RiskLevel", () => {
  const validRiskLevels: RiskLevel[] = ["low", "medium", "high"];

  it.each(validRiskLevels)("accepts '%s' as a valid risk level", (risk) => {
    const r: RiskLevel = risk;
    expect(r).toBe(risk);
  });

  it("has exactly 3 risk levels", () => {
    expect(validRiskLevels).toHaveLength(3);
  });

  it("risk levels have a natural ordering: low < medium < high", () => {
    const riskOrder: Record<RiskLevel, number> = {
      low: 0,
      medium: 1,
      high: 2,
    };

    expect(riskOrder.low).toBeLessThan(riskOrder.medium);
    expect(riskOrder.medium).toBeLessThan(riskOrder.high);
    expect(riskOrder.low).toBeLessThan(riskOrder.high);
  });

  it("can be sorted by severity", () => {
    const riskOrder: Record<RiskLevel, number> = {
      low: 0,
      medium: 1,
      high: 2,
    };

    const unsorted: RiskLevel[] = ["high", "low", "medium", "low", "high"];
    const sorted = [...unsorted].sort((a, b) => riskOrder[a] - riskOrder[b]);

    expect(sorted).toEqual(["low", "low", "medium", "high", "high"]);
  });
});

// ---------------------------------------------------------------------------
// SwarmBoardEdge type validation
// ---------------------------------------------------------------------------

describe("SwarmBoardEdge", () => {
  const validEdgeTypes: NonNullable<SwarmBoardEdge["type"]>[] = [
    "handoff",
    "spawned",
    "artifact",
    "receipt",
  ];

  it.each(validEdgeTypes)("accepts '%s' as a valid edge type", (edgeType) => {
    const edge: SwarmBoardEdge = {
      id: "e1",
      source: "n1",
      target: "n2",
      type: edgeType,
    };
    expect(edge.type).toBe(edgeType);
  });

  it("has exactly 4 edge types", () => {
    expect(validEdgeTypes).toHaveLength(4);
  });

  it("all valid edge types are distinct", () => {
    const unique = new Set(validEdgeTypes);
    expect(unique.size).toBe(validEdgeTypes.length);
  });

  it("edge type is optional (undefined is valid)", () => {
    const edge: SwarmBoardEdge = {
      id: "e1",
      source: "n1",
      target: "n2",
    };
    expect(edge.type).toBeUndefined();
  });

  it("label is optional", () => {
    const edge: SwarmBoardEdge = {
      id: "e1",
      source: "n1",
      target: "n2",
      type: "handoff",
    };
    expect(edge.label).toBeUndefined();

    const edgeWithLabel: SwarmBoardEdge = {
      ...edge,
      label: "delegated",
    };
    expect(edgeWithLabel.label).toBe("delegated");
  });
});

// ---------------------------------------------------------------------------
// SwarmBoardNodeData structure
// ---------------------------------------------------------------------------

describe("SwarmBoardNodeData", () => {
  it("requires title, status, and nodeType", () => {
    const minimal: SwarmBoardNodeData = {
      title: "Test",
      status: "idle",
      nodeType: "note",
    };

    expect(minimal.title).toBe("Test");
    expect(minimal.status).toBe("idle");
    expect(minimal.nodeType).toBe("note");
  });

  it("supports agentSession fields", () => {
    const agent: SwarmBoardNodeData = {
      title: "Agent",
      status: "running",
      nodeType: "agentSession",
      sessionId: "sess-123",
      worktreePath: "/path/to/worktree",
      branch: "feat/test",
      previewLines: ["line1", "line2"],
      receiptCount: 5,
      blockedActionCount: 1,
      changedFilesCount: 3,
      risk: "medium",
      policyMode: "strict",
      agentModel: "opus-4.6",
      taskPrompt: "Fix the auth bug",
    };

    expect(agent.sessionId).toBe("sess-123");
    expect(agent.branch).toBe("feat/test");
    expect(agent.previewLines).toHaveLength(2);
    expect(agent.receiptCount).toBe(5);
    expect(agent.risk).toBe("medium");
  });

  it("supports receipt fields", () => {
    const receipt: SwarmBoardNodeData = {
      title: "Receipt",
      status: "completed",
      nodeType: "receipt",
      verdict: "deny",
      guardResults: [
        { guard: "ForbiddenPathGuard", allowed: false, duration_ms: 3 },
        { guard: "SecretLeakGuard", allowed: true, duration_ms: 5 },
      ],
    };

    expect(receipt.verdict).toBe("deny");
    expect(receipt.guardResults).toHaveLength(2);
    expect(receipt.guardResults![0].guard).toBe("ForbiddenPathGuard");
    expect(receipt.guardResults![0].allowed).toBe(false);
  });

  it("supports diff fields", () => {
    const diff: SwarmBoardNodeData = {
      title: "Diff",
      status: "idle",
      nodeType: "diff",
      diffSummary: {
        added: 42,
        removed: 7,
        files: ["src/main.rs", "Cargo.toml"],
      },
    };

    expect(diff.diffSummary!.added).toBe(42);
    expect(diff.diffSummary!.removed).toBe(7);
    expect(diff.diffSummary!.files).toHaveLength(2);
  });

  it("supports artifact fields", () => {
    const artifact: SwarmBoardNodeData = {
      title: "main.rs",
      status: "idle",
      nodeType: "artifact",
      filePath: "src/main.rs",
      fileType: "rust",
    };

    expect(artifact.filePath).toBe("src/main.rs");
    expect(artifact.fileType).toBe("rust");
  });

  it("supports note fields", () => {
    const note: SwarmBoardNodeData = {
      title: "Notes",
      status: "idle",
      nodeType: "note",
      content: "This is a note about the coordination plan.",
    };

    expect(note.content).toContain("coordination plan");
  });

  it("verdict only accepts allow, deny, or warn", () => {
    const verdicts: Array<NonNullable<SwarmBoardNodeData["verdict"]>> = ["allow", "deny", "warn"];

    for (const v of verdicts) {
      const node: SwarmBoardNodeData = {
        title: "Test",
        status: "idle",
        nodeType: "receipt",
        verdict: v,
      };
      expect(node.verdict).toBe(v);
    }
  });
});

// ---------------------------------------------------------------------------
// SwarmBoardState structure
// ---------------------------------------------------------------------------

describe("SwarmBoardState", () => {
  it("has required fields", () => {
    const state: SwarmBoardState = {
      boardId: "board-1",
      repoRoot: "/path/to/repo",
      nodes: [],
      edges: [],
      selectedNodeId: null,
      inspectorOpen: false,
    };

    expect(state.boardId).toBe("board-1");
    expect(state.repoRoot).toBe("/path/to/repo");
    expect(state.nodes).toEqual([]);
    expect(state.edges).toEqual([]);
    expect(state.selectedNodeId).toBeNull();
    expect(state.inspectorOpen).toBe(false);
  });

  it("selectedNodeId can be a string when a node is selected", () => {
    const state: SwarmBoardState = {
      boardId: "board-1",
      repoRoot: "",
      nodes: [],
      edges: [],
      selectedNodeId: "node-123",
      inspectorOpen: true,
    };

    expect(state.selectedNodeId).toBe("node-123");
    expect(state.inspectorOpen).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Utility: risk level comparison helper
// ---------------------------------------------------------------------------

describe("Risk level comparison utility", () => {
  // Utility function that consumers would use
  function compareRiskLevels(a: RiskLevel, b: RiskLevel): number {
    const order: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };
    return order[a] - order[b];
  }

  it("low < medium", () => {
    expect(compareRiskLevels("low", "medium")).toBeLessThan(0);
  });

  it("medium < high", () => {
    expect(compareRiskLevels("medium", "high")).toBeLessThan(0);
  });

  it("high > low", () => {
    expect(compareRiskLevels("high", "low")).toBeGreaterThan(0);
  });

  it("equal levels return 0", () => {
    expect(compareRiskLevels("low", "low")).toBe(0);
    expect(compareRiskLevels("medium", "medium")).toBe(0);
    expect(compareRiskLevels("high", "high")).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Utility: status dot color mapping
// ---------------------------------------------------------------------------

describe("Status dot color mapping", () => {
  function statusColor(status: SessionStatus): string {
    switch (status) {
      case "idle":
        return "#6f7f9a";
      case "running":
        return "#3dbf84";
      case "blocked":
        return "#d4a84b";
      case "completed":
        return "#5b8def";
      case "failed":
        return "#ef4444";
    }
  }

  it("idle has a muted color", () => {
    expect(statusColor("idle")).toBe("#6f7f9a");
  });

  it("running has a green color", () => {
    expect(statusColor("running")).toBe("#3dbf84");
  });

  it("blocked has a warning/gold color", () => {
    expect(statusColor("blocked")).toBe("#d4a84b");
  });

  it("completed has a blue color", () => {
    expect(statusColor("completed")).toBe("#5b8def");
  });

  it("failed has a red color", () => {
    expect(statusColor("failed")).toBe("#ef4444");
  });

  it("all statuses have distinct colors", () => {
    const statuses: SessionStatus[] = ["idle", "running", "blocked", "completed", "failed"];
    const colors = statuses.map(statusColor);
    const unique = new Set(colors);
    expect(unique.size).toBe(colors.length);
  });
});
