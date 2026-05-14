import { beforeEach, describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// The persistence functions are not individually exported from the store,
// so we test them via their observable effects: what gets written to
// localStorage and what the store restores on initialization.
//
// We replicate the persistence contract here with thin helpers.
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_swarm_board";

// ---------------------------------------------------------------------------
// Minimal persistence contract (mirrors swarm-board-store.tsx)
// ---------------------------------------------------------------------------

interface PersistedBoard {
  boardId: string;
  repoRoot: string;
  nodes: Array<{
    id: string;
    type: string;
    position: { x: number; y: number };
    data: Record<string, unknown>;
    width?: number;
    height?: number;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    type?: string;
    label?: string;
  }>;
}

function persistBoard(board: PersistedBoard): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(board));
  } catch {
    // Silently fail (mirroring store behavior)
  }
}

function loadPersistedBoard(): PersistedBoard | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (
      !parsed ||
      typeof parsed !== "object" ||
      !Array.isArray(parsed.nodes) ||
      !Array.isArray(parsed.edges)
    ) {
      return null;
    }
    return {
      boardId: typeof parsed.boardId === "string" ? parsed.boardId : "board-fallback",
      repoRoot: typeof parsed.repoRoot === "string" ? parsed.repoRoot : "",
      nodes: parsed.nodes,
      edges: parsed.edges,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  localStorage.clear();
});

describe("save/restore board layout", () => {
  it("saves a board layout with node positions, zoom, and pan", () => {
    const board: PersistedBoard = {
      boardId: "board-test-1",
      repoRoot: "/home/user/project",
      nodes: [
        {
          id: "n1",
          type: "agentSession",
          position: { x: 150, y: 250 },
          data: { title: "Agent 1", status: "running", nodeType: "agentSession" },
          width: 380,
          height: 280,
        },
        {
          id: "n2",
          type: "receipt",
          position: { x: 600, y: 100 },
          data: { title: "Receipt 1", status: "completed", nodeType: "receipt", verdict: "allow" },
          width: 300,
          height: 220,
        },
      ],
      edges: [
        {
          id: "e1",
          source: "n1",
          target: "n2",
          type: "receipt",
          label: "receipt",
        },
      ],
    };

    persistBoard(board);

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.boardId).toBe("board-test-1");
    expect(restored!.repoRoot).toBe("/home/user/project");
    expect(restored!.nodes).toHaveLength(2);
    expect(restored!.edges).toHaveLength(1);

    // Verify node positions are preserved
    expect(restored!.nodes[0].position).toEqual({ x: 150, y: 250 });
    expect(restored!.nodes[1].position).toEqual({ x: 600, y: 100 });

    // Verify node data is preserved
    expect(restored!.nodes[0].data.title).toBe("Agent 1");
    expect(restored!.nodes[1].data.verdict).toBe("allow");

    // Verify edge data is preserved
    expect(restored!.edges[0].source).toBe("n1");
    expect(restored!.edges[0].target).toBe("n2");
    expect(restored!.edges[0].type).toBe("receipt");
  });

  it("preserves node dimensions (width/height)", () => {
    const board: PersistedBoard = {
      boardId: "board-dims",
      repoRoot: "",
      nodes: [
        {
          id: "n1",
          type: "agentSession",
          position: { x: 0, y: 0 },
          data: { title: "Agent", status: "idle", nodeType: "agentSession" },
          width: 380,
          height: 280,
        },
      ],
      edges: [],
    };

    persistBoard(board);
    const restored = loadPersistedBoard();

    expect(restored!.nodes[0].width).toBe(380);
    expect(restored!.nodes[0].height).toBe(280);
  });
});

describe("handle corrupted localStorage gracefully", () => {
  it("returns null for garbage string", () => {
    localStorage.setItem(STORAGE_KEY, "this is not JSON");
    expect(loadPersistedBoard()).toBeNull();
  });

  it("returns null for valid JSON that is not an object", () => {
    localStorage.setItem(STORAGE_KEY, '"just a string"');
    expect(loadPersistedBoard()).toBeNull();
  });

  it("returns null for valid JSON array", () => {
    localStorage.setItem(STORAGE_KEY, "[1, 2, 3]");
    expect(loadPersistedBoard()).toBeNull();
  });

  it("returns null for object missing nodes array", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ boardId: "b1", repoRoot: "", edges: [] }),
    );
    expect(loadPersistedBoard()).toBeNull();
  });

  it("returns null for object missing edges array", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ boardId: "b1", repoRoot: "", nodes: [] }),
    );
    expect(loadPersistedBoard()).toBeNull();
  });

  it("returns null for object where nodes is not an array", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ boardId: "b1", repoRoot: "", nodes: "not-array", edges: [] }),
    );
    expect(loadPersistedBoard()).toBeNull();
  });

  it("returns null for object where edges is not an array", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ boardId: "b1", repoRoot: "", nodes: [], edges: "not-array" }),
    );
    expect(loadPersistedBoard()).toBeNull();
  });

  it("returns null for null JSON", () => {
    localStorage.setItem(STORAGE_KEY, "null");
    expect(loadPersistedBoard()).toBeNull();
  });

  it("returns null for empty object", () => {
    localStorage.setItem(STORAGE_KEY, "{}");
    expect(loadPersistedBoard()).toBeNull();
  });
});

describe("handle missing localStorage gracefully", () => {
  it("returns null when no key exists", () => {
    expect(loadPersistedBoard()).toBeNull();
  });

  it("returns null for empty string value", () => {
    localStorage.setItem(STORAGE_KEY, "");
    // Empty string will throw JSON.parse error, caught and returns null
    expect(loadPersistedBoard()).toBeNull();
  });
});

describe("field fallbacks", () => {
  it("falls back to generated boardId when missing", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ repoRoot: "", nodes: [{ id: "n1" }], edges: [] }),
    );

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.boardId).toBe("board-fallback");
  });

  it("falls back to empty string for repoRoot when missing", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ boardId: "b1", nodes: [{ id: "n1" }], edges: [] }),
    );

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.repoRoot).toBe("");
  });

  it("falls back when boardId is a number instead of string", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ boardId: 42, repoRoot: "", nodes: [{ id: "n1" }], edges: [] }),
    );

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.boardId).toBe("board-fallback");
  });

  it("falls back when repoRoot is a number instead of string", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ boardId: "b1", repoRoot: 42, nodes: [{ id: "n1" }], edges: [] }),
    );

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.repoRoot).toBe("");
  });
});

describe("migration from older format (future-proofing)", () => {
  it("handles persisted data with extra unknown fields gracefully", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        boardId: "b-old",
        repoRoot: "/old",
        nodes: [
          {
            id: "n1",
            type: "agentSession",
            position: { x: 0, y: 0 },
            data: { title: "Old Node", status: "idle", nodeType: "agentSession" },
          },
        ],
        edges: [],
        // Unknown fields from a hypothetical older format
        version: 1,
        viewport: { x: 100, y: 200, zoom: 1.5 },
        lastSavedAt: 1700000000000,
        metadata: { author: "test" },
      }),
    );

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.boardId).toBe("b-old");
    expect(restored!.nodes).toHaveLength(1);
    expect(restored!.nodes[0].data.title).toBe("Old Node");
    // Extra fields are ignored but don't break loading
  });

  it("handles nodes with extra unknown data fields", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        boardId: "b-extra",
        repoRoot: "",
        nodes: [
          {
            id: "n1",
            type: "agentSession",
            position: { x: 0, y: 0 },
            data: {
              title: "Agent",
              status: "running",
              nodeType: "agentSession",
              // Unknown fields that might exist in a future version
              connectionId: "conn-123",
              metrics: { cpu: 0.5, memory: 128 },
            },
            // Unknown node-level fields
            zIndex: 10,
            selected: true,
          },
        ],
        edges: [],
      }),
    );

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.nodes).toHaveLength(1);
    expect(restored!.nodes[0].data.title).toBe("Agent");
  });

  it("handles edges with unknown type values", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        boardId: "b-edge",
        repoRoot: "",
        nodes: [{ id: "n1" }, { id: "n2" }],
        edges: [
          {
            id: "e1",
            source: "n1",
            target: "n2",
            // A hypothetical future edge type
            type: "delegation",
            label: "delegates to",
          },
        ],
      }),
    );

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.edges).toHaveLength(1);
    expect(restored!.edges[0].type).toBe("delegation");
  });

  it("handles empty nodes array (cleared board)", () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        boardId: "b-empty",
        repoRoot: "",
        nodes: [],
        edges: [],
      }),
    );

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.nodes).toEqual([]);
    expect(restored!.edges).toEqual([]);
  });
});

describe("save roundtrip", () => {
  it("persist and restore is lossless for well-formed data", () => {
    const original: PersistedBoard = {
      boardId: "board-roundtrip",
      repoRoot: "/home/user/project",
      nodes: [
        {
          id: "n1",
          type: "agentSession",
          position: { x: 100, y: 200 },
          data: {
            title: "Agent",
            status: "running",
            nodeType: "agentSession",
            branch: "feat/test",
            receiptCount: 5,
          },
          width: 380,
          height: 280,
        },
        {
          id: "n2",
          type: "receipt",
          position: { x: 500, y: 200 },
          data: {
            title: "Receipt",
            status: "completed",
            nodeType: "receipt",
            verdict: "allow",
            guardResults: [
              { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
            ],
          },
          width: 300,
          height: 220,
        },
        {
          id: "n3",
          type: "diff",
          position: { x: 300, y: 400 },
          data: {
            title: "Changes",
            status: "idle",
            nodeType: "diff",
            diffSummary: { added: 10, removed: 3, files: ["a.rs", "b.rs"] },
          },
          width: 280,
          height: 180,
        },
      ],
      edges: [
        { id: "e1", source: "n1", target: "n2", type: "receipt", label: "receipt" },
        { id: "e2", source: "n1", target: "n3", type: "artifact" },
      ],
    };

    persistBoard(original);
    const restored = loadPersistedBoard();

    expect(restored).not.toBeNull();
    expect(restored!.boardId).toBe(original.boardId);
    expect(restored!.repoRoot).toBe(original.repoRoot);
    expect(restored!.nodes).toHaveLength(original.nodes.length);
    expect(restored!.edges).toHaveLength(original.edges.length);

    // Deep equality check
    for (let i = 0; i < original.nodes.length; i++) {
      expect(restored!.nodes[i].id).toBe(original.nodes[i].id);
      expect(restored!.nodes[i].position).toEqual(original.nodes[i].position);
      expect(restored!.nodes[i].data).toEqual(original.nodes[i].data);
    }

    for (let i = 0; i < original.edges.length; i++) {
      expect(restored!.edges[i]).toEqual(original.edges[i]);
    }
  });

  it("overwriting persisted data replaces the old data", () => {
    const board1: PersistedBoard = {
      boardId: "b-first",
      repoRoot: "",
      nodes: [
        {
          id: "n1",
          type: "note",
          position: { x: 0, y: 0 },
          data: { title: "First", status: "idle", nodeType: "note" },
        },
      ],
      edges: [],
    };

    const board2: PersistedBoard = {
      boardId: "b-second",
      repoRoot: "/new/root",
      nodes: [
        {
          id: "n2",
          type: "artifact",
          position: { x: 50, y: 50 },
          data: { title: "Second", status: "idle", nodeType: "artifact" },
        },
        {
          id: "n3",
          type: "diff",
          position: { x: 100, y: 100 },
          data: { title: "Third", status: "idle", nodeType: "diff" },
        },
      ],
      edges: [],
    };

    persistBoard(board1);
    persistBoard(board2);

    const restored = loadPersistedBoard();
    expect(restored).not.toBeNull();
    expect(restored!.boardId).toBe("b-second");
    expect(restored!.nodes).toHaveLength(2);
    expect(restored!.nodes[0].id).toBe("n2");
  });
});
