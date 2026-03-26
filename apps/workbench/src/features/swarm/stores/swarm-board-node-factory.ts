// ---------------------------------------------------------------------------
// SwarmBoard Node Factory — node creation, mock board seeding, edge helpers
//
// Extracted from swarm-board-store.tsx. All functions are pure factory/helper
// functions with zero store dependency.
// ---------------------------------------------------------------------------
import { MarkerType, type Node, type Edge } from "@xyflow/react";
import type {
  SwarmBoardNodeData,
  SwarmBoardEdge,
  SwarmNodeType,
} from "@/features/swarm/swarm-board-types";

// ---------------------------------------------------------------------------
// ID generators
// ---------------------------------------------------------------------------

const AUTH_CHANGES_DIFF = `diff --git a/src/middleware/auth.rs b/src/middleware/auth.rs
index 91c8f76..5f14219 100644
--- a/src/middleware/auth.rs
+++ b/src/middleware/auth.rs
@@ -1,7 +1,13 @@
 use crate::middleware::token::TokenClaims;
+use crate::middleware::rate_limit::RateLimitContext;

 pub fn validate_token(token: &str) -> Result<TokenClaims, AuthError> {
-    decode_token(token)
+    let claims = decode_token(token)?;
+    if claims.expired() {
+        return Err(AuthError::ExpiredToken);
+    }
+
+    Ok(claims)
 }
diff --git a/tests/auth_test.rs b/tests/auth_test.rs
index 321aa77..611ae21 100644
--- a/tests/auth_test.rs
+++ b/tests/auth_test.rs
@@ -12,3 +12,7 @@ fn validates_token() {}

 #[test]
 fn validates_token() {}
+
+#[test]
+fn rejects_expired_token() {}
`;

function generateBoardId(): string {
  return `board-${Date.now().toString(36)}`;
}

export function generateNodeId(): string {
  return `node-${crypto.randomUUID()}`;
}

// ---------------------------------------------------------------------------
// Node factory
// ---------------------------------------------------------------------------

export interface CreateNodeConfig {
  nodeType: SwarmNodeType;
  title: string;
  position?: { x: number; y: number };
  data?: Partial<SwarmBoardNodeData>;
}

export function createBoardNode(config: CreateNodeConfig): Node<SwarmBoardNodeData> {
  const id = generateNodeId();
  const position = config.position ?? {
    x: 100 + Math.random() * 400,
    y: 100 + Math.random() * 300,
  };

  const defaults: SwarmBoardNodeData = {
    title: config.title,
    status: "idle",
    nodeType: config.nodeType,
    createdAt: Date.now(),
  };

  // Dimension defaults per node type
  const dimensions: Record<SwarmNodeType, { width?: number; height?: number }> = {
    agentSession: { width: 380, height: 280 },
    terminalTask: { width: 300, height: 180 },
    artifact: { width: 240, height: 100 },
    diff: { width: 280, height: 180 },
    note: { width: 260, height: 160 },
    receipt: { width: 300, height: 220 },
  };

  const dims = dimensions[config.nodeType];

  return {
    id,
    type: config.nodeType,
    position,
    data: { ...defaults, ...config.data },
    ...(dims.width ? { width: dims.width } : {}),
    ...(dims.height ? { height: dims.height } : {}),
  };
}

// ---------------------------------------------------------------------------
// Mock data seeder
// ---------------------------------------------------------------------------

export function createMockBoard(): {
  nodes: Node<SwarmBoardNodeData>[];
  edges: SwarmBoardEdge[];
} {
  const agent1 = createBoardNode({
    nodeType: "agentSession",
    title: "Fix auth middleware",
    position: { x: 80, y: 60 },
    data: {
      agentModel: "opus-4.6",
      branch: "feat/fix-auth",
      status: "running",
      worktreePath: "/home/user/project/.worktrees/fix-auth",
      previewLines: [
        "$ cargo test -p auth-middleware",
        "running 12 tests...",
        "test middleware::validate_token ... ok",
        "test middleware::refresh_expired ... ok",
        "test middleware::reject_malformed ... FAILED",
        "--- analyzing failure ---",
      ],
      receiptCount: 7,
      blockedActionCount: 1,
      changedFilesCount: 4,
      risk: "medium",
      policyMode: "strict",
      toolBoundaryEvents: 23,
      filesTouched: [
        "src/middleware/auth.rs",
        "src/middleware/token.rs",
        "tests/auth_test.rs",
        "Cargo.toml",
      ],
      confidence: 72,
      huntId: "hunt-sec-audit",
    },
  });

  const agent2 = createBoardNode({
    nodeType: "agentSession",
    title: "Add rate limiter",
    position: { x: 560, y: 60 },
    data: {
      agentModel: "sonnet-4",
      branch: "feat/rate-limit",
      status: "completed",
      worktreePath: "/home/user/project/.worktrees/rate-limit",
      previewLines: [
        "$ cargo clippy --workspace",
        "Checking rate-limiter v0.1.0",
        'Finished `dev` profile target(s)',
        "All checks passed.",
      ],
      receiptCount: 12,
      blockedActionCount: 0,
      changedFilesCount: 6,
      risk: "low",
      policyMode: "default",
      toolBoundaryEvents: 41,
      filesTouched: [
        "src/rate_limiter/mod.rs",
        "src/rate_limiter/sliding_window.rs",
        "src/rate_limiter/config.rs",
        "tests/rate_limiter_test.rs",
        "Cargo.toml",
        "docs/rate-limiting.md",
      ],
      confidence: 95,
      huntId: "hunt-sec-audit",
    },
  });

  const agent3 = createBoardNode({
    nodeType: "agentSession",
    title: "Investigate CVE-2026-1234",
    position: { x: 1040, y: 60 },
    data: {
      agentModel: "opus-4.6",
      branch: "security/cve-2026-1234",
      status: "blocked",
      worktreePath: "/home/user/project/.worktrees/cve-fix",
      previewLines: [
        "$ clawdstrike check --action-type file --ruleset strict",
        "DENIED: write to /etc/shadow blocked by ForbiddenPathGuard",
        "Waiting for operator approval...",
      ],
      receiptCount: 3,
      blockedActionCount: 2,
      changedFilesCount: 1,
      risk: "high",
      policyMode: "strict",
      toolBoundaryEvents: 8,
      confidence: 35,
    },
  });

  const task1 = createBoardNode({
    nodeType: "terminalTask",
    title: "Run integration tests",
    position: { x: 80, y: 400 },
    data: {
      status: "running",
      taskPrompt: "Execute the full integration test suite and report failures",
    },
  });

  const receipt1 = createBoardNode({
    nodeType: "receipt",
    title: "File write check",
    position: { x: 560, y: 400 },
    data: {
      status: "completed",
      verdict: "allow",
      guardResults: [
        { guard: "ForbiddenPathGuard", allowed: true, duration_ms: 2 },
        { guard: "SecretLeakGuard", allowed: true, duration_ms: 8 },
        { guard: "PatchIntegrityGuard", allowed: true, duration_ms: 3 },
      ],
      receiptCount: 1,
    },
  });

  const receipt2 = createBoardNode({
    nodeType: "receipt",
    title: "Shell exec denied",
    position: { x: 1040, y: 400 },
    data: {
      status: "completed",
      verdict: "deny",
      guardResults: [
        { guard: "ShellCommandGuard", allowed: false, duration_ms: 1 },
        { guard: "ForbiddenPathGuard", allowed: false, duration_ms: 2 },
        { guard: "SpiderSenseGuard", allowed: true, duration_ms: 15 },
      ],
      receiptCount: 1,
    },
  });

  const diff1 = createBoardNode({
    nodeType: "diff",
    title: "Auth changes",
    position: { x: 340, y: 400 },
    data: {
      status: "idle",
      diffSummary: {
        added: 8,
        removed: 1,
        files: [
          "src/middleware/auth.rs",
          "tests/auth_test.rs",
        ],
      },
      diffContent: AUTH_CHANGES_DIFF,
    },
  });

  const artifact1 = createBoardNode({
    nodeType: "artifact",
    title: "auth.rs",
    position: { x: 340, y: 220 },
    data: {
      status: "idle",
      filePath: "src/middleware/auth.rs",
      fileType: "rust",
    },
  });

  const artifact2 = createBoardNode({
    nodeType: "artifact",
    title: "sliding_window.rs",
    position: { x: 860, y: 340 },
    data: {
      status: "idle",
      filePath: "src/rate_limiter/sliding_window.rs",
      fileType: "rust",
    },
  });

  const note1 = createBoardNode({
    nodeType: "note",
    title: "Coordination notes",
    position: { x: 860, y: 120 },
    data: {
      status: "idle",
      content:
        "Agent 1 owns auth middleware changes.\nAgent 2 owns rate limiter.\nAgent 3 investigating CVE — blocked, needs operator review.\n\nMerge order: rate-limiter first, then auth.",
    },
  });

  const nodes = [agent1, agent2, agent3, task1, receipt1, receipt2, diff1, artifact1, artifact2, note1];

  const edges: SwarmBoardEdge[] = [
    {
      id: `edge-${agent1.id}-${task1.id}`,
      source: agent1.id,
      target: task1.id,
      type: "spawned",
      label: "spawned",
    },
    {
      id: `edge-${agent1.id}-${artifact1.id}`,
      source: agent1.id,
      target: artifact1.id,
      type: "artifact",
      label: "produces",
    },
    {
      id: `edge-${agent1.id}-${diff1.id}`,
      source: agent1.id,
      target: diff1.id,
      type: "artifact",
    },
    {
      id: `edge-${agent2.id}-${receipt1.id}`,
      source: agent2.id,
      target: receipt1.id,
      type: "receipt",
      label: "receipt",
    },
    {
      id: `edge-${agent2.id}-${artifact2.id}`,
      source: agent2.id,
      target: artifact2.id,
      type: "artifact",
      label: "produces",
    },
    {
      id: `edge-${agent3.id}-${receipt2.id}`,
      source: agent3.id,
      target: receipt2.id,
      type: "receipt",
      label: "denied",
    },
    {
      id: `edge-${agent1.id}-${agent2.id}`,
      source: agent1.id,
      target: agent2.id,
      type: "handoff",
      label: "handoff",
    },
  ];

  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Edge color helper
// ---------------------------------------------------------------------------

export function edgeColor(type?: SwarmBoardEdge["type"]): string {
  switch (type) {
    case "handoff":
      return "#5b8def";
    case "spawned":
      return "#d4a84b";
    case "dependency":
      return "#7085ad";
    case "artifact":
      return "#3dbf84";
    case "receipt":
      return "#8b5cf6";
    case "topology":
      return "#3d4250";
    default:
      return "#2d3240";
  }
}

// ---------------------------------------------------------------------------
// Convert SwarmBoardEdge[] to React Flow Edge[]
// ---------------------------------------------------------------------------

export function toRfEdges(edges: SwarmBoardEdge[]): Edge[] {
  return edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    type: "swarmEdge",
    data: { edgeType: e.type },
    animated: e.type === "spawned",
    style: { stroke: edgeColor(e.type) },
    markerEnd:
      e.type === "handoff" || e.type === "spawned" || e.type === "dependency"
        ? { type: MarkerType.ArrowClosed, color: edgeColor(e.type) }
        : undefined,
  }));
}
