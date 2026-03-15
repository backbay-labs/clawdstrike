/**
 * useTerminalSessions — convenience hook for SwarmBoard terminal session lifecycle.
 *
 * Wraps the store's session management methods with additional helpers for
 * common spawn patterns. The core session lifecycle (spawn, monitor exit,
 * kill, cleanup) lives in the SwarmBoardProvider; this hook provides a
 * friendlier API surface for toolbar/UI consumers.
 */

import { useCallback, useMemo } from "react";
import {
  useSwarmBoard,
  MAX_ACTIVE_TERMINALS,
  type SpawnSessionOptions,
  type SpawnClaudeSessionOptions,
  type SpawnWorktreeSessionOptions,
} from "./swarm-board-store";
import type { SwarmBoardNodeData } from "./swarm-board-types";
import type { Node } from "@xyflow/react";

// ---------------------------------------------------------------------------
// Types re-exported for convenience
// ---------------------------------------------------------------------------

export type { SpawnSessionOptions, SpawnClaudeSessionOptions, SpawnWorktreeSessionOptions };

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useTerminalSessions() {
  const {
    state,
    spawnSession,
    spawnClaudeSession,
    spawnWorktreeSession,
    killSession,
    removeNode,
  } = useSwarmBoard();

  const repoRoot = state.repoRoot;

  // -----------------------------------------------------------------------
  // Quick-spawn helpers (use defaults from the store's repoRoot)
  // -----------------------------------------------------------------------

  /** Spawn a plain terminal at the repo root. */
  const spawnTerminal = useCallback(
    async (position?: { x: number; y: number }): Promise<Node<SwarmBoardNodeData>> => {
      if (!repoRoot) {
        throw new Error("repoRoot is not set. Configure it in SwarmBoard settings.");
      }
      return spawnSession({ cwd: repoRoot, position, title: "Terminal" });
    },
    [repoRoot, spawnSession],
  );

  /** Spawn Claude Code at repo root (no worktree). */
  const spawnClaude = useCallback(
    async (position?: { x: number; y: number }): Promise<Node<SwarmBoardNodeData>> => {
      return spawnClaudeSession({ position });
    },
    [spawnClaudeSession],
  );

  /** Spawn Claude Code in an isolated worktree. */
  const spawnClaudeInWorktree = useCallback(
    async (
      position?: { x: number; y: number },
      branch?: string,
      prompt?: string,
    ): Promise<Node<SwarmBoardNodeData>> => {
      return spawnClaudeSession({ position, worktree: true, branch, prompt });
    },
    [spawnClaudeSession],
  );

  /** Spawn a shell in a new worktree. */
  const spawnWorktree = useCallback(
    async (
      position?: { x: number; y: number },
      branch?: string,
    ): Promise<Node<SwarmBoardNodeData>> => {
      return spawnWorktreeSession({ position, branch });
    },
    [spawnWorktreeSession],
  );

  // -----------------------------------------------------------------------
  // Node removal with session cleanup
  // -----------------------------------------------------------------------

  /** Remove a node from the board, killing its session if active. */
  const removeNodeWithCleanup = useCallback(
    async (nodeId: string) => {
      const node = state.nodes.find((n) => n.id === nodeId);
      if (node) {
        const d = node.data as SwarmBoardNodeData;
        if (d.sessionId && (d.status === "running" || d.status === "blocked")) {
          try {
            await killSession(nodeId);
          } catch (err) {
            // Kill failed (IPC error, timeout, etc.) — still remove the node
            // so the UI doesn't get stuck with an unkillable tile.
            console.warn("[use-terminal-sessions] killSession failed during removal:", err);
          }
        }
      }
      removeNode(nodeId);
    },
    [state.nodes, killSession, removeNode],
  );

  // -----------------------------------------------------------------------
  // Session queries
  // -----------------------------------------------------------------------

  /** Count of currently active (running/blocked) sessions. */
  const activeSessionCount = useMemo(
    () => state.nodes.filter((n) => {
      const d = n.data as SwarmBoardNodeData;
      return d.sessionId && (d.status === "running" || d.status === "blocked");
    }).length,
    [state.nodes],
  );

  /** Whether we can spawn more sessions (below the limit). */
  const canSpawnMore = activeSessionCount < MAX_ACTIVE_TERMINALS;

  /** Whether repoRoot is configured. */
  const hasRepoRoot = Boolean(repoRoot);

  return {
    // Core session methods (from store)
    spawnSession,
    spawnClaudeSession,
    spawnWorktreeSession,
    killSession,
    // Quick-spawn helpers
    spawnTerminal,
    spawnClaude,
    spawnClaudeInWorktree,
    spawnWorktree,
    // Cleanup
    removeNodeWithCleanup,
    // Queries
    activeSessionCount,
    canSpawnMore,
    hasRepoRoot,
    repoRoot,
  };
}
