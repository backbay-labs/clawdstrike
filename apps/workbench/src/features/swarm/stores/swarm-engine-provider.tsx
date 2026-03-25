/**
 * SwarmEngineProvider -- React context provider that manages the lifecycle of a
 * SwarmOrchestrator instance from @clawdstrike/swarm-engine.
 *
 * Provides:
 * - Engine initialization on mount with error fallback (mode="error")
 * - Cleanup via shutdown() on unmount (NOT dispose -- Pitfall 8)
 * - React strict mode double-mount guard via `cancelled` boolean
 * - Convenience hooks: useSwarmEngine, useAgentRegistry, useTaskGraph, useTopology
 *
 * When `enabled` is false, the provider operates in manual mode: all hooks
 * return null and the existing SwarmBoard works as-is with no engine overhead.
 *
 * @module
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { Node } from "@xyflow/react";
import {
  SwarmOrchestrator,
  TypedEventEmitter,
  AgentRegistry,
  TaskGraph,
  TopologyManager,
  type GuardedAction,
  type SwarmEngineEventMap,
  type SwarmEngineState,
  type SwarmOrchestratorConfig,
} from "@clawdstrike/swarm-engine";
import type { SwarmBoardNodeData } from "../swarm-board-types";
import {
  useSwarmBoardStore,
  type SpawnSessionOptions,
  type SpawnClaudeSessionOptions,
  type SpawnWorktreeSessionOptions,
} from "./swarm-board-store";
import { workbenchGuardEvaluator } from "./workbench-guard-evaluator";

// ---------------------------------------------------------------------------
// Context value type
// ---------------------------------------------------------------------------

export interface SwarmEngineContextValue {
  /**
   * The SwarmOrchestrator is the primary API. All mutations should go through
   * it so that the guard pipeline is enforced. Use the read-only accessors
   * (getAgent, getTask, getTopologyState) for UI reads instead of touching
   * raw subsystems directly.
   */
  engine: SwarmOrchestrator | null;
  /** @deprecated Use engine.getState().agents instead. Kept for migration. */
  agentRegistry: AgentRegistry | null;
  /** @deprecated Use engine.getState().tasks instead. Kept for migration. */
  taskGraph: TaskGraph | null;
  /** @deprecated Use engine.getState().topology instead. Kept for migration. */
  topology: TopologyManager | null;
  isReady: boolean;
  /** "engine" = orchestrator running, "manual" = fallback/disabled, "error" = init failed */
  mode: "engine" | "manual" | "error";
  /** Non-null when mode === "error". Describes what went wrong. */
  error: string | null;
  /**
   * Wraps a spawnSession call with guard pipeline evaluation and receipt node creation.
   * Falls back to calling spawnFn directly when engine is unavailable (manual/error mode).
   */
  spawnEngineSession: (
    spawnFn: (opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>,
    opts: SpawnSessionOptions,
  ) => Promise<Node<SwarmBoardNodeData>>;
  spawnEngineClaudeSession: (
    spawnFn: (opts: SpawnClaudeSessionOptions) => Promise<Node<SwarmBoardNodeData>>,
    opts: SpawnClaudeSessionOptions,
  ) => Promise<Node<SwarmBoardNodeData>>;
  spawnEngineWorktreeSession: (
    spawnFn: (opts: SpawnWorktreeSessionOptions) => Promise<Node<SwarmBoardNodeData>>,
    opts: SpawnWorktreeSessionOptions,
  ) => Promise<Node<SwarmBoardNodeData>>;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const SwarmEngineContext = createContext<SwarmEngineContextValue | null>(null);

// ---------------------------------------------------------------------------
// Default config for the workbench orchestrator
// ---------------------------------------------------------------------------

const WORKBENCH_CONFIG: SwarmOrchestratorConfig = {
  namespace: "workbench",
  topology: {
    type: "mesh",
    partitionStrategy: "round-robin",
    maxAgents: 50,
    replicationFactor: 1,
    failoverEnabled: true,
    autoRebalance: true,
  },
  consensus: {
    algorithm: "raft",
    threshold: 0.5,
    timeoutMs: 30_000,
    maxRounds: 5,
    requireQuorum: true,
  },
  pool: {
    minSize: 0,
    maxSize: 20,
    scaleUpThreshold: 0.8,
    scaleDownThreshold: 0.2,
    cooldownMs: 5000,
  },
  maxAgents: 50,
  maxTasks: 200,
  heartbeatIntervalMs: 5000,
  healthCheckIntervalMs: 10_000,
  taskTimeoutMs: 300_000,
  maxGuardActionHistory: 100,
  guardEvaluator: workbenchGuardEvaluator,
};

// ---------------------------------------------------------------------------
// Manual-mode passthrough: calls spawnFn directly (no guard evaluation)
// ---------------------------------------------------------------------------

const manualSpawnEngineSession: SwarmEngineContextValue["spawnEngineSession"] =
  (spawnFn, opts) => spawnFn(opts);
const manualSpawnEngineClaudeSession: SwarmEngineContextValue["spawnEngineClaudeSession"] =
  (spawnFn, opts) => spawnFn(opts);
const manualSpawnEngineWorktreeSession: SwarmEngineContextValue["spawnEngineWorktreeSession"] =
  (spawnFn, opts) => spawnFn(opts);

// ---------------------------------------------------------------------------
// Initial context value (manual/disabled state)
// ---------------------------------------------------------------------------

const MANUAL_CONTEXT: SwarmEngineContextValue = {
  engine: null,
  agentRegistry: null,
  taskGraph: null,
  topology: null,
  isReady: false,
  mode: "manual",
  error: null,
  spawnEngineSession: manualSpawnEngineSession,
  spawnEngineClaudeSession: manualSpawnEngineClaudeSession,
  spawnEngineWorktreeSession: manualSpawnEngineWorktreeSession,
};

interface PositionedSpawnOptions {
  position?: { x: number; y: number };
}

function buildSpawnGuardAction(
  kind: "terminal" | "claude" | "worktree",
  opts: SpawnSessionOptions | SpawnClaudeSessionOptions | SpawnWorktreeSessionOptions,
): GuardedAction {
  const repoRoot = useSwarmBoardStore.getState().repoRoot || "/tmp";

  if (kind === "terminal") {
    const terminalOpts = opts as SpawnSessionOptions;
    return {
      agentId: `pending_${Date.now()}`,
      taskId: null,
      actionType: "shell_command",
      target:
        terminalOpts.command ??
        (terminalOpts.launchClaude ? "claude" : terminalOpts.shell ?? "shell"),
      context: {
        operation: "agent_spawn",
        cwd: terminalOpts.cwd,
        launchClaude: terminalOpts.launchClaude ?? false,
        command: terminalOpts.command ?? null,
      },
      requestedAt: Date.now(),
    };
  }

  if (kind === "claude") {
    const claudeOpts = opts as SpawnClaudeSessionOptions;
    return {
      agentId: `pending_${Date.now()}`,
      taskId: null,
      actionType: "shell_command",
      target: "claude",
      context: {
        operation: "claude_spawn",
        cwd: claudeOpts.cwd ?? repoRoot,
        worktree: claudeOpts.worktree ?? false,
        branch: claudeOpts.branch ?? null,
        prompt: claudeOpts.prompt ?? null,
      },
      requestedAt: Date.now(),
    };
  }

  const worktreeOpts = opts as SpawnWorktreeSessionOptions;
  return {
    agentId: `pending_${Date.now()}`,
    taskId: null,
    actionType: "shell_command",
    target: `git worktree add ${worktreeOpts.branch ?? "(auto)"}`,
    context: {
      operation: "worktree_spawn",
      cwd: repoRoot,
      branch: worktreeOpts.branch ?? null,
      shell: worktreeOpts.shell ?? null,
    },
    requestedAt: Date.now(),
  };
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export interface SwarmEngineProviderProps {
  children: ReactNode;
  /** When false, no engine is created and all hooks return null (manual mode). */
  enabled?: boolean;
}

export function SwarmEngineProvider({
  children,
  enabled = true,
}: SwarmEngineProviderProps) {
  const [contextValue, setContextValue] =
    useState<SwarmEngineContextValue>(MANUAL_CONTEXT);

  const engineRef = useRef<SwarmOrchestrator | null>(null);

  useEffect(() => {
    if (!enabled) {
      setContextValue(MANUAL_CONTEXT);
      return;
    }

    let cancelled = false; // React strict mode double-mount guard (PITFALL 2)
    let orchestrator: SwarmOrchestrator | null = null;

    try {
      const events = new TypedEventEmitter<SwarmEngineEventMap>();
      const registry = new AgentRegistry(events);
      const taskGraph = new TaskGraph(events, registry, {
        maxTasks: WORKBENCH_CONFIG.maxTasks,
        defaultTimeoutMs: WORKBENCH_CONFIG.taskTimeoutMs,
      });
      const topologyMgr = new TopologyManager(events);

      orchestrator = new SwarmOrchestrator(
        events,
        registry,
        taskGraph,
        topologyMgr,
        WORKBENCH_CONFIG,
      );
      orchestrator.initialize(); // synchronous -- throws on failure (PITFALL 5)

      if (cancelled) {
        orchestrator.shutdown();
        return;
      }

      engineRef.current = orchestrator;
      setContextValue({
        engine: orchestrator,
        agentRegistry: registry,
        taskGraph,
        topology: topologyMgr,
        isReady: true,
        mode: "engine",
        error: null,
        spawnEngineSession: manualSpawnEngineSession, // overridden by valueWithSpawn
        spawnEngineClaudeSession: manualSpawnEngineClaudeSession,
        spawnEngineWorktreeSession: manualSpawnEngineWorktreeSession,
      });
    } catch (err) {
      if (cancelled) return;
      if (orchestrator) {
        try {
          orchestrator.shutdown();
        } catch (shutdownErr) {
          console.warn(
            "[SwarmEngineProvider] Failed to shut down partially initialized orchestrator:",
            shutdownErr instanceof Error ? shutdownErr.message : String(shutdownErr),
          );
        }
      }
      const message = err instanceof Error ? err.message : String(err);
      console.warn(
        "[SwarmEngineProvider] Engine init failed, falling back to manual mode:",
        message,
      );
      engineRef.current = null;
      setContextValue({
        engine: null,
        agentRegistry: null,
        taskGraph: null,
        topology: null,
        isReady: false,
        mode: "error",
        error: message,
        spawnEngineSession: manualSpawnEngineSession,
        spawnEngineClaudeSession: manualSpawnEngineClaudeSession,
        spawnEngineWorktreeSession: manualSpawnEngineWorktreeSession,
      });
    }

    return () => {
      cancelled = true;
      if (engineRef.current) {
        engineRef.current.shutdown(); // NOT dispose -- Pitfall 8
        engineRef.current = null;
      }
    };
  }, [enabled]);

  const finalizeAllowedSpawn = useCallback((
    nodeId: string,
    result: Awaited<ReturnType<SwarmOrchestrator["evaluateGuard"]>>,
  ): void => {
    const { actions } = useSwarmBoardStore.getState();
    actions.guardEvaluate(
      nodeId,
      result.verdict,
      result.guardResults.map((guardResult) => ({
        guard: guardResult.guardId,
        allowed: guardResult.verdict !== "deny",
        duration_ms: guardResult.duration_ms,
      })),
      result.receipt,
    );
  }, []);

  const runGuardedSpawn = useCallback(
    async function <Opts extends PositionedSpawnOptions>(
      kind: "terminal" | "claude" | "worktree",
      spawnFn: (opts: Opts) => Promise<Node<SwarmBoardNodeData>>,
      opts: Opts,
    ): Promise<Node<SwarmBoardNodeData>> {
      const engine = engineRef.current;

      if (!engine) {
        return spawnFn(opts);
      }

      let result: Awaited<ReturnType<SwarmOrchestrator["evaluateGuard"]>>;
      try {
        result = await engine.evaluateGuard(buildSpawnGuardAction(kind, opts));
      } catch (guardErr) {
        console.warn(
          "[SwarmEngineProvider] Guard evaluation failed, falling back to manual spawn:",
          guardErr instanceof Error ? guardErr.message : String(guardErr),
        );
        return spawnFn(opts);
      }

      if (!result.allowed) {
        const { actions } = useSwarmBoardStore.getState();
        const position = opts.position ?? {
          x: 100 + Math.random() * 400,
          y: 100 + Math.random() * 300,
        };
        return actions.addNode({
          nodeType: "receipt",
          title: "Guard: DENY",
          position: { x: position.x, y: position.y + 340 },
          data: {
            ...(Number.isFinite(Date.parse(result.receipt.timestamp))
              ? { createdAt: Date.parse(result.receipt.timestamp) }
              : {}),
            verdict: "deny",
            guardResults: result.guardResults.map((gr) => ({
              guard: gr.guardId,
              allowed: gr.verdict !== "deny",
              duration_ms: gr.duration_ms,
            })),
            signature: result.receipt.signature,
            publicKey: result.receipt.publicKey,
            receiptData: result.receipt,
            status: "completed",
            engineManaged: true,
          },
        });
      }

      const node = await spawnFn(opts);
      finalizeAllowedSpawn(node.id, result);
      return node;
    },
    [finalizeAllowedSpawn],
  );

  const spawnEngineSession = useCallback(
    async (
      spawnFn: (opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>,
      opts: SpawnSessionOptions,
    ): Promise<Node<SwarmBoardNodeData>> =>
      runGuardedSpawn("terminal", spawnFn, opts),
    [runGuardedSpawn],
  );

  const spawnEngineClaudeSession = useCallback(
    async (
      spawnFn: (opts: SpawnClaudeSessionOptions) => Promise<Node<SwarmBoardNodeData>>,
      opts: SpawnClaudeSessionOptions,
    ): Promise<Node<SwarmBoardNodeData>> =>
      runGuardedSpawn("claude", spawnFn, opts),
    [runGuardedSpawn],
  );

  const spawnEngineWorktreeSession = useCallback(
    async (
      spawnFn: (opts: SpawnWorktreeSessionOptions) => Promise<Node<SwarmBoardNodeData>>,
      opts: SpawnWorktreeSessionOptions,
    ): Promise<Node<SwarmBoardNodeData>> =>
      runGuardedSpawn("worktree", spawnFn, opts),
    [runGuardedSpawn],
  );

  const valueWithSpawn = useMemo(
    () => ({
      ...contextValue,
      spawnEngineSession,
      spawnEngineClaudeSession,
      spawnEngineWorktreeSession,
    }),
    [
      contextValue,
      spawnEngineSession,
      spawnEngineClaudeSession,
      spawnEngineWorktreeSession,
    ],
  );

  return (
    <SwarmEngineContext.Provider value={valueWithSpawn}>
      {children}
    </SwarmEngineContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Convenience hooks
// ---------------------------------------------------------------------------

/**
 * Returns the full SwarmEngine context value.
 * Throws if called outside of SwarmEngineProvider.
 */
export function useSwarmEngine(): SwarmEngineContextValue {
  const ctx = useContext(SwarmEngineContext);
  if (ctx === null) {
    throw new Error(
      "useSwarmEngine must be used within a <SwarmEngineProvider>. " +
        "Wrap your component tree with SwarmEngineProvider.",
    );
  }
  return ctx;
}

export function useOptionalSwarmEngine(): SwarmEngineContextValue | null {
  return useContext(SwarmEngineContext);
}

/**
 * Returns a read-only snapshot of the agent registry state via the orchestrator.
 * Returns null if the engine is not ready. Does NOT expose the mutable
 * AgentRegistry -- all mutations must go through SwarmOrchestrator methods
 * so that the guard pipeline is enforced.
 *
 * @deprecated Prefer `useSwarmEngine().engine?.getState().agents` for one-off reads.
 */
export function useAgentRegistry(): ReturnType<AgentRegistry["getState"]> | null {
  const { engine } = useSwarmEngine();
  return engine?.getState().agents ?? null;
}

/**
 * Returns a read-only snapshot of the task graph state via the orchestrator.
 * Returns null if the engine is not ready. Does NOT expose the mutable
 * TaskGraph -- all mutations must go through SwarmOrchestrator methods
 * so that the guard pipeline is enforced.
 *
 * @deprecated Prefer `useSwarmEngine().engine?.getState().tasks` for one-off reads.
 */
export function useTaskGraph(): ReturnType<TaskGraph["getState"]> | null {
  const { engine } = useSwarmEngine();
  return engine?.getState().tasks ?? null;
}

/**
 * Returns a read-only snapshot of the topology state via the orchestrator.
 * Returns null if the engine is not ready. Does NOT expose the mutable
 * TopologyManager -- all mutations must go through SwarmOrchestrator methods
 * so that the guard pipeline is enforced.
 *
 * @deprecated Prefer `useSwarmEngine().engine?.getState().topology` for one-off reads.
 */
export function useTopology(): SwarmEngineState["topology"] | null {
  const { engine } = useSwarmEngine();
  return engine?.getState().topology ?? null;
}
