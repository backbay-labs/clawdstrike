import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, cleanup, act } from "@testing-library/react";
import { TypedEventEmitter } from "@clawdstrike/swarm-engine";
import type {
  SwarmEngineEventMap,
  SwarmEngineState,
} from "@clawdstrike/swarm-engine";
import { useEngineBoardBridge } from "../use-engine-board-bridge";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";

function resetStore() {
  const { actions } = useSwarmBoardStore.getState();
  actions.clearBoard();
}

function makeEngineState(): SwarmEngineState {
  const now = Date.now();
  return {
    id: "swe_test",
    namespace: "workbench",
    version: "0.1.0",
    status: "running",
    topologyConfig: {
      type: "mesh",
      maxAgents: 5,
      replicationFactor: 1,
      partitionStrategy: "round-robin",
      failoverEnabled: true,
      autoRebalance: true,
    },
    topology: {
      type: "mesh",
      nodes: [
        {
          id: "agt_pool_1",
          agentId: "agt_pool_1",
          role: "worker",
          status: "active",
          connections: [],
          metadata: {},
          positionX: 240,
          positionY: 120,
          hierarchyDepth: null,
        },
      ],
      edges: [],
      leaderId: null,
      partitions: [],
      snapshotAt: now,
    },
    consensusConfig: {
      algorithm: "raft",
      threshold: 0.5,
      timeoutMs: 30_000,
      maxRounds: 3,
      requireQuorum: true,
    },
    agents: {
      agt_pool_1: {
        id: "agt_pool_1",
        name: "Pool Agent agt_pool_1",
        role: "worker",
        status: "idle",
        capabilities: {
          codeGeneration: false,
          codeReview: false,
          testing: false,
          documentation: false,
          research: false,
          analysis: false,
          coordination: false,
          securityAnalysis: false,
          languages: [],
          frameworks: [],
          domains: [],
          tools: [],
          maxConcurrentTasks: 1,
          maxMemoryUsageBytes: 0,
          maxExecutionTimeMs: 0,
        },
        metrics: {
          tasksCompleted: 0,
          tasksFailed: 0,
          averageExecutionTimeMs: 0,
          successRate: 0,
          cpuUsage: 0,
          memoryUsageBytes: 0,
          messagesProcessed: 0,
          lastActivityAt: now,
          responseTimeMs: 0,
          health: 1,
        },
        quality: {
          reliability: 0.5,
          speed: 0.5,
          quality: 0.5,
        },
        currentTaskId: null,
        workload: 0,
        health: 1,
        lastHeartbeatAt: now,
        topologyRole: null,
        connections: [],
        worktreePath: null,
        branch: null,
        risk: "low",
        policyMode: null,
        agentModel: "pooled",
        receiptCount: 0,
        blockedActionCount: 0,
        changedFilesCount: 0,
        filesTouched: [],
        toolBoundaryEvents: 0,
        confidence: null,
        guardResults: [],
        receipt: null,
        sentinelId: null,
        createdAt: now,
        updatedAt: now,
        exitCode: null,
      },
    },
    tasks: {},
    activeProposals: {},
    metrics: {
      uptimeMs: 100,
      activeAgents: 1,
      totalTasks: 0,
      completedTasks: 0,
      failedTasks: 0,
      avgTaskDurationMs: 0,
      messagesPerSecond: 0,
      consensusSuccessRate: 0,
      coordinationLatencyMs: 0,
      memoryUsageBytes: 0,
      guardEvaluationsTotal: 0,
      guardDenialRate: 0,
    },
    recentGuardActions: [],
    maxGuardActionHistory: 100,
    createdAt: now,
    startedAt: now,
    updatedAt: now,
  };
}

describe("useEngineBoardBridge", () => {
  beforeEach(() => {
    resetStore();
  });

  afterEach(() => {
    cleanup();
  });

  it("seeds engine-managed nodes from the initial orchestrator snapshot", () => {
    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engine = {
      getState: () => makeEngineState(),
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    const agentNode = useSwarmBoardStore
      .getState()
      .nodes.find((node) => node.data.agentId === "agt_pool_1");

    expect(agentNode).toBeDefined();
    expect(agentNode?.data.engineManaged).toBe(true);
    expect(agentNode?.position).toEqual({ x: 240, y: 120 });

    unmount();
  });

  it("uses engine IDs for runtime-spawned agent nodes", () => {
    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engine = {
      getState: () => makeEngineState(),
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    try {
      act(() => {
        events.emit("agent.spawned", {
          agent: {
            id: "agt_runtime_1",
            name: "Runtime Agent",
            role: "worker",
            status: "idle",
          },
        } as any);
      });

      const runtimeNode = useSwarmBoardStore
        .getState()
        .nodes.find((node) => node.data.agentId === "agt_runtime_1");

      expect(runtimeNode?.id).toBe("agt_runtime_1");
      expect(runtimeNode?.data.engineManaged).toBe(true);
    } finally {
      unmount();
    }
  });

  it("replaces topology edges from the latest topology event and preserves non-topology edges", () => {
    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engineState = makeEngineState();
    const baseAgent = engineState.agents.agt_pool_1;
    const originalWidth = window.innerWidth;
    const originalHeight = window.innerHeight;
    const flowCanvas = document.createElement("div");

    flowCanvas.className = "react-flow";
    Object.defineProperty(flowCanvas, "getBoundingClientRect", {
      configurable: true,
      value: () => ({
        x: 0,
        y: 0,
        top: 0,
        left: 0,
        right: 180,
        bottom: 140,
        width: 180,
        height: 140,
        toJSON: () => ({}),
      }),
    });
    document.body.appendChild(flowCanvas);

    engineState.topology.nodes.push({
      ...engineState.topology.nodes[0],
      id: "agt_pool_2",
      agentId: "agt_pool_2",
      positionX: 480,
      positionY: 120,
    });
    engineState.topology.edges = [{
      from: "agt_pool_1",
      to: "agt_pool_2",
      weight: 1,
      bidirectional: false,
      latencyMs: null,
      edgeType: "topology",
    }];
    engineState.agents.agt_pool_2 = {
      ...baseAgent,
      id: "agt_pool_2",
      name: "Pool Agent agt_pool_2",
      metrics: { ...baseAgent.metrics },
      filesTouched: [...baseAgent.filesTouched],
    };
    engineState.metrics.activeAgents = 2;

    const engine = {
      getState: () => engineState,
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    act(() => {
      useSwarmBoardStore.getState().actions.addEdge({
        id: "edge-spawn-keep",
        source: "agt_pool_1",
        target: "agt_pool_2",
        type: "spawned",
      });
    });

    const states: Array<{ edgeIds: string[]; positions: Array<{ id: string; x: number; y: number }> }> = [];
    let unsubscribe = () => {};

    try {
      Object.defineProperty(window, "innerWidth", {
        configurable: true,
        value: 320,
      });
      Object.defineProperty(window, "innerHeight", {
        configurable: true,
        value: 240,
      });

      unsubscribe = useSwarmBoardStore.subscribe((state) => {
        states.push({
          edgeIds: state.edges.map((edge) => edge.id),
          positions: state.nodes.map((node) => ({
            id: node.id,
            x: node.position.x,
            y: node.position.y,
          })),
        });
      });

      act(() => {
        events.emit("topology.updated", {
          newTopology: {
            type: "mesh",
            edges: [{
              from: "agt_pool_2",
              to: "agt_pool_1",
              weight: 1,
              bidirectional: false,
              latencyMs: null,
              edgeType: "topology",
            }],
          },
        } as any);
      });
    } finally {
      unsubscribe();
      Object.defineProperty(window, "innerWidth", {
        configurable: true,
        value: originalWidth,
      });
      Object.defineProperty(window, "innerHeight", {
        configurable: true,
        value: originalHeight,
      });
      flowCanvas.remove();
    }

    const state = useSwarmBoardStore.getState();
    const topologyEdges = state.edges.filter((edge) => edge.type === "topology");

    expect(states).toHaveLength(1);
    expect(topologyEdges).toEqual([
      {
        id: "edge-topo-agt_pool_2-agt_pool_1",
        source: "agt_pool_2",
        target: "agt_pool_1",
        type: "topology",
      },
    ]);
    expect(state.edges).toContainEqual({
      id: "edge-spawn-keep",
      source: "agt_pool_1",
      target: "agt_pool_2",
      type: "spawned",
    });
    expect(
      Math.max(...state.nodes.map((node) => node.position.x)),
    ).toBeLessThanOrEqual(180);
    expect(
      Math.max(...state.nodes.map((node) => node.position.y)),
    ).toBeLessThanOrEqual(140);

    unmount();
  });

  it("clears pending guard-glow state on termination before a later glow reuses the baseline", () => {
    vi.useFakeTimers();

    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engine = {
      getState: () => makeEngineState(),
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    try {
      act(() => {
        events.emit("guard.evaluated", {
          action: { agentId: "agt_pool_1" },
          result: {
            verdict: "allow",
            guardResults: [],
            receipt: {
              signature: "abcd".repeat(32),
              publicKey: "1234".repeat(16),
            },
          },
        } as any);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.id === "agt_pool_1")?.data.status,
      ).toBe("evaluating");

      act(() => {
        events.emit("agent.terminated", {
          agentId: "agt_pool_1",
          exitCode: 0,
        } as any);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.id === "agt_pool_1")?.data.status,
      ).toBe("completed");

      act(() => {
        events.emit("guard.evaluated", {
          action: { agentId: "agt_pool_1" },
          result: {
            verdict: "allow",
            guardResults: [],
            receipt: {
              signature: "dcba".repeat(32),
              publicKey: "5678".repeat(16),
            },
          },
        } as any);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.id === "agt_pool_1")?.data.status,
      ).toBe("evaluating");

      act(() => {
        vi.advanceTimersByTime(2000);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.id === "agt_pool_1")?.data.status,
      ).toBe("completed");
    } finally {
      unmount();
      vi.useRealTimers();
    }
  });

  it("refreshes the restore status when guard evaluation re-triggers after a status change", () => {
    vi.useFakeTimers();

    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engine = {
      getState: () => makeEngineState(),
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    try {
      act(() => {
        events.emit("agent.status_changed", {
          agentId: "agt_pool_1",
          newStatus: "running",
        } as any);
      });

      act(() => {
        events.emit("guard.evaluated", {
          action: { agentId: "agt_pool_1" },
          result: {
            verdict: "allow",
            guardResults: [],
            receipt: {
              signature: "beef".repeat(32),
              publicKey: "1234".repeat(16),
            },
          },
        } as any);
      });

      act(() => {
        events.emit("agent.status_changed", {
          agentId: "agt_pool_1",
          newStatus: "idle",
        } as any);
      });

      act(() => {
        events.emit("guard.evaluated", {
          action: { agentId: "agt_pool_1" },
          result: {
            verdict: "allow",
            guardResults: [],
            receipt: {
              signature: "cafe".repeat(32),
              publicKey: "5678".repeat(16),
            },
          },
        } as any);
      });

      act(() => {
        vi.advanceTimersByTime(2000);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.id === "agt_pool_1")?.data.status,
      ).toBe("idle");
    } finally {
      unmount();
      vi.useRealTimers();
    }
  });

  it("updates the pending guard-glow restore status when agent lifecycle events land mid-glow", () => {
    vi.useFakeTimers();

    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engine = {
      getState: () => makeEngineState(),
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    try {
      act(() => {
        events.emit("guard.evaluated", {
          action: { agentId: "agt_pool_1" },
          result: {
            verdict: "allow",
            guardResults: [],
            receipt: {
              signature: "fade".repeat(32),
              publicKey: "1234".repeat(16),
            },
          },
        } as any);
      });

      act(() => {
        events.emit("agent.status_changed", {
          agentId: "agt_pool_1",
          newStatus: "running",
        } as any);
      });

      act(() => {
        events.emit("agent.status_changed", {
          agentId: "agt_pool_1",
          newStatus: "evaluating",
        } as any);
      });

      act(() => {
        vi.advanceTimersByTime(2000);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.id === "agt_pool_1")?.data.status,
      ).toBe("running");
    } finally {
      unmount();
      vi.useRealTimers();
    }
  });

  it("restores the pre-glow status when the bridge cleans up mid-evaluation", () => {
    vi.useFakeTimers();

    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engine = {
      getState: () => makeEngineState(),
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    try {
      act(() => {
        events.emit("agent.status_changed", {
          agentId: "agt_pool_1",
          newStatus: "running",
        } as any);
        events.emit("guard.evaluated", {
          action: { agentId: "agt_pool_1" },
          result: {
            verdict: "allow",
            guardResults: [],
            receipt: {
              signature: "deed".repeat(32),
              publicKey: "1234".repeat(16),
            },
          },
        } as any);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.id === "agt_pool_1")?.data.status,
      ).toBe("evaluating");

      unmount();

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.id === "agt_pool_1")?.data.status,
      ).toBe("running");
    } finally {
      vi.useRealTimers();
    }
  });

  it("stacks runtime-created tasks under the same agent instead of overlapping them", () => {
    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engine = {
      getState: () => makeEngineState(),
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    try {
      act(() => {
        events.emit("task.created", {
          task: {
            id: "tsk_1",
            name: "Queue scan",
            type: "analysis",
            status: "created",
            assignedTo: "agt_pool_1",
          },
        } as any);

        events.emit("task.created", {
          task: {
            id: "tsk_2",
            name: "Trace graph",
            type: "analysis",
            status: "created",
            assignedTo: "agt_pool_1",
          },
        } as any);
      });

      const taskPositions = useSwarmBoardStore.getState().nodes
        .filter((node) => node.data.taskId === "tsk_1" || node.data.taskId === "tsk_2")
        .sort((left, right) => left.id.localeCompare(right.id))
        .map((node) => ({
          id: node.id,
          position: node.position,
        }));

      expect(taskPositions).toEqual([
        { id: "tsk_1", position: { x: 240, y: 320 } },
        { id: "tsk_2", position: { x: 240, y: 344 } },
      ]);
    } finally {
      unmount();
    }
  });

  it("preserves task prompts from live task.created events", () => {
    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engine = {
      getState: () => makeEngineState(),
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    try {
      act(() => {
        events.emit("task.created", {
          task: {
            id: "tsk_prompt",
            name: "Investigate auth",
            type: "analysis",
            status: "created",
            assignedTo: "agt_pool_1",
            taskPrompt: "Inspect the last failing auth trace",
          },
        } as any);

        events.emit("task.created", {
          task: {
            id: "tsk_desc",
            name: "Fallback task",
            type: "analysis",
            status: "created",
            assignedTo: "agt_pool_1",
            description: "Use description when no task prompt exists",
          },
        } as any);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.data.taskId === "tsk_prompt")
          ?.data.taskPrompt,
      ).toBe("Inspect the last failing auth trace");

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.data.taskId === "tsk_desc")
          ?.data.taskPrompt,
      ).toBe("Use description when no task prompt exists");
    } finally {
      unmount();
    }
  });

  it("maps task statuses safely and binds tasks when assignment happens after creation", () => {
    const events = new TypedEventEmitter<SwarmEngineEventMap>();
    const engine = {
      getState: () => makeEngineState(),
      getEvents: () => events,
    };

    const { unmount } = renderHook(() =>
      useEngineBoardBridge(engine as any),
    );

    try {
      act(() => {
        events.emit("task.created", {
          task: {
            id: "tsk_1",
            name: "Queue scan",
            type: "analysis",
            status: "created",
            assignedTo: null,
          },
        } as any);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.data.taskId === "tsk_1")?.data.status,
      ).toBe("idle");

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.data.taskId === "tsk_1")?.id,
      ).toBe("tsk_1");

      act(() => {
        events.emit("task.assigned", {
          taskId: "tsk_1",
          agentId: "agt_pool_1",
        } as any);
      });

      const assignedTaskNode = useSwarmBoardStore
        .getState()
        .nodes.find((node) => node.data.taskId === "tsk_1");

      expect(assignedTaskNode?.data.agentId).toBe("agt_pool_1");
      expect(assignedTaskNode?.position).toEqual({ x: 240, y: 320 });
      expect(useSwarmBoardStore.getState().edges).toContainEqual({
        id: "edge-spawn-tsk_1",
        source: "agt_pool_1",
        target: "tsk_1",
        type: "spawned",
      });

      act(() => {
        events.emit("task.status_changed", {
          taskId: "tsk_1",
          newStatus: "paused",
        } as any);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.data.taskId === "tsk_1")?.data.status,
      ).toBe("blocked");

      act(() => {
        events.emit("task.status_changed", {
          taskId: "tsk_1",
          newStatus: "cancelled",
        } as any);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.data.taskId === "tsk_1")?.data.status,
      ).toBe("completed");

      act(() => {
        events.emit("agent.status_changed", {
          agentId: "agt_pool_1",
          newStatus: "draining",
        } as any);
      });

      expect(
        useSwarmBoardStore.getState().nodes.find((node) => node.id === "agt_pool_1")?.data.status,
      ).toBe("blocked");
    } finally {
      unmount();
    }
  });
});
