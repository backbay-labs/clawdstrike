import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, act, cleanup } from "@testing-library/react";
import { useEngineBoardBridge } from "../use-engine-board-bridge";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";

const MAX_AGENT_CONVERSATION_TURNS = 200;

vi.mock("@/lib/workbench/terminal-service", () => ({
  terminalService: {
    getCwd: vi.fn().mockResolvedValue("/mock/cwd"),
    create: vi.fn().mockResolvedValue({ id: "mock-session", branch: "main" }),
    write: vi.fn().mockResolvedValue(undefined),
    kill: vi.fn().mockResolvedValue(undefined),
    onExit: vi.fn().mockResolvedValue(() => {}),
  },
  worktreeService: {
    create: vi.fn().mockResolvedValue({ path: "/mock/worktree", branch: "test-branch" }),
    remove: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("@/features/swarm/layout/topology-layout", () => ({
  computeLayout: vi.fn().mockReturnValue({ positions: new Map() }),
  computeTaskDagLayout: vi.fn().mockReturnValue({ positions: new Map() }),
}));

type EventHandler = (data: any) => void;

function createMockEvents() {
  const listeners = new Map<string, Set<EventHandler>>();

  return {
    on(event: string, handler: EventHandler) {
      if (!listeners.has(event)) {
        listeners.set(event, new Set());
      }
      listeners.get(event)!.add(handler);
      return () => {
        listeners.get(event)?.delete(handler);
      };
    },
    emit(event: string, data: unknown) {
      for (const handler of listeners.get(event) ?? []) {
        handler(data);
      }
    },
  };
}

function resetStore(): void {
  useSwarmBoardStore.getState().actions.clearBoard();
}

function makeTask(overrides: Record<string, unknown> = {}) {
  return {
    id: "tsk_replay",
    swarmEngineId: "swe_test",
    type: "coding",
    name: "Review auth middleware",
    description: "Inspect expired-token handling",
    priority: "normal",
    status: "created",
    sequence: 1,
    assignedTo: null,
    dependencies: [],
    input: {},
    output: null,
    timeoutMs: 300000,
    retries: 0,
    maxRetries: 3,
    taskPrompt: null,
    previewLines: [],
    huntId: null,
    artifactIds: [],
    receipt: null,
    metadata: {},
    createdAt: Date.parse("2026-03-25T14:02:00Z"),
    startedAt: null,
    completedAt: null,
    updatedAt: Date.parse("2026-03-25T14:02:00Z"),
    ...overrides,
  };
}

describe("useEngineBoardBridge conversation replay", () => {
  beforeEach(() => {
    resetStore();
  });

  afterEach(() => {
    cleanup();
  });

  it("hydrates existing conversation history when an agent node is spawned", () => {
    const events = createMockEvents();
    const existingHistory = [
      {
        id: "turn-1",
        kind: "prompt",
        role: "user",
        content: "Audit the auth middleware.",
        createdAt: Date.parse("2026-03-25T14:01:00Z"),
      },
    ];
    const engine = {
      getEvents: () => events,
      getConversationHistory: vi.fn((agentId: string) =>
        agentId === "agt_replay" ? existingHistory : [],
      ),
      getState: vi.fn(() => ({ tasks: {} })),
    };

    renderHook(() => useEngineBoardBridge(engine as any));

    act(() => {
      events.emit("agent.spawned", {
        agent: {
          id: "agt_replay",
          name: "Replay Agent",
          role: "worker",
          status: "running",
        },
      });
    });

    const node = useSwarmBoardStore
      .getState()
      .nodes.find((candidate) => candidate.data.agentId === "agt_replay");

    expect(node).toBeDefined();
    expect(node?.data.status).toBe("running");
    expect(node?.data.conversationHistory).toEqual(existingHistory);
  });

  it("appends agent.message turns to the owning node history", () => {
    const events = createMockEvents();
    const engine = {
      getEvents: () => events,
      getConversationHistory: vi.fn(() => []),
      getState: vi.fn(() => ({ tasks: {} })),
    };

    renderHook(() => useEngineBoardBridge(engine as any));

    act(() => {
      events.emit("agent.spawned", {
        agent: {
          id: "agt_replay",
          name: "Replay Agent",
          role: "worker",
          status: "idle",
        },
      });
    });

    act(() => {
      events.emit("agent.message", {
        agentId: "agt_replay",
        turn: {
          id: "turn-2",
          kind: "tool_call",
          role: "assistant",
          toolName: "read_file",
          content: "{\"path\":\"src/middleware/auth.rs\"}",
          createdAt: Date.parse("2026-03-25T14:01:05Z"),
        },
      });
    });

    act(() => {
      events.emit("agent.message", {
        agentId: "agt_replay",
        turn: {
          id: "turn-3",
          kind: "response",
          role: "assistant",
          content: "Found an expired-token branch without test coverage.",
          createdAt: Date.parse("2026-03-25T14:01:08Z"),
        },
      });
    });

    const node = useSwarmBoardStore
      .getState()
      .nodes.find((candidate) => candidate.data.agentId === "agt_replay");

    expect(node?.data.conversationHistory).toHaveLength(2);
    expect(node?.data.conversationHistory?.[0]).toMatchObject({
      kind: "tool_call",
      toolName: "read_file",
    });
    expect(node?.data.conversationHistory?.[1]).toMatchObject({
      kind: "response",
      content: "Found an expired-token branch without test coverage.",
    });
  });

  it("truncates agent.message history to the configured maximum length", () => {
    const events = createMockEvents();
    const engine = {
      getEvents: () => events,
      getConversationHistory: vi.fn(() => []),
      getState: vi.fn(() => ({ tasks: {} })),
    };

    renderHook(() => useEngineBoardBridge(engine as any));

    act(() => {
      events.emit("agent.spawned", {
        agent: {
          id: "agt_replay",
          name: "Replay Agent",
          role: "worker",
          status: "idle",
        },
      });
    });

    for (
      let index = 0;
      index < MAX_AGENT_CONVERSATION_TURNS + 3;
      index += 1
    ) {
      act(() => {
        events.emit("agent.message", {
          agentId: "agt_replay",
          turn: {
            id: `turn-${index}`,
            kind: "response",
            role: "assistant",
            content: `turn ${index}`,
            createdAt: index,
          },
        });
      });
    }

    const node = useSwarmBoardStore
      .getState()
      .nodes.find((candidate) => candidate.data.agentId === "agt_replay");
    const history = node?.data.conversationHistory;

    expect(history).toHaveLength(MAX_AGENT_CONVERSATION_TURNS);
    expect(history?.[0]?.id).toBe("turn-3");
    expect(history?.[history.length - 1]?.id).toBe(
      `turn-${MAX_AGENT_CONVERSATION_TURNS + 2}`,
    );
  });

  it("renders dependency edges and blocked task status from task events", () => {
    const events = createMockEvents();
    const dependencyTask = makeTask({
      id: "tsk_dependency",
      name: "Collect evidence",
      status: "running",
    });
    const blockedTask = makeTask({
      id: "tsk_blocked",
      name: "Write patch",
      dependencies: ["tsk_dependency"],
    });
    const taskGraph = {
      getTopologicalOrder: vi.fn(() => []),
      getDependencyEdges: vi.fn(() => []),
      getTask: vi.fn((taskId: string) =>
        taskId === "tsk_dependency" ? dependencyTask : taskId === "tsk_blocked" ? blockedTask : undefined,
      ),
    };
    const engine = {
      getEvents: () => events,
      getConversationHistory: vi.fn(() => []),
      getState: vi.fn(() => ({ tasks: {} })),
    };

    renderHook(() => useEngineBoardBridge(engine as any, taskGraph as any));

    act(() => {
      events.emit("task.created", { task: dependencyTask });
      events.emit("task.created", { task: blockedTask });
    });

    const state = useSwarmBoardStore.getState();
    const blockedNode = state.nodes.find((node) => node.data.taskId === "tsk_blocked");
    const dependencyNode = state.nodes.find((node) => node.data.taskId === "tsk_dependency");
    const dependencyEdge = state.edges.find((edge) => edge.type === "dependency");

    expect(blockedNode?.data.status).toBe("blocked");
    expect(blockedNode?.data.blockingTaskIds).toEqual(["tsk_dependency"]);
    expect(dependencyNode).toBeDefined();
    expect(dependencyEdge).toBeDefined();
    expect(dependencyEdge?.source).toBe(dependencyNode?.id);
    expect(dependencyEdge?.target).toBe(blockedNode?.id);
  });

  it("adds spawned edges on task.assigned and updates status from task.status_changed", () => {
    const events = createMockEvents();
    const queuedTask = makeTask({
      id: "tsk_assigned",
      status: "queued",
      assignedTo: "agt_replay",
      dependencies: [],
    });
    const taskGraph = {
      getTopologicalOrder: vi.fn(() => []),
      getDependencyEdges: vi.fn(() => []),
      getTask: vi.fn((taskId: string) =>
        taskId === "tsk_assigned" ? queuedTask : undefined,
      ),
    };
    const engine = {
      getEvents: () => events,
      getConversationHistory: vi.fn(() => []),
      getState: vi.fn(() => ({ tasks: {} })),
    };

    renderHook(() => useEngineBoardBridge(engine as any, taskGraph as any));

    act(() => {
      events.emit("agent.spawned", {
        agent: {
          id: "agt_replay",
          name: "Replay Agent",
          role: "worker",
          status: "idle",
        },
      });
      events.emit("task.created", {
        task: {
          ...queuedTask,
          assignedTo: null,
        },
      });
      events.emit("task.assigned", {
        taskId: "tsk_assigned",
        agentId: "agt_replay",
      });
      events.emit("task.status_changed", {
        taskId: "tsk_assigned",
        newStatus: "queued",
      });
    });

    const state = useSwarmBoardStore.getState();
    const taskNode = state.nodes.find((node) => node.data.taskId === "tsk_assigned");
    const spawnedEdge = state.edges.find((edge) => edge.type === "spawned");

    expect(taskNode?.data.agentId).toBe("agt_replay");
    expect(taskNode?.data.status).toBe("idle");
    expect(spawnedEdge).toBeDefined();
    expect(spawnedEdge?.target).toBe(taskNode?.id);
  });
});
