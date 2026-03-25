/**
 * useEngineBoardBridge -- React hook that bridges SwarmOrchestrator's
 * TypedEventEmitter events to the Zustand board store.
 *
 * Maps engine lifecycle, task, topology, and guard events to board node
 * creation, status updates, layout repositioning, and receipt nodes.
 *
 * Follows the same pattern as useCoordinatorBoardBridge:
 * - Subscribe in useEffect
 * - Dedup by agentId/taskId before creating nodes (INTG-08)
 * - Call useSwarmBoardStore.getState().actions.* (not hook selectors)
 * - Clean up on unmount
 *
 * Additionally implements the evaluating glow pattern from
 * usePolicyEvalBoardBridge for guard.evaluated events (INTG-09).
 */

import { useEffect, useRef } from "react";
import type {
  AgentConversationTurn,
  SwarmOrchestrator,
  Task,
  TaskGraph,
} from "@clawdstrike/swarm-engine";
import { useSwarmBoardStore } from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardNodeData, SessionStatus } from "@/features/swarm/swarm-board-types";
import type { Node } from "@xyflow/react";
import {
  computeLayout,
  computeTaskDagLayout,
} from "@/features/swarm/layout/topology-layout";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Duration in ms that the evaluating glow remains visible. */
const EVAL_GLOW_DURATION_MS = 2000;
const MAX_AGENT_CONVERSATION_TURNS = 200;

// ---------------------------------------------------------------------------
// Position helper
// ---------------------------------------------------------------------------

/**
 * Calculate a position for a new auto-created node, placing it to the right
 * of the rightmost existing node with slight vertical jitter.
 * Copied from use-coordinator-board-bridge.ts lines 36-44.
 */
function nextNodePosition(
  nodes: Array<{ position: { x: number; y: number } }>,
): { x: number; y: number } {
  if (nodes.length === 0) return { x: 200, y: 200 };
  const maxX = Math.max(...nodes.map((n) => n.position.x));
  const avgY =
    nodes.reduce((sum, n) => sum + n.position.y, 0) / nodes.length;
  return { x: maxX + 320, y: avgY + (Math.random() - 0.5) * 100 };
}

// ---------------------------------------------------------------------------
// Status mapping: engine AgentSessionStatus -> board SessionStatus
// ---------------------------------------------------------------------------

function mapEngineStatus(engineStatus: string): SessionStatus {
  switch (engineStatus) {
    case "running":
      return "running";
    case "idle":
      return "idle";
    case "busy":
      return "running";
    case "terminated":
      return "completed";
    case "offline":
      return "failed";
    case "completed":
      return "completed";
    case "failed":
      return "failed";
    case "blocked":
      return "blocked";
    case "evaluating":
      return "evaluating";
    default:
      return "running";
  }
}

function appendConversationTurn(
  history: AgentConversationTurn[] | undefined,
  turn: AgentConversationTurn,
): AgentConversationTurn[] {
  const nextHistory = [...(history ?? []), turn];
  if (nextHistory.length <= MAX_AGENT_CONVERSATION_TURNS) {
    return nextHistory;
  }
  return nextHistory.slice(-MAX_AGENT_CONVERSATION_TURNS);
}

function dependencyEdgeId(sourceNodeId: string, targetNodeId: string): string {
  return `edge-dependency-${sourceNodeId}-${targetNodeId}`;
}

function spawnedEdgeId(sourceNodeId: string, targetNodeId: string): string {
  return `edge-spawn-${sourceNodeId}-${targetNodeId}`;
}

function resolveBlockingTaskIds(
  dependencyTaskIds: string[],
  nodes: Array<Node<SwarmBoardNodeData>>,
): string[] {
  return dependencyTaskIds.filter((dependencyTaskId) => {
    const dependencyNode = nodes.find(
      (node) => node.data.taskId === dependencyTaskId,
    );
    return dependencyNode?.data.status !== "completed";
  });
}

function mapTaskStatus(task: Task, nodes: Array<Node<SwarmBoardNodeData>>): SessionStatus {
  const blockingTaskIds = resolveBlockingTaskIds(task.dependencies, nodes);

  switch (task.status) {
    case "running":
      return "running";
    case "paused":
      return "blocked";
    case "completed":
      return "completed";
    case "failed":
    case "cancelled":
    case "timeout":
      return "failed";
    case "created":
      return blockingTaskIds.length > 0 ? "blocked" : "idle";
    case "queued":
    case "assigned":
    default:
      return "idle";
  }
}

function buildTaskNodePatch(
  task: Task,
  nodes: Array<Node<SwarmBoardNodeData>>,
): Partial<SwarmBoardNodeData> {
  const dependencyTaskIds = [...task.dependencies];
  return {
    title: task.name ?? task.type ?? "Task",
    status: mapTaskStatus(task, nodes),
    taskId: task.id,
    agentId: task.assignedTo ?? undefined,
    engineManaged: true,
    createdAt: task.createdAt,
    taskPrompt: task.description ?? task.taskPrompt ?? task.type,
    previewLines: task.previewLines,
    dependencyTaskIds,
    blockingTaskIds: resolveBlockingTaskIds(dependencyTaskIds, nodes),
  };
}

type TaskGraphReader = Pick<TaskGraph, "getTopologicalOrder" | "getDependencyEdges" | "getTask">;

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Bridge SwarmOrchestrator engine events to the Zustand board store.
 *
 * @param engine - The SwarmOrchestrator instance, or null if unavailable.
 */
export function useEngineBoardBridge(
  engine: SwarmOrchestrator | null,
  taskGraph?: TaskGraphReader | null,
): void {
  // Glow tracking refs (matching usePolicyEvalBoardBridge exactly)
  const timeoutsRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const restoreStatusRef = useRef<Map<string, SessionStatus>>(new Map());

  useEffect(() => {
    if (!engine) return;
    const orchestrator = engine;

    const store = useSwarmBoardStore.getState;
    const unsubs: Array<() => void> = [];
    const timeouts = timeoutsRef.current;
    const restoreStatuses = restoreStatusRef.current;

    // Access the shared event emitter via the orchestrator's public accessor.
    const events = orchestrator.getEvents();

    function syncTaskDagLayout(): void {
      const { nodes, edges, actions } = store();
      const result = computeTaskDagLayout(
        nodes as Node<SwarmBoardNodeData>[],
        edges,
        { width: 1200, height: 800 },
      );
      if (result.positions.size > 0) {
        actions.topologyLayout("hierarchical", result.positions);
      }
    }

    function upsertTaskNode(task: Task): Node<SwarmBoardNodeData> {
      const { nodes, actions } = store();
      const existingTaskNode = nodes.find(
        (node: Node<SwarmBoardNodeData>) => node.data.taskId === task.id,
      );
      const patch = buildTaskNodePatch(task, nodes);

      if (existingTaskNode) {
        actions.updateNode(existingTaskNode.id, patch);
        return {
          ...existingTaskNode,
          data: {
            ...existingTaskNode.data,
            ...patch,
          },
        };
      }

      const parentNode = nodes.find(
        (node: Node<SwarmBoardNodeData>) => node.data.agentId === task.assignedTo,
      );
      const position = parentNode
        ? { x: parentNode.position.x, y: parentNode.position.y + 200 }
        : nextNodePosition(nodes);

      return actions.addNode({
        nodeType: "terminalTask",
        title: (patch.title as string) ?? task.name ?? task.type ?? "Task",
        position,
        data: {
          nodeType: "terminalTask",
          ...patch,
        },
      });
    }

    function addDependencyEdge(sourceTaskId: string, targetTaskId: string): void {
      const { nodes, actions } = store();
      const sourceNode = nodes.find(
        (node: Node<SwarmBoardNodeData>) => node.data.taskId === sourceTaskId,
      );
      const targetNode = nodes.find(
        (node: Node<SwarmBoardNodeData>) => node.data.taskId === targetTaskId,
      );

      if (!sourceNode || !targetNode) {
        return;
      }

      actions.addEdge({
        id: dependencyEdgeId(sourceNode.id, targetNode.id),
        source: sourceNode.id,
        target: targetNode.id,
        type: "dependency",
        label: "depends on",
      });
    }

    function addSpawnedEdge(agentId: string | null | undefined, taskNodeId: string): void {
      if (!agentId) {
        return;
      }

      const { nodes, actions } = store();
      const parentNode = nodes.find(
        (node: Node<SwarmBoardNodeData>) => node.data.agentId === agentId,
      );
      if (!parentNode) {
        return;
      }

      actions.addEdge({
        id: spawnedEdgeId(parentNode.id, taskNodeId),
        source: parentNode.id,
        target: taskNodeId,
        type: "spawned",
      });
    }

    function bootstrapTaskDag(): void {
      const orderedTasks =
        taskGraph?.getTopologicalOrder?.() ??
        Object.values(orchestrator.getState().tasks).sort((a, b) => a.sequence - b.sequence);

      if (orderedTasks.length === 0) {
        return;
      }

      for (const task of orderedTasks) {
        const taskNode = upsertTaskNode(task);
        addSpawnedEdge(task.assignedTo, taskNode.id);
      }

      const dependencyEdges =
        taskGraph?.getDependencyEdges?.() ??
        orderedTasks.flatMap((task) =>
          task.dependencies.map((dependencyTaskId) => ({
            sourceTaskId: dependencyTaskId,
            targetTaskId: task.id,
          })),
        );

      for (const edge of dependencyEdges) {
        addDependencyEdge(edge.sourceTaskId, edge.targetTaskId);
      }

      syncTaskDagLayout();
    }

    bootstrapTaskDag();

    // -----------------------------------------------------------------------
    // 1. agent.spawned -> addNode({ nodeType: "agentSession" }) (INTG-02, INTG-08)
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("agent.spawned", (event: any) => {
        const { nodes, actions } = store();

        // Dedup: skip if a node with this agentId already exists
        if (nodes.some((n: Node<SwarmBoardNodeData>) => n.data.agentId === event.agent.id)) return;

        const position = nextNodePosition(nodes);

        actions.addNode({
          nodeType: "agentSession",
          title: event.agent.name ?? event.agent.id,
          position,
          data: {
            nodeType: "agentSession",
            title: event.agent.name ?? event.agent.id,
            status: mapEngineStatus(event.agent.status ?? "idle"),
            agentId: event.agent.id,
            agentModel: event.agent.role,
            engineManaged: true,
            conversationHistory: engine.getConversationHistory(event.agent.id),
          },
        });
      }),
    );

    // -----------------------------------------------------------------------
    // 2. agent.status_changed -> updateNode (INTG-02)
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("agent.status_changed", (event: any) => {
        const { nodes, actions } = store();

        const node = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.agentId === event.agentId,
        );
        if (!node) return;

        const mappedStatus = mapEngineStatus(event.newStatus);
        actions.updateNode(node.id, { status: mappedStatus });
      }),
    );

    // -----------------------------------------------------------------------
    // 3. agent.heartbeat -> updateNode (INTG-02)
    //    Engine-managed nodes don't have a sessionId, so setSessionMetadata
    //    (which matches by sessionId) would be a no-op. Use updateNode which
    //    matches by node.id directly.
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("agent.heartbeat", (event: any) => {
        const { nodes, actions } = store();

        const node = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.agentId === event.agentId,
        );
        if (!node) return;

        actions.updateNode(node.id, {
          toolBoundaryEvents: event.metricsSnapshot?.tasksCompleted,
          confidence: Math.round((event.health ?? 0) * 100),
        });
      }),
    );

    // -----------------------------------------------------------------------
    // 4. agent.terminated -> updateNode({ status: "completed" }) (INTG-02)
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("agent.terminated", (event: any) => {
        const { nodes, actions } = store();

        const node = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.agentId === event.agentId,
        );
        if (!node) return;

        actions.updateNode(node.id, {
          status: "completed",
          exitCode: event.exitCode,
        });
      }),
    );

    // -----------------------------------------------------------------------
    // 5. agent.message -> append replay turn to the owning agent session
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("agent.message", (event: any) => {
        const { nodes, actions } = store();

        const agentNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.agentId === event.agentId,
        );
        if (!agentNode) return;

        const currentHistory = (agentNode.data as SwarmBoardNodeData)
          .conversationHistory;
        actions.updateNode(agentNode.id, {
          conversationHistory: appendConversationTurn(currentHistory, event.turn),
        });
      }),
    );

    // -----------------------------------------------------------------------
    // 6. task.created -> addNode({ nodeType: "terminalTask" }) + addEdge (INTG-02, INTG-08)
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("task.created", (event: any) => {
        const { nodes, actions } = store();

        // Dedup: skip if a node with this taskId already exists
        if (nodes.some((n: Node<SwarmBoardNodeData>) => n.data.taskId === event.task.id)) return;

        // Find parent agent node by assignedTo
        const parentNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) =>
            n.data.agentId === event.task.assignedTo,
        );

        // Position: below parent if found, else nextNodePosition
        const position = parentNode
          ? { x: parentNode.position.x, y: parentNode.position.y + 200 }
          : nextNodePosition(nodes);

        const taskNode = actions.addNode({
          nodeType: "terminalTask",
          title: event.task.name ?? event.task.type ?? "Task",
          position,
          data: {
            nodeType: "terminalTask",
            ...buildTaskNodePatch(event.task, nodes),
          },
        });

        // Add spawned edge from parent agent to task
        if (event.task.assignedTo && parentNode) {
          actions.addEdge({
            id: spawnedEdgeId(parentNode.id, taskNode.id),
            source: parentNode.id,
            target: taskNode.id,
            type: "spawned",
          });
        }

        for (const dependencyTaskId of event.task.dependencies ?? []) {
          addDependencyEdge(dependencyTaskId, event.task.id);
        }

        syncTaskDagLayout();
      }),
    );

    // -----------------------------------------------------------------------
    // 7. task.assigned -> attach agent/task relationship and edge
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("task.assigned", (event: any) => {
        const { nodes, actions } = store();

        const taskNode = nodes.find(
          (node: Node<SwarmBoardNodeData>) => node.data.taskId === event.taskId,
        );
        if (!taskNode) {
          const task = taskGraph?.getTask(event.taskId);
          if (task) {
            const createdNode = upsertTaskNode(task);
            addSpawnedEdge(event.agentId, createdNode.id);
            syncTaskDagLayout();
          }
          return;
        }

        actions.updateNode(taskNode.id, {
          agentId: event.agentId,
        });
        addSpawnedEdge(event.agentId, taskNode.id);
        syncTaskDagLayout();
      }),
    );

    // -----------------------------------------------------------------------
    // 8. task.status_changed -> keep task tile state aligned with TaskGraph
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("task.status_changed", (event: any) => {
        const { nodes, actions } = store();
        const task = taskGraph?.getTask(event.taskId);
        const taskNode = nodes.find(
          (node: Node<SwarmBoardNodeData>) => node.data.taskId === event.taskId,
        );

        if (task) {
          if (taskNode) {
            actions.updateNode(taskNode.id, buildTaskNodePatch(task, nodes));
          } else {
            upsertTaskNode(task);
            syncTaskDagLayout();
          }
          return;
        }

        if (!taskNode) {
          return;
        }

        actions.updateNode(taskNode.id, {
          status:
            event.newStatus === "running"
              ? "running"
              : event.newStatus === "completed"
                ? "completed"
                : event.newStatus === "failed" ||
                    event.newStatus === "cancelled" ||
                    event.newStatus === "timeout"
                  ? "failed"
                  : "idle",
        });
      }),
    );

    // -----------------------------------------------------------------------
    // 9. task.completed -> updateNode (INTG-02)
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("task.completed", (event: any) => {
        const { nodes, actions } = store();

        const taskNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.taskId === event.taskId,
        );
        if (!taskNode) return;

        actions.updateNode(taskNode.id, { status: "completed" });
      }),
    );

    // -----------------------------------------------------------------------
    // 10. task.failed -> updateNode({ status: "failed" }) (INTG-02)
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("task.failed", (event: any) => {
        const { nodes, actions } = store();

        const taskNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.taskId === event.taskId,
        );
        if (!taskNode) return;

        actions.updateNode(taskNode.id, {
          status: event.retryable ? "idle" : "failed",
        });
      }),
    );

    // -----------------------------------------------------------------------
    // 11. task.progress -> task preview line updates
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("task.progress", (event: any) => {
        const { nodes, actions } = store();

        const taskNode = nodes.find(
          (node: Node<SwarmBoardNodeData>) => node.data.taskId === event.taskId,
        );
        if (!taskNode) return;

        actions.updateNode(taskNode.id, {
          status: "running",
          previewLines: [
            `[${event.percent}%] ${event.currentStep}`,
          ],
        });
      }),
    );

    // -----------------------------------------------------------------------
    // 12. guard.evaluated -> guardEvaluate action + evaluating glow (INTG-02, INTG-09)
    // -----------------------------------------------------------------------
    unsubs.push(
      events.on("guard.evaluated", (event: any) => {
        const { nodes, actions } = store();

        // Find agent node by action.agentId
        const agentNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) =>
            n.data.agentId === event.action?.agentId,
        );

        if (agentNode) {
          const nodeId = agentNode.id;
          const currentStatus = (agentNode.data as SwarmBoardNodeData).status;

          // Evaluating glow pattern (copied from usePolicyEvalBoardBridge)
          const existingTimeout = timeouts.get(nodeId);
          if (existingTimeout != null) {
            clearTimeout(existingTimeout);
          } else {
            // Only save restore status if this is a fresh evaluation
            restoreStatuses.set(
              nodeId,
              currentStatus === "evaluating" ? "running" : currentStatus,
            );
          }

          // Set the node to evaluating status (triggers gold glow ring)
          actions.updateNode(nodeId, { status: "evaluating" });

          // Schedule reset back to previous status after glow duration
          const timeout = setTimeout(() => {
            timeouts.delete(nodeId);
            const restoreTo = restoreStatuses.get(nodeId) ?? "running";
            restoreStatuses.delete(nodeId);
            actions.updateNode(nodeId, { status: restoreTo });
          }, EVAL_GLOW_DURATION_MS);

          timeouts.set(nodeId, timeout);

          // Create receipt node via guardEvaluate action
          actions.guardEvaluate(
            nodeId,
            event.result?.verdict ?? "deny",
            (event.result?.guardResults ?? []).map((g: any) => ({
              guard: g.guard ?? g.guardId ?? "unknown",
              allowed: g.verdict !== "deny",
              duration_ms: g.duration_ms ?? g.durationMs,
            })),
            event.result?.receipt,
          );
        }
      }),
    );

    // -----------------------------------------------------------------------
    // 13 & 14. Shared handler for topology.updated and topology.rebalanced
    // -----------------------------------------------------------------------
    function handleTopologyEvent(topologyState: { type?: string; edges?: Array<{ from: string; to: string }> } | undefined): void {
      const { nodes, edges, actions } = store();
      const topoType = (topologyState?.type ?? "mesh") as Parameters<typeof computeLayout>[2];

      const result = computeLayout(
        nodes as Node<SwarmBoardNodeData>[],
        edges,
        topoType,
        { width: 1200, height: 800 },
      );

      actions.topologyLayout(topoType, result.positions);

      // Reconcile topology edges: remove stale ones, add new ones
      // First, remove all existing topology edges
      const nonTopoEdges = edges.filter((e) => e.type !== "topology");
      actions.setEdges(nonTopoEdges);

      // Then add the current topology edges
      if (topologyState?.edges) {
        for (const topoEdge of topologyState.edges) {
          // Map topology node IDs to board node IDs via agentId matching
          const fromNode = nodes.find(
            (n: Node<SwarmBoardNodeData>) =>
              n.data.agentId === topoEdge.from || n.id === topoEdge.from,
          );
          const toNode = nodes.find(
            (n: Node<SwarmBoardNodeData>) =>
              n.data.agentId === topoEdge.to || n.id === topoEdge.to,
          );
          if (fromNode && toNode) {
            actions.addEdge({
              id: `edge-topo-${topoEdge.from}-${topoEdge.to}`,
              source: fromNode.id,
              target: toNode.id,
              type: "topology",
            });
          }
        }
      }
    }

    // 9. topology.updated (INTG-02)
    unsubs.push(
      events.on("topology.updated", (event: any) => {
        handleTopologyEvent(event.newTopology);
      }),
    );

    // 10. topology.rebalanced (INTG-02)
    unsubs.push(
      events.on("topology.rebalanced", (event: any) => {
        handleTopologyEvent(event.topology);
      }),
    );

    // -----------------------------------------------------------------------
    // Cleanup: unsubscribe all events + clear all glow timeouts
    // -----------------------------------------------------------------------
    return () => {
      unsubs.forEach((fn) => fn());

      for (const timeout of timeouts.values()) {
        clearTimeout(timeout);
      }
      timeouts.clear();
      restoreStatuses.clear();
    };
  }, [engine]);
}
