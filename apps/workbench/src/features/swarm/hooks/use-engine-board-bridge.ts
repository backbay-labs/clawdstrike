/** Bridges SwarmOrchestrator events to the Zustand board store. */

import { useEffect, useRef } from "react";
import type { SwarmOrchestrator } from "@clawdstrike/swarm-engine";
import {
  createBoardNode,
  useSwarmBoardStore,
} from "@/features/swarm/stores/swarm-board-store";
import type {
  SwarmBoardEdge,
  SwarmBoardNodeData,
  SessionStatus,
} from "@/features/swarm/swarm-board-types";
import type { Node } from "@xyflow/react";
import { computeLayout } from "@/features/swarm/layout/topology-layout";
import { nextNodePosition } from "./node-position";

const EVAL_GLOW_DURATION_MS = 2000;
const DEFAULT_LAYOUT_VIEWPORT = { width: 1200, height: 800 };
const TASK_VERTICAL_OFFSET = 200;
const TASK_VERTICAL_STAGGER = 24;

function mapEngineStatus(engineStatus: string): SessionStatus {
  switch (engineStatus) {
    case "created":
    case "queued":
    case "assigned":
      return "idle";
    case "running":
      return "running";
    case "idle":
      return "idle";
    case "busy":
      return "running";
    case "paused":
    case "draining":
      return "blocked";
    case "terminated":
      return "completed";
    case "cancelled":
      return "completed";
    case "timeout":
      return "failed";
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
      return "idle";
  }
}

function seedBoardFromEngineSnapshot(engine: SwarmOrchestrator): void {
  const snapshot = engine.getState();
  const { actions } = useSwarmBoardStore.getState();

  const topologyNodeById = new Map(
    snapshot.topology.nodes.map((topologyNode) => [topologyNode.id, topologyNode]),
  );
  const agentPositions = new Map(
    snapshot.topology.nodes
      .filter(
        (topologyNode) =>
          topologyNode.positionX !== null && topologyNode.positionY !== null,
      )
      .map((topologyNode) => [
        topologyNode.agentId,
        { x: topologyNode.positionX ?? 0, y: topologyNode.positionY ?? 0 },
      ]),
  );

  const agentNodes = Object.values(snapshot.agents).map((agent) => ({
    id: agent.id,
    agentId: agent.id,
    data: {
      nodeType: "agentSession" as const,
      title: agent.name,
      status: mapEngineStatus(agent.status),
      agentId: agent.id,
      agentModel: agent.agentModel ?? agent.role,
      branch: agent.branch ?? undefined,
      worktreePath: agent.worktreePath ?? undefined,
      risk: agent.risk,
      policyMode: agent.policyMode ?? undefined,
      receiptCount: agent.receiptCount,
      blockedActionCount: agent.blockedActionCount,
      changedFilesCount: agent.changedFilesCount,
      filesTouched: agent.filesTouched,
      toolBoundaryEvents: agent.toolBoundaryEvents,
      confidence: agent.confidence ?? undefined,
      engineManaged: true,
    },
    position: agentPositions.get(agent.id),
  }));

  const seededTaskCounts = new Map<string, number>();

  const taskNodes = Object.values(snapshot.tasks).map((task) => {
    const agentPosition = task.assignedTo
      ? agentPositions.get(task.assignedTo)
      : undefined;
    const taskIndex = task.assignedTo
      ? (seededTaskCounts.get(task.assignedTo) ?? 0)
      : 0;

    if (task.assignedTo) {
      seededTaskCounts.set(task.assignedTo, taskIndex + 1);
    }

    return {
      id: task.id,
      taskId: task.id,
      agentId: task.assignedTo ?? undefined,
      data: {
        nodeType: "terminalTask" as const,
        title: task.type ?? task.name ?? "Task",
        status: mapEngineStatus(task.status),
        taskId: task.id,
        agentId: task.assignedTo ?? undefined,
        engineManaged: true,
        taskPrompt: task.taskPrompt ?? task.description,
        previewLines: task.previewLines,
      },
      position: agentPosition
        ? getStackedTaskPosition(agentPosition, taskIndex)
        : undefined,
    };
  });

  const taskEdges = Object.values(snapshot.tasks)
    .filter((task) => task.assignedTo)
    .map((task) => ({
      id: `edge-spawn-${task.id}`,
      source: task.assignedTo!,
      target: task.id,
      type: "spawned" as const,
    }));

  const topologyEdges = snapshot.topology.edges.map((topologyEdge) => {
    const fromNode = topologyNodeById.get(topologyEdge.from);
    const toNode = topologyNodeById.get(topologyEdge.to);
    return {
      id: `edge-topo-${topologyEdge.from}-${topologyEdge.to}`,
      source: fromNode?.agentId ?? topologyEdge.from,
      target: toNode?.agentId ?? topologyEdge.to,
      type: "topology" as const,
    };
  });

  actions.engineSync(
    [...agentNodes, ...taskNodes],
    [...taskEdges, ...topologyEdges],
  );
}

function buildTopologyEdges(
  nodes: Node<SwarmBoardNodeData>[],
  topologyEdges: Array<{ from: string; to: string }> | undefined,
): SwarmBoardEdge[] {
  if (!topologyEdges?.length) {
    return [];
  }

  return topologyEdges.flatMap((topologyEdge) => {
    const fromNode = nodes.find(
      (node) =>
        node.data.agentId === topologyEdge.from || node.id === topologyEdge.from,
    );
    const toNode = nodes.find(
      (node) =>
        node.data.agentId === topologyEdge.to || node.id === topologyEdge.to,
    );

    if (!fromNode || !toNode) {
      return [];
    }

    return [{
      id: `edge-topo-${topologyEdge.from}-${topologyEdge.to}`,
      source: fromNode.id,
      target: toNode.id,
      type: "topology" as const,
    }];
  });
}

function getStackedTaskPosition(
  agentPosition: { x: number; y: number },
  taskIndex: number,
): { x: number; y: number } {
  return {
    x: agentPosition.x,
    y: agentPosition.y + TASK_VERTICAL_OFFSET + taskIndex * TASK_VERTICAL_STAGGER,
  };
}

function getAssignedTaskPosition(
  nodes: Node<SwarmBoardNodeData>[],
  agentId: string | null | undefined,
  excludeTaskNodeId?: string,
): { x: number; y: number } | undefined {
  if (!agentId) {
    return undefined;
  }

  const agentNode = nodes.find(
    (node) => node.data.agentId === agentId,
  );

  if (!agentNode) {
    return undefined;
  }

  const siblingTaskCount = nodes.filter((node) => {
    if (node.id === excludeTaskNodeId) {
      return false;
    }

    return (
      node.data.nodeType === "terminalTask" &&
      node.data.agentId === agentId
    );
  }).length;

  return getStackedTaskPosition(agentNode.position, siblingTaskCount);
}

function getLayoutViewport(): { width: number; height: number } {
  if (typeof window === "undefined") {
    return DEFAULT_LAYOUT_VIEWPORT;
  }

  const flowCanvas = document.querySelector(".react-flow");
  if (flowCanvas) {
    const rect = flowCanvas.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      return {
        width: rect.width,
        height: rect.height,
      };
    }
  }

  const width = Math.max(
    window.innerWidth || 0,
    document.documentElement?.clientWidth || 0,
  );
  const height = Math.max(
    window.innerHeight || 0,
    document.documentElement?.clientHeight || 0,
  );

  return {
    width: width > 0 ? width : DEFAULT_LAYOUT_VIEWPORT.width,
    height: height > 0 ? height : DEFAULT_LAYOUT_VIEWPORT.height,
  };
}

export function useEngineBoardBridge(engine: SwarmOrchestrator | null): void {
  const timeoutsRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());
  const restoreStatusRef = useRef<Map<string, SessionStatus>>(new Map());

  useEffect(() => {
    if (!engine) return;

    const store = useSwarmBoardStore.getState;
    const unsubs: Array<() => void> = [];
    const timeouts = timeoutsRef.current;
    const restoreStatuses = restoreStatusRef.current;
    const clearPendingGuardGlow = (
      nodeId: string,
      options: { restore?: boolean } = {},
    ): void => {
      const timeout = timeouts.get(nodeId);
      if (timeout != null) {
        clearTimeout(timeout);
        timeouts.delete(nodeId);
      }
      if (options.restore) {
        const restoreTo = restoreStatuses.get(nodeId) ?? "running";
        const currentNode = store().nodes.find((node) => node.id === nodeId);
        if (currentNode?.data.status === "evaluating") {
          store().actions.updateNode(nodeId, { status: restoreTo });
        }
      }
      restoreStatuses.delete(nodeId);
    };

    const events = engine.getEvents();
    seedBoardFromEngineSnapshot(engine);

    unsubs.push(
      events.on("agent.spawned", (event: any) => {
        const { nodes, actions } = store();
        if (nodes.some((n: Node<SwarmBoardNodeData>) => n.data.agentId === event.agent.id)) return;

        const position = nextNodePosition(nodes);
        const agentNode = {
          ...createBoardNode({
            nodeType: "agentSession",
            title: event.agent.name ?? event.agent.id,
            position,
            data: {
              nodeType: "agentSession",
              title: event.agent.name ?? event.agent.id,
              status: mapEngineStatus(event.agent.status),
              agentId: event.agent.id,
              agentModel: event.agent.role,
              engineManaged: true,
            },
          }),
          id: event.agent.id,
        };

        actions.addNodeDirect(agentNode);
      }),
    );

    unsubs.push(
      events.on("agent.status_changed", (event: any) => {
        const { nodes, actions } = store();

        const node = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.agentId === event.agentId,
        );
        if (!node) return;

        const mappedStatus = mapEngineStatus(event.newStatus);
        if (timeouts.has(node.id) && mappedStatus !== "evaluating") {
          restoreStatuses.set(node.id, mappedStatus);
        }
        actions.updateNode(node.id, { status: mappedStatus });
      }),
    );

    // Engine-managed nodes lack sessionId, so use updateNode (not setSessionMetadata).
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

    unsubs.push(
      events.on("agent.terminated", (event: any) => {
        const { nodes, actions } = store();

        const node = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.agentId === event.agentId,
        );
        if (!node) return;

        clearPendingGuardGlow(node.id);
        actions.updateNode(node.id, {
          status: "completed",
          exitCode: event.exitCode,
        });
      }),
    );

    unsubs.push(
      events.on("task.created", (event: any) => {
        const { nodes, actions } = store();
        if (nodes.some((n: Node<SwarmBoardNodeData>) => n.data.taskId === event.task.id)) return;

        const parentNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) =>
            n.data.agentId === event.task.assignedTo,
        );

        const position = getAssignedTaskPosition(
          nodes,
          event.task.assignedTo,
        ) ?? nextNodePosition(nodes);

        const taskNode = {
          ...createBoardNode({
            nodeType: "terminalTask",
            title: event.task.type ?? event.task.name ?? "Task",
            position,
            data: {
              nodeType: "terminalTask",
              title: event.task.type ?? event.task.name ?? "Task",
              status: mapEngineStatus(event.task.status),
              taskId: event.task.id,
              agentId: event.task.assignedTo,
              engineManaged: true,
              taskPrompt: event.task.taskPrompt ?? event.task.description,
            },
          }),
          id: event.task.id,
        };

        actions.addNodeDirect(taskNode);

        if (parentNode) {
          actions.addEdge({
            id: `edge-spawn-${event.task.id}`,
            source: parentNode.id,
            target: taskNode.id,
            type: "spawned",
          });
        }
      }),
    );

    unsubs.push(
      events.on("task.status_changed", (event: any) => {
        const { nodes, actions } = store();

        const taskNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.taskId === event.taskId,
        );
        if (!taskNode) return;

        actions.updateNode(taskNode.id, {
          status: mapEngineStatus(event.newStatus),
        });
      }),
    );

    unsubs.push(
      events.on("task.assigned", (event: any) => {
        const { nodes, edges, actions } = store();

        const taskNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.taskId === event.taskId,
        );
        if (!taskNode) return;

        const agentNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.agentId === event.agentId,
        );

        const nextNodes = nodes.map((node) => {
          if (node.id !== taskNode.id) {
            return node;
          }

          return {
            ...node,
            position: agentNode
              ? (
                getAssignedTaskPosition(nodes, event.agentId, taskNode.id) ??
                node.position
              )
              : node.position,
            data: {
              ...node.data,
              agentId: event.agentId,
              status: mapEngineStatus("assigned"),
            },
          };
        });

        if (!agentNode) {
          actions.loadState({ nodes: nextNodes });
          return;
        }

        const nextEdges = [
          ...edges.filter(
            (edge: SwarmBoardEdge) =>
              !(edge.type === "spawned" && edge.target === taskNode.id),
          ),
          {
            id: `edge-spawn-${event.taskId}`,
            source: agentNode.id,
            target: taskNode.id,
            type: "spawned" as const,
          },
        ];

        actions.loadState({ nodes: nextNodes, edges: nextEdges });
      }),
    );

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

    unsubs.push(
      events.on("task.failed", (event: any) => {
        const { nodes, actions } = store();

        const taskNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) => n.data.taskId === event.taskId,
        );
        if (!taskNode) return;

        actions.updateNode(taskNode.id, { status: "failed" });
      }),
    );

    unsubs.push(
      events.on("guard.evaluated", (event: any) => {
        const { nodes, actions } = store();
        const agentNode = nodes.find(
          (n: Node<SwarmBoardNodeData>) =>
            n.data.agentId === event.action?.agentId,
        );

        if (agentNode) {
          const nodeId = agentNode.id;
          const currentStatus = (agentNode.data as SwarmBoardNodeData).status;

          const existingTimeout = timeouts.get(nodeId);
          if (existingTimeout != null) {
            clearTimeout(existingTimeout);
          }

          if (currentStatus !== "evaluating" || !restoreStatuses.has(nodeId)) {
            restoreStatuses.set(
              nodeId,
              currentStatus === "evaluating" ? "running" : currentStatus,
            );
          }

          actions.updateNode(nodeId, { status: "evaluating" });

          const timeout = setTimeout(() => {
            timeouts.delete(nodeId);
            const restoreTo = restoreStatuses.get(nodeId) ?? "running";
            restoreStatuses.delete(nodeId);
            const currentNode = store().nodes.find((node) => node.id === nodeId);
            const latestStatus = currentNode?.data.status;

            // Don't overwrite fresher lifecycle updates that landed during the glow
            if (latestStatus !== "evaluating") {
              return;
            }

            actions.updateNode(nodeId, { status: restoreTo });
          }, EVAL_GLOW_DURATION_MS);

          timeouts.set(nodeId, timeout);

          actions.guardEvaluate(
            nodeId,
            event.result?.verdict ?? "deny",
            (event.result?.guardResults ?? []).map((g: any) => ({
              guard: g.guard ?? g.guardId ?? "unknown",
              allowed: g.verdict !== "deny",
              duration_ms: g.duration_ms ?? g.durationMs,
            })),
            event.result?.receipt?.signature,
            event.result?.receipt?.publicKey,
          );
        }
      }),
    );

    function handleTopologyEvent(topologyState: { type?: string; edges?: Array<{ from: string; to: string }> } | undefined): void {
      const { nodes, edges, actions } = store();
      const topoType = (topologyState?.type ?? "mesh") as Parameters<typeof computeLayout>[2];
      const currentNodes = nodes as Node<SwarmBoardNodeData>[];
      const nextTopologyEdges = buildTopologyEdges(currentNodes, topologyState?.edges);
      const nextEdges = [
        ...edges.filter((edge) => edge.type !== "topology"),
        ...nextTopologyEdges,
      ];

      const result = computeLayout(
        currentNodes,
        nextEdges,
        topoType,
        getLayoutViewport(),
      );

      actions.applyTopologyLayout(nextTopologyEdges, result.positions);
    }

    unsubs.push(
      events.on("topology.updated", (event: any) => {
        handleTopologyEvent(event.newTopology);
      }),
    );

    unsubs.push(
      events.on("topology.rebalanced", (event: any) => {
        handleTopologyEvent(event.topology);
      }),
    );

    return () => {
      unsubs.forEach((fn) => fn());

      for (const nodeId of Array.from(timeouts.keys())) {
        clearPendingGuardGlow(nodeId, { restore: true });
      }
    };
  }, [engine]);
}
