import { useEffect, useMemo } from "react";
import type { Node, Viewport } from "@xyflow/react";
import { getCoordinator } from "@/features/swarm/coordinator-instance";
import {
  createBoardNode,
  type SpawnClaudeSessionOptions,
  type SpawnSessionOptions,
  type SpawnWorktreeSessionOptions,
  useSwarmBoardStore,
} from "@/features/swarm/stores/swarm-board-store";
import type { SwarmBoardEdge, SwarmBoardNodeData, SwarmNodeType } from "@/features/swarm/swarm-board-types";
import { getSwarmRpcViewportController } from "@/features/swarm/rpc/swarm-rpc-viewport";
import { isDesktop } from "@/lib/tauri-bridge";
import { respondToRpcFrontendRequestNative } from "@/lib/tauri-commands";
import { terminalService, type SessionInfo } from "@/lib/workbench/terminal-service";

export const SWARM_RPC_REQUEST_EVENT = "swarm:rpc_request";

type RpcMethodName =
  | "board.snapshot"
  | "board.nodeAdd"
  | "board.nodeRemove"
  | "board.nodeUpdate"
  | "board.edgeAdd"
  | "board.edgeRemove"
  | "board.viewportGet"
  | "board.viewportSet"
  | "session.spawn"
  | "session.kill"
  | "session.list"
  | "session.readOutput"
  | "coordinator.status"
  | "coordinator.publish";

const NODE_TYPES: SwarmNodeType[] = [
  "agentSession",
  "terminalTask",
  "artifact",
  "diff",
  "note",
  "receipt",
];
const EDGE_TYPES: Array<NonNullable<SwarmBoardEdge["type"]>> = [
  "handoff",
  "spawned",
  "artifact",
  "receipt",
  "topology",
  "dependency",
];
type SwarmBoardNodeRecordPatch = Omit<Partial<Node<SwarmBoardNodeData>>, "id" | "data"> & {
  data?: Partial<SwarmBoardNodeData>;
};
const COORDINATOR_CHANNELS = ["intel", "signal", "detection", "coordination"] as const;

interface SwarmRpcFrontendRequest {
  request_id: string;
  method: RpcMethodName;
  params?: unknown;
}

interface SwarmRpcDispatcherDeps {
  getBoardStore: typeof useSwarmBoardStore.getState;
  spawnSession: (opts: SpawnSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnClaudeSession: (opts: SpawnClaudeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  spawnWorktreeSession: (opts: SpawnWorktreeSessionOptions) => Promise<Node<SwarmBoardNodeData>>;
  killSession: (nodeId: string) => Promise<void>;
  terminal: Pick<typeof terminalService, "discover" | "kill" | "list" | "preview">;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function maybeRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return asRecord(value, "params");
}

function readString(record: Record<string, unknown>, key: string, label = key): string {
  const value = record[key];
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function readOptionalString(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.trim() ? value : undefined;
}

function readOptionalBoolean(record: Record<string, unknown>, key: string): boolean | undefined {
  const value = record[key];
  return typeof value === "boolean" ? value : undefined;
}

function readOptionalNumber(record: Record<string, unknown>, key: string): number | undefined {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function readOptionalPosition(
  record: Record<string, unknown>,
  key: string,
): { x: number; y: number } | undefined {
  const value = record[key];
  if (value === undefined || value === null) {
    return undefined;
  }
  const parsed = asRecord(value, key);
  const x = readOptionalNumber(parsed, "x");
  const y = readOptionalNumber(parsed, "y");
  if (x === undefined || y === undefined) {
    throw new Error(`${key} must include numeric x and y values`);
  }
  return { x, y };
}

function readViewport(record: Record<string, unknown>): Viewport {
  const viewport = asRecord(record.viewport, "viewport");
  const x = readOptionalNumber(viewport, "x");
  const y = readOptionalNumber(viewport, "y");
  const zoom = readOptionalNumber(viewport, "zoom");
  if (x === undefined || y === undefined || zoom === undefined) {
    throw new Error("viewport must include numeric x, y, and zoom values");
  }
  return { x, y, zoom };
}

function readNodeType(record: Record<string, unknown>): SwarmNodeType {
  const nodeType = readString(record, "nodeType");
  if (!NODE_TYPES.includes(nodeType as SwarmNodeType)) {
    throw new Error(`Unsupported nodeType: ${nodeType}`);
  }
  return nodeType as SwarmNodeType;
}

function readOptionalEdgeType(
  record: Record<string, unknown>,
): SwarmBoardEdge["type"] | undefined {
  const edgeType = readOptionalString(record, "type");
  if (!edgeType) {
    return undefined;
  }
  if (!EDGE_TYPES.includes(edgeType as NonNullable<SwarmBoardEdge["type"]>)) {
    throw new Error(`Unsupported edge type: ${edgeType}`);
  }
  return edgeType as SwarmBoardEdge["type"];
}

function readNodeDataPatch(
  record: Record<string, unknown>,
  key: string,
): Partial<SwarmBoardNodeData> | undefined {
  const value = record[key];
  if (value === undefined || value === null) {
    return undefined;
  }
  return asRecord(value, key) as Partial<SwarmBoardNodeData>;
}

function resolveSessionId(
  params: Record<string, unknown>,
  nodes: Array<Node<SwarmBoardNodeData>>,
): { nodeId: string | null; sessionId: string } {
  const nodeId = readOptionalString(params, "nodeId");
  const sessionId = readOptionalString(params, "sessionId");

  if (nodeId) {
    const node = nodes.find((entry) => entry.id === nodeId);
    const nodeSessionId = typeof node?.data?.sessionId === "string" ? node.data.sessionId : undefined;
    if (!node || !nodeSessionId) {
      throw new Error(`Node ${nodeId} does not have a live session`);
    }
    return { nodeId, sessionId: nodeSessionId };
  }

  if (!sessionId) {
    throw new Error("Either nodeId or sessionId is required");
  }

  const matchingNode = nodes.find((entry) => entry.data?.sessionId === sessionId);
  return { nodeId: matchingNode?.id ?? null, sessionId };
}

function buildEdgeId(source: string, target: string): string {
  return `edge-${source}-${target}-${Date.now().toString(36)}`;
}

function mergeBoardSessions(
  nodes: Array<Node<SwarmBoardNodeData>>,
  sessions: SessionInfo[],
): Array<Record<string, unknown>> {
  const sessionById = new Map(sessions.map((session) => [session.id, session]));
  const seenIds = new Set<string>();
  const results: Array<Record<string, unknown>> = [];

  for (const node of nodes) {
    const sessionId = typeof node.data?.sessionId === "string" ? node.data.sessionId : undefined;
    if (!sessionId) {
      continue;
    }

    const session = sessionById.get(sessionId);
    seenIds.add(sessionId);
    results.push({
      nodeId: node.id,
      sessionId,
      title: node.data.title,
      boardStatus: node.data.status,
      terminalAttached: node.data.terminalAttached ?? false,
      sessionPersistence: node.data.sessionPersistence ?? null,
      sessionRecoveryState: node.data.sessionRecoveryState ?? null,
      ...(session ? session : {}),
    });
  }

  for (const session of sessions) {
    if (seenIds.has(session.id)) {
      continue;
    }
    results.push({
      nodeId: null,
      sessionId: session.id,
      title: null,
      boardStatus: null,
      terminalAttached: false,
      sessionPersistence: session.persistence_mode,
      sessionRecoveryState: session.recovery_state,
      ...session,
    });
  }

  return results.sort((left, right) =>
    String(left.created_at ?? "").localeCompare(String(right.created_at ?? "")),
  );
}

export function createSwarmRpcDispatcher(deps: SwarmRpcDispatcherDeps) {
  return async (method: RpcMethodName, params: unknown): Promise<unknown> => {
    const boardStore = deps.getBoardStore();
    const boardState = boardStore;
    const record = maybeRecord(params);

    switch (method) {
      case "board.snapshot":
        return {
          boardId: boardState.boardId,
          repoRoot: boardState.repoRoot,
          bundlePath: boardState.bundlePath,
          selectedNodeId: boardState.selectedNodeId,
          inspectorOpen: boardState.inspectorOpen,
          fileWatchRevision: boardState.fileWatchRevision,
          nodes: boardState.nodes,
          edges: boardState.edges,
        };

      case "board.nodeAdd": {
        const input = asRecord(record, "board.nodeAdd params");
        const node = createBoardNode({
          nodeType: readNodeType(input),
          title: readString(input, "title"),
          position: readOptionalPosition(input, "position"),
          data: readNodeDataPatch(input, "data"),
        });
        const explicitId = readOptionalString(input, "id");
        if (explicitId) {
          node.id = explicitId;
        }
        const width = readOptionalNumber(input, "width");
        const height = readOptionalNumber(input, "height");
        if (width !== undefined) {
          node.width = width;
        }
        if (height !== undefined) {
          node.height = height;
        }
        boardState.actions.addNodeDirect(node);
        if (readOptionalBoolean(input, "selected")) {
          boardState.actions.selectNode(node.id);
        }
        return node;
      }

      case "board.nodeRemove": {
        const input = asRecord(record, "board.nodeRemove params");
        const nodeId = readString(input, "nodeId");
        const node = boardState.nodes.find((entry) => entry.id === nodeId);
        if (node?.data?.sessionId) {
          await deps.killSession(nodeId);
        }
        boardState.actions.removeNode(nodeId);
        return { removed: true, nodeId };
      }

      case "board.nodeUpdate": {
        const input = asRecord(record, "board.nodeUpdate params");
        const nodeId = readString(input, "nodeId");
        const patch: SwarmBoardNodeRecordPatch = {};
        const position = readOptionalPosition(input, "position");
        const width = readOptionalNumber(input, "width");
        const height = readOptionalNumber(input, "height");
        const data = readNodeDataPatch(input, "data");
        if (position) {
          patch.position = position;
        }
        if (width !== undefined) {
          patch.width = width;
        }
        if (height !== undefined) {
          patch.height = height;
        }
        if (data) {
          patch.data = data;
        }
        const updated = boardState.actions.updateNodeRecord(nodeId, patch);
        if (!updated) {
          throw new Error(`Node not found: ${nodeId}`);
        }
        if (readOptionalBoolean(input, "selected")) {
          boardState.actions.selectNode(nodeId);
        }
        return updated;
      }

      case "board.edgeAdd": {
        const input = asRecord(record, "board.edgeAdd params");
        const source = readString(input, "source");
        const target = readString(input, "target");
        const edge: SwarmBoardEdge = {
          id: readOptionalString(input, "id") ?? buildEdgeId(source, target),
          source,
          target,
          label: readOptionalString(input, "label"),
          type: readOptionalEdgeType(input),
        };
        boardState.actions.addEdge(edge);
        return edge;
      }

      case "board.edgeRemove": {
        const input = asRecord(record, "board.edgeRemove params");
        const edgeId = readString(input, "edgeId");
        boardState.actions.removeEdge(edgeId);
        return { removed: true, edgeId };
      }

      case "board.viewportGet": {
        const controller = getSwarmRpcViewportController();
        if (!controller) {
          throw new Error("Board viewport is unavailable on the current screen");
        }
        return controller.getViewport();
      }

      case "board.viewportSet": {
        const input = asRecord(record, "board.viewportSet params");
        const controller = getSwarmRpcViewportController();
        if (!controller) {
          throw new Error("Board viewport is unavailable on the current screen");
        }
        return controller.setViewport(readViewport(input), {
          duration: readOptionalNumber(input, "duration"),
        });
      }

      case "session.spawn": {
        const input = asRecord(record, "session.spawn params");
        const kind = readOptionalString(input, "kind") ?? "terminal";
        if (kind === "claude") {
          return deps.spawnClaudeSession({
            cwd: readOptionalString(input, "cwd"),
            position: readOptionalPosition(input, "position"),
            prompt: readOptionalString(input, "prompt"),
            worktree: readOptionalBoolean(input, "worktree"),
            branch: readOptionalString(input, "branch"),
            title: readOptionalString(input, "title"),
          });
        }
        if (kind === "worktree") {
          return deps.spawnWorktreeSession({
            position: readOptionalPosition(input, "position"),
            branch: readOptionalString(input, "branch"),
            title: readOptionalString(input, "title"),
            shell: readOptionalString(input, "shell"),
          });
        }
        return deps.spawnSession({
          cwd: readOptionalString(input, "cwd") ?? "",
          position: readOptionalPosition(input, "position"),
          launchClaude: readOptionalBoolean(input, "launchClaude"),
          title: readOptionalString(input, "title"),
          shell: readOptionalString(input, "shell"),
          command: readOptionalString(input, "command"),
        });
      }

      case "session.kill": {
        const input = asRecord(record, "session.kill params");
        const { nodeId, sessionId } = resolveSessionId(input, boardState.nodes);
        if (nodeId) {
          await deps.killSession(nodeId);
          return { killed: true, nodeId, sessionId };
        }
        await deps.terminal.kill(sessionId);
        return { killed: true, nodeId: null, sessionId };
      }

      case "session.list": {
        const [liveSessions, recoverableSessions] = await Promise.all([
          deps.terminal.list().catch(() => []),
          deps.terminal.discover().catch(() => []),
        ]);
        const merged = new Map<string, SessionInfo>();
        for (const session of [...liveSessions, ...recoverableSessions]) {
          merged.set(session.id, session);
        }
        return mergeBoardSessions(boardState.nodes, Array.from(merged.values()));
      }

      case "session.readOutput": {
        const input = asRecord(record, "session.readOutput params");
        const lines = readOptionalNumber(input, "lines");
        const { nodeId, sessionId } = resolveSessionId(input, boardState.nodes);
        const output = await deps.terminal.preview(
          sessionId,
          lines !== undefined ? Math.max(1, Math.trunc(lines)) : undefined,
        );
        return {
          nodeId,
          sessionId,
          lines: output,
          lineCount: output.length,
        };
      }

      case "coordinator.status": {
        const coordinator = getCoordinator();
        return {
          connected: coordinator.isConnected,
          outboxSize: coordinator.outboxSize,
          joinedSwarmIds: coordinator.joinedSwarmIds,
          reconnectAttempts: coordinator.currentReconnectAttempts,
        };
      }

      case "coordinator.publish": {
        const input = asRecord(record, "coordinator.publish params");
        const swarmId = readString(input, "swarmId");
        const channel = readString(input, "channel");
        if (!COORDINATOR_CHANNELS.includes(channel as (typeof COORDINATOR_CHANNELS)[number])) {
          throw new Error(`Unsupported coordinator channel: ${channel}`);
        }
        if (!("payload" in input)) {
          throw new Error("payload is required");
        }
        const coordinator = getCoordinator();
        await coordinator.publishMessage(
          swarmId,
          channel as (typeof COORDINATOR_CHANNELS)[number],
          input.payload,
        );
        return {
          published: true,
          queued: !coordinator.isConnected,
          swarmId,
          channel,
        };
      }
    }
  };
}

export function useSwarmRpcBridge(
  {
    killSession,
    spawnClaudeSession,
    spawnSession,
    spawnWorktreeSession,
  }: Pick<
    SwarmRpcDispatcherDeps,
    "killSession" | "spawnClaudeSession" | "spawnSession" | "spawnWorktreeSession"
  >,
): void {
  const dispatcher = useMemo(
    () =>
      createSwarmRpcDispatcher({
        getBoardStore: useSwarmBoardStore.getState,
        terminal: terminalService,
        killSession,
        spawnClaudeSession,
        spawnSession,
        spawnWorktreeSession,
      }),
    [killSession, spawnClaudeSession, spawnSession, spawnWorktreeSession],
  );

  useEffect(() => {
    if (!isDesktop()) {
      return;
    }

    let cancelled = false;
    let detach: (() => void) | undefined;

    void import("@tauri-apps/api/event")
      .then(({ listen }) =>
        listen<SwarmRpcFrontendRequest>(SWARM_RPC_REQUEST_EVENT, (event) => {
          void (async () => {
            try {
              const result = await dispatcher(event.payload.method, event.payload.params);
              await respondToRpcFrontendRequestNative(
                event.payload.request_id,
                result ?? null,
              );
            } catch (error) {
              const message = error instanceof Error ? error.message : String(error);
              await respondToRpcFrontendRequestNative(event.payload.request_id, null, message);
            }
          })();
        }),
      )
      .then((unlisten) => {
        if (cancelled) {
          unlisten();
          return;
        }
        detach = unlisten;
      })
      .catch((error) => {
        console.error("[swarm-rpc-bridge] failed to start frontend RPC listener:", error);
      });

    return () => {
      cancelled = true;
      detach?.();
    };
  }, [dispatcher]);
}
