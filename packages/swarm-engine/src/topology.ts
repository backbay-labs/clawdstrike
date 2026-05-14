/** Swarm network topology across 5 modes (mesh, hierarchical, centralized, hybrid, adaptive). */

import type {
  TypedEventEmitter,
  SwarmEngineEventMap,
} from "./events.js";

import type {
  TopologyConfig,
  TopologyNode,
  TopologyNodeRole,
  TopologyEdge,
  TopologyPartition,
  TopologyState,
  TopologyType,
} from "./types.js";

import { SWARM_ENGINE_CONSTANTS } from "./types.js";

export interface AdaptiveThresholds {
  meshMax?: number;
  hierarchicalMax?: number;
}

const DEFAULT_ADAPTIVE_THRESHOLDS: Required<AdaptiveThresholds> = {
  meshMax: 5,
  hierarchicalMax: 20,
};

export class TopologyManager {
  private readonly config: TopologyConfig;
  private readonly adaptiveThresholds: Required<AdaptiveThresholds>;

  private state: TopologyState;

  // Internal indexes
  private nodeIndex = new Map<string, TopologyNode>();
  private adjacencyList = new Map<string, Set<string>>();
  private roleIndex = new Map<TopologyNodeRole, Set<string>>();
  private queenNode: TopologyNode | null = null;
  private coordinatorNode: TopologyNode | null = null;
  private lastRebalanceAt: number = 0;
  private electionTerm = 0;

  private lastEffectiveType: TopologyType;

  constructor(
    private readonly events: TypedEventEmitter<SwarmEngineEventMap>,
    config?: Partial<TopologyConfig & { adaptiveThresholds?: AdaptiveThresholds }>,
  ) {
    this.config = {
      type: config?.type ?? "mesh",
      maxAgents: config?.maxAgents ?? SWARM_ENGINE_CONSTANTS.DEFAULT_MAX_AGENTS,
      replicationFactor: config?.replicationFactor ?? 2,
      partitionStrategy: config?.partitionStrategy ?? "hash",
      failoverEnabled: config?.failoverEnabled ?? true,
      autoRebalance: config?.autoRebalance ?? true,
    };

    this.adaptiveThresholds = {
      meshMax: config?.adaptiveThresholds?.meshMax ?? DEFAULT_ADAPTIVE_THRESHOLDS.meshMax,
      hierarchicalMax:
        config?.adaptiveThresholds?.hierarchicalMax ??
        DEFAULT_ADAPTIVE_THRESHOLDS.hierarchicalMax,
    };

    this.state = {
      type: this.config.type,
      nodes: [],
      edges: [],
      leaderId: null,
      partitions: [],
      snapshotAt: Date.now(),
    };

    this.lastEffectiveType = this.resolveEffectiveType();
  }

  addNode(agentId: string, role: TopologyNodeRole): TopologyNode {
    if (this.nodeIndex.has(agentId)) {
      throw new Error(`Node ${agentId} already exists in topology`);
    }

    if (this.nodeIndex.size >= this.config.maxAgents) {
      throw new Error(`Maximum agents (${this.config.maxAgents}) reached`);
    }

    const effectiveType = this.resolveEffectiveType();
    const determinedRole = this.determineRole(role, effectiveType);
    const connections = this.calculateInitialConnections(agentId, determinedRole, effectiveType);

    const node: TopologyNode = {
      id: agentId,
      agentId,
      role: determinedRole,
      status: "syncing",
      connections,
      metadata: {
        joinedAt: Date.now(),
        version: "1.0.0",
      },
      positionX: null,
      positionY: null,
      hierarchyDepth: null,
    };

    this.nodeIndex.set(agentId, node);
    this.state.nodes.push(node);

    this.addToRoleIndex(node);
    this.adjacencyList.set(agentId, new Set(connections));
    this.createEdgesForNode(node, effectiveType);
    this.updatePartitions(node, effectiveType);
    node.status = "active";
    this.checkAdaptiveTransition();
    this.emitTopologyUpdated();

    if (this.config.autoRebalance && this.shouldRebalance()) {
      this.rebalance();
    }

    return node;
  }

  removeNode(agentId: string): void {
    const node = this.nodeIndex.get(agentId);
    if (!node) {
      return;
    }

    this.state.nodes = this.state.nodes.filter((n) => n.agentId !== agentId);
    this.nodeIndex.delete(agentId);
    this.removeFromRoleIndex(node);

    this.state.edges = this.state.edges.filter(
      (e) => e.from !== agentId && e.to !== agentId,
    );

    this.adjacencyList.delete(agentId);
    for (const neighbors of this.adjacencyList.values()) {
      neighbors.delete(agentId);
    }

    for (const n of this.state.nodes) {
      n.connections = n.connections.filter((c) => c !== agentId);
    }

    if (this.state.leaderId === agentId) {
      if (this.state.nodes.length > 0) {
        this.electLeader();
      } else {
        this.state.leaderId = null;
      }
    }

    for (const partition of this.state.partitions) {
      partition.nodeIds = partition.nodeIds.filter((n) => n !== agentId);
      if (partition.leaderId === agentId) {
        partition.leaderId = partition.nodeIds[0] ?? "";
      }
    }

    this.emitTopologyUpdated();

    if (this.config.autoRebalance) {
      this.rebalance();
    }
  }

  updateNode(agentId: string, updates: Partial<TopologyNode>): void {
    const node = this.nodeIndex.get(agentId);
    if (!node) {
      throw new Error(`Node ${agentId} not found`);
    }

    if (updates.role !== undefined && updates.role !== node.role) {
      this.removeFromRoleIndex({ ...node });
      node.role = updates.role;
      this.addToRoleIndex(node);
    }
    if (updates.status !== undefined) node.status = updates.status;
    if (updates.connections !== undefined) {
      node.connections = updates.connections;
      this.adjacencyList.set(agentId, new Set(updates.connections));
      this.rebuildEdgesFromConnections();
    }
    if (updates.metadata !== undefined) {
      node.metadata = { ...node.metadata, ...updates.metadata };
    }
  }

  electLeader(): string {
    if (this.state.nodes.length === 0) {
      throw new Error("No nodes available for leader election");
    }

    const effectiveType = this.resolveEffectiveType();

    if (effectiveType === "hierarchical") {
      const queen = this.queenNode;
      if (queen) {
        this.state.leaderId = queen.agentId;
        this.electionTerm++;
        this.emitLeaderElected(queen.agentId);
        return queen.agentId;
      }
    }

    if (effectiveType === "centralized") {
      const coordinator = this.coordinatorNode;
      if (coordinator) {
        this.state.leaderId = coordinator.agentId;
        this.electionTerm++;
        this.emitLeaderElected(coordinator.agentId);
        return coordinator.agentId;
      }
    }

    const candidates = this.state.nodes
      .filter((n) => n.status === "active")
      .sort((a, b) => {
        const roleOrder: Record<TopologyNodeRole, number> = {
          queen: 0,
          coordinator: 1,
          worker: 2,
          peer: 2,
        };
        return roleOrder[a.role] - roleOrder[b.role];
      });

    if (candidates.length === 0) {
      throw new Error("No active nodes available for leader election");
    }

    const leader = candidates[0]!;
    this.state.leaderId = leader.agentId;
    this.electionTerm++;
    this.emitLeaderElected(leader.agentId);

    return leader.agentId;
  }

  rebalance(): void {
    const now = Date.now();
    const timeSinceLastRebalance = now - this.lastRebalanceAt;

    if (timeSinceLastRebalance < 5000) {
      return;
    }

    this.lastRebalanceAt = now;

    const effectiveType = this.resolveEffectiveType();

    switch (effectiveType) {
      case "mesh":
        this.rebalanceMesh();
        break;
      case "hierarchical":
        this.rebalanceHierarchical();
        break;
      case "centralized":
        this.rebalanceCentralized();
        break;
      case "hybrid":
        this.rebalanceHybrid();
        break;
      case "adaptive":
        break;
    }

    this.rebuildEdgesFromConnections();

    this.events.emit("topology.rebalanced", {
      kind: "topology.rebalanced",
      movedAgents: [],
      topology: this.getState(),
      sourceAgentId: null,
      timestamp: Date.now(),
    });
  }

  /** BFS shortest path between two nodes. */
  findOptimalPath(from: string, to: string): string[] {
    if (from === to) {
      return [from];
    }

    const visited = new Set<string>();
    const queue: Array<{ node: string; path: string[] }> = [
      { node: from, path: [from] },
    ];

    while (queue.length > 0) {
      const current = queue.shift()!;

      if (current.node === to) {
        return current.path;
      }

      if (visited.has(current.node)) {
        continue;
      }
      visited.add(current.node);

      const neighbors = this.adjacencyList.get(current.node) ?? new Set<string>();
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          queue.push({ node: neighbor, path: [...current.path, neighbor] });
        }
      }
    }

    return [];
  }

  getNeighbors(agentId: string): string[] {
    return Array.from(this.adjacencyList.get(agentId) ?? []);
  }

  getState(): TopologyState {
    return globalThis.structuredClone({
      ...this.state,
      nodes: [...this.state.nodes],
      edges: [...this.state.edges],
      partitions: [...this.state.partitions],
      snapshotAt: Date.now(),
    });
  }

  getNode(agentId: string): TopologyNode | undefined {
    return this.nodeIndex.get(agentId);
  }

  getLeader(): string | null {
    return this.state.leaderId;
  }

  getQueen(): TopologyNode | undefined {
    return this.queenNode ?? undefined;
  }

  getCoordinator(): TopologyNode | undefined {
    return this.coordinatorNode ?? undefined;
  }

  getActiveNodes(): TopologyNode[] {
    return this.state.nodes.filter((n) => n.status === "active");
  }

  getNodesByRole(role: TopologyNodeRole): TopologyNode[] {
    const roleSet = this.roleIndex.get(role);
    if (!roleSet) return [];

    const nodes: TopologyNode[] = [];
    for (const agentId of roleSet) {
      const node = this.nodeIndex.get(agentId);
      if (node) nodes.push(node);
    }
    return nodes;
  }

  getPartition(partitionId: string): TopologyPartition | undefined {
    return this.state.partitions.find((p) => p.id === partitionId);
  }

  isConnected(from: string, to: string): boolean {
    return this.adjacencyList.get(from)?.has(to) ?? false;
  }

  getConnectionCount(): number {
    return this.state.edges.length;
  }

  getAverageConnections(): number {
    if (this.state.nodes.length === 0) return 0;
    const total = this.state.nodes.reduce(
      (sum, n) => sum + n.connections.length,
      0,
    );
    return total / this.state.nodes.length;
  }

  dispose(): void {
    this.nodeIndex.clear();
    this.adjacencyList.clear();
    this.roleIndex.clear();
    this.queenNode = null;
    this.coordinatorNode = null;
    this.state.nodes = [];
    this.state.edges = [];
    this.state.partitions = [];
    this.state.leaderId = null;
  }

  private resolveEffectiveType(): TopologyType {
    if (this.config.type !== "adaptive") {
      return this.config.type;
    }

    const count = this.nodeIndex.size;
    if (count < this.adaptiveThresholds.meshMax) {
      return "mesh";
    }
    if (count < this.adaptiveThresholds.hierarchicalMax) {
      return "hierarchical";
    }
    return "hybrid";
  }

  private checkAdaptiveTransition(): void {
    if (this.config.type !== "adaptive") return;

    const newEffective = this.resolveEffectiveType();
    if (newEffective !== this.lastEffectiveType) {
      this.lastEffectiveType = newEffective;
    }
  }

  private determineRole(
    requestedRole: TopologyNodeRole,
    effectiveType: TopologyType,
  ): TopologyNodeRole {
    switch (effectiveType) {
      case "mesh":
        return "peer";
      case "hierarchical":
        if (this.state.nodes.length === 0) {
          return "queen";
        }
        return requestedRole === "queen" && !this.hasQueen() ? "queen" : "worker";
      case "centralized":
        if (this.state.nodes.length === 0) {
          return "coordinator";
        }
        return "worker";
      case "hybrid":
        return requestedRole;
      case "adaptive":
        return requestedRole;
    }
  }

  private hasQueen(): boolean {
    return this.queenNode !== null;
  }

  private calculateInitialConnections(
    _agentId: string,
    role: TopologyNodeRole,
    effectiveType: TopologyType,
  ): string[] {
    const existingNodes = Array.from(this.nodeIndex.keys());

    switch (effectiveType) {
      case "mesh": {
        const maxMeshConnections = Math.min(10, existingNodes.length);
        return existingNodes.slice(0, maxMeshConnections);
      }

      case "hierarchical": {
        if (role === "queen" || existingNodes.length === 0) {
          return existingNodes;
        }
        return this.queenNode ? [this.queenNode.agentId] : [];
      }

      case "centralized": {
        if (role === "coordinator" || existingNodes.length === 0) {
          return existingNodes;
        }
        return this.coordinatorNode ? [this.coordinatorNode.agentId] : [];
      }

      case "hybrid": {
        const leaders = this.state.nodes.filter(
          (n) => n.role === "queen" || n.role === "coordinator",
        );
        const peers = existingNodes.slice(0, 3);
        return [...new Set([...leaders.map((l) => l.agentId), ...peers])];
      }

      case "adaptive":
        return existingNodes.slice(0, 3);
    }
  }

  private createEdgesForNode(node: TopologyNode, effectiveType: TopologyType): void {
    for (const connectionId of node.connections) {
      const isBidirectional = effectiveType === "mesh";

      const edge: TopologyEdge = {
        from: node.agentId,
        to: connectionId,
        weight: 1,
        bidirectional: isBidirectional,
        latencyMs: null,
        edgeType: "topology",
      };

      this.state.edges.push(edge);

      // Reverse adjacency for BFS traversal; mesh also updates visible connections.
      const existingNode = this.nodeIndex.get(connectionId);
      if (existingNode) {
        this.adjacencyList.get(connectionId)?.add(node.agentId);
        if (isBidirectional && !existingNode.connections.includes(node.agentId)) {
          existingNode.connections.push(node.agentId);
        }
      }
    }
  }

  private updatePartitions(node: TopologyNode, effectiveType: TopologyType): void {
    if (effectiveType !== "mesh" && effectiveType !== "hybrid") {
      return;
    }

    const nodesPerPartition = Math.ceil(this.config.maxAgents / 10);
    // length - 1: the node was already pushed before this call
    const partitionIndex = Math.floor((this.state.nodes.length - 1) / nodesPerPartition);

    if (this.state.partitions.length <= partitionIndex) {
      const partition: TopologyPartition = {
        id: `partition_${partitionIndex}`,
        nodeIds: [node.agentId],
        leaderId: node.agentId,
        replicaCount: 1,
      };
      this.state.partitions.push(partition);
    } else {
      const partition = this.state.partitions[partitionIndex]!;
      partition.nodeIds.push(node.agentId);
      partition.replicaCount = Math.min(
        partition.nodeIds.length,
        this.config.replicationFactor ?? 2,
      );
    }
  }

  private shouldRebalance(): boolean {
    if (this.resolveEffectiveType() === "mesh") {
      const avgConnections =
        this.state.nodes.reduce((sum, n) => sum + n.connections.length, 0) /
        Math.max(1, this.state.nodes.length);

      for (const node of this.state.nodes) {
        if (
          Math.abs(node.connections.length - avgConnections) >
          avgConnections * 0.5
        ) {
          return true;
        }
      }
    }

    return false;
  }

  private rebalanceMesh(): void {
    const targetConnections = Math.min(5, this.state.nodes.length - 1);

    for (const node of this.state.nodes) {
      const connectionSet = new Set(node.connections);
      while (node.connections.length < targetConnections) {
        const candidates = this.state.nodes.filter(
          (n) =>
            n.agentId !== node.agentId &&
            !connectionSet.has(n.agentId),
        );

        if (candidates.length === 0) break;

        fisherYatesShuffle(candidates, this.state.snapshotAt);

        const target = candidates[0]!;
        node.connections.push(target.agentId);
        connectionSet.add(target.agentId);
        this.adjacencyList.get(node.agentId)?.add(target.agentId);

        target.connections.push(node.agentId);
        this.adjacencyList.get(target.agentId)?.add(node.agentId);

      }
    }
  }

  private rebalanceHierarchical(): void {
    let queen = this.queenNode;
    if (!queen) {
      if (this.state.nodes.length > 0) {
        const newQueen = this.state.nodes[0]!;
        newQueen.role = "queen";
        this.addToRoleIndex(newQueen);
        queen = newQueen;
      } else {
        return;
      }
    }

    const queenConnectionSet = new Set(queen.connections);
    for (const node of this.state.nodes) {
      const nodeConnectionSet = new Set(node.connections);
      if (node.role === "worker" && !nodeConnectionSet.has(queen.agentId)) {
        node.connections.push(queen.agentId);
        this.adjacencyList.get(node.agentId)?.add(queen.agentId);
        if (!queenConnectionSet.has(node.agentId)) {
          queen.connections.push(node.agentId);
          queenConnectionSet.add(node.agentId);
          this.adjacencyList.get(queen.agentId)?.add(node.agentId);
        }
      }
    }
  }

  private rebalanceCentralized(): void {
    let coordinator = this.coordinatorNode;
    if (!coordinator) {
      if (this.state.nodes.length > 0) {
        const newCoord = this.state.nodes[0]!;
        newCoord.role = "coordinator";
        this.addToRoleIndex(newCoord);
        coordinator = newCoord;
      } else {
        return;
      }
    }

    const coordConnectionSet = new Set(coordinator.connections);
    for (const node of this.state.nodes) {
      const nodeConnectionSet = new Set(node.connections);
      if (
        node.role !== "coordinator" &&
        !nodeConnectionSet.has(coordinator.agentId)
      ) {
        node.connections = [coordinator.agentId];
        this.adjacencyList.set(node.agentId, new Set([coordinator.agentId]));
        if (!coordConnectionSet.has(node.agentId)) {
          coordinator.connections.push(node.agentId);
          coordConnectionSet.add(node.agentId);
          this.adjacencyList.get(coordinator.agentId)?.add(node.agentId);
        }
      }
    }
  }

  private rebalanceHybrid(): void {
    const coordinators = this.state.nodes.filter(
      (n) => n.role === "queen" || n.role === "coordinator",
    );
    const workers = this.state.nodes.filter(
      (n) => n.role === "worker" || n.role === "peer",
    );
    const workerIdSet = new Set(workers.map((w) => w.agentId));

    // Connect workers in mesh (limited connections)
    for (const worker of workers) {
      const targetConnections = Math.min(3, workers.length - 1);
      const workerConnectionSet = new Set(
        worker.connections.filter((c) => workerIdSet.has(c)),
      );

      while (workerConnectionSet.size < targetConnections) {
        const candidates = workers.filter(
          (w) =>
            w.agentId !== worker.agentId &&
            !workerConnectionSet.has(w.agentId),
        );
        if (candidates.length === 0) break;

        fisherYatesShuffle(candidates, this.state.snapshotAt);

        const target = candidates[0]!;
        worker.connections.push(target.agentId);
        workerConnectionSet.add(target.agentId);
        this.adjacencyList.get(worker.agentId)?.add(target.agentId);
      }
    }

    if (coordinators.length > 0) {
      for (const worker of workers) {
        const connectionSet = new Set(worker.connections);
        const hasCoordinator = coordinators.some((coord) =>
          connectionSet.has(coord.agentId),
        );
        if (!hasCoordinator) {
          const idx = this.state.snapshotAt % coordinators.length;
          const coord = coordinators[idx]!;
          worker.connections.push(coord.agentId);
          this.adjacencyList.get(worker.agentId)?.add(coord.agentId);
          if (!new Set(coord.connections).has(worker.agentId)) {
            coord.connections.push(worker.agentId);
            this.adjacencyList.get(coord.agentId)?.add(worker.agentId);
          }
        }
      }
    }
  }

  private rebuildEdgesFromConnections(): void {
    const edges: TopologyEdge[] = [];
    const bidirectionalPairs = new Set<string>();

    for (const node of this.state.nodes) {
      for (const connectionId of new Set(node.connections)) {
        const reverseConnected =
          this.nodeIndex.get(connectionId)?.connections.includes(node.agentId) ??
          false;

        if (reverseConnected) {
          const pairKey = [node.agentId, connectionId].sort().join("::");
          if (bidirectionalPairs.has(pairKey)) {
            continue;
          }
          bidirectionalPairs.add(pairKey);
        }

        edges.push({
          from: node.agentId,
          to: connectionId,
          weight: 1,
          bidirectional: reverseConnected,
          latencyMs: null,
          edgeType: "topology",
        });
      }
    }

    this.state.edges = edges;
  }

  private addToRoleIndex(node: TopologyNode): void {
    let roleSet = this.roleIndex.get(node.role);
    if (!roleSet) {
      roleSet = new Set();
      this.roleIndex.set(node.role, roleSet);
    }
    roleSet.add(node.agentId);

    if (node.role === "queen") {
      this.queenNode = node;
    } else if (node.role === "coordinator") {
      this.coordinatorNode = node;
    }
  }

  private removeFromRoleIndex(node: TopologyNode): void {
    const roleSet = this.roleIndex.get(node.role);
    if (roleSet) {
      roleSet.delete(node.agentId);
    }

    if (node.role === "queen" && this.queenNode?.agentId === node.agentId) {
      this.queenNode = null;
    } else if (
      node.role === "coordinator" &&
      this.coordinatorNode?.agentId === node.agentId
    ) {
      this.coordinatorNode = null;
    }
  }

  private emitTopologyUpdated(): void {
    const previousType = this.lastEffectiveType;
    const currentEffective = this.resolveEffectiveType();
    this.lastEffectiveType = currentEffective;

    this.events.emit("topology.updated", {
      kind: "topology.updated",
      previousType,
      newTopology: this.getState(),
      sourceAgentId: null,
      timestamp: Date.now(),
    });
  }

  private emitLeaderElected(leaderId: string): void {
    this.events.emit("topology.leader_elected", {
      kind: "topology.leader_elected",
      leaderId,
      term: this.electionTerm,
      electionDurationMs: 0,
      sourceAgentId: null,
      timestamp: Date.now(),
    });
  }
}

/** In-place Fisher-Yates shuffle using a seeded xorshift PRNG. */
function fisherYatesShuffle<T>(arr: T[], seed: number): void {
  let s = seed | 0;
  for (let i = arr.length - 1; i > 0; i--) {
    s = (s ^ (s << 13)) | 0;
    s = (s ^ (s >> 17)) | 0;
    s = (s ^ (s << 5)) | 0;
    const j = ((s >>> 0) % (i + 1));
    const tmp = arr[i]!;
    arr[i] = arr[j]!;
    arr[j] = tmp;
  }
}
