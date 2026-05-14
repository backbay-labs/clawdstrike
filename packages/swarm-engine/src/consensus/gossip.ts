/** Gossip protocol consensus -- eventually consistent. */

import type { TypedEventEmitter, SwarmEngineEventMap } from "../events.js";
import type {
  ConsensusProposal,
  ConsensusVote,
  ConsensusResult,
} from "../types.js";
import { SWARM_ENGINE_CONSTANTS } from "../types.js";
import { generateSwarmId } from "../ids.js";

export interface GossipMessage {
  id: string;
  type: "proposal" | "vote" | "state" | "ack";
  senderId: string;
  version: number;
  payload: Record<string, unknown>;
  timestamp: number;
  ttl: number;
  hops: number;
  path: string[];
}

export interface GossipNode {
  id: string;
  state: Map<string, unknown>;
  version: number;
  neighbors: Set<string>;
  seenMessages: Set<string>;
  lastSync: number;
}

export interface GossipConfig {
  threshold?: number;
  timeoutMs?: number;
  maxRounds?: number;
  requireQuorum?: boolean;
  fanout?: number;
  gossipIntervalMs?: number;
  maxHops?: number;
  convergenceThreshold?: number;
}

interface QueuedGossipMessage {
  senderId: string;
  message: GossipMessage;
}

export class GossipConsensus {
  private readonly events: TypedEventEmitter<SwarmEngineEventMap>;
  private readonly config: Required<GossipConfig>;
  private readonly node: GossipNode;
  private readonly nodes: Map<string, GossipNode> = new Map();
  private readonly proposals: Map<string, ConsensusProposal> = new Map();
  private readonly proposalVotes: Map<string, Map<string, ConsensusVote>> =
    new Map();
  private readonly messageQueue: QueuedGossipMessage[] = [];
  private gossipInterval: ReturnType<typeof setInterval> | null = null;

  constructor(
    events: TypedEventEmitter<SwarmEngineEventMap>,
    nodeId: string,
    config?: GossipConfig,
  ) {
    this.events = events;
    this.config = {
      threshold:
        config?.threshold ?? SWARM_ENGINE_CONSTANTS.DEFAULT_CONSENSUS_THRESHOLD,
      timeoutMs:
        config?.timeoutMs ??
        SWARM_ENGINE_CONSTANTS.DEFAULT_CONSENSUS_TIMEOUT_MS,
      maxRounds: config?.maxRounds ?? 10,
      requireQuorum: config?.requireQuorum ?? false,
      fanout: config?.fanout ?? 3,
      gossipIntervalMs: config?.gossipIntervalMs ?? 100,
      maxHops: config?.maxHops ?? 10,
      convergenceThreshold: config?.convergenceThreshold ?? 0.9,
    };

    this.node = {
      id: nodeId,
      state: new Map(),
      version: 0,
      neighbors: new Set(),
      seenMessages: new Set(),
      lastSync: Date.now(),
    };
  }

  initialize(): void {
    this.startGossipLoop();
  }

  addNode(nodeId: string): void {
    this.nodes.set(nodeId, {
      id: nodeId,
      state: new Map(),
      version: 0,
      neighbors: new Set(),
      seenMessages: new Set(),
      lastSync: Date.now(),
    });

    if (Math.random() < 0.5) {
      this.node.neighbors.add(nodeId);
      this.nodes.get(nodeId)!.neighbors.add(this.node.id);
    }
  }

  removeNode(nodeId: string): void {
    this.nodes.delete(nodeId);
    this.node.neighbors.delete(nodeId);

    for (const node of this.nodes.values()) {
      node.neighbors.delete(nodeId);
    }
  }

  addNeighbor(nodeId: string): void {
    if (this.nodes.has(nodeId)) {
      this.node.neighbors.add(nodeId);
    }
  }

  removeNeighbor(nodeId: string): void {
    this.node.neighbors.delete(nodeId);
  }

  propose(value: Record<string, unknown>): ConsensusProposal {
    const proposalId = generateSwarmId("csn");

    const voteMap = new Map<string, ConsensusVote>();
    this.proposalVotes.set(proposalId, voteMap);

    const proposal: ConsensusProposal = {
      id: proposalId,
      proposerId: this.node.id,
      value,
      term: this.node.version,
      timestamp: Date.now(),
      votes: [],
      status: "pending",
    };

    this.proposals.set(proposalId, proposal);

    const selfVote: ConsensusVote = {
      voterId: this.node.id,
      approve: true,
      confidence: 1.0,
      timestamp: Date.now(),
    };
    voteMap.set(this.node.id, selfVote);
    proposal.votes = Array.from(voteMap.values());

    const message: GossipMessage = {
      id: `msg_${proposalId}`,
      type: "proposal",
      senderId: this.node.id,
      version: ++this.node.version,
      payload: { proposalId, value },
      timestamp: Date.now(),
      ttl: this.config.maxHops,
      hops: 0,
      path: [this.node.id],
    };

    this.node.seenMessages.add(message.id);
    this.queueMessage(this.node.id, message);

    this.events.emit("consensus.proposed", {
      kind: "consensus.proposed",
      sourceAgentId: this.node.id,
      timestamp: Date.now(),
      proposal,
    });

    this.checkConvergence(proposalId);

    return proposal;
  }

  vote(
    proposalId: string,
    approve: boolean,
    confidence?: number,
  ): void {
    const proposal = this.proposals.get(proposalId);
    if (!proposal) {
      return;
    }

    const voteMap =
      this.proposalVotes.get(proposalId) ?? new Map<string, ConsensusVote>();
    if (!this.proposalVotes.has(proposalId)) {
      this.proposalVotes.set(proposalId, voteMap);
    }

    const vote: ConsensusVote = {
      voterId: this.node.id,
      approve,
      confidence: confidence ?? 1.0,
      timestamp: Date.now(),
    };

    voteMap.set(vote.voterId, vote);
    proposal.votes = Array.from(voteMap.values());

    const message: GossipMessage = {
      id: `vote_${proposalId}_${vote.voterId}`,
      type: "vote",
      senderId: this.node.id,
      version: ++this.node.version,
      payload: { proposalId, vote: vote as unknown as Record<string, unknown> },
      timestamp: Date.now(),
      ttl: this.config.maxHops,
      hops: 0,
      path: [this.node.id],
    };

    this.node.seenMessages.add(message.id);
    this.queueMessage(this.node.id, message);

    this.events.emit("consensus.vote_cast", {
      kind: "consensus.vote_cast",
      sourceAgentId: vote.voterId,
      timestamp: Date.now(),
      proposalId,
      vote,
    });

    this.checkConvergence(proposalId);
  }

  awaitConsensus(proposalId: string): Promise<ConsensusResult> {
    const startTime = Date.now();

    return new Promise((resolve, reject) => {
      const proposal = this.proposals.get(proposalId);
      if (!proposal) {
        reject(new Error(`Proposal ${proposalId} not found`));
        return;
      }

      if (proposal.status !== "pending") {
        resolve(this.createResult(proposal, Date.now() - startTime));
        return;
      }

      const cleanup = this.events.on("consensus.resolved", (event) => {
        if (event.result.proposalId === proposalId) {
          cleanup();
          if (timer !== null) {
            clearTimeout(timer);
          }
          resolve(event.result);
        }
      });

      const timer = setTimeout(() => {
        cleanup();
        const p = this.proposals.get(proposalId);
        if (p && p.status === "pending") {
          const totalNodes = this.nodes.size + 1;
          const voteMap = this.proposalVotes.get(proposalId);
          const votes = voteMap ? voteMap.size : 0;

          if (votes / totalNodes >= this.config.convergenceThreshold) {
            p.status = "accepted";
          } else {
            p.status = "expired";
          }

          resolve(this.createResult(p, Date.now() - startTime));
        }
      }, this.config.timeoutMs);
    });
  }

  getConvergence(proposalId: string): number {
    const voteMap = this.proposalVotes.get(proposalId);
    if (!voteMap) return 0;

    const totalNodes = this.nodes.size + 1;
    return voteMap.size / totalNodes;
  }

  getVersion(): number {
    return this.node.version;
  }

  getNeighborCount(): number {
    return this.node.neighbors.size;
  }

  getSeenMessageCount(): number {
    return this.node.seenMessages.size;
  }

  getQueueDepth(): number {
    return this.messageQueue.length;
  }

  getActiveProposals(): Record<string, ConsensusProposal> {
    const result: Record<string, ConsensusProposal> = {};
    for (const [id, proposal] of this.proposals) {
      if (proposal.status === "pending") {
        const voteMap = this.proposalVotes.get(id);
        if (voteMap) {
          proposal.votes = Array.from(voteMap.values());
        }
        result[id] = proposal;
      }
    }
    return result;
  }

  dispose(): void {
    if (this.gossipInterval !== null) {
      clearInterval(this.gossipInterval);
      this.gossipInterval = null;
    }
  }

  antiEntropy(): void {
    if (this.node.neighbors.size === 0) return;

    const neighbors = Array.from(this.node.neighbors);
    const randomNeighbor =
      neighbors[Math.floor(Math.random() * neighbors.length)]!;

    const stateMessage: GossipMessage = {
      id: `state_${this.node.id}_${Date.now()}`,
      type: "state",
      senderId: this.node.id,
      version: this.node.version,
      payload: Object.fromEntries(this.node.state),
      timestamp: Date.now(),
      ttl: 1,
      hops: 0,
      path: [this.node.id],
    };

    this.sendToNeighbor(randomNeighbor, stateMessage);
  }

  private startGossipLoop(): void {
    this.gossipInterval = setInterval(() => {
      this.gossipRound();
    }, this.config.gossipIntervalMs);
  }

  private gossipRound(): void {
    if (this.messageQueue.length === 0) {
      return;
    }

    const queuedMessages = this.messageQueue.splice(0, 10);

    for (const { senderId, message } of queuedMessages) {
      const sender = this.getNode(senderId);
      if (!sender) {
        continue;
      }

      const fanout = Math.min(this.config.fanout, sender.neighbors.size);
      const neighbors = this.selectRandomNeighbors(sender.neighbors, fanout);
      for (const neighborId of neighbors) {
        this.sendToNeighbor(neighborId, message);
      }

      sender.lastSync = Date.now();
    }

    this.node.lastSync = Date.now();
  }

  private selectRandomNeighbors(
    neighborSet: Set<string>,
    count: number,
  ): string[] {
    const neighbors = Array.from(neighborSet);
    const selected: string[] = [];

    while (selected.length < count && neighbors.length > 0) {
      const idx = Math.floor(Math.random() * neighbors.length);
      selected.push(neighbors.splice(idx, 1)[0]!);
    }

    return selected;
  }

  private sendToNeighbor(neighborId: string, message: GossipMessage): void {
    const neighbor = this.nodes.get(neighborId);
    if (!neighbor) {
      return;
    }

    if (neighbor.seenMessages.has(message.id)) {
      return;
    }

    const deliveredMessage: GossipMessage = {
      ...message,
      hops: message.hops + 1,
      path: [...message.path, neighborId],
    };

    this.processReceivedMessage(neighbor, deliveredMessage);
  }

  private processReceivedMessage(
    node: GossipNode,
    message: GossipMessage,
  ): void {
    node.seenMessages.add(message.id);

    if (message.ttl <= 0 || message.hops >= this.config.maxHops) {
      return;
    }

    switch (message.type) {
      case "proposal":
        this.handleProposalMessage(node, message);
        break;
      case "vote":
        this.handleVoteMessage(message);
        break;
      case "state":
        this.handleStateMessage(node, message);
        break;
    }

    if (message.hops < this.config.maxHops) {
      const propagateMessage: GossipMessage = {
        ...message,
        ttl: message.ttl - 1,
      };

      if (propagateMessage.ttl > 0) {
        this.queueMessage(node.id, propagateMessage);
      }
    }
  }

  private handleProposalMessage(
    node: GossipNode,
    message: GossipMessage,
  ): void {
    const { proposalId, value } = message.payload as {
      proposalId: string;
      value: Record<string, unknown>;
    };

    if (!this.proposals.has(proposalId)) {
      const voteMap = new Map<string, ConsensusVote>();
      this.proposalVotes.set(proposalId, voteMap);

      const proposal: ConsensusProposal = {
        id: proposalId,
        proposerId: message.senderId,
        value,
        term: message.version,
        timestamp: message.timestamp,
        votes: [],
        status: "pending",
      };

      this.proposals.set(proposalId, proposal);

      if (node.id === this.node.id) {
        this.vote(proposalId, true, 0.9);
      }
    }
  }

  private handleVoteMessage(message: GossipMessage): void {
    const { proposalId, vote } = message.payload as {
      proposalId: string;
      vote: ConsensusVote;
    };

    const voteMap = this.proposalVotes.get(proposalId);
    if (voteMap && !voteMap.has(vote.voterId)) {
      voteMap.set(vote.voterId, vote);
      const proposal = this.proposals.get(proposalId);
      if (proposal) {
        proposal.votes = Array.from(voteMap.values());
      }
      this.checkConvergence(proposalId);
    }
  }

  private handleStateMessage(
    node: GossipNode,
    message: GossipMessage,
  ): void {
    const state = message.payload;

    if (message.version > node.version) {
      for (const [key, value] of Object.entries(state)) {
        node.state.set(key, value);
      }
      node.version = message.version;
    }
  }

  private queueMessage(senderId: string, message: GossipMessage): void {
    this.messageQueue.push({ senderId, message });
  }

  private getNode(nodeId: string): GossipNode | undefined {
    if (nodeId === this.node.id) {
      return this.node;
    }

    return this.nodes.get(nodeId);
  }

  private checkConvergence(proposalId: string): void {
    const proposal = this.proposals.get(proposalId);
    if (!proposal || proposal.status !== "pending") {
      return;
    }

    const voteMap = this.proposalVotes.get(proposalId);
    if (!voteMap) return;

    const totalNodes = this.nodes.size + 1;
    const votes = voteMap.size;

    if (votes / totalNodes >= this.config.convergenceThreshold) {
      const approvingVotes = Array.from(voteMap.values()).filter(
        (v) => v.approve,
      ).length;

      if (approvingVotes / votes >= this.config.threshold) {
        proposal.status = "accepted";
        proposal.votes = Array.from(voteMap.values());
        this.emitResolved(proposal);
      } else {
        proposal.status = "rejected";
        proposal.votes = Array.from(voteMap.values());
        this.emitResolved(proposal);
      }
    }
  }

  private emitResolved(proposal: ConsensusProposal): void {
    const voteMap = this.proposalVotes.get(proposal.id);
    const totalNodes = this.nodes.size + 1;
    const approvingVotes = voteMap
      ? Array.from(voteMap.values()).filter((v) => v.approve).length
      : 0;

    const result: ConsensusResult = {
      proposalId: proposal.id,
      approved: proposal.status === "accepted",
      approvalRate:
        voteMap && voteMap.size > 0 ? approvingVotes / voteMap.size : 0,
      participationRate: voteMap ? voteMap.size / totalNodes : 0,
      finalValue: proposal.value,
      rounds: this.node.version,
      durationMs: Date.now() - proposal.timestamp,
      receipt: null,
    };

    this.events.emit("consensus.resolved", {
      kind: "consensus.resolved",
      sourceAgentId: proposal.proposerId,
      timestamp: Date.now(),
      result,
    });
  }

  private createResult(
    proposal: ConsensusProposal,
    durationMs: number,
  ): ConsensusResult {
    const voteMap = this.proposalVotes.get(proposal.id);
    const totalNodes = this.nodes.size + 1;
    const approvingVotes = voteMap
      ? Array.from(voteMap.values()).filter((v) => v.approve).length
      : 0;

    return {
      proposalId: proposal.id,
      approved: proposal.status === "accepted",
      approvalRate:
        voteMap && voteMap.size > 0 ? approvingVotes / voteMap.size : 0,
      participationRate: voteMap ? voteMap.size / totalNodes : 0,
      finalValue: proposal.value,
      rounds: this.node.version,
      durationMs,
      receipt: null,
    };
  }
}
