/** Consensus engine factory for Raft, Byzantine, and Gossip. */

import type { TypedEventEmitter, SwarmEngineEventMap } from "../events.js";
import type {
  ConsensusConfig,
  ConsensusProposal,
  ConsensusResult,
} from "../types.js";
import { SWARM_ENGINE_CONSTANTS } from "../types.js";
import { RaftConsensus } from "./raft.js";
import type { RaftConfig } from "./raft.js";
import { ByzantineConsensus } from "./byzantine.js";
import type { ByzantineConfig } from "./byzantine.js";
import { GossipConsensus } from "./gossip.js";
import type { GossipConfig } from "./gossip.js";

export { RaftConsensus, ByzantineConsensus, GossipConsensus };
export type { RaftConfig, ByzantineConfig, GossipConfig };

type ConsensusImplementation =
  | RaftConsensus
  | ByzantineConsensus
  | GossipConsensus;

export class ConsensusEngine {
  private readonly events: TypedEventEmitter<SwarmEngineEventMap>;
  private readonly nodeId: string;
  private config: ConsensusConfig;
  private implementation: ConsensusImplementation | null = null;

  constructor(
    events: TypedEventEmitter<SwarmEngineEventMap>,
    nodeId: string,
    config?: Partial<ConsensusConfig>,
  ) {
    this.events = events;
    this.nodeId = nodeId;
    this.config = {
      algorithm: config?.algorithm ?? "raft",
      threshold:
        config?.threshold ?? SWARM_ENGINE_CONSTANTS.DEFAULT_CONSENSUS_THRESHOLD,
      timeoutMs:
        config?.timeoutMs ??
        SWARM_ENGINE_CONSTANTS.DEFAULT_CONSENSUS_TIMEOUT_MS,
      maxRounds: config?.maxRounds ?? 10,
      requireQuorum: config?.requireQuorum ?? true,
    };
  }

  initialize(config?: Partial<ConsensusConfig>): void {
    if (config) {
      this.config = { ...this.config, ...config };
    }

    const baseConfig = {
      threshold: this.config.threshold,
      timeoutMs: this.config.timeoutMs,
      maxRounds: this.config.maxRounds,
      requireQuorum: this.config.requireQuorum,
    };

    switch (this.config.algorithm) {
      case "raft":
        this.implementation = new RaftConsensus(
          this.events,
          this.nodeId,
          baseConfig,
        );
        break;

      case "byzantine":
        this.implementation = new ByzantineConsensus(
          this.events,
          this.nodeId,
          baseConfig,
        );
        break;

      case "gossip":
        this.implementation = new GossipConsensus(
          this.events,
          this.nodeId,
          baseConfig,
        );
        break;

      case "paxos":
        throw new Error("Paxos algorithm is not yet implemented");

      default:
        throw new Error(
          `Unknown consensus algorithm: ${this.config.algorithm as string}`,
        );
    }

    this.implementation.initialize();
  }

  addNode(nodeId: string, options?: { isPrimary?: boolean }): void {
    if (!this.implementation) {
      throw new Error("Consensus engine not initialized");
    }

    if (this.implementation instanceof RaftConsensus) {
      this.implementation.addPeer(nodeId);
    } else if (this.implementation instanceof ByzantineConsensus) {
      this.implementation.addNode(nodeId, options?.isPrimary);
    } else if (this.implementation instanceof GossipConsensus) {
      this.implementation.addNode(nodeId);
    }
  }

  removeNode(nodeId: string): void {
    if (!this.implementation) {
      return;
    }

    if (this.implementation instanceof RaftConsensus) {
      this.implementation.removePeer(nodeId);
    } else if (this.implementation instanceof ByzantineConsensus) {
      this.implementation.removeNode(nodeId);
    } else if (this.implementation instanceof GossipConsensus) {
      this.implementation.removeNode(nodeId);
    }
  }

  propose(value: Record<string, unknown>): ConsensusProposal {
    if (!this.implementation) {
      throw new Error("Consensus engine not initialized");
    }

    return this.implementation.propose(value);
  }

  vote(proposalId: string, approve: boolean, confidence?: number): void {
    if (!this.implementation) {
      throw new Error("Consensus engine not initialized");
    }

    this.implementation.vote(proposalId, approve, confidence);
  }

  awaitConsensus(proposalId: string): Promise<ConsensusResult> {
    if (!this.implementation) {
      throw new Error("Consensus engine not initialized");
    }

    return this.implementation.awaitConsensus(proposalId);
  }

  getActiveProposals(): Record<string, ConsensusProposal> {
    if (!this.implementation) {
      return {};
    }

    return this.implementation.getActiveProposals();
  }

  getAlgorithm(): ConsensusConfig["algorithm"] {
    return this.config.algorithm;
  }

  getConfig(): ConsensusConfig {
    return { ...this.config };
  }

  /** Gossip has no leader concept and always returns false. */
  isLeader(): boolean {
    if (this.implementation instanceof RaftConsensus) {
      return this.implementation.isLeader();
    }
    if (this.implementation instanceof ByzantineConsensus) {
      return this.implementation.getIsPrimary();
    }
    return false;
  }

  dispose(): void {
    if (this.implementation) {
      this.implementation.dispose();
      this.implementation = null;
    }
  }
}
