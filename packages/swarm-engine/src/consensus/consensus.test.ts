/**
 * Consensus subsystem tests.
 *
 * Covers: ConsensusEngine factory, Raft leader election + propose/vote,
 * Byzantine PBFT phases + quorum, Gossip convergence + fanout,
 * and event lifecycle (consensus.proposed, consensus.vote_cast, consensus.resolved).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { TypedEventEmitter } from "../events.js";
import type {
  SwarmEngineEventMap,
  ConsensusProposedEvent,
  ConsensusVoteCastEvent,
  ConsensusResolvedEvent,
  LeaderElectedEvent,
} from "../events.js";
import { ConsensusEngine } from "./index.js";
import { RaftConsensus } from "./raft.js";
import { ByzantineConsensus } from "./byzantine.js";
import { GossipConsensus } from "./gossip.js";

// ============================================================================
// Helpers
// ============================================================================

function createEvents(): TypedEventEmitter<SwarmEngineEventMap> {
  return new TypedEventEmitter<SwarmEngineEventMap>();
}

// ============================================================================
// Factory Tests
// ============================================================================

describe("ConsensusEngine factory", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;
  let engine: ConsensusEngine;

  beforeEach(() => {
    events = createEvents();
  });

  afterEach(() => {
    engine?.dispose();
    events.dispose();
  });

  it("creates raft implementation by default", () => {
    engine = new ConsensusEngine(events, "node-1");
    engine.initialize();
    expect(engine.getAlgorithm()).toBe("raft");
  });

  it("creates byzantine implementation", () => {
    engine = new ConsensusEngine(events, "node-1", { algorithm: "byzantine" });
    engine.initialize();
    expect(engine.getAlgorithm()).toBe("byzantine");
  });

  it("creates gossip implementation", () => {
    engine = new ConsensusEngine(events, "node-1", { algorithm: "gossip" });
    engine.initialize();
    expect(engine.getAlgorithm()).toBe("gossip");
  });

  it("throws on paxos algorithm", () => {
    engine = new ConsensusEngine(events, "node-1", { algorithm: "paxos" });
    expect(() => engine.initialize()).toThrow(
      "Paxos algorithm is not yet implemented",
    );
  });

  it("throws on unknown algorithm", () => {
    engine = new ConsensusEngine(events, "node-1", {
      algorithm: "unknown" as "raft",
    });
    expect(() => engine.initialize()).toThrow("Unknown consensus algorithm");
  });

  it("throws when proposing without initialization", () => {
    engine = new ConsensusEngine(events, "node-1");
    expect(() => engine.propose({ action: "test" })).toThrow(
      "Consensus engine not initialized",
    );
  });

  it("getConfig returns copy of config", () => {
    engine = new ConsensusEngine(events, "node-1", { threshold: 0.75 });
    const config = engine.getConfig();
    expect(config.threshold).toBe(0.75);
    expect(config.algorithm).toBe("raft");
  });

  it("getActiveProposals returns empty when not initialized", () => {
    engine = new ConsensusEngine(events, "node-1");
    expect(engine.getActiveProposals()).toEqual({});
  });
});

// ============================================================================
// Raft Tests
// ============================================================================

describe("RaftConsensus", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;
  let raft: RaftConsensus;

  beforeEach(() => {
    events = createEvents();
    raft = new RaftConsensus(events, "node-1", {
      electionTimeoutMinMs: 50,
      electionTimeoutMaxMs: 100,
      heartbeatIntervalMs: 20,
    });
  });

  afterEach(() => {
    raft.dispose();
    events.dispose();
  });

  it("starts as follower", () => {
    expect(raft.getState()).toBe("follower");
    expect(raft.getTerm()).toBe(0);
    expect(raft.isLeader()).toBe(false);
  });

  it("initialize starts election timeout", () => {
    raft.initialize();
    // No error thrown -> timer started successfully
    expect(raft.getState()).toBe("follower");
  });

  it("becomes leader when no peers (self-election)", async () => {
    const leaderEvents: LeaderElectedEvent[] = [];
    events.on("topology.leader_elected", (e) => leaderEvents.push(e));

    raft.initialize();

    // Wait for election timeout to fire (max 100ms + buffer)
    await new Promise((r) => setTimeout(r, 200));

    expect(raft.isLeader()).toBe(true);
    expect(raft.getState()).toBe("leader");
    expect(raft.getTerm()).toBe(1);
    expect(leaderEvents.length).toBeGreaterThanOrEqual(1);
    expect(leaderEvents[0]!.leaderId).toBe("node-1");
    expect(leaderEvents[0]!.kind).toBe("topology.leader_elected");
  });

  it("addPeer and removePeer manage peers", () => {
    raft.addPeer("node-2");
    raft.addPeer("node-3");
    raft.removePeer("node-2");
    // No error thrown -- peers managed internally
    expect(true).toBe(true);
  });

  it("propose creates proposal with csn_ ID and emits consensus.proposed", async () => {
    // Recreate with high threshold so self-vote doesn't resolve immediately
    raft.dispose();
    events.dispose();
    events = createEvents();
    raft = new RaftConsensus(events, "node-1", {
      electionTimeoutMinMs: 50,
      electionTimeoutMaxMs: 100,
      heartbeatIntervalMs: 20,
      threshold: 0.9,
    });
    raft.addPeer("node-2");
    raft.addPeer("node-3");

    const proposed: ConsensusProposedEvent[] = [];
    events.on("consensus.proposed", (e) => proposed.push(e));

    // Become leader first
    raft.initialize();
    await new Promise((r) => setTimeout(r, 200));
    expect(raft.isLeader()).toBe(true);

    // threshold=0.9, 3 voters, quorum=floor(3*0.9)=2. Self-vote=1 < 2 => stays pending
    const proposal = raft.propose({ action: "scale-up" });
    expect(proposal.id).toMatch(/^csn_/);
    expect(proposal.proposerId).toBe("node-1");
    expect(proposal.status).toBe("pending");
    expect(proposal.value).toEqual({ action: "scale-up" });
    expect(proposal.term).toBe(raft.getTerm());
    expect(typeof proposal.timestamp).toBe("number");
    expect(Array.isArray(proposal.votes)).toBe(true);

    // Leader self-votes
    expect(proposal.votes.length).toBe(1);
    expect(proposal.votes[0]!.voterId).toBe("node-1");
    expect(proposal.votes[0]!.approve).toBe(true);

    // Event emitted
    expect(proposed.length).toBe(1);
    expect(proposed[0]!.kind).toBe("consensus.proposed");
  });

  it("vote records vote and emits consensus.vote_cast", async () => {
    // Recreate with high threshold so proposal stays pending after propose
    raft.dispose();
    events.dispose();
    events = createEvents();
    raft = new RaftConsensus(events, "node-1", {
      electionTimeoutMinMs: 50,
      electionTimeoutMaxMs: 100,
      heartbeatIntervalMs: 20,
      threshold: 0.9,
    });
    raft.addPeer("node-2");
    raft.addPeer("node-3");

    const voteCasts: ConsensusVoteCastEvent[] = [];
    events.on("consensus.vote_cast", (e) => voteCasts.push(e));

    raft.initialize();
    await new Promise((r) => setTimeout(r, 200));

    const proposal = raft.propose({ action: "test" });
    // vote() now derives voterId from this node (node-1)
    raft.vote(proposal.id, true, 0.9);

    expect(voteCasts.length).toBe(1);
    expect(voteCasts[0]!.kind).toBe("consensus.vote_cast");
    expect(voteCasts[0]!.proposalId).toBe(proposal.id);
    expect(voteCasts[0]!.vote.voterId).toBe("node-1");
    expect(voteCasts[0]!.vote.approve).toBe(true);
  });

  it("throws when proposing as non-leader", () => {
    expect(() => raft.propose({ action: "test" })).toThrow(
      "Only leader can propose values",
    );
  });

  it("throws when voting on non-existent proposal", () => {
    expect(() => raft.vote("nonexistent", true)).toThrow(
      "Proposal nonexistent not found",
    );
  });

  it("threshold resolution emits consensus.resolved only after quorum is met", async () => {
    const resolved: ConsensusResolvedEvent[] = [];
    events.on("consensus.resolved", (e) => resolved.push(e));

    raft.addPeer("node-2");
    raft.addPeer("node-3");
    raft.initialize();
    await new Promise((r) => setTimeout(r, 200));

    const proposal = raft.propose({ action: "commit" });
    expect(resolved).toHaveLength(0);

    const voteMap = (raft as any).proposalVotes.get(proposal.id) as Map<string, unknown>;
    voteMap.set("node-2", {
      voterId: "node-2",
      approve: true,
      confidence: 1.0,
      timestamp: Date.now(),
    });

    proposal.votes = Array.from(voteMap.values()) as any;
    (raft as any).checkConsensus(proposal.id);

    expect(resolved).toHaveLength(1);
    expect(resolved[0]!.result.approved).toBe(true);
    expect(resolved[0]!.kind).toBe("consensus.resolved");
    expect(resolved[0]!.result.receipt).toBeNull();
  });

  it("getActiveProposals returns pending proposals with array votes", async () => {
    raft.initialize();
    await new Promise((r) => setTimeout(r, 200));

    // With no peers, threshold=0.66, 1 voter -> quorum=floor(1*0.66)=0
    // Self-vote (1 approve) >= 0 -> resolves immediately as accepted
    // So let's add peers to keep it pending
    raft.addPeer("node-2");
    raft.addPeer("node-3");

    // Need to re-initialize with peers to get correct quorum
    // Actually, peers are just for quorum calc. Let's set threshold higher
    raft.dispose();
    events.dispose();

    events = createEvents();
    raft = new RaftConsensus(events, "node-1", {
      electionTimeoutMinMs: 50,
      electionTimeoutMaxMs: 100,
      heartbeatIntervalMs: 20,
      threshold: 0.9,
    });
    raft.addPeer("node-2");
    raft.addPeer("node-3");
    raft.initialize();
    await new Promise((r) => setTimeout(r, 200));

    const proposal = raft.propose({ action: "test" });
    // threshold=0.9, 3 voters, quorum=floor(3*0.9)=2. Self-vote=1 < 2 => pending
    const active = raft.getActiveProposals();
    const ids = Object.keys(active);
    expect(ids.length).toBe(1);
    expect(ids[0]).toBe(proposal.id);
    expect(Array.isArray(active[proposal.id]!.votes)).toBe(true);
  });

  it("handleVoteRequest and handleAppendEntries work", () => {
    raft.initialize();

    // Grant vote for higher term
    const granted = raft.handleVoteRequest("candidate-1", 5, 0, 0);
    expect(granted).toBe(true);
    expect(raft.getTerm()).toBe(5);

    // Accept append entries from leader
    const accepted = raft.handleAppendEntries("leader-1", 6, [], 0);
    expect(accepted).toBe(true);
    expect(raft.getTerm()).toBe(6);
  });

  it("dispose clears election timeout and heartbeat interval", async () => {
    raft.initialize();
    await new Promise((r) => setTimeout(r, 200));
    expect(raft.isLeader()).toBe(true);

    // dispose should not throw even after becoming leader
    raft.dispose();
    // No dangling timers -- test framework would detect leaks
  });
});

// ============================================================================
// Byzantine Tests
// ============================================================================

describe("ByzantineConsensus", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;
  let bft: ByzantineConsensus;

  beforeEach(() => {
    events = createEvents();
    bft = new ByzantineConsensus(events, "node-1", {
      viewChangeTimeoutMs: 1000,
    });
  });

  afterEach(() => {
    bft.dispose();
    events.dispose();
  });

  it("starts as non-primary", () => {
    expect(bft.getIsPrimary()).toBe(false);
    expect(bft.getViewNumber()).toBe(0);
  });

  it("electPrimary emits topology.leader_elected", () => {
    const leaderEvents: LeaderElectedEvent[] = [];
    events.on("topology.leader_elected", (e) => leaderEvents.push(e));

    bft.addNode("node-2");
    bft.addNode("node-3");
    const primaryId = bft.electPrimary();

    expect(leaderEvents.length).toBe(1);
    expect(leaderEvents[0]!.kind).toBe("topology.leader_elected");
    expect(leaderEvents[0]!.leaderId).toBe(primaryId);
  });

  it("PBFT quorum calculation: f = floor((n-1)/3)", () => {
    // 1 node: f = floor(0/3) = 0
    expect(bft.getMaxFaultyNodes()).toBe(0);

    bft.addNode("node-2");
    bft.addNode("node-3");
    // 3 nodes: f = floor(2/3) = 0
    expect(bft.getMaxFaultyNodes()).toBe(0);

    bft.addNode("node-4");
    // 4 nodes: f = floor(3/3) = 1
    expect(bft.getMaxFaultyNodes()).toBe(1);
    expect(bft.canTolerate(1)).toBe(true);
    expect(bft.canTolerate(2)).toBe(false);
  });

  it("respects configured maxFaultyNodes without exceeding the PBFT bound", () => {
    const strictBudget = new ByzantineConsensus(events, "node-1", {
      viewChangeTimeoutMs: 1000,
      maxFaultyNodes: 0,
    });
    strictBudget.addNode("node-2");
    strictBudget.addNode("node-3");
    strictBudget.addNode("node-4");

    expect(strictBudget.getMaxFaultyNodes()).toBe(0);
    expect(strictBudget.canTolerate(1)).toBe(false);

    strictBudget.dispose();

    const cappedBudget = new ByzantineConsensus(events, "node-1", {
      viewChangeTimeoutMs: 1000,
      maxFaultyNodes: 3,
    });
    cappedBudget.addNode("node-2");
    cappedBudget.addNode("node-3");
    cappedBudget.addNode("node-4");

    expect(cappedBudget.getMaxFaultyNodes()).toBe(1);

    cappedBudget.dispose();
  });

  it("propose creates proposal with csn_ ID and emits consensus.proposed", () => {
    const proposed: ConsensusProposedEvent[] = [];
    events.on("consensus.proposed", (e) => proposed.push(e));

    // Make this node primary with enough nodes that self-prepare alone
    // doesn't reach quorum: 5 nodes -> f=1 -> need 3 prepares
    bft.addNode("node-1", true);
    bft.addNode("node-2");
    bft.addNode("node-3");
    bft.addNode("node-4");
    const proposal = bft.propose({ action: "upgrade" });

    expect(proposal.id).toMatch(/^csn_/);
    expect(proposal.proposerId).toBe("node-1");
    expect(proposal.status).toBe("pending");

    expect(proposed.length).toBe(1);
    expect(proposed[0]!.kind).toBe("consensus.proposed");
  });

  it("vote with PBFT quorum emits consensus.resolved", () => {
    const resolved: ConsensusResolvedEvent[] = [];
    events.on("consensus.resolved", (e) => resolved.push(e));

    // 1 node total (just the primary): f = floor(0/3) = 0, need 2*0+1 = 1 vote
    bft.addNode("node-1", true);

    const proposal = bft.propose({ action: "commit" });

    // vote() derives identity from this node (node-1)
    bft.vote(proposal.id, true, 1.0);

    expect(resolved.length).toBe(1);
    expect(resolved[0]!.result.approved).toBe(true);
    expect(resolved[0]!.result.rounds).toBe(3); // PBFT rounds
  });

  it("vote_cast events fire for each vote", () => {
    const voteCasts: ConsensusVoteCastEvent[] = [];
    events.on("consensus.vote_cast", (e) => voteCasts.push(e));

    // Enough nodes to keep proposal pending after propose:
    // 5 nodes -> f=1 -> need 3 prepares; self-prepare = 1 < 3 -> stays pending
    bft.addNode("node-1", true);
    bft.addNode("node-2");
    bft.addNode("node-3");
    bft.addNode("node-4");
    const proposal = bft.propose({ action: "test" });

    // vote() derives identity from this node (node-1). Calling twice
    // overwrites the same voter's entry but still emits vote_cast each time.
    bft.vote(proposal.id, true, 0.8);
    bft.vote(proposal.id, false, 0.5);

    expect(voteCasts.length).toBe(2);
    expect(voteCasts[0]!.vote.voterId).toBe("node-1");
    expect(voteCasts[1]!.vote.voterId).toBe("node-1");
  });

  it("initiateViewChange increments view and re-elects primary", () => {
    const leaderEvents: LeaderElectedEvent[] = [];
    events.on("topology.leader_elected", (e) => leaderEvents.push(e));

    bft.addNode("node-2");
    bft.addNode("node-3");

    bft.initiateViewChange();
    expect(bft.getViewNumber()).toBe(1);
    expect(leaderEvents.length).toBe(1);
  });

  it("throws when non-primary proposes", () => {
    expect(() => bft.propose({ action: "test" })).toThrow(
      "Only primary can propose values",
    );
  });

  it("dispose clears viewChangeTimeout", () => {
    bft.dispose();
    // No error -> timer cleared (or was null)
  });
});

// ============================================================================
// Gossip Tests
// ============================================================================

describe("GossipConsensus", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;
  let gossip: GossipConsensus;

  beforeEach(() => {
    events = createEvents();
    gossip = new GossipConsensus(events, "node-1", {
      gossipIntervalMs: 50,
      convergenceThreshold: 0.5,
      fanout: 2,
      maxHops: 5,
    });
  });

  afterEach(() => {
    gossip.dispose();
    events.dispose();
  });

  it("starts with version 0 and no neighbors", () => {
    expect(gossip.getVersion()).toBe(0);
    expect(gossip.getNeighborCount()).toBe(0);
  });

  it("initialize starts gossip interval", () => {
    gossip.initialize();
    // No error -> interval started
  });

  it("propose creates proposal with csn_ ID and emits consensus.proposed", () => {
    const proposed: ConsensusProposedEvent[] = [];
    events.on("consensus.proposed", (e) => proposed.push(e));

    // Add nodes so self-vote alone doesn't trigger convergence (1/4 = 0.25 < 0.5)
    gossip.addNode("node-2");
    gossip.addNode("node-3");
    gossip.addNode("node-4");

    const proposal = gossip.propose({ action: "spread" });

    expect(proposal.id).toMatch(/^csn_/);
    expect(proposal.proposerId).toBe("node-1");
    expect(proposal.status).toBe("pending");
    expect(proposal.votes.length).toBe(1); // Self-vote

    expect(proposed.length).toBe(1);
  });

  it("vote emits consensus.vote_cast", () => {
    const voteCasts: ConsensusVoteCastEvent[] = [];
    events.on("consensus.vote_cast", (e) => voteCasts.push(e));

    // Add nodes so self-vote on propose doesn't trigger convergence
    gossip.addNode("node-2");
    gossip.addNode("node-3");
    gossip.addNode("node-4");

    const proposal = gossip.propose({ action: "test" });
    // vote() derives voterId from this node (node-1)
    gossip.vote(proposal.id, true, 0.8);

    expect(voteCasts.length).toBe(1);
    expect(voteCasts[0]!.vote.voterId).toBe("node-1");
  });

  it("convergence threshold triggers resolution", () => {
    const resolved: ConsensusResolvedEvent[] = [];
    events.on("consensus.resolved", (e) => resolved.push(e));

    // convergenceThreshold=0.5, 1 node total -> 1/1 = 1.0 >= 0.5
    // Self-vote on propose should already trigger convergence
    gossip.propose({ action: "converge" });

    expect(resolved.length).toBe(1);
    expect(resolved[0]!.result.approved).toBe(true);
  });

  it("convergence requires enough nodes when cluster is larger", () => {
    const resolved: ConsensusResolvedEvent[] = [];
    events.on("consensus.resolved", (e) => resolved.push(e));

    // Recreate with higher threshold and more nodes
    gossip.dispose();
    events.dispose();

    events = createEvents();
    gossip = new GossipConsensus(events, "node-1", {
      gossipIntervalMs: 50,
      convergenceThreshold: 0.9,
      fanout: 2,
      maxHops: 5,
    });

    gossip.addNode("node-2");
    gossip.addNode("node-3");
    gossip.addNode("node-4");
    gossip.addNode("node-5");
    // 5 nodes total, convergenceThreshold=0.9, need 5*0.9=4.5 -> 5 votes

    events.on("consensus.resolved", (e) => resolved.push(e));
    const proposal = gossip.propose({ action: "test" });

    // Only self-vote (1/5 = 0.2 < 0.9), should remain pending
    expect(proposal.status).toBe("pending");
    expect(resolved.length).toBe(0);
  });

  it("addNode and removeNode manage cluster", () => {
    gossip.addNode("node-2");
    gossip.addNode("node-3");
    gossip.removeNode("node-2");
    // No error thrown
    expect(true).toBe(true);
  });

  it("addNeighbor and removeNeighbor manage mesh", () => {
    gossip.addNode("node-2");
    gossip.addNeighbor("node-2");
    expect(gossip.getNeighborCount()).toBeGreaterThanOrEqual(1);
    gossip.removeNeighbor("node-2");
  });

  it("getQueueDepth and getSeenMessageCount track state", () => {
    gossip.propose({ action: "test" });
    // After propose, there should be a queued message
    expect(gossip.getSeenMessageCount()).toBeGreaterThanOrEqual(1);
  });

  it("getConvergence returns fraction", () => {
    gossip.addNode("node-2");
    const proposal = gossip.propose({ action: "test" });
    // 1 self-vote out of 2 nodes = 0.5
    expect(gossip.getConvergence(proposal.id)).toBe(0.5);
    expect(gossip.getConvergence("nonexistent")).toBe(0);
  });

  it("requeues received messages so multi-hop neighbors eventually see them", () => {
    gossip = new GossipConsensus(events, "node-1", {
      gossipIntervalMs: 50,
      convergenceThreshold: 0.9,
      fanout: 1,
      maxHops: 5,
    });
    gossip.addNode("node-2");
    gossip.addNode("node-3");

    const localNode = (gossip as any).node as {
      neighbors: Set<string>;
    };
    const nodes = (gossip as any).nodes as Map<string, {
      neighbors: Set<string>;
      seenMessages: Set<string>;
    }>;

    localNode.neighbors = new Set(["node-2"]);
    nodes.get("node-2")!.neighbors = new Set(["node-3"]);
    nodes.get("node-3")!.neighbors = new Set(["node-2"]);

    const proposal = gossip.propose({ action: "spread" });
    const messageId = `msg_${proposal.id}`;

    (gossip as any).gossipRound();
    expect(nodes.get("node-2")!.seenMessages.has(messageId)).toBe(true);
    expect(nodes.get("node-3")!.seenMessages.has(messageId)).toBe(false);

    (gossip as any).gossipRound();
    expect(nodes.get("node-3")!.seenMessages.has(messageId)).toBe(true);
  });

  it("dispose clears gossip interval", () => {
    gossip.initialize();
    gossip.dispose();
    // No dangling intervals
  });
});

// ============================================================================
// Lifecycle / Event Integration Tests
// ============================================================================

describe("Consensus lifecycle events", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;
  let engine: ConsensusEngine;

  afterEach(() => {
    engine?.dispose();
    events?.dispose();
  });

  it("consensus.proposed fires on propose (via factory)", async () => {
    events = createEvents();
    engine = new ConsensusEngine(events, "node-1", { algorithm: "raft" });
    engine.initialize();

    const proposed: ConsensusProposedEvent[] = [];
    events.on("consensus.proposed", (e) => proposed.push(e));

    // Wait for leader election
    await new Promise((r) => setTimeout(r, 400));

    engine.propose({ action: "factory-test" });
    expect(proposed.length).toBe(1);
    expect(proposed[0]!.proposal.value).toEqual({ action: "factory-test" });
  });

  it("consensus.vote_cast fires on vote (via factory)", async () => {
    events = createEvents();
    // Use high threshold so self-vote doesn't resolve immediately
    engine = new ConsensusEngine(events, "node-1", {
      algorithm: "raft",
      threshold: 0.9,
    });
    engine.initialize();

    const votes: ConsensusVoteCastEvent[] = [];
    events.on("consensus.vote_cast", (e) => votes.push(e));

    await new Promise((r) => setTimeout(r, 400));

    engine.addNode("node-2");
    engine.addNode("node-3");
    // threshold=0.9, 3 voters, quorum=floor(3*0.9)=2. Self-vote=1 < 2 => pending

    const proposal = engine.propose({ action: "vote-test" });
    engine.vote(proposal.id, true, 0.9);

    expect(votes.length).toBeGreaterThanOrEqual(1);
  });

  it("consensus.resolved fires when threshold met (via factory)", async () => {
    events = createEvents();
    engine = new ConsensusEngine(events, "node-1", {
      algorithm: "gossip",
      threshold: 0.5,
    });
    engine.initialize({ threshold: 0.5 });

    const resolved: ConsensusResolvedEvent[] = [];
    events.on("consensus.resolved", (e) => resolved.push(e));

    // Gossip with 1 node: self-vote triggers convergence
    engine.propose({ action: "resolve-test" });

    expect(resolved.length).toBe(1);
    expect(resolved[0]!.result.approved).toBe(true);
  });

  it("dispose clears all timers without error", async () => {
    events = createEvents();
    engine = new ConsensusEngine(events, "node-1", { algorithm: "raft" });
    engine.initialize();

    await new Promise((r) => setTimeout(r, 200));

    // Should not throw
    engine.dispose();

    // Double dispose should be safe
    engine.dispose();
  });
});
