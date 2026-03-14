/**
 * Reputation Tracker — Trust and reputation scoring for swarm members.
 *
 * Pure-function module (no React, no side effects). All functions return new
 * values rather than mutating inputs. Implements the trust model described in
 * SPEAKEASY-INTEGRATION.md section 6 and the reputation update protocol from
 * SIGNAL-PIPELINE.md section 7.4.
 *
 * Key design decisions:
 *   - Asymmetric updates: negative events are penalized more heavily than
 *     positive events are rewarded. This is the fail-closed principle applied
 *     to trust: it is harder to earn reputation than to lose it.
 *   - Scores are always clamped to [0.0, 1.0].
 *   - Trust edges decay over time with a configurable half-life (default 30 days).
 *   - Transitive trust is computed with multiplicative decay, max 3 hops.
 *   - Sybil resistance via invitation chain depth limits and proof-of-useful-work.
 *
 * @see docs/plans/sentinel-swarm/SPEAKEASY-INTEGRATION.md (section 6)
 * @see docs/plans/sentinel-swarm/SIGNAL-PIPELINE.md (section 7.4)
 */

import type {
  ReputationScore,
  SwarmMember,
  TrustEdge,
  SwarmPolicy,
} from "./sentinel-types";
import type { TrustLevel } from "./delegation-types";


/** Starting reputation for new members (neutral). */
export const DEFAULT_INITIAL_REPUTATION = 0.5;

/** Minimum reputation required to publish intel to a swarm. */
export const MIN_REPUTATION_TO_PUBLISH = 0.3;

/** Minimum reputation required to cast reputation votes. */
export const MIN_REPUTATION_TO_VOTE = 0.4;

/**
 * Minimum reputation for pattern ingestion via mergeSwarmPattern in
 * sentinel-manager.ts. Peers below this threshold cannot contribute patterns
 * to another sentinel's memory.
 */
export const MIN_REPUTATION_FOR_PATTERNS = 0.6;

/** Maximum depth of invitation chains for Sybil resistance. */
export const MAX_INVITATION_DEPTH = 5;

/** Default trust edge half-life: 30 days in milliseconds. */
export const TRUST_DECAY_HALF_LIFE_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Maximum number of hops for transitive trust computation.
 * Beyond 3 hops, trust attenuates to near-zero and the graph search
 * cost is not worthwhile.
 */
const MAX_TRANSITIVE_HOPS = 3;


/** Discriminator for reputation-affecting events. */
export type ReputationEventType =
  | "intel_corroborated"
  | "intel_contradicted"
  | "finding_confirmed"
  | "finding_false_positive"
  | "detection_useful"
  | "detection_noisy"
  | "timely_response"
  | "inactive_penalty";

/**
 * A discrete event that affects a swarm member's reputation.
 * Created by the SwarmCoordinator or FindingEngine and consumed by
 * updateReputation() to produce a new ReputationScore.
 */
export interface ReputationEvent {
  /** The type of event. Determines the delta applied. */
  type: ReputationEventType;
  /** Fingerprint of the member whose reputation is affected. */
  targetMemberId: string;
  /** Intel artifact ID, if this event relates to shared intel. */
  intelId?: string;
  /** Finding ID, if this event relates to a finding. */
  findingId?: string;
  /** When this event occurred (Unix ms). */
  timestamp: number;
  /**
   * The reputation delta applied by updateReputation().
   * Computed from the event type; stored for audit trail.
   */
  delta: number;
}


/**
 * Reputation deltas per event type. Asymmetric by design: negative outcomes
 * cost more reputation than positive outcomes earn.
 *
 * Values from SIGNAL-PIPELINE.md section 7.4 and the task specification.
 */
const REPUTATION_DELTAS: Readonly<Record<ReputationEventType, number>> = {
  intel_corroborated: +0.02,
  intel_contradicted: -0.05,
  finding_confirmed: +0.01,
  finding_false_positive: -0.03,
  detection_useful: +0.015,
  detection_noisy: -0.02,
  timely_response: +0.005,
  inactive_penalty: -0.01,
};


/**
 * Numeric weight for each TrustLevel. Used internally for trust computation.
 * Maps the categorical TrustLevel enum to a [0, 1] weight.
 */
const TRUST_LEVEL_WEIGHTS: Readonly<Record<TrustLevel, number>> = {
  Untrusted: 0.0,
  Low: 0.25,
  Medium: 0.5,
  High: 0.75,
  System: 1.0,
};

/**
 * Derive a TrustLevel from a numeric weight.
 */
export function trustLevelFromWeight(weight: number): TrustLevel {
  if (weight >= 0.9) return "System";
  if (weight >= 0.6) return "High";
  if (weight >= 0.35) return "Medium";
  if (weight >= 0.15) return "Low";
  return "Untrusted";
}

/**
 * Get the numeric weight for a TrustLevel.
 */
export function trustLevelToWeight(level: TrustLevel): number {
  return TRUST_LEVEL_WEIGHTS[level];
}

/**
 * Derive TrustLevel from a reputation score value.
 */
export function trustLevelFromReputation(overall: number): TrustLevel {
  if (overall >= 0.8) return "High";
  if (overall >= 0.5) return "Medium";
  if (overall >= 0.2) return "Low";
  return "Untrusted";
}


/** Clamp a value to [min, max]. */
function clamp(value: number, min: number, max: number): number {
  if (value < min) return min;
  if (value > max) return max;
  return value;
}


/**
 * Create a fresh ReputationScore for a new swarm member.
 * Starts at the neutral midpoint (0.5).
 */
export function createInitialReputation(): ReputationScore {
  return {
    overall: DEFAULT_INITIAL_REPUTATION,
    trustLevel: trustLevelFromReputation(DEFAULT_INITIAL_REPUTATION),
    intelContributed: 0,
    truePositives: 0,
    falsePositives: 0,
    lastUpdated: Date.now(),
  };
}

/**
 * Apply a reputation event and return a new ReputationScore.
 *
 * The delta is determined by the event type from REPUTATION_DELTAS.
 * The overall score is always clamped to [0.0, 1.0].
 * The returned ReputationEvent has its `delta` field populated.
 *
 * This function also updates the counters (intelContributed, truePositives,
 * falsePositives) based on the event type.
 *
 * @param score - Current reputation score (not mutated).
 * @param event - The reputation event to apply.
 * @returns A tuple of [newScore, eventWithDelta].
 */
export function updateReputation(
  score: ReputationScore,
  event: Omit<ReputationEvent, "delta">,
): [ReputationScore, ReputationEvent] {
  const delta = REPUTATION_DELTAS[event.type];
  const newOverall = clamp(score.overall + delta, 0.0, 1.0);

  // Update counters based on event type
  let { intelContributed, truePositives, falsePositives } = score;

  switch (event.type) {
    case "intel_corroborated":
      intelContributed += 1;
      break;
    case "finding_confirmed":
    case "detection_useful":
      truePositives += 1;
      break;
    case "finding_false_positive":
    case "detection_noisy":
      falsePositives += 1;
      break;
    // intel_contradicted, timely_response, inactive_penalty: no counter change
  }

  const newScore: ReputationScore = {
    overall: newOverall,
    trustLevel: trustLevelFromReputation(newOverall),
    intelContributed,
    truePositives,
    falsePositives,
    lastUpdated: event.timestamp,
  };

  const eventWithDelta: ReputationEvent = {
    ...event,
    delta,
  };

  return [newScore, eventWithDelta];
}

/**
 * Apply a sequence of reputation events in order.
 * Returns the final ReputationScore and the events with deltas populated.
 */
export function applyReputationEvents(
  score: ReputationScore,
  events: ReadonlyArray<Omit<ReputationEvent, "delta">>,
): [ReputationScore, ReputationEvent[]] {
  let current = score;
  const results: ReputationEvent[] = [];

  for (const event of events) {
    const [next, withDelta] = updateReputation(current, event);
    current = next;
    results.push(withDelta);
  }

  return [current, results];
}


/**
 * Create a new trust edge between two swarm members.
 *
 * @param fromId - Source member fingerprint.
 * @param toId   - Target member fingerprint.
 * @param weight - Numeric trust weight in [0.0, 1.0].
 * @param basis  - The basis for this trust assertion.
 */
export function createTrustEdge(
  fromId: string,
  toId: string,
  weight: number,
  basis: TrustEdge["basis"],
): TrustEdge {
  const clamped = clamp(weight, 0.0, 1.0);
  return {
    from: fromId,
    to: toId,
    trustLevel: trustLevelFromWeight(clamped),
    updatedAt: Date.now(),
    basis,
  };
}

/**
 * Update an existing trust edge with a new weight and basis.
 * Returns a new TrustEdge (immutable).
 *
 * @param edge      - Existing edge (not mutated).
 * @param newWeight - New numeric trust weight in [0.0, 1.0].
 * @param basis     - Updated basis for the trust assertion.
 */
export function updateTrustEdge(
  edge: TrustEdge,
  newWeight: number,
  basis: TrustEdge["basis"],
): TrustEdge {
  const clamped = clamp(newWeight, 0.0, 1.0);
  return {
    ...edge,
    trustLevel: trustLevelFromWeight(clamped),
    updatedAt: Date.now(),
    basis,
  };
}

/**
 * Apply time-based exponential decay to trust edges.
 *
 * Trust edges lose weight over time following a half-life model:
 *   decayed_weight = current_weight * 2^(-elapsed / halfLife)
 *
 * Edges that decay to below 0.01 are dropped (effectively forgotten).
 *
 * @param edges      - Array of trust edges (not mutated).
 * @param now        - Current timestamp (Unix ms).
 * @param halfLifeMs - Half-life in ms. Defaults to TRUST_DECAY_HALF_LIFE_MS (30 days).
 * @returns New array of decayed trust edges (edges below 0.01 are removed).
 */
export function decayTrustEdges(
  edges: readonly TrustEdge[],
  now: number,
  halfLifeMs: number = TRUST_DECAY_HALF_LIFE_MS,
): TrustEdge[] {
  const result: TrustEdge[] = [];

  for (const edge of edges) {
    const elapsed = now - edge.updatedAt;
    if (elapsed <= 0) {
      // Edge is in the future or exactly now — no decay
      result.push(edge);
      continue;
    }

    const currentWeight = trustLevelToWeight(edge.trustLevel);
    const decayFactor = Math.pow(2, -elapsed / halfLifeMs);
    const decayedWeight = currentWeight * decayFactor;

    // Drop edges that have decayed to negligible weight
    if (decayedWeight < 0.01) {
      continue;
    }

    result.push({
      ...edge,
      trustLevel: trustLevelFromWeight(decayedWeight),
      // Note: updatedAt is NOT changed by decay. It records when the edge was
      // last explicitly updated, not when decay was computed.
    });
  }

  return result;
}

/**
 * Compute transitive trust from `from` to `to` through the trust graph.
 *
 * Uses BFS with multiplicative decay: at each hop, the trust weight is
 * multiplied by the edge weight. Maximum 3 hops (MAX_TRANSITIVE_HOPS).
 * When multiple paths exist, returns the maximum trust across all paths.
 *
 * @param from  - Source member fingerprint.
 * @param to    - Target member fingerprint.
 * @param edges - The trust graph edges.
 * @returns Transitive trust weight in [0.0, 1.0]. Returns 0 if no path exists.
 */
export function computeTransitiveTrust(
  from: string,
  to: string,
  edges: readonly TrustEdge[],
): number {
  // Direct self-trust
  if (from === to) return 1.0;

  // Build adjacency list: from -> [(to, weight)]
  const adjacency = new Map<string, Array<{ target: string; weight: number }>>();
  for (const edge of edges) {
    let neighbors = adjacency.get(edge.from);
    if (!neighbors) {
      neighbors = [];
      adjacency.set(edge.from, neighbors);
    }
    neighbors.push({
      target: edge.to,
      weight: trustLevelToWeight(edge.trustLevel),
    });
  }

  // BFS with trust accumulation
  // Queue entries: [currentNode, accumulatedTrust, hopCount]
  const queue: Array<[string, number, number]> = [[from, 1.0, 0]];
  // Track best trust seen for each node to prune worse paths
  const bestSeen = new Map<string, number>();
  bestSeen.set(from, 1.0);

  let maxTrust = 0;

  while (queue.length > 0) {
    const [current, accTrust, hops] = queue.shift()!;

    if (hops >= MAX_TRANSITIVE_HOPS) continue;

    const neighbors = adjacency.get(current);
    if (!neighbors) continue;

    for (const { target, weight } of neighbors) {
      const pathTrust = accTrust * weight;

      // Skip negligible trust paths
      if (pathTrust < 0.001) continue;

      if (target === to) {
        maxTrust = Math.max(maxTrust, pathTrust);
        continue;
      }

      // Only explore if this path gives better trust than previously seen
      const prev = bestSeen.get(target) ?? 0;
      if (pathTrust > prev) {
        bestSeen.set(target, pathTrust);
        queue.push([target, pathTrust, hops + 1]);
      }
    }
  }

  return maxTrust;
}


/**
 * Check whether a member meets the minimum reputation to publish intel
 * to a swarm.
 *
 * Uses the swarm policy's `minReputationToPublish` if set, otherwise falls
 * back to MIN_REPUTATION_TO_PUBLISH.
 *
 * @param member      - The swarm member.
 * @param swarmPolicy - The swarm's governance policy.
 * @returns True if the member can publish intel.
 */
export function canPublishIntel(
  member: SwarmMember,
  swarmPolicy: SwarmPolicy,
): boolean {
  const threshold = swarmPolicy.minReputationToPublish ?? MIN_REPUTATION_TO_PUBLISH;
  return member.reputation.overall >= threshold;
}

/**
 * Check whether a member meets the minimum reputation to share detection
 * rules with the swarm.
 *
 * Detection sharing uses the same threshold as intel publishing — detection
 * rules are a form of intel artifact (type: "detection_rule").
 *
 * @param member      - The swarm member.
 * @param swarmPolicy - The swarm's governance policy.
 * @returns True if the member can share detections.
 */
export function canShareDetection(
  member: SwarmMember,
  swarmPolicy: SwarmPolicy,
): boolean {
  // Same gate as intel publishing — detections are intel
  const threshold = swarmPolicy.minReputationToPublish ?? MIN_REPUTATION_TO_PUBLISH;
  return member.reputation.overall >= threshold;
}

/**
 * Check whether a voter can cast a reputation vote on a target member.
 *
 * Rules:
 *   1. No self-voting (voter and target must be different members).
 *   2. Voter must meet MIN_REPUTATION_TO_VOTE threshold.
 *
 * @param voter  - The member casting the vote.
 * @param target - The member being voted on.
 * @returns True if the vote is allowed.
 */
export function canVoteOnReputation(
  voter: SwarmMember,
  target: SwarmMember,
): boolean {
  // Prevent self-voting
  if (voter.fingerprint === target.fingerprint) return false;

  // Voter must have sufficient reputation
  return voter.reputation.overall >= MIN_REPUTATION_TO_VOTE;
}

/**
 * Attenuate an incoming confidence value by the peer's reputation.
 *
 * Used when ingesting swarm intel or signals: the confidence reported by a
 * peer is scaled by their reputation. A fully trusted peer (reputation 1.0)
 * passes confidence unchanged; a peer at 0.5 halves the confidence.
 *
 * This is the `confidence * peerReputation` formula from
 * SIGNAL-PIPELINE.md section 1.2 (swarm intel normalization).
 *
 * @param confidence     - The reported confidence value in [0.0, 1.0].
 * @param peerReputation - The peer's overall reputation score in [0.0, 1.0].
 * @returns Attenuated confidence, clamped to [0.0, 1.0].
 */
export function attenuateConfidence(
  confidence: number,
  peerReputation: number,
): number {
  return clamp(confidence * peerReputation, 0.0, 1.0);
}


/**
 * Validate an invitation chain to prevent deep invitation trees.
 *
 * Each member in a federated swarm is invited by an existing member. The
 * invitation chain depth is limited to MAX_INVITATION_DEPTH to prevent
 * rapid Sybil propagation.
 *
 * The function traces the invitation chain from the candidate through
 * `invitedBy` to the root, counting hops. If the chain exceeds the
 * maximum depth, or the inviter is not a member, the invitation is rejected.
 *
 * @param memberFingerprint - Fingerprint of the candidate member.
 * @param invitedBy         - Fingerprint of the inviting member (null for founding members).
 * @param existingMembers   - Current swarm members with their invitation metadata.
 * @returns Object with `valid` flag and `depth` of the chain, plus optional `reason`.
 */
export function validateInvitationChain(
  memberFingerprint: string,
  invitedBy: string | null,
  existingMembers: ReadonlyArray<SwarmMember & { invitedBy?: string | null }>,
): { valid: boolean; depth: number; reason?: string } {
  // Founding members (no inviter) are always valid at depth 0
  if (invitedBy === null) {
    return { valid: true, depth: 0 };
  }

  // Build a map of fingerprint -> member for fast lookup
  const memberMap = new Map<string, SwarmMember & { invitedBy?: string | null }>();
  for (const m of existingMembers) {
    memberMap.set(m.fingerprint, m);
  }

  // The inviter must be an existing member
  if (!memberMap.has(invitedBy)) {
    return {
      valid: false,
      depth: 0,
      reason: `Inviter ${invitedBy} is not a swarm member`,
    };
  }

  // Self-invitation is not allowed
  if (memberFingerprint === invitedBy) {
    return {
      valid: false,
      depth: 0,
      reason: "Cannot invite yourself",
    };
  }

  // Trace the invitation chain from the inviter back to a root
  let depth = 1; // The candidate is 1 hop from the inviter
  let current = invitedBy;
  const visited = new Set<string>();
  visited.add(memberFingerprint);

  while (current !== null) {
    // Cycle detection
    if (visited.has(current)) {
      return {
        valid: false,
        depth,
        reason: "Invitation chain contains a cycle",
      };
    }
    visited.add(current);

    const member = memberMap.get(current);
    if (!member) {
      // Reached a member not in the swarm — treat as root
      break;
    }

    if (member.invitedBy === null || member.invitedBy === undefined) {
      // Reached a founding member — chain is complete
      break;
    }

    current = member.invitedBy;
    depth += 1;

    if (depth > MAX_INVITATION_DEPTH) {
      return {
        valid: false,
        depth,
        reason: `Invitation chain depth ${depth} exceeds maximum ${MAX_INVITATION_DEPTH}`,
      };
    }
  }

  return { valid: true, depth };
}

/**
 * Compute a proof-of-useful-work score for a swarm member.
 *
 * Reputation accrues only from validated contributions. Creating many
 * identities does not bypass this gate because each identity must
 * independently produce confirmed findings and useful detections.
 *
 * The score is a weighted sum of:
 *   - Confirmed true positives (weight 2.0)
 *   - Intel contributed (weight 1.0)
 *   - False positives reduce score (weight -0.5)
 *
 * Normalized to [0.0, 1.0] using a sigmoid curve with midpoint at 10.
 *
 * @param member - The swarm member.
 * @returns Proof-of-useful-work score in [0.0, 1.0].
 */
export function computeProofOfUsefulWork(member: SwarmMember): number {
  const { truePositives, intelContributed, falsePositives } = member.reputation;

  const rawScore =
    truePositives * 2.0 +
    intelContributed * 1.0 +
    falsePositives * -0.5;

  // Sigmoid normalization: maps raw score to [0, 1] with midpoint at 10
  // This prevents gaming by ensuring diminishing returns at high counts.
  // Guard: when rawScore <= 0 (no useful work or net-negative), return 0
  // to avoid division-by-zero (rawScore + midpoint = 0 when rawScore = -10)
  // and nonsensical negative normalized values.
  if (rawScore <= 0) return 0;

  const midpoint = 10;
  const normalized = rawScore / (rawScore + midpoint);

  return clamp(normalized, 0.0, 1.0);
}

/**
 * Check whether a member's proof-of-useful-work meets the swarm's join
 * threshold for federated membership.
 *
 * @param proofOfWork - Score from computeProofOfUsefulWork().
 * @param swarmPolicy - The swarm's governance policy.
 * @returns True if the member qualifies.
 */
export function meetsJoinThreshold(
  proofOfWork: number,
  swarmPolicy: SwarmPolicy,
): boolean {
  // Use the swarm's minimum reputation as the join threshold for federated swarms.
  // If the swarm has no minimum, use the global default.
  const threshold = swarmPolicy.minReputationToPublish ?? MIN_REPUTATION_TO_PUBLISH;
  return proofOfWork >= threshold;
}


/**
 * Aggregate reputation statistics for a swarm.
 *
 * Returns summary stats: mean, median, min, max, and count of members
 * above/below the publishing threshold.
 */
export interface SwarmReputationSummary {
  /** Number of members in the swarm. */
  memberCount: number;
  /** Mean reputation across all members. */
  meanReputation: number;
  /** Median reputation across all members. */
  medianReputation: number;
  /** Minimum reputation in the swarm. */
  minReputation: number;
  /** Maximum reputation in the swarm. */
  maxReputation: number;
  /** Number of members above MIN_REPUTATION_TO_PUBLISH. */
  membersAbovePublishThreshold: number;
  /** Number of members below MIN_REPUTATION_TO_PUBLISH. */
  membersBelowPublishThreshold: number;
}

/**
 * Compute aggregate reputation statistics for a swarm.
 *
 * @param members - The swarm's members.
 * @returns Summary statistics, or null if the swarm has no members.
 */
export function computeSwarmReputation(
  members: readonly SwarmMember[],
): SwarmReputationSummary | null {
  if (members.length === 0) return null;

  const scores = members.map((m) => m.reputation.overall);
  const sorted = [...scores].sort((a, b) => a - b);

  const sum = sorted.reduce((acc, s) => acc + s, 0);
  const mean = sum / sorted.length;

  let median: number;
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    median = (sorted[mid - 1]! + sorted[mid]!) / 2;
  } else {
    median = sorted[mid]!;
  }

  const aboveThreshold = scores.filter(
    (s) => s >= MIN_REPUTATION_TO_PUBLISH,
  ).length;

  return {
    memberCount: members.length,
    meanReputation: mean,
    medianReputation: median,
    minReputation: sorted[0]!,
    maxReputation: sorted[sorted.length - 1]!,
    membersAbovePublishThreshold: aboveThreshold,
    membersBelowPublishThreshold: members.length - aboveThreshold,
  };
}

/**
 * Rank swarm members by reputation score, descending.
 * Returns a new array (does not mutate the input).
 *
 * @param members - The swarm's members.
 * @returns Members sorted by reputation.overall descending.
 */
export function rankMembers(
  members: readonly SwarmMember[],
): SwarmMember[] {
  return [...members].sort(
    (a, b) => b.reputation.overall - a.reputation.overall,
  );
}

/**
 * Identify swarm members whose reputation falls below a threshold.
 *
 * @param members   - The swarm's members.
 * @param threshold - Reputation threshold. Defaults to MIN_REPUTATION_TO_PUBLISH.
 * @returns Members with reputation.overall < threshold.
 */
export function identifyLowReputationMembers(
  members: readonly SwarmMember[],
  threshold: number = MIN_REPUTATION_TO_PUBLISH,
): SwarmMember[] {
  return members.filter((m) => m.reputation.overall < threshold);
}

/**
 * Reputation trend direction.
 */
export type ReputationTrend = "rising" | "falling" | "stable";

/**
 * A single point in a reputation history timeline.
 */
export interface ReputationHistoryEntry {
  /** Reputation score at this point. */
  overall: number;
  /** Timestamp (Unix ms). */
  timestamp: number;
}

/**
 * Compute the trend direction from a reputation history.
 *
 * Uses simple linear regression on the history entries. The slope determines
 * the trend:
 *   - slope > +0.001/day  -> "rising"
 *   - slope < -0.001/day  -> "falling"
 *   - otherwise           -> "stable"
 *
 * Requires at least 2 history entries to compute a trend; returns "stable"
 * for fewer entries.
 *
 * @param history - Chronologically ordered reputation snapshots.
 * @returns The trend direction.
 */
export function computeReputationTrend(
  history: readonly ReputationHistoryEntry[],
): ReputationTrend {
  if (history.length < 2) return "stable";

  // Simple linear regression: y = a + b*x
  // x = timestamp (in days since first entry), y = overall score
  const baseTime = history[0]!.timestamp;
  const msPerDay = 24 * 60 * 60 * 1000;

  let sumX = 0;
  let sumY = 0;
  let sumXY = 0;
  let sumX2 = 0;
  const n = history.length;

  for (const entry of history) {
    const x = (entry.timestamp - baseTime) / msPerDay;
    const y = entry.overall;
    sumX += x;
    sumY += y;
    sumXY += x * y;
    sumX2 += x * x;
  }

  const denominator = n * sumX2 - sumX * sumX;

  // If all timestamps are the same, slope is undefined -> stable
  if (Math.abs(denominator) < 1e-12) return "stable";

  const slope = (n * sumXY - sumX * sumY) / denominator;

  // Threshold: 0.001 reputation points per day
  const slopeThreshold = 0.001;

  if (slope > slopeThreshold) return "rising";
  if (slope < -slopeThreshold) return "falling";
  return "stable";
}


/**
 * Get the reputation delta for a given event type.
 * Useful for UI display ("this event will cost -0.05 reputation").
 *
 * @param eventType - The reputation event type.
 * @returns The delta value (positive or negative).
 */
export function getReputationDelta(eventType: ReputationEventType): number {
  return REPUTATION_DELTAS[eventType];
}

/**
 * Get all reputation delta definitions.
 * Returns a readonly copy of the delta map.
 */
export function getAllReputationDeltas(): Readonly<Record<ReputationEventType, number>> {
  return REPUTATION_DELTAS;
}
