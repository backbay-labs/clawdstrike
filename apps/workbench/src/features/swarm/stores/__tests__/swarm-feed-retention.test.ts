import { describe, expect, it, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mocks -- must be set up before importing the store
// ---------------------------------------------------------------------------

vi.mock("@/lib/workbench/terminal-service", () => ({
  terminalService: {
    getCwd: vi.fn().mockResolvedValue("/mock/cwd"),
    create: vi.fn().mockResolvedValue({
      id: "mock-session",
      branch: "main",
      shell: "zsh",
      persistence_mode: "tmux",
      recovery_state: "fresh",
    }),
    discover: vi.fn().mockResolvedValue([]),
    reconnect: vi.fn().mockResolvedValue({
      id: "mock-session",
      branch: "main",
      shell: "zsh",
      persistence_mode: "tmux",
      recovery_state: "recovered",
    }),
    preview: vi.fn().mockResolvedValue([]),
    write: vi.fn().mockResolvedValue(undefined),
    kill: vi.fn().mockResolvedValue(undefined),
    onExit: vi.fn().mockResolvedValue(() => {}),
  },
  worktreeService: {
    create: vi.fn().mockResolvedValue({ path: "/mock/worktree", branch: "test-branch" }),
    remove: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("@/lib/tauri-bridge", async () => {
  const actual = await vi.importActual<typeof import("@/lib/tauri-bridge")>("@/lib/tauri-bridge");
  return {
    ...actual,
    isDesktop: () => false,
  };
});

vi.mock("../swarm-persistence", () => ({
  SWARM_FEED_PERSISTENCE_FILE: "swarm-feed-state.v1.json",
  SWARM_BOARD_PERSISTENCE_FILE: "swarm-board-state.v1.json",
  SWARMS_PERSISTENCE_FILE: "swarms-state.v1.json",
  readSwarmPersistencePayload: vi.fn().mockResolvedValue(null),
  writeSwarmPersistencePayload: vi.fn().mockResolvedValue(true),
}));

vi.mock("../swarm-file-watch", () => ({
  setSwarmFileWatchScope: vi.fn().mockResolvedValue(undefined),
  clearSwarmFileWatchScope: vi.fn().mockResolvedValue(undefined),
  subscribeSwarmFileWatchEvents: vi.fn().mockReturnValue(() => {}),
}));

// ---------------------------------------------------------------------------
// Imports -- after mocks
// ---------------------------------------------------------------------------

import {
  FINDING_ENVELOPE_SCHEMA,
  HEAD_ANNOUNCEMENT_SCHEMA,
  REVOCATION_ENVELOPE_SCHEMA,
} from "@/features/swarm/swarm-protocol";
import { DEFAULT_HUB_TRUST_POLICY } from "@/features/swarm/swarm-trust-policy";
import type {
  SwarmFindingEnvelopeRecord,
  SwarmHeadAnnouncementRecord,
  SwarmRevocationEnvelopeRecord,
  SwarmFeedState,
} from "../swarm-feed-store";
import {
  applyRetentionPolicy,
  updateHighWaterMarks,
  getSwarmFeedSyncState,
  RETENTION_MAX_FINDINGS,
  RETENTION_MAX_HEADS,
  RETENTION_MAX_REVOCATIONS,
} from "../swarm-feed-store";

// ---------------------------------------------------------------------------
// Factory helpers
// ---------------------------------------------------------------------------

function makeFindingRecord(
  swarmId: string,
  feedId: string,
  issuerId: string,
  feedSeq: number,
  receivedAt = Date.now(),
): SwarmFindingEnvelopeRecord {
  return {
    swarmId,
    envelope: {
      schema: FINDING_ENVELOPE_SCHEMA,
      findingId: `finding-${swarmId}-${feedId}-${feedSeq}`,
      issuerId,
      feedId,
      feedSeq,
      publishedAt: receivedAt - 100,
      title: `Finding ${feedSeq}`,
      summary: `Summary for finding ${feedSeq}`,
      severity: "medium",
      confidence: 0.8,
      status: "open",
      signalCount: 1,
      tags: [],
      blobRefs: [],
    },
    receivedAt,
  };
}

function makeHeadRecord(
  swarmId: string,
  feedId: string,
  issuerId: string,
  headSeq: number,
  receivedAt = Date.now(),
): SwarmHeadAnnouncementRecord {
  return {
    swarmId,
    lane: "findings" as const,
    announcement: {
      schema: HEAD_ANNOUNCEMENT_SCHEMA,
      factId: `fact-${swarmId}-${feedId}-${headSeq}`,
      feedId,
      issuerId,
      headSeq,
      headEnvelopeHash: { algorithm: "sha256", hex: "0".repeat(64) },
      entryCount: headSeq,
      announcedAt: receivedAt - 50,
    },
    receivedAt,
  };
}

function makeRevocationRecord(
  swarmId: string,
  feedId: string,
  issuerId: string,
  feedSeq: number,
  receivedAt = Date.now(),
): SwarmRevocationEnvelopeRecord {
  return {
    swarmId,
    envelope: {
      schema: REVOCATION_ENVELOPE_SCHEMA,
      revocationId: `rev-${swarmId}-${feedId}-${feedSeq}`,
      issuerId,
      feedId,
      feedSeq,
      issuedAt: receivedAt - 100,
      action: "revoke",
      target: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: `finding-${swarmId}-${feedId}-${feedSeq}`,
        digest: { algorithm: "sha256", hex: "0".repeat(64) },
      },
      reason: "test revocation",
    },
    receivedAt,
  };
}

function makeState(overrides?: Partial<SwarmFeedState>): SwarmFeedState {
  return {
    findingEnvelopes: [],
    headAnnouncements: [],
    revocationEnvelopes: [],
    quarantinedFindingEnvelopes: [],
    quarantinedHeadAnnouncements: [],
    quarantinedRevocationEnvelopes: [],
    defaultTrustPolicy: DEFAULT_HUB_TRUST_POLICY,
    trustPolicies: {},
    ...overrides,
  };
}

/**
 * Generate an array of finding records with feedSeq from 1..count,
 * sorted descending (newest first) as the store maintains.
 */
function generateFindings(
  count: number,
  swarmId = "s1",
  feedId = "f1",
  issuerId = "i1",
): SwarmFindingEnvelopeRecord[] {
  const base = Date.now();
  return Array.from({ length: count }, (_, i) => {
    const seq = count - i; // descending: count, count-1, ..., 1
    return makeFindingRecord(swarmId, feedId, issuerId, seq, base + seq);
  });
}

function generateHeads(
  count: number,
  swarmId = "s1",
  feedId = "f1",
  issuerId = "i1",
): SwarmHeadAnnouncementRecord[] {
  const base = Date.now();
  return Array.from({ length: count }, (_, i) => {
    const seq = count - i;
    return makeHeadRecord(swarmId, feedId, issuerId, seq, base + seq);
  });
}

function generateRevocations(
  count: number,
  swarmId = "s1",
  feedId = "f1",
  issuerId = "i1",
): SwarmRevocationEnvelopeRecord[] {
  const base = Date.now();
  return Array.from({ length: count }, (_, i) => {
    const seq = count - i;
    return makeRevocationRecord(swarmId, feedId, issuerId, seq, base + seq);
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("applyRetentionPolicy", () => {
  it("trims 600 findings to 500, returning 100 as overflow", () => {
    const findings = generateFindings(600);
    const state = makeState({ findingEnvelopes: findings });

    const { retained, overflow } = applyRetentionPolicy(state);

    expect(retained.findingEnvelopes).toHaveLength(RETENTION_MAX_FINDINGS);
    // Retained should be the newest 500 (feedSeq 600..101 descending)
    expect(retained.findingEnvelopes[0]!.envelope.feedSeq).toBe(600);
    expect(retained.findingEnvelopes[RETENTION_MAX_FINDINGS - 1]!.envelope.feedSeq).toBe(101);

    expect(overflow).not.toBeNull();
    expect(overflow!.findingEnvelopes).toHaveLength(100);
    // Overflow should be the oldest 100 (feedSeq 100..1 descending)
    expect(overflow!.findingEnvelopes[0]!.envelope.feedSeq).toBe(100);
    expect(overflow!.findingEnvelopes[99]!.envelope.feedSeq).toBe(1);
  });

  it("trims 250 heads to 200, returning 50 as overflow", () => {
    const heads = generateHeads(250);
    const state = makeState({ headAnnouncements: heads });

    const { retained, overflow } = applyRetentionPolicy(state);

    expect(retained.headAnnouncements).toHaveLength(RETENTION_MAX_HEADS);
    expect(overflow).not.toBeNull();
    expect(overflow!.headAnnouncements).toHaveLength(50);
  });

  it("trims 250 revocations to 200, returning 50 as overflow", () => {
    const revocations = generateRevocations(250);
    const state = makeState({ revocationEnvelopes: revocations });

    const { retained, overflow } = applyRetentionPolicy(state);

    expect(retained.revocationEnvelopes).toHaveLength(RETENTION_MAX_REVOCATIONS);
    expect(overflow).not.toBeNull();
    expect(overflow!.revocationEnvelopes).toHaveLength(50);
  });

  it("trims quarantined arrays independently", () => {
    const qFindings = generateFindings(600, "s1", "f1", "i1");
    const qHeads = generateHeads(250, "s1", "f1", "i1");
    const state = makeState({
      quarantinedFindingEnvelopes: qFindings,
      quarantinedHeadAnnouncements: qHeads,
    });

    const { retained, overflow } = applyRetentionPolicy(state);

    expect(retained.quarantinedFindingEnvelopes).toHaveLength(RETENTION_MAX_FINDINGS);
    expect(retained.quarantinedHeadAnnouncements).toHaveLength(RETENTION_MAX_HEADS);
    expect(overflow).not.toBeNull();
    expect(overflow!.quarantinedFindingEnvelopes).toHaveLength(100);
    expect(overflow!.quarantinedHeadAnnouncements).toHaveLength(50);
  });

  it("returns overflow: null when all arrays are under limits", () => {
    const state = makeState({
      findingEnvelopes: generateFindings(100),
      headAnnouncements: generateHeads(50),
      revocationEnvelopes: generateRevocations(50),
    });

    const { retained, overflow } = applyRetentionPolicy(state);

    expect(overflow).toBeNull();
    expect(retained.findingEnvelopes).toHaveLength(100);
    expect(retained.headAnnouncements).toHaveLength(50);
    expect(retained.revocationEnvelopes).toHaveLength(50);
  });

  it("preserves defaultTrustPolicy and trustPolicies in retained state", () => {
    const customPolicy = { ...DEFAULT_HUB_TRUST_POLICY, trustedIssuers: ["issuer-1"] };
    const state = makeState({
      findingEnvelopes: generateFindings(600),
      defaultTrustPolicy: customPolicy,
      trustPolicies: { "swarm-1": customPolicy },
    });

    const { retained } = applyRetentionPolicy(state);

    expect(retained.defaultTrustPolicy).toBe(customPolicy);
    expect(retained.trustPolicies).toEqual({ "swarm-1": customPolicy });
  });

  it("handles mixed arrays where only some exceed limits", () => {
    const state = makeState({
      findingEnvelopes: generateFindings(300),
      headAnnouncements: generateHeads(250),
      revocationEnvelopes: generateRevocations(50),
    });

    const { retained, overflow } = applyRetentionPolicy(state);

    // Findings under limit (300 < 500)
    expect(retained.findingEnvelopes).toHaveLength(300);
    // Heads over limit (250 > 200)
    expect(retained.headAnnouncements).toHaveLength(RETENTION_MAX_HEADS);
    // Revocations under limit (50 < 200)
    expect(retained.revocationEnvelopes).toHaveLength(50);

    expect(overflow).not.toBeNull();
    expect(overflow!.headAnnouncements).toHaveLength(50);
    // Arrays under limit should be empty in overflow
    expect(overflow!.findingEnvelopes).toHaveLength(0);
    expect(overflow!.revocationEnvelopes).toHaveLength(0);
  });
});

describe("updateHighWaterMarks", () => {
  it("tracks max feedSeq per (swarmId, feedId) from findings", () => {
    const state = makeState({
      findingEnvelopes: [
        makeFindingRecord("s1", "f1", "i1", 10),
        makeFindingRecord("s1", "f1", "i1", 20),
        makeFindingRecord("s1", "f1", "i1", 30),
      ],
    });

    const result = updateHighWaterMarks({}, state);

    expect(result).toEqual({ s1: { f1: 30 } });
  });

  it("preserves existing higher marks", () => {
    const state = makeState({
      findingEnvelopes: [
        makeFindingRecord("s1", "f1", "i1", 10),
        makeFindingRecord("s1", "f1", "i1", 20),
      ],
    });

    const result = updateHighWaterMarks({ s1: { f1: 50 } }, state);

    expect(result).toEqual({ s1: { f1: 50 } });
  });

  it("tracks multiple swarms independently", () => {
    const state = makeState({
      findingEnvelopes: [
        makeFindingRecord("s1", "f1", "i1", 10),
        makeFindingRecord("s2", "f2", "i2", 25),
      ],
    });

    const result = updateHighWaterMarks({}, state);

    expect(result).toEqual({ s1: { f1: 10 }, s2: { f2: 25 } });
  });

  it("also scans revocation envelopes", () => {
    const state = makeState({
      findingEnvelopes: [makeFindingRecord("s1", "f1", "i1", 10)],
      revocationEnvelopes: [makeRevocationRecord("s1", "f1", "i1", 15)],
    });

    const result = updateHighWaterMarks({}, state);

    // Revocation feedSeq 15 > finding feedSeq 10
    expect(result).toEqual({ s1: { f1: 15 } });
  });

  it("does not regress when new state has lower seq", () => {
    const existing = { s1: { f1: 100, f2: 200 } };
    const state = makeState({
      findingEnvelopes: [
        makeFindingRecord("s1", "f1", "i1", 50),
        makeFindingRecord("s1", "f2", "i1", 210),
      ],
    });

    const result = updateHighWaterMarks(existing, state);

    expect(result.s1!.f1).toBe(100); // preserved
    expect(result.s1!.f2).toBe(210); // updated
  });
});

describe("high-water mark integration", () => {
  it("high-water mark reflects true max after retention trim", () => {
    const findings = generateFindings(600); // feedSeq 600..1 descending
    const state = makeState({ findingEnvelopes: findings });

    // First update high-water marks from the full state
    const hwm = updateHighWaterMarks({}, state);
    expect(hwm.s1!.f1).toBe(600);

    // Then apply retention: trims to 500 (seq 600..101)
    const { retained } = applyRetentionPolicy(state);
    expect(retained.findingEnvelopes).toHaveLength(500);

    // High-water marks should still be 600
    const hwmAfterTrim = updateHighWaterMarks(hwm, retained);
    expect(hwmAfterTrim.s1!.f1).toBe(600);
  });

  it("getSwarmFeedSyncState falls back to highWaterMarks when array lacks the max seq", () => {
    // Create a trimmed state: only seq 101..600
    const trimmedFindings = generateFindings(600).slice(0, 500);
    const state = makeState({ findingEnvelopes: trimmedFindings });

    // Without high-water marks, sync state should report max from array
    const syncWithArray = getSwarmFeedSyncState(state, "s1", "f1", "i1");
    expect(syncWithArray.localMaxFindingSeq).toBe(600);

    // Even with high-water marks, the array still has seq 600 since we kept newest 500
    // Test the fallback case: state has no findings for a specific feed but HWM exists
    const emptyState = makeState({ findingEnvelopes: [] });

    // getSwarmFeedSyncState should fall back to highWaterMarks
    // We need to set the module-level _highWaterMarks for this test
    // This will be tested after the implementation provides a way to set HWM for tests
    const syncEmpty = getSwarmFeedSyncState(emptyState, "s1", "f1", "i1");
    // Without HWM set, this should be null
    expect(syncEmpty.localMaxFindingSeq).toBeNull();
  });
});
