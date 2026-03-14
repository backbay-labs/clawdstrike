import { describe, expect, it } from "vitest";
import {
  HEAD_ANNOUNCEMENT_SCHEMA,
  FINDING_ENVELOPE_SCHEMA,
  type FindingEnvelope,
  type HeadAnnouncement,
  type ProtocolDigest,
} from "../swarm-protocol";
import { planSwarmReplay, validateSwarmReplayBatch } from "../swarm-sync";

const HEX_1 = `0x${"1".repeat(64)}` as ProtocolDigest;
const HEX_2 = `0x${"2".repeat(64)}` as ProtocolDigest;
const PUBLIC_KEY = "b".repeat(64);
const OTHER_PUBLIC_KEY = "c".repeat(64);
const SIGNATURE = "a".repeat(128);
const ISSUER_ID = `aegis:ed25519:${PUBLIC_KEY}`;
const OTHER_ISSUER_ID = `aegis:ed25519:${OTHER_PUBLIC_KEY}`;

function makeFindingEnvelope(overrides: Partial<FindingEnvelope> = {}): FindingEnvelope {
  return {
    schema: FINDING_ENVELOPE_SCHEMA,
    findingId: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
    issuerId: ISSUER_ID,
    feedId: "fed.alpha",
    feedSeq: 3,
    publishedAt: 1_715_000_000_000,
    title: "Suspicious shell pipeline",
    summary: "Repeated shell + egress behavior across one runtime session.",
    severity: "high",
    confidence: 0.92,
    status: "confirmed",
    signalCount: 3,
    tags: ["egress", "shell"],
    blobRefs: [],
    attestation: {
      algorithm: "ed25519",
      publicKey: PUBLIC_KEY,
      signature: SIGNATURE,
    },
    ...overrides,
  };
}

function makeHeadAnnouncement(overrides: Partial<HeadAnnouncement> = {}): HeadAnnouncement {
  return {
    schema: HEAD_ANNOUNCEMENT_SCHEMA,
    factId: "head_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
    feedId: "fed.alpha",
    issuerId: ISSUER_ID,
    headSeq: 5,
    headEnvelopeHash: HEX_1,
    entryCount: 5,
    announcedAt: 1_715_000_000_500,
    ...overrides,
  };
}

describe("planSwarmReplay", () => {
  it("returns no replay request when the local feed is already caught up", () => {
    const plan = planSwarmReplay({
      swarmId: "swm_alpha",
      feedId: "fed.alpha",
      issuerId: ISSUER_ID,
      localFindingSeq: 5,
      localMaxFindingSeq: 5,
      localHeadSeq: 5,
      remoteHeadSeq: 5,
    });

    expect(plan).toMatchObject({
      localFindingSeq: 5,
      localMaxFindingSeq: 5,
      localHeadSeq: 5,
      remoteHeadSeq: 5,
      missingFromSeq: null,
      missingToSeq: null,
      missingCount: 0,
      request: null,
    });
  });

  it("creates a bounded request when the remote head is ahead", () => {
    const plan = planSwarmReplay({
      swarmId: "swm_alpha",
      feedId: "fed.alpha",
      issuerId: ISSUER_ID,
      localFindingSeq: 2,
      localMaxFindingSeq: 2,
      localHeadSeq: 2,
      remoteHeadSeq: 7,
      maxEntries: 2,
    });

    expect(plan).toMatchObject({
      missingFromSeq: 3,
      missingToSeq: 4,
      missingCount: 5,
      request: {
        swarmId: "swm_alpha",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        fromSeq: 3,
        toSeq: 4,
        limit: 2,
        localFindingSeq: 2,
        localMaxFindingSeq: 2,
        localHeadSeq: 2,
        remoteHeadSeq: 7,
      },
    });
  });

  it("keeps the next replay request pinned to the earliest missing sequence after sparse recovery", () => {
    const request = planSwarmReplay({
      swarmId: "swm_alpha",
      feedId: "fed.alpha",
      issuerId: ISSUER_ID,
      localFindingSeq: 2,
      localMaxFindingSeq: 2,
      localHeadSeq: 2,
      remoteHeadSeq: 5,
    }).request;

    expect(request).not.toBeNull();

    const sparseResult = validateSwarmReplayBatch({
      request: request!,
      existingSeqs: [1, 2],
      currentHeadSeq: 2,
      batch: {
        envelopes: [
          makeFindingEnvelope({
            findingId: "fnd_sparse_5",
            feedSeq: 5,
          }),
        ],
        headAnnouncement: makeHeadAnnouncement({
          headSeq: 5,
        }),
      },
    });

    expect(sparseResult.acceptedEnvelopes.map((entry) => entry.feedSeq)).toEqual([5]);
    expect(sparseResult.latestFindingSeq).toBe(2);
    expect(sparseResult.highestSeenFindingSeq).toBe(5);
    expect(sparseResult.appliedHeadAnnouncement).toBeNull();
    expect(sparseResult.rejectedHeadAnnouncement).toEqual(
      expect.objectContaining({
        announcement: expect.objectContaining({ headSeq: 5 }),
        reason: "gap_incomplete",
      }),
    );

    const nextPlan = planSwarmReplay({
      swarmId: "swm_alpha",
      feedId: "fed.alpha",
      issuerId: ISSUER_ID,
      localFindingSeq: sparseResult.latestFindingSeq,
      localMaxFindingSeq: sparseResult.highestSeenFindingSeq,
      localHeadSeq: sparseResult.latestHeadSeq,
      remoteHeadSeq: 5,
    });

    expect(nextPlan.request).toMatchObject({
      fromSeq: 3,
      toSeq: 5,
      localFindingSeq: 2,
      localMaxFindingSeq: 5,
      localHeadSeq: 2,
      remoteHeadSeq: 5,
    });
  });
});

describe("validateSwarmReplayBatch", () => {
  it("filters stale, duplicate, out-of-range, and mismatched replay entries fail-closed", () => {
    const request = planSwarmReplay({
      swarmId: "swm_alpha",
      feedId: "fed.alpha",
      issuerId: ISSUER_ID,
      localFindingSeq: 2,
      localMaxFindingSeq: 2,
      localHeadSeq: 2,
      remoteHeadSeq: 5,
    }).request;

    expect(request).not.toBeNull();

    const result = validateSwarmReplayBatch({
      request: request!,
      existingSeqs: [1, 2],
      currentHeadSeq: 2,
      batch: {
        envelopes: [
          makeFindingEnvelope({
            findingId: "fnd_stale",
            feedSeq: 2,
          }),
          makeFindingEnvelope({
            findingId: "fnd_valid",
            feedSeq: 3,
          }),
          makeFindingEnvelope({
            findingId: "fnd_duplicate",
            feedSeq: 3,
          }),
          makeFindingEnvelope({
            findingId: "fnd_wrong_issuer",
            feedSeq: 4,
            issuerId: OTHER_ISSUER_ID,
          }),
          makeFindingEnvelope({
            findingId: "fnd_out_of_range",
            feedSeq: 6,
          }),
        ],
        headAnnouncement: makeHeadAnnouncement({
          feedId: "fed.bravo",
          headEnvelopeHash: HEX_2,
        }),
      },
    });

    expect(result.acceptedEnvelopes.map((entry) => entry.feedSeq)).toEqual([3]);
    expect(result.rejectedEnvelopes).toEqual([
      expect.objectContaining({
        envelope: expect.objectContaining({ findingId: "fnd_stale", feedSeq: 2 }),
        reason: "stale_seq",
      }),
      expect.objectContaining({
        envelope: expect.objectContaining({ findingId: "fnd_duplicate", feedSeq: 3 }),
        reason: "duplicate_seq",
      }),
      expect.objectContaining({
        envelope: expect.objectContaining({ findingId: "fnd_wrong_issuer", feedSeq: 4 }),
        reason: "target_mismatch",
      }),
      expect.objectContaining({
        envelope: expect.objectContaining({ findingId: "fnd_out_of_range", feedSeq: 6 }),
        reason: "out_of_range",
      }),
    ]);
    expect(result.appliedHeadAnnouncement).toBeNull();
    expect(result.rejectedHeadAnnouncement).toEqual(
      expect.objectContaining({
        announcement: expect.objectContaining({ feedId: "fed.bravo" }),
        reason: "target_mismatch",
      }),
    );
    expect(result.latestFindingSeq).toBe(3);
    expect(result.highestSeenFindingSeq).toBe(3);
    expect(result.latestHeadSeq).toBe(2);
  });
});
