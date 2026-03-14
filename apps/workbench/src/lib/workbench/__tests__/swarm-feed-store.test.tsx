import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { generateOperatorKeypair } from "../operator-crypto";
import { signDetachedPayload } from "../signature-adapter";
import {
  FINDING_ENVELOPE_SCHEMA,
  HEAD_ANNOUNCEMENT_SCHEMA,
  REVOCATION_ENVELOPE_SCHEMA,
  extractFindingEnvelopeSignableFields,
  hashProtocolPayload,
  type FindingEnvelope,
  type HeadAnnouncement,
  type HubTrustPolicy,
  type ProtocolDigest,
  type RevocationEnvelope,
} from "../swarm-protocol";
import {
  SwarmFeedProvider,
  useSwarmFeed,
  type SwarmFindingReferenceResolution,
} from "../swarm-feed-store";
import {
  DEFAULT_HUB_TRUST_POLICY,
  FAIL_CLOSED_HUB_TRUST_POLICY,
} from "../swarm-trust-policy";

const STORAGE_KEY = "clawdstrike_workbench_swarm_feed";
const HEX_1 = `0x${"1".repeat(64)}` as ProtocolDigest;
const HEX_2 = `0x${"2".repeat(64)}` as ProtocolDigest;
const HEX_3 = `0x${"3".repeat(64)}` as ProtocolDigest;
const PUBLIC_KEY = "b".repeat(64);
const OTHER_PUBLIC_KEY = "c".repeat(64);
const SIGNATURE = "a".repeat(128);
const ISSUER_ID = `aegis:ed25519:${PUBLIC_KEY}`;
const OTHER_ISSUER_ID = `aegis:ed25519:${OTHER_PUBLIC_KEY}`;
type ReplayHarnessApi = Pick<
  ReturnType<typeof useSwarmFeed>,
  "deriveReplayRequest" | "ingestReplayBatch"
>;
type ProjectedFindingHarnessRecord = NonNullable<ProjectionHarnessApi["projectedFindingRecords"]>[number];
type ProjectionHarnessApi = ReturnType<typeof useSwarmFeed> & {
  ingestRevocationEnvelope?: (record: {
    swarmId: string;
    envelope: RevocationEnvelope;
    receivedAt: number;
  }) => unknown;
  projectedFindingRecords?: Array<{
    swarmId: string;
    receivedAt: number;
    sourceFindingIds?: string[];
    envelope: FindingEnvelope;
  }>;
  resolveFindingReference?: (
    swarmId: string,
    feedId: string,
    issuerId: string,
    findingId: string,
  ) =>
    | {
        status: "active" | "revoked" | "superseded";
        findingId: string;
        envelope?: FindingEnvelope;
        revocation?: RevocationEnvelope;
        replacement?: {
          id: string;
          digest?: ProtocolDigest;
          envelope?: FindingEnvelope;
        };
      }
    | null
    | undefined;
  revocationEnvelopeRecords?: Array<{
    swarmId: string;
    envelope: RevocationEnvelope;
    receivedAt: number;
  }>;
};
type SignatureHarnessApi = Pick<
  ReturnType<typeof useSwarmFeed>,
  | "deriveReplayRequest"
  | "getFeedSyncState"
  | "getLatestFindingSeq"
  | "getLatestHeadSeq"
  | "getTrustPolicy"
  | "ingestFindingEnvelope"
  | "ingestReplayBatch"
  | "listFindingEnvelopesForFeed"
  | "setTrustPolicy"
>;
type TrustPolicyHarnessApi = ReturnType<typeof useSwarmFeed> & {
  setTrustPolicy?: (swarmId: string, policy: HubTrustPolicy) => unknown;
  getTrustPolicy?: (swarmId: string) => HubTrustPolicy | null | undefined;
};
type DuplicateGuardHarnessApi = Pick<
  ReturnType<typeof useSwarmFeed>,
  | "findingEnvelopeRecords"
  | "revocationEnvelopeRecords"
  | "ingestFindingEnvelope"
  | "ingestRevocationEnvelope"
>;
type PolicyFlipHarnessApi = Pick<
  ReturnType<typeof useSwarmFeed>,
  | "deriveReplayRequest"
  | "getFeedSyncState"
  | "ingestFindingEnvelope"
  | "ingestRevocationEnvelope"
  | "setTrustPolicy"
>;
type HeadLaneHarnessApi = ReturnType<typeof useSwarmFeed> & {
  headAnnouncementRecords?: Array<{
    swarmId: string;
    announcement: HeadAnnouncement;
    receivedAt: number;
    lane?: "findings" | "revocations";
  }>;
  ingestHeadAnnouncement?: (record: {
    swarmId: string;
    announcement: HeadAnnouncement;
    receivedAt: number;
    lane?: "findings" | "revocations";
  }) => unknown;
  getHeadAnnouncement?: (
    swarmId: string,
    feedId: string,
    issuerId: string,
  ) => HeadAnnouncement | undefined;
  getLatestHeadSeq?: (swarmId: string, feedId: string, issuerId: string) => number | null;
};

interface FindingSignerFixture {
  issuerId: string;
  publicKeyHex: string;
  secretKeyHex: string;
}

let replayApi: ReplayHarnessApi | null = null;
let projectionApi: ProjectionHarnessApi | null = null;
let signatureApi: SignatureHarnessApi | null = null;
let lastTrustIngestResult: unknown = null;
let lastTrustReplayResult: unknown = null;
let lastStrictSignatureIngestResult: unknown = null;
let lastStrictSignatureReplayResult: unknown = null;
let duplicateGuardApi: DuplicateGuardHarnessApi | null = null;
let policyFlipApi: PolicyFlipHarnessApi | null = null;
let headLaneApi: HeadLaneHarnessApi | null = null;

const STRICT_TRUST_POLICY: HubTrustPolicy = {
  trustedIssuers: [ISSUER_ID],
  blockedIssuers: [OTHER_ISSUER_ID],
  requireAttestation: true,
  requireWitnessProofs: true,
  allowedSchemas: [FINDING_ENVELOPE_SCHEMA],
};

const QUARANTINE_BOUNDARY_POLICY: HubTrustPolicy = {
  trustedIssuers: [],
  blockedIssuers: [],
  requireAttestation: false,
  requireWitnessProofs: false,
  allowedSchemas: [REVOCATION_ENVELOPE_SCHEMA, FINDING_ENVELOPE_SCHEMA],
};

function issuerIdFromPublicKey(publicKey: string): string {
  return `aegis:ed25519:${publicKey}`;
}

async function createFindingSigner(): Promise<FindingSignerFixture> {
  const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
  return {
    issuerId: issuerIdFromPublicKey(publicKeyHex),
    publicKeyHex,
    secretKeyHex,
  };
}

async function signFindingEnvelope(
  envelope: FindingEnvelope,
  signer: FindingSignerFixture,
): Promise<FindingEnvelope> {
  const unsignedEnvelope = { ...envelope };
  if (unsignedEnvelope.attestation === undefined) {
    delete unsignedEnvelope.attestation;
  }
  const digest = await hashProtocolPayload(
    extractFindingEnvelopeSignableFields(unsignedEnvelope),
  );
  const signature = await signDetachedPayload(new TextEncoder().encode(digest), signer.secretKeyHex);

  return {
    ...unsignedEnvelope,
    attestation: {
      algorithm: "ed25519",
      publicKey: signer.publicKeyHex,
      signature,
    },
  };
}

async function createSignedFindingEnvelope(
  signer: FindingSignerFixture,
  overrides: Omit<Partial<FindingEnvelope>, "issuerId" | "attestation"> = {},
): Promise<FindingEnvelope> {
  return signFindingEnvelope(
    makeFindingEnvelope({
      ...overrides,
      issuerId: signer.issuerId,
      attestation: undefined,
    }),
    signer,
  );
}

function makeVerifiedIssuerTrustPolicy(issuerId: string): HubTrustPolicy {
  return {
    trustedIssuers: [issuerId],
    blockedIssuers: [],
    requireAttestation: true,
    requireWitnessProofs: true,
    allowedSchemas: [FINDING_ENVELOPE_SCHEMA],
  };
}

function makeFindingEnvelope(overrides: Partial<FindingEnvelope> = {}): FindingEnvelope {
  const issuerId = overrides.issuerId ?? ISSUER_ID;
  const attestedPublicKey =
    issuerId.startsWith("aegis:ed25519:") ? issuerId.slice("aegis:ed25519:".length) : PUBLIC_KEY;
  return {
    schema: FINDING_ENVELOPE_SCHEMA,
    findingId: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
    issuerId,
    feedId: "fed.alpha",
    feedSeq: 7,
    publishedAt: 1_715_000_000_000,
    title: "Suspicious shell pipeline",
    summary: "Repeated shell + egress behavior across one runtime session.",
    severity: "high",
    confidence: 0.92,
    status: "confirmed",
    signalCount: 3,
    tags: ["egress", "shell"],
    relatedFindingIds: ["fnd_01J6Y8QF4N63N6K7R73Q4AJ7AA"],
    blobRefs: [
      {
        blobId: "blob_01J6Y8QF4N63N6K7R73Q4AJ7B1",
        digest: HEX_1,
        mediaType: "application/json",
        byteLength: 512,
        publish: {
          uri: "ipfs://blob-one",
          notaryRecordId: "notary-record-1",
          notaryEnvelopeHash: HEX_2,
          publishedAt: 1_715_000_000_001,
          witnessProofs: [
            {
              provider: "witness",
              digest: HEX_3,
              uri: "https://witness.example/proofs/1",
            },
          ],
        },
      },
    ],
    attestation: {
      algorithm: "ed25519",
      publicKey: attestedPublicKey,
      signature: SIGNATURE,
    },
    publish: {
      uri: "https://hub.example/findings/fnd_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
      notaryRecordId: "notary-finding-1",
      notaryEnvelopeHash: HEX_2,
      publishedAt: 1_715_000_000_002,
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
    headEnvelopeHash: HEX_3,
    entryCount: 9,
    checkpointRef: {
      logId: "log_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
      checkpointSeq: 5,
      envelopeHash: HEX_2,
    },
    announcedAt: 1_715_000_000_500,
    ...overrides,
  };
}

function makeRevocationEnvelope(overrides: Partial<RevocationEnvelope> = {}): RevocationEnvelope {
  const action = overrides.action ?? "revoke";
  return {
    schema: REVOCATION_ENVELOPE_SCHEMA,
    revocationId: "rev_01J6Y8QF4N63N6K7R73Q4AJ7R1",
    issuerId: ISSUER_ID,
    feedId: "fed.alpha",
    feedSeq: 8,
    issuedAt: 1_715_000_000_880,
    action,
    target: {
      schema: FINDING_ENVELOPE_SCHEMA,
      id: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
    },
    reason: "Revoked after duplicate analyst triage.",
    ...(action === "supersede"
      ? {
          replacement: {
            schema: FINDING_ENVELOPE_SCHEMA,
            id: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7NEW",
          },
        }
      : {}),
    ...overrides,
  };
}

function SwarmFeedHarness() {
  const {
    findingEnvelopeRecords,
    headAnnouncementRecords,
    ingestFindingEnvelope,
    ingestHeadAnnouncement,
    getFindingEnvelope,
    getHeadAnnouncement,
    getLatestFindingSeq,
    getLatestHeadSeq,
    listFindingEnvelopesForFeed,
  } = useSwarmFeed();

  return (
    <>
      <button
        data-testid="finding-base"
        onClick={() =>
          ingestFindingEnvelope({
            swarmId: "swm_alpha",
            receivedAt: 1_715_000_000_010,
            envelope: makeFindingEnvelope(),
          })
        }
      >
        finding base
      </button>
      <button
        data-testid="finding-newer"
        onClick={() =>
          ingestFindingEnvelope({
            swarmId: "swm_alpha",
            receivedAt: 1_715_000_000_020,
            envelope: makeFindingEnvelope({
              feedSeq: 9,
              title: "Suspicious shell pipeline v2",
            }),
          })
        }
      >
        finding newer
      </button>
      <button
        data-testid="head-newer"
        onClick={() =>
          ingestHeadAnnouncement({
            swarmId: "swm_alpha",
            lane: "findings",
            receivedAt: 1_715_000_000_600,
            announcement: makeHeadAnnouncement({
              headSeq: 5,
            }),
          })
        }
      >
        head newer
      </button>
      <button
        data-testid="head-older"
        onClick={() =>
          ingestHeadAnnouncement({
            swarmId: "swm_alpha",
            lane: "findings",
            receivedAt: 1_715_000_000_300,
            announcement: makeHeadAnnouncement({
              headSeq: 3,
              headEnvelopeHash: HEX_1,
            }),
          })
        }
      >
        head older
      </button>
      <pre data-testid="snapshot">
        {JSON.stringify({
          findingCount: findingEnvelopeRecords.length,
          headCount: headAnnouncementRecords.length,
          latestFindingSeq: getLatestFindingSeq("swm_alpha", "fed.alpha"),
          latestHeadSeq: getLatestHeadSeq("swm_alpha", "fed.alpha", ISSUER_ID),
          findingTitle:
            getFindingEnvelope("swm_alpha", "fed.alpha", ISSUER_ID, "fnd_01J6Y8QF4N63N6K7R73Q4AJ7Z8")
              ?.title ?? null,
          headHash:
            getHeadAnnouncement("swm_alpha", "fed.alpha", ISSUER_ID)?.headEnvelopeHash ?? null,
          feedFindingCount: listFindingEnvelopesForFeed("swm_alpha", "fed.alpha").length,
        })}
      </pre>
    </>
  );
}

function SwarmReplayHarness() {
  const {
    ingestFindingEnvelope,
    ingestHeadAnnouncement,
    listFindingEnvelopesForFeed,
    getLatestFindingSeq,
    getLatestHeadSeq,
    getFeedSyncState,
    deriveReplayRequest,
    ingestReplayBatch,
  } = useSwarmFeed();
  replayApi = {
    deriveReplayRequest,
    ingestReplayBatch,
  };

  const remoteHead = makeHeadAnnouncement({
    headSeq: 5,
    entryCount: 5,
    headEnvelopeHash: HEX_3,
  });
  const replayRequest = deriveReplayRequest("swm_alpha", remoteHead);
  const syncState = getFeedSyncState("swm_alpha", "fed.alpha", ISSUER_ID);

  return (
    <>
      <button
        data-testid="seed-gap"
        onClick={() => {
          ingestFindingEnvelope({
            swarmId: "swm_alpha",
            receivedAt: 1_715_000_000_010,
            envelope: makeFindingEnvelope({
              findingId: "fnd_gap_1",
              feedSeq: 1,
              title: "Gap seed 1",
            }),
          });
          ingestFindingEnvelope({
            swarmId: "swm_alpha",
            receivedAt: 1_715_000_000_020,
            envelope: makeFindingEnvelope({
              findingId: "fnd_gap_2",
              feedSeq: 2,
              title: "Gap seed 2",
            }),
          });
          ingestHeadAnnouncement({
            swarmId: "swm_alpha",
            lane: "findings",
            receivedAt: 1_715_000_000_030,
            announcement: makeHeadAnnouncement({
              headSeq: 2,
              entryCount: 2,
              headEnvelopeHash: HEX_2,
            }),
          });
        }}
      >
        seed gap
      </button>
      <button
        data-testid="ingest-replay-gap"
        onClick={() => {
          if (!replayRequest) {
            return;
          }
          ingestReplayBatch(
            replayRequest,
            {
              envelopes: [
                makeFindingEnvelope({
                  findingId: "fnd_gap_3",
                  feedSeq: 3,
                  title: "Gap fill 3",
                }),
                makeFindingEnvelope({
                  findingId: "fnd_gap_4",
                  feedSeq: 4,
                  title: "Gap fill 4",
                }),
                makeFindingEnvelope({
                  findingId: "fnd_gap_5",
                  feedSeq: 5,
                  title: "Gap fill 5",
                }),
              ],
              headAnnouncement: remoteHead,
            },
            1_715_000_000_800,
          );
        }}
      >
        ingest replay gap
      </button>
      <button
        data-testid="ingest-replay-high-only"
        onClick={() => {
          if (!replayRequest) {
            return;
          }
          ingestReplayBatch(
            replayRequest,
            {
              envelopes: [
                makeFindingEnvelope({
                  findingId: "fnd_sparse_5",
                  feedSeq: 5,
                  title: "Sparse high replay",
                }),
              ],
              headAnnouncement: remoteHead,
            },
            1_715_000_000_850,
          );
        }}
      >
        ingest replay high only
      </button>
      <button
        data-testid="ingest-replay-invalid"
        onClick={() => {
          if (!replayRequest) {
            return;
          }
          ingestReplayBatch(
            replayRequest,
            {
              envelopes: [
                makeFindingEnvelope({
                  findingId: "fnd_stale",
                  feedSeq: 2,
                  title: "Stale replay",
                }),
                makeFindingEnvelope({
                  findingId: "fnd_valid_3",
                  feedSeq: 3,
                  title: "Valid replay",
                }),
                makeFindingEnvelope({
                  findingId: "fnd_duplicate_3",
                  feedSeq: 3,
                  title: "Duplicate replay",
                }),
                makeFindingEnvelope({
                  findingId: "fnd_wrong_issuer",
                  feedSeq: 4,
                  issuerId: `aegis:ed25519:${"c".repeat(64)}`,
                  title: "Wrong issuer replay",
                }),
                makeFindingEnvelope({
                  findingId: "fnd_out_of_range",
                  feedSeq: 6,
                  title: "Out of range replay",
                }),
              ],
              headAnnouncement: makeHeadAnnouncement({
                feedId: "fed.bravo",
              }),
            },
            1_715_000_000_900,
          );
        }}
      >
        ingest replay invalid
      </button>
      <pre data-testid="replay-snapshot">
        {JSON.stringify({
          requestFromSeq: replayRequest?.fromSeq ?? null,
          requestToSeq: replayRequest?.toSeq ?? null,
          syncState,
          maxFindingSeq: getLatestFindingSeq("swm_alpha", "fed.alpha"),
          latestHeadSeq: getLatestHeadSeq("swm_alpha", "fed.alpha", ISSUER_ID),
          feedFindingSeqs: listFindingEnvelopesForFeed("swm_alpha", "fed.alpha")
            .map((entry) => entry.feedSeq)
            .sort((left, right) => left - right),
        })}
      </pre>
    </>
  );
}

function SwarmHistoryHarness() {
  const {
    ingestFindingEnvelope,
    getFindingEnvelope,
    getFeedSyncState,
    listFindingEnvelopesForFeed,
  } = useSwarmFeed();

  return (
    <>
      <button
        data-testid="append-same-finding"
        onClick={() => {
          ingestFindingEnvelope({
            swarmId: "swm_history",
            receivedAt: 1_715_100_000_010,
            envelope: makeFindingEnvelope({
              feedId: "fed.replay",
              findingId: "fnd_repeat",
              feedSeq: 1,
              title: "Repeat finding v1",
            }),
          });
          ingestFindingEnvelope({
            swarmId: "swm_history",
            receivedAt: 1_715_100_000_020,
            envelope: makeFindingEnvelope({
              feedId: "fed.replay",
              findingId: "fnd_repeat",
              feedSeq: 2,
              title: "Repeat finding v2",
            }),
          });
        }}
      >
        append same finding
      </button>
      <button
        data-testid="cross-issuer-same-finding"
        onClick={() => {
          ingestFindingEnvelope({
            swarmId: "swm_history",
            receivedAt: 1_715_100_000_030,
            envelope: makeFindingEnvelope({
              feedId: "fed.shared",
              findingId: "fnd_shared",
              feedSeq: 1,
              title: "Issuer alpha copy",
            }),
          });
          ingestFindingEnvelope({
            swarmId: "swm_history",
            receivedAt: 1_715_100_000_040,
            envelope: makeFindingEnvelope({
              issuerId: OTHER_ISSUER_ID,
              feedId: "fed.shared",
              findingId: "fnd_shared",
              feedSeq: 1,
              title: "Issuer bravo copy",
            }),
          });
        }}
      >
        cross issuer same finding
      </button>
      <pre data-testid="history-snapshot">
        {JSON.stringify({
          repeatedLatestTitle:
            getFindingEnvelope("swm_history", "fed.replay", ISSUER_ID, "fnd_repeat")?.title ?? null,
          repeatedSeqs: listFindingEnvelopesForFeed("swm_history", "fed.replay")
            .filter((entry) => entry.findingId === "fnd_repeat")
            .map((entry) => entry.feedSeq)
            .sort((left, right) => left - right),
          repeatedSyncState: getFeedSyncState("swm_history", "fed.replay", ISSUER_ID),
          sharedEntries: listFindingEnvelopesForFeed("swm_history", "fed.shared")
            .filter((entry) => entry.findingId === "fnd_shared")
            .map((entry) => `${entry.issuerId}:${entry.feedSeq}`)
            .sort(),
          issuerAlphaSync: getFeedSyncState("swm_history", "fed.shared", ISSUER_ID),
          issuerBravoSync: getFeedSyncState("swm_history", "fed.shared", OTHER_ISSUER_ID),
        })}
      </pre>
    </>
  );
}

function SwarmDuplicateGuardHarness() {
  const api = useSwarmFeed() as DuplicateGuardHarnessApi;
  duplicateGuardApi = api;

  const findingRecords = api.findingEnvelopeRecords.filter(
    (record) =>
      record.swarmId === "swm_duplicates" &&
      record.envelope.feedId === "fed.duplicates" &&
      record.envelope.issuerId === ISSUER_ID &&
      record.envelope.feedSeq === 1,
  );
  const revocationRecords = api.revocationEnvelopeRecords.filter(
    (record) =>
      record.swarmId === "swm_duplicates" &&
      record.envelope.feedId === "fed.duplicates" &&
      record.envelope.issuerId === ISSUER_ID &&
      record.envelope.feedSeq === 1,
  );

  return (
    <pre data-testid="duplicate-guard-snapshot">
      {JSON.stringify({
        findingCount: findingRecords.length,
        findingTitle: findingRecords[0]?.envelope.title ?? null,
        findingReceivedAt: findingRecords[0]?.receivedAt ?? null,
        revocationCount: revocationRecords.length,
        revocationReason: revocationRecords[0]?.envelope.reason ?? null,
        revocationReceivedAt: revocationRecords[0]?.receivedAt ?? null,
      })}
    </pre>
  );
}

function SwarmHeadLaneHarness() {
  const api = useSwarmFeed() as HeadLaneHarnessApi;
  headLaneApi = api;

  const headRecords = (api.headAnnouncementRecords ?? []).filter(
    (record) =>
      record.swarmId === "swm_head_lanes" &&
      record.announcement.feedId === "fed.head-lanes" &&
      record.announcement.issuerId === ISSUER_ID,
  );

  return (
    <pre data-testid="head-lane-snapshot">
      {JSON.stringify({
        headCount: headRecords.length,
        lanes: headRecords.map((record) => record.lane ?? "findings").sort(),
        findingHeadHash:
          api.getHeadAnnouncement?.("swm_head_lanes", "fed.head-lanes", ISSUER_ID)?.headEnvelopeHash ??
          null,
        latestFindingHeadSeq:
          api.getLatestHeadSeq?.("swm_head_lanes", "fed.head-lanes", ISSUER_ID) ?? null,
      })}
    </pre>
  );
}

function SwarmProjectionHarness() {
  const api = useSwarmFeed() as ProjectionHarnessApi;
  projectionApi = api;
  const projectedFindingRecords = api.projectedFindingRecords ?? [];
  const revokeResolution = api.resolveFindingReference?.(
    "swm_projection",
    "fed.projection",
    ISSUER_ID,
    "fnd_revoked",
  );
  const reemitResolution = api.resolveFindingReference?.(
    "swm_projection",
    "fed.projection",
    ISSUER_ID,
    "fnd_reemit",
  );
  const supersedeResolution = api.resolveFindingReference?.(
    "swm_projection",
    "fed.projection",
    ISSUER_ID,
    "fnd_source",
  );
  const summarizeResolution = (resolution: SwarmFindingReferenceResolution | null | undefined) => {
    if (!resolution) {
      return null;
    }

    if (resolution.status === "active") {
      return {
        status: resolution.status,
        findingId: resolution.findingId,
        revocationId: null,
        replacementId: null,
        replacementEnvelopeId: null,
      };
    }

    if (resolution.status === "revoked") {
      return {
        status: resolution.status,
        findingId: resolution.findingId,
        revocationId: resolution.revocation.revocationId,
        replacementId: null,
        replacementEnvelopeId: null,
      };
    }

    return {
      status: resolution.status,
      findingId: resolution.findingId,
      revocationId: resolution.revocation.revocationId,
      replacementId: resolution.replacement.id,
      replacementEnvelopeId: resolution.replacement.envelope?.findingId ?? null,
    };
  };

  return (
    <>
      <button
        data-testid="seed-revoke-projection"
        onClick={() => {
          api.ingestFindingEnvelope({
            swarmId: "swm_projection",
            receivedAt: 1_715_200_000_010,
            envelope: makeFindingEnvelope({
              feedId: "fed.projection",
              findingId: "fnd_revoked",
              feedSeq: 1,
              title: "Revoked finding",
            }),
          });
          api.ingestRevocationEnvelope?.({
            swarmId: "swm_projection",
            receivedAt: 1_715_200_000_020,
            envelope: makeRevocationEnvelope({
              revocationId: "rev_projection_revoke",
              feedId: "fed.projection",
              feedSeq: 2,
              issuedAt: 1_715_200_000_020,
              target: {
                schema: FINDING_ENVELOPE_SCHEMA,
                id: "fnd_revoked",
              },
              action: "revoke",
              replacement: undefined,
              reason: "Finding revoked during analyst review.",
            }),
          });
        }}
      >
        seed revoke projection
      </button>
      <button
        data-testid="seed-supersede-projection"
        onClick={() => {
          api.ingestFindingEnvelope({
            swarmId: "swm_projection",
            receivedAt: 1_715_200_000_030,
            envelope: makeFindingEnvelope({
              feedId: "fed.projection",
              findingId: "fnd_source",
              feedSeq: 3,
              title: "Superseded source finding",
              blobRefs: [
                {
                  blobId: "blob_superseded_source",
                  digest: HEX_1,
                  mediaType: "application/json",
                  byteLength: 64,
                },
              ],
            }),
          });
          api.ingestFindingEnvelope({
            swarmId: "swm_projection",
            receivedAt: 1_715_200_000_040,
            envelope: makeFindingEnvelope({
              feedId: "fed.projection",
              findingId: "fnd_replacement",
              feedSeq: 4,
              title: "Replacement finding",
              blobRefs: [
                {
                  blobId: "blob_superseded_replacement",
                  digest: HEX_2,
                  mediaType: "application/json",
                  byteLength: 96,
                },
              ],
            }),
          });
          api.ingestRevocationEnvelope?.({
            swarmId: "swm_projection",
            receivedAt: 1_715_200_000_050,
            envelope: makeRevocationEnvelope({
              revocationId: "rev_projection_supersede",
              feedId: "fed.projection",
              feedSeq: 5,
              issuedAt: 1_715_200_000_050,
              action: "supersede",
              target: {
                schema: FINDING_ENVELOPE_SCHEMA,
                id: "fnd_source",
              },
              replacement: {
                schema: FINDING_ENVELOPE_SCHEMA,
                id: "fnd_replacement",
              },
              reason: "Finding superseded by replacement analyst record.",
            }),
          });
        }}
      >
        seed supersede projection
      </button>
      <pre data-testid="projection-snapshot">
        {JSON.stringify({
          revocationCount: api.revocationEnvelopeRecords?.length ?? null,
          projectedFindingIds: projectedFindingRecords
            .map((record) => record.envelope.findingId)
            .sort(),
          projectedFindingTitles: Object.fromEntries(
            projectedFindingRecords.map((record) => [record.envelope.findingId, record.envelope.title]),
          ),
          projectedSourceFindingIds: Object.fromEntries(
            projectedFindingRecords.map((record) => [
              record.envelope.findingId,
              [...(record.sourceFindingIds ?? [])].sort(),
            ]),
          ),
          revokeResolution: summarizeResolution(revokeResolution),
          reemitResolution: summarizeResolution(reemitResolution),
          supersedeResolution: summarizeResolution(supersedeResolution),
        })}
      </pre>
    </>
  );
}

function SwarmTrustPolicyHarness() {
  const api = useSwarmFeed() as TrustPolicyHarnessApi;
  const {
    deriveReplayRequest,
    getFeedSyncState,
    getLatestFindingSeq,
    getLatestHeadSeq,
    ingestFindingEnvelope,
    ingestReplayBatch,
    listFindingEnvelopesForFeed,
  } = api;

  const remoteHead = makeHeadAnnouncement({
    headSeq: 3,
    entryCount: 3,
    headEnvelopeHash: HEX_3,
  });
  const replayRequest = deriveReplayRequest("swm_trust", remoteHead);

  return (
    <>
      <button
        data-testid="set-trust-policy"
        onClick={() => {
          api.setTrustPolicy?.("swm_trust", STRICT_TRUST_POLICY);
        }}
      >
        set trust policy
      </button>
      <button
        data-testid="ingest-trust-valid"
        onClick={async () => {
          lastTrustIngestResult = await ingestFindingEnvelope({
            swarmId: "swm_trust",
            receivedAt: 1_715_000_001_000,
            envelope: makeFindingEnvelope({
              findingId: "fnd_trust_valid",
              feedSeq: 1,
            }),
          });
        }}
      >
        ingest trust valid
      </button>
      <button
        data-testid="ingest-trust-blocked"
        onClick={async () => {
          lastTrustIngestResult = await ingestFindingEnvelope({
            swarmId: "swm_trust",
            receivedAt: 1_715_000_001_000,
            envelope: makeFindingEnvelope({
              findingId: "fnd_trust_blocked",
              feedSeq: 1,
              issuerId: OTHER_ISSUER_ID,
              attestation: {
                algorithm: "ed25519",
                publicKey: OTHER_PUBLIC_KEY,
                signature: SIGNATURE,
              },
            }),
          });
        }}
      >
        ingest trust blocked
      </button>
      <button
        data-testid="same-turn-trust-blocked"
        onClick={async () => {
          api.setTrustPolicy?.("swm_trust", STRICT_TRUST_POLICY);
          lastTrustIngestResult = await ingestFindingEnvelope({
            swarmId: "swm_trust",
            receivedAt: 1_715_000_001_000,
            envelope: makeFindingEnvelope({
              findingId: "fnd_trust_same_turn_blocked",
              feedSeq: 1,
              issuerId: OTHER_ISSUER_ID,
              attestation: {
                algorithm: "ed25519",
                publicKey: OTHER_PUBLIC_KEY,
                signature: SIGNATURE,
              },
            }),
          });
        }}
      >
        same turn trust blocked
      </button>
      <button
        data-testid="ingest-trust-replay"
        onClick={async () => {
          if (!replayRequest) {
            return;
          }

          lastTrustReplayResult = await ingestReplayBatch(
            replayRequest,
            {
              envelopes: [
                makeFindingEnvelope({
                  findingId: "fnd_trust_accept_1",
                  feedSeq: 1,
                  title: "Accepted replay 1",
                }),
                makeFindingEnvelope({
                  findingId: "fnd_trust_reject_2",
                  feedSeq: 2,
                  title: "Rejected replay 2",
                  attestation: undefined,
                }),
                makeFindingEnvelope({
                  findingId: "fnd_trust_accept_3",
                  feedSeq: 3,
                  title: "Accepted replay 3",
                }),
              ],
              headAnnouncement: remoteHead,
            },
            1_715_000_001_100,
          );
        }}
      >
        ingest trust replay
      </button>
      <button
        data-testid="same-turn-trust-replay"
        onClick={async () => {
          if (!replayRequest) {
            return;
          }

          api.setTrustPolicy?.("swm_trust", STRICT_TRUST_POLICY);
          lastTrustReplayResult = await ingestReplayBatch(
            replayRequest,
            {
              envelopes: [
                makeFindingEnvelope({
                  findingId: "fnd_trust_same_turn_reject_1",
                  feedSeq: 1,
                  title: "Same-turn rejected replay 1",
                  attestation: undefined,
                }),
              ],
              headAnnouncement: remoteHead,
            },
            1_715_000_001_100,
          );
        }}
      >
        same turn trust replay
      </button>
      <pre data-testid="trust-snapshot">
        {JSON.stringify({
          trustPolicy: api.getTrustPolicy?.("swm_trust") ?? null,
          replayRequestFromSeq: replayRequest?.fromSeq ?? null,
          replayRequestToSeq: replayRequest?.toSeq ?? null,
          latestStoredSeq: getLatestFindingSeq("swm_trust", "fed.alpha"),
          latestHeadSeq: getLatestHeadSeq("swm_trust", "fed.alpha", ISSUER_ID),
          syncState: getFeedSyncState("swm_trust", "fed.alpha", ISSUER_ID),
          findingSeqs: listFindingEnvelopesForFeed("swm_trust", "fed.alpha")
            .filter((entry) => entry.issuerId === ISSUER_ID)
            .map((entry) => entry.feedSeq)
            .sort((left, right) => left - right),
        })}
      </pre>
    </>
  );
}

function SwarmPolicyFlipHarness() {
  const api = useSwarmFeed();
  policyFlipApi = api;
  const activeFindingRecords = api.findingEnvelopeRecords.filter(
    (record) => record.swarmId === "swm_policy_flip",
  );
  const activeHeadRecords = api.headAnnouncementRecords.filter(
    (record) => record.swarmId === "swm_policy_flip",
  );
  const activeRevocationRecords = api.revocationEnvelopeRecords.filter(
    (record) => record.swarmId === "swm_policy_flip",
  );

  return (
    <>
      <button
        data-testid="seed-policy-flip"
        onClick={async () => {
          await api.ingestFindingEnvelope({
            swarmId: "swm_policy_flip",
            receivedAt: 1_715_400_000_010,
            envelope: makeFindingEnvelope({
              feedId: "fed.policy-flip",
              findingId: "fnd_policy_flip",
              feedSeq: 1,
              title: "Policy flip finding",
            }),
          });
          api.ingestHeadAnnouncement({
            swarmId: "swm_policy_flip",
            lane: "findings",
            receivedAt: 1_715_400_000_020,
            announcement: makeHeadAnnouncement({
              feedId: "fed.policy-flip",
              headSeq: 1,
              headEnvelopeHash: HEX_2,
            }),
          });
          await api.ingestRevocationEnvelope({
            swarmId: "swm_policy_flip",
            receivedAt: 1_715_400_000_030,
            envelope: makeRevocationEnvelope({
              feedId: "fed.policy-flip",
              revocationId: "rev_policy_flip",
              feedSeq: 2,
              target: {
                schema: FINDING_ENVELOPE_SCHEMA,
                id: "fnd_policy_flip",
              },
              reason: "Policy flip revocation",
            }),
          });
        }}
      >
        seed policy flip
      </button>
      <button
        data-testid="tighten-policy-flip"
        onClick={() => {
          api.setTrustPolicy("swm_policy_flip", STRICT_TRUST_POLICY);
        }}
      >
        tighten policy flip
      </button>
      <button
        data-testid="relax-policy-flip"
        onClick={() => {
          api.setTrustPolicy("swm_policy_flip", DEFAULT_HUB_TRUST_POLICY);
        }}
      >
        relax policy flip
      </button>
      <pre data-testid="policy-flip-snapshot">
        {JSON.stringify({
          trustPolicy: api.getTrustPolicy("swm_policy_flip"),
          activeFindingIds: activeFindingRecords.map((record) => record.envelope.findingId).sort(),
          activeFindingSeqs: activeFindingRecords
            .map((record) => record.envelope.feedSeq)
            .sort((left, right) => left - right),
          activeHeadKeys: activeHeadRecords
            .map(
              (record) =>
                `${record.lane ?? "findings"}:${record.announcement.feedId}:${record.announcement.headSeq}`,
            )
            .sort(),
          activeRevocationIds: activeRevocationRecords
            .map((record) => record.envelope.revocationId)
            .sort(),
          activeRevocationSeqs: activeRevocationRecords
            .map((record) => record.envelope.feedSeq)
            .sort((left, right) => left - right),
        })}
      </pre>
    </>
  );
}

function SwarmStrictSignatureHarness({
  swarmId,
  feedId,
  issuerId,
  remoteHeadSeq,
}: {
  swarmId: string;
  feedId: string;
  issuerId: string;
  remoteHeadSeq: number;
}) {
  const api = useSwarmFeed();
  const {
    deriveReplayRequest,
    getFeedSyncState,
    getLatestFindingSeq,
    getLatestHeadSeq,
    getTrustPolicy,
    listFindingEnvelopesForFeed,
  } = api;
  signatureApi = api;

  const replayRequest = deriveReplayRequest(
    swarmId,
    makeHeadAnnouncement({
      feedId,
      issuerId,
      headSeq: remoteHeadSeq,
      entryCount: remoteHeadSeq,
      headEnvelopeHash: HEX_3,
    }),
  );

  return (
    <pre data-testid="strict-signature-snapshot">
      {JSON.stringify({
        trustPolicy: getTrustPolicy(swarmId),
        replayRequestFromSeq: replayRequest?.fromSeq ?? null,
        replayRequestToSeq: replayRequest?.toSeq ?? null,
        latestStoredSeq: getLatestFindingSeq(swarmId, feedId),
        latestHeadSeq: getLatestHeadSeq(swarmId, feedId, issuerId),
        syncState: getFeedSyncState(swarmId, feedId, issuerId),
        findingSeqs: listFindingEnvelopesForFeed(swarmId, feedId)
          .filter((entry) => entry.issuerId === issuerId)
          .map((entry) => entry.feedSeq)
          .sort((left, right) => left - right),
      })}
    </pre>
  );
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  localStorage.clear();
  replayApi = null;
  projectionApi = null;
  signatureApi = null;
  duplicateGuardApi = null;
  policyFlipApi = null;
  headLaneApi = null;
  lastTrustIngestResult = null;
  lastTrustReplayResult = null;
  lastStrictSignatureIngestResult = null;
  lastStrictSignatureReplayResult = null;
});

describe("swarm-feed-store", () => {
  it("persists finding envelopes and keeps the newest head announcement per feed issuer", () => {
    vi.useFakeTimers();

    const { unmount } = render(
      <SwarmFeedProvider>
        <SwarmFeedHarness />
      </SwarmFeedProvider>,
    );

    fireEvent.click(screen.getByTestId("finding-base"));
    fireEvent.click(screen.getByTestId("finding-newer"));
    fireEvent.click(screen.getByTestId("head-newer"));
    fireEvent.click(screen.getByTestId("head-older"));

    expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
      findingCount: 2,
      headCount: 1,
      latestFindingSeq: 9,
      latestHeadSeq: 5,
      findingTitle: "Suspicious shell pipeline v2",
      headHash: HEX_3,
      feedFindingCount: 2,
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted.findingEnvelopes).toHaveLength(2);
    expect(
      persisted.findingEnvelopes
        .map((record: { envelope: { feedSeq: number } }) => record.envelope.feedSeq)
        .sort((left: number, right: number) => left - right),
    ).toEqual([7, 9]);
    expect(persisted.headAnnouncements).toHaveLength(1);
    expect(persisted.headAnnouncements[0]).toMatchObject({
      swarmId: "swm_alpha",
      announcement: {
        headSeq: 5,
        headEnvelopeHash: HEX_3,
      },
    });

    unmount();

    render(
      <SwarmFeedProvider>
        <SwarmFeedHarness />
      </SwarmFeedProvider>,
    );

    expect(JSON.parse(screen.getByTestId("snapshot").textContent ?? "{}")).toMatchObject({
      findingCount: 2,
      headCount: 1,
      latestFindingSeq: 9,
      latestHeadSeq: 5,
      findingTitle: "Suspicious shell pipeline v2",
      headHash: HEX_3,
    });
  });

  it("quarantines persisted finding and head records for strict-policy swarms until revalidation exists", () => {
    vi.useFakeTimers();

    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        findingEnvelopes: [
          {
            swarmId: "swm_strict_reload",
            receivedAt: 1_715_000_001_000,
            envelope: makeFindingEnvelope({
              feedId: "fed.strict-reload",
              findingId: "fnd_strict_reload",
              feedSeq: 1,
            }),
          },
        ],
        headAnnouncements: [
          {
            swarmId: "swm_strict_reload",
            receivedAt: 1_715_000_001_050,
            announcement: makeHeadAnnouncement({
              feedId: "fed.strict-reload",
              issuerId: ISSUER_ID,
              headSeq: 1,
            }),
          },
        ],
        trustPolicies: {
          swm_strict_reload: STRICT_TRUST_POLICY,
        },
      }),
    );

    render(
      <SwarmFeedProvider>
        <SwarmStrictSignatureHarness
          swarmId="swm_strict_reload"
          feedId="fed.strict-reload"
          issuerId={ISSUER_ID}
          remoteHeadSeq={1}
        />
      </SwarmFeedProvider>,
    );

    expect(JSON.parse(screen.getByTestId("strict-signature-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: STRICT_TRUST_POLICY,
      replayRequestFromSeq: null,
      replayRequestToSeq: null,
      latestStoredSeq: null,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_strict_reload",
        feedId: "fed.strict-reload",
        issuerId: ISSUER_ID,
        localFindingSeq: 1,
        localMaxFindingSeq: 1,
        localHeadSeq: null,
      },
      findingSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted.trustPolicies).toMatchObject({
      swm_strict_reload: STRICT_TRUST_POLICY,
    });
    expect(persisted.findingEnvelopes).toEqual([]);
    expect(persisted.headAnnouncements).toEqual([]);
    expect(persisted.quarantinedFindingEnvelopes).toEqual([
      expect.objectContaining({
        swarmId: "swm_strict_reload",
        receivedAt: 1_715_000_001_000,
        envelope: expect.objectContaining({
          feedId: "fed.strict-reload",
          findingId: "fnd_strict_reload",
          feedSeq: 1,
        }),
      }),
    ]);
    expect(persisted.quarantinedHeadAnnouncements).toEqual([
      expect.objectContaining({
        swarmId: "swm_strict_reload",
        receivedAt: 1_715_000_001_050,
        announcement: expect.objectContaining({
          feedId: "fed.strict-reload",
          issuerId: ISSUER_ID,
          headSeq: 1,
        }),
      }),
    ]);
  });

  it("stores finding and revocation heads in separate lanes without overwriting the finding lane", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmHeadLaneHarness />
      </SwarmFeedProvider>,
    );

    expect(headLaneApi).not.toBeNull();

    await act(async () => {
      headLaneApi?.ingestHeadAnnouncement?.({
        swarmId: "swm_head_lanes",
        receivedAt: 1_715_000_002_010,
        lane: "findings",
        announcement: makeHeadAnnouncement({
          feedId: "fed.head-lanes",
          factId: "head_findings_lane",
          headSeq: 5,
          headEnvelopeHash: HEX_3,
          announcedAt: 1_715_000_002_000,
        }),
      });
      headLaneApi?.ingestHeadAnnouncement?.({
        swarmId: "swm_head_lanes",
        receivedAt: 1_715_000_002_020,
        lane: "revocations",
        announcement: makeHeadAnnouncement({
          feedId: "fed.head-lanes",
          factId: "head_revocations_lane",
          headSeq: 11,
          headEnvelopeHash: HEX_2,
          announcedAt: 1_715_000_002_010,
        }),
      });
    });

    expect(JSON.parse(screen.getByTestId("head-lane-snapshot").textContent ?? "{}")).toMatchObject({
      headCount: 2,
      lanes: ["findings", "revocations"],
      findingHeadHash: HEX_3,
      latestFindingHeadSeq: 5,
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(
      (JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}").headAnnouncements ?? [])
        .filter((record: { swarmId: string; announcement: { feedId: string; issuerId: string } }) =>
          record.swarmId === "swm_head_lanes" &&
          record.announcement.feedId === "fed.head-lanes" &&
          record.announcement.issuerId === ISSUER_ID,
        )
        .map((record: { lane?: string; announcement: { headEnvelopeHash: ProtocolDigest } }) => ({
          lane: record.lane ?? "findings",
          headEnvelopeHash: record.announcement.headEnvelopeHash,
        }))
        .sort((left: { lane: string }, right: { lane: string }) => left.lane.localeCompare(right.lane)),
    ).toEqual([
      {
        lane: "findings",
        headEnvelopeHash: HEX_3,
      },
      {
        lane: "revocations",
        headEnvelopeHash: HEX_2,
      },
    ]);
  });

  it("ingests replay batches into the durable feed store and advances local head state", () => {
    render(
      <SwarmFeedProvider>
        <SwarmReplayHarness />
      </SwarmFeedProvider>,
    );

    fireEvent.click(screen.getByTestId("seed-gap"));

    expect(JSON.parse(screen.getByTestId("replay-snapshot").textContent ?? "{}")).toMatchObject({
      requestFromSeq: 3,
      requestToSeq: 5,
      syncState: {
        swarmId: "swm_alpha",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: 2,
        localMaxFindingSeq: 2,
        localHeadSeq: 2,
      },
      maxFindingSeq: 2,
      latestHeadSeq: 2,
      feedFindingSeqs: [1, 2],
    });

    fireEvent.click(screen.getByTestId("ingest-replay-gap"));

    expect(JSON.parse(screen.getByTestId("replay-snapshot").textContent ?? "{}")).toMatchObject({
      requestFromSeq: null,
      requestToSeq: null,
      syncState: {
        swarmId: "swm_alpha",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: 5,
        localMaxFindingSeq: 5,
        localHeadSeq: 5,
      },
      maxFindingSeq: 5,
      latestHeadSeq: 5,
      feedFindingSeqs: [1, 2, 3, 4, 5],
    });
  });

  it("ignores stale, duplicate, and mismatched replay entries without corrupting durable state", () => {
    render(
      <SwarmFeedProvider>
        <SwarmReplayHarness />
      </SwarmFeedProvider>,
    );

    fireEvent.click(screen.getByTestId("seed-gap"));
    fireEvent.click(screen.getByTestId("ingest-replay-invalid"));

    expect(JSON.parse(screen.getByTestId("replay-snapshot").textContent ?? "{}")).toMatchObject({
      requestFromSeq: 4,
      requestToSeq: 5,
      syncState: {
        swarmId: "swm_alpha",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: 3,
        localMaxFindingSeq: 3,
        localHeadSeq: 2,
      },
      maxFindingSeq: 3,
      latestHeadSeq: 2,
      feedFindingSeqs: [1, 2, 3],
    });
  });

  it("keeps replay planning gap-aware when a batch only returns the highest in-range sequence", () => {
    render(
      <SwarmFeedProvider>
        <SwarmReplayHarness />
      </SwarmFeedProvider>,
    );

    fireEvent.click(screen.getByTestId("seed-gap"));
    fireEvent.click(screen.getByTestId("ingest-replay-high-only"));

    expect(JSON.parse(screen.getByTestId("replay-snapshot").textContent ?? "{}")).toMatchObject({
      requestFromSeq: 3,
      requestToSeq: 5,
      syncState: {
        swarmId: "swm_alpha",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: 2,
        localMaxFindingSeq: 5,
        localHeadSeq: 2,
      },
      maxFindingSeq: 5,
      latestHeadSeq: 2,
      feedFindingSeqs: [1, 2, 5],
    });
  });

  it("reduces replay batches against current state when called twice in one act", () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmReplayHarness />
      </SwarmFeedProvider>,
    );

    fireEvent.click(screen.getByTestId("seed-gap"));

    const request = replayApi?.deriveReplayRequest(
      "swm_alpha",
      makeHeadAnnouncement({
        headSeq: 5,
        entryCount: 5,
        headEnvelopeHash: HEX_3,
      }),
    );

    expect(request).not.toBeNull();

    act(() => {
      replayApi?.ingestReplayBatch(
        request!,
        {
          envelopes: [
            makeFindingEnvelope({
              findingId: "fnd_gap_3",
              feedSeq: 3,
              title: "Gap fill 3",
            }),
          ],
        },
        1_715_000_001_000,
      );
      replayApi?.ingestReplayBatch(
        request!,
        {
          envelopes: [
            makeFindingEnvelope({
              findingId: "fnd_gap_4",
              feedSeq: 4,
              title: "Gap fill 4",
            }),
          ],
        },
        1_715_000_001_010,
      );
    });

    expect(JSON.parse(screen.getByTestId("replay-snapshot").textContent ?? "{}")).toMatchObject({
      requestFromSeq: 5,
      requestToSeq: 5,
      syncState: {
        swarmId: "swm_alpha",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: 4,
        localMaxFindingSeq: 4,
        localHeadSeq: 2,
      },
      maxFindingSeq: 4,
      latestHeadSeq: 2,
      feedFindingSeqs: [1, 2, 3, 4],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(
      persisted.findingEnvelopes
        .filter((record: { swarmId: string; envelope: { feedId: string; issuerId: string } }) =>
          record.swarmId === "swm_alpha" &&
          record.envelope.feedId === "fed.alpha" &&
          record.envelope.issuerId === ISSUER_ID,
        )
        .map((record: { envelope: { feedSeq: number } }) => record.envelope.feedSeq)
        .sort((left: number, right: number) => left - right),
    ).toEqual([1, 2, 3, 4]);
  });

  it("preserves older feed sequences when the same finding id is re-emitted", () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmHistoryHarness />
      </SwarmFeedProvider>,
    );

    fireEvent.click(screen.getByTestId("append-same-finding"));

    expect(JSON.parse(screen.getByTestId("history-snapshot").textContent ?? "{}")).toMatchObject({
      repeatedLatestTitle: "Repeat finding v2",
      repeatedSeqs: [1, 2],
      repeatedSyncState: {
        swarmId: "swm_history",
        feedId: "fed.replay",
        issuerId: ISSUER_ID,
        localFindingSeq: 2,
        localMaxFindingSeq: 2,
        localHeadSeq: null,
      },
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(
      persisted.findingEnvelopes
        .filter((record: { swarmId: string; envelope: { feedId: string; issuerId: string } }) =>
          record.swarmId === "swm_history" &&
          record.envelope.feedId === "fed.replay" &&
          record.envelope.issuerId === ISSUER_ID,
        )
        .map((record: { envelope: { feedSeq: number } }) => record.envelope.feedSeq)
        .sort((left: number, right: number) => left - right),
    ).toEqual([1, 2]);
  });

  it("keeps replay state isolated when two issuers share a feed id and finding id", () => {
    render(
      <SwarmFeedProvider>
        <SwarmHistoryHarness />
      </SwarmFeedProvider>,
    );

    fireEvent.click(screen.getByTestId("cross-issuer-same-finding"));

    expect(JSON.parse(screen.getByTestId("history-snapshot").textContent ?? "{}")).toMatchObject({
      sharedEntries: [`${ISSUER_ID}:1`, `${OTHER_ISSUER_ID}:1`].sort(),
      issuerAlphaSync: {
        swarmId: "swm_history",
        feedId: "fed.shared",
        issuerId: ISSUER_ID,
        localFindingSeq: 1,
        localMaxFindingSeq: 1,
        localHeadSeq: null,
      },
      issuerBravoSync: {
        swarmId: "swm_history",
        feedId: "fed.shared",
        issuerId: OTHER_ISSUER_ID,
        localFindingSeq: 1,
        localMaxFindingSeq: 1,
        localHeadSeq: null,
      },
    });
  });

  it("rejects conflicting same-seq finding duplicates on single-record ingest before durable state mutates", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmDuplicateGuardHarness />
      </SwarmFeedProvider>,
    );

    expect(duplicateGuardApi).not.toBeNull();

    let firstResult: unknown = null;
    await act(async () => {
      firstResult = await duplicateGuardApi?.ingestFindingEnvelope({
        swarmId: "swm_duplicates",
        receivedAt: 1_715_300_000_010,
        envelope: makeFindingEnvelope({
          feedId: "fed.duplicates",
          findingId: "fnd_duplicate_guard",
          feedSeq: 1,
          title: "Original duplicate-guard title",
        }),
      });
    });

    expect(firstResult).toMatchObject({ accepted: true });
    expect(JSON.parse(screen.getByTestId("duplicate-guard-snapshot").textContent ?? "{}")).toMatchObject({
      findingCount: 1,
      findingTitle: "Original duplicate-guard title",
      findingReceivedAt: 1_715_300_000_010,
      revocationCount: 0,
      revocationReason: null,
      revocationReceivedAt: null,
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    let conflictResult: unknown = null;
    await act(async () => {
      conflictResult = await duplicateGuardApi?.ingestFindingEnvelope({
        swarmId: "swm_duplicates",
        receivedAt: 1_715_300_000_020,
        envelope: makeFindingEnvelope({
          feedId: "fed.duplicates",
          findingId: "fnd_duplicate_guard",
          feedSeq: 1,
          title: "Conflicting duplicate-guard title",
        }),
      });
    });

    expect(conflictResult).toMatchObject({
      accepted: false,
      reason: "seq_conflict",
    });
    expect(JSON.parse(screen.getByTestId("duplicate-guard-snapshot").textContent ?? "{}")).toMatchObject({
      findingCount: 1,
      findingTitle: "Original duplicate-guard title",
      findingReceivedAt: 1_715_300_000_010,
      revocationCount: 0,
      revocationReason: null,
      revocationReceivedAt: null,
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(
      persisted.findingEnvelopes.filter(
        (record: {
          swarmId: string;
          receivedAt: number;
          envelope: { feedId: string; issuerId: string; feedSeq: number; title: string };
        }) =>
          record.swarmId === "swm_duplicates" &&
          record.envelope.feedId === "fed.duplicates" &&
          record.envelope.issuerId === ISSUER_ID &&
          record.envelope.feedSeq === 1,
      ),
    ).toEqual([
      expect.objectContaining({
        receivedAt: 1_715_300_000_010,
        envelope: expect.objectContaining({
          title: "Original duplicate-guard title",
        }),
      }),
    ]);
  });

  it("rejects conflicting same-seq revocation duplicates on single-record ingest before durable state mutates", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmDuplicateGuardHarness />
      </SwarmFeedProvider>,
    );

    expect(duplicateGuardApi).not.toBeNull();

    let firstResult: unknown = null;
    await act(async () => {
      firstResult = await duplicateGuardApi?.ingestRevocationEnvelope({
        swarmId: "swm_duplicates",
        receivedAt: 1_715_300_000_030,
        envelope: makeRevocationEnvelope({
          feedId: "fed.duplicates",
          revocationId: "rev_duplicate_guard",
          feedSeq: 1,
          reason: "Original duplicate-guard revocation reason",
        }),
      });
    });

    expect(firstResult).toMatchObject({ accepted: true });
    expect(JSON.parse(screen.getByTestId("duplicate-guard-snapshot").textContent ?? "{}")).toMatchObject({
      findingCount: 0,
      findingTitle: null,
      findingReceivedAt: null,
      revocationCount: 1,
      revocationReason: "Original duplicate-guard revocation reason",
      revocationReceivedAt: 1_715_300_000_030,
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    let conflictResult: unknown = null;
    await act(async () => {
      conflictResult = await duplicateGuardApi?.ingestRevocationEnvelope({
        swarmId: "swm_duplicates",
        receivedAt: 1_715_300_000_040,
        envelope: makeRevocationEnvelope({
          feedId: "fed.duplicates",
          revocationId: "rev_duplicate_guard",
          feedSeq: 1,
          reason: "Conflicting duplicate-guard revocation reason",
        }),
      });
    });

    expect(conflictResult).toMatchObject({
      accepted: false,
      reason: "seq_conflict",
    });
    expect(JSON.parse(screen.getByTestId("duplicate-guard-snapshot").textContent ?? "{}")).toMatchObject({
      findingCount: 0,
      findingTitle: null,
      findingReceivedAt: null,
      revocationCount: 1,
      revocationReason: "Original duplicate-guard revocation reason",
      revocationReceivedAt: 1_715_300_000_030,
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(
      persisted.revocationEnvelopes.filter(
        (record: {
          swarmId: string;
          receivedAt: number;
          envelope: { feedId: string; issuerId: string; feedSeq: number; reason: string };
        }) =>
          record.swarmId === "swm_duplicates" &&
          record.envelope.feedId === "fed.duplicates" &&
          record.envelope.issuerId === ISSUER_ID &&
          record.envelope.feedSeq === 1,
      ),
    ).toEqual([
      expect.objectContaining({
        receivedAt: 1_715_300_000_030,
        envelope: expect.objectContaining({
          reason: "Original duplicate-guard revocation reason",
        }),
      }),
    ]);
  });

  it("treats exact single-record finding and revocation duplicates as idempotent without replacing stored records", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmDuplicateGuardHarness />
      </SwarmFeedProvider>,
    );

    expect(duplicateGuardApi).not.toBeNull();

    const findingEnvelope = makeFindingEnvelope({
      feedId: "fed.duplicates",
      findingId: "fnd_duplicate_guard",
      feedSeq: 1,
      title: "Exact duplicate-guard title",
    });
    const revocationEnvelope = makeRevocationEnvelope({
      feedId: "fed.duplicates",
      revocationId: "rev_duplicate_guard",
      feedSeq: 1,
      reason: "Exact duplicate-guard revocation reason",
    });

    let firstFindingResult: unknown = null;
    let duplicateFindingResult: unknown = null;
    let firstRevocationResult: unknown = null;
    let duplicateRevocationResult: unknown = null;

    await act(async () => {
      firstFindingResult = await duplicateGuardApi?.ingestFindingEnvelope({
        swarmId: "swm_duplicates",
        receivedAt: 1_715_300_000_050,
        envelope: findingEnvelope,
      });
    });
    await act(async () => {
      duplicateFindingResult = await duplicateGuardApi?.ingestFindingEnvelope({
        swarmId: "swm_duplicates",
        receivedAt: 1_715_300_000_060,
        envelope: findingEnvelope,
      });
    });
    await act(async () => {
      firstRevocationResult = await duplicateGuardApi?.ingestRevocationEnvelope({
        swarmId: "swm_duplicates",
        receivedAt: 1_715_300_000_070,
        envelope: revocationEnvelope,
      });
    });
    await act(async () => {
      duplicateRevocationResult = await duplicateGuardApi?.ingestRevocationEnvelope({
        swarmId: "swm_duplicates",
        receivedAt: 1_715_300_000_080,
        envelope: revocationEnvelope,
      });
    });

    expect(firstFindingResult).toMatchObject({ accepted: true });
    expect(duplicateFindingResult).toMatchObject({ accepted: true });
    expect(firstRevocationResult).toMatchObject({ accepted: true });
    expect(duplicateRevocationResult).toMatchObject({ accepted: true });
    expect(JSON.parse(screen.getByTestId("duplicate-guard-snapshot").textContent ?? "{}")).toMatchObject({
      findingCount: 1,
      findingTitle: "Exact duplicate-guard title",
      findingReceivedAt: 1_715_300_000_050,
      revocationCount: 1,
      revocationReason: "Exact duplicate-guard revocation reason",
      revocationReceivedAt: 1_715_300_000_070,
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(
      persisted.findingEnvelopes.filter(
        (record: {
          swarmId: string;
          receivedAt: number;
          envelope: { feedId: string; issuerId: string; feedSeq: number; title: string };
        }) =>
          record.swarmId === "swm_duplicates" &&
          record.envelope.feedId === "fed.duplicates" &&
          record.envelope.issuerId === ISSUER_ID &&
          record.envelope.feedSeq === 1,
      ),
    ).toEqual([
      expect.objectContaining({
        receivedAt: 1_715_300_000_050,
        envelope: expect.objectContaining({
          title: "Exact duplicate-guard title",
        }),
      }),
    ]);
    expect(
      persisted.revocationEnvelopes.filter(
        (record: {
          swarmId: string;
          receivedAt: number;
          envelope: { feedId: string; issuerId: string; feedSeq: number; reason: string };
        }) =>
          record.swarmId === "swm_duplicates" &&
          record.envelope.feedId === "fed.duplicates" &&
          record.envelope.issuerId === ISSUER_ID &&
          record.envelope.feedSeq === 1,
      ),
    ).toEqual([
      expect.objectContaining({
        receivedAt: 1_715_300_000_070,
        envelope: expect.objectContaining({
          reason: "Exact duplicate-guard revocation reason",
        }),
      }),
    ]);
  });

  it("persists durable revocations and projects revoked and superseded findings across reload", () => {
    vi.useFakeTimers();

    const { unmount } = render(
      <SwarmFeedProvider>
        <SwarmProjectionHarness />
      </SwarmFeedProvider>,
    );

    fireEvent.click(screen.getByTestId("seed-revoke-projection"));
    fireEvent.click(screen.getByTestId("seed-supersede-projection"));

    expect(JSON.parse(screen.getByTestId("projection-snapshot").textContent ?? "{}")).toMatchObject({
      revocationCount: 2,
      projectedFindingIds: ["fnd_replacement"],
      projectedSourceFindingIds: {
        fnd_replacement: ["fnd_replacement", "fnd_source"],
      },
      revokeResolution: {
        status: "revoked",
        findingId: "fnd_revoked",
        revocationId: "rev_projection_revoke",
        replacementId: null,
      },
      supersedeResolution: {
        status: "superseded",
        findingId: "fnd_source",
        revocationId: "rev_projection_supersede",
        replacementId: "fnd_replacement",
        replacementEnvelopeId: "fnd_replacement",
      },
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted.findingEnvelopes).toHaveLength(3);
    expect(persisted.revocationEnvelopes).toHaveLength(2);
    expect(
      persisted.revocationEnvelopes
        .map((record: { envelope: { revocationId: string } }) => record.envelope.revocationId)
        .sort(),
    ).toEqual(["rev_projection_revoke", "rev_projection_supersede"]);

    unmount();

    render(
      <SwarmFeedProvider>
        <SwarmProjectionHarness />
      </SwarmFeedProvider>,
    );

    expect(JSON.parse(screen.getByTestId("projection-snapshot").textContent ?? "{}")).toMatchObject({
      revocationCount: 2,
      projectedFindingIds: ["fnd_replacement"],
      projectedSourceFindingIds: {
        fnd_replacement: ["fnd_replacement", "fnd_source"],
      },
      revokeResolution: {
        status: "revoked",
        findingId: "fnd_revoked",
        revocationId: "rev_projection_revoke",
        replacementId: null,
      },
      supersedeResolution: {
        status: "superseded",
        findingId: "fnd_source",
        revocationId: "rev_projection_supersede",
        replacementId: "fnd_replacement",
        replacementEnvelopeId: "fnd_replacement",
      },
    });
  });

  it("projects a same-id digest-scoped supersede to the replacement revision instead of cycling away", async () => {
    render(
      <SwarmFeedProvider>
        <SwarmProjectionHarness />
      </SwarmFeedProvider>,
    );

    expect(projectionApi).not.toBeNull();

    const findingId = "fnd_same_id_digest";
    const olderFinding = makeFindingEnvelope({
      feedId: "fed.projection",
      findingId,
      feedSeq: 9,
      publishedAt: 1_715_200_000_900,
      title: "Same-id finding v1",
      summary: "Original revision before supersede.",
      blobRefs: [
        {
          blobId: "blob_same_id_v1",
          digest: HEX_1,
          mediaType: "application/json",
          byteLength: 64,
        },
      ],
    });
    const newerFinding = makeFindingEnvelope({
      feedId: "fed.projection",
      findingId,
      feedSeq: 10,
      publishedAt: 1_715_200_001_000,
      title: "Same-id finding v2",
      summary: "Replacement revision after supersede.",
      blobRefs: [
        {
          blobId: "blob_same_id_v2",
          digest: HEX_2,
          mediaType: "application/json",
          byteLength: 96,
        },
      ],
    });
    const olderDigest = await hashProtocolPayload(olderFinding);
    const newerDigest = await hashProtocolPayload(newerFinding);

    await act(async () => {
      await projectionApi?.ingestFindingEnvelope({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_000_910,
        envelope: olderFinding,
        digest: olderDigest,
      });
      await projectionApi?.ingestFindingEnvelope({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_001_010,
        envelope: newerFinding,
        digest: newerDigest,
      });
      await projectionApi?.ingestRevocationEnvelope?.({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_001_020,
        envelope: makeRevocationEnvelope({
          revocationId: "rev_projection_same_id_digest",
          feedId: "fed.projection",
          feedSeq: 11,
          issuedAt: 1_715_200_001_020,
          action: "supersede",
          target: {
            schema: FINDING_ENVELOPE_SCHEMA,
            id: findingId,
            digest: newerDigest,
          },
          replacement: {
            schema: FINDING_ENVELOPE_SCHEMA,
            id: findingId,
            digest: olderDigest,
          },
          reason: "Digest-scoped same-id supersede should land on v1 without cycling.",
        }),
      });
    });

    await waitFor(() => {
      const projectedSameIdRecord = (projectionApi?.projectedFindingRecords ?? []).find(
        (record: ProjectedFindingHarnessRecord) =>
          record.swarmId === "swm_projection" &&
          record.envelope.feedId === "fed.projection" &&
          record.envelope.findingId === findingId,
      );

      expect(projectedSameIdRecord).toMatchObject({
        digest: olderDigest,
        envelope: {
          feedSeq: 9,
          title: "Same-id finding v1",
        },
      });
    });
  });

  it("keeps a digest-scoped supersede pinned to its original replacement revision after a later re-emit", async () => {
    render(
      <SwarmFeedProvider>
        <SwarmProjectionHarness />
      </SwarmFeedProvider>,
    );

    expect(projectionApi).not.toBeNull();

    const sourceFinding = makeFindingEnvelope({
      feedId: "fed.projection",
      findingId: "fnd_digest_scoped_source",
      feedSeq: 12,
      publishedAt: 1_715_200_001_200,
      title: "Digest-scoped source",
      summary: "Source finding before supersede.",
      blobRefs: [
        {
          blobId: "blob_digest_source",
          digest: HEX_1,
          mediaType: "application/json",
          byteLength: 64,
        },
      ],
    });
    const replacementV1 = makeFindingEnvelope({
      feedId: "fed.projection",
      findingId: "fnd_digest_scoped_replacement",
      feedSeq: 13,
      publishedAt: 1_715_200_001_300,
      title: "Replacement v1",
      summary: "Original replacement revision.",
      blobRefs: [
        {
          blobId: "blob_digest_replacement_v1",
          digest: HEX_2,
          mediaType: "application/json",
          byteLength: 96,
        },
      ],
    });
    const replacementV2 = makeFindingEnvelope({
      feedId: "fed.projection",
      findingId: "fnd_digest_scoped_replacement",
      feedSeq: 14,
      publishedAt: 1_715_200_001_400,
      title: "Replacement v2",
      summary: "Later re-emitted replacement revision.",
      blobRefs: [
        {
          blobId: "blob_digest_replacement_v2",
          digest: HEX_3,
          mediaType: "application/json",
          byteLength: 128,
        },
      ],
    });
    const sourceDigest = await hashProtocolPayload(sourceFinding);
    const replacementV1Digest = await hashProtocolPayload(replacementV1);
    const replacementV2Digest = await hashProtocolPayload(replacementV2);

    await act(async () => {
      await projectionApi?.ingestFindingEnvelope({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_001_210,
        envelope: sourceFinding,
        digest: sourceDigest,
      });
      await projectionApi?.ingestFindingEnvelope({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_001_310,
        envelope: replacementV1,
        digest: replacementV1Digest,
      });
      await projectionApi?.ingestRevocationEnvelope?.({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_001_320,
        envelope: makeRevocationEnvelope({
          revocationId: "rev_projection_digest_scoped_replacement",
          feedId: "fed.projection",
          feedSeq: 15,
          issuedAt: 1_715_200_001_320,
          action: "supersede",
          target: {
            schema: FINDING_ENVELOPE_SCHEMA,
            id: sourceFinding.findingId,
            digest: sourceDigest,
          },
          replacement: {
            schema: FINDING_ENVELOPE_SCHEMA,
            id: replacementV1.findingId,
            digest: replacementV1Digest,
          },
          reason: "Source finding points at the original replacement digest.",
        }),
      });
      await projectionApi?.ingestFindingEnvelope({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_001_410,
        envelope: replacementV2,
        digest: replacementV2Digest,
      });
    });

    await waitFor(() => {
      const projectedReplacementRecords = (projectionApi?.projectedFindingRecords ?? []).filter(
        (record: ProjectedFindingHarnessRecord) =>
          record.swarmId === "swm_projection" &&
          record.envelope.feedId === "fed.projection" &&
          record.envelope.findingId === replacementV1.findingId,
      );

      expect(projectedReplacementRecords).toHaveLength(2);
      expect(projectedReplacementRecords).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            digest: replacementV1Digest,
            sourceFindingIds: [replacementV1.findingId, sourceFinding.findingId],
            envelope: expect.objectContaining({
              title: "Replacement v1",
              feedSeq: 13,
            }),
          }),
        ]),
      );
    });

    expect(
      projectionApi?.resolveFindingReference?.(
        "swm_projection",
        "fed.projection",
        ISSUER_ID,
        sourceFinding.findingId,
      ),
    ).toMatchObject({
      status: "superseded",
      findingId: sourceFinding.findingId,
      replacement: {
        id: replacementV1.findingId,
        digest: replacementV1Digest,
        envelope: expect.objectContaining({
          title: "Replacement v1",
          feedSeq: 13,
        }),
      },
    });
  });

  it("keeps a newer re-emitted finding active when an older digest-scoped revocation targets the same finding id", async () => {
    render(
      <SwarmFeedProvider>
        <SwarmProjectionHarness />
      </SwarmFeedProvider>,
    );

    expect(projectionApi).not.toBeNull();

    const findingId = "fnd_reemit";
    const olderFinding = makeFindingEnvelope({
      feedId: "fed.projection",
      findingId,
      feedSeq: 6,
      publishedAt: 1_715_200_001_000,
      title: "Re-emitted finding v1",
      summary: "Older revision",
      blobRefs: [
        {
          blobId: "blob_reemit_v1",
          digest: HEX_1,
          mediaType: "application/json",
          byteLength: 64,
        },
      ],
    });
    const newerFinding = makeFindingEnvelope({
      feedId: "fed.projection",
      findingId,
      feedSeq: 7,
      publishedAt: 1_715_200_001_100,
      title: "Re-emitted finding v2",
      summary: "Newer revision",
      blobRefs: [
        {
          blobId: "blob_reemit_v2",
          digest: HEX_2,
          mediaType: "application/json",
          byteLength: 96,
        },
      ],
    });
    const olderDigest = await hashProtocolPayload(olderFinding);

    await act(async () => {
      await projectionApi?.ingestFindingEnvelope({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_001_010,
        envelope: olderFinding,
      });
      await projectionApi?.ingestRevocationEnvelope?.({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_001_020,
        envelope: makeRevocationEnvelope({
          revocationId: "rev_projection_reemit_v1",
          feedId: "fed.projection",
          feedSeq: 8,
          issuedAt: 1_715_200_001_020,
          target: {
            schema: FINDING_ENVELOPE_SCHEMA,
            id: findingId,
            digest: olderDigest,
          },
          action: "revoke",
          replacement: undefined,
          reason: "Revokes only the older finding revision.",
        }),
      });
      await projectionApi?.ingestFindingEnvelope({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_001_110,
        envelope: newerFinding,
      });
    });

    await waitFor(() => {
      expect(JSON.parse(screen.getByTestId("projection-snapshot").textContent ?? "{}")).toMatchObject({
        projectedFindingIds: ["fnd_reemit"],
        projectedFindingTitles: {
          fnd_reemit: "Re-emitted finding v2",
        },
        reemitResolution: {
          status: "active",
          findingId: "fnd_reemit",
          revocationId: null,
          replacementId: null,
          replacementEnvelopeId: null,
        },
      });
    });
  });

  it("keeps issuer lanes isolated when one issuer revokes a shared-feed finding id", async () => {
    render(
      <SwarmFeedProvider>
        <SwarmProjectionHarness />
      </SwarmFeedProvider>,
    );

    expect(projectionApi).not.toBeNull();

    await act(async () => {
      await projectionApi?.ingestFindingEnvelope({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_002_010,
        envelope: makeFindingEnvelope({
          feedId: "fed.shared-projection",
          findingId: "fnd_shared_projection",
          issuerId: ISSUER_ID,
          feedSeq: 1,
          publishedAt: 1_715_200_002_000,
          title: "Issuer alpha shared finding",
        }),
      });
      await projectionApi?.ingestFindingEnvelope({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_002_020,
        envelope: makeFindingEnvelope({
          feedId: "fed.shared-projection",
          findingId: "fnd_shared_projection",
          issuerId: OTHER_ISSUER_ID,
          feedSeq: 1,
          publishedAt: 1_715_200_002_010,
          title: "Issuer bravo shared finding",
        }),
      });
      await projectionApi?.ingestRevocationEnvelope?.({
        swarmId: "swm_projection",
        receivedAt: 1_715_200_002_030,
        envelope: makeRevocationEnvelope({
          revocationId: "rev_projection_shared_alpha",
          issuerId: ISSUER_ID,
          feedId: "fed.shared-projection",
          feedSeq: 2,
          issuedAt: 1_715_200_002_020,
          target: {
            schema: FINDING_ENVELOPE_SCHEMA,
            id: "fnd_shared_projection",
          },
          action: "revoke",
          replacement: undefined,
          reason: "Issuer alpha revokes only the alpha lane.",
        }),
      });
    });

    await waitFor(() => {
      const projectedSharedFindingTitles = (projectionApi?.projectedFindingRecords ?? [])
        .filter(
          (record: ProjectedFindingHarnessRecord) =>
            record.swarmId === "swm_projection" &&
            record.envelope.feedId === "fed.shared-projection" &&
            record.envelope.findingId === "fnd_shared_projection",
        )
        .map(
          (record: ProjectedFindingHarnessRecord) =>
            `${record.envelope.issuerId}:${record.envelope.title}`,
        )
        .sort();

      expect(projectedSharedFindingTitles).toEqual([
        `${OTHER_ISSUER_ID}:Issuer bravo shared finding`,
      ]);
    });
  });

  it("persists per-swarm trust policy and rejects blocked single-record ingests before they reach durable state", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmTrustPolicyHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("set-trust-policy"));
      fireEvent.click(screen.getByTestId("ingest-trust-blocked"));
    });

    expect(lastTrustIngestResult).toMatchObject({
      accepted: false,
      reason: "blocked_issuer",
    });
    expect(JSON.parse(screen.getByTestId("trust-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: STRICT_TRUST_POLICY,
      replayRequestFromSeq: 1,
      replayRequestToSeq: 3,
      latestStoredSeq: null,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_trust",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: null,
        localMaxFindingSeq: null,
        localHeadSeq: null,
      },
      findingSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted.trustPolicies).toMatchObject({
      swm_trust: STRICT_TRUST_POLICY,
    });
    expect(
      persisted.findingEnvelopes.filter((record: { swarmId: string }) => record.swarmId === "swm_trust"),
    ).toEqual([]);
  });

  it("quarantines already-loaded finding, head, and revocation records when setTrustPolicy tightens fail-closed", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmPolicyFlipHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("seed-policy-flip"));
    });

    expect(JSON.parse(screen.getByTestId("policy-flip-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: DEFAULT_HUB_TRUST_POLICY,
      activeFindingIds: ["fnd_policy_flip"],
      activeFindingSeqs: [1],
      activeHeadKeys: ["findings:fed.policy-flip:1"],
      activeRevocationIds: ["rev_policy_flip"],
      activeRevocationSeqs: [2],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")).toMatchObject({
      findingEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            findingId: "fnd_policy_flip",
            feedSeq: 1,
          }),
        }),
      ],
      headAnnouncements: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          announcement: expect.objectContaining({
            feedId: "fed.policy-flip",
            headSeq: 1,
          }),
        }),
      ],
      revocationEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            revocationId: "rev_policy_flip",
            feedSeq: 2,
          }),
        }),
      ],
      quarantinedFindingEnvelopes: [],
      quarantinedHeadAnnouncements: [],
      quarantinedRevocationEnvelopes: [],
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId("tighten-policy-flip"));
    });

    expect(JSON.parse(screen.getByTestId("policy-flip-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: STRICT_TRUST_POLICY,
      activeFindingIds: [],
      activeFindingSeqs: [],
      activeHeadKeys: [],
      activeRevocationIds: [],
      activeRevocationSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")).toMatchObject({
      trustPolicies: {
        swm_policy_flip: STRICT_TRUST_POLICY,
      },
      findingEnvelopes: [],
      headAnnouncements: [],
      revocationEnvelopes: [],
      quarantinedFindingEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            findingId: "fnd_policy_flip",
            feedSeq: 1,
          }),
        }),
      ],
      quarantinedHeadAnnouncements: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          announcement: expect.objectContaining({
            feedId: "fed.policy-flip",
            headSeq: 1,
          }),
        }),
      ],
      quarantinedRevocationEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            revocationId: "rev_policy_flip",
            feedSeq: 2,
          }),
        }),
      ],
    });
  });

  it("restores quarantined finding, head, and revocation records when setTrustPolicy relaxes back to default permissive", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmPolicyFlipHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("seed-policy-flip"));
    });

    expect(JSON.parse(screen.getByTestId("policy-flip-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: DEFAULT_HUB_TRUST_POLICY,
      activeFindingIds: ["fnd_policy_flip"],
      activeFindingSeqs: [1],
      activeHeadKeys: ["findings:fed.policy-flip:1"],
      activeRevocationIds: ["rev_policy_flip"],
      activeRevocationSeqs: [2],
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId("tighten-policy-flip"));
    });

    expect(JSON.parse(screen.getByTestId("policy-flip-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: STRICT_TRUST_POLICY,
      activeFindingIds: [],
      activeFindingSeqs: [],
      activeHeadKeys: [],
      activeRevocationIds: [],
      activeRevocationSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")).toMatchObject({
      findingEnvelopes: [],
      headAnnouncements: [],
      revocationEnvelopes: [],
      quarantinedFindingEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            findingId: "fnd_policy_flip",
          }),
        }),
      ],
      quarantinedHeadAnnouncements: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          announcement: expect.objectContaining({
            feedId: "fed.policy-flip",
          }),
        }),
      ],
      quarantinedRevocationEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            revocationId: "rev_policy_flip",
          }),
        }),
      ],
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId("relax-policy-flip"));
    });

    expect(JSON.parse(screen.getByTestId("policy-flip-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: DEFAULT_HUB_TRUST_POLICY,
      activeFindingIds: ["fnd_policy_flip"],
      activeFindingSeqs: [1],
      activeHeadKeys: ["findings:fed.policy-flip:1"],
      activeRevocationIds: ["rev_policy_flip"],
      activeRevocationSeqs: [2],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")).toMatchObject({
      trustPolicies: {
        swm_policy_flip: DEFAULT_HUB_TRUST_POLICY,
      },
      findingEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            findingId: "fnd_policy_flip",
            feedSeq: 1,
          }),
        }),
      ],
      headAnnouncements: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          announcement: expect.objectContaining({
            feedId: "fed.policy-flip",
            headSeq: 1,
          }),
        }),
      ],
      revocationEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            revocationId: "rev_policy_flip",
            feedSeq: 2,
          }),
        }),
      ],
      quarantinedFindingEnvelopes: [],
      quarantinedHeadAnnouncements: [],
      quarantinedRevocationEnvelopes: [],
    });
  });

  it("keeps pending digest hydration inside quarantine after policy tightening", async () => {
    vi.useFakeTimers();

    let resolveDigestBuffer: ((value: ArrayBuffer) => void) | null = null;
    const pendingDigestBuffer = new Promise<ArrayBuffer>((resolve) => {
      resolveDigestBuffer = resolve;
    });
    const digestSpy = vi.spyOn(crypto.subtle, "digest").mockImplementationOnce(
      async () => pendingDigestBuffer,
    );

    render(
      <SwarmFeedProvider>
        <SwarmPolicyFlipHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("seed-policy-flip"));
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(policyFlipApi).not.toBeNull();
    expect(digestSpy).toHaveBeenCalledTimes(1);

    await act(async () => {
      fireEvent.click(screen.getByTestId("tighten-policy-flip"));
    });

    await act(async () => {
      resolveDigestBuffer?.(new Uint8Array(32).fill(0x33).buffer);
      await pendingDigestBuffer;
      await Promise.resolve();
    });

    expect(JSON.parse(screen.getByTestId("policy-flip-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: STRICT_TRUST_POLICY,
      activeFindingIds: [],
      activeFindingSeqs: [],
      activeHeadKeys: [],
      activeRevocationIds: [],
      activeRevocationSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")).toMatchObject({
      findingEnvelopes: [],
      quarantinedFindingEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          digest: HEX_3,
          envelope: expect.objectContaining({
            findingId: "fnd_policy_flip",
            feedSeq: 1,
          }),
        }),
      ],
    });
  });

  it("keeps replay progress for quarantined finding history after policy tightening", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmPolicyFlipHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("seed-policy-flip"));
    });
    await act(async () => {
      policyFlipApi?.setTrustPolicy("swm_policy_flip", QUARANTINE_BOUNDARY_POLICY);
    });

    expect(policyFlipApi).not.toBeNull();
    expect(
      policyFlipApi?.getFeedSyncState("swm_policy_flip", "fed.policy-flip", ISSUER_ID),
    ).toMatchObject({
      localFindingSeq: 1,
      localMaxFindingSeq: 1,
    });
    expect(
      policyFlipApi?.deriveReplayRequest(
        "swm_policy_flip",
        makeHeadAnnouncement({
          feedId: "fed.policy-flip",
          headSeq: 1,
          headEnvelopeHash: HEX_2,
        }),
      ),
    ).toBeNull();
  });

  it("rejects conflicting same-seq finding duplicates when the original record is quarantined", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmPolicyFlipHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("seed-policy-flip"));
    });
    await act(async () => {
      policyFlipApi?.setTrustPolicy("swm_policy_flip", QUARANTINE_BOUNDARY_POLICY);
    });

    expect(policyFlipApi).not.toBeNull();

    let conflictResult: unknown = null;
    await act(async () => {
      conflictResult = await policyFlipApi?.ingestFindingEnvelope({
        swarmId: "swm_policy_flip",
        receivedAt: 1_715_400_000_040,
        envelope: makeFindingEnvelope({
          feedId: "fed.policy-flip",
          findingId: "fnd_policy_flip",
          feedSeq: 1,
          title: "Conflicting policy flip finding",
        }),
      });
    });

    expect(conflictResult).toMatchObject({
      accepted: false,
      reason: "seq_conflict",
    });
    expect(JSON.parse(screen.getByTestId("policy-flip-snapshot").textContent ?? "{}")).toMatchObject({
      activeFindingIds: [],
      activeFindingSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")).toMatchObject({
      findingEnvelopes: [],
      quarantinedFindingEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            findingId: "fnd_policy_flip",
            feedSeq: 1,
            title: "Policy flip finding",
          }),
        }),
      ],
    });
  });

  it("rejects conflicting same-seq revocation duplicates when the original record is quarantined", async () => {
    vi.useFakeTimers();

    render(
      <SwarmFeedProvider>
        <SwarmPolicyFlipHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("seed-policy-flip"));
    });
    await act(async () => {
      policyFlipApi?.setTrustPolicy("swm_policy_flip", QUARANTINE_BOUNDARY_POLICY);
    });

    expect(policyFlipApi).not.toBeNull();

    let conflictResult: unknown = null;
    await act(async () => {
      conflictResult = await policyFlipApi?.ingestRevocationEnvelope({
        swarmId: "swm_policy_flip",
        receivedAt: 1_715_400_000_040,
        envelope: makeRevocationEnvelope({
          feedId: "fed.policy-flip",
          revocationId: "rev_policy_flip",
          feedSeq: 2,
          target: {
            schema: FINDING_ENVELOPE_SCHEMA,
            id: "fnd_policy_flip",
          },
          reason: "Conflicting policy flip revocation",
        }),
      });
    });

    expect(conflictResult).toMatchObject({
      accepted: false,
      reason: "seq_conflict",
    });
    expect(JSON.parse(screen.getByTestId("policy-flip-snapshot").textContent ?? "{}")).toMatchObject({
      activeRevocationIds: [],
      activeRevocationSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")).toMatchObject({
      revocationEnvelopes: [],
      quarantinedRevocationEnvelopes: [
        expect.objectContaining({
          swarmId: "swm_policy_flip",
          envelope: expect.objectContaining({
            revocationId: "rev_policy_flip",
            feedSeq: 2,
            reason: "Policy flip revocation",
          }),
        }),
      ],
    });
  });

  it("applies a freshly set trust policy to single-record ingests in the same turn", async () => {
    render(
      <SwarmFeedProvider>
        <SwarmTrustPolicyHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("same-turn-trust-blocked"));
    });

    expect(lastTrustIngestResult).toMatchObject({
      accepted: false,
      reason: "blocked_issuer",
    });
    expect(JSON.parse(screen.getByTestId("trust-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: STRICT_TRUST_POLICY,
      latestStoredSeq: null,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_trust",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: null,
        localMaxFindingSeq: null,
        localHeadSeq: null,
      },
      findingSeqs: [],
    });
  });

  it("drops replay findings that violate trust policy while keeping accepted gap-aware replay state", async () => {
    vi.useFakeTimers();

    const signer = await createFindingSigner();
    const strictPolicy = makeVerifiedIssuerTrustPolicy(signer.issuerId);
    const validEnvelope1 = await createSignedFindingEnvelope(signer, {
      feedId: "fed.gap",
      findingId: "fnd_trust_accept_1",
      feedSeq: 1,
      title: "Accepted replay 1",
    });
    const missingAttestationEnvelope2 = makeFindingEnvelope({
      issuerId: signer.issuerId,
      feedId: "fed.gap",
      findingId: "fnd_trust_reject_2",
      feedSeq: 2,
      title: "Rejected replay 2",
      attestation: undefined,
    });
    const validEnvelope3 = await createSignedFindingEnvelope(signer, {
      feedId: "fed.gap",
      findingId: "fnd_trust_accept_3",
      feedSeq: 3,
      title: "Accepted replay 3",
    });
    const remoteHead = makeHeadAnnouncement({
      feedId: "fed.gap",
      issuerId: signer.issuerId,
      headSeq: 3,
      entryCount: 3,
      headEnvelopeHash: HEX_3,
    });

    render(
      <SwarmFeedProvider>
        <SwarmStrictSignatureHarness
          swarmId="swm_trust"
          feedId="fed.gap"
          issuerId={signer.issuerId}
          remoteHeadSeq={3}
        />
      </SwarmFeedProvider>,
    );

    expect(signatureApi).not.toBeNull();
    const replayRequest = signatureApi?.deriveReplayRequest("swm_trust", remoteHead);
    expect(replayRequest).not.toBeNull();

    await act(async () => {
      signatureApi?.setTrustPolicy("swm_trust", strictPolicy);
      lastTrustReplayResult = await signatureApi?.ingestReplayBatch(
        replayRequest!,
        {
          envelopes: [validEnvelope1, missingAttestationEnvelope2, validEnvelope3],
          headAnnouncement: remoteHead,
        },
        1_715_000_001_100,
      );
    });

    expect(lastTrustReplayResult).toMatchObject({
      trustRejectedEnvelopes: [
        {
          reason: "missing_attestation",
          envelope: expect.objectContaining({
            findingId: "fnd_trust_reject_2",
            feedSeq: 2,
          }),
        },
      ],
    });
    expect(JSON.parse(screen.getByTestId("strict-signature-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: strictPolicy,
      replayRequestFromSeq: 2,
      replayRequestToSeq: 3,
      latestStoredSeq: 3,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_trust",
        feedId: "fed.gap",
        issuerId: signer.issuerId,
        localFindingSeq: 1,
        localMaxFindingSeq: 3,
        localHeadSeq: null,
      },
      findingSeqs: [1, 3],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted.trustPolicies).toMatchObject({
      swm_trust: strictPolicy,
    });
    expect(
      persisted.findingEnvelopes
        .filter(
          (record: { swarmId: string; envelope: { issuerId: string; feedId: string } }) =>
            record.swarmId === "swm_trust" &&
            record.envelope.feedId === "fed.gap" &&
            record.envelope.issuerId === signer.issuerId,
        )
        .map((record: { envelope: { feedSeq: number } }) => record.envelope.feedSeq)
        .sort((left: number, right: number) => left - right),
    ).toEqual([1, 3]);
  });

  it("applies a freshly set trust policy to replay ingests in the same turn", async () => {
    const signer = await createFindingSigner();
    const strictPolicy = makeVerifiedIssuerTrustPolicy(signer.issuerId);
    const missingAttestationEnvelope = makeFindingEnvelope({
      issuerId: signer.issuerId,
      feedId: "fed.same-turn",
      findingId: "fnd_trust_same_turn_reject_1",
      feedSeq: 1,
      title: "Same-turn rejected replay 1",
      attestation: undefined,
    });
    const remoteHead = makeHeadAnnouncement({
      feedId: "fed.same-turn",
      issuerId: signer.issuerId,
      headSeq: 1,
      entryCount: 1,
      headEnvelopeHash: HEX_3,
    });

    render(
      <SwarmFeedProvider>
        <SwarmStrictSignatureHarness
          swarmId="swm_trust"
          feedId="fed.same-turn"
          issuerId={signer.issuerId}
          remoteHeadSeq={1}
        />
      </SwarmFeedProvider>,
    );

    expect(signatureApi).not.toBeNull();
    const replayRequest = signatureApi?.deriveReplayRequest("swm_trust", remoteHead);
    expect(replayRequest).not.toBeNull();

    await act(async () => {
      signatureApi?.setTrustPolicy("swm_trust", strictPolicy);
      lastTrustReplayResult = await signatureApi?.ingestReplayBatch(
        replayRequest!,
        {
          envelopes: [missingAttestationEnvelope],
          headAnnouncement: remoteHead,
        },
        1_715_000_001_100,
      );
    });

    expect(lastTrustReplayResult).toMatchObject({
      trustRejectedEnvelopes: [
        {
          reason: "missing_attestation",
          envelope: expect.objectContaining({
            findingId: "fnd_trust_same_turn_reject_1",
            feedSeq: 1,
          }),
        },
      ],
    });
    expect(JSON.parse(screen.getByTestId("strict-signature-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: strictPolicy,
      latestStoredSeq: null,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_trust",
        feedId: "fed.same-turn",
        issuerId: signer.issuerId,
        localFindingSeq: null,
        localMaxFindingSeq: null,
        localHeadSeq: null,
      },
      findingSeqs: [],
    });
  });

  it("rejects forged well-formed signatures on strict single-record ingests", async () => {
    vi.useFakeTimers();

    const signer = await createFindingSigner();
    const strictPolicy = makeVerifiedIssuerTrustPolicy(signer.issuerId);
    const validEnvelope = await createSignedFindingEnvelope(signer, {
      feedId: "fed.strict",
      findingId: "fnd_strict_ingest",
      feedSeq: 1,
      title: "Strict valid ingest",
    });
    const forgedEnvelope: FindingEnvelope = {
      ...validEnvelope,
      title: "Strict forged ingest",
    };

    render(
      <SwarmFeedProvider>
        <SwarmStrictSignatureHarness
          swarmId="swm_signature"
          feedId="fed.strict"
          issuerId={signer.issuerId}
          remoteHeadSeq={1}
        />
      </SwarmFeedProvider>,
    );

    expect(signatureApi).not.toBeNull();

    await act(async () => {
      signatureApi?.setTrustPolicy("swm_signature", strictPolicy);
      lastStrictSignatureIngestResult = await signatureApi?.ingestFindingEnvelope({
        swarmId: "swm_signature",
        receivedAt: 1_715_000_001_200,
        envelope: forgedEnvelope,
      });
    });

    expect(lastStrictSignatureIngestResult).toMatchObject({
      accepted: false,
      reason: "invalid_attestation",
    });
    expect(JSON.parse(screen.getByTestId("strict-signature-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: strictPolicy,
      replayRequestFromSeq: 1,
      replayRequestToSeq: 1,
      latestStoredSeq: null,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_signature",
        feedId: "fed.strict",
        issuerId: signer.issuerId,
        localFindingSeq: null,
        localMaxFindingSeq: null,
        localHeadSeq: null,
      },
      findingSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted.trustPolicies).toMatchObject({
      swm_signature: strictPolicy,
    });
    expect(
      persisted.findingEnvelopes.filter((record: { swarmId: string }) => record.swarmId === "swm_signature"),
    ).toEqual([]);
  });

  it("rejects strict single-record ingests when issuerId and attested public key diverge", async () => {
    vi.useFakeTimers();

    const trustedSigner = await createFindingSigner();
    const spoofingSigner = await createFindingSigner();
    const strictPolicy = makeVerifiedIssuerTrustPolicy(trustedSigner.issuerId);
    const spoofedEnvelope = await signFindingEnvelope(
      makeFindingEnvelope({
        feedId: "fed.strict-binding",
        findingId: "fnd_strict_binding_ingest",
        feedSeq: 1,
        title: "Strict binding spoof",
        issuerId: trustedSigner.issuerId,
        attestation: undefined,
      }),
      spoofingSigner,
    );

    render(
      <SwarmFeedProvider>
        <SwarmStrictSignatureHarness
          swarmId="swm_signature"
          feedId="fed.strict-binding"
          issuerId={trustedSigner.issuerId}
          remoteHeadSeq={1}
        />
      </SwarmFeedProvider>,
    );

    expect(signatureApi).not.toBeNull();

    await act(async () => {
      signatureApi?.setTrustPolicy("swm_signature", strictPolicy);
      lastStrictSignatureIngestResult = await signatureApi?.ingestFindingEnvelope({
        swarmId: "swm_signature",
        receivedAt: 1_715_000_001_210,
        envelope: spoofedEnvelope,
      });
    });

    expect(lastStrictSignatureIngestResult).toMatchObject({
      accepted: false,
      reason: "invalid_attestation",
    });
    expect(JSON.parse(screen.getByTestId("strict-signature-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: strictPolicy,
      replayRequestFromSeq: 1,
      replayRequestToSeq: 1,
      latestStoredSeq: null,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_signature",
        feedId: "fed.strict-binding",
        issuerId: trustedSigner.issuerId,
        localFindingSeq: null,
        localMaxFindingSeq: null,
        localHeadSeq: null,
      },
      findingSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted.trustPolicies).toMatchObject({
      swm_signature: strictPolicy,
    });
    expect(
      persisted.findingEnvelopes.filter(
        (record: { swarmId: string; envelope: { feedId: string } }) =>
          record.swarmId === "swm_signature" &&
          record.envelope.feedId === "fed.strict-binding",
      ),
    ).toEqual([]);
  });

  it("rejects forged replay signatures while keeping valid signed entries gap-aware", async () => {
    vi.useFakeTimers();

    const signer = await createFindingSigner();
    const strictPolicy = makeVerifiedIssuerTrustPolicy(signer.issuerId);
    const validEnvelope1 = await createSignedFindingEnvelope(signer, {
      feedId: "fed.strict",
      findingId: "fnd_strict_replay_1",
      feedSeq: 1,
      title: "Strict replay 1",
    });
    const validEnvelope2 = await createSignedFindingEnvelope(signer, {
      feedId: "fed.strict",
      findingId: "fnd_strict_replay_2",
      feedSeq: 2,
      title: "Strict replay 2",
    });
    const validEnvelope3 = await createSignedFindingEnvelope(signer, {
      feedId: "fed.strict",
      findingId: "fnd_strict_replay_3",
      feedSeq: 3,
      title: "Strict replay 3",
    });
    const forgedEnvelope2: FindingEnvelope = {
      ...validEnvelope2,
      summary: "Forged replay 2",
    };
    const remoteHead = makeHeadAnnouncement({
      feedId: "fed.strict",
      issuerId: signer.issuerId,
      headSeq: 3,
      entryCount: 3,
      headEnvelopeHash: HEX_3,
    });

    render(
      <SwarmFeedProvider>
        <SwarmStrictSignatureHarness
          swarmId="swm_signature"
          feedId="fed.strict"
          issuerId={signer.issuerId}
          remoteHeadSeq={3}
        />
      </SwarmFeedProvider>,
    );

    expect(signatureApi).not.toBeNull();
    const replayRequest = signatureApi?.deriveReplayRequest("swm_signature", remoteHead);
    expect(replayRequest).not.toBeNull();

    await act(async () => {
      signatureApi?.setTrustPolicy("swm_signature", strictPolicy);
      lastStrictSignatureReplayResult = await signatureApi?.ingestReplayBatch(
        replayRequest!,
        {
          envelopes: [validEnvelope1, forgedEnvelope2, validEnvelope3],
          headAnnouncement: remoteHead,
        },
        1_715_000_001_300,
      );
    });

    expect(lastStrictSignatureReplayResult).toMatchObject({
      trustRejectedEnvelopes: [
        {
          reason: "invalid_attestation",
          envelope: expect.objectContaining({
            findingId: "fnd_strict_replay_2",
            feedSeq: 2,
          }),
        },
      ],
    });
    expect(JSON.parse(screen.getByTestId("strict-signature-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: strictPolicy,
      replayRequestFromSeq: 2,
      replayRequestToSeq: 3,
      latestStoredSeq: 3,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_signature",
        feedId: "fed.strict",
        issuerId: signer.issuerId,
        localFindingSeq: 1,
        localMaxFindingSeq: 3,
        localHeadSeq: null,
      },
      findingSeqs: [1, 3],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    const persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}");
    expect(persisted.trustPolicies).toMatchObject({
      swm_signature: strictPolicy,
    });
    expect(
      persisted.findingEnvelopes
        .filter(
          (record: { swarmId: string; envelope: { issuerId: string; feedId: string } }) =>
            record.swarmId === "swm_signature" &&
            record.envelope.feedId === "fed.strict" &&
            record.envelope.issuerId === signer.issuerId,
        )
        .map((record: { envelope: { feedSeq: number } }) => record.envelope.feedSeq)
        .sort((left: number, right: number) => left - right),
    ).toEqual([1, 3]);
  });

  it("fails closed when a persisted trust policy exists for a swarm but cannot be canonically validated", async () => {
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        findingEnvelopes: [],
        headAnnouncements: [],
        trustPolicies: {
          swm_trust: {
            trustedIssuers: [],
            blockedIssuers: [],
            requireAttestation: false,
            requireWitnessProofs: false,
            allowedSchemas: [FINDING_ENVELOPE_SCHEMA, "clawdstrike.swarm.invalid_schema.v1"],
          },
        },
      }),
    );

    render(
      <SwarmFeedProvider>
        <SwarmTrustPolicyHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("ingest-trust-valid"));
    });

    expect(lastTrustIngestResult).toMatchObject({
      accepted: false,
      reason: "disallowed_schema",
    });
    expect(JSON.parse(screen.getByTestId("trust-snapshot").textContent ?? "{}")).toMatchObject({
      latestStoredSeq: null,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_trust",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: null,
        localMaxFindingSeq: null,
        localHeadSeq: null,
      },
      findingSeqs: [],
    });
  });

  it("fails closed when persisted outer storage is malformed JSON and rewrites a quarantined default policy", async () => {
    vi.useFakeTimers();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    localStorage.setItem(STORAGE_KEY, "{not valid json");

    render(
      <SwarmFeedProvider>
        <SwarmTrustPolicyHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("ingest-trust-valid"));
    });

    expect(lastTrustIngestResult).toMatchObject({
      accepted: false,
      reason: "disallowed_schema",
    });
    expect(JSON.parse(screen.getByTestId("trust-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: FAIL_CLOSED_HUB_TRUST_POLICY,
      latestStoredSeq: null,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_trust",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: null,
        localMaxFindingSeq: null,
        localHeadSeq: null,
      },
      findingSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")).toMatchObject({
      defaultTrustPolicy: FAIL_CLOSED_HUB_TRUST_POLICY,
      trustPolicies: {},
    });
  });

  it("fails closed when persisted trustPolicies is not an object and keeps per-swarm storage quarantined by default", async () => {
    vi.useFakeTimers();
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        findingEnvelopes: [],
        headAnnouncements: [],
        trustPolicies: ["not", "an", "object"],
      }),
    );

    render(
      <SwarmFeedProvider>
        <SwarmTrustPolicyHarness />
      </SwarmFeedProvider>,
    );

    await act(async () => {
      fireEvent.click(screen.getByTestId("ingest-trust-valid"));
    });

    expect(lastTrustIngestResult).toMatchObject({
      accepted: false,
      reason: "disallowed_schema",
    });
    expect(JSON.parse(screen.getByTestId("trust-snapshot").textContent ?? "{}")).toMatchObject({
      trustPolicy: FAIL_CLOSED_HUB_TRUST_POLICY,
      latestStoredSeq: null,
      latestHeadSeq: null,
      syncState: {
        swarmId: "swm_trust",
        feedId: "fed.alpha",
        issuerId: ISSUER_ID,
        localFindingSeq: null,
        localMaxFindingSeq: null,
        localHeadSeq: null,
      },
      findingSeqs: [],
    });

    act(() => {
      vi.advanceTimersByTime(500);
    });

    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}")).toMatchObject({
      defaultTrustPolicy: FAIL_CLOSED_HUB_TRUST_POLICY,
      trustPolicies: {},
    });
  });
});
