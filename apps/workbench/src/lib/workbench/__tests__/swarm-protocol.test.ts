import { describe, expect, it } from "vitest";
import {
  FINDING_BLOB_SCHEMA,
  FINDING_ENVELOPE_SCHEMA,
  HEAD_ANNOUNCEMENT_SCHEMA,
  HUB_CONFIG_SCHEMA,
  REVOCATION_ENVELOPE_SCHEMA,
  SWARM_PROTOCOL_COMPATIBILITY,
  SWARM_PROTOCOL_HASH_PROFILE,
  SWARM_PROTOCOL_VERSION,
  createHeadAnnouncement,
  extractFindingEnvelopeSignableFields,
  extractRevocationEnvelopeSignableFields,
  hashProtocolPayload,
  isFindingBlob,
  isFindingEnvelope,
  isHeadAnnouncement,
  isHubConfig,
  isRevocationEnvelope,
  serializeProtocolPayload,
  type FindingBlob,
  type FindingBlobArtifact,
  type FindingEnvelope,
  type HubConfig,
  type ProtocolDigest,
  type RevocationEnvelope,
} from "../swarm-protocol";

const HEX_1 = `0x${"1".repeat(64)}` as ProtocolDigest;
const HEX_2 = `0x${"2".repeat(64)}` as ProtocolDigest;
const HEX_3 = `0x${"3".repeat(64)}` as ProtocolDigest;
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
      publicKey: PUBLIC_KEY,
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

function makeFindingBlob(overrides: Partial<FindingBlob> = {}): FindingBlob {
  return {
    schema: FINDING_BLOB_SCHEMA,
    blobId: "blob_01J6Y8QF4N63N6K7R73Q4AJ7B1",
    findingId: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
    issuerId: ISSUER_ID,
    createdAt: 1_715_000_000_100,
    manifest: {
      bundleType: "evidence",
      native: {
        arch: "arm64",
        os: "darwin",
      },
      summary: {
        artifacts: 2,
        receipts: 1,
      },
    },
    artifacts: [
      {
        artifactId: "artifact_1",
        kind: "receipt",
        mediaType: "application/json",
        digest: HEX_1,
        byteLength: 128,
        name: "receipt.json",
        publish: {
          uri: "ipfs://artifact-1",
          notaryRecordId: "artifact-record-1",
        },
      },
      {
        artifactId: "artifact_2",
        kind: "transcript",
        mediaType: "text/plain",
        digest: HEX_2,
        byteLength: 256,
        name: "transcript.txt",
      },
    ],
    proofRefs: [
      {
        provider: "witness",
        digest: HEX_3,
        uri: "https://witness.example/proofs/blob-1",
      },
    ],
    publish: {
      uri: "https://blob.example/blob_01J6Y8QF4N63N6K7R73Q4AJ7B1",
      notaryRecordId: "blob-record-1",
      publishedAt: 1_715_000_000_101,
    },
    ...overrides,
  };
}

function makeHubConfig(overrides: Partial<HubConfig> = {}): HubConfig {
  return {
    schema: HUB_CONFIG_SCHEMA,
    hubId: "hub.alpha",
    displayName: "Alpha Hub",
    updatedAt: 1_715_000_000_300,
    bootstrapPeers: [
      {
        id: "bootstrap-1",
        url: "https://bootstrap.example",
        protocols: ["https", "wss"],
      },
    ],
    relayPeers: [
      {
        id: "relay-1",
        url: "https://relay.example",
        protocols: ["https"],
      },
    ],
    replay: {
      maxEntriesPerSync: 500,
      checkpointInterval: 50,
      retentionMs: 86_400_000,
    },
    blobs: {
      maxInlineBytes: 16_384,
      requireDigest: true,
      providers: [
        {
          id: "blob-primary",
          url: "https://blob.example",
          protocols: ["https"],
        },
      ],
    },
    trustPolicy: {
      trustedIssuers: [ISSUER_ID, `aegis:ed25519:${"d".repeat(64)}`],
      blockedIssuers: [OTHER_ISSUER_ID],
      requireAttestation: true,
      requireWitnessProofs: false,
      allowedSchemas: [
        FINDING_ENVELOPE_SCHEMA,
        FINDING_BLOB_SCHEMA,
        REVOCATION_ENVELOPE_SCHEMA,
      ],
    },
    ...overrides,
  };
}

describe("swarm protocol schema constants", () => {
  it("pins v1 schema ids and the witness-compatible hash profile", () => {
    expect(SWARM_PROTOCOL_VERSION).toBe("v1");
    expect(FINDING_ENVELOPE_SCHEMA).toBe("clawdstrike.swarm.finding_envelope.v1");
    expect(FINDING_BLOB_SCHEMA).toBe("clawdstrike.swarm.finding_blob.v1");
    expect(HEAD_ANNOUNCEMENT_SCHEMA).toBe("clawdstrike.swarm.head_announcement.v1");
    expect(REVOCATION_ENVELOPE_SCHEMA).toBe("clawdstrike.swarm.revocation_envelope.v1");
    expect(HUB_CONFIG_SCHEMA).toBe("clawdstrike.swarm.hub_config.v1");
    expect(SWARM_PROTOCOL_COMPATIBILITY).toEqual({
      canonicalization: "plain-json-sorted-keys-v1",
      digestAlgorithm: "sha-256",
      digestEncoding: "0x-lower-hex",
      intendedVerifier: "@backbay/witness",
    });
    expect(SWARM_PROTOCOL_HASH_PROFILE).toEqual({
      id: "witness-json-sha256-v1",
      canonicalization: "plain-json-sorted-keys-v1",
      hashAlgorithm: "sha256",
      digestFormat: "0x-prefixed-lowercase-hex",
      stripsFields: ["payload.publish", "blobRefs[].publish", "artifacts[].publish"],
      targetCompatibility: "@backbay/witness",
    });
  });
});

describe("serializeProtocolPayload", () => {
  it("canonicalizes nested protocol payloads deterministically", () => {
    const a = makeFindingBlob();
    const b = makeFindingBlob({
      artifacts: [
        {
          mediaType: "application/json",
          kind: "receipt",
          name: "receipt.json",
          byteLength: 128,
          digest: HEX_1,
          artifactId: "artifact_1",
          publish: {
            notaryRecordId: "artifact-record-1",
            uri: "ipfs://artifact-1",
          },
        },
        {
          byteLength: 256,
          mediaType: "text/plain",
          artifactId: "artifact_2",
          digest: HEX_2,
          name: "transcript.txt",
          kind: "transcript",
        },
      ],
      manifest: {
        summary: {
          receipts: 1,
          artifacts: 2,
        },
        native: {
          os: "darwin",
          arch: "arm64",
        },
        bundleType: "evidence",
      },
    });

    expect(serializeProtocolPayload(a)).toBe(serializeProtocolPayload(b));
  });

  it("rejects non-plain JSON values so serialized payloads stay transport-safe", () => {
    const invalid = makeHubConfig({
      replay: {
        maxEntriesPerSync: 500,
        checkpointInterval: 50,
        retentionMs: new Date() as unknown as number,
      },
    });

    expect(() => serializeProtocolPayload(invalid)).toThrow(/plain JSON|finite number/i);
  });
});

describe("hashProtocolPayload", () => {
  it("returns a 0x sha256 digest and ignores durable publish metadata", async () => {
    const a = makeFindingEnvelope();
    const b = makeFindingEnvelope({
      publish: {
        uri: "https://mirror.example/findings/fnd_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
        notaryRecordId: "notary-finding-2",
        notaryEnvelopeHash: HEX_3,
        publishedAt: 1_715_000_000_555,
      },
      blobRefs: [
        {
          blobId: "blob_01J6Y8QF4N63N6K7R73Q4AJ7B1",
          digest: HEX_1,
          mediaType: "application/json",
          byteLength: 512,
          publish: {
            uri: "https://mirror.example/blob-one",
            notaryRecordId: "notary-record-2",
            notaryEnvelopeHash: HEX_3,
          },
        },
      ],
    });

    const digestA = await hashProtocolPayload(a);
    const digestB = await hashProtocolPayload(b);

    expect(digestA).toMatch(/^0x[0-9a-f]{64}$/);
    expect(digestA).toBe(digestB);
  });

  it("keeps manifest publish fields in blob hashes while ignoring protocol publish slots", async () => {
    const manifestPublishA = makeFindingBlob({
      manifest: {
        bundleType: "evidence",
        native: {
          arch: "arm64",
          os: "darwin",
        },
        publish: {
          mode: "local",
          replicas: 1,
        },
      },
    });
    const onlyProtocolPublishChanged = makeFindingBlob({
      manifest: manifestPublishA.manifest,
      proofRefs: manifestPublishA.proofRefs,
      artifacts: manifestPublishA.artifacts.map((artifact: FindingBlobArtifact, index: number) =>
        index === 0
          ? {
              ...artifact,
              publish: {
                uri: "ipfs://artifact-1-mirror",
                notaryRecordId: "artifact-record-2",
              },
            }
          : artifact,
      ),
      publish: {
        uri: "https://mirror.example/blob_01J6Y8QF4N63N6K7R73Q4AJ7B1",
        notaryRecordId: "blob-record-2",
        publishedAt: 1_715_000_000_444,
      },
    });
    const manifestPublishB = makeFindingBlob({
      manifest: {
        bundleType: "evidence",
        native: {
          arch: "arm64",
          os: "darwin",
        },
        publish: {
          mode: "replicated",
          replicas: 2,
        },
      },
      proofRefs: onlyProtocolPublishChanged.proofRefs,
      artifacts: onlyProtocolPublishChanged.artifacts,
      publish: onlyProtocolPublishChanged.publish,
    });

    expect(await hashProtocolPayload(manifestPublishA)).toBe(await hashProtocolPayload(onlyProtocolPublishChanged));
    expect(await hashProtocolPayload(manifestPublishA)).not.toBe(await hashProtocolPayload(manifestPublishB));
  });
});

describe("runtime shape guards", () => {
  it("recognizes canonical protocol objects at runtime", async () => {
    const finding = makeFindingEnvelope();
    const blob = makeFindingBlob();
    const config = makeHubConfig();
    const head = await createHeadAnnouncement({
      factId: "head_01J6Y8QF4N63N6K7R73Q4AJ7C1",
      entryCount: 7,
      head: finding,
      announcedAt: 1_715_000_000_777,
    });
    const revocation: RevocationEnvelope = {
      schema: REVOCATION_ENVELOPE_SCHEMA,
      revocationId: "rev_01J6Y8QF4N63N6K7R73Q4AJ7D1",
      issuerId: ISSUER_ID,
      feedId: "fed.alpha",
      feedSeq: 8,
      issuedAt: 1_715_000_000_888,
      action: "supersede",
      target: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: finding.findingId,
        digest: await hashProtocolPayload(finding),
      },
      replacement: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7NEW",
        digest: HEX_3,
      },
      reason: "Merged duplicate analyst triage into replacement finding.",
      attestation: {
        algorithm: "ed25519",
        publicKey: PUBLIC_KEY,
        signature: SIGNATURE,
      },
    };

    expect(isFindingEnvelope(finding)).toBe(true);
    expect(isFindingBlob(blob)).toBe(true);
    expect(isHeadAnnouncement(head)).toBe(true);
    expect(isRevocationEnvelope(revocation)).toBe(true);
    expect(isHubConfig(config)).toBe(true);
  });

  it("rejects unknown keys on protocol objects and nested protocol sub-objects", () => {
    expect(
      isFindingEnvelope({
        ...makeFindingEnvelope(),
        rogue: true,
      } as FindingEnvelope & { rogue: boolean }),
    ).toBe(false);

    expect(
      isFindingEnvelope({
        ...makeFindingEnvelope(),
        blobRefs: [
          {
            ...makeFindingEnvelope().blobRefs[0]!,
            rogue: true,
          },
        ],
      } as unknown as FindingEnvelope),
    ).toBe(false);

    expect(
      isHubConfig({
        ...makeHubConfig(),
        replay: {
          ...makeHubConfig().replay,
          rogue: true,
        },
      } as unknown as HubConfig),
    ).toBe(false);
  });

  it("rejects invalid confidence and non-integer numeric protocol fields", () => {
    expect(isFindingEnvelope({ ...makeFindingEnvelope(), confidence: 1.01 })).toBe(false);
    expect(isFindingEnvelope({ ...makeFindingEnvelope(), signalCount: -1 })).toBe(false);
    expect(isFindingEnvelope({ ...makeFindingEnvelope(), signalCount: 1.5 })).toBe(false);
    expect(
      isHubConfig({
        ...makeHubConfig(),
        replay: {
          ...makeHubConfig().replay,
          maxEntriesPerSync: 0,
        },
      }),
    ).toBe(false);
  });

  it("requires Spine-like issuer ids and matching attestation signer keys", () => {
    expect(isFindingEnvelope({ ...makeFindingEnvelope(), issuerId: "sentinel.alpha" })).toBe(false);
    expect(
      isFindingEnvelope({
        ...makeFindingEnvelope(),
        attestation: {
          algorithm: "ed25519",
          publicKey: OTHER_PUBLIC_KEY,
          signature: SIGNATURE,
        },
      }),
    ).toBe(false);
    expect(isFindingBlob({ ...makeFindingBlob(), issuerId: "sentinel.alpha" })).toBe(false);
  });
});

describe("extractFindingEnvelopeSignableFields", () => {
  it("drops attestation and durable publish metadata while preserving stable blob refs", () => {
    const envelope = makeFindingEnvelope();
    const signable = extractFindingEnvelopeSignableFields(envelope);

    expect(signable).toEqual({
      schema: FINDING_ENVELOPE_SCHEMA,
      findingId: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
      issuerId: ISSUER_ID,
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
        },
      ],
    });
  });
});

describe("createHeadAnnouncement", () => {
  it("builds Rust-aligned head announcements from hashed feed entries", async () => {
    const head = makeFindingEnvelope();

    const announcement = await createHeadAnnouncement({
      factId: "head_01J6Y8QF4N63N6K7R73Q4AJ7C1",
      entryCount: 7,
      head,
      announcedAt: 1_715_000_000_777,
      checkpointRef: {
        logId: "spine-log.alpha",
        checkpointSeq: 42,
        envelopeHash: HEX_2,
      },
    });

    expect(announcement).toEqual({
      schema: HEAD_ANNOUNCEMENT_SCHEMA,
      factId: "head_01J6Y8QF4N63N6K7R73Q4AJ7C1",
      feedId: head.feedId,
      issuerId: head.issuerId,
      headSeq: head.feedSeq,
      headEnvelopeHash: await hashProtocolPayload(head),
      entryCount: 7,
      checkpointRef: {
        logId: "spine-log.alpha",
        checkpointSeq: 42,
        envelopeHash: HEX_2,
      },
      announcedAt: 1_715_000_000_777,
    });
  });
});

describe("extractRevocationEnvelopeSignableFields", () => {
  it("drops attestation and durable publish metadata for revoke and supersede flows", async () => {
    const target = makeFindingEnvelope();
    const revocation: RevocationEnvelope = {
      schema: REVOCATION_ENVELOPE_SCHEMA,
      revocationId: "rev_01J6Y8QF4N63N6K7R73Q4AJ7D1",
      issuerId: ISSUER_ID,
      feedId: "fed.alpha",
      feedSeq: 8,
      issuedAt: 1_715_000_000_888,
      action: "supersede",
      target: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: target.findingId,
        digest: await hashProtocolPayload(target),
      },
      replacement: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7NEW",
        digest: HEX_3,
      },
      reason: "Merged duplicate analyst triage into replacement finding.",
      attestation: {
        algorithm: "ed25519",
        publicKey: PUBLIC_KEY,
        signature: SIGNATURE,
      },
      publish: {
        uri: "https://hub.example/revocations/rev_01J6Y8QF4N63N6K7R73Q4AJ7D1",
        publishedAt: 1_715_000_000_889,
      },
    };

    const signable = extractRevocationEnvelopeSignableFields(revocation);

    expect(signable).toEqual({
      schema: REVOCATION_ENVELOPE_SCHEMA,
      revocationId: "rev_01J6Y8QF4N63N6K7R73Q4AJ7D1",
      issuerId: ISSUER_ID,
      feedId: "fed.alpha",
      feedSeq: 8,
      issuedAt: 1_715_000_000_888,
      action: "supersede",
      target: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: target.findingId,
        digest: await hashProtocolPayload(target),
      },
      replacement: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7NEW",
        digest: HEX_3,
      },
      reason: "Merged duplicate analyst triage into replacement finding.",
    });
  });
});

describe("revocation and hub config payloads", () => {
  it("serializes revocation envelopes with explicit supersede targets", async () => {
    const target = makeFindingEnvelope();
    const revocation: RevocationEnvelope = {
      schema: REVOCATION_ENVELOPE_SCHEMA,
      revocationId: "rev_01J6Y8QF4N63N6K7R73Q4AJ7D1",
      issuerId: ISSUER_ID,
      feedId: "fed.alpha",
      feedSeq: 8,
      issuedAt: 1_715_000_000_888,
      action: "supersede",
      target: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: target.findingId,
        digest: await hashProtocolPayload(target),
      },
      replacement: {
        schema: FINDING_ENVELOPE_SCHEMA,
        id: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7NEW",
        digest: HEX_3,
      },
      reason: "Merged duplicate analyst triage into replacement finding.",
      attestation: {
        algorithm: "ed25519",
        publicKey: PUBLIC_KEY,
        signature: SIGNATURE,
      },
    };

    const parsed = JSON.parse(serializeProtocolPayload(revocation)) as RevocationEnvelope;

    expect(parsed.target.digest).toMatch(/^0x[0-9a-f]{64}$/);
    expect(parsed.replacement?.id).toBe("fnd_01J6Y8QF4N63N6K7R73Q4AJ7NEW");
  });

  it("round-trips blob and hub config references as plain JSON", () => {
    const blob = JSON.parse(serializeProtocolPayload(makeFindingBlob())) as FindingBlob;
    const config = JSON.parse(serializeProtocolPayload(makeHubConfig())) as HubConfig;

    expect(blob.artifacts[0]?.publish?.notaryRecordId).toBe("artifact-record-1");
    expect(blob.proofRefs?.[0]?.provider).toBe("witness");
    expect(config.trustPolicy.allowedSchemas).toContain(FINDING_ENVELOPE_SCHEMA);
    expect(config.blobs.providers[0]?.url).toBe("https://blob.example");
  });
});
