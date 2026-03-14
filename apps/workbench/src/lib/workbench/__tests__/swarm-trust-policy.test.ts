import { describe, expect, it } from "vitest";
import { generateOperatorKeypair } from "../operator-crypto";
import { signDetachedPayload } from "../signature-adapter";
import {
  FINDING_ENVELOPE_SCHEMA,
  REVOCATION_ENVELOPE_SCHEMA,
  extractFindingEnvelopeSignableFields,
  extractRevocationEnvelopeSignableFields,
  hashProtocolPayload,
  type FindingEnvelope,
  type HubTrustPolicy,
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

type TrustPolicyDecision =
  | { accepted: true }
  | {
      accepted: false;
      reason:
        | "blocked_issuer"
        | "untrusted_issuer"
        | "disallowed_schema"
        | "missing_attestation"
        | "invalid_attestation"
        | "missing_witness_proofs";
    };

type TrustPolicyModule = {
  evaluateFindingTrustPolicy?: (
    policy: HubTrustPolicy,
    finding: FindingEnvelope,
  ) => TrustPolicyDecision | Promise<TrustPolicyDecision>;
  evaluateRevocationTrustPolicy?: (
    policy: HubTrustPolicy,
    revocation: RevocationEnvelope,
  ) => TrustPolicyDecision | Promise<TrustPolicyDecision>;
};

async function loadTrustPolicyModule(): Promise<TrustPolicyModule> {
  const modulePath = "../swarm-trust-policy";

  try {
    return (await import(/* @vite-ignore */ modulePath)) as TrustPolicyModule;
  } catch {
    return {};
  }
}

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

function makeTrustPolicy(overrides: Partial<HubTrustPolicy> = {}): HubTrustPolicy {
  return {
    trustedIssuers: [],
    blockedIssuers: [],
    requireAttestation: false,
    requireWitnessProofs: false,
    allowedSchemas: [FINDING_ENVELOPE_SCHEMA],
    ...overrides,
  };
}

function issuerIdFromPublicKey(publicKey: string): string {
  return `aegis:ed25519:${publicKey}`;
}

async function signFindingEnvelope(
  envelope: FindingEnvelope,
  signer: {
    publicKeyHex: string;
    secretKeyHex: string;
  },
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

async function makeSignedFindingEnvelope(
  overrides: Omit<Partial<FindingEnvelope>, "issuerId" | "attestation"> = {},
): Promise<FindingEnvelope> {
  const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
  return signFindingEnvelope(
    makeFindingEnvelope({
      ...overrides,
      issuerId: issuerIdFromPublicKey(publicKeyHex),
      attestation: undefined,
    }),
    { publicKeyHex, secretKeyHex },
  );
}

async function signRevocationEnvelope(
  envelope: RevocationEnvelope,
  signer: {
    publicKeyHex: string;
    secretKeyHex: string;
  },
): Promise<RevocationEnvelope> {
  const unsignedEnvelope = { ...envelope };
  if (unsignedEnvelope.attestation === undefined) {
    delete unsignedEnvelope.attestation;
  }
  const digest = await hashProtocolPayload(
    extractRevocationEnvelopeSignableFields(unsignedEnvelope),
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

async function makeSignedRevocationEnvelope(
  overrides: Omit<Partial<RevocationEnvelope>, "issuerId" | "attestation"> = {},
): Promise<RevocationEnvelope> {
  const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
  return signRevocationEnvelope(
    makeRevocationEnvelope({
      ...overrides,
      issuerId: issuerIdFromPublicKey(publicKeyHex),
      attestation: undefined,
    }),
    { publicKeyHex, secretKeyHex },
  );
}

function makeRevocationEnvelope(overrides: Partial<RevocationEnvelope> = {}): RevocationEnvelope {
  return {
    schema: REVOCATION_ENVELOPE_SCHEMA,
    revocationId: "rev_01J6Y8QF4N63N6K7R73Q4AJ7D1",
    issuerId: ISSUER_ID,
    feedId: "fed.alpha",
    feedSeq: 8,
    issuedAt: 1_715_000_000_888,
    action: "revoke",
    target: {
      schema: FINDING_ENVELOPE_SCHEMA,
      id: "fnd_01J6Y8QF4N63N6K7R73Q4AJ7Z8",
    },
    reason: "Revoked after duplicate analyst triage.",
    publish: {
      uri: "https://hub.example/revocations/rev_01J6Y8QF4N63N6K7R73Q4AJ7D1",
      publishedAt: 1_715_000_000_889,
    },
    ...overrides,
  };
}

describe("evaluateFindingTrustPolicy", () => {
  it("rejects blocked issuers before any allowlist match", async () => {
    const { evaluateFindingTrustPolicy } = await loadTrustPolicyModule();
    const result = await evaluateFindingTrustPolicy?.(
      makeTrustPolicy({
        blockedIssuers: [OTHER_ISSUER_ID],
        trustedIssuers: [ISSUER_ID, OTHER_ISSUER_ID],
      }),
      makeFindingEnvelope({
        issuerId: OTHER_ISSUER_ID,
        attestation: {
          algorithm: "ed25519",
          publicKey: OTHER_PUBLIC_KEY,
          signature: SIGNATURE,
        },
      }),
    );

    expect(result).toEqual({
      accepted: false,
      reason: "blocked_issuer",
    });
  });

  it("rejects issuers outside a non-empty allowlist", async () => {
    const { evaluateFindingTrustPolicy } = await loadTrustPolicyModule();
    const result = await evaluateFindingTrustPolicy?.(
      makeTrustPolicy({
        trustedIssuers: [ISSUER_ID],
      }),
      makeFindingEnvelope({
        issuerId: OTHER_ISSUER_ID,
        attestation: {
          algorithm: "ed25519",
          publicKey: OTHER_PUBLIC_KEY,
          signature: SIGNATURE,
        },
      }),
    );

    expect(result).toEqual({
      accepted: false,
      reason: "untrusted_issuer",
    });
  });

  it("rejects findings whose schema is not allowlisted", async () => {
    const { evaluateFindingTrustPolicy } = await loadTrustPolicyModule();
    const result = await evaluateFindingTrustPolicy?.(
      makeTrustPolicy({
        allowedSchemas: [],
      }),
      makeFindingEnvelope(),
    );

    expect(result).toEqual({
      accepted: false,
      reason: "disallowed_schema",
    });
  });

  it("rejects missing attestations when the policy requires them", async () => {
    const { evaluateFindingTrustPolicy } = await loadTrustPolicyModule();
    const result = await evaluateFindingTrustPolicy?.(
      makeTrustPolicy({
        requireAttestation: true,
      }),
      makeFindingEnvelope({
        attestation: undefined,
      }),
    );

    expect(result).toEqual({
      accepted: false,
      reason: "missing_attestation",
    });
  });

  it("rejects findings without witness proofs when the policy requires them", async () => {
    const { evaluateFindingTrustPolicy } = await loadTrustPolicyModule();
    const result = await evaluateFindingTrustPolicy?.(
      makeTrustPolicy({
        requireWitnessProofs: true,
      }),
      makeFindingEnvelope({
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
            },
          },
        ],
      }),
    );

    expect(result).toEqual({
      accepted: false,
      reason: "missing_witness_proofs",
    });
  });

  it("rejects forged signatures when strict issuer trust depends on attestation validity", async () => {
    const { evaluateFindingTrustPolicy } = await loadTrustPolicyModule();
    const signedFinding = await makeSignedFindingEnvelope();
    const forgedFinding: FindingEnvelope = {
      ...signedFinding,
      title: "Forged after signing",
    };
    const result = await evaluateFindingTrustPolicy?.(
      makeTrustPolicy({
        trustedIssuers: [signedFinding.issuerId],
        requireAttestation: true,
        requireWitnessProofs: true,
      }),
      forgedFinding,
    );

    expect(result).toEqual({
      accepted: false,
      reason: "invalid_attestation",
    });
  });

  it("rejects valid signatures when strict issuer trust sees an issuer/public-key mismatch", async () => {
    const { evaluateFindingTrustPolicy } = await loadTrustPolicyModule();
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const spoofedFinding = await signFindingEnvelope(
      makeFindingEnvelope({
        issuerId: OTHER_ISSUER_ID,
        attestation: undefined,
      }),
      { publicKeyHex, secretKeyHex },
    );
    const result = await evaluateFindingTrustPolicy?.(
      makeTrustPolicy({
        trustedIssuers: [OTHER_ISSUER_ID],
        requireAttestation: true,
        requireWitnessProofs: true,
      }),
      spoofedFinding,
    );

    expect(result).toEqual({
      accepted: false,
      reason: "invalid_attestation",
    });
  });

  it("accepts valid signed findings when strict issuer trust depends on attestation validity", async () => {
    const { evaluateFindingTrustPolicy } = await loadTrustPolicyModule();
    const signedFinding = await makeSignedFindingEnvelope();
    const result = await evaluateFindingTrustPolicy?.(
      makeTrustPolicy({
        trustedIssuers: [signedFinding.issuerId],
        requireAttestation: true,
        requireWitnessProofs: true,
      }),
      signedFinding,
    );

    expect(result).toEqual({
      accepted: true,
    });
  });
});

describe("evaluateRevocationTrustPolicy", () => {
  it("rejects revocations from issuers outside a non-empty allowlist", async () => {
    const { evaluateRevocationTrustPolicy } = await loadTrustPolicyModule();
    const result = await evaluateRevocationTrustPolicy?.(
      makeTrustPolicy({
        trustedIssuers: [ISSUER_ID],
        allowedSchemas: [REVOCATION_ENVELOPE_SCHEMA],
      }),
      makeRevocationEnvelope({
        issuerId: OTHER_ISSUER_ID,
        attestation: {
          algorithm: "ed25519",
          publicKey: OTHER_PUBLIC_KEY,
          signature: SIGNATURE,
        },
      }),
    );

    expect(result).toEqual({
      accepted: false,
      reason: "untrusted_issuer",
    });
  });

  it("rejects revocations whose schema is not allowlisted", async () => {
    const { evaluateRevocationTrustPolicy } = await loadTrustPolicyModule();
    const result = await evaluateRevocationTrustPolicy?.(
      makeTrustPolicy({
        allowedSchemas: [FINDING_ENVELOPE_SCHEMA],
      }),
      makeRevocationEnvelope(),
    );

    expect(result).toEqual({
      accepted: false,
      reason: "disallowed_schema",
    });
  });

  it("rejects forged revocation signatures when strict issuer trust depends on attestation validity", async () => {
    const { evaluateRevocationTrustPolicy } = await loadTrustPolicyModule();
    const signedRevocation = await makeSignedRevocationEnvelope();
    const forgedRevocation: RevocationEnvelope = {
      ...signedRevocation,
      reason: "Forged after signing.",
    };
    const result = await evaluateRevocationTrustPolicy?.(
      makeTrustPolicy({
        trustedIssuers: [signedRevocation.issuerId],
        requireAttestation: true,
        allowedSchemas: [REVOCATION_ENVELOPE_SCHEMA],
      }),
      forgedRevocation,
    );

    expect(result).toEqual({
      accepted: false,
      reason: "invalid_attestation",
    });
  });
});
