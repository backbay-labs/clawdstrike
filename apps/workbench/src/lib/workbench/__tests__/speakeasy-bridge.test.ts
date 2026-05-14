import { describe, expect, it } from "vitest";
import {
  computeContentHash,
  signIntel,
} from "../intel-forge";
import {
  computeClawdstrikeMessageHash,
  createDetectionSyncMessage,
  createFindingUpdateMessage,
  createIntelAckMessage,
  createIntelShareMessage,
  createRoomMetadataMessage,
  type ClawdstrikeBaseMessage,
  verifyClawdstrikeMessage,
} from "../speakeasy-bridge";
import { generateOperatorKeypair } from "../operator-crypto";
import type { Intel } from "../sentinel-types";

function makeIntel(): Intel {
  return {
    id: "int_test_01",
    type: "advisory",
    title: "Credential replay pattern",
    description: "Multiple runtimes attempted the same credential replay path.",
    content: {
      kind: "advisory",
      narrative: "Credential reuse observed across multiple runtimes.",
      recommendations: ["Rotate credentials", "Audit agent sessions"],
    },
    derivedFrom: ["fnd_01"],
    confidence: 0.93,
    tags: ["credential", "replay"],
    mitre: [
      {
        techniqueId: "T1078",
        techniqueName: "Valid Accounts",
        tactic: "Defense Evasion",
      },
    ],
    shareability: "swarm",
    signature: "a".repeat(128),
    signerPublicKey: "b".repeat(64),
    receipt: {
      id: "rcpt_01",
      timestamp: new Date(1_715_000_000_000).toISOString(),
      verdict: "allow",
      guard: "intel_forge",
      policyName: "intel_promotion",
      action: {
        type: "file_access",
        target: "intel:int_test_01",
      },
      evidence: {
        content_hash: "pending",
      },
      signature: "c".repeat(128),
      publicKey: "d".repeat(64),
      valid: true,
    },
    author: "feedfacefeedface",
    createdAt: 1_715_000_000_000,
    version: 1,
  };
}

async function withRecomputedId<T extends ClawdstrikeBaseMessage>(
  message: T,
): Promise<T> {
  const { id: _id, signature: _signature, ...content } = message;
  const recomputedId = await computeClawdstrikeMessageHash(
    content as Omit<ClawdstrikeBaseMessage, "signature" | "id"> &
      Record<string, unknown>,
  );

  return {
    ...message,
    id: recomputedId,
  };
}

describe("verifyClawdstrikeMessage", () => {
  it("accepts a freshly signed message", async () => {
    const signer = await generateOperatorKeypair();
    const message = await createIntelAckMessage(
      "intel-01",
      "ingested",
      signer.publicKeyHex,
      signer.secretKeyHex,
    );

    await expect(verifyClawdstrikeMessage(message)).resolves.toEqual({
      valid: true,
    });
  });

  it("rejects a message whose content changed without being re-signed", async () => {
    const signer = await generateOperatorKeypair();
    const message = await createIntelAckMessage(
      "intel-01",
      "ingested",
      signer.publicKeyHex,
      signer.secretKeyHex,
    );

    const tampered = await withRecomputedId({
      ...message,
      action: "rejected" as const,
      reason: "spoofed",
    });

    await expect(verifyClawdstrikeMessage(tampered)).resolves.toEqual({
      valid: false,
      reason: "invalid_signature",
    });
  });

  it("rejects a message whose sender key does not match the signature", async () => {
    const signer = await generateOperatorKeypair();
    const stranger = await generateOperatorKeypair();
    const message = await createIntelAckMessage(
      "intel-01",
      "ingested",
      signer.publicKeyHex,
      signer.secretKeyHex,
    );

    const wrongSender = await withRecomputedId({
      ...message,
      sender: stranger.publicKeyHex,
    });

    await expect(verifyClawdstrikeMessage(wrongSender)).resolves.toEqual({
      valid: false,
      reason: "invalid_signature",
    });
  });

  it("rejects intel share tampering when summary changes", async () => {
    const signer = await generateOperatorKeypair();
    const message = await createIntelShareMessage(
      makeIntel(),
      signer.publicKeyHex,
      signer.secretKeyHex,
      {
        receiptJson: '{"receipt":"ok"}',
      },
    );

    const tampered = await withRecomputedId({
      ...message,
      summary: "Tampered summary that used to sit outside the signature",
    });

    await expect(verifyClawdstrikeMessage(tampered)).resolves.toEqual({
      valid: false,
      reason: "invalid_signature",
    });
  });

  it("publishes intel-share hashes and signer identity from the signed intel artifact", async () => {
    const intelAuthor = await generateOperatorKeypair();
    const relaySigner = await generateOperatorKeypair();
    const signedIntel = await signIntel(
      makeIntel(),
      intelAuthor.secretKeyHex,
      intelAuthor.publicKeyHex,
    );

    const message = await createIntelShareMessage(
      signedIntel,
      relaySigner.publicKeyHex,
      relaySigner.secretKeyHex,
      {
        receiptJson: JSON.stringify(signedIntel.receipt),
      },
    );

    expect(message.sender).toBe(relaySigner.publicKeyHex);
    expect(message.contentHash).toBe(await computeContentHash(signedIntel));
    expect(message.intelSignature).toBe(signedIntel.signature);
    expect(message.intelSignerPublicKey).toBe(signedIntel.signerPublicKey);
  });

  it("rejects finding update tampering when signalCount changes", async () => {
    const signer = await generateOperatorKeypair();
    const message = await createFindingUpdateMessage(
      "finding-01",
      "confirmed",
      signer.publicKeyHex,
      signer.secretKeyHex,
      {
        annotation: "Initial analyst note",
        signalCount: 3,
      },
    );

    const tampered = await withRecomputedId({
      ...message,
      signalCount: 99,
    });

    await expect(verifyClawdstrikeMessage(tampered)).resolves.toEqual({
      valid: false,
      reason: "invalid_signature",
    });
  });

  it("rejects room metadata tampering when changeReason changes", async () => {
    const signer = await generateOperatorKeypair();
    const message = await createRoomMetadataMessage(
      "spk_alpha",
      signer.publicKeyHex,
      signer.secretKeyHex,
      {
        purpose: "coordination",
        classification: "sensitive",
        changeReason: "Operator-approved policy change",
      },
    );

    const tampered = await withRecomputedId({
      ...message,
      changeReason: "Tampered after signing",
    });

    await expect(verifyClawdstrikeMessage(tampered)).resolves.toEqual({
      valid: false,
      reason: "invalid_signature",
    });
  });

  it("rejects detection sync tampering when rule content changes", async () => {
    const signer = await generateOperatorKeypair();
    const message = await createDetectionSyncMessage(
      "rule-01",
      "publish",
      "sigma",
      "title: original rule",
      1,
      0.82,
      signer.publicKeyHex,
      signer.secretKeyHex,
      "feedfacefeedface",
    );

    const tampered = await withRecomputedId({
      ...message,
      content: "title: tampered rule",
    });

    await expect(verifyClawdstrikeMessage(tampered)).resolves.toEqual({
      valid: false,
      reason: "invalid_signature",
    });
  });

  it("rejects a replayed nonce after the first successful verification", async () => {
    const signer = await generateOperatorKeypair();
    const message = await createIntelAckMessage(
      "intel-01",
      "ingested",
      signer.publicKeyHex,
      signer.secretKeyHex,
    );

    await expect(verifyClawdstrikeMessage(message)).resolves.toEqual({
      valid: true,
    });
    await expect(verifyClawdstrikeMessage(message)).resolves.toEqual({
      valid: false,
      reason: "nonce_reused",
    });
  });
});
