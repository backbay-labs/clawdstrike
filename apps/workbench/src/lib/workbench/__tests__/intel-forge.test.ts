import { describe, expect, it } from "vitest";
import type { Intel } from "../sentinel-types";
import { generateOperatorKeypair } from "../operator-crypto";
import { signIntel, verifyIntel } from "../intel-forge";

function makeIntel(overrides: Partial<Intel> = {}): Intel {
  return {
    id: "int_test_01",
    type: "advisory",
    title: "Credential reuse across agents",
    description: "Multiple runtimes attempted the same credential replay path.",
    content: {
      kind: "advisory",
      narrative: "Operators should rotate the affected credentials and review agent scope.",
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
    signature: "",
    signerPublicKey: "",
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
      signature: "",
      publicKey: "",
      valid: false,
    },
    author: "feedfacefeedface",
    createdAt: 1_715_000_000_000,
    version: 1,
    ...overrides,
  };
}

describe("signIntel + verifyIntel", () => {
  it("binds signed intel to the real signer public key", async () => {
    const signer = await generateOperatorKeypair();

    const signed = await signIntel(
      makeIntel(),
      signer.secretKeyHex,
      signer.publicKeyHex,
    );

    expect(signed.signerPublicKey).toBe(signer.publicKeyHex);

    const verification = await verifyIntel(signed);
    expect(verification).toEqual({
      valid: true,
      reason: "Intel signature verified",
    });
  });

  it("rejects intel whose signed content was tampered after signing", async () => {
    const signer = await generateOperatorKeypair();
    const signed = await signIntel(
      makeIntel(),
      signer.secretKeyHex,
      signer.publicKeyHex,
    );

    const tampered = {
      ...signed,
      title: "Tampered title",
    };

    await expect(verifyIntel(tampered)).resolves.toEqual({
      valid: false,
      reason: "invalid_signature",
    });
  });

  it("rejects intel when the signer public key does not match the signature", async () => {
    const signer = await generateOperatorKeypair();
    const stranger = await generateOperatorKeypair();
    const signed = await signIntel(
      makeIntel(),
      signer.secretKeyHex,
      signer.publicKeyHex,
    );

    const wrongSigner = {
      ...signed,
      signerPublicKey: stranger.publicKeyHex,
    };

    await expect(verifyIntel(wrongSigner)).resolves.toEqual({
      valid: false,
      reason: "invalid_signature",
    });
  });

  it("rejects a valid receipt that was swapped in from another signed intel artifact", async () => {
    const signer = await generateOperatorKeypair();
    const first = await signIntel(
      makeIntel(),
      signer.secretKeyHex,
      signer.publicKeyHex,
    );
    const second = await signIntel(
      makeIntel({
        id: "int_test_02",
        title: "Different artifact",
        derivedFrom: ["fnd_02"],
      }),
      signer.secretKeyHex,
      signer.publicKeyHex,
    );

    const swappedReceipt = {
      ...first,
      receipt: second.receipt,
    };

    await expect(verifyIntel(swappedReceipt)).resolves.toEqual({
      valid: false,
      reason: "receipt_target_mismatch",
    });
  });
});
