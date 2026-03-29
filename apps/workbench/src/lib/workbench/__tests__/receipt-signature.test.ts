import { canonicalizeJson, generateOperatorKeypair } from "../operator-crypto";
import { signDetachedPayload } from "../signature-adapter";
import {
  getReceiptVerificationPayload,
  verifyReceiptSignature,
} from "../receipt-signature";
import type { Receipt } from "../types";
import { describe, expect, it } from "vitest";

describe("receipt-signature", () => {
  it("verifies canonical board receipt payloads", async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const unsignedReceipt: Receipt = {
      id: "rct_local_01",
      timestamp: "2026-03-25T12:00:00.000Z",
      verdict: "allow",
      guard: "policy_validation",
      policyName: "strict-default",
      action: {
        type: "shell_command",
        target: "/tmp/project",
      },
      evidence: {
        content_hash: "abc123",
      },
      signature: "",
      publicKey: publicKeyHex,
      valid: false,
      keyType: "ephemeral",
    };

    const signature = await signDetachedPayload(
      getReceiptVerificationPayload(unsignedReceipt),
      secretKeyHex,
    );

    const signedReceipt: Receipt = {
      ...unsignedReceipt,
      signature,
      valid: true,
    };

    await expect(verifyReceiptSignature(signedReceipt)).resolves.toBe(true);
    await expect(
      verifyReceiptSignature({
        ...signedReceipt,
        guard: "mutated_guard",
      }),
    ).resolves.toBe(false);
  });

  it("prefers the embedded signed receipt body when present", async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const signedReceiptBody = {
      timestamp: "2026-03-25T12:00:00.000Z",
      verdict: {
        passed: true,
      },
      content_hash: "feedbeef",
    };

    const signature = await signDetachedPayload(
      new TextEncoder().encode(canonicalizeJson(signedReceiptBody)),
      secretKeyHex,
    );

    const receipt: Receipt = {
      id: "rct_embedded_01",
      timestamp: "2026-03-25T12:00:00.000Z",
      verdict: "deny",
      guard: "fail-closed",
      policyName: "placeholder",
      action: {
        type: "shell_command",
        target: "/tmp/project",
      },
      evidence: {
        signed_receipt: {
          receipt: signedReceiptBody,
          signatures: {
            signer: signature,
          },
        },
      },
      signature,
      publicKey: publicKeyHex,
      valid: true,
    };

    await expect(verifyReceiptSignature(receipt)).resolves.toBe(true);
  });
});
