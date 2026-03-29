import { canonicalizeJson } from "./operator-crypto";
import { verifyDetachedPayload } from "./signature-adapter";
import type { Receipt } from "./types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractSignedReceiptBody(receipt: Receipt): Record<string, unknown> | null {
  const signedReceipt = receipt.evidence?.signed_receipt;
  if (!isRecord(signedReceipt)) {
    return null;
  }

  const body = signedReceipt.receipt;
  return isRecord(body) ? body : null;
}

export function extractReceiptSignableFields(receipt: Receipt): Record<string, unknown> {
  return {
    id: receipt.id,
    timestamp: receipt.timestamp,
    verdict: receipt.verdict,
    guard: receipt.guard,
    policyName: receipt.policyName,
    action: receipt.action,
    evidence: receipt.evidence,
    publicKey: receipt.publicKey,
    keyType: receipt.keyType,
    imported: receipt.imported,
  };
}

export function getReceiptVerificationPayload(receipt: Receipt): Uint8Array {
  const payload =
    extractSignedReceiptBody(receipt) ?? extractReceiptSignableFields(receipt);
  return new TextEncoder().encode(canonicalizeJson(payload));
}

export async function verifyReceiptSignature(
  receipt: Receipt,
): Promise<boolean> {
  if (!receipt.signature || !receipt.publicKey) {
    return false;
  }

  return verifyDetachedPayload(
    getReceiptVerificationPayload(receipt),
    receipt.signature,
    receipt.publicKey,
  );
}
