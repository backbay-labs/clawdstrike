import { signData, verifySignature } from "./operator-crypto";

/**
 * Narrow detached-signature boundary for workbench verification.
 *
 * The preferred long-term verifier is `@backbay/witness`, but the workbench
 * does not currently depend on it. Centralizing detached Ed25519 operations
 * here gives the app real cryptographic semantics today without forcing
 * cross-repo dependency churn, and leaves a single swap point for a future
 * witness-backed adapter.
 */
export const SIGNATURE_ADAPTER_ID = "workbench-operator-crypto-ed25519";

export const ED25519_SIGNATURE_HEX = /^[0-9a-f]{128}$/;
export const ED25519_PUBLIC_KEY_HEX = /^[0-9a-f]{64}$/;

export async function signDetachedPayload(
  payload: Uint8Array,
  secretKeyHex: string,
): Promise<string> {
  return signData(payload, secretKeyHex);
}

export async function verifyDetachedPayload(
  payload: Uint8Array,
  signatureHex: string,
  publicKeyHex: string,
): Promise<boolean> {
  if (
    !ED25519_SIGNATURE_HEX.test(signatureHex) ||
    !ED25519_PUBLIC_KEY_HEX.test(publicKeyHex)
  ) {
    return false;
  }

  return verifySignature(payload, signatureHex, publicKeyHex);
}
