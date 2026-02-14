import { getBackend } from "./backend";

export interface Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Generate an Ed25519 keypair.
 * @returns Promise resolving to { privateKey, publicKey } (both 32 bytes)
 */
export async function generateKeypair(): Promise<Keypair> {
  return getBackend().generateKeypair();
}

/**
 * Sign a message with Ed25519.
 * @param message - Message bytes to sign
 * @param privateKey - 32-byte private key
 * @returns 64-byte signature
 */
export async function signMessage(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  return getBackend().signMessage(message, privateKey);
}

/**
 * Verify an Ed25519 signature.
 * @param message - Original message bytes
 * @param signature - 64-byte signature
 * @param publicKey - 32-byte public key
 * @returns True if valid, false otherwise
 */
export async function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  return getBackend().verifySignature(message, signature, publicKey);
}
