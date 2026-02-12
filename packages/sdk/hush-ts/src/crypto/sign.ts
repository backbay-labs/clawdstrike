import * as ed25519 from "@noble/ed25519";

export interface Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Generate an Ed25519 keypair.
 * @returns Promise resolving to { privateKey, publicKey } (both 32 bytes)
 */
export async function generateKeypair(): Promise<Keypair> {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
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
  return ed25519.signAsync(message, privateKey);
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
  try {
    return await ed25519.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}
