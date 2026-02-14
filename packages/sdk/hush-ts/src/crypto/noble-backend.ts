/**
 * Noble (pure-JS) crypto backend.
 *
 * Wraps @noble/ed25519 and @noble/hashes into the CryptoBackend interface.
 * This is the default backend — always available, no native dependencies.
 */

import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import * as ed25519 from "@noble/ed25519";
import type { CryptoBackend } from "./backend";

export function createNobleBackend(): CryptoBackend {
  return {
    name: "noble",

    sha256(data: Uint8Array): Uint8Array {
      return nobleSha256(data);
    },

    keccak256(data: Uint8Array): Uint8Array {
      return keccak_256(data);
    },

    async generateKeypair(): Promise<{
      privateKey: Uint8Array;
      publicKey: Uint8Array;
    }> {
      const privateKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
      const publicKey = await ed25519.getPublicKeyAsync(privateKey);
      return { privateKey, publicKey };
    },

    async signMessage(
      message: Uint8Array,
      privateKey: Uint8Array
    ): Promise<Uint8Array> {
      return ed25519.signAsync(message, privateKey);
    },

    async verifySignature(
      message: Uint8Array,
      signature: Uint8Array,
      publicKey: Uint8Array
    ): Promise<boolean> {
      try {
        return await ed25519.verifyAsync(signature, message, publicKey);
      } catch {
        return false;
      }
    },

    async publicKeyFromPrivate(
      privateKey: Uint8Array
    ): Promise<Uint8Array> {
      return ed25519.getPublicKeyAsync(privateKey);
    },
  };
}
