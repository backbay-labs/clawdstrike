/**
 * WASM crypto backend.
 *
 * Wraps @clawdstrike/wasm (hush-core compiled to WebAssembly) into CryptoBackend.
 * Only loaded via dynamic import() in initWasm() — tree-shaken away otherwise.
 */

import type { CryptoBackend } from "./backend";
import { toHex, fromHex } from "./hash";

interface WasmModule {
  hash_sha256_bytes(data: Uint8Array): Uint8Array;
  hash_keccak256_bytes(data: Uint8Array): Uint8Array;
  generate_keypair(): { privateKey: string; publicKey: string };
  sign_ed25519(privateKeyHex: string, message: Uint8Array): string;
  verify_ed25519(
    publicKeyHex: string,
    message: Uint8Array,
    signatureHex: string
  ): boolean;
  public_key_from_private(privateKeyHex: string): string;
}

export function createWasmBackend(wasm: WasmModule): CryptoBackend {
  return {
    name: "wasm",

    sha256(data: Uint8Array): Uint8Array {
      return wasm.hash_sha256_bytes(data);
    },

    keccak256(data: Uint8Array): Uint8Array {
      return wasm.hash_keccak256_bytes(data);
    },

    async generateKeypair(): Promise<{
      privateKey: Uint8Array;
      publicKey: Uint8Array;
    }> {
      const kp = wasm.generate_keypair();
      return {
        privateKey: fromHex(kp.privateKey),
        publicKey: fromHex(kp.publicKey),
      };
    },

    async signMessage(
      message: Uint8Array,
      privateKey: Uint8Array
    ): Promise<Uint8Array> {
      const sigHex = wasm.sign_ed25519(toHex(privateKey), message);
      return fromHex(sigHex);
    },

    async verifySignature(
      message: Uint8Array,
      signature: Uint8Array,
      publicKey: Uint8Array
    ): Promise<boolean> {
      try {
        return wasm.verify_ed25519(toHex(publicKey), message, toHex(signature));
      } catch {
        return false;
      }
    },

    async publicKeyFromPrivate(
      privateKey: Uint8Array
    ): Promise<Uint8Array> {
      const pkHex = wasm.public_key_from_private(toHex(privateKey));
      return fromHex(pkHex);
    },
  };
}
