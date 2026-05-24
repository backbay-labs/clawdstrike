/**
 * WASM crypto backend.
 *
 * Wraps @clawdstrike/wasm (hush-core compiled to WebAssembly) into CryptoBackend.
 * Loaded by the backend lazy-loader when WASM becomes available.
 */

import type { CryptoBackend } from "./backend";
import { fromHex, toHex } from "./hash";
import type { HushWasmFreeFunctions } from "../types/wasm.js";

/** Subset of HushWasmModule used by the crypto backend. */
export type CryptoWasmModule = Pick<
  HushWasmFreeFunctions,
  | "hash_sha256_bytes"
  | "hash_keccak256_bytes"
  | "generate_keypair"
  | "sign_ed25519"
  | "verify_ed25519"
  | "public_key_from_private"
>;

export function createWasmBackend(wasm: CryptoWasmModule): CryptoBackend {
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
      // wasm_bindgen serializes Rust structs as JS Maps, not plain objects
      const privHex =
        kp instanceof Map
          ? (kp.get("privateKey") ?? "")
          : kp.privateKey;
      const pubHex =
        kp instanceof Map
          ? (kp.get("publicKey") ?? "")
          : kp.publicKey;
      return {
        privateKey: fromHex(privHex),
        publicKey: fromHex(pubHex),
      };
    },

    async signMessage(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
      const sigHex = wasm.sign_ed25519(toHex(privateKey), message);
      return fromHex(sigHex);
    },

    async verifySignature(
      message: Uint8Array,
      signature: Uint8Array,
      publicKey: Uint8Array,
    ): Promise<boolean> {
      try {
        return wasm.verify_ed25519(toHex(publicKey), message, toHex(signature));
      } catch {
        return false;
      }
    },

    async publicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array> {
      const pkHex = wasm.public_key_from_private(toHex(privateKey));
      return fromHex(pkHex);
    },
  };
}
