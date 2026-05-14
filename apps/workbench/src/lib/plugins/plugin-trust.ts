/**
 * Plugin Trust Verification
 *
 * Verifies Ed25519 signatures on plugin manifests before activation.
 * Consumed by PluginLoader (Plan 03-02) as a precondition gate.
 *
 * Trust verification flow:
 * 1. Internal plugins bypass signature check (always trusted)
 * 2. If no signature and allowUnsigned is set, permit (dev mode)
 * 3. If no signature, reject
 * 4. If no publisher key provided, reject
 * 5. Verify Ed25519 signature of canonical manifest JSON (minus the signature field)
 *
 * Uses existing operator-crypto primitives — does not implement its own Ed25519.
 */

import { verifyCanonical } from "../workbench/operator-crypto";
import type { PluginManifest, InstallationMetadata } from "./types";

// ---- Types ----

/** Reason codes for trust verification outcomes. */
export type TrustVerificationReason =
  | "internal"
  | "signature_valid"
  | "signature_invalid"
  | "signature_missing"
  | "publisher_key_missing"
  | "unsigned_allowed";

/** Result of trust verification on a plugin manifest. */
export interface TrustVerificationResult {
  /** Whether the plugin is trusted for activation. */
  trusted: boolean;
  /** Machine-readable reason for the verdict. */
  reason: TrustVerificationReason;
}

/** Options for trust verification. */
export interface TrustVerificationOptions {
  /** Ed25519 public key (hex) of the expected plugin publisher. */
  publisherKey?: string;
  /** If true, allow plugins without a signature (development mode). */
  allowUnsigned?: boolean;
}

// ---- Verification ----

/**
 * Verify the trust status of a plugin manifest.
 *
 * Internal plugins are always trusted. Community and MCP plugins require
 * a valid Ed25519 signature verified against the publisher's public key.
 *
 * The signature is computed over the canonical JSON of the manifest object
 * with the `installation.signature` field removed (the signature signs
 * the content, not itself).
 *
 * @param manifest - The plugin manifest to verify
 * @param options  - Publisher key and unsigned-allow flag
 * @returns Trust verification result with trusted flag and reason
 */
export async function verifyPluginTrust(
  manifest: PluginManifest,
  options?: TrustVerificationOptions,
): Promise<TrustVerificationResult> {
  // 1. Internal plugins bypass signature verification entirely
  if (manifest.trust === "internal") {
    return { trusted: true, reason: "internal" };
  }

  const signature = manifest.installation?.signature;
  const hasSignature = typeof signature === "string" && signature.length > 0;

  // 2. No signature + allowUnsigned => permit (development/operator override)
  if (!hasSignature && options?.allowUnsigned) {
    return { trusted: true, reason: "unsigned_allowed" };
  }

  // 3. No signature => reject
  if (!hasSignature) {
    return { trusted: false, reason: "signature_missing" };
  }

  const publisherKey =
    options?.publisherKey ?? manifest.installation?.publisherKey;

  // 4. No publisher key => cannot verify
  if (!publisherKey) {
    return { trusted: false, reason: "publisher_key_missing" };
  }

  // 5. Build the manifest object that was originally signed (without the signature field)
  const manifestForVerification = structuredClone(manifest);
  delete (
    manifestForVerification.installation as Partial<InstallationMetadata>
  ).signature;

  // 6. Verify Ed25519 signature of canonical JSON
  const valid = await verifyCanonical(
    manifestForVerification,
    signature,
    publisherKey,
  );

  return valid
    ? { trusted: true, reason: "signature_valid" }
    : { trusted: false, reason: "signature_invalid" };
}
