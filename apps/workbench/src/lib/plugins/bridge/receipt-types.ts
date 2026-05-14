/**
 * Plugin Action Receipt Types
 *
 * Defines the PluginActionReceipt -- an Ed25519-signed attestation that a
 * plugin bridge call occurred. Each receipt captures plugin identity, action
 * type, a SHA-256 hash of the canonical params, the result (allowed/denied/error),
 * which permission was checked, and the wall-clock duration.
 *
 * These receipts form the cryptographic audit trail for the plugin ecosystem.
 * They are stored locally (receipt-store.ts) and optionally forwarded to hushd.
 */

import type { PluginTrustTier } from "../types";
import { toHex, canonicalizeJson } from "../../workbench/operator-crypto";

// ---- Receipt Content ----

/**
 * The signed payload of a plugin action receipt.
 * All fields are included in the Ed25519 signature.
 */
export interface PluginActionReceiptContent {
  /** Receipt schema version. */
  version: "1.0.0";
  /** Unique receipt identifier (UUID v4). */
  receipt_id: string;
  /** ISO-8601 timestamp of when the action occurred. */
  timestamp: string;
  /** Identity of the plugin that performed the action. */
  plugin: {
    id: string;
    version: string;
    publisher: string;
    trust_tier: PluginTrustTier;
  };
  /** Details of the action that was performed. */
  action: {
    /** Bridge method name (e.g. "guards.register"). */
    type: string;
    /** SHA-256 hex digest of the canonical JSON representation of the params. */
    params_hash: string;
    /** Whether the action was allowed, denied, or errored. */
    result: "allowed" | "denied" | "error";
    /** The permission string that was checked for this action. */
    permission_checked: string;
    /** Wall-clock duration of the action in milliseconds. */
    duration_ms: number;
  };
}

// ---- Signed Receipt ----

/**
 * A complete plugin action receipt: signed content + Ed25519 signature.
 */
export interface PluginActionReceipt {
  /** The receipt payload (included in signature). */
  content: PluginActionReceiptContent;
  /** Ed25519 signature of the canonical JSON of content (hex). Empty string if unsigned (dev mode). */
  signature: string;
  /** Public key of the signer (hex). */
  signer_public_key: string;
}

// ---- Factory ----

/**
 * Create a PluginActionReceiptContent with all fields populated.
 *
 * Computes params_hash as SHA-256 of the canonical JSON representation
 * of the params (deterministic, cross-language compatible via RFC 8785).
 */
export async function createReceiptContent(
  pluginId: string,
  pluginVersion: string,
  publisher: string,
  trustTier: PluginTrustTier,
  actionType: string,
  params: unknown,
  result: "allowed" | "denied" | "error",
  permissionChecked: string,
  durationMs: number,
): Promise<PluginActionReceiptContent> {
  // Compute SHA-256 of the canonical JSON params
  const canonical = canonicalizeJson(params);
  const encoded = new TextEncoder().encode(canonical);
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
  const paramsHash = toHex(new Uint8Array(hashBuffer));

  return {
    version: "1.0.0",
    receipt_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    plugin: {
      id: pluginId,
      version: pluginVersion,
      publisher,
      trust_tier: trustTier,
    },
    action: {
      type: actionType,
      params_hash: paramsHash,
      result,
      permission_checked: permissionChecked,
      duration_ms: durationMs,
    },
  };
}
