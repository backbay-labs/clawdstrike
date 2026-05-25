/**
 * @clawdstrike/openclaw - Receipt Signer
 *
 * Development receipt builder. Unsigned receipts are allowed only when
 * cryptographic signing is not requested.
 */

import { createHash } from "node:crypto";

import type { Decision, PolicyEvent } from "../types.js";
import type { DecisionReceipt, ReceiptSignerConfig, ReceiptVerifyOptions } from "./types.js";

/** Default configuration values for receipt signing */
const DEFAULTS: Required<ReceiptSignerConfig> = {
  enabled: true,
  sign: false,
  keyId: "",
};

/**
 * Creates structured receipt attestations for security decisions.
 *
 * `sign: true` is intentionally fail-closed until the hush-wasm signing
 * bridge is wired in. Returning an unsigned receipt from a signing-required
 * configuration would create a false audit boundary.
 */
export class ReceiptSigner {
  private readonly config: Required<ReceiptSignerConfig>;

  constructor(config: ReceiptSignerConfig = {}) {
    this.config = {
      enabled: config.enabled ?? DEFAULTS.enabled,
      sign: config.sign ?? DEFAULTS.sign,
      keyId: config.keyId ?? DEFAULTS.keyId,
    };
  }

  /**
   * Create a receipt for a security decision.
   *
   * Returns `null` if receipts are disabled via configuration.
   */
  createReceipt(
    decision: Decision,
    event: PolicyEvent,
    policyHash: string,
  ): DecisionReceipt | null {
    if (!this.config.enabled) {
      return null;
    }
    if (this.config.sign) {
      throw new Error(
        "OpenClaw signed receipts require the hush-wasm Ed25519 signing bridge; unsigned fallback is disabled when sign=true",
      );
    }

    // Extract event metadata for the receipt envelope
    const eventData = event.data;
    const toolName = eventData.type === "tool" ? eventData.toolName : undefined;
    const resource = extractResource(eventData);

    return {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      policyHash,
      decision: {
        status: decision.status,
        guard: decision.guard,
        reason: decision.reason,
      },
      event: {
        type: event.eventType,
        toolName,
        resource,
      },
      signature: null,
      algorithm: "EdDSA",
      keyId: null,
    };
  }

  /**
   * Compute SHA-256 hash of a policy config object using canonical JSON
   * (keys sorted recursively, no extra whitespace — mirrors RFC 8785
   * canonicalization used by hush-core).
   */
  static hashPolicy(policy: unknown): string {
    const canonical = JSON.stringify(sortKeys(policy));
    return createHash("sha256").update(canonical).digest("hex");
  }

  /**
   * Verify a receipt signature.
   *
   * Fail-closed behavior:
   *   - Unsigned receipts return `false` unless the caller explicitly opts
   *     into `allowUnsignedDevReceipts: true` (intended for local dev only).
   *   - Signed receipts return `false` (or throw when `strict: true`) unless
   *     the caller supplies a `verifySignature` callback that performs the
   *     actual Ed25519 verification against a trusted public key resolved
   *     from `keyId`.
   *
   * This adapter intentionally does not embed a crypto backend; production
   * callers should wire `verifySignature` to `@clawdstrike/sdk`'s
   * `verifySignature` (or an equivalent KMS-backed verifier).
   */
  static verify(receipt: DecisionReceipt, options: ReceiptVerifyOptions = {}): boolean {
    if (receipt.signature === null) {
      // Unsigned: never a verified attestation. Honor the explicit dev opt-in
      // but default to fail-closed.
      return options.allowUnsignedDevReceipts === true;
    }

    const verifier = options.verifySignature;
    if (!verifier) {
      if (options.strict === true) {
        throw new Error(
          "ReceiptSigner.verify: signed receipt cannot be verified — no verifySignature callback was provided",
        );
      }
      return false;
    }

    const canonical = canonicalizeReceiptForSignature(receipt);
    const result = verifier({
      canonical,
      signature: receipt.signature,
      keyId: receipt.keyId ?? "",
      algorithm: receipt.algorithm,
    });
    // Refuse to fail-open on async verifiers: callers must use verifyAsync.
    if (typeof (result as Promise<boolean>)?.then === "function") {
      throw new Error(
        "ReceiptSigner.verify: verifySignature returned a Promise — use verifyAsync for async verifiers",
      );
    }
    return result === true;
  }

  /**
   * Async variant of {@link verify}. Required when the supplied
   * `verifySignature` callback is asynchronous (e.g. KMS-backed).
   */
  static async verifyAsync(
    receipt: DecisionReceipt,
    options: ReceiptVerifyOptions = {},
  ): Promise<boolean> {
    if (receipt.signature === null) {
      return options.allowUnsignedDevReceipts === true;
    }

    const verifier = options.verifySignature;
    if (!verifier) {
      if (options.strict === true) {
        throw new Error(
          "ReceiptSigner.verifyAsync: signed receipt cannot be verified — no verifySignature callback was provided",
        );
      }
      return false;
    }

    const canonical = canonicalizeReceiptForSignature(receipt);
    const result = await verifier({
      canonical,
      signature: receipt.signature,
      keyId: receipt.keyId ?? "",
      algorithm: receipt.algorithm,
    });
    return result === true;
  }
}

/**
 * Compute the canonical signing input for a receipt — all fields except
 * the signature itself (which is what the signer would have signed).
 */
function canonicalizeReceiptForSignature(receipt: DecisionReceipt): string {
  const envelope: Omit<DecisionReceipt, "signature"> = {
    id: receipt.id,
    timestamp: receipt.timestamp,
    policyHash: receipt.policyHash,
    decision: receipt.decision,
    event: receipt.event,
    algorithm: receipt.algorithm,
    keyId: receipt.keyId,
  };
  return JSON.stringify(sortKeys(envelope));
}

/**
 * Recursively sort object keys for canonical JSON serialization.
 * Non-object values are returned as-is. Arrays preserve element order
 * but their object elements have keys sorted.
 */
function sortKeys(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Extract a resource identifier from event data when available.
 */
function extractResource(data: PolicyEvent["data"]): string | undefined {
  switch (data.type) {
    case "file":
      return data.path;
    case "network":
      return data.url ?? data.host;
    case "command":
      return data.command;
    case "tool":
      return data.toolName;
    case "patch":
      return data.filePath;
    case "secret":
      return data.secretName;
    default:
      return undefined;
  }
}
