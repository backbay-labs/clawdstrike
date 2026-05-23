/**
 * @clawdstrike/openclaw - Receipt/Attestation Types
 *
 * TypeScript-side receipt types that mirror the Rust hush-core receipt
 * infrastructure. These establish the API surface for structured (but
 * unsigned) receipts until the WASM bridge to hush-core is ready.
 */

/**
 * A signed attestation of a security decision.
 *
 * When the hush-wasm bridge is integrated, the `signature` and `keyId`
 * fields will carry real Ed25519 values. Until then, they are `null`
 * (unsigned stub receipts).
 */
export interface DecisionReceipt {
  /** Unique receipt identifier */
  id: string;
  /** ISO 8601 timestamp of when the receipt was created */
  timestamp: string;
  /** SHA-256 hash of the applied policy configuration */
  policyHash: string;
  /** The decision that was made */
  decision: {
    status: "allow" | "warn" | "deny" | "sanitize";
    guard?: string;
    reason?: string;
  };
  /** Event that triggered the decision */
  event: {
    type: string;
    toolName?: string;
    resource?: string;
  };
  /** Ed25519 signature in JWS compact format (null when unsigned) */
  signature: string | null;
  /** Signing algorithm (always 'EdDSA' for Ed25519) */
  algorithm: "EdDSA";
  /** Public key identifier (null when unsigned) */
  keyId: string | null;
}

/** Configuration for receipt signing */
export interface ReceiptSignerConfig {
  /** Whether to generate receipts (default: true) */
  enabled?: boolean;
  /** Whether to cryptographically sign receipts (default: false - requires WASM bridge) */
  sign?: boolean;
  /** Key ID for the signing key */
  keyId?: string;
}

/**
 * Signature verifier function. Returns `true` if the signature on `canonical`
 * (the canonical JSON form of the receipt envelope) is valid for the receipt's
 * `signature` and `keyId`. Callers must provide their own implementation —
 * the openclaw adapter does not bundle a crypto backend.
 *
 * Implementations MUST resolve `keyId` to a trusted public key out of band
 * (e.g. JWKS, KMS) — passing `keyId` straight through is not sufficient.
 */
export type ReceiptSignatureVerifier = (input: {
  canonical: string;
  signature: string;
  keyId: string;
  algorithm: "EdDSA";
}) => boolean | Promise<boolean>;

/** Options for receipt verification. */
export interface ReceiptVerifyOptions {
  /**
   * Permit unsigned local-development receipts to verify.
   * Production callers must leave this `false` (the default).
   */
  allowUnsignedDevReceipts?: boolean;
  /**
   * Pluggable signature verifier. When omitted, signed receipts cannot be
   * cryptographically validated by this adapter and verification fails
   * closed (returns `false`).
   */
  verifySignature?: ReceiptSignatureVerifier;
  /**
   * Throw an error instead of returning `false` when a signed receipt
   * cannot be verified because no `verifySignature` callback was supplied.
   * Useful for surfacing misconfiguration early in production builds.
   * Default: `false`.
   */
  strict?: boolean;
}
