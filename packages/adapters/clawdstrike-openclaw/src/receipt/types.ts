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
    status: 'allow' | 'warn' | 'deny' | 'sanitize';
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
  algorithm: 'EdDSA';
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
