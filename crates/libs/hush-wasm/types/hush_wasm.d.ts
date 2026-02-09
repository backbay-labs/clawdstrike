/**
 * TypeScript type definitions for @clawdstrike/wasm
 *
 * These augment the auto-generated wasm-bindgen types with
 * more detailed documentation and type information.
 */

/** Verification result from verify_receipt */
export interface VerificationResult {
  /** Overall validity - true only if all signatures are valid */
  valid: boolean;
  /** Primary signer signature valid */
  signer_valid: boolean;
  /** Co-signer signature valid (null if no co-signer) */
  cosigner_valid: boolean | null;
  /** Error messages if verification failed */
  errors: string[];
}

/** Initialize the WASM module (called automatically on import) */
export function init(): void;

/** Get the WASM module version */
export function version(): string;

/**
 * Compute SHA-256 hash of data
 * @param data - Bytes to hash
 * @returns Hex-encoded hash (64 chars, no prefix)
 */
export function hash_sha256(data: Uint8Array): string;

/**
 * Compute SHA-256 hash with 0x prefix
 * @param data - Bytes to hash
 * @returns Hex-encoded hash with 0x prefix
 */
export function hash_sha256_prefixed(data: Uint8Array): string;

/**
 * Compute Keccak-256 hash (Ethereum-compatible)
 * @param data - Bytes to hash
 * @returns Hex-encoded hash with 0x prefix
 */
export function hash_keccak256(data: Uint8Array): string;

/**
 * Verify an Ed25519 signature
 * @param publicKeyHex - Hex-encoded public key (32 bytes)
 * @param message - Message bytes that were signed
 * @param signatureHex - Hex-encoded signature (64 bytes)
 * @returns true if signature is valid
 * @throws Error if keys/signature are malformed
 */
export function verify_ed25519(
  publicKeyHex: string,
  message: Uint8Array,
  signatureHex: string
): boolean;

/**
 * Verify a signed receipt
 * @param receiptJson - JSON-serialized SignedReceipt
 * @param signerPubkeyHex - Hex-encoded signer public key
 * @param cosignerPubkeyHex - Optional hex-encoded co-signer public key
 * @returns Verification result object
 * @throws Error if JSON is malformed or keys are invalid
 */
export function verify_receipt(
  receiptJson: string,
  signerPubkeyHex: string,
  cosignerPubkeyHex?: string
): VerificationResult;

/**
 * Hash a receipt using specified algorithm
 * @param receiptJson - JSON-serialized Receipt
 * @param algorithm - "sha256" or "keccak256"
 * @returns Hex-encoded hash with 0x prefix
 * @throws Error if JSON is malformed or algorithm is invalid
 */
export function hash_receipt(
  receiptJson: string,
  algorithm: 'sha256' | 'keccak256'
): string;

/**
 * Get canonical JSON representation of a receipt
 * @param receiptJson - JSON-serialized Receipt
 * @returns Canonical JSON (sorted keys, no whitespace)
 * @throws Error if JSON is malformed
 */
export function get_canonical_json(receiptJson: string): string;

/**
 * Verify a Merkle inclusion proof
 * @param leafHashHex - Hex-encoded leaf hash
 * @param proofJson - JSON-serialized MerkleProof
 * @param rootHex - Hex-encoded expected root hash
 * @returns true if proof is valid
 * @throws Error if hashes are malformed
 */
export function verify_merkle_proof(
  leafHashHex: string,
  proofJson: string,
  rootHex: string
): boolean;

/**
 * Compute Merkle root from leaf hashes
 * @param leafHashesJson - JSON array of hex-encoded leaf hashes
 * @returns Hex-encoded root with 0x prefix
 * @throws Error if hashes are malformed
 */
export function compute_merkle_root(leafHashesJson: string): string;

/**
 * Generate a Merkle inclusion proof
 * @param leafHashesJson - JSON array of hex-encoded leaf hashes
 * @param leafIndex - 0-based index of leaf to prove
 * @returns JSON-serialized MerkleProof
 * @throws Error if index is out of bounds
 */
export function generate_merkle_proof(
  leafHashesJson: string,
  leafIndex: number
): string;
