/* tslint:disable */
/* eslint-disable */

export class WasmInstructionHierarchyEnforcer {
    free(): void;
    [Symbol.dispose](): void;
    enforce(messages_json: string): string;
    constructor(config_json?: string | null);
}

export class WasmJailbreakDetector {
    free(): void;
    [Symbol.dispose](): void;
    detect(text: string, session_id?: string | null): string;
    constructor(config_json?: string | null);
}

export class WasmOutputSanitizer {
    free(): void;
    [Symbol.dispose](): void;
    constructor(config_json?: string | null);
    sanitize(text: string): string;
}

/**
 * WASM wrapper around `PolicyLabHandle` for policy validation.
 *
 * Simulation is not available in WASM. Use the native FFI or PyO3
 * bindings for simulate support.
 */
export class WasmPolicyLab {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Create a new PolicyLab handle from a policy YAML string.
     *
     * Validates that the YAML is a well-formed policy.
     */
    constructor(policy_yaml: string);
}

export class WasmSpiderSenseDetector {
    free(): void;
    [Symbol.dispose](): void;
    expected_dim(): number | undefined;
    load_patterns(patterns_json: string): void;
    constructor(config_json?: string | null);
    pattern_count(): number;
    screen(embedding_json: string): string;
}

export function canonicalize_json(json_str: string): string;

/**
 * Compute Merkle root from leaf hashes.
 *
 * # Arguments
 * * `leaf_hashes_json` - JSON array of hex-encoded leaf hashes
 *
 * # Returns
 * Hex-encoded Merkle root (with 0x prefix)
 */
export function compute_merkle_root(leaf_hashes_json: string): string;

export function detect_prompt_injection(text: string, max_scan_bytes?: number | null): string;

/**
 * Generate a new Ed25519 keypair.
 *
 * # Returns
 * JavaScript object `{ privateKey: string, publicKey: string }` with hex-encoded keys (no 0x prefix).
 * Private key is 32 bytes (64 hex chars), public key is 32 bytes (64 hex chars).
 */
export function generate_keypair(): any;

/**
 * Generate a Merkle proof for a specific leaf index.
 *
 * # Arguments
 * * `leaf_hashes_json` - JSON array of hex-encoded leaf hashes
 * * `leaf_index` - Index of the leaf to prove (0-based)
 *
 * # Returns
 * JSON-serialized MerkleProof
 */
export function generate_merkle_proof(leaf_hashes_json: string, leaf_index: number): string;

/**
 * Get the canonical JSON representation of a receipt.
 * This is the exact bytes that are signed.
 *
 * # Arguments
 * * `receipt_json` - JSON-serialized Receipt
 *
 * # Returns
 * Canonical JSON string (sorted keys, no extra whitespace)
 */
export function get_canonical_json(receipt_json: string): string;

/**
 * Compute Keccak-256 hash of data (Ethereum-compatible).
 *
 * # Arguments
 * * `data` - The bytes to hash
 *
 * # Returns
 * Hex-encoded hash with 0x prefix (66 characters)
 */
export function hash_keccak256(data: Uint8Array): string;

/**
 * Compute Keccak-256 hash of data, returning raw bytes.
 *
 * # Arguments
 * * `data` - The bytes to hash
 *
 * # Returns
 * 32-byte hash as `Uint8Array`
 */
export function hash_keccak256_bytes(data: Uint8Array): Uint8Array;

/**
 * Hash a Receipt to get its canonical hash.
 *
 * # Arguments
 * * `receipt_json` - JSON-serialized Receipt (unsigned)
 * * `algorithm` - "sha256" or "keccak256"
 *
 * # Returns
 * Hex-encoded hash with 0x prefix
 */
export function hash_receipt(receipt_json: string, algorithm: string): string;

/**
 * Compute SHA-256 hash of data.
 *
 * # Arguments
 * * `data` - The bytes to hash
 *
 * # Returns
 * Hex-encoded hash (64 characters, no 0x prefix)
 */
export function hash_sha256(data: Uint8Array): string;

/**
 * Compute SHA-256 hash of data, returning raw bytes.
 *
 * # Arguments
 * * `data` - The bytes to hash
 *
 * # Returns
 * 32-byte hash as `Uint8Array`
 */
export function hash_sha256_bytes(data: Uint8Array): Uint8Array;

/**
 * Compute SHA-256 hash with 0x prefix.
 *
 * # Arguments
 * * `data` - The bytes to hash
 *
 * # Returns
 * Hex-encoded hash with 0x prefix (66 characters)
 */
export function hash_sha256_prefixed(data: Uint8Array): string;

/**
 * Initialize the WASM module (call once at startup)
 */
export function init(): void;

/**
 * Synthesize a policy from observed events (JSONL).
 *
 * Returns a camelCase JSON string with `policyYaml` and `risks`.
 */
export function policy_lab_synth(events_jsonl: string): string;

/**
 * Convert events JSONL to OCSF JSONL.
 */
export function policy_lab_to_ocsf(events_jsonl: string): string;

/**
 * Convert events JSONL to timeline JSONL.
 */
export function policy_lab_to_timeline(events_jsonl: string): string;

/**
 * Derive an Ed25519 public key from a private key.
 *
 * # Arguments
 * * `private_key_hex` - Hex-encoded private key (32 bytes, with or without 0x prefix)
 *
 * # Returns
 * Hex-encoded public key (32 bytes = 64 hex chars, no 0x prefix)
 */
export function public_key_from_private(private_key_hex: string): string;

/**
 * Sign a message with an Ed25519 private key.
 *
 * # Arguments
 * * `private_key_hex` - Hex-encoded private key (32 bytes, with or without 0x prefix)
 * * `message` - The message bytes to sign
 *
 * # Returns
 * Hex-encoded signature (64 bytes = 128 hex chars, no 0x prefix)
 */
export function sign_ed25519(private_key_hex: string, message: Uint8Array): string;

/**
 * Verify an Ed25519 signature over a message.
 *
 * # Arguments
 * * `public_key_hex` - Hex-encoded public key (32 bytes, with or without 0x prefix)
 * * `message` - The message bytes that were signed
 * * `signature_hex` - Hex-encoded signature (64 bytes, with or without 0x prefix)
 *
 * # Returns
 * `true` if the signature is valid, `false` otherwise
 */
export function verify_ed25519(public_key_hex: string, message: Uint8Array, signature_hex: string): boolean;

/**
 * Verify a Merkle inclusion proof.
 *
 * # Arguments
 * * `leaf_hash_hex` - Hex-encoded leaf hash (with or without 0x prefix)
 * * `proof_json` - JSON-serialized MerkleProof
 * * `root_hex` - Hex-encoded expected root hash (with or without 0x prefix)
 *
 * # Returns
 * `true` if the proof is valid, `false` otherwise
 */
export function verify_merkle_proof(leaf_hash_hex: string, proof_json: string, root_hex: string): boolean;

/**
 * Verify a signed Receipt.
 *
 * # Arguments
 * * `receipt_json` - JSON-serialized SignedReceipt
 * * `signer_pubkey_hex` - Hex-encoded signer public key
 * * `cosigner_pubkey_hex` - Optional hex-encoded co-signer public key
 *
 * # Returns
 * JavaScript object with verification result:
 * ```json
 * {
 *   "valid": true,
 *   "signer_valid": true,
 *   "cosigner_valid": null,
 *   "errors": []
 * }
 * ```
 */
export function verify_receipt(receipt_json: string, signer_pubkey_hex: string, cosigner_pubkey_hex?: string | null): any;

/**
 * Get version information about this WASM module
 */
export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_wasminstructionhierarchyenforcer_free: (a: number, b: number) => void;
    readonly __wbg_wasmjailbreakdetector_free: (a: number, b: number) => void;
    readonly __wbg_wasmoutputsanitizer_free: (a: number, b: number) => void;
    readonly __wbg_wasmpolicylab_free: (a: number, b: number) => void;
    readonly __wbg_wasmspidersensedetector_free: (a: number, b: number) => void;
    readonly canonicalize_json: (a: number, b: number) => [number, number, number, number];
    readonly compute_merkle_root: (a: number, b: number) => [number, number, number, number];
    readonly detect_prompt_injection: (a: number, b: number, c: number) => [number, number, number, number];
    readonly generate_keypair: () => [number, number, number];
    readonly generate_merkle_proof: (a: number, b: number, c: number) => [number, number, number, number];
    readonly get_canonical_json: (a: number, b: number) => [number, number, number, number];
    readonly hash_keccak256: (a: number, b: number) => [number, number];
    readonly hash_keccak256_bytes: (a: number, b: number) => [number, number];
    readonly hash_receipt: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly hash_sha256: (a: number, b: number) => [number, number];
    readonly hash_sha256_bytes: (a: number, b: number) => [number, number];
    readonly hash_sha256_prefixed: (a: number, b: number) => [number, number];
    readonly policy_lab_synth: (a: number, b: number) => [number, number];
    readonly policy_lab_to_ocsf: (a: number, b: number) => [number, number];
    readonly policy_lab_to_timeline: (a: number, b: number) => [number, number];
    readonly public_key_from_private: (a: number, b: number) => [number, number, number, number];
    readonly sign_ed25519: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly verify_ed25519: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly verify_merkle_proof: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly verify_receipt: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly version: () => [number, number];
    readonly wasminstructionhierarchyenforcer_enforce: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasminstructionhierarchyenforcer_new: (a: number, b: number) => [number, number, number];
    readonly wasmjailbreakdetector_detect: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly wasmjailbreakdetector_new: (a: number, b: number) => [number, number, number];
    readonly wasmoutputsanitizer_new: (a: number, b: number) => [number, number, number];
    readonly wasmoutputsanitizer_sanitize: (a: number, b: number, c: number) => [number, number, number, number];
    readonly wasmpolicylab_new: (a: number, b: number) => [number, number, number];
    readonly wasmspidersensedetector_expected_dim: (a: number) => number;
    readonly wasmspidersensedetector_load_patterns: (a: number, b: number, c: number) => [number, number];
    readonly wasmspidersensedetector_new: (a: number, b: number) => [number, number, number];
    readonly wasmspidersensedetector_pattern_count: (a: number) => number;
    readonly wasmspidersensedetector_screen: (a: number, b: number, c: number) => [number, number, number, number];
    readonly init: () => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
