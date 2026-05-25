/**
 * TypeScript surface for the `@clawdstrike/wasm` (hush-wasm) crate.
 *
 * These interfaces mirror the `#[wasm_bindgen]` exports in:
 *   - `crates/libs/hush-wasm/src/lib.rs`
 *   - `crates/libs/hush-wasm/src/detect.rs`
 *   - `crates/libs/hush-wasm/src/policy_lab.rs`
 *
 * They are hand-written because the auto-generated `.d.ts` produced by
 * wasm-bindgen is not currently published as part of the SDK. Keep this file
 * in sync with the Rust source until the build pipeline emits typings
 * directly (tracked as TS-any Sprint 1 follow-up).
 *
 * @module
 */

// ----------------------------------------------------------------------------
// Free functions (lib.rs)
// ----------------------------------------------------------------------------

export interface WasmKeypair {
  privateKey: string;
  publicKey: string;
}

export interface WasmReceiptVerifyResult {
  valid: boolean;
  signer_valid: boolean;
  cosigner_valid: boolean | null;
  errors: string[];
}

/** Convex subset of the wasm-bindgen-exported free functions. */
export interface HushWasmFreeFunctions {
  version(): string;
  hash_sha256(data: Uint8Array): string;
  hash_sha256_prefixed(data: Uint8Array): string;
  hash_keccak256(data: Uint8Array): string;
  hash_sha256_bytes(data: Uint8Array): Uint8Array;
  hash_keccak256_bytes(data: Uint8Array): Uint8Array;
  generate_keypair(): WasmKeypair | Map<string, string>;
  sign_ed25519(privateKeyHex: string, message: Uint8Array): string;
  public_key_from_private(privateKeyHex: string): string;
  verify_ed25519(publicKeyHex: string, message: Uint8Array, signatureHex: string): boolean;
  verify_receipt(
    receiptJson: string,
    signerPubkeyHex: string,
    cosignerPubkeyHex?: string,
  ): WasmReceiptVerifyResult;
  hash_receipt(receiptJson: string, algorithm: "sha256" | "keccak256"): string;
  get_canonical_json(receiptJson: string): string;
  verify_merkle_proof(leafHashHex: string, proofJson: string, rootHex: string): boolean;
  compute_merkle_root(leafHashesJson: string): string;
  generate_merkle_proof(leafHashesJson: string, leafIndex: number): string;
  canonicalize_json(jsonStr: string): string;
  detect_prompt_injection(text: string, maxScanBytes?: number): string;
  policy_lab_synth(eventsJsonl: string): string;
  policy_lab_to_ocsf(eventsJsonl: string): string;
  policy_lab_to_timeline(eventsJsonl: string): string;
}

// ----------------------------------------------------------------------------
// Detector classes (detect.rs)
// ----------------------------------------------------------------------------

/** Mirrors `WasmJailbreakDetector` in detect.rs. */
export interface WasmJailbreakDetectorInstance {
  detect(text: string, sessionId?: string): string;
  free?(): void;
}

export interface WasmJailbreakDetectorCtor {
  new (configJson?: string): WasmJailbreakDetectorInstance;
}

/** Mirrors `WasmOutputSanitizer` in detect.rs. */
export interface WasmOutputSanitizerInstance {
  sanitize(text: string): string;
  free?(): void;
}

export interface WasmOutputSanitizerCtor {
  new (configJson?: string): WasmOutputSanitizerInstance;
}

/** Mirrors `WasmInstructionHierarchyEnforcer` in detect.rs. */
export interface WasmInstructionHierarchyEnforcerInstance {
  enforce(messagesJson: string): string;
  free?(): void;
}

export interface WasmInstructionHierarchyEnforcerCtor {
  new (configJson?: string): WasmInstructionHierarchyEnforcerInstance;
}

/** Mirrors `WasmSpiderSenseDetector` in detect.rs. */
export interface WasmSpiderSenseDetectorInstance {
  load_patterns(patternsJson: string): void;
  screen(embeddingJson: string): string;
  expected_dim(): number | undefined;
  pattern_count(): number;
  free?(): void;
}

export interface WasmSpiderSenseDetectorCtor {
  new (configJson?: string): WasmSpiderSenseDetectorInstance;
}

/** Mirrors `WasmPolicyLab` in policy_lab.rs. */
export interface WasmPolicyLabInstance {
  free?(): void;
}

export interface WasmPolicyLabCtor {
  new (policyYaml: string): WasmPolicyLabInstance;
}

// ----------------------------------------------------------------------------
// Aggregate module surface
// ----------------------------------------------------------------------------

/** Full surface of the `@clawdstrike/wasm` module as imported by the SDK. */
export interface HushWasmModule extends HushWasmFreeFunctions {
  WasmJailbreakDetector: WasmJailbreakDetectorCtor;
  WasmOutputSanitizer: WasmOutputSanitizerCtor;
  WasmInstructionHierarchyEnforcer: WasmInstructionHierarchyEnforcerCtor;
  WasmSpiderSenseDetector: WasmSpiderSenseDetectorCtor;
  WasmPolicyLab: WasmPolicyLabCtor;
  /** wasm-bindgen-generated default export (init function). */
  default?: (...args: unknown[]) => Promise<unknown>;
}
