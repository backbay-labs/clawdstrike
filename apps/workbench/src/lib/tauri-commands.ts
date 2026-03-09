/**
 * Typed wrappers for Tauri backend commands (defined in `src-tauri/src/commands/workbench.rs`).
 *
 * Each function gates on `isDesktop()`. When running outside a Tauri webview
 * (dev server, tests, web-only builds) the call returns `null` so callers
 * can fall back to the existing client-side implementation.
 *
 * invoke() is lazily imported to avoid top-level module errors when the
 * `@tauri-apps/api` package is unavailable.
 */

import { isDesktop } from "./tauri-bridge";

// ---------------------------------------------------------------------------
// Response types — mirrors the Rust structs in commands/workbench.rs
// ---------------------------------------------------------------------------

export interface TauriValidationError {
  path: string;
  message: string;
}

export interface TauriValidationResponse {
  valid: boolean;
  name: string | null;
  version: string | null;
  schema_version: string;
  errors: TauriValidationError[];
  parse_error: string | null;
}

export interface TauriRulesetInfo {
  id: string;
  name: string;
  description: string;
}

export interface TauriGuardResultEntry {
  allowed: boolean;
  guard: string;
  severity: string;
  message: string;
  details: unknown | null;
}

export interface TauriEvaluationPathStep {
  guard: string;
  stage: string;
  stage_duration_ms: number;
  result: string;
}

export interface TauriSimulationResponse {
  allowed: boolean;
  results: TauriGuardResultEntry[];
  guard: string;
  message: string;
  evaluation_path: TauriEvaluationPathStep[];
}

export interface TauriPostureBudgetEntry {
  name: string;
  limit: number;
  consumed: number;
  remaining: number;
}

export interface TauriPostureReport {
  budgets: TauriPostureBudgetEntry[];
  violations: string[];
  state: string;
  state_before: string;
  transitioned: boolean;
}

export interface TauriPostureSimulationResponse {
  allowed: boolean;
  results: TauriGuardResultEntry[];
  guard: string;
  message: string;
  posture: TauriPostureReport | null;
}

export interface TauriSignedReceiptResponse {
  public_key: string;
  signed_receipt: Record<string, unknown>;
  receipt_hash: string;
}

export interface TauriExportResponse {
  success: boolean;
  path: string;
  message: string;
}

export interface TauriImportResponse {
  valid: boolean;
  yaml: string;
  name: string | null;
  version: string | null;
  errors: TauriValidationError[];
  parse_error: string | null;
}

export interface TauriChainReceiptInput {
  id: string;
  timestamp: string;
  verdict: string;
  guard: string;
  policyName: string;
  signature: string;
  publicKey: string;
  valid: boolean;
}

export interface TauriChainReceiptVerification {
  id: string;
  signature_valid: boolean | null;
  signature_reason: string;
  timestamp_order_valid: boolean;
  timestamp_note: string;
  receipt_hash: string;
}

export interface TauriChainVerificationResponse {
  receipts: TauriChainReceiptVerification[];
  chain_hash: string;
  all_signatures_valid: boolean;
  timestamps_ordered: boolean;
  chain_intact: boolean;
  chain_length: number;
  summary: string;
}

// ---------------------------------------------------------------------------
// Lazy invoke helper
// ---------------------------------------------------------------------------

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

// ---------------------------------------------------------------------------
// Command wrappers
// ---------------------------------------------------------------------------

/**
 * Validate policy YAML via the Rust policy engine.
 * Returns null when not running inside Tauri.
 */
export async function validatePolicyNative(yaml: string): Promise<TauriValidationResponse | null> {
  if (!isDesktop()) return null;
  try {
    return await tauriInvoke<TauriValidationResponse>("validate_policy", { yaml });
  } catch (err) {
    console.error("[tauri-commands] validate_policy failed:", err);
    return null;
  }
}

/**
 * List all built-in rulesets available in the Rust engine.
 * Returns null when not running inside Tauri.
 */
export async function listBuiltinRulesets(): Promise<TauriRulesetInfo[] | null> {
  if (!isDesktop()) return null;
  try {
    return await tauriInvoke<TauriRulesetInfo[]>("list_builtin_rulesets");
  } catch (err) {
    console.error("[tauri-commands] list_builtin_rulesets failed:", err);
    return null;
  }
}

/**
 * Load raw YAML for a named built-in ruleset from the Rust engine.
 * Returns null when not running inside Tauri or on error.
 */
export async function loadBuiltinRuleset(name: string): Promise<string | null> {
  if (!isDesktop()) return null;
  try {
    return await tauriInvoke<string>("load_builtin_ruleset", { name });
  } catch (err) {
    console.error("[tauri-commands] load_builtin_ruleset failed:", err);
    return null;
  }
}

/**
 * Simulate an action against a policy using the real Rust guard engine.
 * Returns null when not running inside Tauri.
 */
export async function simulateActionNative(
  policyYaml: string,
  actionType: string,
  target: string,
  content?: string,
): Promise<TauriSimulationResponse | null> {
  if (!isDesktop()) return null;
  try {
    return await tauriInvoke<TauriSimulationResponse>("simulate_action", {
      policyYaml,
      actionType,
      target,
      content: content ?? null,
    });
  } catch (err) {
    console.error("[tauri-commands] simulate_action failed:", err);
    return null;
  }
}

/**
 * Simulate an action with posture tracking via the Rust engine.
 * Accepts optional serialized posture state for cumulative budget tracking.
 * Returns null when not running inside Tauri.
 */
export async function simulateWithPostureNative(
  policyYaml: string,
  actionType: string,
  target: string,
  content?: string,
  postureStateJson?: string,
): Promise<TauriPostureSimulationResponse | null> {
  if (!isDesktop()) return null;
  try {
    return await tauriInvoke<TauriPostureSimulationResponse>("simulate_action_with_posture", {
      policyYaml,
      actionType,
      target,
      content: content ?? null,
      postureStateJson: postureStateJson ?? null,
    });
  } catch (err) {
    console.error("[tauri-commands] simulate_action_with_posture failed:", err);
    return null;
  }
}

/**
 * Create an Ed25519-signed receipt via the Rust crypto layer.
 * Returns null when not running inside Tauri.
 */
export async function signReceiptNative(
  contentHash: string,
  verdictPassed: boolean,
): Promise<TauriSignedReceiptResponse | null> {
  if (!isDesktop()) return null;
  try {
    return await tauriInvoke<TauriSignedReceiptResponse>("sign_receipt", {
      contentHash,
      verdictPassed,
    });
  } catch (err) {
    console.error("[tauri-commands] sign_receipt failed:", err);
    return null;
  }
}

/**
 * Validate and write a policy to a file on disk.
 *
 * @param content - The serialized policy content (YAML, JSON, or TOML string).
 * @param path    - Target file path on disk.
 * @param format  - Export format: "yaml" (default), "json", or "toml".
 * Returns null when not running inside Tauri.
 */
export async function exportPolicyFileNative(
  content: string,
  path: string,
  format: string = "yaml",
): Promise<TauriExportResponse | null> {
  if (!isDesktop()) return null;
  try {
    return await tauriInvoke<TauriExportResponse>("export_policy_file", { content, path, format });
  } catch (err) {
    console.error("[tauri-commands] export_policy_file failed:", err);
    return null;
  }
}

/**
 * Read and validate a policy file from disk.
 * Returns null when not running inside Tauri.
 */
export async function importPolicyFileNative(
  path: string,
): Promise<TauriImportResponse | null> {
  if (!isDesktop()) return null;
  try {
    return await tauriInvoke<TauriImportResponse>("import_policy_file", { path });
  } catch (err) {
    console.error("[tauri-commands] import_policy_file failed:", err);
    return null;
  }
}

/**
 * Verify a chain of receipts using the Rust Ed25519 crypto layer.
 * Checks signature validity, timestamp ordering, and computes chain hash.
 * Returns null when not running inside Tauri.
 */
export async function verifyReceiptChainNative(
  receipts: TauriChainReceiptInput[],
): Promise<TauriChainVerificationResponse | null> {
  if (!isDesktop()) return null;
  try {
    return await tauriInvoke<TauriChainVerificationResponse>("verify_receipt_chain", { receipts });
  } catch (err) {
    console.error("[tauri-commands] verify_receipt_chain failed:", err);
    return null;
  }
}
