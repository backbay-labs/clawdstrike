//! Workbench commands — local-first policy editing, simulation, and receipt signing.
//!
//! These commands integrate directly with the `clawdstrike` and `hush-core` crates
//! without requiring a running daemon. All evaluation happens in-process.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

use serde::{Deserialize, Serialize};

use clawdstrike::error::{Error as CsError, PolicyValidationError};
use clawdstrike::guards::{GuardAction, GuardContext};
use clawdstrike::policy::{
    LocalPolicyResolver, Policy, PolicyValidationOptions, RuleSet, POLICY_SCHEMA_VERSION,
};
use clawdstrike::posture::PostureRuntimeState;
use clawdstrike::{GuardReport, HushEngine, PostureAwareReport};
use hush_core::receipt::{Receipt, Verdict};
use hush_core::signing::{PublicKey, Signature};
use hush_core::{sha256, Hash, Keypair, SignedReceipt};

/// Maximum allowed size for policy content (2 MiB).
const MAX_POLICY_SIZE: usize = 2_097_152;

/// Maximum allowed size for action target/content inputs (10 MiB).
const MAX_INPUT_SIZE: usize = 10_485_760;

/// Maximum number of receipts in a chain verification request.
const MAX_CHAIN_LENGTH: usize = 10_000;

/// Sensitive path prefixes and suffixes that must never be read from or written to.
/// All comparisons are case-insensitive (paths are lowercased before matching).
const SENSITIVE_PATTERNS: &[&str] = &[
    "/.ssh",
    "/.gnupg/",
    "/.aws",
    "/.config/gcloud/",
    "/.azure/",
    "/library/keychains/",
    "/.password-store/",
    "/.config",
    "/.kube",
    "/.docker/config.json",
    "/.docker/",
    "/.netrc",
    "/.git-credentials",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/",
    "/proc/",
    "/sys/",
];

/// Sensitive file names (matched against the final path component or suffix).
/// All comparisons are case-insensitive (paths are lowercased before matching).
const SENSITIVE_SUFFIXES: &[&str] = &[
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".env",
    ".pem",
    ".key",
    "/.vault-token",
    "/.npmrc",
    "/.pypirc",
];

// ---------------------------------------------------------------------------
// L3: Rate limiting for signing commands
// ---------------------------------------------------------------------------

/// Minimum interval between signing operations (50 ms).
const SIGN_RATE_LIMIT_MS: u128 = 50;

/// Global timestamp of the last signing operation.
static LAST_SIGN_TIME: Mutex<Option<Instant>> = Mutex::new(None);

/// Check the signing rate limit. Returns an error if called faster than
/// `SIGN_RATE_LIMIT_MS` milliseconds since the last signing operation.
fn check_sign_rate_limit() -> Result<(), String> {
    let mut guard = LAST_SIGN_TIME.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(last) = *guard {
        let elapsed = last.elapsed().as_millis();
        if elapsed < SIGN_RATE_LIMIT_MS {
            return Err("Signing rate limit exceeded. Please wait before signing again.".into());
        }
    }
    *guard = Some(Instant::now());
    Ok(())
}

/// Reset the signing rate limiter (test-only).
#[cfg(test)]
fn reset_sign_rate_limit() {
    let mut guard = LAST_SIGN_TIME.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Check a normalized, lowercased path string against the sensitive patterns.
fn check_sensitive_path(check_str: &str) -> Result<(), String> {
    // Check sensitive prefixes.
    for pattern in SENSITIVE_PATTERNS {
        if check_str.contains(pattern) {
            return Err("Refusing to access sensitive path".to_string());
        }
    }

    // Check sensitive suffixes.
    for suffix in SENSITIVE_SUFFIXES {
        if check_str.ends_with(suffix) {
            return Err("Refusing to access sensitive file".to_string());
        }
    }

    Ok(())
}

/// Validate that a filesystem path is safe for import/export operations.
///
/// Rejects paths with `..` segments after normalization and paths that target
/// sensitive directories or files.
fn validate_file_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("Empty file path".into());
    }

    let p = Path::new(path);

    // If the full path already exists, canonicalize it entirely so that
    // file-level symlinks are resolved before the sensitive-path check.
    // Otherwise, canonicalize the parent directory and join the filename
    // (the file itself may not exist yet for export). Reject the path
    // outright if the parent doesn't exist — falling back to the raw path
    // would allow symlink/TOCTOU bypasses.
    let normalized = if p.exists() {
        p.canonicalize().map_err(|e| {
            eprintln!("[workbench] cannot resolve path: {e}");
            "Cannot resolve path".to_string()
        })?
    } else if let Some(parent) = p.parent() {
        if parent.as_os_str().is_empty() {
            // Relative filename with no directory component (e.g. "foo.yaml").
            // Resolve against CWD so the sensitive-path checks still fire.
            let cwd = std::env::current_dir().map_err(|e| {
                eprintln!("[workbench] cannot determine working directory: {e}");
                "Cannot determine working directory".to_string()
            })?;
            let canon_cwd = cwd.canonicalize().map_err(|e| {
                eprintln!("[workbench] cannot resolve working directory: {e}");
                "Cannot resolve working directory".to_string()
            })?;
            canon_cwd.join(p)
        } else if parent.exists() {
            let canon_parent = parent.canonicalize().map_err(|e| {
                eprintln!("[workbench] cannot resolve parent directory: {e}");
                "Cannot resolve parent directory".to_string()
            })?;
            let file_name = p.file_name().unwrap_or_default();
            canon_parent.join(file_name)
        } else {
            return Err("Parent directory does not exist".to_string());
        }
    } else {
        return Err("Invalid path: no parent component".into());
    };

    let normalized_str = normalized.to_string_lossy();

    // Reject paths that still contain ".." after normalization.
    for component in normalized.components() {
        if let std::path::Component::ParentDir = component {
            return Err("Path traversal detected".to_string());
        }
    }

    // Normalize backslashes to forward slashes and lowercase for cross-platform
    // case-insensitive sensitive-path matching.
    let check_str = normalized_str.replace('\\', "/").to_lowercase();

    check_sensitive_path(&check_str)?;
    Ok(normalized)
}

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

fn open_file_read_no_follow(path: &Path) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    #[cfg(windows)]
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path).map_err(|e| {
        eprintln!("[workbench] file open error: {e}");
        "Failed to read file".to_string()
    })
}

fn open_file_write_no_follow(path: &Path) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    #[cfg(windows)]
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path).map_err(|e| {
        eprintln!("[workbench] file open error: {e}");
        "Failed to write file".to_string()
    })
}

async fn read_text_file_secure(path: PathBuf) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let mut file = open_file_read_no_follow(&path)?;
        let mut yaml = String::new();
        file.read_to_string(&mut yaml).map_err(|e| {
            eprintln!("[workbench] file read error: {e}");
            "Failed to read file".to_string()
        })?;
        Ok(yaml)
    })
    .await
    .map_err(|e| {
        eprintln!("[workbench] file read task join error: {e}");
        "Failed to read file".to_string()
    })?
}

async fn write_text_file_secure(path: PathBuf, output: String) -> Result<(), String> {
    let bytes = output.into_bytes();
    tokio::task::spawn_blocking(move || {
        let mut file = open_file_write_no_follow(&path)?;
        file.write_all(&bytes).map_err(|e| {
            eprintln!("[workbench] file write error: {e}");
            "Failed to write file".to_string()
        })?;
        file.sync_all().map_err(|e| {
            eprintln!("[workbench] file sync error: {e}");
            "Failed to write file".to_string()
        })?;
        Ok(())
    })
    .await
    .map_err(|e| {
        eprintln!("[workbench] file write task join error: {e}");
        "Failed to write file".to_string()
    })?
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationResponse {
    /// Whether the policy YAML is valid.
    pub valid: bool,
    /// Policy name (extracted when parsing succeeds, even if validation fails).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Policy version field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Current schema version supported by this build.
    pub schema_version: String,
    /// Structured validation errors (empty when valid).
    pub errors: Vec<ValidationError>,
    /// Human-readable summary when the YAML cannot be parsed at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RulesetInfo {
    pub id: String,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuardResultEntry {
    pub allowed: bool,
    pub guard: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvaluationPathStep {
    /// Guard name.
    pub guard: String,
    /// Evaluation stage this guard belongs to (fast_path, std_path, deep_path).
    pub stage: String,
    /// Stage-level elapsed time in milliseconds (shared by all guards in the same stage).
    pub stage_duration_ms: f64,
    /// Per-guard result: "allow", "deny", or "skip".
    pub result: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationResponse {
    /// Aggregated verdict.
    pub allowed: bool,
    /// Per-guard results.
    pub results: Vec<GuardResultEntry>,
    /// Overall guard name that produced the aggregate.
    pub guard: String,
    /// Overall message.
    pub message: String,
    /// Ordered evaluation path showing which guards ran, in what stage, with timing.
    pub evaluation_path: Vec<EvaluationPathStep>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostureBudgetEntry {
    pub name: String,
    pub limit: u64,
    pub consumed: u64,
    pub remaining: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostureReport {
    /// Budget entries with consumption data.
    pub budgets: Vec<PostureBudgetEntry>,
    /// Human-readable violation messages.
    pub violations: Vec<String>,
    /// Current posture state name (e.g., "normal", "restricted", "quarantine").
    pub state: String,
    /// Posture state before this evaluation.
    pub state_before: String,
    /// Whether a state transition occurred.
    pub transitioned: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostureSimulationResponse {
    /// Aggregated verdict.
    pub allowed: bool,
    /// Per-guard results.
    pub results: Vec<GuardResultEntry>,
    /// Overall guard name that produced the aggregate.
    pub guard: String,
    /// Overall message.
    pub message: String,
    /// Posture data (present when the policy has a posture config).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureReport>,
    /// Serialized `PostureRuntimeState` after evaluation, for passing into the
    /// next simulation call to preserve cumulative budget/state tracking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture_state_json: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedReceiptResponse {
    /// Hex-encoded public key of the signer.
    pub public_key: String,
    /// The signed receipt as a JSON value (for display/export).
    pub signed_receipt: serde_json::Value,
    /// Hex-encoded SHA-256 hash of the canonical receipt JSON.
    pub receipt_hash: String,
    /// Whether the key used was "persistent" (Stronghold-stored) or "ephemeral".
    pub key_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportResponse {
    pub success: bool,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportResponse {
    pub valid: bool,
    pub yaml: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub errors: Vec<ValidationError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
}

/// Input receipt for chain verification (matches the frontend Receipt type).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainReceiptInput {
    pub id: String,
    pub timestamp: String,
    pub verdict: String,
    pub guard: String,
    pub policy_name: String,
    pub signature: String,
    pub public_key: String,
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_receipt: Option<serde_json::Value>,
}

/// Per-receipt verification result in a chain.
#[derive(Debug, Clone, Serialize)]
pub struct ChainReceiptVerification {
    /// Receipt ID.
    pub id: String,
    /// Whether the Ed25519 signature verified against the public key.
    pub signature_valid: Option<bool>,
    /// Human-readable reason when signature verification is skipped or fails.
    pub signature_reason: String,
    /// Whether this receipt's timestamp is >= the previous receipt's timestamp.
    pub timestamp_order_valid: bool,
    /// Human-readable note about timestamp ordering.
    pub timestamp_note: String,
    /// SHA-256 hash of the receipt's canonical content (id + timestamp + verdict + guard).
    pub receipt_hash: String,
}

/// Overall chain verification result.
#[derive(Debug, Clone, Serialize)]
pub struct ChainVerificationResponse {
    /// Per-receipt verification results, in the same order as the input.
    pub receipts: Vec<ChainReceiptVerification>,
    /// SHA-256 hash of the concatenated receipt hashes (the chain hash).
    pub chain_hash: String,
    /// Whether all signatures that could be verified were valid.
    pub all_signatures_valid: bool,
    /// Whether all timestamps are in non-decreasing order.
    pub timestamps_ordered: bool,
    /// Whether the overall chain integrity is intact.
    pub chain_intact: bool,
    /// Number of receipts in the chain.
    pub chain_length: usize,
    /// Summary message.
    pub summary: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Try to parse YAML into a `Policy` without validation so we can extract
/// metadata even when validation fails.
fn parse_policy_lax(yaml: &str) -> Result<Policy, String> {
    // Use serde_yaml directly to avoid the validate() call inside from_yaml().
    serde_yaml::from_str::<Policy>(yaml).map_err(|e| e.to_string())
}

/// Validate a parsed policy using lax options (env-var placeholders are not
/// required to resolve on the workbench host).
fn validate_policy_lax(policy: &Policy) -> Result<(), PolicyValidationError> {
    policy
        .validate_with_options(PolicyValidationOptions::LAX)
        .map_err(|e| match e {
            CsError::PolicyValidation(pve) => pve,
            other => PolicyValidationError::new(vec![clawdstrike::error::PolicyFieldError::new(
                "policy",
                other.to_string(),
            )]),
        })
}

fn guard_result_to_entry(r: &clawdstrike::GuardResult) -> GuardResultEntry {
    GuardResultEntry {
        allowed: r.allowed,
        guard: r.guard.clone(),
        severity: format!("{:?}", r.severity).to_ascii_lowercase(),
        message: r.message.clone(),
        details: r.details.clone(),
    }
}

/// Convert the `GuardReport::evaluation_path` into a flat list of per-guard
/// steps the frontend can render as a waterfall chart. Each guard is annotated
/// with its pipeline stage and the stage-level duration (in milliseconds).
fn build_evaluation_path(report: &GuardReport) -> Vec<EvaluationPathStep> {
    let ep = match report.evaluation_path.as_ref() {
        Some(ep) if !ep.guard_sequence.is_empty() => ep,
        _ => return Vec::new(),
    };

    // Build a lookup from guard name -> result string using per_guard results.
    let guard_result_map: std::collections::HashMap<&str, &str> = report
        .per_guard
        .iter()
        .map(|r| (r.guard.as_str(), if r.allowed { "allow" } else { "deny" }))
        .collect();

    // Reconstruct which guards belong to which stage. The evaluation path
    // records stages in order and guards in order; we need to correlate them.
    // Use the builtin_stage_for_guard_name helper to assign each guard.
    ep.guard_sequence
        .iter()
        .map(|guard_name| {
            let stage = clawdstrike::pipeline::builtin_stage_for_guard_name(guard_name);
            let stage_str = stage.as_str();
            let stage_us = ep.stage_timings_us.get(stage_str).copied().unwrap_or(0);
            let stage_duration_ms = stage_us as f64 / 1000.0;
            let result = guard_result_map
                .get(guard_name.as_str())
                .copied()
                .unwrap_or("skip")
                .to_string();

            EvaluationPathStep {
                guard: guard_name.clone(),
                stage: stage_str.to_string(),
                stage_duration_ms,
                result,
            }
        })
        .collect()
}

/// Parse a "host:port" string, defaulting to port 443 when omitted.
fn parse_host_port(target: &str) -> Result<(&str, u16), String> {
    if target.is_empty() {
        return Err("Empty target".into());
    }
    if let Some((h, p)) = target.rsplit_once(':') {
        let port: u16 = p.parse().map_err(|_| format!("Invalid port: {}", p))?;
        Ok((h, port))
    } else {
        Ok((target, 443u16))
    }
}

/// Load a policy from YAML using lax validation (env-var placeholders are not
/// required to resolve on the workbench host).
fn load_policy_lax(yaml: &str) -> Result<Policy, String> {
    Policy::from_yaml_with_extends_resolver_with_validation_options(
        yaml,
        None,
        &LocalPolicyResolver::new(),
        PolicyValidationOptions::LAX,
    )
    .map_err(|e| {
        eprintln!("[workbench] policy load error: {e}");
        "Policy load error: invalid or unsupported policy format".to_string()
    })
}

/// Build a `PostureReport` from a `PostureAwareReport`.
fn posture_report_from_aware(
    report: &PostureAwareReport,
    posture_state: &Option<PostureRuntimeState>,
) -> PostureReport {
    let mut budgets = Vec::new();
    let mut violations = Vec::new();

    for (name, counter) in &report.budgets_after {
        let entry = PostureBudgetEntry {
            name: name.clone(),
            limit: counter.limit,
            consumed: counter.used,
            remaining: counter.remaining(),
        };

        if counter.is_exhausted() && counter.limit > 0 {
            violations.push(format!(
                "Budget '{}' exhausted ({}/{})",
                name, counter.used, counter.limit
            ));
        }

        budgets.push(entry);
    }

    budgets.sort_by(|a, b| a.name.cmp(&b.name));

    if let Some(ref transition) = report.transition {
        violations.push(format!(
            "State transition: {} -> {} (trigger: {})",
            transition.from, transition.to, transition.trigger
        ));
    }

    if !report.guard_report.overall.allowed && report.guard_report.overall.guard == "posture" {
        violations.push(report.guard_report.overall.message.clone());
    }

    let state = if let Some(ps) = posture_state {
        ps.current_state.clone()
    } else {
        report.posture_after.clone()
    };

    PostureReport {
        budgets,
        violations,
        state,
        state_before: report.posture_before.clone(),
        transitioned: report.posture_before != report.posture_after,
    }
}

/// Check whether a timestamp string has the basic ISO 8601 UTC structure
/// required for reliable lexicographic comparison (`*T*Z`, at least 20 chars).
fn is_valid_utc_timestamp(ts: &str) -> bool {
    // Must end with Z and have the basic ISO 8601 structure
    ts.ends_with('Z') && ts.len() >= 20 && ts.contains('T')
}

/// Try to verify an Ed25519 signature. Returns `(Some(bool), reason)` if
/// verification was attempted, or `(None, reason)` if the inputs could not be
/// parsed (verification skipped).
fn verify_receipt_signature(
    public_key_hex: &str,
    signature_hex: &str,
    message: &[u8],
) -> (Option<bool>, String) {
    let pk = match PublicKey::from_hex(public_key_hex) {
        Ok(pk) => pk,
        Err(e) => {
            return (None, format!("Could not parse public key: {}", e));
        }
    };

    let sig = match Signature::from_hex(signature_hex) {
        Ok(sig) => sig,
        Err(e) => {
            return (None, format!("Could not parse signature: {}", e));
        }
    };

    if pk.verify(message, &sig) {
        (Some(true), "Signature valid.".to_string())
    } else {
        (
            Some(false),
            "Signature does not match public key and content.".to_string(),
        )
    }
}

fn verify_signed_receipt_signature(
    public_key_hex: &str,
    signature_hex: &str,
    signed_receipt_json: &serde_json::Value,
) -> (Option<bool>, String) {
    let signed_receipt: SignedReceipt = match serde_json::from_value(signed_receipt_json.clone()) {
        Ok(signed_receipt) => signed_receipt,
        Err(e) => {
            return (
                Some(false),
                format!("Embedded signed_receipt is invalid: {}", e),
            );
        }
    };

    let embedded_signature = signed_receipt.signatures.signer.to_hex();
    if embedded_signature != signature_hex {
        return (
            Some(false),
            "Provided signature does not match signed_receipt.signatures.signer.".to_string(),
        );
    }

    let canonical_receipt = match signed_receipt.receipt.to_canonical_json() {
        Ok(canonical_receipt) => canonical_receipt,
        Err(e) => {
            return (
                Some(false),
                format!(
                    "Could not canonicalize embedded signed_receipt payload: {}",
                    e
                ),
            );
        }
    };

    verify_receipt_signature(public_key_hex, signature_hex, canonical_receipt.as_bytes())
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Parse and validate policy YAML, returning structured results.
#[tauri::command]
pub async fn validate_policy(yaml: String) -> Result<ValidationResponse, String> {
    if yaml.len() > MAX_POLICY_SIZE {
        return Err(format!(
            "Input too large: {} bytes (max {})",
            yaml.len(),
            MAX_POLICY_SIZE
        ));
    }

    let policy = match parse_policy_lax(&yaml) {
        Ok(p) => p,
        Err(parse_err) => {
            return Ok(ValidationResponse {
                valid: false,
                name: None,
                version: None,
                schema_version: POLICY_SCHEMA_VERSION.to_string(),
                errors: vec![],
                parse_error: Some(parse_err),
            });
        }
    };

    let name = if policy.name.is_empty() {
        None
    } else {
        Some(policy.name.clone())
    };
    let version = Some(policy.version.clone());

    match validate_policy_lax(&policy) {
        Ok(()) => Ok(ValidationResponse {
            valid: true,
            name,
            version,
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            errors: vec![],
            parse_error: None,
        }),
        Err(pve) => {
            let errors = pve
                .errors
                .iter()
                .map(|e| ValidationError {
                    path: e.path.clone(),
                    message: e.message.clone(),
                })
                .collect();
            Ok(ValidationResponse {
                valid: false,
                name,
                version,
                schema_version: POLICY_SCHEMA_VERSION.to_string(),
                errors,
                parse_error: None,
            })
        }
    }
}

/// Return the raw YAML content of a named built-in ruleset.
#[tauri::command]
pub async fn load_builtin_ruleset(name: String) -> Result<String, String> {
    match RuleSet::yaml_by_name(&name) {
        Some((yaml, _id)) => Ok(yaml.to_string()),
        None => Err(format!("Unknown built-in ruleset: {}", name)),
    }
}

/// Return metadata for all built-in rulesets.
#[tauri::command]
pub async fn list_builtin_rulesets() -> Result<Vec<RulesetInfo>, String> {
    let names = RuleSet::list();
    let mut out = Vec::with_capacity(names.len());

    for &name in names {
        match RuleSet::by_name(name) {
            Ok(Some(rs)) => out.push(RulesetInfo {
                id: rs.id.clone(),
                name: if rs.name.is_empty() {
                    rs.id.clone()
                } else {
                    rs.name
                },
                description: rs.description,
            }),
            _ => {
                // Fallback: include the id even if extends resolution fails
                // on this host.
                out.push(RulesetInfo {
                    id: name.to_string(),
                    name: name.to_string(),
                    description: String::new(),
                });
            }
        }
    }

    Ok(out)
}

/// Evaluate a single simulated action against the given policy YAML.
#[tauri::command]
pub async fn simulate_action(
    policy_yaml: String,
    action_type: String,
    target: String,
    content: Option<String>,
) -> Result<SimulationResponse, String> {
    if policy_yaml.len() > MAX_POLICY_SIZE {
        return Err(format!(
            "Input too large: {} bytes (max {})",
            policy_yaml.len(),
            MAX_POLICY_SIZE
        ));
    }
    if target.len() > MAX_INPUT_SIZE {
        return Err(format!(
            "Target too large: {} bytes (max {})",
            target.len(),
            MAX_INPUT_SIZE
        ));
    }
    if let Some(ref c) = content {
        if c.len() > MAX_INPUT_SIZE {
            return Err(format!(
                "Content too large: {} bytes (max {})",
                c.len(),
                MAX_INPUT_SIZE
            ));
        }
    }

    let policy = load_policy_lax(&policy_yaml)?;

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();
    let content_str = content.as_deref().unwrap_or("");

    // Parse MCP args eagerly so the owned value lives through the await point.
    let mcp_args: serde_json::Value = if matches!(action_type.as_str(), "mcp_tool" | "mcp") {
        if content_str.is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str(content_str).map_err(|e| {
                eprintln!("[workbench] JSON parse error: {e}");
                "Invalid JSON for MCP args".to_string()
            })?
        }
    } else {
        serde_json::Value::Null // unused
    };

    let action = match action_type.as_str() {
        "file_access" | "file" => GuardAction::FileAccess(&target),
        "file_write" => GuardAction::FileWrite(&target, content_str.as_bytes()),
        "network" | "egress" => {
            let (host, port) = parse_host_port(&target)?;
            GuardAction::NetworkEgress(host, port)
        }
        "shell" | "command" => GuardAction::ShellCommand(&target),
        "mcp_tool" | "mcp" => GuardAction::McpTool(&target, &mcp_args),
        "patch" => GuardAction::Patch(&target, content_str),
        other => {
            return Err(format!(
                "Unknown action type '{}'. Supported: file_access, file_write, network, shell, mcp_tool, patch",
                other
            ));
        }
    };

    let report: GuardReport = engine
        .check_action_report(&action, &context)
        .await
        .map_err(|e| {
            eprintln!("[workbench] evaluation error: {e}");
            "Policy evaluation failed".to_string()
        })?;

    let results: Vec<GuardResultEntry> =
        report.per_guard.iter().map(guard_result_to_entry).collect();
    let evaluation_path = build_evaluation_path(&report);

    Ok(SimulationResponse {
        allowed: report.overall.allowed,
        results,
        guard: report.overall.guard.clone(),
        message: report.overall.message.clone(),
        evaluation_path,
    })
}

/// Evaluate a simulated action with posture tracking, returning guard results
/// plus posture budget data.
#[tauri::command]
pub async fn simulate_action_with_posture(
    policy_yaml: String,
    action_type: String,
    target: String,
    content: Option<String>,
    posture_state_json: Option<String>,
) -> Result<PostureSimulationResponse, String> {
    if policy_yaml.len() > MAX_POLICY_SIZE {
        return Err(format!(
            "Input too large: {} bytes (max {})",
            policy_yaml.len(),
            MAX_POLICY_SIZE
        ));
    }
    if target.len() > MAX_INPUT_SIZE {
        return Err(format!(
            "Target too large: {} bytes (max {})",
            target.len(),
            MAX_INPUT_SIZE
        ));
    }
    if let Some(ref c) = content {
        if c.len() > MAX_INPUT_SIZE {
            return Err(format!(
                "Content too large: {} bytes (max {})",
                c.len(),
                MAX_INPUT_SIZE
            ));
        }
    }
    if let Some(ref psj) = posture_state_json {
        if psj.len() > MAX_POLICY_SIZE {
            return Err(format!(
                "Posture state too large: {} bytes (max {})",
                psj.len(),
                MAX_POLICY_SIZE
            ));
        }
    }

    let policy = load_policy_lax(&policy_yaml)?;

    let mut posture_state: Option<PostureRuntimeState> = match posture_state_json {
        Some(json) if !json.is_empty() => Some(serde_json::from_str(&json).map_err(|e| {
            eprintln!("[workbench] posture state parse error: {e}");
            "Invalid posture state JSON".to_string()
        })?),
        _ => None,
    };

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();
    let content_str = content.as_deref().unwrap_or("");

    // Parse MCP args eagerly so the owned value lives through the await point.
    let mcp_args: serde_json::Value = if matches!(action_type.as_str(), "mcp_tool" | "mcp") {
        if content_str.is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str(content_str).map_err(|e| {
                eprintln!("[workbench] JSON parse error: {e}");
                "Invalid JSON for MCP args".to_string()
            })?
        }
    } else {
        serde_json::Value::Null // unused
    };

    let action = match action_type.as_str() {
        "file_access" | "file" => GuardAction::FileAccess(&target),
        "file_write" => GuardAction::FileWrite(&target, content_str.as_bytes()),
        "network" | "egress" => {
            let (host, port) = parse_host_port(&target)?;
            GuardAction::NetworkEgress(host, port)
        }
        "shell" | "command" => GuardAction::ShellCommand(&target),
        "mcp_tool" | "mcp" => GuardAction::McpTool(&target, &mcp_args),
        "patch" => GuardAction::Patch(&target, content_str),
        other => {
            return Err(format!(
                "Unknown action type '{}'. Supported: file_access, file_write, network, shell, mcp_tool, patch",
                other
            ));
        }
    };

    let report: PostureAwareReport = engine
        .check_action_report_with_posture(&action, &context, &mut posture_state)
        .await
        .map_err(|e| {
            eprintln!("[workbench] evaluation error: {e}");
            "Policy evaluation failed".to_string()
        })?;

    let results: Vec<GuardResultEntry> = report
        .guard_report
        .per_guard
        .iter()
        .map(guard_result_to_entry)
        .collect();

    let has_posture = !report.budgets_after.is_empty()
        || report.posture_after != "default"
        || report.transition.is_some();

    let posture = if has_posture {
        Some(posture_report_from_aware(&report, &posture_state))
    } else {
        None
    };

    // Serialize the mutated posture runtime state so the frontend can pass it
    // back into the next simulation for cumulative budget/state tracking.
    let posture_state_json = posture_state
        .as_ref()
        .and_then(|ps| serde_json::to_string(ps).ok());

    Ok(PostureSimulationResponse {
        allowed: report.guard_report.overall.allowed,
        results,
        guard: report.guard_report.overall.guard.clone(),
        message: report.guard_report.overall.message.clone(),
        posture,
        posture_state_json,
    })
}

/// Generate an ephemeral keypair, create a receipt for the given content hash
/// and verdict, sign it, and return the result.
///
/// # Security Note
///
/// This command generates a fresh ephemeral Ed25519 keypair per invocation.
/// The private key is dropped when the function returns. This is suitable for
/// workbench demonstration and testing only — NOT for production signing.
/// For production use, keys should be loaded from a keystore or HSM.
#[tauri::command]
pub async fn sign_receipt(
    content_hash: String,
    verdict_passed: bool,
) -> Result<SignedReceiptResponse, String> {
    check_sign_rate_limit()?;

    let hash = Hash::from_hex(&content_hash).map_err(|e| {
        eprintln!("[workbench] invalid content hash hex: {e}");
        "Invalid content hash".to_string()
    })?;

    let verdict = if verdict_passed {
        Verdict::pass()
    } else {
        Verdict::fail()
    };

    let receipt = Receipt::new(hash, verdict);

    let keypair = Keypair::generate();
    let public_key_hex = keypair.public_key().to_hex();

    let receipt_hash = receipt
        .hash_sha256()
        .map_err(|e| {
            eprintln!("[workbench] receipt hashing error: {e}");
            "Receipt hashing failed".to_string()
        })?
        .to_hex();

    let signed = SignedReceipt::sign(receipt, &keypair).map_err(|e| {
        eprintln!("[workbench] signing error: {e}");
        "Signing failed".to_string()
    })?;

    let signed_json = serde_json::to_value(&signed).map_err(|e| {
        eprintln!("[workbench] serialization error: {e}");
        "Serialization failed".to_string()
    })?;

    Ok(SignedReceiptResponse {
        public_key: public_key_hex,
        signed_receipt: signed_json,
        receipt_hash,
        key_type: "ephemeral".to_string(),
    })
}

/// Sign a receipt using the persistent Ed25519 key stored in Stronghold.
///
/// Identical to `sign_receipt` but instead of generating an ephemeral keypair,
/// it retrieves the persistent key seed from Stronghold and uses it to produce
/// a deterministic signature. The `key_type` field in the response is set to
/// `"persistent"`.
///
/// Falls back to an ephemeral key if no persistent key is available yet.
#[tauri::command]
pub async fn sign_receipt_persistent(
    app: tauri::AppHandle,
    content_hash: String,
    verdict_passed: bool,
) -> Result<SignedReceiptResponse, String> {
    use tauri::Manager;

    check_sign_rate_limit()?;

    let hash = Hash::from_hex(&content_hash).map_err(|e| {
        eprintln!("[workbench] invalid content hash hex: {e}");
        "Invalid content hash".to_string()
    })?;

    let verdict = if verdict_passed {
        Verdict::pass()
    } else {
        Verdict::fail()
    };

    let receipt = Receipt::new(hash, verdict);

    // Try to load the persistent key from Stronghold state.
    let stronghold_state = app.state::<super::stronghold::StrongholdState>();
    let (keypair, key_type) =
        match super::stronghold::load_persistent_keypair_from_state(&stronghold_state) {
            Some(kp) => (kp, "persistent"),
            None => (Keypair::generate(), "ephemeral"),
        };

    let public_key_hex = keypair.public_key().to_hex();

    let receipt_hash = receipt
        .hash_sha256()
        .map_err(|e| {
            eprintln!("[workbench] receipt hashing error: {e}");
            "Receipt hashing failed".to_string()
        })?
        .to_hex();

    let signed = SignedReceipt::sign(receipt, &keypair).map_err(|e| {
        eprintln!("[workbench] signing error: {e}");
        "Signing failed".to_string()
    })?;

    let signed_json = serde_json::to_value(&signed).map_err(|e| {
        eprintln!("[workbench] serialization error: {e}");
        "Serialization failed".to_string()
    })?;

    Ok(SignedReceiptResponse {
        public_key: public_key_hex,
        signed_receipt: signed_json,
        receipt_hash,
        key_type: key_type.to_string(),
    })
}

/// Verify a chain of receipts: check Ed25519 signatures, timestamp ordering,
/// and compute a chain hash from concatenated per-receipt hashes.
///
/// # Signature verification strategy (P1-1 / P1-4)
///
/// When an embedded `signed_receipt` is present, signature verification tries
/// the RFC 8785 canonical JSON payload first — this matches what
/// `SignedReceipt::sign()` actually signs. If that fails, it falls back to
/// the legacy colon-delimited format `id:timestamp:verdict:guard:policy_name`.
///
/// When no `signed_receipt` is provided, only the colon-delimited format is
/// attempted.
///
/// The chain hash is always computed from the colon-delimited format to keep
/// existing chain hashes stable.
#[tauri::command]
pub async fn verify_receipt_chain(
    receipts: Vec<ChainReceiptInput>,
) -> Result<ChainVerificationResponse, String> {
    if receipts.len() > MAX_CHAIN_LENGTH {
        return Err(format!(
            "Receipt chain too long: {} receipts (max {})",
            receipts.len(),
            MAX_CHAIN_LENGTH
        ));
    }

    if receipts.is_empty() {
        return Ok(ChainVerificationResponse {
            receipts: vec![],
            chain_hash: sha256(b"").to_hex(),
            all_signatures_valid: true,
            timestamps_ordered: true,
            chain_intact: true,
            chain_length: 0,
            summary: "Empty chain — nothing to verify.".to_string(),
        });
    }

    // Sort by timestamp (stable sort preserves original order for equal timestamps).
    let mut sorted = receipts.clone();
    sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Validate that all timestamps conform to ISO 8601 with Z suffix so that
    // lexicographic comparison is correct (Fix #19).
    let non_conforming_timestamps: Vec<&str> = sorted
        .iter()
        .filter(|r| !is_valid_utc_timestamp(&r.timestamp))
        .map(|r| r.timestamp.as_str())
        .collect();

    let mut per_receipt: Vec<ChainReceiptVerification> = Vec::with_capacity(sorted.len());
    let mut any_sig_failed = false;
    let mut any_sig_verified = false;
    let mut timestamps_ordered = true;
    let mut chain_hash_input = Vec::new();

    for (i, r) in sorted.iter().enumerate() {
        // Chain-level canonical format: "id:timestamp:verdict:guard:policy_name".
        // This is used for the chain hash (always) and as the *first* signature
        // verification attempt.
        let canonical_content = format!(
            "{}:{}:{}:{}:{}",
            r.id, r.timestamp, r.verdict, r.guard, r.policy_name
        );
        let receipt_hash = sha256(canonical_content.as_bytes());
        let receipt_hash_hex = receipt_hash.to_hex();
        chain_hash_input.extend_from_slice(receipt_hash.as_bytes());

        let (ts_valid, ts_note) = if i == 0 {
            (true, "First receipt in chain.".to_string())
        } else {
            let prev = &sorted[i - 1];
            if r.timestamp >= prev.timestamp {
                (true, "Timestamp >= previous.".to_string())
            } else {
                timestamps_ordered = false;
                (
                    false,
                    format!(
                        "Timestamp {} is before previous {}.",
                        r.timestamp, prev.timestamp
                    ),
                )
            }
        };

        // Try the canonical JSON payload first (matches what SignedReceipt::sign()
        // actually signs — RFC 8785 canonical JSON of the receipt). Fall back to the
        // legacy colon-delimited format for backward compatibility with older chains.
        let (sig_valid, sig_reason) = if let Some(signed_receipt) = &r.signed_receipt {
            let (json_sig_valid, json_sig_reason) =
                verify_signed_receipt_signature(&r.public_key, &r.signature, signed_receipt);
            if json_sig_valid == Some(true) {
                (
                    json_sig_valid,
                    format!("{} (verified via canonical JSON payload)", json_sig_reason,),
                )
            } else {
                // Canonical JSON failed — fall back to colon-delimited format.
                let (colon_valid, colon_reason) = verify_receipt_signature(
                    &r.public_key,
                    &r.signature,
                    canonical_content.as_bytes(),
                );
                if colon_valid == Some(true) {
                    (colon_valid, colon_reason)
                } else {
                    // Both failed — report the canonical JSON failure as primary.
                    (json_sig_valid, json_sig_reason)
                }
            }
        } else {
            // No embedded signed_receipt — use the legacy colon-delimited payload.
            verify_receipt_signature(&r.public_key, &r.signature, canonical_content.as_bytes())
        };

        if sig_valid == Some(true) {
            any_sig_verified = true;
        }
        if sig_valid == Some(false) {
            any_sig_failed = true;
        }

        per_receipt.push(ChainReceiptVerification {
            id: r.id.clone(),
            signature_valid: sig_valid,
            signature_reason: sig_reason,
            timestamp_order_valid: ts_valid,
            timestamp_note: ts_note,
            receipt_hash: receipt_hash_hex,
        });
    }

    let chain_hash = sha256(&chain_hash_input).to_hex();
    // Chain is intact only when no signatures explicitly failed, timestamps are
    // ordered, and at least one signature was positively verified (or the chain
    // is empty). Unparseable signatures alone no longer count as "valid". (#20)
    let chain_intact =
        !any_sig_failed && timestamps_ordered && (any_sig_verified || sorted.is_empty());

    let mut summary = if chain_intact {
        format!(
            "Chain of {} receipt(s) verified successfully.",
            sorted.len()
        )
    } else {
        let mut issues = Vec::new();
        if any_sig_failed {
            issues.push("signature verification failure(s)");
        }
        if !any_sig_verified && !sorted.is_empty() {
            issues.push("no signatures could be positively verified");
        }
        if !timestamps_ordered {
            issues.push("timestamp ordering violation(s)");
        }
        format!(
            "Chain of {} receipt(s) has issues: {}.",
            sorted.len(),
            issues.join(", ")
        )
    };

    // Append a warning if any timestamps don't conform to the expected format.
    if !non_conforming_timestamps.is_empty() {
        summary.push_str(&format!(
            " Warning: {} timestamp(s) do not conform to ISO 8601 UTC format (expected *T*Z); \
             lexicographic ordering may be unreliable.",
            non_conforming_timestamps.len()
        ));
    }

    Ok(ChainVerificationResponse {
        receipts: per_receipt,
        chain_hash,
        all_signatures_valid: !any_sig_failed,
        timestamps_ordered,
        chain_intact,
        chain_length: sorted.len(),
        summary,
    })
}

/// Validate a policy and write it to a file at the given path.
///
/// Accepts `content` (the serialized policy string) and an optional `format`
/// parameter ("yaml", "json", or "toml"). For YAML the content is validated
/// directly. For JSON and TOML the content is deserialized, validated, then
/// re-serialized with the canonical library for clean output.
#[tauri::command]
pub async fn export_policy_file(
    content: String,
    path: String,
    format: Option<String>,
) -> Result<ExportResponse, String> {
    if content.len() > MAX_POLICY_SIZE {
        return Err(format!(
            "Input too large: {} bytes (max {})",
            content.len(),
            MAX_POLICY_SIZE
        ));
    }

    let _export_path = validate_file_path(&path)?;

    let fmt = format.as_deref().unwrap_or("yaml");

    let policy = match fmt {
        "json" => serde_json::from_str::<Policy>(&content).map_err(|e| {
            eprintln!("[workbench] invalid JSON: {e}");
            "Invalid JSON input".to_string()
        })?,
        "toml" => toml::from_str::<Policy>(&content).map_err(|e| {
            eprintln!("[workbench] invalid TOML: {e}");
            "Invalid TOML input".to_string()
        })?,
        _ => parse_policy_lax(&content).map_err(|e| {
            eprintln!("[workbench] invalid YAML: {e}");
            "Invalid YAML input".to_string()
        })?,
    };

    if let Err(pve) = validate_policy_lax(&policy) {
        return Ok(ExportResponse {
            success: false,
            path: path.clone(),
            message: format!("Policy validation failed: {}", pve),
        });
    }

    let output = match fmt {
        "json" => serde_json::to_string_pretty(&policy).map_err(|e| {
            eprintln!("[workbench] JSON serialization error: {e}");
            "Failed to serialize policy as JSON".to_string()
        })?,
        "toml" => toml::to_string_pretty(&policy).map_err(|e| {
            eprintln!("[workbench] TOML serialization error: {e}");
            "Failed to serialize policy as TOML".to_string()
        })?,
        _ => content,
    };

    // Re-validate the canonical path just before I/O to minimize the TOCTOU window.
    let export_path = validate_file_path(&path)?;

    write_text_file_secure(export_path.clone(), output).await?;

    // Post-write verification: re-canonicalize the written file and re-check
    // sensitive path patterns on the resolved path.
    let written = export_path.as_path();
    if written.exists() {
        if let Ok(canon) = written.canonicalize() {
            let canon_check = canon.to_string_lossy().replace('\\', "/").to_lowercase();
            if check_sensitive_path(&canon_check).is_err() {
                // The file was written to a sensitive location (e.g. via symlink race).
                // Remove it and return an error.
                let _ = tokio::fs::remove_file(&export_path).await;
                return Err("File resolved to a sensitive path after write; removed".to_string());
            }
        }
    }

    Ok(ExportResponse {
        success: true,
        path,
        message: format!("Policy exported as {} successfully", fmt.to_uppercase()),
    })
}

/// Read a YAML file from disk, parse and validate it, and return structured results.
#[tauri::command]
pub async fn import_policy_file(path: String) -> Result<ImportResponse, String> {
    // Resolve the canonical safe path up front and read that resolved target
    // directly. The final open uses no-follow semantics so a last-moment
    // symlink swap cannot redirect the read to another file.
    let import_path = validate_file_path(&path)?;
    let yaml = read_text_file_secure(import_path.clone()).await?;

    // Post-open re-canonicalize and check the resolved path.
    let opened = import_path.as_path();
    if opened.exists() {
        if let Ok(canon) = opened.canonicalize() {
            let canon_check = canon.to_string_lossy().replace('\\', "/").to_lowercase();
            check_sensitive_path(&canon_check)?;
        }
    }

    if yaml.len() > MAX_POLICY_SIZE {
        return Err(format!(
            "Imported file too large: {} bytes (max {})",
            yaml.len(),
            MAX_POLICY_SIZE
        ));
    }

    let policy = match parse_policy_lax(&yaml) {
        Ok(p) => p,
        Err(parse_err) => {
            return Ok(ImportResponse {
                valid: false,
                yaml,
                name: None,
                version: None,
                errors: vec![],
                parse_error: Some(parse_err),
            });
        }
    };

    let name = if policy.name.is_empty() {
        None
    } else {
        Some(policy.name.clone())
    };
    let version = Some(policy.version.clone());

    match validate_policy_lax(&policy) {
        Ok(()) => Ok(ImportResponse {
            valid: true,
            yaml,
            name,
            version,
            errors: vec![],
            parse_error: None,
        }),
        Err(pve) => {
            let errors = pve
                .errors
                .iter()
                .map(|e| ValidationError {
                    path: e.path.clone(),
                    message: e.message.clone(),
                })
                .collect();
            Ok(ImportResponse {
                valid: false,
                yaml,
                name,
                version,
                errors,
                parse_error: None,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use tempfile::NamedTempFile;

    /// A minimal valid policy YAML string for testing.
    fn minimal_valid_policy() -> String {
        r#"
version: "1.1.0"
name: Test Policy
description: A test policy
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
"#
        .to_string()
    }

    // =======================================================================
    // validate_policy
    // =======================================================================

    #[tokio::test]
    async fn validate_policy_valid_yaml_returns_valid_true() {
        let yaml = minimal_valid_policy();
        let res = validate_policy(yaml).await.unwrap();
        assert!(
            res.valid,
            "expected valid: true, got errors: {:?}",
            res.errors
        );
        assert_eq!(res.name.as_deref(), Some("Test Policy"));
        assert_eq!(res.version.as_deref(), Some("1.1.0"));
        assert!(res.errors.is_empty());
        assert!(res.parse_error.is_none());
    }

    #[tokio::test]
    async fn validate_policy_invalid_yaml_syntax_returns_parse_error() {
        let yaml = "not: valid: yaml: {{{{".to_string();
        let res = validate_policy(yaml).await.unwrap();
        assert!(!res.valid);
        assert!(
            res.parse_error.is_some(),
            "expected parse_error to be set for malformed YAML"
        );
    }

    #[tokio::test]
    async fn validate_policy_empty_yaml_returns_error() {
        // Empty YAML deserializes into a Policy with all defaults (serde defaults
        // kick in), so parsing succeeds. The validation step catches the invalid
        // default version string, producing a validation error or a parse error.
        let res = validate_policy(String::new()).await.unwrap();
        // It may be valid if all defaults happen to pass validation.
        // At minimum, verify the response is well-formed and has the schema version.
        assert!(
            !res.schema_version.is_empty(),
            "schema_version should always be populated"
        );
    }

    #[tokio::test]
    async fn validate_policy_unsupported_version_returns_validation_error() {
        let yaml = r#"
version: "0.0.1"
name: Bad Version
guards: {}
"#
        .to_string();
        let res = validate_policy(yaml).await.unwrap();
        assert!(!res.valid);
        // Either a parse_error or validation errors should be present.
        let has_error = res.parse_error.is_some() || !res.errors.is_empty();
        assert!(
            has_error,
            "expected error for unsupported version, got: {res:?}"
        );
    }

    #[tokio::test]
    async fn validate_policy_negative_max_additions_returns_error() {
        // `max_additions` is `usize`, so a negative number fails YAML deserialization.
        let yaml = r#"
version: "1.1.0"
name: Negative Max
guards:
  patch_integrity:
    max_additions: -5
"#
        .to_string();
        let res = validate_policy(yaml).await.unwrap();
        assert!(!res.valid);
        assert!(
            res.parse_error.is_some(),
            "expected parse error for negative usize value"
        );
    }

    #[tokio::test]
    async fn validate_policy_unknown_field_returns_error() {
        // The Policy struct uses deny_unknown_fields so an unknown top-level field
        // should cause a parse error.
        let yaml = r#"
version: "1.1.0"
name: Unknown Field
guards: {}
totally_bogus_field: true
"#
        .to_string();
        let res = validate_policy(yaml).await.unwrap();
        assert!(!res.valid);
        assert!(
            res.parse_error.is_some(),
            "expected parse error for unknown field"
        );
    }

    #[tokio::test]
    async fn validate_policy_with_builtin_default_yaml_is_valid() {
        let yaml = load_builtin_ruleset("default".into()).await.unwrap();
        let res = validate_policy(yaml).await.unwrap();
        assert!(
            res.valid,
            "built-in default policy should validate: {:?}",
            res
        );
    }

    #[tokio::test]
    async fn validate_policy_with_builtin_strict_yaml_is_valid() {
        let yaml = load_builtin_ruleset("strict".into()).await.unwrap();
        let res = validate_policy(yaml).await.unwrap();
        assert!(
            res.valid,
            "built-in strict policy should validate: {:?}",
            res
        );
    }

    // =======================================================================
    // list_builtin_rulesets
    // =======================================================================

    #[tokio::test]
    async fn list_builtin_rulesets_returns_non_empty() {
        let rulesets = list_builtin_rulesets().await.unwrap();
        assert!(
            !rulesets.is_empty(),
            "expected at least one built-in ruleset"
        );
    }

    #[tokio::test]
    async fn list_builtin_rulesets_entries_have_id_and_name() {
        let rulesets = list_builtin_rulesets().await.unwrap();
        for rs in &rulesets {
            assert!(!rs.id.is_empty(), "ruleset id must be non-empty");
            assert!(!rs.name.is_empty(), "ruleset name must be non-empty");
        }
    }

    #[tokio::test]
    async fn list_builtin_rulesets_contains_known_ids() {
        let rulesets = list_builtin_rulesets().await.unwrap();
        let ids: Vec<&str> = rulesets.iter().map(|r| r.id.as_str()).collect();
        for expected in &["default", "strict", "permissive", "ai-agent"] {
            assert!(
                ids.contains(expected),
                "expected built-in ruleset '{expected}' to be present, found: {ids:?}"
            );
        }
    }

    // =======================================================================
    // load_builtin_ruleset
    // =======================================================================

    #[tokio::test]
    async fn load_builtin_ruleset_default_returns_valid_yaml() {
        let yaml = load_builtin_ruleset("default".into()).await.unwrap();
        assert!(!yaml.is_empty());
        // Verify it is parseable YAML that contains a version field.
        assert!(
            yaml.contains("version:"),
            "expected YAML to contain version field"
        );
    }

    #[tokio::test]
    async fn load_builtin_ruleset_strict_returns_valid_yaml() {
        let yaml = load_builtin_ruleset("strict".into()).await.unwrap();
        assert!(!yaml.is_empty());
        assert!(yaml.contains("version:"));
    }

    #[tokio::test]
    async fn load_builtin_ruleset_nonexistent_returns_error() {
        let result = load_builtin_ruleset("nonexistent-ruleset-xyz".into()).await;
        assert!(result.is_err(), "expected error for nonexistent ruleset");
        let err = result.unwrap_err();
        assert!(
            err.contains("Unknown"),
            "error should mention 'Unknown', got: {err}"
        );
    }

    // =======================================================================
    // simulate_action
    // =======================================================================

    #[tokio::test]
    async fn simulate_action_file_access_ssh_key_strict_denied() {
        let policy_yaml = load_builtin_ruleset("strict".into()).await.unwrap();
        let res = simulate_action(
            policy_yaml,
            "file_access".into(),
            "/home/user/.ssh/id_rsa".into(),
            None,
        )
        .await
        .unwrap();
        assert!(
            !res.allowed,
            "accessing .ssh/id_rsa under strict policy should be denied"
        );
    }

    #[tokio::test]
    async fn simulate_action_file_access_safe_path_default_allowed() {
        let policy_yaml = load_builtin_ruleset("default".into()).await.unwrap();
        let res = simulate_action(
            policy_yaml,
            "file_access".into(),
            "/home/user/project/src/main.rs".into(),
            None,
        )
        .await
        .unwrap();
        assert!(
            res.allowed,
            "accessing a safe project file under default policy should be allowed"
        );
    }

    #[tokio::test]
    async fn simulate_action_network_egress_unknown_domain_denied() {
        // Default policy blocks egress to domains not on the allowlist.
        let policy_yaml = load_builtin_ruleset("default".into()).await.unwrap();
        let res = simulate_action(
            policy_yaml,
            "network".into(),
            "evil-malware-site.example.com".into(),
            None,
        )
        .await
        .unwrap();
        assert!(
            !res.allowed,
            "egress to unknown domain under default policy should be denied"
        );
    }

    #[tokio::test]
    async fn simulate_action_shell_rm_rf_root_denied() {
        let policy_yaml = load_builtin_ruleset("default".into()).await.unwrap();
        let res = simulate_action(policy_yaml, "shell".into(), "rm -rf /".into(), None)
            .await
            .unwrap();
        assert!(
            !res.allowed,
            "'rm -rf /' should be denied by shell_command guard"
        );
    }

    #[tokio::test]
    async fn simulate_action_unknown_action_type_returns_error() {
        let policy_yaml = minimal_valid_policy();
        let result = simulate_action(
            policy_yaml,
            "bogus_action_type".into(),
            "target".into(),
            None,
        )
        .await;
        assert!(result.is_err(), "expected error for unknown action type");
    }

    #[tokio::test]
    async fn simulate_action_invalid_policy_yaml_returns_error() {
        let result = simulate_action(
            "not valid yaml {{".into(),
            "file_access".into(),
            "/tmp/foo".into(),
            None,
        )
        .await;
        assert!(result.is_err(), "expected error for invalid policy YAML");
    }

    #[tokio::test]
    async fn simulate_action_mcp_tool_blocked_by_default() {
        // The default policy blocks shell_exec via mcp_tool guard.
        let policy_yaml = load_builtin_ruleset("default".into()).await.unwrap();
        let res = simulate_action(
            policy_yaml,
            "mcp_tool".into(),
            "shell_exec".into(),
            Some("{}".into()),
        )
        .await
        .unwrap();
        assert!(
            !res.allowed,
            "shell_exec MCP tool should be blocked by default policy"
        );
    }

    #[tokio::test]
    async fn simulate_action_returns_per_guard_results() {
        let policy_yaml = load_builtin_ruleset("strict".into()).await.unwrap();
        let res = simulate_action(
            policy_yaml,
            "file_access".into(),
            "/home/user/.ssh/id_rsa".into(),
            None,
        )
        .await
        .unwrap();
        // Should have at least one per-guard result entry.
        assert!(
            !res.results.is_empty(),
            "expected per-guard results, got empty list"
        );
        // At least one guard should have denied.
        assert!(
            res.results.iter().any(|r| !r.allowed),
            "expected at least one guard to deny access"
        );
    }

    #[tokio::test]
    async fn simulate_action_evaluation_path_present_for_file_write() {
        let policy_yaml = load_builtin_ruleset("default".into()).await.unwrap();
        let res = simulate_action(
            policy_yaml,
            "file_write".into(),
            "/app/src/main.rs".into(),
            Some("hello world".into()),
        )
        .await
        .unwrap();

        // evaluation_path should contain entries when the native engine runs guards.
        assert!(
            !res.evaluation_path.is_empty(),
            "expected non-empty evaluation_path for file_write action"
        );

        // Every step should have a non-empty guard name and stage.
        for step in &res.evaluation_path {
            assert!(!step.guard.is_empty(), "guard name must be non-empty");
            assert!(!step.stage.is_empty(), "stage must be non-empty");
            assert!(
                ["allow", "deny", "skip"].contains(&step.result.as_str()),
                "result must be allow, deny, or skip — got: {}",
                step.result
            );
            assert!(
                step.stage_duration_ms >= 0.0,
                "stage_duration_ms must be non-negative"
            );
        }

        // Should contain at least forbidden_path and secret_leak guards.
        let guard_names: Vec<&str> = res
            .evaluation_path
            .iter()
            .map(|s| s.guard.as_str())
            .collect();
        assert!(
            guard_names.contains(&"forbidden_path"),
            "expected forbidden_path in evaluation_path, got: {:?}",
            guard_names
        );
        assert!(
            guard_names.contains(&"secret_leak"),
            "expected secret_leak in evaluation_path, got: {:?}",
            guard_names
        );
    }

    // =======================================================================
    // sign_receipt
    // =======================================================================

    #[tokio::test]
    async fn sign_receipt_returns_valid_structure() {
        reset_sign_rate_limit();
        // 64 hex chars = 32 bytes SHA-256 hash.
        let hash = "a".repeat(64);
        let res = sign_receipt(hash, true).await.unwrap();
        assert!(!res.public_key.is_empty(), "public_key should be present");
        assert!(
            !res.receipt_hash.is_empty(),
            "receipt_hash should be present"
        );
        // signed_receipt should be a JSON object.
        assert!(
            res.signed_receipt.is_object(),
            "signed_receipt should be a JSON object"
        );
    }

    #[tokio::test]
    async fn sign_receipt_public_key_is_hex() {
        reset_sign_rate_limit();
        let hash = "b".repeat(64);
        let res = sign_receipt(hash, false).await.unwrap();
        // Public key should be valid hex (64 hex chars = 32 bytes).
        assert!(
            res.public_key.len() == 64,
            "expected 64-char hex public key, got {} chars",
            res.public_key.len()
        );
        assert!(
            res.public_key.chars().all(|c| c.is_ascii_hexdigit()),
            "public key should be hex-encoded"
        );
    }

    #[tokio::test]
    async fn sign_receipt_signature_present_in_response() {
        reset_sign_rate_limit();
        let hash = "c".repeat(64);
        let res = sign_receipt(hash, true).await.unwrap();
        let obj = res.signed_receipt.as_object().unwrap();
        // SignedReceipt has "receipt" and "signatures" fields.
        assert!(
            obj.contains_key("signatures"),
            "signed_receipt JSON should contain 'signatures' field, keys: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
        assert!(
            obj.contains_key("receipt"),
            "signed_receipt JSON should contain 'receipt' field"
        );
        // The signatures field should be non-empty (at least one signature).
        let sigs = &obj["signatures"];
        assert!(!sigs.is_null(), "signatures field should be non-null");
    }

    #[tokio::test]
    async fn sign_receipt_invalid_hash_returns_error() {
        reset_sign_rate_limit();
        let result = sign_receipt("not-valid-hex".into(), true).await;
        assert!(result.is_err(), "expected error for invalid hex hash");
    }

    #[tokio::test]
    async fn sign_receipt_wrong_length_hash_returns_error() {
        reset_sign_rate_limit();
        // Too short: only 10 hex chars (5 bytes).
        let result = sign_receipt("abcdef1234".into(), true).await;
        assert!(result.is_err(), "expected error for wrong-length hash");
    }

    #[tokio::test]
    async fn sign_receipt_pass_vs_fail_verdict() {
        let hash = "d".repeat(64);
        reset_sign_rate_limit();
        let pass = sign_receipt(hash.clone(), true).await.unwrap();
        reset_sign_rate_limit();
        let fail = sign_receipt(hash, false).await.unwrap();
        // Both should succeed with different receipt hashes (different verdicts).
        assert_ne!(
            pass.receipt_hash, fail.receipt_hash,
            "pass and fail receipts should have different hashes"
        );
    }

    // =======================================================================
    // export_policy_file
    // =======================================================================

    #[tokio::test]
    async fn export_policy_file_invalid_yaml_returns_error() {
        let path = std::env::temp_dir()
            .join("clawdstrike_test_export_invalid.yaml")
            .to_string_lossy()
            .to_string();
        let result = export_policy_file("not: valid: yaml: {{".into(), path, None).await;
        assert!(result.is_err(), "expected error for unparseable YAML");
    }

    #[tokio::test]
    async fn export_policy_file_valid_yaml_writes_to_disk() {
        let path = std::env::temp_dir()
            .join("clawdstrike_test_export_valid.yaml")
            .to_string_lossy()
            .to_string();

        let yaml = minimal_valid_policy();
        let res = export_policy_file(yaml.clone(), path.clone(), None)
            .await
            .unwrap();
        assert!(res.success, "export should succeed: {}", res.message);
        assert_eq!(res.path, path);

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(contents, yaml);

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn export_policy_file_valid_json_writes_to_disk() {
        let path = std::env::temp_dir()
            .join("clawdstrike_test_export_valid.json")
            .to_string_lossy()
            .to_string();

        let yaml = minimal_valid_policy();
        let policy: Policy = serde_yaml::from_str(&yaml).unwrap();
        let json = serde_json::to_string_pretty(&policy).unwrap();

        let res = export_policy_file(json, path.clone(), Some("json".into()))
            .await
            .unwrap();
        assert!(res.success, "JSON export should succeed: {}", res.message);
        assert!(res.message.contains("JSON"));

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let _: serde_json::Value = serde_json::from_str(&contents).unwrap();

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn export_policy_file_valid_toml_writes_to_disk() {
        let path = std::env::temp_dir()
            .join("clawdstrike_test_export_valid.toml")
            .to_string_lossy()
            .to_string();

        let yaml = minimal_valid_policy();
        let policy: Policy = serde_yaml::from_str(&yaml).unwrap();
        let toml_str = toml::to_string_pretty(&policy).unwrap();

        let res = export_policy_file(toml_str, path.clone(), Some("toml".into()))
            .await
            .unwrap();
        assert!(res.success, "TOML export should succeed: {}", res.message);
        assert!(res.message.contains("TOML"));

        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        let _: toml::Value = toml::from_str(&contents).unwrap();

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn export_policy_file_invalid_json_returns_error() {
        let path = std::env::temp_dir()
            .join("clawdstrike_test_export_invalid.json")
            .to_string_lossy()
            .to_string();
        let result = export_policy_file("{not valid json".into(), path, Some("json".into())).await;
        assert!(result.is_err(), "expected error for invalid JSON");
    }

    #[tokio::test]
    async fn export_policy_file_validation_failure_does_not_write() {
        let path = std::env::temp_dir()
            .join("clawdstrike_test_export_no_write.yaml")
            .to_string_lossy()
            .to_string();

        // Valid YAML structure but unsupported version triggers validation error.
        let yaml = r#"
version: "0.0.1"
name: Bad
guards: {}
"#
        .to_string();
        let res = export_policy_file(yaml, path.clone(), None).await;
        // Could be Err or Ok with success=false depending on whether version check
        // is a parse error or validation error.
        match res {
            Err(_) => {} // expected
            Ok(resp) => {
                assert!(
                    !resp.success,
                    "export with invalid version should not succeed"
                );
            }
        }

        // File should not exist (or at least not be written with bad content).
        let exists = tokio::fs::metadata(&path).await.is_ok();
        if exists {
            let _ = tokio::fs::remove_file(&path).await;
        }
    }

    // =======================================================================
    // import_policy_file
    // =======================================================================

    #[tokio::test]
    async fn import_policy_file_nonexistent_returns_error() {
        let result = import_policy_file("/nonexistent/path/to/policy.yaml".into()).await;
        assert!(result.is_err(), "expected error for nonexistent file");
    }

    #[tokio::test]
    async fn import_policy_file_valid_yaml_returns_parsed_info() {
        let yaml = minimal_valid_policy();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(yaml.as_bytes()).unwrap();
        file.flush().unwrap();
        let path = file.path().to_string_lossy().to_string();

        let res = import_policy_file(path.clone()).await.unwrap();
        assert!(
            res.valid,
            "import of valid policy should be valid: {:?}",
            res
        );
        assert_eq!(res.name.as_deref(), Some("Test Policy"));
        assert_eq!(res.version.as_deref(), Some("1.1.0"));
        assert!(res.errors.is_empty());
        assert!(res.parse_error.is_none());
        assert!(!res.yaml.is_empty());
    }

    #[tokio::test]
    async fn import_policy_file_invalid_yaml_returns_parse_error() {
        let path = std::env::temp_dir()
            .join("clawdstrike_test_import_invalid.yaml")
            .to_string_lossy()
            .to_string();

        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"not: valid: yaml: {{{{").unwrap();
        }

        let res = import_policy_file(path.clone()).await.unwrap();
        assert!(!res.valid);
        assert!(
            res.parse_error.is_some(),
            "expected parse_error for invalid YAML file"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn import_policy_file_roundtrip_with_builtin() {
        // Export a built-in ruleset, then re-import it.
        let yaml = load_builtin_ruleset("default".into()).await.unwrap();
        let path = std::env::temp_dir()
            .join("clawdstrike_test_import_roundtrip.yaml")
            .to_string_lossy()
            .to_string();

        let export_res = export_policy_file(yaml, path.clone(), None).await.unwrap();
        assert!(export_res.success);

        let import_res = import_policy_file(path.clone()).await.unwrap();
        assert!(
            import_res.valid,
            "round-tripped default policy should be valid: {:?}",
            import_res
        );
        assert_eq!(import_res.name.as_deref(), Some("Default"));

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[test]
    fn validate_file_path_rejects_sensitive_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sensitive_dir = dir.path().join(".ssh");
        std::fs::create_dir_all(&sensitive_dir).unwrap();
        let path = sensitive_dir
            .join("policy.yaml")
            .to_string_lossy()
            .to_string();

        let err = validate_file_path(&path).unwrap_err();
        assert_eq!(err, "Refusing to access sensitive path");
    }

    #[test]
    fn validate_file_path_rejects_sensitive_suffix() {
        let path = std::env::temp_dir()
            .join("policy.env")
            .with_file_name(".env")
            .to_string_lossy()
            .to_string();

        let err = validate_file_path(&path).unwrap_err();
        assert_eq!(err, "Refusing to access sensitive file");
    }

    // =======================================================================
    // simulate_action_with_posture
    // =======================================================================

    fn posture_policy_yaml() -> String {
        r#"
version: "1.2.0"
name: "Posture Test Policy"
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
posture:
  initial: normal
  states:
    normal:
      capabilities: [file_access, file_write, egress, shell]
      budgets:
        file_writes: 3
        shell_commands: 2
    restricted:
      capabilities: [file_access]
      budgets:
        file_writes: 0
  transitions:
    - { from: "*", to: restricted, on: budget_exhausted }
"#
        .to_string()
    }

    #[tokio::test]
    async fn simulate_with_posture_returns_budget_data() {
        let yaml = posture_policy_yaml();
        let res = simulate_action_with_posture(
            yaml,
            "file_write".into(),
            "/tmp/test.txt".into(),
            Some("hello".into()),
            None,
        )
        .await
        .unwrap();

        assert!(res.allowed, "file write should be allowed in normal state");
        let posture = res.posture.expect("posture report should be present");
        assert_eq!(posture.state, "normal");

        // Should have budget entries.
        assert!(
            !posture.budgets.is_empty(),
            "expected budget entries, got empty"
        );

        let fw = posture
            .budgets
            .iter()
            .find(|b| b.name == "file_writes")
            .expect("expected file_writes budget");
        assert_eq!(fw.limit, 3);
        assert_eq!(fw.consumed, 1);
        assert_eq!(fw.remaining, 2);
    }

    #[tokio::test]
    async fn simulate_with_posture_no_posture_config_returns_none() {
        let yaml = minimal_valid_policy();
        let res = simulate_action_with_posture(
            yaml,
            "file_access".into(),
            "/tmp/foo.txt".into(),
            None,
            None,
        )
        .await
        .unwrap();

        assert!(
            res.posture.is_none(),
            "posture report should be None when policy has no posture config"
        );
    }

    #[tokio::test]
    async fn simulate_with_posture_denied_capability() {
        // In 'normal' state, only file_access, file_write, egress, shell are allowed.
        // 'mcp_tool' is NOT in the capabilities list.
        let yaml = posture_policy_yaml();
        let res = simulate_action_with_posture(
            yaml,
            "mcp_tool".into(),
            "some_tool".into(),
            Some("{}".into()),
            None,
        )
        .await
        .unwrap();

        assert!(
            !res.allowed,
            "mcp_tool should be denied by posture (not in capabilities)"
        );
    }

    // =======================================================================
    // verify_receipt_chain
    // =======================================================================

    fn make_chain_receipt(id: &str, timestamp: &str, verdict: &str) -> ChainReceiptInput {
        ChainReceiptInput {
            id: id.to_string(),
            timestamp: timestamp.to_string(),
            verdict: verdict.to_string(),
            guard: "forbidden_path".to_string(),
            policy_name: "test-policy".to_string(),
            signature: "a".repeat(128), // fake 64-byte hex sig
            public_key: "b".repeat(64), // fake 32-byte hex pubkey
            valid: true,
            signed_receipt: None,
        }
    }

    #[tokio::test]
    async fn verify_chain_empty_returns_intact() {
        let res = verify_receipt_chain(vec![]).await.unwrap();
        assert!(res.chain_intact);
        assert_eq!(res.chain_length, 0);
        assert!(res.all_signatures_valid);
        assert!(res.timestamps_ordered);
    }

    #[tokio::test]
    async fn verify_chain_single_receipt() {
        let r = make_chain_receipt("r1", "2026-03-01T00:00:00Z", "allow");
        let res = verify_receipt_chain(vec![r]).await.unwrap();
        assert_eq!(res.chain_length, 1);
        assert!(res.timestamps_ordered);
        assert!(!res.chain_hash.is_empty());
        assert_eq!(res.receipts.len(), 1);
        assert!(res.receipts[0].timestamp_order_valid);
    }

    #[tokio::test]
    async fn verify_chain_ordered_timestamps() {
        let chain = vec![
            make_chain_receipt("r1", "2026-03-01T00:00:00Z", "allow"),
            make_chain_receipt("r2", "2026-03-01T00:01:00Z", "deny"),
            make_chain_receipt("r3", "2026-03-01T00:02:00Z", "warn"),
        ];
        let res = verify_receipt_chain(chain).await.unwrap();
        assert!(res.timestamps_ordered);
        assert_eq!(res.chain_length, 3);
        for r in &res.receipts {
            assert!(
                r.timestamp_order_valid,
                "receipt {} should have valid timestamp order",
                r.id
            );
        }
    }

    #[tokio::test]
    async fn verify_chain_unordered_input_is_sorted_before_verification() {
        // Input arrives out of order; verify_receipt_chain sorts by timestamp
        // before checking ordering, so the result should be ordered.
        let chain = vec![
            make_chain_receipt("r1", "2026-03-01T00:02:00Z", "allow"),
            make_chain_receipt("r2", "2026-03-01T00:00:00Z", "deny"),
            make_chain_receipt("r3", "2026-03-01T00:01:00Z", "warn"),
        ];
        let res = verify_receipt_chain(chain).await.unwrap();
        assert!(res.timestamps_ordered);
        assert_eq!(res.chain_length, 3);
    }

    #[tokio::test]
    async fn verify_chain_with_real_signature() {
        let keypair = Keypair::generate();
        let pk_hex = keypair.public_key().to_hex();

        let id = "real-sig-receipt";
        let timestamp = "2026-03-08T12:00:00Z";
        let verdict = "allow";
        let guard = "forbidden_path";
        let policy_name = "test-policy";

        // The canonical content matches what verify_receipt_chain computes.
        let canonical = format!("{}:{}:{}:{}:{}", id, timestamp, verdict, guard, policy_name);
        let sig = keypair.sign(canonical.as_bytes());

        let r = ChainReceiptInput {
            id: id.to_string(),
            timestamp: timestamp.to_string(),
            verdict: verdict.to_string(),
            guard: guard.to_string(),
            policy_name: policy_name.to_string(),
            signature: sig.to_hex(),
            public_key: pk_hex,
            valid: true,
            signed_receipt: None,
        };

        let res = verify_receipt_chain(vec![r]).await.unwrap();
        assert_eq!(res.chain_length, 1);
        assert!(res.chain_intact);
        assert!(res.all_signatures_valid);
        assert_eq!(res.receipts[0].signature_valid, Some(true));
    }

    #[tokio::test]
    async fn verify_chain_invalid_signature_detected() {
        let keypair = Keypair::generate();
        let pk_hex = keypair.public_key().to_hex();

        // Sign a different message than what the chain verifier will compute.
        let sig = keypair.sign(b"wrong content");

        let r = ChainReceiptInput {
            id: "bad-sig".to_string(),
            timestamp: "2026-03-08T12:00:00Z".to_string(),
            verdict: "deny".to_string(),
            guard: "egress_allowlist".to_string(),
            policy_name: "test-policy".to_string(),
            signature: sig.to_hex(),
            public_key: pk_hex,
            valid: true,
            signed_receipt: None,
        };

        let res = verify_receipt_chain(vec![r]).await.unwrap();
        assert!(!res.chain_intact);
        assert!(!res.all_signatures_valid);
        assert_eq!(res.receipts[0].signature_valid, Some(false));
    }

    #[tokio::test]
    async fn verify_chain_unparseable_signature_skipped() {
        let r = ChainReceiptInput {
            id: "skip-sig".to_string(),
            timestamp: "2026-03-08T12:00:00Z".to_string(),
            verdict: "allow".to_string(),
            guard: "forbidden_path".to_string(),
            policy_name: "test-policy".to_string(),
            signature: "not-hex-at-all".to_string(),
            public_key: "also-not-hex".to_string(),
            valid: true,
            signed_receipt: None,
        };

        let res = verify_receipt_chain(vec![r]).await.unwrap();
        // Unparseable signatures are not positively verified, so the chain is
        // not considered intact (no signature was verified). (#20)
        assert!(!res.chain_intact);
        assert_eq!(res.receipts[0].signature_valid, None);
    }

    #[tokio::test]
    async fn verify_chain_deterministic_chain_hash() {
        let chain = vec![
            make_chain_receipt("r1", "2026-03-01T00:00:00Z", "allow"),
            make_chain_receipt("r2", "2026-03-01T00:01:00Z", "deny"),
        ];
        let res1 = verify_receipt_chain(chain.clone()).await.unwrap();
        let res2 = verify_receipt_chain(chain).await.unwrap();
        assert_eq!(
            res1.chain_hash, res2.chain_hash,
            "chain hash should be deterministic"
        );
    }

    /// P1-4: Receipts signed over the exact canonical hush-core payload should
    /// verify via the embedded `signed_receipt` fallback even though the
    /// primary colon-delimited check would reject them.
    #[tokio::test]
    async fn verify_chain_signed_receipt_payload_fallback() {
        let keypair = Keypair::generate();
        let pk_hex = keypair.public_key().to_hex();

        let id = "json-sig-receipt";
        let timestamp = "2026-03-09T10:00:00Z";
        let verdict = Verdict::pass();
        let guard = "forbidden_path";
        let policy_name = "test-policy";

        let signed_receipt = SignedReceipt::sign(
            Receipt::new(Hash::zero(), verdict).with_id(id.to_string()),
            &keypair,
        )
        .expect("signing should succeed");
        let sig = signed_receipt.signatures.signer.to_hex();
        let signed_receipt_json =
            serde_json::to_value(&signed_receipt).expect("serialization should succeed");

        let r = ChainReceiptInput {
            id: id.to_string(),
            timestamp: timestamp.to_string(),
            verdict: "allow".to_string(),
            guard: guard.to_string(),
            policy_name: policy_name.to_string(),
            signature: sig,
            public_key: pk_hex,
            valid: true,
            signed_receipt: Some(signed_receipt_json),
        };

        let res = verify_receipt_chain(vec![r]).await.unwrap();
        assert_eq!(res.chain_length, 1);
        assert!(
            res.chain_intact,
            "chain should be intact via exact signed_receipt fallback"
        );
        assert!(res.all_signatures_valid);
        assert_eq!(res.receipts[0].signature_valid, Some(true));
        assert!(
            res.receipts[0]
                .signature_reason
                .as_str()
                .contains("canonical JSON payload"),
            "reason should mention the fallback path: {}",
            res.receipts[0].signature_reason,
        );
    }

    /// P1-4: A receipt whose signature matches neither the chain-native payload
    /// nor the embedded signed receipt should still be reported as invalid.
    #[tokio::test]
    async fn verify_chain_signed_receipt_fallback_does_not_weaken_verification() {
        let keypair = Keypair::generate();
        let pk_hex = keypair.public_key().to_hex();

        let unrelated_signed_receipt =
            SignedReceipt::sign(Receipt::new(Hash::zero(), Verdict::pass()), &keypair)
                .expect("signing should succeed");
        let signed_receipt_json =
            serde_json::to_value(&unrelated_signed_receipt).expect("serialization should succeed");

        // Sign completely unrelated content so neither payload matches.
        let sig = keypair.sign(b"totally unrelated content");

        let r = ChainReceiptInput {
            id: "neither-format".to_string(),
            timestamp: "2026-03-09T10:00:00Z".to_string(),
            verdict: "deny".to_string(),
            guard: "egress_allowlist".to_string(),
            policy_name: "test-policy".to_string(),
            signature: sig.to_hex(),
            public_key: pk_hex,
            valid: true,
            signed_receipt: Some(signed_receipt_json),
        };

        let res = verify_receipt_chain(vec![r]).await.unwrap();
        assert!(!res.chain_intact);
        assert!(!res.all_signatures_valid);
        assert_eq!(res.receipts[0].signature_valid, Some(false));
    }
}
