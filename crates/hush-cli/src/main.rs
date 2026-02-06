#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! Hush CLI - Command-line interface for clawdstrike
//!
//! Commands:
//! - `hush check <action>` - Check an action against policy
//! - `hush verify <receipt>` - Verify a signed receipt
//! - `hush keygen` - Generate a signing keypair
//! - `hush hash <file>` - Compute hash of a file (SHA-256/Keccak-256)
//! - `hush sign --key <key> <file>` - Sign a file
//! - `hush merkle root|proof|verify` - Merkle tree operations
//! - `hush policy show` - Show current policy
//! - `hush policy validate <file>` - Validate a policy file
//! - `hush policy diff <left> <right>` - Diff two policies (rulesets or files)
//! - `hush policy eval <policyRef> <eventPath|->` - Evaluate a PolicyEvent JSON against a policy
//! - `hush policy simulate <policyRef> <eventsJsonlPath|->` - Evaluate a JSONL stream of PolicyEvents
//! - `hush policy lint <policyRef>` - Lint a policy (warnings)
//! - `hush policy test <testYaml>` - Run policy tests from YAML
//! - `hush policy impact <old> <new> <eventsJsonlPath|->` - Compare decisions across policies
//! - `hush policy observe [--out <events.jsonl>] -- <cmd ...>` - Run a command and record PolicyEvent JSONL
//! - `hush policy synth <events.jsonl> [--out <candidate.yaml>]` - Synthesize a least-privilege policy candidate
//! - `hush policy migrate <input> --to 1.2.0 [--output <path>|--in-place] [--from <ver>|--legacy-openclaw]` - Migrate a policy to a supported schema version
//! - `hush policy version <policyRef>` - Show policy schema version compatibility
//! - `hush run --policy <ref|file> -- <cmd> <args…>` - Best-effort process wrapper (proxy + audit log + receipt)
//! - `hush daemon start|stop|status|reload` - Daemon management

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::generate;
use rand::Rng;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clawdstrike::{GuardContext, GuardResult, HushEngine, Policy, RuleSet, Severity};
use hush_core::{keccak256, sha256, Hash, Keypair, MerkleProof, MerkleTree, SignedReceipt};

mod canonical_commandline;
mod guard_report_json;
mod hush_run;
mod policy_bundle;
mod policy_diff;
mod policy_event;
mod policy_impact;
mod policy_lint;
mod policy_migrate;
mod policy_observe;
mod policy_pac;
mod policy_rego;
mod policy_synth;
mod policy_test;
mod policy_version;
mod remote_extends;

const CLI_JSON_VERSION: u8 = 1;

/// Stable exit codes for `hush` commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
enum ExitCode {
    /// Operation succeeded, with no warnings.
    Ok = 0,
    /// Operation succeeded, but produced warnings (e.g. a guard returned `warn`).
    Warn = 1,
    /// Operation failed due to a policy failure or negative verdict (blocked / FAIL).
    Fail = 2,
    /// Configuration error (invalid policy, unknown ruleset, invalid inputs).
    ConfigError = 3,
    /// Runtime error (I/O, internal errors).
    RuntimeError = 4,
    /// CLI usage error (invalid arguments).
    InvalidArgs = 5,
}

impl ExitCode {
    fn as_i32(self) -> i32 {
        self as i32
    }
}

struct CheckArgs {
    action_type: String,
    target: String,
    json: bool,
    policy: Option<String>,
    ruleset: Option<String>,
}

#[derive(Parser, Debug)]
#[command(name = "hush")]
#[command(version, about = "Clawdstrike security guard CLI", long_about = None)]
struct Cli {
    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Allow remote policy extends from this host (repeatable). Remote extends require `#sha256=<HEX>` pins.
    #[arg(long = "remote-extends-allow-host")]
    remote_extends_allow_host: Vec<String>,

    /// Cache directory for remote policy extends.
    #[arg(long = "remote-extends-cache-dir")]
    remote_extends_cache_dir: Option<PathBuf>,

    /// Maximum bytes to fetch for a single remote policy (default: 1 MiB).
    #[arg(long = "remote-extends-max-fetch-bytes", default_value_t = 1_048_576)]
    remote_extends_max_fetch_bytes: usize,

    /// Maximum total bytes for the remote policy cache (default: 100 MB).
    #[arg(long = "remote-extends-max-cache-bytes", default_value_t = 100_000_000)]
    remote_extends_max_cache_bytes: usize,

    /// Allow http:// URLs for remote extends (INSECURE; prefer HTTPS).
    #[arg(long = "remote-extends-allow-http")]
    remote_extends_allow_http: bool,

    /// Allow resolving remote extends to private/loopback/link-local IPs (INSECURE).
    #[arg(long = "remote-extends-allow-private-ips")]
    remote_extends_allow_private_ips: bool,

    /// Allow redirects to a different host for remote extends (INSECURE).
    #[arg(long = "remote-extends-allow-cross-host-redirects")]
    remote_extends_allow_cross_host_redirects: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Check an action against policy
    Check {
        /// Action type (file, egress, mcp)
        #[arg(short, long)]
        action_type: String,

        /// Target (path, host, tool name)
        target: String,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,

        /// Policy YAML file to use (supports `extends`)
        #[arg(long)]
        policy: Option<String>,

        /// Ruleset to use
        #[arg(short, long)]
        ruleset: Option<String>,
    },

    /// Best-effort process wrapper (audit log + optional proxy/sandbox + receipt)
    Run {
        /// Policy reference (ruleset id like `default`/`clawdstrike:default`, or a YAML file path)
        #[arg(long)]
        policy: String,

        /// Output path for PolicyEvent JSONL (default: hush.events.jsonl)
        #[arg(long, default_value = "hush.events.jsonl")]
        events_out: String,

        /// Output path for the signed receipt (default: hush.run.receipt.json)
        #[arg(long, default_value = "hush.run.receipt.json")]
        receipt_out: String,

        /// Signing key path (hex-encoded Ed25519 seed). If missing, a new keypair is generated.
        #[arg(long, default_value = "hush.key")]
        signing_key: String,

        /// Disable the local CONNECT proxy (egress enforcement becomes audit-only/best-effort).
        #[arg(long)]
        no_proxy: bool,

        /// Proxy listen port (0 = random free port)
        #[arg(long, default_value_t = 0)]
        proxy_port: u16,

        /// Enable best-effort OS sandbox wrapper (macOS: sandbox-exec; Linux: bwrap when available)
        #[arg(long)]
        sandbox: bool,

        /// Optional hushd URL to forward events for centralized audit (best-effort)
        #[arg(long)]
        hushd_url: Option<String>,

        /// Bearer token for daemon (if omitted, uses CLAWDSTRIKE_ADMIN_KEY or CLAWDSTRIKE_API_KEY env vars)
        #[arg(long)]
        hushd_token: Option<String>,

        /// Command to run (use `--` before the command if it contains flags)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Verify a signed receipt
    Verify {
        /// Path to receipt JSON file
        receipt: String,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,

        /// Path to public key file
        #[arg(short, long)]
        pubkey: String,
    },

    /// Generate a signing keypair
    Keygen {
        /// Output path for private key
        #[arg(short, long, alias = "out", default_value = "hush.key")]
        output: String,

        /// Store the Ed25519 seed sealed in TPM2 (writes a `.keyblob` JSON file).
        ///
        /// This requires `tpm2-tools` (`tpm2_createprimary`, `tpm2_create`, `tpm2_load`, `tpm2_unseal`).
        #[arg(long)]
        tpm_seal: bool,
    },

    /// Policy commands
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Daemon management commands
    Daemon {
        #[command(subcommand)]
        command: DaemonCommands,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, powershell, elvish)
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Compute hash of a file or stdin
    Hash {
        /// File to hash (use - for stdin)
        file: String,

        /// Hash algorithm (sha256 or keccak256)
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,

        /// Output format (hex or base64)
        #[arg(short, long, default_value = "hex")]
        format: String,
    },

    /// Sign a file with a private key
    Sign {
        /// Path to private key file
        #[arg(short, long)]
        key: String,

        /// File to sign
        file: String,

        /// Verify signature after signing
        #[arg(long)]
        verify: bool,

        /// Output file for signature (defaults to stdout)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Merkle tree operations
    Merkle {
        #[command(subcommand)]
        command: MerkleCommands,
    },
}

#[derive(Subcommand, Debug)]
enum MerkleCommands {
    /// Compute Merkle root of files
    Root {
        /// Files to include in the tree
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// Generate inclusion proof for a file
    Proof {
        /// Index of the leaf to prove (0-indexed)
        #[arg(short, long)]
        index: usize,

        /// Files to include in the tree
        #[arg(required = true)]
        files: Vec<String>,
    },

    /// Verify an inclusion proof
    Verify {
        /// Expected Merkle root (hex)
        #[arg(long)]
        root: String,

        /// Leaf file to verify
        #[arg(long)]
        leaf: String,

        /// Path to proof JSON file
        #[arg(long)]
        proof: String,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Show a ruleset's policy
    Show {
        /// Ruleset name or file path
        #[arg(default_value = "default")]
        ruleset: String,
        /// Show merged policy (resolve extends)
        #[arg(long)]
        merged: bool,
    },

    /// Validate a policy file
    Validate {
        /// Path to policy YAML file
        file: String,
        /// Resolve extends and show merged policy
        #[arg(long)]
        resolve: bool,
        /// Also require referenced environment variables to be set for `${VAR}` placeholders.
        #[arg(long)]
        check_env: bool,
    },

    /// Diff two policies (rulesets or files)
    Diff {
        /// Left policy (ruleset id or file path)
        left: String,
        /// Right policy (ruleset id or file path)
        right: String,
        /// Resolve extends before diffing
        #[arg(long)]
        resolve: bool,
        /// Emit machine-readable JSON (array of diff entries)
        #[arg(long)]
        json: bool,
    },

    /// List available rulesets
    List,

    /// Lint a policy for common issues and risky defaults
    Lint {
        /// Policy reference (ruleset name or file path)
        policy_ref: String,
        /// Resolve extends before linting
        #[arg(long)]
        resolve: bool,
        /// Treat warnings as errors
        #[arg(long)]
        strict: bool,
        /// Emit machine-readable JSON.
        #[arg(long, conflicts_with = "sarif")]
        json: bool,
        /// Emit machine-readable SARIF 2.1.0 JSON.
        #[arg(long, conflicts_with = "json")]
        sarif: bool,
    },

    /// Run a policy test suite (YAML)
    Test {
        /// Path to a policy test YAML file
        test_file: String,
        /// Resolve extends in the referenced policy
        #[arg(long)]
        resolve: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Emit guard coverage counts
        #[arg(long)]
        coverage: bool,
    },

    /// Impact analysis: compare two policies over a stream of PolicyEvents
    Impact {
        /// Old policy (ruleset id or file path)
        old_policy: String,
        /// New policy (ruleset id or file path)
        new_policy: String,
        /// Path to PolicyEvent JSONL (use - for stdin)
        events: String,
        /// Resolve extends before evaluation
        #[arg(long)]
        resolve: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Exit non-zero if any allow->block transitions are observed
        #[arg(long)]
        fail_on_breaking: bool,
    },

    /// Show policy schema version compatibility
    Version {
        /// Policy reference (ruleset name or file path)
        policy_ref: String,
        /// Resolve extends before printing version info
        #[arg(long)]
        resolve: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Migrate a policy to a supported schema version
    Migrate {
        /// Input policy YAML path (use - for stdin)
        input: String,

        /// Target schema version (default: 1.2.0)
        #[arg(long, default_value = "1.2.0")]
        to: String,

        /// Source schema version (e.g., 1.0.0). If omitted, uses best-effort detection.
        #[arg(long)]
        from: Option<String>,

        /// Treat input as legacy OpenClaw policy (clawdstrike-v1.0) and translate to canonical schema.
        #[arg(long, conflicts_with = "from")]
        legacy_openclaw: bool,

        /// Output path for migrated YAML (default: stdout, unless --json is used).
        #[arg(short, long, conflicts_with = "in_place")]
        output: Option<String>,

        /// Overwrite the input file in-place (refuses stdin)
        #[arg(long, conflicts_with = "output")]
        in_place: bool,

        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,

        /// Validate and report, but do not write files.
        #[arg(long)]
        dry_run: bool,
    },

    /// Build/verify signed policy bundles
    Bundle {
        #[command(subcommand)]
        command: PolicyBundleCommands,
    },

    /// Rego/OPA policy tooling (not yet implemented)
    Rego {
        #[command(subcommand)]
        command: RegoCommands,
    },

    /// Evaluate a canonical PolicyEvent JSON against a policy
    Eval {
        /// Policy reference (ruleset name or file path)
        policy_ref: String,
        /// Path to PolicyEvent JSON (use - for stdin)
        event: String,
        /// Resolve extends before evaluation
        #[arg(long)]
        resolve: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Simulate canonical PolicyEvent JSONL against a policy
    Simulate {
        /// Policy reference (ruleset name or file path)
        policy_ref: String,
        /// Path to PolicyEvent JSONL (use - for stdin). If omitted and stdin is a TTY, runs interactively.
        events: Option<String>,
        /// Resolve extends before evaluation
        #[arg(long)]
        resolve: bool,
        /// Emit machine-readable JSON.
        #[arg(long, conflicts_with = "jsonl")]
        json: bool,
        /// Emit one JSON object per event (JSONL).
        #[arg(long, conflicts_with = "json")]
        jsonl: bool,
        /// Only emit the summary (JSON output uses an empty `results` array).
        #[arg(long)]
        summary: bool,
        /// Exit non-zero if any event is blocked.
        #[arg(long)]
        fail_on_deny: bool,
        /// Do not fail the command if any event is blocked.
        #[arg(long, conflicts_with = "fail_on_deny")]
        no_fail_on_deny: bool,
        /// Print throughput/latency metrics to stderr.
        #[arg(long)]
        benchmark: bool,

        /// Track posture state across events while simulating.
        #[arg(long)]
        track_posture: bool,
    },

    /// Observe runtime activity and write canonical PolicyEvent JSONL
    Observe {
        /// Policy reference used for local command observation.
        #[arg(long, default_value = "clawdstrike:permissive")]
        policy: String,
        /// Output JSONL path.
        #[arg(long, default_value = "hush.events.jsonl")]
        out: String,
        /// Observe an existing hushd session instead of running a local command.
        #[arg(long)]
        hushd_url: Option<String>,
        /// Bearer token for authenticated hushd audit exports.
        #[arg(long)]
        hushd_token: Option<String>,
        /// Session ID for hushd observation mode.
        #[arg(long)]
        session: Option<String>,
        /// Command to run for local observation mode.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Synthesize a least-privilege policy candidate from observed events
    Synth {
        /// Input PolicyEvent JSONL file.
        events: String,
        /// Optional base policy reference to extend.
        #[arg(long)]
        extends: Option<String>,
        /// Output synthesized policy YAML path.
        #[arg(long, default_value = "candidate.yaml")]
        out: String,
        /// Optional JSON diff output path (requires --extends).
        #[arg(long)]
        diff_out: Option<String>,
        /// Output markdown risk report path.
        #[arg(long, default_value = "candidate.risks.md")]
        risk_out: String,
        /// Include a generated posture block.
        #[arg(long)]
        with_posture: bool,
        /// Emit machine-readable JSON summary.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RegoCommands {
    /// Compile a .rego policy into a bundle (stub)
    Compile {
        /// Path to .rego file
        file: String,
    },
    /// Evaluate a .rego policy against an input JSON (stub)
    Eval {
        /// Path to .rego file
        file: String,
        /// Input JSON path (use - for stdin)
        input: String,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyBundleCommands {
    /// Build a signed policy bundle (JSON) from a policy reference
    Build {
        /// Policy reference (ruleset name or file path)
        policy_ref: String,
        /// Resolve extends before bundling
        #[arg(long)]
        resolve: bool,
        /// Signing private key file (hex seed, 32 bytes)
        #[arg(long)]
        key: String,
        /// Output path for the bundle JSON
        #[arg(short, long, default_value = "policy.bundle.json")]
        output: String,
        /// Include the signing public key in the bundle
        #[arg(long)]
        embed_pubkey: bool,
        /// Additional source strings to include (repeatable)
        #[arg(long)]
        source: Vec<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Verify a signed policy bundle (JSON)
    Verify {
        /// Bundle JSON path
        bundle: String,
        /// Public key file (hex). If omitted, uses embedded public_key.
        #[arg(long)]
        pubkey: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum DaemonCommands {
    /// Start the daemon
    Start {
        /// Configuration file
        #[arg(short, long)]
        config: Option<String>,
        /// Bind address
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
        /// Port
        #[arg(short, long, default_value = "9876")]
        port: u16,
    },
    /// Stop the daemon
    Stop {
        /// Daemon URL
        #[arg(default_value = "http://127.0.0.1:9876")]
        url: String,

        /// Bearer token for authenticated daemons (if omitted, uses CLAWDSTRIKE_ADMIN_KEY or CLAWDSTRIKE_API_KEY env vars)
        #[arg(long)]
        token: Option<String>,
    },
    /// Show daemon status
    Status {
        /// Daemon URL
        #[arg(default_value = "http://127.0.0.1:9876")]
        url: String,
    },
    /// Reload daemon policy
    Reload {
        /// Daemon URL
        #[arg(default_value = "http://127.0.0.1:9876")]
        url: String,

        /// Bearer token for authenticated daemons (if omitted, uses CLAWDSTRIKE_ADMIN_KEY or CLAWDSTRIKE_API_KEY env vars)
        #[arg(long)]
        token: Option<String>,
    },
    /// Generate a new API key for the daemon
    Keygen {
        /// Name for the key
        #[arg(long)]
        name: String,

        /// Scopes (comma-separated: check,read,admin,*)
        #[arg(long, default_value = "check,read")]
        scopes: String,

        /// Expiration in days (0 = never expires)
        #[arg(long, default_value = "0")]
        expires_days: u64,
    },
}

#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let code = match err.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    ExitCode::Ok
                }
                _ => ExitCode::InvalidArgs,
            };

            let _ = err.print();
            std::process::exit(code.as_i32());
        }
    };

    // Initialize logging
    let log_level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    tracing_subscriber::registry()
        // Keep stdout clean for machine-readable output (`--json`, `--jsonl`).
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            log_level,
        ))
        .init();

    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let code = run(cli, &mut stdout, &mut stderr).await;
    std::process::exit(code);
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum PolicySource {
    Ruleset { name: String },
    PolicyFile { path: String },
}

#[derive(Clone, Debug, serde::Serialize)]
struct CliJsonError {
    kind: &'static str,
    message: String,
}

#[derive(Clone, Debug, serde::Serialize)]
struct CheckJsonOutput {
    version: u8,
    command: &'static str,
    action_type: String,
    target: String,
    policy: PolicySource,
    outcome: &'static str,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<GuardResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CliJsonError>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct ReceiptSummary {
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_id: Option<String>,
    timestamp: String,
    content_hash: Hash,
    verdict_passed: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
struct VerifyJsonOutput {
    version: u8,
    command: &'static str,
    receipt: String,
    pubkey: String,
    outcome: &'static str,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<hush_core::receipt::VerificationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_summary: Option<ReceiptSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CliJsonError>,
}

async fn run(cli: Cli, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let Cli {
        remote_extends_allow_host,
        remote_extends_cache_dir,
        remote_extends_max_fetch_bytes,
        remote_extends_max_cache_bytes,
        remote_extends_allow_http,
        remote_extends_allow_private_ips,
        remote_extends_allow_cross_host_redirects,
        command,
        ..
    } = cli;

    let mut remote_extends = remote_extends::RemoteExtendsConfig::new(remote_extends_allow_host)
        .with_limits(
            remote_extends_max_fetch_bytes,
            remote_extends_max_cache_bytes,
        )
        .with_https_only(!remote_extends_allow_http)
        .with_allow_private_ips(remote_extends_allow_private_ips)
        .with_allow_cross_host_redirects(remote_extends_allow_cross_host_redirects);
    if let Some(dir) = remote_extends_cache_dir {
        remote_extends = remote_extends.with_cache_dir(dir);
    }

    match command {
        Commands::Check {
            action_type,
            target,
            json,
            policy,
            ruleset,
        } => cmd_check(
            CheckArgs {
                action_type,
                target,
                json,
                policy,
                ruleset,
            },
            &remote_extends,
            stdout,
            stderr,
        )
        .await
        .as_i32(),

        Commands::Run {
            policy,
            events_out,
            receipt_out,
            signing_key,
            no_proxy,
            proxy_port,
            sandbox,
            hushd_url,
            hushd_token,
            command,
        } => {
            hush_run::cmd_run(
                hush_run::RunArgs {
                    policy,
                    events_out,
                    receipt_out,
                    signing_key,
                    no_proxy,
                    proxy_port,
                    sandbox,
                    hushd_url,
                    hushd_token,
                    command,
                },
                &remote_extends,
                stdout,
                stderr,
            )
            .await
        }

        Commands::Verify {
            receipt,
            json,
            pubkey,
        } => cmd_verify(receipt, pubkey, json, stdout, stderr).as_i32(),

        Commands::Keygen { output, tpm_seal } => match cmd_keygen(&output, tpm_seal) {
            Ok(out) => {
                let _ = writeln!(stdout, "Generated keypair:");
                let _ = writeln!(stdout, "  {}: {}", out.private_label, out.private_path);
                let _ = writeln!(stdout, "  Public key:  {}", out.public_path);
                let _ = writeln!(stdout, "  Public key (hex): {}", out.public_hex);
                ExitCode::Ok.as_i32()
            }
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                ExitCode::RuntimeError.as_i32()
            }
        },

        Commands::Policy { command } => {
            match cmd_policy(command, &remote_extends, stdout, stderr).await {
                Ok(code) => code.as_i32(),
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {}", e);
                    ExitCode::RuntimeError.as_i32()
                }
            }
        }

        Commands::Daemon { command } => cmd_daemon(command, stdout, stderr).as_i32(),

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "hush", &mut std::io::stdout());
            ExitCode::Ok.as_i32()
        }

        Commands::Hash {
            file,
            algorithm,
            format,
        } => match cmd_hash(&file, &algorithm, &format) {
            Ok(output) => {
                let _ = writeln!(stdout, "{}", output);
                ExitCode::Ok.as_i32()
            }
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                ExitCode::InvalidArgs.as_i32()
            }
        },

        Commands::Sign {
            key,
            file,
            verify,
            output,
        } => cmd_sign(&key, &file, verify, output.as_deref(), stdout, stderr).as_i32(),

        Commands::Merkle { command } => match cmd_merkle(command, stdout, stderr) {
            Ok(code) => code.as_i32(),
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                ExitCode::RuntimeError.as_i32()
            }
        },
    }
}

fn guard_result_exit_code(result: &GuardResult) -> ExitCode {
    if !result.allowed {
        return ExitCode::Fail;
    }

    match result.severity {
        Severity::Warning => ExitCode::Warn,
        _ => ExitCode::Ok,
    }
}

async fn cmd_check(
    args: CheckArgs,
    remote_extends: &remote_extends::RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let CheckArgs {
        action_type,
        target,
        json,
        policy,
        ruleset,
    } = args;

    let resolver = match remote_extends::RemotePolicyResolver::new(remote_extends.clone()) {
        Ok(r) => r,
        Err(e) => {
            return emit_check_error(
                CheckErrorOutput {
                    json,
                    action_type: &action_type,
                    target: &target,
                    stdout,
                    stderr,
                },
                PolicySource::Ruleset {
                    name: ruleset.unwrap_or_else(|| "default".to_string()),
                },
                ExitCode::ConfigError,
                "config_error",
                &format!("Failed to initialize remote extends resolver: {}", e),
            );
        }
    };

    let (engine, policy_source) = if let Some(policy_path) = policy {
        let content = match std::fs::read_to_string(&policy_path) {
            Ok(c) => c,
            Err(e) => {
                return emit_check_error(
                    CheckErrorOutput {
                        json,
                        action_type: &action_type,
                        target: &target,
                        stdout,
                        stderr,
                    },
                    PolicySource::PolicyFile {
                        path: policy_path.clone(),
                    },
                    ExitCode::RuntimeError,
                    "runtime_error",
                    &format!("Failed to read policy file: {}", e),
                );
            }
        };

        match Policy::from_yaml_with_extends_resolver(
            &content,
            Some(std::path::Path::new(&policy_path)),
            &resolver,
        ) {
            Ok(policy) => {
                let engine = match HushEngine::builder(policy).build() {
                    Ok(engine) => engine,
                    Err(e) => {
                        return emit_check_error(
                            CheckErrorOutput {
                                json,
                                action_type: &action_type,
                                target: &target,
                                stdout,
                                stderr,
                            },
                            PolicySource::PolicyFile {
                                path: policy_path.clone(),
                            },
                            ExitCode::ConfigError,
                            "config_error",
                            &format!("Failed to initialize engine: {}", e),
                        );
                    }
                };

                (engine, PolicySource::PolicyFile { path: policy_path })
            }
            Err(e) => {
                return emit_check_error(
                    CheckErrorOutput {
                        json,
                        action_type: &action_type,
                        target: &target,
                        stdout,
                        stderr,
                    },
                    PolicySource::PolicyFile { path: policy_path },
                    ExitCode::ConfigError,
                    "config_error",
                    &format!("Failed to load policy: {}", e),
                );
            }
        }
    } else {
        let ruleset_name = ruleset.unwrap_or_else(|| "default".to_string());
        match HushEngine::from_ruleset(&ruleset_name) {
            Ok(engine) => (engine, PolicySource::Ruleset { name: ruleset_name }),
            Err(e) => {
                return emit_check_error(
                    CheckErrorOutput {
                        json,
                        action_type: &action_type,
                        target: &target,
                        stdout,
                        stderr,
                    },
                    PolicySource::Ruleset { name: ruleset_name },
                    ExitCode::ConfigError,
                    "config_error",
                    &format!("Failed to load ruleset: {}", e),
                );
            }
        }
    };

    let context = GuardContext::new();

    let result = match action_type.as_str() {
        "file" => engine.check_file_access(&target, &context).await,
        "egress" => {
            let mut parts = target.split(':');
            let host = match parts.next() {
                Some(host) if !host.is_empty() => host,
                _ => {
                    return emit_check_error(
                        CheckErrorOutput {
                            json,
                            action_type: &action_type,
                            target: &target,
                            stdout,
                            stderr,
                        },
                        policy_source,
                        ExitCode::InvalidArgs,
                        "invalid_args",
                        "Invalid egress target: expected host[:port]",
                    );
                }
            };
            let port: u16 = match parts.next() {
                Some(port) => match port.parse() {
                    Ok(p) => p,
                    Err(_) => {
                        return emit_check_error(
                            CheckErrorOutput {
                                json,
                                action_type: &action_type,
                                target: &target,
                                stdout,
                                stderr,
                            },
                            policy_source,
                            ExitCode::InvalidArgs,
                            "invalid_args",
                            "Invalid egress target: port must be a number",
                        );
                    }
                },
                None => 443,
            };
            engine.check_egress(host, port, &context).await
        }
        "mcp" => {
            let args = serde_json::json!({});
            engine.check_mcp_tool(&target, &args, &context).await
        }
        _ => {
            return emit_check_error(
                CheckErrorOutput {
                    json,
                    action_type: &action_type,
                    target: &target,
                    stdout,
                    stderr,
                },
                policy_source,
                ExitCode::InvalidArgs,
                "invalid_args",
                &format!("Unknown action type: {}", action_type),
            );
        }
    };

    let result = match result {
        Ok(r) => r,
        Err(e) => {
            return emit_check_error(
                CheckErrorOutput {
                    json,
                    action_type: &action_type,
                    target: &target,
                    stdout,
                    stderr,
                },
                policy_source,
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Check failed: {}", e),
            );
        }
    };

    let code = guard_result_exit_code(&result);
    if json {
        let outcome = match code {
            ExitCode::Ok => "allowed",
            ExitCode::Warn => "warn",
            ExitCode::Fail => "blocked",
            _ => "error",
        };

        let output = CheckJsonOutput {
            version: CLI_JSON_VERSION,
            command: "check",
            action_type,
            target,
            policy: policy_source,
            outcome,
            exit_code: code.as_i32(),
            result: Some(result),
            error: None,
        };
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    match code {
        ExitCode::Ok => {
            let _ = writeln!(stdout, "ALLOWED: {}", result.message);
        }
        ExitCode::Warn => {
            let _ = writeln!(stdout, "WARN: {}", result.message);
        }
        ExitCode::Fail => {
            let _ = writeln!(
                stderr,
                "BLOCKED [{:?}]: {}",
                result.severity, result.message
            );
        }
        _ => {
            let _ = writeln!(stderr, "Error: {}", result.message);
        }
    }

    code
}

fn emit_check_error(
    out: CheckErrorOutput<'_>,
    policy: PolicySource,
    code: ExitCode,
    error_kind: &'static str,
    message: &str,
) -> ExitCode {
    if out.json {
        let output = CheckJsonOutput {
            version: CLI_JSON_VERSION,
            command: "check",
            action_type: out.action_type.to_string(),
            target: out.target.to_string(),
            policy,
            outcome: "error",
            exit_code: code.as_i32(),
            result: None,
            error: Some(CliJsonError {
                kind: error_kind,
                message: message.to_string(),
            }),
        };
        let _ = writeln!(
            out.stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    let _ = writeln!(out.stderr, "Error: {}", message);
    code
}

struct CheckErrorOutput<'a> {
    json: bool,
    action_type: &'a str,
    target: &'a str,
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
}

fn cmd_verify(
    receipt: String,
    pubkey: String,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let receipt_json = match std::fs::read_to_string(&receipt) {
        Ok(v) => v,
        Err(e) => {
            return emit_verify_error(
                VerifyErrorOutput {
                    json,
                    receipt: &receipt,
                    pubkey: &pubkey,
                    stdout,
                    stderr,
                },
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Failed to read receipt: {}", e),
                None,
                None,
            );
        }
    };

    let signed: SignedReceipt = match serde_json::from_str(&receipt_json) {
        Ok(v) => v,
        Err(e) => {
            return emit_verify_error(
                VerifyErrorOutput {
                    json,
                    receipt: &receipt,
                    pubkey: &pubkey,
                    stdout,
                    stderr,
                },
                ExitCode::ConfigError,
                "config_error",
                &format!("Invalid receipt JSON: {}", e),
                None,
                None,
            );
        }
    };

    let summary = ReceiptSummary {
        version: signed.receipt.version.clone(),
        receipt_id: signed.receipt.receipt_id.clone(),
        timestamp: signed.receipt.timestamp.clone(),
        content_hash: signed.receipt.content_hash,
        verdict_passed: signed.receipt.verdict.passed,
    };

    let pubkey_hex = match std::fs::read_to_string(&pubkey) {
        Ok(v) => v.trim().to_string(),
        Err(e) => {
            return emit_verify_error(
                VerifyErrorOutput {
                    json,
                    receipt: &receipt,
                    pubkey: &pubkey,
                    stdout,
                    stderr,
                },
                ExitCode::RuntimeError,
                "runtime_error",
                &format!("Failed to read pubkey: {}", e),
                None,
                Some(summary),
            );
        }
    };

    let public_key = match hush_core::PublicKey::from_hex(&pubkey_hex) {
        Ok(v) => v,
        Err(e) => {
            return emit_verify_error(
                VerifyErrorOutput {
                    json,
                    receipt: &receipt,
                    pubkey: &pubkey,
                    stdout,
                    stderr,
                },
                ExitCode::ConfigError,
                "config_error",
                &format!("Invalid pubkey: {}", e),
                None,
                Some(summary),
            );
        }
    };

    let keys = hush_core::receipt::PublicKeySet::new(public_key);
    let result = signed.verify(&keys);

    let outcome = if !result.valid {
        "invalid"
    } else if signed.receipt.verdict.passed {
        "pass"
    } else {
        "fail"
    };

    let code = if !result.valid {
        ExitCode::Fail
    } else if signed.receipt.verdict.passed {
        ExitCode::Ok
    } else {
        ExitCode::Fail
    };

    if json {
        let output = VerifyJsonOutput {
            version: CLI_JSON_VERSION,
            command: "verify",
            receipt,
            pubkey,
            outcome,
            exit_code: code.as_i32(),
            signature: Some(result),
            receipt_summary: Some(summary),
            error: None,
        };
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    if result.valid {
        let _ = writeln!(stdout, "VALID: Receipt signature verified");
        let verdict = if signed.receipt.verdict.passed {
            "PASS"
        } else {
            "FAIL"
        };
        let _ = writeln!(stdout, "  Verdict: {}", verdict);
    } else {
        let _ = writeln!(stderr, "INVALID: {}", result.errors.join(", "));
    }

    code
}

fn emit_verify_error(
    out: VerifyErrorOutput<'_>,
    code: ExitCode,
    error_kind: &'static str,
    message: &str,
    signature: Option<hush_core::receipt::VerificationResult>,
    receipt_summary: Option<ReceiptSummary>,
) -> ExitCode {
    if out.json {
        let output = VerifyJsonOutput {
            version: CLI_JSON_VERSION,
            command: "verify",
            receipt: out.receipt.to_string(),
            pubkey: out.pubkey.to_string(),
            outcome: "error",
            exit_code: code.as_i32(),
            signature,
            receipt_summary,
            error: Some(CliJsonError {
                kind: error_kind,
                message: message.to_string(),
            }),
        };
        let _ = writeln!(
            out.stdout,
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
        );
        return code;
    }

    let _ = writeln!(out.stderr, "Error: {}", message);
    code
}

struct VerifyErrorOutput<'a> {
    json: bool,
    receipt: &'a str,
    pubkey: &'a str,
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
}

struct KeygenOutput {
    private_label: &'static str,
    private_path: String,
    public_path: String,
    public_hex: String,
}

fn cmd_keygen(output: &str, tpm_seal: bool) -> anyhow::Result<KeygenOutput> {
    let public_path = format!("{}.pub", output);

    if tpm_seal {
        let keypair = Keypair::generate();
        let private_hex = keypair.to_hex();
        let seed_bytes = hex::decode(private_hex.trim())
            .map_err(|e| anyhow::anyhow!("failed to decode generated seed hex: {}", e))?;
        let seed_len = seed_bytes.len();
        let mut seed: [u8; 32] = seed_bytes.try_into().map_err(|_| {
            anyhow::anyhow!(
                "unexpected generated seed length (expected 32 bytes, got {})",
                seed_len
            )
        })?;
        let public_hex = keypair.public_key().to_hex();

        let blob = hush_core::TpmSealedBlob::seal(&seed)?;
        seed.fill(0);

        let json = serde_json::to_string_pretty(&blob)?;
        std::fs::write(output, json)?;
        std::fs::write(&public_path, &public_hex)?;

        return Ok(KeygenOutput {
            private_label: "Sealed key blob",
            private_path: output.to_string(),
            public_path,
            public_hex,
        });
    }

    let keypair = Keypair::generate();
    let private_hex = keypair.to_hex();
    let public_hex = keypair.public_key().to_hex();

    std::fs::write(output, &private_hex)?;
    std::fs::write(&public_path, &public_hex)?;

    Ok(KeygenOutput {
        private_label: "Private key",
        private_path: output.to_string(),
        public_path,
        public_hex,
    })
}

async fn cmd_policy(
    command: PolicyCommands,
    remote_extends: &remote_extends::RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    let resolver = remote_extends::RemotePolicyResolver::new(remote_extends.clone())
        .map_err(|e| anyhow::anyhow!("Failed to initialize remote extends resolver: {}", e))?;

    match command {
        PolicyCommands::Show { ruleset, merged } => {
            let is_file = std::path::Path::new(&ruleset).exists();

            if is_file {
                let policy = if merged {
                    let content = std::fs::read_to_string(&ruleset)?;
                    Policy::from_yaml_with_extends_resolver(
                        &content,
                        Some(std::path::Path::new(&ruleset)),
                        &resolver,
                    )?
                } else {
                    Policy::from_yaml_file(&ruleset)?
                };
                let yaml = policy.to_yaml()?;
                if merged {
                    let _ = writeln!(stdout, "# Policy: {} (merged)", policy.name);
                } else {
                    let _ = writeln!(stdout, "# Policy: {}", policy.name);
                }
                let _ = writeln!(stdout, "{}", yaml);
            } else {
                let rs = RuleSet::by_name(&ruleset)?
                    .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", ruleset))?;
                let yaml = rs.policy.to_yaml()?;
                let _ = writeln!(stdout, "# Ruleset: {} ({})", rs.name, rs.id);
                let _ = writeln!(stdout, "# {}", rs.description);
                let _ = writeln!(stdout, "{}", yaml);
            }
            Ok(ExitCode::Ok)
        }

        PolicyCommands::Validate {
            file,
            resolve,
            check_env,
        } => {
            let content = std::fs::read_to_string(&file)?;
            let validation = clawdstrike::policy::PolicyValidationOptions {
                require_env: check_env,
            };

            let policy = if resolve {
                match Policy::from_yaml_with_extends_resolver_with_validation_options(
                    &content,
                    Some(std::path::Path::new(&file)),
                    &resolver,
                    validation,
                ) {
                    Ok(policy) => policy,
                    Err(e) => {
                        let code = policy_error_exit_code(&e);
                        let _ = writeln!(stderr, "Error: {}", e);
                        return Ok(code);
                    }
                }
            } else {
                let policy: Policy = match serde_yaml::from_str(&content) {
                    Ok(policy) => policy,
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {}", e);
                        return Ok(ExitCode::ConfigError);
                    }
                };
                if let Err(e) = policy.validate_with_options(validation) {
                    let code = policy_error_exit_code(&e);
                    let _ = writeln!(stderr, "Error: {}", e);
                    return Ok(code);
                }
                policy
            };

            let _ = writeln!(stdout, "Policy is valid:");
            let _ = writeln!(stdout, "  Version: {}", policy.version);
            let _ = writeln!(stdout, "  Name: {}", policy.name);
            if let Some(ref extends) = policy.extends {
                let _ = writeln!(stdout, "  Extends: {}", extends);
            }
            if resolve {
                let _ = writeln!(stdout, "\nMerged policy:");
                let _ = writeln!(stdout, "{}", policy.to_yaml()?);
            }
            Ok(ExitCode::Ok)
        }

        PolicyCommands::Diff {
            left,
            right,
            resolve,
            json,
        } => {
            let left_loaded =
                match policy_diff::load_policy_from_arg(&left, resolve, remote_extends) {
                    Ok(v) => v,
                    Err(e) => {
                        let code = policy_error_exit_code(&e.source);
                        let _ =
                            writeln!(stderr, "Error loading left policy {left:?}: {}", e.message);
                        return Ok(code);
                    }
                };
            let right_loaded =
                match policy_diff::load_policy_from_arg(&right, resolve, remote_extends) {
                    Ok(v) => v,
                    Err(e) => {
                        let code = policy_error_exit_code(&e.source);
                        let _ = writeln!(
                            stderr,
                            "Error loading right policy {right:?}: {}",
                            e.message
                        );
                        return Ok(code);
                    }
                };

            let left_policy = left_loaded.policy;
            let right_policy = right_loaded.policy;

            let left_value = match serde_json::to_value(&left_policy) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: Failed to serialize left policy: {}", e);
                    return Ok(ExitCode::RuntimeError);
                }
            };
            let right_value = match serde_json::to_value(&right_policy) {
                Ok(v) => v,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: Failed to serialize right policy: {}", e);
                    return Ok(ExitCode::RuntimeError);
                }
            };

            let diffs = policy_diff::diff_values(&left_value, &right_value);

            if json {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&diffs).unwrap_or_else(|_| "[]".to_string())
                );
                return Ok(ExitCode::Ok);
            }

            let _ = writeln!(
                stdout,
                "Diff: {} -> {}{}",
                left_loaded.source.describe(),
                right_loaded.source.describe(),
                if resolve { " (resolved)" } else { "" }
            );

            if diffs.is_empty() {
                let _ = writeln!(stdout, "No changes.");
                return Ok(ExitCode::Ok);
            }

            let mut added = 0usize;
            let mut removed = 0usize;
            let mut changed = 0usize;
            for d in &diffs {
                match d.kind {
                    policy_diff::DiffKind::Added => added += 1,
                    policy_diff::DiffKind::Removed => removed += 1,
                    policy_diff::DiffKind::Changed => changed += 1,
                }
            }

            let _ = writeln!(
                stdout,
                "Found {} change(s): {} changed, {} added, {} removed",
                diffs.len(),
                changed,
                added,
                removed
            );

            for d in diffs {
                let path = if d.path.is_empty() {
                    "/"
                } else {
                    d.path.as_str()
                };
                match d.kind {
                    policy_diff::DiffKind::Added => {
                        let new = d
                            .new
                            .as_ref()
                            .map(|v| policy_diff::format_compact_value(v, 120))
                            .unwrap_or_else(|| "null".to_string());
                        let _ = writeln!(stdout, "+ {}: null -> {}", path, new);
                    }
                    policy_diff::DiffKind::Removed => {
                        let old = d
                            .old
                            .as_ref()
                            .map(|v| policy_diff::format_compact_value(v, 120))
                            .unwrap_or_else(|| "null".to_string());
                        let _ = writeln!(stdout, "- {}: {} -> null", path, old);
                    }
                    policy_diff::DiffKind::Changed => {
                        let old = d
                            .old
                            .as_ref()
                            .map(|v| policy_diff::format_compact_value(v, 120))
                            .unwrap_or_else(|| "null".to_string());
                        let new = d
                            .new
                            .as_ref()
                            .map(|v| policy_diff::format_compact_value(v, 120))
                            .unwrap_or_else(|| "null".to_string());
                        let _ = writeln!(stdout, "~ {}: {} -> {}", path, old, new);
                    }
                }
            }

            Ok(ExitCode::Ok)
        }

        PolicyCommands::List => {
            let _ = writeln!(stdout, "Available rulesets:");
            for id in RuleSet::list() {
                let Some(rs) = RuleSet::by_name(id)? else {
                    continue;
                };
                let _ = writeln!(stdout, "  {} - {}", rs.id, rs.description);
            }
            Ok(ExitCode::Ok)
        }

        PolicyCommands::Lint {
            policy_ref,
            resolve,
            strict,
            json,
            sarif,
        } => Ok(policy_lint::cmd_policy_lint(
            policy_lint::PolicyLintCommand {
                policy_ref,
                resolve,
                json,
                sarif,
                strict,
            },
            remote_extends,
            stdout,
            stderr,
        )),

        PolicyCommands::Test {
            test_file,
            resolve,
            json,
            coverage,
        } => Ok(policy_test::cmd_policy_test(
            test_file,
            resolve,
            remote_extends,
            json,
            coverage,
            stdout,
            stderr,
        )
        .await),

        PolicyCommands::Impact {
            old_policy,
            new_policy,
            events,
            resolve,
            json,
            fail_on_breaking,
        } => Ok(policy_impact::cmd_policy_impact(
            old_policy,
            new_policy,
            events,
            policy_impact::PolicyImpactOptions {
                resolve,
                remote_extends,
                json,
                fail_on_breaking,
            },
            stdout,
            stderr,
        )
        .await),

        PolicyCommands::Version {
            policy_ref,
            resolve,
            json,
        } => Ok(policy_version::cmd_policy_version(
            policy_ref,
            resolve,
            remote_extends,
            json,
            stdout,
            stderr,
        )),

        PolicyCommands::Migrate {
            input,
            to,
            from,
            legacy_openclaw,
            output,
            in_place,
            json,
            dry_run,
        } => Ok(policy_migrate::cmd_policy_migrate(
            policy_migrate::PolicyMigrateCommand {
                input,
                from,
                to,
                legacy_openclaw,
                output,
                in_place,
                json,
                dry_run,
            },
            stdout,
            stderr,
        )),

        PolicyCommands::Bundle { command } => Ok(policy_bundle::cmd_policy_bundle(
            command,
            remote_extends,
            stdout,
            stderr,
        )),

        PolicyCommands::Rego { command } => {
            Ok(policy_rego::cmd_policy_rego(command, stdout, stderr))
        }

        PolicyCommands::Eval {
            policy_ref,
            event,
            resolve,
            json,
        } => Ok(policy_pac::cmd_policy_eval(
            policy_ref,
            event,
            resolve,
            remote_extends,
            json,
            stdout,
            stderr,
        )
        .await),

        PolicyCommands::Simulate {
            policy_ref,
            events,
            resolve,
            json,
            jsonl,
            summary,
            fail_on_deny,
            no_fail_on_deny,
            benchmark,
            track_posture,
        } => Ok(policy_pac::cmd_policy_simulate(
            policy_ref,
            events,
            policy_pac::PolicySimulateOptions {
                resolve,
                remote_extends,
                json,
                jsonl,
                summary,
                fail_on_deny: fail_on_deny || !no_fail_on_deny,
                benchmark,
                track_posture,
            },
            stdout,
            stderr,
        )
        .await),

        PolicyCommands::Observe {
            policy,
            out,
            hushd_url,
            hushd_token,
            session,
            command,
        } => Ok(policy_observe::cmd_policy_observe(
            policy_observe::PolicyObserveCommand {
                policy,
                out: PathBuf::from(out),
                hushd_url,
                hushd_token,
                session,
                command,
            },
            remote_extends,
            stdout,
            stderr,
        )
        .await),

        PolicyCommands::Synth {
            events,
            extends,
            out,
            diff_out,
            risk_out,
            with_posture,
            json,
        } => Ok(policy_synth::cmd_policy_synth(
            policy_synth::PolicySynthCommand {
                events: PathBuf::from(events),
                extends,
                out: PathBuf::from(out),
                diff_out: diff_out.map(PathBuf::from),
                risk_out: PathBuf::from(risk_out),
                with_posture,
                json,
            },
            remote_extends,
            stdout,
            stderr,
        )),
    }
}

fn policy_error_exit_code(err: &clawdstrike::Error) -> ExitCode {
    match err {
        clawdstrike::Error::IoError(_) | clawdstrike::Error::CoreError(_) => ExitCode::RuntimeError,
        _ => ExitCode::ConfigError,
    }
}

fn cmd_daemon(command: DaemonCommands, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match command {
        DaemonCommands::Start { config, bind, port } => {
            use std::process::Command;

            let mut cmd = Command::new("hushd");
            cmd.arg("start")
                .arg("--bind")
                .arg(&bind)
                .arg("--port")
                .arg(port.to_string());

            if let Some(config) = config {
                cmd.arg("--config").arg(&config);
            }

            let _ = writeln!(stdout, "Starting hushd on {}:{}...", bind, port);

            match cmd.spawn() {
                Ok(_) => {
                    let _ = writeln!(stdout, "Daemon started");
                    ExitCode::Ok
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        let _ = writeln!(
                            stderr,
                            "Error: hushd not found in PATH. Run 'cargo install --path crates/hushd'"
                        );
                    } else {
                        let _ = writeln!(stderr, "Error starting daemon: {}", e);
                    }
                    ExitCode::RuntimeError
                }
            }
        }

        DaemonCommands::Stop { url, token } => {
            let client = reqwest::blocking::Client::new();
            let token = token
                .or_else(|| std::env::var("CLAWDSTRIKE_ADMIN_KEY").ok())
                .or_else(|| std::env::var("CLAWDSTRIKE_API_KEY").ok());

            let _ = writeln!(stdout, "Requesting shutdown at {}...", url);

            let mut req = client.post(format!("{}/api/v1/shutdown", url));
            if let Some(token) = token {
                req = req.bearer_auth(token);
            }

            match req.send() {
                Ok(resp) if resp.status().is_success() => {
                    let _ = writeln!(stdout, "Shutdown requested");

                    // Best-effort: wait briefly for the daemon to exit.
                    for _ in 0..20 {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        match client.get(format!("{}/health", url)).send() {
                            Ok(h) if h.status().is_success() => continue,
                            _ => break,
                        }
                    }

                    ExitCode::Ok
                }
                Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                    let _ = writeln!(
                        stderr,
                        "Daemon does not support shutdown via API. Stop it with Ctrl+C or SIGTERM."
                    );
                    ExitCode::RuntimeError
                }
                Ok(resp) => {
                    let _ = writeln!(
                        stderr,
                        "Error: {} {}",
                        resp.status(),
                        resp.text().unwrap_or_default()
                    );
                    ExitCode::RuntimeError
                }
                Err(e) => {
                    let _ = writeln!(stderr, "Error connecting to daemon: {}", e);
                    ExitCode::RuntimeError
                }
            }
        }

        DaemonCommands::Status { url } => {
            let client = reqwest::blocking::Client::new();
            match client.get(format!("{}/health", url)).send() {
                Ok(resp) if resp.status().is_success() => {
                    let health: serde_json::Value = resp.json().unwrap_or_default();
                    let _ = writeln!(
                        stdout,
                        "Status: {}",
                        health
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                    );
                    let _ = writeln!(
                        stdout,
                        "Version: {}",
                        health
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                    );
                    let _ = writeln!(
                        stdout,
                        "Uptime: {}s",
                        health
                            .get("uptime_secs")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0)
                    );
                    let _ = writeln!(
                        stdout,
                        "Session: {}",
                        health
                            .get("session_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                    );
                    let _ = writeln!(
                        stdout,
                        "Audit events: {}",
                        health
                            .get("audit_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0)
                    );
                    ExitCode::Ok
                }
                _ => {
                    let _ = writeln!(stderr, "Daemon is not running at {}", url);
                    ExitCode::RuntimeError
                }
            }
        }

        DaemonCommands::Reload { url, token } => {
            let client = reqwest::blocking::Client::new();
            let token = token
                .or_else(|| std::env::var("CLAWDSTRIKE_ADMIN_KEY").ok())
                .or_else(|| std::env::var("CLAWDSTRIKE_API_KEY").ok());

            let mut req = client.post(format!("{}/api/v1/policy/reload", url));
            if let Some(token) = token {
                req = req.bearer_auth(token);
            }

            match req.send() {
                Ok(resp) if resp.status().is_success() => {
                    let _ = writeln!(stdout, "Policy reloaded successfully");
                    ExitCode::Ok
                }
                Ok(resp) => {
                    let _ = writeln!(
                        stderr,
                        "Error: {} {}",
                        resp.status(),
                        resp.text().unwrap_or_default()
                    );
                    ExitCode::RuntimeError
                }
                Err(e) => {
                    let _ = writeln!(stderr, "Error connecting to daemon: {}", e);
                    ExitCode::RuntimeError
                }
            }
        }

        DaemonCommands::Keygen {
            name,
            scopes,
            expires_days,
        } => {
            // Generate a secure random key
            let mut rng = rand::rng();
            let key_bytes: [u8; 32] = rng.random();
            let raw_key = format!("hush_{}", hex::encode(key_bytes));

            // Parse scopes
            let scope_list: Vec<String> = scopes
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();

            // Calculate expiration
            let expires_at = if expires_days > 0 {
                Some(chrono::Utc::now() + chrono::Duration::days(expires_days as i64))
            } else {
                None
            };

            let _ = writeln!(stdout, "Generated API key for '{}':\n", name);
            let _ = writeln!(stdout, "  Key:    {}", raw_key);
            let _ = writeln!(stdout, "  Scopes: {:?}", scope_list);
            if let Some(exp) = expires_at {
                let _ = writeln!(stdout, "  Expires: {}", exp.to_rfc3339());
            } else {
                let _ = writeln!(stdout, "  Expires: never");
            }

            let _ = writeln!(stdout, "\nAdd to config.yaml:\n");
            let _ = writeln!(stdout, "auth:");
            let _ = writeln!(stdout, "  api_keys:");
            let _ = writeln!(stdout, "    - name: \"{}\"", name);
            let _ = writeln!(stdout, "      key: \"{}\"", raw_key);
            let _ = writeln!(stdout, "      scopes: {:?}", scope_list);
            if let Some(exp) = expires_at {
                let _ = writeln!(stdout, "      expires_at: \"{}\"", exp.to_rfc3339());
            }

            let _ = writeln!(stdout, "\nOr set environment variable:");
            let _ = writeln!(stdout, "  export CLAWDSTRIKE_API_KEY=\"{}\"", raw_key);
            ExitCode::Ok
        }
    }
}

fn cmd_hash(file: &str, algorithm: &str, format: &str) -> anyhow::Result<String> {
    let data = if file == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(file)?
    };

    let hash = match algorithm {
        "sha256" => sha256(&data),
        "keccak256" => keccak256(&data),
        _ => anyhow::bail!("Unknown algorithm: {}. Use sha256 or keccak256", algorithm),
    };

    let output = match format {
        "hex" => hash.to_hex(),
        "base64" => BASE64.encode(hash.as_bytes()),
        _ => anyhow::bail!("Unknown format: {}. Use hex or base64", format),
    };

    Ok(output)
}

fn cmd_sign(
    key: &str,
    file: &str,
    verify: bool,
    output: Option<&str>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let key_hex = match std::fs::read_to_string(key) {
        Ok(v) => v.trim().to_string(),
        Err(e) => {
            let _ = writeln!(stderr, "Error: Failed to read private key: {}", e);
            return ExitCode::RuntimeError;
        }
    };

    let keypair = match Keypair::from_hex(&key_hex) {
        Ok(k) => k,
        Err(e) => {
            let _ = writeln!(stderr, "Error: Failed to load private key: {}", e);
            return ExitCode::ConfigError;
        }
    };

    let data = match std::fs::read(file) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: Failed to read file: {}", e);
            return ExitCode::RuntimeError;
        }
    };

    let signature = keypair.sign(&data);
    let sig_hex = signature.to_hex();

    if let Some(output_path) = output {
        if let Err(e) = std::fs::write(output_path, &sig_hex) {
            let _ = writeln!(stderr, "Error: Failed to write signature: {}", e);
            return ExitCode::RuntimeError;
        }
        let _ = writeln!(stdout, "Signature written to {}", output_path);
    } else {
        let _ = writeln!(stdout, "{}", sig_hex);
    }

    if verify {
        let public_key = keypair.public_key();
        if public_key.verify(&data, &signature) {
            let _ = writeln!(stderr, "Signature verified successfully");
        } else {
            let _ = writeln!(stderr, "Error: Signature verification failed!");
            return ExitCode::Fail;
        }
    }

    ExitCode::Ok
}

fn cmd_merkle(
    command: MerkleCommands,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    match command {
        MerkleCommands::Root { files } => {
            if files.is_empty() {
                anyhow::bail!("At least one file is required");
            }

            let leaves: Vec<Vec<u8>> = files
                .iter()
                .map(std::fs::read)
                .collect::<std::io::Result<_>>()?;

            let tree = MerkleTree::from_leaves(&leaves)
                .map_err(|e| anyhow::anyhow!("Failed to build tree: {}", e))?;

            let _ = writeln!(stdout, "{}", tree.root().to_hex());
            Ok(ExitCode::Ok)
        }

        MerkleCommands::Proof { index, files } => {
            if files.is_empty() {
                anyhow::bail!("At least one file is required");
            }

            let leaves: Vec<Vec<u8>> = files
                .iter()
                .map(std::fs::read)
                .collect::<std::io::Result<_>>()?;

            let tree = MerkleTree::from_leaves(&leaves)
                .map_err(|e| anyhow::anyhow!("Failed to build tree: {}", e))?;

            let proof = tree
                .inclusion_proof(index)
                .map_err(|e| anyhow::anyhow!("Failed to generate proof: {}", e))?;

            let json = serde_json::to_string_pretty(&proof)?;
            let _ = writeln!(stdout, "{}", json);
            Ok(ExitCode::Ok)
        }

        MerkleCommands::Verify { root, leaf, proof } => {
            let expected_root =
                Hash::from_hex(&root).map_err(|e| anyhow::anyhow!("Invalid root hash: {}", e))?;

            let leaf_data = std::fs::read(&leaf)?;

            let proof_json = std::fs::read_to_string(&proof)?;
            let merkle_proof: MerkleProof = serde_json::from_str(&proof_json)?;

            if merkle_proof.verify(&leaf_data, &expected_root) {
                let _ = writeln!(stdout, "VALID: Proof verified successfully");
                let _ = writeln!(stdout, "  Root: {}", expected_root.to_hex());
                let _ = writeln!(stdout, "  Leaf index: {}", merkle_proof.leaf_index);
                let _ = writeln!(stdout, "  Tree size: {}", merkle_proof.tree_size);
                Ok(ExitCode::Ok)
            } else {
                let _ = writeln!(stderr, "INVALID: Proof verification failed");
                Ok(ExitCode::Fail)
            }
        }
    }
}

#[cfg(test)]
mod tests;
