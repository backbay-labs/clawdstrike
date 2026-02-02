#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! Hush CLI - Command-line interface for hushclaw
//!
//! Commands:
//! - hush check <action> - Check an action against policy
//! - hush verify <receipt> - Verify a signed receipt
//! - hush keygen - Generate a signing keypair
//! - hush hash <file> - Compute hash of a file (SHA-256/Keccak-256)
//! - hush sign --key <key> <file> - Sign a file
//! - hush merkle root/proof/verify - Merkle tree operations
//! - hush policy show - Show current policy
//! - hush policy validate <file> - Validate a policy file
//! - hush daemon start/stop/status/reload - Daemon management

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::generate;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hush_core::{keccak256, sha256, Hash, Keypair, MerkleProof, MerkleTree, SignedReceipt};
use hushclaw::{GuardContext, GuardResult, HushEngine, Policy, RuleSet, Severity};

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

#[derive(Parser, Debug)]
#[command(name = "hush")]
#[command(version, about = "Hushclaw security guard CLI", long_about = None)]
struct Cli {
    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

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
        #[arg(short, long, default_value = "hush.key")]
        output: String,
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
    },

    /// List available rulesets
    List,
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
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            log_level,
        ))
        .init();

    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let code = run(cli, &mut stdout, &mut stderr).await;
    std::process::exit(code.as_i32());
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

async fn run(cli: Cli, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match cli.command {
        Commands::Check {
            action_type,
            target,
            json,
            policy,
            ruleset,
        } => cmd_check(action_type, target, json, policy, ruleset, stdout, stderr).await,

        Commands::Verify {
            receipt,
            json,
            pubkey,
        } => cmd_verify(receipt, pubkey, json, stdout, stderr),

        Commands::Keygen { output } => match cmd_keygen(&output) {
            Ok((private_path, public_path, public_hex)) => {
                let _ = writeln!(stdout, "Generated keypair:");
                let _ = writeln!(stdout, "  Private key: {}", private_path);
                let _ = writeln!(stdout, "  Public key:  {}", public_path);
                let _ = writeln!(stdout, "  Public key (hex): {}", public_hex);
                ExitCode::Ok
            }
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                ExitCode::RuntimeError
            }
        },

        Commands::Policy { command } => match cmd_policy(command, stdout, stderr) {
            Ok(code) => code,
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                ExitCode::RuntimeError
            }
        },

        Commands::Daemon { command } => cmd_daemon(command, stdout, stderr),

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "hush", &mut std::io::stdout());
            ExitCode::Ok
        }

        Commands::Hash {
            file,
            algorithm,
            format,
        } => match cmd_hash(&file, &algorithm, &format) {
            Ok(output) => {
                let _ = writeln!(stdout, "{}", output);
                ExitCode::Ok
            }
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                ExitCode::InvalidArgs
            }
        },

        Commands::Sign {
            key,
            file,
            verify,
            output,
        } => cmd_sign(&key, &file, verify, output.as_deref(), stdout, stderr),

        Commands::Merkle { command } => match cmd_merkle(command, stdout, stderr) {
            Ok(code) => code,
            Err(e) => {
                let _ = writeln!(stderr, "Error: {}", e);
                ExitCode::RuntimeError
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
    action_type: String,
    target: String,
    json: bool,
    policy: Option<String>,
    ruleset: Option<String>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let (engine, policy_source) = if let Some(policy_path) = policy {
        match Policy::from_yaml_file_with_extends(&policy_path) {
            Ok(policy) => (
                HushEngine::with_policy(policy),
                PolicySource::PolicyFile { path: policy_path },
            ),
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

fn cmd_keygen(output: &str) -> anyhow::Result<(String, String, String)> {
    let keypair = Keypair::generate();
    let private_hex = keypair.to_hex();
    let public_hex = keypair.public_key().to_hex();

    std::fs::write(output, &private_hex)?;
    let public_path = format!("{}.pub", output);
    std::fs::write(&public_path, &public_hex)?;

    Ok((output.to_string(), public_path, public_hex))
}

fn cmd_policy(
    command: PolicyCommands,
    stdout: &mut dyn Write,
    _stderr: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    match command {
        PolicyCommands::Show { ruleset, merged } => {
            let is_file = std::path::Path::new(&ruleset).exists();

            if is_file {
                let policy = if merged {
                    Policy::from_yaml_file_with_extends(&ruleset)?
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

        PolicyCommands::Validate { file, resolve } => {
            let policy = if resolve {
                Policy::from_yaml_file_with_extends(&file)?
            } else {
                Policy::from_yaml_file(&file)?
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

        DaemonCommands::Stop { url } => {
            let _ = writeln!(stdout, "Note: Daemon can be stopped with Ctrl+C or SIGTERM");
            let _ = writeln!(stdout, "Checking status at {}...", url);

            let client = reqwest::blocking::Client::new();
            match client.get(format!("{}/health", url)).send() {
                Ok(resp) if resp.status().is_success() => {
                    let _ = writeln!(stdout, "Daemon is running. Send SIGTERM to stop.");
                }
                _ => {
                    let _ = writeln!(stdout, "Daemon is not running.");
                }
            }
            ExitCode::Ok
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

        DaemonCommands::Reload { url } => {
            let client = reqwest::blocking::Client::new();
            match client.post(format!("{}/api/v1/policy/reload", url)).send() {
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
            let mut rng = rand::thread_rng();
            let key_bytes: [u8; 32] = rng.gen();
            let raw_key = format!("hush_{}", hex::encode(key_bytes));

            // Compute hash for config
            let hash = Sha256::digest(raw_key.as_bytes());
            let key_hash = hex::encode(hash);

            // Parse scopes
            let scope_list: Vec<&str> = scopes.split(',').map(|s| s.trim()).collect();

            // Calculate expiration
            let expires_at = if expires_days > 0 {
                Some(chrono::Utc::now() + chrono::Duration::days(expires_days as i64))
            } else {
                None
            };

            let _ = writeln!(stdout, "Generated API key for '{}':\n", name);
            let _ = writeln!(stdout, "  Key:    {}", raw_key);
            let _ = writeln!(stdout, "  Hash:   {}", key_hash);
            let _ = writeln!(stdout, "  Scopes: {:?}", scope_list);
            if let Some(exp) = expires_at {
                let _ = writeln!(stdout, "  Expires: {}", exp.to_rfc3339());
            } else {
                let _ = writeln!(stdout, "  Expires: never");
            }

            let _ = writeln!(stdout, "\nAdd to config.yaml:\n");
            let _ = writeln!(stdout, "[[auth.api_keys]]");
            let _ = writeln!(stdout, "name = \"{}\"", name);
            let _ = writeln!(stdout, "key = \"{}\"", raw_key);
            let _ = writeln!(stdout, "scopes = {:?}", scope_list);
            if let Some(exp) = expires_at {
                let _ = writeln!(stdout, "expires_at = \"{}\"", exp.to_rfc3339());
            }

            let _ = writeln!(stdout, "\nOr set environment variable:");
            let _ = writeln!(stdout, "  export HUSHD_API_KEY=\"{}\"", raw_key);
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
