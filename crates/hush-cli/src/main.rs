//! Hush CLI - Command-line interface for hushclaw
//!
//! Commands:
//! - hush check <action> - Check an action against policy
//! - hush verify <receipt> - Verify a signed receipt
//! - hush keygen - Generate a signing keypair
//! - hush policy show - Show current policy
//! - hush policy validate <file> - Validate a policy file
//! - hush daemon start/stop/status/reload - Daemon management

use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hush_core::{Keypair, SignedReceipt};
use hushclaw::{GuardContext, HushEngine, Policy, RuleSet};

#[derive(Parser)]
#[command(name = "hush")]
#[command(about = "Hushclaw security guard CLI", long_about = None)]
struct Cli {
    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check an action against policy
    Check {
        /// Action type (file, egress, mcp)
        #[arg(short, long)]
        action_type: String,

        /// Target (path, host, tool name)
        target: String,

        /// Ruleset to use
        #[arg(short, long, default_value = "default")]
        ruleset: String,
    },

    /// Verify a signed receipt
    Verify {
        /// Path to receipt JSON file
        receipt: String,

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
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Show a ruleset's policy
    Show {
        /// Ruleset name
        #[arg(default_value = "default")]
        ruleset: String,
    },

    /// Validate a policy file
    Validate {
        /// Path to policy YAML file
        file: String,
    },

    /// List available rulesets
    List,
}

#[derive(Subcommand)]
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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

    match cli.command {
        Commands::Check {
            action_type,
            target,
            ruleset,
        } => {
            let engine = HushEngine::from_ruleset(&ruleset)
                .map_err(|e| anyhow::anyhow!("Failed to load ruleset: {}", e))?;
            let context = GuardContext::new();

            let result = match action_type.as_str() {
                "file" => engine.check_file_access(&target, &context).await?,
                "egress" => {
                    let parts: Vec<&str> = target.split(':').collect();
                    let host = parts[0];
                    let port: u16 = parts.get(1).unwrap_or(&"443").parse()?;
                    engine.check_egress(host, port, &context).await?
                }
                "mcp" => {
                    let args = serde_json::json!({});
                    engine.check_mcp_tool(&target, &args, &context).await?
                }
                _ => anyhow::bail!("Unknown action type: {}", action_type),
            };

            if result.allowed {
                println!("ALLOWED: {}", result.message);
            } else {
                println!("BLOCKED [{:?}]: {}", result.severity, result.message);
                std::process::exit(1);
            }
        }

        Commands::Verify { receipt, pubkey } => {
            let receipt_json = std::fs::read_to_string(&receipt)?;
            let signed: SignedReceipt = serde_json::from_str(&receipt_json)?;

            let pubkey_hex = std::fs::read_to_string(&pubkey)?.trim().to_string();
            let public_key = hush_core::PublicKey::from_hex(&pubkey_hex)?;

            let keys = hush_core::receipt::PublicKeySet::new(public_key);
            let result = signed.verify(&keys);

            if result.valid {
                println!("VALID: Receipt signature verified");
                println!(
                    "  Verdict: {}",
                    if signed.receipt.verdict.passed {
                        "PASS"
                    } else {
                        "FAIL"
                    }
                );
            } else {
                println!("INVALID: {}", result.errors.join(", "));
                std::process::exit(1);
            }
        }

        Commands::Keygen { output } => {
            let keypair = Keypair::generate();
            let private_hex = keypair.to_hex();
            let public_hex = keypair.public_key().to_hex();

            std::fs::write(&output, &private_hex)?;
            std::fs::write(format!("{}.pub", output), &public_hex)?;

            println!("Generated keypair:");
            println!("  Private key: {}", output);
            println!("  Public key:  {}.pub", output);
            println!("  Public key (hex): {}", public_hex);
        }

        Commands::Policy { command } => match command {
            PolicyCommands::Show { ruleset } => {
                let rs = RuleSet::by_name(&ruleset)
                    .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", ruleset))?;
                let yaml = rs.policy.to_yaml()?;
                println!("# Ruleset: {} ({})", rs.name, rs.id);
                println!("# {}", rs.description);
                println!("{}", yaml);
            }

            PolicyCommands::Validate { file } => {
                let policy = Policy::from_yaml_file(&file)?;
                println!("Policy is valid:");
                println!("  Version: {}", policy.version);
                println!("  Name: {}", policy.name);
            }

            PolicyCommands::List => {
                println!("Available rulesets:");
                for name in ["default", "strict", "permissive"] {
                    let rs = RuleSet::by_name(name).unwrap();
                    println!("  {} - {}", rs.id, rs.description);
                }
            }
        },

        Commands::Daemon { command } => match command {
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

                println!("Starting hushd on {}:{}...", bind, port);

                // Try to spawn the daemon
                match cmd.spawn() {
                    Ok(_) => println!("Daemon started"),
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            eprintln!(
                                "Error: hushd not found in PATH. Run 'cargo install --path crates/hushd'"
                            );
                        } else {
                            eprintln!("Error starting daemon: {}", e);
                        }
                        std::process::exit(1);
                    }
                }
            }
            DaemonCommands::Stop { url } => {
                println!("Note: Daemon can be stopped with Ctrl+C or SIGTERM");
                println!("Checking status at {}...", url);

                let client = reqwest::blocking::Client::new();
                match client.get(format!("{}/health", url)).send() {
                    Ok(resp) if resp.status().is_success() => {
                        println!("Daemon is running. Send SIGTERM to stop.");
                    }
                    _ => {
                        println!("Daemon is not running.");
                    }
                }
            }
            DaemonCommands::Status { url } => {
                let client = reqwest::blocking::Client::new();
                match client.get(format!("{}/health", url)).send() {
                    Ok(resp) if resp.status().is_success() => {
                        let health: serde_json::Value = resp.json().unwrap_or_default();
                        println!(
                            "Status: {}",
                            health
                                .get("status")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        );
                        println!(
                            "Version: {}",
                            health
                                .get("version")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        );
                        println!(
                            "Uptime: {}s",
                            health
                                .get("uptime_secs")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0)
                        );
                        println!(
                            "Session: {}",
                            health
                                .get("session_id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        );
                        println!(
                            "Audit events: {}",
                            health
                                .get("audit_count")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0)
                        );
                    }
                    _ => {
                        println!("Daemon is not running at {}", url);
                        std::process::exit(1);
                    }
                }
            }
            DaemonCommands::Reload { url } => {
                let client = reqwest::blocking::Client::new();
                match client.post(format!("{}/api/v1/policy/reload", url)).send() {
                    Ok(resp) if resp.status().is_success() => {
                        println!("Policy reloaded successfully");
                    }
                    Ok(resp) => {
                        eprintln!("Error: {} {}", resp.status(), resp.text().unwrap_or_default());
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Error connecting to daemon: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
    }

    Ok(())
}
