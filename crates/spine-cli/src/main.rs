#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod commands;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "spine-cli", about = "Spine protocol CLI for operations and debugging")]
struct Cli {
    /// NATS server URL
    #[arg(long, env = "NATS_URL", default_value = "nats://localhost:4222", global = true)]
    nats_url: String,

    /// Output format
    #[arg(long, default_value = "table", global = true)]
    format: OutputFormat,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Json,
    Table,
}

#[derive(Subcommand)]
enum Commands {
    /// Show NATS connection + stream info
    Status,

    /// Envelope operations
    #[command(subcommand)]
    Envelopes(EnvelopeCommands),

    /// Checkpoint operations
    #[command(subcommand)]
    Checkpoints(CheckpointCommands),

    /// Inclusion proof operations
    #[command(subcommand)]
    Proofs(ProofCommands),

    /// Trust bundle operations
    #[command(subcommand)]
    Trust(TrustCommands),
}

#[derive(Subcommand)]
enum EnvelopeCommands {
    /// List recent envelopes
    List {
        /// Maximum number of envelopes to return
        #[arg(long, default_value = "20")]
        limit: u64,
    },
    /// Get envelope by hash
    Get {
        /// Envelope hash (0x-prefixed hex)
        hash: String,
    },
    /// Sign a JSON fact from stdin and publish
    Sign,
}

#[derive(Subcommand)]
enum CheckpointCommands {
    /// List recent checkpoints
    List {
        /// Maximum number of checkpoints to return
        #[arg(long, default_value = "10")]
        limit: u64,
    },
    /// Verify checkpoint Merkle root
    Verify {
        /// Checkpoint hash (0x-prefixed hex)
        hash: String,
    },
}

#[derive(Subcommand)]
enum ProofCommands {
    /// Get/verify inclusion proof for an envelope
    Inclusion {
        /// Envelope hash to prove inclusion for
        hash: String,

        /// Proofs API URL
        #[arg(long, env = "PROOFS_API_URL", default_value = "http://localhost:3100")]
        api_url: String,
    },
}

#[derive(Subcommand)]
enum TrustCommands {
    /// Show loaded trust bundle
    Show {
        /// Path to trust bundle JSON file
        #[arg(long, env = "TRUST_BUNDLE_PATH")]
        path: String,
    },
    /// Verify envelope against trust bundle
    Verify {
        /// Envelope hash to verify
        hash: String,

        /// Path to trust bundle JSON file
        #[arg(long, env = "TRUST_BUNDLE_PATH")]
        path: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let is_json = matches!(cli.format, OutputFormat::Json);

    match cli.command {
        Commands::Status => {
            commands::status::run(&cli.nats_url, is_json, cli.verbose).await
        }
        Commands::Envelopes(cmd) => match cmd {
            EnvelopeCommands::List { limit } => {
                commands::envelopes::list(&cli.nats_url, limit, is_json, cli.verbose).await
            }
            EnvelopeCommands::Get { hash } => {
                commands::envelopes::get(&cli.nats_url, &hash, is_json).await
            }
            EnvelopeCommands::Sign => {
                commands::envelopes::sign(&cli.nats_url, is_json).await
            }
        },
        Commands::Checkpoints(cmd) => match cmd {
            CheckpointCommands::List { limit } => {
                commands::checkpoints::list(&cli.nats_url, limit, is_json, cli.verbose).await
            }
            CheckpointCommands::Verify { hash } => {
                commands::checkpoints::verify(&cli.nats_url, &hash, is_json).await
            }
        },
        Commands::Proofs(cmd) => match cmd {
            ProofCommands::Inclusion { hash, api_url } => {
                commands::proofs::inclusion(&hash, &api_url, is_json).await
            }
        },
        Commands::Trust(cmd) => match cmd {
            TrustCommands::Show { path } => {
                commands::trust::show(&path, is_json)
            }
            TrustCommands::Verify { hash, path } => {
                commands::trust::verify(&cli.nats_url, &hash, &path, is_json).await
            }
        },
    }
}
