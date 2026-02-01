//! Hushd - Hushclaw security daemon
//!
//! This daemon provides:
//! - HTTP API for action checking
//! - Policy management and hot-reload
//! - SQLite audit ledger
//! - SSE event streaming

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use hushd::api;
use hushd::config::Config;
use hushd::state::AppState;

#[derive(Parser)]
#[command(name = "hushd")]
#[command(about = "Hushclaw security daemon", long_about = None)]
#[command(version)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Path to configuration file
    #[arg(short, long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon (default)
    Start {
        /// Bind address
        #[arg(short, long)]
        bind: Option<String>,

        /// Port
        #[arg(short, long)]
        port: Option<u16>,

        /// Ruleset to use
        #[arg(short, long)]
        ruleset: Option<String>,
    },

    /// Show daemon status
    Status {
        /// Daemon URL
        #[arg(default_value = "http://127.0.0.1:9876")]
        url: String,
    },

    /// Show effective configuration
    ShowConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let mut config = if let Some(ref path) = cli.config {
        Config::from_file(path)?
    } else {
        Config::load_default()
    };

    // Override log level from CLI
    let log_level = match cli.verbose {
        0 => config.tracing_level(),
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            log_level,
        ))
        .init();

    match cli.command {
        None | Some(Commands::Start { .. }) => {
            // Apply CLI overrides
            if let Some(Commands::Start {
                bind,
                port,
                ruleset,
            }) = cli.command
            {
                if let Some(bind) = bind {
                    if let Some(port) = port {
                        config.listen = format!("{}:{}", bind, port);
                    } else {
                        let current_port = config.listen.split(':').last().unwrap_or("9876");
                        config.listen = format!("{}:{}", bind, current_port);
                    }
                } else if let Some(port) = port {
                    let current_host = config.listen.split(':').next().unwrap_or("127.0.0.1");
                    config.listen = format!("{}:{}", current_host, port);
                }
                if let Some(ruleset) = ruleset {
                    config.ruleset = ruleset;
                }
            }

            run_daemon(config).await
        }

        Some(Commands::Status { url }) => check_status(&url).await,

        Some(Commands::ShowConfig) => {
            let yaml = serde_yaml::to_string(&config)?;
            println!("{}", yaml);
            Ok(())
        }
    }
}

async fn run_daemon(config: Config) -> anyhow::Result<()> {
    tracing::info!(
        listen = %config.listen,
        ruleset = %config.ruleset,
        audit_db = %config.audit_db.display(),
        "Starting hushd"
    );

    // Create application state
    let state = AppState::new(config.clone()).await?;

    // Create router
    let app = api::create_router(state.clone());

    // Parse listen address
    let addr: SocketAddr = config.listen.parse()?;

    // Create listener
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(address = %addr, "Listening");

    // Setup signal handlers for graceful shutdown
    let shutdown_signal = async {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }

        tracing::info!("Shutdown signal received");
    };

    // Run server
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Log final stats
    let engine = state.engine.read().await;
    let stats = engine.stats().await;
    tracing::info!(
        actions = stats.action_count,
        violations = stats.violation_count,
        uptime_secs = state.uptime_secs(),
        "Daemon stopped"
    );

    Ok(())
}

async fn check_status(url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client.get(format!("{}/health", url)).send().await?;

    if resp.status().is_success() {
        let health: api::HealthResponse = resp.json().await?;
        println!("Status: {}", health.status);
        println!("Version: {}", health.version);
        println!("Uptime: {}s", health.uptime_secs);
        println!("Session: {}", health.session_id);
        println!("Audit events: {}", health.audit_count);
    } else {
        println!("Error: {} {}", resp.status(), resp.text().await?);
    }

    Ok(())
}
