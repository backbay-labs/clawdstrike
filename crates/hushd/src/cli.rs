//! Hushd CLI entrypoint.

use std::net::SocketAddr;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::api;
use crate::audit::{AuditEvent, SessionStats};
use crate::config::Config;
use crate::siem::types::SecurityEvent;
use crate::state::AppState;
use crate::tls::{TlsConnectInfo, TlsListener};

fn normalize_host_for_listen(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

fn parse_listen_host_port(listen: &str) -> anyhow::Result<(String, u16)> {
    let listen = listen.trim();

    if let Ok(addr) = listen.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }

    if let Some(rest) = listen.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| {
            anyhow::anyhow!("Invalid listen address {listen:?}: missing closing ']'")
        })?;
        let host = &rest[..end];
        let port_str = rest[end + 1..].strip_prefix(':').ok_or_else(|| {
            anyhow::anyhow!("Invalid listen address {listen:?}: expected :PORT after ]")
        })?;
        let port: u16 = port_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid listen address {listen:?}: invalid port: {e}"))?;
        return Ok((host.to_string(), port));
    }

    let idx = listen
        .rfind(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid listen address {listen:?}: expected HOST:PORT"))?;
    let host = &listen[..idx];
    let port_str = &listen[idx + 1..];
    let port: u16 = port_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid listen address {listen:?}: invalid port: {e}"))?;
    Ok((host.to_string(), port))
}

fn format_listen(host: &str, port: u16) -> String {
    let host = normalize_host_for_listen(host);
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Parser)]
#[command(about = "Clawdstrike security daemon", long_about = None)]
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

fn parse_cli(bin_name: &'static str) -> Cli {
    let matches = Cli::command()
        .name(bin_name)
        .bin_name(bin_name)
        .get_matches();
    match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    }
}

pub async fn run_bin(bin_name: &'static str) -> anyhow::Result<()> {
    run(parse_cli(bin_name)).await
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    // Load configuration
    let mut config = if let Some(ref path) = cli.config {
        Config::from_file(path)?
    } else {
        Config::load_default()?
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
                    let port = match port {
                        Some(p) => p,
                        None => parse_listen_host_port(&config.listen)?.1,
                    };
                    config.listen = format_listen(&bind, port);
                } else if let Some(port) = port {
                    let host = parse_listen_host_port(&config.listen)?.0;
                    config.listen = format_listen(&host, port);
                }
                if let Some(ruleset) = ruleset {
                    config.ruleset = ruleset;
                }
            }

            config.validate()?;
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
        tls = %config.tls.is_some(),
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

    // Notify systemd that the daemon is ready (Type=notify).
    #[cfg(feature = "systemd")]
    {
        sd_notify::notify(true, &[sd_notify::NotifyState::Ready]).ok();
        tracing::info!("sd_notify: READY=1 sent");
    }

    // Spawn periodic watchdog heartbeat for systemd WatchdogSec.
    #[cfg(feature = "systemd")]
    tokio::spawn(async {
        let interval = std::time::Duration::from_secs(15);
        loop {
            sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]).ok();
            tokio::time::sleep(interval).await;
        }
    });

    // Handle SIGHUP for policy reload (systemd ExecReload).
    #[cfg(unix)]
    {
        let state = state.clone();
        tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(mut signal) => {
                    while signal.recv().await.is_some() {
                        tracing::info!("SIGHUP received: reloading policy");
                        if let Err(err) = state.reload_policy().await {
                            tracing::error!(error = %err, "Policy reload failed");
                        }
                    }
                }
                Err(err) => {
                    tracing::error!(error = %err, "Failed to install SIGHUP handler");
                }
            }
        });
    }

    // Setup signal handlers for graceful shutdown
    let shutdown_notify = state.shutdown.clone();
    let shutdown_signal = async move {
        let ctrl_c = async {
            if let Err(err) = tokio::signal::ctrl_c().await {
                tracing::error!(error = %err, "Failed to install Ctrl+C handler");
                std::future::pending::<()>().await;
            }
        };

        #[cfg(unix)]
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(err) => {
                    tracing::error!(error = %err, "Failed to install SIGTERM handler");
                    std::future::pending::<()>().await;
                }
            }
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        let shutdown_requested = async move {
            shutdown_notify.notified().await;
        };

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
            _ = shutdown_requested => {},
        }

        tracing::info!("Shutdown signal received");
    };

    // Run server
    if let Some(ref tls) = config.tls {
        let tls_listener = TlsListener::new(listener, tls)?;
        axum::serve(
            tls_listener,
            app.into_make_service_with_connect_info::<TlsConnectInfo>(),
        )
        .with_graceful_shutdown(shutdown_signal)
        .await?;
    } else {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal)
        .await?;
    }

    // Log final stats
    let engine = state.engine.read().await;
    let stats = engine.stats().await;

    // Record session end to the audit ledger and SIEM stream.
    let end_event = AuditEvent::session_end(
        &state.session_id,
        &SessionStats {
            action_count: stats.action_count,
            violation_count: stats.violation_count,
            duration_secs: state.uptime_secs().max(0) as u64,
        },
    );
    if let Err(err) = state.ledger.record(&end_event) {
        tracing::warn!(error = %err, "Failed to record session_end audit event");
    } else {
        let ctx = state.security_ctx.read().await.clone();
        let end_security_event = SecurityEvent::from_audit_event(&end_event, &ctx);
        state.emit_security_event(end_security_event);
    }

    state.shutdown_background_tasks().await;

    tracing::info!(
        actions = stats.action_count,
        violations = stats.violation_count,
        uptime_secs = state.uptime_secs(),
        "Daemon stopped"
    );
    drop(engine);

    // Record session end.
    let duration_secs = u64::try_from(state.uptime_secs()).unwrap_or_default();
    let session_stats = crate::audit::SessionStats {
        action_count: stats.action_count,
        violation_count: stats.violation_count,
        duration_secs,
    };
    state.record_audit_event(crate::audit::AuditEvent::session_end(
        &state.session_id,
        &session_stats,
    ));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listen_host_port_handles_ipv6() {
        let (host, port) = parse_listen_host_port("[::1]:9876").expect("parse");
        assert_eq!(host, "::1");
        assert_eq!(port, 9876);
    }

    #[test]
    fn parse_listen_host_port_handles_hostname() {
        let (host, port) = parse_listen_host_port("localhost:9876").expect("parse");
        assert_eq!(host, "localhost");
        assert_eq!(port, 9876);
    }

    #[test]
    fn format_listen_brackets_ipv6_hosts() {
        assert_eq!(format_listen("::1", 9876), "[::1]:9876");
        assert_eq!(format_listen("[::1]", 9876), "[::1]:9876");
    }
}
