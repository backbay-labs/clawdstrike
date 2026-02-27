use std::net::SocketAddr;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub database_url: String,
    pub nats_url: String,
    pub jwt_secret: String,
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
    pub approval_signing_enabled: bool,
    pub approval_signing_keypair_path: Option<String>,
    pub audit_consumer_enabled: bool,
    pub audit_subject_filter: String,
    pub audit_stream_name: String,
    pub audit_consumer_name: String,
    pub heartbeat_consumer_enabled: bool,
    pub heartbeat_subject_filter: String,
    pub heartbeat_stream_name: String,
    pub heartbeat_consumer_name: String,
    pub stale_detector_enabled: bool,
    pub stale_check_interval_secs: u64,
    pub stale_threshold_secs: i64,
    pub dead_threshold_secs: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing environment variable: {0}")]
    MissingVar(String),
    #[error("invalid listen address: {0}")]
    InvalidAddr(#[from] std::net::AddrParseError),
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen_addr = std::env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse::<SocketAddr>()?;

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| ConfigError::MissingVar("DATABASE_URL".into()))?;
        let nats_url =
            std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
        let jwt_secret = std::env::var("JWT_SECRET")
            .map_err(|_| ConfigError::MissingVar("JWT_SECRET".into()))?;
        let stripe_secret_key = std::env::var("STRIPE_SECRET_KEY")
            .map_err(|_| ConfigError::MissingVar("STRIPE_SECRET_KEY".into()))?;
        let stripe_webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET")
            .map_err(|_| ConfigError::MissingVar("STRIPE_WEBHOOK_SECRET".into()))?;
        let approval_signing_enabled = std::env::var("APPROVAL_SIGNING_ENABLED")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let approval_signing_keypair_path = std::env::var("APPROVAL_SIGNING_KEYPAIR_PATH").ok();
        let audit_consumer_enabled = std::env::var("AUDIT_CONSUMER_ENABLED")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let audit_subject_filter = std::env::var("AUDIT_SUBJECT_FILTER")
            .unwrap_or_else(|_| "tenant-*.clawdstrike.>".to_string());
        let audit_stream_name =
            std::env::var("AUDIT_STREAM_NAME").unwrap_or_else(|_| "clawdstrike_audit".to_string());
        let audit_consumer_name = std::env::var("AUDIT_CONSUMER_NAME")
            .unwrap_or_else(|_| "clawdstrike_audit_consumer".to_string());
        let heartbeat_consumer_enabled = std::env::var("HEARTBEAT_CONSUMER_ENABLED")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(true);
        let heartbeat_subject_filter = std::env::var("HEARTBEAT_SUBJECT_FILTER")
            .unwrap_or_else(|_| "tenant-*.clawdstrike.agent.heartbeat.*".to_string());
        let heartbeat_stream_name = std::env::var("HEARTBEAT_STREAM_NAME")
            .unwrap_or_else(|_| "clawdstrike_agent_heartbeats".to_string());
        let heartbeat_consumer_name = std::env::var("HEARTBEAT_CONSUMER_NAME")
            .unwrap_or_else(|_| "clawdstrike_agent_heartbeat_consumer".to_string());
        let stale_detector_enabled = std::env::var("STALE_DETECTOR_ENABLED")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let stale_check_interval_secs = std::env::var("STALE_CHECK_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        let stale_threshold_secs = std::env::var("STALE_THRESHOLD_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(120);
        let dead_threshold_secs = std::env::var("DEAD_THRESHOLD_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(300);

        Ok(Self {
            listen_addr,
            database_url,
            nats_url,
            jwt_secret,
            stripe_secret_key,
            stripe_webhook_secret,
            approval_signing_enabled,
            approval_signing_keypair_path,
            audit_consumer_enabled,
            audit_subject_filter,
            audit_stream_name,
            audit_consumer_name,
            heartbeat_consumer_enabled,
            heartbeat_subject_filter,
            heartbeat_stream_name,
            heartbeat_consumer_name,
            stale_detector_enabled,
            stale_check_interval_secs,
            stale_threshold_secs,
            dead_threshold_secs,
        })
    }
}
