use std::net::SocketAddr;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub database_url: String,
    pub nats_url: String,
    pub nats_provisioning_mode: String,
    pub nats_provisioner_base_url: Option<String>,
    pub nats_provisioner_api_token: Option<String>,
    pub nats_allow_insecure_mock_provisioner: bool,
    pub jwt_secret: String,
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,
    pub approval_signing_enabled: bool,
    pub approval_signing_keypair_path: Option<String>,
    pub approval_resolution_outbox_enabled: bool,
    pub approval_resolution_outbox_poll_interval_secs: u64,
    pub audit_consumer_enabled: bool,
    pub audit_subject_filter: String,
    pub audit_stream_name: String,
    pub audit_consumer_name: String,
    pub approval_consumer_enabled: bool,
    pub approval_subject_filter: String,
    pub approval_stream_name: String,
    pub approval_consumer_name: String,
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
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
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
        let nats_provisioning_mode =
            std::env::var("NATS_PROVISIONING_MODE").unwrap_or_else(|_| "external".to_string());
        let nats_provisioner_base_url = std::env::var("NATS_PROVISIONER_BASE_URL").ok();
        let nats_provisioner_api_token = std::env::var("NATS_PROVISIONER_API_TOKEN").ok();
        let nats_allow_insecure_mock_provisioner =
            std::env::var("NATS_ALLOW_INSECURE_MOCK_PROVISIONER")
                .ok()
                .as_deref()
                .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false);
        match nats_provisioning_mode.trim().to_ascii_lowercase().as_str() {
            "external" => {}
            "mock" => {
                if !nats_allow_insecure_mock_provisioner {
                    return Err(ConfigError::InvalidConfig(
                        "NATS_PROVISIONING_MODE=mock requires NATS_ALLOW_INSECURE_MOCK_PROVISIONER=true"
                            .to_string(),
                    ));
                }
            }
            other => {
                return Err(ConfigError::InvalidConfig(format!(
                    "unsupported NATS_PROVISIONING_MODE '{other}' (expected 'external' or 'mock')"
                )));
            }
        }
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
            .unwrap_or(true);
        let approval_signing_keypair_path = std::env::var("APPROVAL_SIGNING_KEYPAIR_PATH").ok();
        let approval_resolution_outbox_enabled =
            std::env::var("APPROVAL_RESOLUTION_OUTBOX_ENABLED")
                .ok()
                .as_deref()
                .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(true);
        let approval_resolution_outbox_poll_interval_secs =
            std::env::var("APPROVAL_RESOLUTION_OUTBOX_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5);
        let audit_consumer_enabled = std::env::var("AUDIT_CONSUMER_ENABLED")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let audit_subject_filter =
            std::env::var("AUDIT_SUBJECT_FILTER").unwrap_or_else(|_| "tenant-*.>".to_string());
        let audit_stream_name =
            std::env::var("AUDIT_STREAM_NAME").unwrap_or_else(|_| "clawdstrike_audit".to_string());
        let audit_consumer_name = std::env::var("AUDIT_CONSUMER_NAME")
            .unwrap_or_else(|_| "clawdstrike_audit_consumer".to_string());
        let approval_consumer_enabled = std::env::var("APPROVAL_CONSUMER_ENABLED")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(true);
        let approval_subject_filter = std::env::var("APPROVAL_SUBJECT_FILTER")
            .unwrap_or_else(|_| default_approval_subject_filter());
        let approval_stream_name = std::env::var("APPROVAL_STREAM_NAME")
            .unwrap_or_else(|_| "clawdstrike_approval_requests".to_string());
        let approval_consumer_name = std::env::var("APPROVAL_CONSUMER_NAME")
            .unwrap_or_else(|_| "clawdstrike_approval_request_consumer".to_string());
        let heartbeat_consumer_enabled = std::env::var("HEARTBEAT_CONSUMER_ENABLED")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(true);
        let heartbeat_subject_filter = std::env::var("HEARTBEAT_SUBJECT_FILTER")
            .unwrap_or_else(|_| default_heartbeat_subject_filter());
        let heartbeat_stream_name = std::env::var("HEARTBEAT_STREAM_NAME")
            .unwrap_or_else(|_| "clawdstrike_agent_heartbeats".to_string());
        let heartbeat_consumer_name = std::env::var("HEARTBEAT_CONSUMER_NAME")
            .unwrap_or_else(|_| "clawdstrike_agent_heartbeat_consumer".to_string());
        let stale_detector_enabled = std::env::var("STALE_DETECTOR_ENABLED")
            .ok()
            .as_deref()
            .map(|v| matches!(v, "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(true);
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
            nats_provisioning_mode,
            nats_provisioner_base_url,
            nats_provisioner_api_token,
            nats_allow_insecure_mock_provisioner,
            jwt_secret,
            stripe_secret_key,
            stripe_webhook_secret,
            approval_signing_enabled,
            approval_signing_keypair_path,
            approval_resolution_outbox_enabled,
            approval_resolution_outbox_poll_interval_secs,
            audit_consumer_enabled,
            audit_subject_filter,
            audit_stream_name,
            audit_consumer_name,
            approval_consumer_enabled,
            approval_subject_filter,
            approval_stream_name,
            approval_consumer_name,
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

fn default_approval_subject_filter() -> String {
    "tenant-*.clawdstrike.approval.request.*".to_string()
}

fn default_heartbeat_subject_filter() -> String {
    "tenant-*.clawdstrike.agent.heartbeat.*".to_string()
}

#[cfg(test)]
mod tests {
    use super::{default_approval_subject_filter, default_heartbeat_subject_filter};

    #[test]
    fn default_approval_subject_filter_is_scoped_to_request_shape() {
        assert_eq!(
            default_approval_subject_filter(),
            "tenant-*.clawdstrike.approval.request.*"
        );
    }

    #[test]
    fn default_heartbeat_subject_filter_is_scoped_to_heartbeat_shape() {
        assert_eq!(
            default_heartbeat_subject_filter(),
            "tenant-*.clawdstrike.agent.heartbeat.*"
        );
    }
}
