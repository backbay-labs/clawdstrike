use std::collections::HashMap;
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
            std::env::var("AUDIT_SUBJECT_FILTER").unwrap_or_else(|_| ">".to_string());
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
            .unwrap_or_else(|_| default_adaptive_ingress_stream_name());
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
            .unwrap_or_else(|_| default_adaptive_ingress_stream_name());
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

        validate_consumer_stream_configuration(
            approval_consumer_enabled,
            heartbeat_consumer_enabled,
            &approval_subject_filter,
            &heartbeat_subject_filter,
            &approval_stream_name,
            &heartbeat_stream_name,
        )?;

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
    "tenant-*.>".to_string()
}

fn default_heartbeat_subject_filter() -> String {
    "tenant-*.>".to_string()
}

fn default_adaptive_ingress_stream_name() -> String {
    "clawdstrike_adaptive_ingress".to_string()
}

fn validate_consumer_stream_configuration(
    approval_consumer_enabled: bool,
    heartbeat_consumer_enabled: bool,
    approval_subject_filter: &str,
    heartbeat_subject_filter: &str,
    approval_stream_name: &str,
    heartbeat_stream_name: &str,
) -> Result<(), ConfigError> {
    if !approval_consumer_enabled || !heartbeat_consumer_enabled {
        return Ok(());
    }

    let filters_overlap =
        subject_filters_overlap(approval_subject_filter, heartbeat_subject_filter);
    if !filters_overlap {
        return Ok(());
    }

    if approval_stream_name == heartbeat_stream_name {
        return Ok(());
    }

    Err(ConfigError::InvalidConfig(format!(
        "APPROVAL_SUBJECT_FILTER ({approval_subject_filter}) overlaps HEARTBEAT_SUBJECT_FILTER ({heartbeat_subject_filter}) \
         while APPROVAL_STREAM_NAME ({approval_stream_name}) and HEARTBEAT_STREAM_NAME ({heartbeat_stream_name}) differ; \
         use non-overlapping filters or a shared stream name"
    )))
}

fn subject_filters_overlap(left: &str, right: &str) -> bool {
    let left_tokens: Vec<&str> = left
        .trim()
        .split('.')
        .filter(|token| !token.is_empty())
        .collect();
    let right_tokens: Vec<&str> = right
        .trim()
        .split('.')
        .filter(|token| !token.is_empty())
        .collect();

    if left_tokens.is_empty() || right_tokens.is_empty() {
        return false;
    }

    let mut memo = HashMap::new();
    subject_filter_tokens_overlap(&left_tokens, &right_tokens, 0, 0, &mut memo)
}

fn subject_filter_tokens_overlap(
    left: &[&str],
    right: &[&str],
    left_idx: usize,
    right_idx: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(cached) = memo.get(&(left_idx, right_idx)) {
        return *cached;
    }

    let result = if left_idx == left.len() && right_idx == right.len() {
        true
    } else if left_idx == left.len() {
        // Conservative overlap detection: if either side has a trailing `>`
        // wildcard, treat it as potentially overlapping at token boundaries.
        right[right_idx..].contains(&">")
    } else if right_idx == right.len() {
        // Conservative overlap detection: if either side has a trailing `>`
        // wildcard, treat it as potentially overlapping at token boundaries.
        left[left_idx..].contains(&">")
    } else {
        let left_token = left[left_idx];
        let right_token = right[right_idx];

        if left_token == ">" && right_token == ">" {
            true
        } else if left_token == ">" {
            subject_filter_tokens_overlap(left, right, left_idx, right_idx + 1, memo)
                || subject_filter_tokens_overlap(left, right, left_idx + 1, right_idx + 1, memo)
        } else if right_token == ">" {
            subject_filter_tokens_overlap(left, right, left_idx + 1, right_idx, memo)
                || subject_filter_tokens_overlap(left, right, left_idx + 1, right_idx + 1, memo)
        } else if token_patterns_overlap(left_token, right_token) {
            subject_filter_tokens_overlap(left, right, left_idx + 1, right_idx + 1, memo)
        } else {
            false
        }
    };

    memo.insert((left_idx, right_idx), result);
    result
}

fn token_patterns_overlap(left: &str, right: &str) -> bool {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let mut memo = HashMap::new();
    token_glob_overlap(left_bytes, right_bytes, 0, 0, &mut memo)
}

fn token_glob_overlap(
    left: &[u8],
    right: &[u8],
    left_idx: usize,
    right_idx: usize,
    memo: &mut HashMap<(usize, usize), bool>,
) -> bool {
    if let Some(cached) = memo.get(&(left_idx, right_idx)) {
        return *cached;
    }

    let result = if left_idx == left.len() && right_idx == right.len() {
        true
    } else if left_idx == left.len() {
        right[right_idx..].iter().all(|c| *c == b'*')
    } else if right_idx == right.len() {
        left[left_idx..].iter().all(|c| *c == b'*')
    } else {
        let left_char = left[left_idx];
        let right_char = right[right_idx];

        if left_char == b'*' && right_char == b'*' {
            token_glob_overlap(left, right, left_idx + 1, right_idx, memo)
                || token_glob_overlap(left, right, left_idx, right_idx + 1, memo)
                || token_glob_overlap(left, right, left_idx + 1, right_idx + 1, memo)
        } else if left_char == b'*' {
            token_glob_overlap(left, right, left_idx + 1, right_idx, memo)
                || token_glob_overlap(left, right, left_idx, right_idx + 1, memo)
        } else if right_char == b'*' {
            token_glob_overlap(left, right, left_idx, right_idx + 1, memo)
                || token_glob_overlap(left, right, left_idx + 1, right_idx, memo)
        } else if left_char == right_char {
            token_glob_overlap(left, right, left_idx + 1, right_idx + 1, memo)
        } else {
            false
        }
    };

    memo.insert((left_idx, right_idx), result);
    result
}

#[cfg(test)]
mod tests {
    use super::{
        default_adaptive_ingress_stream_name, default_approval_subject_filter,
        default_heartbeat_subject_filter, subject_filters_overlap,
        validate_consumer_stream_configuration,
    };

    #[test]
    fn default_approval_subject_filter_is_valid() {
        assert_eq!(default_approval_subject_filter(), "tenant-*.>");
    }

    #[test]
    fn default_heartbeat_subject_filter_is_valid() {
        assert_eq!(default_heartbeat_subject_filter(), "tenant-*.>");
    }

    #[test]
    fn default_ingress_stream_name_is_shared_between_consumers() {
        assert_eq!(
            default_adaptive_ingress_stream_name(),
            "clawdstrike_adaptive_ingress"
        );
    }

    #[test]
    fn shared_stream_allows_overlapping_filters() {
        let result = validate_consumer_stream_configuration(
            true,
            true,
            ">",
            ">",
            "clawdstrike_ingress",
            "clawdstrike_ingress",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn separate_streams_reject_overlapping_filters() {
        let result = validate_consumer_stream_configuration(
            true,
            true,
            ">",
            "tenant-*.>",
            "approval-stream",
            "heartbeat-stream",
        );
        assert!(result.is_err());
    }

    #[test]
    fn overlap_detection_handles_wildcard_patterns() {
        assert!(subject_filters_overlap(
            "tenant-*.>",
            "tenant-*.clawdstrike.agent.heartbeat.*"
        ));
        assert!(subject_filters_overlap("a.b", "a.>"));
        assert!(subject_filters_overlap("a.>", "a.b"));
    }
}
