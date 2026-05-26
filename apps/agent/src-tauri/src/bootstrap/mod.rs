//! Agent runtime orchestrator.
//!
//! [`run_agent`] wires together every subsystem the agent depends on (NATS,
//! daemon manager, MCP/API servers, approval queues, event consumers, etc.).
//! It runs inside the tauri async runtime and is the actual "main" of the
//! agent process — `fn main` only handles tauri builder setup and platform
//! event listeners.
//!
//! Submodules host the larger pieces — NATS bootstrap, event-loop spawns,
//! tauri-listener registration — so the top-level orchestrator stays
//! readable.

mod event_loops;
mod listeners;
mod nats;
mod run;

pub(crate) use run::run_agent;

use crate::daemon::AuditFlushProgressError;
use crate::settings::NatsSettings;

pub(crate) fn log_audit_flush_failure(err: &anyhow::Error, message: &'static str) {
    if let Some(progress) = err.downcast_ref::<AuditFlushProgressError>() {
        tracing::warn!(
            error = %progress.message,
            count = progress.outcome.accepted,
            duplicates = progress.outcome.duplicates,
            rejected = progress.outcome.rejected,
            "{} after partial progress",
            message
        );
    } else {
        tracing::warn!(error = %err, "{}", message);
    }
}

pub(crate) fn validate_nats_security_settings(
    nats: &NatsSettings,
) -> std::result::Result<(), String> {
    if !nats.require_signed_approval_responses {
        return Err(
            "NATS approval sync requires signed responses; unsigned mode is disabled".to_string(),
        );
    }

    let trusted_issuer = nats
        .approval_response_trusted_issuer
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if trusted_issuer.is_none() {
        return Err(
            "NATS is enabled but no trusted approval response issuer is configured".to_string(),
        );
    }

    Ok(())
}

pub(crate) fn is_nats_auth_failure(error_message: &str) -> bool {
    let lower = error_message.to_ascii_lowercase();
    if lower.contains("certificate authentication failed")
        || lower.contains("authentication handshake timeout")
    {
        return false;
    }

    [
        "authorization violation",
        "permissions violation",
        "authentication failed",
        "authorization failed",
        "invalid credentials",
        "invalid token",
        "invalid jwt",
        "user authentication expired",
        "authentication error",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::is_nats_auth_failure;

    #[test]
    fn nats_auth_error_detection_matches_expected_strings() {
        assert!(is_nats_auth_failure("Authorization Violation"));
        assert!(is_nats_auth_failure("user authentication expired"));
        assert!(is_nats_auth_failure("authentication failed"));
        assert!(!is_nats_auth_failure("connection refused"));
        assert!(!is_nats_auth_failure("dial tcp timeout"));
        assert!(!is_nats_auth_failure("authentication handshake timeout"));
        assert!(!is_nats_auth_failure(
            "tls: certificate authentication failed during renegotiation"
        ));
    }
}
