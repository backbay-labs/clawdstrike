//! Parsing and verification of signed posture command envelopes; shared posture-transition helper.

use anyhow::Result;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::session::SessionManager;
use crate::settings::Settings;

use super::types::{CommandResponse, PostureCommand};

pub(super) fn parse_signed_posture_command_payload(
    payload: &[u8],
    trusted_issuer: Option<&str>,
) -> Result<PostureCommand> {
    let raw: Value = serde_json::from_slice(payload)?;
    let envelope = if raw.get("replayed").and_then(|v| v.as_bool()) == Some(true) {
        raw.get("envelope")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("replayed command missing envelope"))?
    } else {
        raw
    };

    if envelope.get("fact").is_none() {
        anyhow::bail!("posture command payload must be a signed envelope");
    }

    if !spine::verify_envelope(&envelope)? {
        anyhow::bail!("posture command signature verification failed");
    }

    let issuer = envelope
        .get("issuer")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("signed posture command missing issuer"))?;
    let expected = trusted_issuer
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing trusted posture command issuer"))?;
    if issuer != expected {
        anyhow::bail!("posture command issuer mismatch: expected {expected}, got {issuer}");
    }

    let fact = envelope
        .get("fact")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("signed posture command missing fact"))?;
    let cmd: PostureCommand = serde_json::from_value(fact)?;
    Ok(cmd)
}

pub(super) async fn transition_posture_command(
    session_manager: &SessionManager,
    settings: &RwLock<Settings>,
    to_state: &str,
    trigger: &str,
    success_message: String,
    no_session_message: String,
    failure_prefix: String,
) -> CommandResponse {
    let (daemon_url, api_key) = {
        let guard = settings.read().await;
        (guard.daemon_url(), guard.api_key.clone())
    };

    match session_manager
        .transition_current_session_posture(&daemon_url, api_key.as_deref(), to_state, trigger)
        .await
    {
        Ok(true) => CommandResponse {
            status: "ok".to_string(),
            message: Some(success_message),
        },
        Ok(false) => CommandResponse {
            status: "error".to_string(),
            message: Some(no_session_message),
        },
        Err(err) => CommandResponse {
            status: "error".to_string(),
            message: Some(format!("{failure_prefix}: {err}")),
        },
    }
}
