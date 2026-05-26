//! Common scalar helpers shared across the OpenClaw submodules.

use super::protocol::GatewayResponseError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis() as u64
}

pub(super) fn normalize_gateway_error(
    error: Option<GatewayResponseError>,
    fallback: &str,
) -> String {
    error
        .and_then(|e| {
            if e.message.trim().is_empty() {
                None
            } else {
                Some(e.message)
            }
        })
        .unwrap_or_else(|| fallback.to_string())
}

pub(super) fn normalize_secret_field(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}
