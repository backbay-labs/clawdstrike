//! Remote desktop side channel guard - controls clipboard, file transfer, audio, drive mapping,
//! printing, and session sharing.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for RemoteDesktopSideChannelGuard
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteDesktopSideChannelConfig {
    /// Enable/disable this guard.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Whether clipboard operations are allowed.
    #[serde(default = "default_enabled")]
    pub clipboard_enabled: bool,
    /// Whether file transfer operations are allowed.
    #[serde(default = "default_enabled")]
    pub file_transfer_enabled: bool,
    /// Whether session sharing is allowed.
    #[serde(default = "default_enabled")]
    pub session_share_enabled: bool,
    /// Whether remote audio channel is allowed.
    #[serde(default = "default_enabled")]
    pub audio_enabled: bool,
    /// Whether remote drive mapping channel is allowed.
    #[serde(default = "default_enabled")]
    pub drive_mapping_enabled: bool,
    /// Whether remote printing channel is allowed.
    #[serde(default = "default_enabled")]
    pub printing_enabled: bool,
    /// Maximum transfer size in bytes (for file_transfer). None means unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transfer_size_bytes: Option<u64>,
}

fn default_enabled() -> bool {
    true
}

impl Default for RemoteDesktopSideChannelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            clipboard_enabled: true,
            file_transfer_enabled: true,
            session_share_enabled: true,
            audio_enabled: true,
            drive_mapping_enabled: true,
            printing_enabled: true,
            max_transfer_size_bytes: None,
        }
    }
}

/// Guard that controls remote desktop side channels (clipboard, file transfer, session sharing).
///
/// Handles `GuardAction::Custom` where the custom type is one of:
/// - `"remote.clipboard"`
/// - `"remote.file_transfer"`
/// - `"remote.audio"`
/// - `"remote.drive_mapping"`
/// - `"remote.printing"`
/// - `"remote.session_share"`
pub struct RemoteDesktopSideChannelGuard {
    name: String,
    enabled: bool,
    config: RemoteDesktopSideChannelConfig,
}

impl RemoteDesktopSideChannelGuard {
    /// Create with default configuration.
    pub fn new() -> Self {
        Self::with_config(RemoteDesktopSideChannelConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: RemoteDesktopSideChannelConfig) -> Self {
        let enabled = config.enabled;
        Self {
            name: "remote_desktop_side_channel".to_string(),
            enabled,
            config,
        }
    }
}

impl Default for RemoteDesktopSideChannelGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for RemoteDesktopSideChannelGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        if !self.enabled {
            return false;
        }

        matches!(action, GuardAction::Custom(ct, _) if is_remote_side_channel_candidate(ct))
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.enabled {
            return GuardResult::allow(&self.name);
        }

        let (custom_type, data) = match action {
            GuardAction::Custom(ct, data) => (*ct, *data),
            _ => return GuardResult::allow(&self.name),
        };

        match custom_type {
            "remote.clipboard" => {
                if !self.config.clipboard_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "Clipboard operations are disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "clipboard",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            "remote.file_transfer" => {
                if !self.config.file_transfer_enabled {
                    return GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "File transfer operations are disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "file_transfer",
                        "reason": "channel_disabled",
                    }));
                }

                // Check transfer size if configured
                if let Some(max_size) = self.config.max_transfer_size_bytes {
                    let transfer_size_value = data
                        .get("transfer_size")
                        .or_else(|| data.get("transferSize"));
                    let transfer_size = match transfer_size_value {
                        Some(value) => match value.as_u64() {
                            Some(size) => size,
                            None => {
                                return GuardResult::block(
                                    &self.name,
                                    Severity::Error,
                                    "File transfer size must be an unsigned integer in bytes",
                                )
                                .with_details(serde_json::json!({
                                    "channel": "file_transfer",
                                    "reason": "invalid_transfer_size_type",
                                }));
                            }
                        },
                        None => {
                            return GuardResult::block(
                                &self.name,
                                Severity::Error,
                                "File transfer size is required when max_transfer_size_bytes is configured",
                            )
                            .with_details(serde_json::json!({
                                "channel": "file_transfer",
                                "reason": "missing_transfer_size",
                            }));
                        }
                    };

                    if transfer_size > max_size {
                        return GuardResult::block(
                            &self.name,
                            Severity::Error,
                            format!(
                                "File transfer size {} bytes exceeds maximum {} bytes",
                                transfer_size, max_size
                            ),
                        )
                        .with_details(serde_json::json!({
                            "channel": "file_transfer",
                            "reason": "transfer_size_exceeded",
                            "transfer_size": transfer_size,
                            "max_size": max_size,
                        }));
                    }
                }

                GuardResult::allow(&self.name)
            }
            "remote.session_share" => {
                if !self.config.session_share_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "Session sharing is disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "session_share",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            "remote.audio" => {
                if !self.config.audio_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "Remote audio channel is disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "audio",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            "remote.drive_mapping" => {
                if !self.config.drive_mapping_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "Drive mapping is disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "drive_mapping",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            "remote.printing" => {
                if !self.config.printing_enabled {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        "Remote printing is disabled by policy",
                    )
                    .with_details(serde_json::json!({
                        "channel": "printing",
                        "reason": "channel_disabled",
                    }))
                } else {
                    GuardResult::allow(&self.name)
                }
            }
            _ => GuardResult::block(
                &self.name,
                Severity::Error,
                format!(
                    "Unknown side channel type '{}' denied by fail-closed policy",
                    custom_type
                ),
            )
            .with_details(serde_json::json!({
                "channel": custom_type,
                "reason": "unknown_channel_type",
            })),
        }
    }
}

fn is_remote_side_channel_candidate(custom_type: &str) -> bool {
    if !custom_type.starts_with("remote.") {
        return false;
    }

    !matches!(
        custom_type,
        "remote.session.connect" | "remote.session.disconnect" | "remote.session.reconnect"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handles_side_channel_actions() {
        let guard = RemoteDesktopSideChannelGuard::new();
        let data = serde_json::json!({});

        assert!(guard.handles(&GuardAction::Custom("remote.clipboard", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.file_transfer", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.audio", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.drive_mapping", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.printing", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.session_share", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.webrtc", &data)));
    }

    #[test]
    fn test_does_not_handle_other_actions() {
        let guard = RemoteDesktopSideChannelGuard::new();
        let data = serde_json::json!({});

        assert!(!guard.handles(&GuardAction::Custom("remote.session.connect", &data)));
        assert!(!guard.handles(&GuardAction::Custom("input.inject", &data)));
        assert!(!guard.handles(&GuardAction::FileAccess("/tmp/file")));
    }

    #[tokio::test]
    async fn test_allows_when_all_channels_enabled() {
        let guard = RemoteDesktopSideChannelGuard::new();
        let context = GuardContext::new();
        let data = serde_json::json!({});

        let result = guard
            .check(&GuardAction::Custom("remote.clipboard", &data), &context)
            .await;
        assert!(result.allowed);

        let result = guard
            .check(
                &GuardAction::Custom("remote.file_transfer", &data),
                &context,
            )
            .await;
        assert!(result.allowed);

        let result = guard
            .check(
                &GuardAction::Custom("remote.session_share", &data),
                &context,
            )
            .await;
        assert!(result.allowed);

        let result = guard
            .check(&GuardAction::Custom("remote.audio", &data), &context)
            .await;
        assert!(result.allowed);

        let result = guard
            .check(
                &GuardAction::Custom("remote.drive_mapping", &data),
                &context,
            )
            .await;
        assert!(result.allowed);

        let result = guard
            .check(&GuardAction::Custom("remote.printing", &data), &context)
            .await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_denies_clipboard_when_disabled() {
        let config = RemoteDesktopSideChannelConfig {
            clipboard_enabled: false,
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let context = GuardContext::new();
        let data = serde_json::json!({});

        let result = guard
            .check(&GuardAction::Custom("remote.clipboard", &data), &context)
            .await;
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_denies_file_transfer_exceeding_size() {
        let config = RemoteDesktopSideChannelConfig {
            max_transfer_size_bytes: Some(1024),
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let context = GuardContext::new();
        let data = serde_json::json!({"transfer_size": 2048});

        let result = guard
            .check(
                &GuardAction::Custom("remote.file_transfer", &data),
                &context,
            )
            .await;
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_allows_file_transfer_within_size() {
        let config = RemoteDesktopSideChannelConfig {
            max_transfer_size_bytes: Some(4096),
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let context = GuardContext::new();
        let data = serde_json::json!({"transfer_size": 1024});

        let result = guard
            .check(
                &GuardAction::Custom("remote.file_transfer", &data),
                &context,
            )
            .await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_denies_audio_when_disabled() {
        let config = RemoteDesktopSideChannelConfig {
            audio_enabled: false,
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let context = GuardContext::new();
        let data = serde_json::json!({});

        let result = guard
            .check(&GuardAction::Custom("remote.audio", &data), &context)
            .await;
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_denies_unknown_remote_side_channel_fail_closed() {
        let guard = RemoteDesktopSideChannelGuard::new();
        let context = GuardContext::new();
        let data = serde_json::json!({});

        assert!(guard.handles(&GuardAction::Custom("remote.webrtc", &data)));
        let result = guard
            .check(&GuardAction::Custom("remote.webrtc", &data), &context)
            .await;
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_allows_camel_case_transfer_size_within_limit() {
        let config = RemoteDesktopSideChannelConfig {
            max_transfer_size_bytes: Some(4096),
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let context = GuardContext::new();
        let data = serde_json::json!({"transferSize": 1024});

        let result = guard
            .check(
                &GuardAction::Custom("remote.file_transfer", &data),
                &context,
            )
            .await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_denies_file_transfer_with_invalid_transfer_size_type() {
        let config = RemoteDesktopSideChannelConfig {
            max_transfer_size_bytes: Some(4096),
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let context = GuardContext::new();
        let data = serde_json::json!({"transfer_size": "1024"});

        let result = guard
            .check(
                &GuardAction::Custom("remote.file_transfer", &data),
                &context,
            )
            .await;
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_denies_file_transfer_when_size_missing_and_limit_set() {
        let config = RemoteDesktopSideChannelConfig {
            max_transfer_size_bytes: Some(4096),
            ..Default::default()
        };
        let guard = RemoteDesktopSideChannelGuard::with_config(config);
        let context = GuardContext::new();
        let data = serde_json::json!({});

        let result = guard
            .check(
                &GuardAction::Custom("remote.file_transfer", &data),
                &context,
            )
            .await;
        assert!(!result.allowed);
    }
}
