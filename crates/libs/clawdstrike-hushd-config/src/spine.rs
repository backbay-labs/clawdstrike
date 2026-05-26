//! Spine attestation log (NATS JetStream) configuration.
//!
//! Mirrors `hushd::config::SpineConfig`. Both the desktop agent's writer
//! and the daemon's reader pull this type from `clawdstrike-hushd-config`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Spine attestation log configuration written by the agent and read by hushd.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpineConfig {
    /// Whether to publish eval receipts to Spine (NATS JetStream).
    #[serde(default)]
    pub enabled: bool,

    /// NATS server URL (e.g. `nats://127.0.0.1:4222`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nats_url: Option<String>,

    /// Path to a `.creds` file for NATS authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creds_file: Option<String>,

    /// Bearer token for NATS authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// NKey seed for NATS authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nkey_seed: Option<String>,

    /// Path to an Ed25519 keypair used to sign Spine envelopes.
    ///
    /// `PathBuf` matches the desktop agent's representation; YAML
    /// serialisation is identical to `Option<String>` so backwards-compatible
    /// with older on-disk configs that stored the key as a plain string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keypair_path: Option<PathBuf>,

    /// Subject prefix for NATS subjects.
    #[serde(default = "default_subject_prefix")]
    pub subject_prefix: String,
}

fn default_subject_prefix() -> String {
    "spine".to_string()
}

impl Default for SpineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            nats_url: None,
            creds_file: None,
            token: None,
            nkey_seed: None,
            keypair_path: None,
            subject_prefix: default_subject_prefix(),
        }
    }
}
