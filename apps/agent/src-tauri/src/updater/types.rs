//! Constants, status, and manifest types for the hushd OTA updater.

use serde::{Deserialize, Serialize};

pub(super) const OTA_SCHEMA_VERSION: &str = "clawdstrike-hushd-ota-v1";
pub(super) const OTA_DEFAULT_MANIFEST_STABLE_URL: &str =
    "https://github.com/backbay-labs/clawdstrike/releases/latest/download/hushd-ota-manifest-stable.json";
pub(super) const OTA_DEFAULT_MANIFEST_BETA_URL: &str =
    "https://github.com/backbay-labs/clawdstrike/releases/latest/download/hushd-ota-manifest-beta.json";
pub(super) const OTA_TRUST_ENV_VAR: &str = "CLAWDSTRIKE_HUSHD_OTA_TRUSTED_KEYS";
pub(super) const OTA_DEFAULT_TRUSTED_KEYS_HEX: &[&str] =
    &["25dac855f4df93b016fa3e03c7e8775f235dbcd8ecea0b0fecf5299511ce6bb4"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaStatus {
    pub state: String,
    pub source_url: Option<String>,
    pub current_version: Option<String>,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub last_check_at: Option<String>,
    pub last_apply_at: Option<String>,
    pub last_result: Option<String>,
    pub last_error: Option<String>,
}

impl Default for OtaStatus {
    fn default() -> Self {
        Self {
            state: "idle".to_string(),
            source_url: None,
            current_version: None,
            latest_version: None,
            update_available: false,
            last_check_at: None,
            last_apply_at: None,
            last_result: None,
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct OtaManifest {
    pub(super) schema_version: String,
    pub(super) release_version: String,
    pub(super) published_at: String,
    pub(super) channel: String,
    pub(super) min_agent_version: Option<String>,
    pub(super) notes_url: Option<String>,
    pub(super) artifacts: Vec<OtaArtifact>,
    pub(super) signature: String,
    pub(super) public_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct OtaArtifact {
    pub(super) platform: String,
    pub(super) url: String,
    pub(super) sha256: String,
    pub(super) size: Option<u64>,
}

#[derive(Clone, Debug)]
pub(super) struct VerifiedManifest {
    pub(super) manifest: OtaManifest,
    pub(super) source_url: String,
}
