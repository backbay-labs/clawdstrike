//! SIEM exporter DTOs written by the agent.
//!
//! Each exporter struct represents the subset of fields the desktop agent
//! populates when materialising a runtime config from user-facing
//! `IntegrationSettings`. `hushd`'s full reader (`SiemSoarConfig`,
//! `SplunkConfig`, etc.) accepts additional fields with defaults; this crate
//! intentionally only carries the keys the agent emits.
//!
//! ## Forwards-compatibility
//!
//! None of the structs use `#[serde(deny_unknown_fields)]`. Two reasons:
//!
//! 1. Existing on-disk configs may contain hushd-only fields (e.g. Datadog
//!    `app_key`, Splunk `index`) that an old agent did not know about.
//!    Deserialising those should not fail.
//! 2. Future hushd versions may add fields the agent does not yet populate.
//!    Round-tripping such configs through the agent should preserve the
//!    daemon's data — currently we do this by only writing keys we know
//!    about.

use serde::{Deserialize, Serialize};

use crate::webhook::GenericWebhookConfig;

/// Top-level SIEM/SOAR block in the runtime YAML.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SiemConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub exporters: ExportersConfig,
}

/// Per-provider exporter wrappers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExportersConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub splunk: Option<ExporterSettings<SplunkExporterConfig>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elastic: Option<ExporterSettings<ElasticExporterConfig>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub datadog: Option<ExporterSettings<DatadogExporterConfig>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sumo_logic: Option<ExporterSettings<SumoLogicExporterConfig>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhooks: Option<ExporterSettings<WebhookExporterConfig>>,
}

impl ExportersConfig {
    /// Returns `true` if at least one exporter is configured.
    #[must_use]
    pub fn has_any(&self) -> bool {
        self.splunk.is_some()
            || self.elastic.is_some()
            || self.datadog.is_some()
            || self.sumo_logic.is_some()
            || self.webhooks.is_some()
    }
}

/// Wrapper that mirrors hushd's `ExporterSettings<T>` enabled-flag layout.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExporterSettings<T> {
    #[serde(default)]
    pub enabled: bool,

    #[serde(flatten)]
    pub config: T,
}

/// Splunk HEC exporter config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SplunkExporterConfig {
    pub hec_url: String,
    pub hec_token: String,
}

/// Elasticsearch exporter config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ElasticExporterConfig {
    pub base_url: String,
    pub index: String,
    #[serde(default)]
    pub auth: ElasticAuthConfig,
}

/// Elasticsearch credential block.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ElasticAuthConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

/// Datadog exporter config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DatadogExporterConfig {
    pub api_key: String,
    pub site: String,
}

/// Sumo Logic exporter config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SumoLogicExporterConfig {
    pub http_source_url: String,
}

/// Generic webhook exporter config (one or more destinations).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebhookExporterConfig {
    #[serde(default)]
    pub webhooks: Vec<GenericWebhookConfig>,
}
