//! Generic webhook DTOs used by SIEM exporter configurations.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A single generic HTTP webhook destination.
///
/// Mirrors the subset of `hushd::siem::exporters::webhooks::GenericWebhookConfig`
/// the desktop agent populates. Optional fields use `skip_serializing_if` so
/// the on-disk YAML stays compact and forward-compatible with future hushd
/// fields.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GenericWebhookConfig {
    /// Destination URL.
    pub url: String,

    /// HTTP method (defaults to `POST` if unset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Static headers to attach to every request.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// Optional authentication descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<WebhookAuthConfig>,

    /// Request `Content-Type`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Authentication settings for a generic webhook.
///
/// The discriminator is serialised as `type` to mirror hushd's existing
/// `WebhookAuthConfig` schema. Backwards compatible: older agent versions
/// only emitted `bearer` tokens, which is encoded as `{ type: "bearer",
/// token: "..." }`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookAuthConfig {
    #[serde(rename = "type")]
    pub auth_type: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}
