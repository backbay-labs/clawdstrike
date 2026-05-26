//! Top-level runtime config the desktop agent writes for `hushd`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::siem::SiemConfig;
use crate::spine::SpineConfig;

/// Root configuration written to `hushd.runtime.<port>.yaml`.
///
/// The desktop agent emits this file as the canonical source of truth for the
/// `hushd` daemon's runtime configuration. `hushd::config::Config` is a strict
/// superset and will deserialise every field the writer emits while leaving
/// daemon-only fields at their defaults.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Listen address (e.g. `127.0.0.1:9876`).
    pub listen: String,

    /// Path to the policy YAML the daemon should load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<PathBuf>,

    /// Ruleset name when `policy_path` is unset.
    pub ruleset: String,

    /// Path to the daemon's Ed25519 signing key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<PathBuf>,

    /// SIEM exporter configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub siem: Option<SiemConfig>,

    /// Spine attestation log configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spine: Option<SpineConfig>,
}

impl RuntimeConfig {
    /// Constructs a minimal runtime config used as the agent's starting
    /// point. Callers populate optional integrations as needed.
    #[must_use]
    pub fn new(listen: impl Into<String>, ruleset: impl Into<String>) -> Self {
        Self {
            listen: listen.into(),
            policy_path: None,
            ruleset: ruleset.into(),
            signing_key: None,
            siem: None,
            spine: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::siem::{
        DatadogExporterConfig, ExporterSettings, ExportersConfig, SiemConfig, WebhookExporterConfig,
    };
    use crate::spine::SpineConfig;
    use crate::webhook::{GenericWebhookConfig, WebhookAuthConfig};

    fn sample_runtime_config() -> RuntimeConfig {
        RuntimeConfig {
            listen: "127.0.0.1:9876".to_string(),
            policy_path: Some(PathBuf::from("/etc/clawdstrike/policy.yaml")),
            ruleset: "default".to_string(),
            signing_key: Some(PathBuf::from("/var/lib/clawdstrike/signing.key")),
            siem: Some(SiemConfig {
                enabled: true,
                exporters: ExportersConfig {
                    datadog: Some(ExporterSettings {
                        enabled: true,
                        config: DatadogExporterConfig {
                            api_key: "abc123".to_string(),
                            site: "datadoghq.com".to_string(),
                        },
                    }),
                    webhooks: Some(ExporterSettings {
                        enabled: true,
                        config: WebhookExporterConfig {
                            webhooks: vec![GenericWebhookConfig {
                                url: "https://example.test/hook".to_string(),
                                method: Some("POST".to_string()),
                                headers: Default::default(),
                                auth: Some(WebhookAuthConfig {
                                    auth_type: "bearer".to_string(),
                                    token: Some("secret".to_string()),
                                }),
                                content_type: Some("application/json".to_string()),
                            }],
                        },
                    }),
                    ..Default::default()
                },
            }),
            spine: Some(SpineConfig {
                enabled: true,
                nats_url: Some("nats://127.0.0.1:4222".to_string()),
                subject_prefix: "spine".to_string(),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn roundtrip_full_runtime_config() {
        let original = sample_runtime_config();
        let yaml = serde_yaml::to_string(&original).expect("serialise");
        let decoded: RuntimeConfig = serde_yaml::from_str(&yaml).expect("deserialise");
        let reencoded = serde_yaml::to_string(&decoded).expect("re-serialise");
        assert_eq!(yaml, reencoded, "round-trip diverged: {yaml}");
    }

    #[test]
    fn roundtrip_minimal_runtime_config() {
        let original = RuntimeConfig::new("127.0.0.1:9876", "default");
        let yaml = serde_yaml::to_string(&original).expect("serialise");
        let decoded: RuntimeConfig = serde_yaml::from_str(&yaml).expect("deserialise");
        let reencoded = serde_yaml::to_string(&decoded).expect("re-serialise");
        assert_eq!(yaml, reencoded);
    }

    #[test]
    fn minimal_runtime_config_yaml_omits_optionals() {
        // Optional integrations should not appear in the on-disk YAML when
        // they are `None`. This keeps the agent-written file compact and
        // matches the pre-extraction behaviour.
        let yaml = serde_yaml::to_string(&RuntimeConfig::new("127.0.0.1:9876", "default")).unwrap();
        assert!(
            !yaml.contains("siem:"),
            "minimal YAML must not contain siem: {yaml}"
        );
        assert!(
            !yaml.contains("spine:"),
            "minimal YAML must not contain spine: {yaml}"
        );
        assert!(!yaml.contains("policy_path:"));
        assert!(!yaml.contains("signing_key:"));
        assert!(yaml.contains("listen: 127.0.0.1:9876"));
        assert!(yaml.contains("ruleset: default"));
    }

    #[test]
    fn accepts_legacy_yaml_with_unknown_keys() {
        // hushd may add fields the writer does not know about (e.g. tls,
        // audit, broker). We must still deserialise those YAML files into
        // a `RuntimeConfig` while ignoring the unknown keys, so config files
        // produced by newer hushd versions remain forwards-compatible.
        let yaml = r#"
listen: "127.0.0.1:9876"
ruleset: "strict"
tls: { cert_path: "/tmp/cert.pem", key_path: "/tmp/key.pem" }
audit:
  enabled: true
broker:
  enabled: false
"#;
        let cfg: RuntimeConfig = serde_yaml::from_str(yaml).expect("forwards-compatible parse");
        assert_eq!(cfg.listen, "127.0.0.1:9876");
        assert_eq!(cfg.ruleset, "strict");
        assert!(cfg.siem.is_none());
        assert!(cfg.spine.is_none());
    }
}
