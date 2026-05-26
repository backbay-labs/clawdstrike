//! Runtime config file generation for hushd.
//!
//! The agent owns the canonical runtime config (`hushd.runtime.<port>.yaml`)
//! that gets passed to the hushd process via `start --config`. This module
//! builds the file from the in-memory agent settings using the wire-types
//! exposed by the `clawdstrike-hushd-config` crate.

use anyhow::{Context, Result};
use clawdstrike_hushd_config::{
    DatadogExporterConfig, ElasticAuthConfig, ElasticExporterConfig, ExporterSettings,
    ExportersConfig, GenericWebhookConfig, RuntimeConfig as HushdRuntimeConfig,
    SiemConfig as HushdRuntimeSiemConfig, SpineConfig as HushdRuntimeSpineConfig,
    SplunkExporterConfig, SumoLogicExporterConfig, WebhookAuthConfig, WebhookExporterConfig,
};
use std::collections::HashMap;
use std::path::PathBuf;

use super::runtime_keypair::{
    materialize_runtime_enrollment_keypair, materialize_runtime_signing_keypair,
};
use super::state::DaemonConfig;

pub(super) async fn write_runtime_config_file(
    config: &DaemonConfig,
    settings: Option<crate::settings::Settings>,
) -> Result<PathBuf> {
    // Keep runtime config files in the agent config directory rather than alongside the
    // policy file. Users may point policy_path at a repo directory or read-only location.
    let parent = crate::settings::get_config_dir().join("runtime");
    let runtime_config_filename = format!("hushd.runtime.{}.yaml", config.port);
    let runtime_config_path = parent.join(&runtime_config_filename);
    let listen = format!("127.0.0.1:{}", config.port);
    let policy_path = config.policy_path.clone();
    let daemon_port = config.port;

    let path = tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&parent)
            .with_context(|| format!("Failed to create runtime config dir {:?}", parent))?;

        let runtime_signing_key_path = materialize_runtime_signing_keypair(&parent, daemon_port)?;
        let runtime_keypair_path = if settings
            .as_ref()
            .and_then(|s| build_runtime_spine_config(s, None))
            .is_some()
        {
            materialize_runtime_enrollment_keypair(&parent, daemon_port)?
        } else {
            None
        };
        let policy_path = resolve_supported_policy_path(&policy_path);
        let runtime = HushdRuntimeConfig {
            listen,
            policy_path,
            ruleset: "default".to_string(),
            signing_key: Some(runtime_signing_key_path),
            siem: settings.as_ref().and_then(build_runtime_siem_config),
            spine: settings
                .as_ref()
                .and_then(|s| build_runtime_spine_config(s, runtime_keypair_path.clone())),
        };
        let serialized = serde_yaml::to_string(&runtime)
            .with_context(|| "Failed to serialize hushd runtime config")?;
        crate::security::fs::write_private_atomic(
            &runtime_config_path,
            serialized.as_bytes(),
            "hushd runtime config",
        )?;

        Ok::<_, anyhow::Error>(runtime_config_path)
    })
    .await
    .with_context(|| "Runtime config write task panicked")??;

    Ok(path)
}

pub(super) async fn load_runtime_settings_for_config(
    config: &DaemonConfig,
) -> Option<crate::settings::Settings> {
    if let Some(settings) = config.settings.as_ref() {
        return Some(settings.read().await.clone());
    }

    let settings = match crate::settings::Settings::load() {
        Ok(settings) => settings,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to load agent settings while generating hushd runtime config"
            );
            return None;
        }
    };

    Some(settings)
}

pub(super) fn build_runtime_siem_config(
    settings: &crate::settings::Settings,
) -> Option<HushdRuntimeSiemConfig> {
    let mut exporters = ExportersConfig::default();

    let siem = &settings.integrations.siem;
    let provider = siem.provider.trim().to_ascii_lowercase();
    let endpoint = siem.endpoint.trim();
    let api_key = siem.api_key.trim();
    let siem_requested = siem.enabled || !endpoint.is_empty() || !api_key.is_empty();

    if siem_requested {
        match provider.as_str() {
            "datadog" => {
                if !endpoint.is_empty() && !api_key.is_empty() {
                    exporters.datadog = Some(ExporterSettings {
                        enabled: true,
                        config: DatadogExporterConfig {
                            api_key: api_key.to_string(),
                            site: normalize_datadog_site(endpoint),
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider datadog requires both endpoint and API key; exporter not enabled"
                    );
                }
            }
            "splunk" => {
                if !endpoint.is_empty() && !api_key.is_empty() {
                    exporters.splunk = Some(ExporterSettings {
                        enabled: true,
                        config: SplunkExporterConfig {
                            hec_url: endpoint.to_string(),
                            hec_token: api_key.to_string(),
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider splunk requires both endpoint and API key; exporter not enabled"
                    );
                }
            }
            "elastic" => {
                if !endpoint.is_empty() && !api_key.is_empty() {
                    exporters.elastic = Some(ExporterSettings {
                        enabled: true,
                        config: ElasticExporterConfig {
                            base_url: endpoint.to_string(),
                            index: "clawdstrike-security".to_string(),
                            auth: ElasticAuthConfig {
                                api_key: Some(api_key.to_string()),
                            },
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider elastic requires both endpoint and API key; exporter not enabled"
                    );
                }
            }
            "sumo_logic" => {
                if !endpoint.is_empty() {
                    exporters.sumo_logic = Some(ExporterSettings {
                        enabled: true,
                        config: SumoLogicExporterConfig {
                            http_source_url: endpoint.to_string(),
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider sumo_logic requires an endpoint; exporter not enabled"
                    );
                }
            }
            "custom" => {
                if !endpoint.is_empty() {
                    let webhook = build_generic_webhook_exporter(endpoint, Some(api_key));
                    exporters.webhooks = Some(ExporterSettings {
                        enabled: true,
                        config: WebhookExporterConfig {
                            webhooks: vec![webhook],
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider custom requires an endpoint; exporter not enabled"
                    );
                }
            }
            other => {
                tracing::warn!(
                    provider = %other,
                    "Unknown SIEM provider in settings; exporter not enabled"
                );
            }
        }
    }

    let webhooks = &settings.integrations.webhooks;
    let webhook_url = webhooks.url.trim();
    let webhook_secret = webhooks.secret.trim();
    let webhooks_requested = webhooks.enabled || !webhook_url.is_empty();
    if webhooks_requested && !webhook_url.is_empty() {
        let exporter = exporters.webhooks.get_or_insert(ExporterSettings {
            enabled: true,
            config: WebhookExporterConfig { webhooks: vec![] },
        });

        exporter
            .config
            .webhooks
            .push(build_generic_webhook_exporter(
                webhook_url,
                Some(webhook_secret),
            ));
    }

    if !exporters.has_any() {
        return None;
    }

    Some(HushdRuntimeSiemConfig {
        enabled: true,
        exporters,
    })
}

pub(super) fn build_runtime_spine_config(
    settings: &crate::settings::Settings,
    keypair_path: Option<PathBuf>,
) -> Option<HushdRuntimeSpineConfig> {
    if !settings.nats.enabled {
        return None;
    }

    let subject_prefix = settings.nats.subject_prefix.as_ref()?.trim();
    if subject_prefix.is_empty() {
        return None;
    }

    Some(HushdRuntimeSpineConfig {
        enabled: true,
        nats_url: settings.nats.nats_url.clone(),
        creds_file: settings.nats.creds_file.clone(),
        token: settings.nats.token.clone(),
        nkey_seed: settings.nats.nkey_seed.clone(),
        keypair_path,
        subject_prefix: subject_prefix.to_string(),
    })
}

fn build_generic_webhook_exporter(url: &str, token: Option<&str>) -> GenericWebhookConfig {
    let token = token.map(str::trim).unwrap_or_default();
    let auth = if token.is_empty() {
        None
    } else {
        Some(WebhookAuthConfig {
            auth_type: "bearer".to_string(),
            token: Some(token.to_string()),
        })
    };

    GenericWebhookConfig {
        url: url.to_string(),
        method: Some("POST".to_string()),
        headers: HashMap::new(),
        auth,
        content_type: Some("application/json".to_string()),
    }
}

fn normalize_datadog_site(endpoint: &str) -> String {
    let trimmed = endpoint.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return "datadoghq.com".to_string();
    }

    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        if let Some(host) = parsed.host_str() {
            return host.trim_start_matches("http-intake.logs.").to_string();
        }
    }

    let host_port = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("datadoghq.com");
    host_port
        .split(':')
        .next()
        .unwrap_or("datadoghq.com")
        .trim_start_matches("http-intake.logs.")
        .to_string()
}

fn yaml_contains_mapping_key(value: &serde_yaml::Value, needle: &str) -> bool {
    match value {
        serde_yaml::Value::Mapping(map) => map.iter().any(|(k, v)| {
            matches!(k, serde_yaml::Value::String(s) if s == needle)
                || yaml_contains_mapping_key(v, needle)
        }),
        serde_yaml::Value::Sequence(seq) => {
            seq.iter().any(|v| yaml_contains_mapping_key(v, needle))
        }
        _ => false,
    }
}

fn resolve_supported_policy_path(policy_path: &PathBuf) -> Option<PathBuf> {
    if !policy_path.exists() {
        return None;
    }
    let Ok(raw) = std::fs::read_to_string(policy_path) else {
        return None;
    };

    // Hushd no longer accepts legacy guard keys like `fs_blocklist`.
    // When an incompatible policy is detected, fall back to built-in ruleset
    // so the daemon stays available instead of restart-looping.
    let doc: serde_yaml::Value = match serde_yaml::from_str(&raw) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                path = %policy_path.display(),
                error = %err,
                "Failed to parse policy file; falling back to default ruleset"
            );
            return None;
        }
    };

    let legacy_guard_keys = ["fs_blocklist", "exec_blocklist", "egress_allowlist"];
    if let Some(legacy_key) = legacy_guard_keys
        .into_iter()
        .find(|key| yaml_contains_mapping_key(&doc, key))
    {
        tracing::warn!(
            path = %policy_path.display(),
            legacy_key,
            "Policy file contains legacy guard key; falling back to default ruleset"
        );
        return None;
    }

    Some(policy_path.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_datadog_site_accepts_host_or_intake_url() {
        assert_eq!(
            normalize_datadog_site("https://us5.datadoghq.com"),
            "us5.datadoghq.com"
        );
        assert_eq!(
            normalize_datadog_site("https://http-intake.logs.datadoghq.eu/api/v2/logs"),
            "datadoghq.eu"
        );
    }

    #[test]
    fn runtime_siem_config_is_generated_for_datadog_and_webhooks() {
        let mut settings = crate::settings::Settings::default();
        settings.integrations.siem.provider = "datadog".to_string();
        settings.integrations.siem.endpoint = "https://us5.datadoghq.com".to_string();
        settings.integrations.siem.api_key = "dd-key".to_string();
        settings.integrations.siem.enabled = true;
        settings.integrations.webhooks.url = "https://hooks.example.com/security".to_string();
        settings.integrations.webhooks.secret = "hook-secret".to_string();
        settings.integrations.webhooks.enabled = true;

        let config = build_runtime_siem_config(&settings)
            .unwrap_or_else(|| panic!("expected runtime SIEM config"));

        assert!(config.exporters.datadog.is_some());
        let datadog = config
            .exporters
            .datadog
            .as_ref()
            .unwrap_or_else(|| panic!("missing datadog exporter"));
        assert_eq!(datadog.config.site, "us5.datadoghq.com");
        assert_eq!(datadog.config.api_key, "dd-key");

        let webhooks = config
            .exporters
            .webhooks
            .as_ref()
            .unwrap_or_else(|| panic!("missing webhooks exporter"));
        assert_eq!(webhooks.config.webhooks.len(), 1);
        assert_eq!(
            webhooks.config.webhooks[0]
                .auth
                .as_ref()
                .and_then(|auth| auth.token.as_deref()),
            Some("hook-secret")
        );
    }

    #[test]
    fn runtime_spine_config_is_generated_from_nats_settings() {
        let mut settings = crate::settings::Settings::default();
        settings.nats.enabled = true;
        settings.nats.nats_url = Some("nats://example:4222".to_string());
        settings.nats.token = Some("nats-token".to_string());
        settings.nats.subject_prefix = Some("tenant-acme.clawdstrike".to_string());

        let config = build_runtime_spine_config(&settings, None)
            .unwrap_or_else(|| panic!("expected runtime spine config"));

        assert!(config.enabled);
        assert_eq!(config.nats_url.as_deref(), Some("nats://example:4222"));
        assert_eq!(config.token.as_deref(), Some("nats-token"));
        assert_eq!(config.subject_prefix, "tenant-acme.clawdstrike");
    }

    #[test]
    fn runtime_spine_config_is_none_when_nats_disabled_or_prefix_missing() {
        let settings = crate::settings::Settings::default();
        assert!(build_runtime_spine_config(&settings, None).is_none());

        let mut enabled = crate::settings::Settings::default();
        enabled.nats.enabled = true;
        enabled.nats.nats_url = Some("nats://example:4222".to_string());
        assert!(build_runtime_spine_config(&enabled, None).is_none());
    }
}
