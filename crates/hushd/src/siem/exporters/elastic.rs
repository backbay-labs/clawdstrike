use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::siem::exporter::{
    ExportEventError, ExportResult, Exporter, ExporterError, SchemaFormat,
};
use crate::siem::transforms::ecs;
use crate::siem::types::SecurityEvent;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElasticConfig {
    /// Base Elasticsearch URL, e.g. https://es.example.com:9200
    pub base_url: String,

    /// Index alias/base name.
    pub index: String,

    #[serde(default)]
    pub auth: ElasticAuthConfig,

    #[serde(default)]
    pub tls: ElasticTlsConfig,

    /// Optional bootstrap of index template / ILM policy.
    #[serde(default)]
    pub init: ElasticInitConfig,

    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    30_000
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ElasticAuthConfig {
    /// Elastic API key (base64-encoded "id:api_key" value).
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ElasticTlsConfig {
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElasticInitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_init_ilm_enabled")]
    pub ilm: bool,
    #[serde(default)]
    pub ilm_policy: Option<String>,
    #[serde(default)]
    pub template_name: Option<String>,
    #[serde(default = "default_init_shards")]
    pub shards: u32,
    #[serde(default = "default_init_replicas")]
    pub replicas: u32,
}

fn default_init_ilm_enabled() -> bool {
    true
}

fn default_init_shards() -> u32 {
    1
}

fn default_init_replicas() -> u32 {
    1
}

impl Default for ElasticInitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ilm: default_init_ilm_enabled(),
            ilm_policy: None,
            template_name: None,
            shards: default_init_shards(),
            replicas: default_init_replicas(),
        }
    }
}

pub struct ElasticExporter {
    config: ElasticConfig,
    client: reqwest::Client,
    init_lock: Mutex<()>,
    initialized: AtomicBool,
}

impl ElasticExporter {
    pub fn new(mut config: ElasticConfig) -> Result<Self, ExporterError> {
        config.base_url = config.base_url.trim_end_matches('/').to_string();

        let mut builder =
            reqwest::Client::builder().timeout(Duration::from_millis(config.timeout_ms.max(1)));
        if config.tls.insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|e| ExporterError::Other(e.to_string()))?;

        Ok(Self {
            config,
            client,
            init_lock: Mutex::new(()),
            initialized: AtomicBool::new(false),
        })
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(api_key) = &self.config.auth.api_key {
            return req.header(header::AUTHORIZATION, format!("ApiKey {api_key}"));
        }
        if let (Some(user), Some(pass)) = (&self.config.auth.username, &self.config.auth.password) {
            return req.basic_auth(user, Some(pass));
        }
        req
    }

    async fn bulk_index(&self, events: &[SecurityEvent]) -> Result<ExportResult, ExporterError> {
        let mut body = String::new();
        for event in events {
            body.push_str(
                &serde_json::json!({
                    "index": { "_index": self.config.index }
                })
                .to_string(),
            );
            body.push('\n');

            body.push_str(
                &serde_json::to_string(&ecs::to_ecs(event))
                    .unwrap_or_else(|_| serde_json::json!({}).to_string()),
            );
            body.push('\n');
        }

        let req = self
            .client
            .post(format!("{}/_bulk", self.config.base_url))
            .header(header::CONTENT_TYPE, "application/x-ndjson");
        let req = self.apply_auth(req);

        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("Elastic bulk request failed: {e}")))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(ExporterError::Http {
                status: status.as_u16(),
                body: text,
            });
        }

        #[derive(Debug, Deserialize)]
        struct BulkItem {
            status: u16,
            #[serde(default)]
            error: Option<serde_json::Value>,
        }

        #[derive(Debug, Deserialize)]
        struct BulkResponse {
            errors: bool,
            items: Vec<std::collections::HashMap<String, BulkItem>>,
        }

        let parsed: BulkResponse =
            serde_json::from_str(&text).map_err(|e| ExporterError::Other(e.to_string()))?;

        if !parsed.errors {
            return Ok(ExportResult {
                exported: events.len(),
                failed: 0,
                errors: vec![],
            });
        }

        let mut errors: Vec<ExportEventError> = Vec::new();
        for (idx, item_map) in parsed.items.into_iter().enumerate() {
            let Some((_op, item)) = item_map.into_iter().next() else {
                continue;
            };
            if (200..=299).contains(&item.status) {
                continue;
            }

            let event_id = events
                .get(idx)
                .map(|e| e.event_id.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let error = item
                .error
                .map(|v| v.to_string())
                .unwrap_or_else(|| format!("bulk item failed with status {}", item.status));
            let retryable = item.status == 429 || (500..=599).contains(&item.status);
            errors.push(ExportEventError {
                event_id,
                error,
                retryable,
            });
        }

        let failed = errors.len();
        Ok(ExportResult {
            exported: events.len().saturating_sub(failed),
            failed,
            errors,
        })
    }

    fn ilm_policy_name(&self) -> String {
        self.config
            .init
            .ilm_policy
            .clone()
            .unwrap_or_else(|| format!("{}-ilm", self.config.index))
    }

    fn template_name(&self) -> String {
        self.config
            .init
            .template_name
            .clone()
            .unwrap_or_else(|| format!("{}-template", self.config.index))
    }

    fn index_pattern(&self) -> String {
        format!("{}-*", self.config.index)
    }

    fn bootstrap_index_name(&self) -> String {
        format!("{}-000001", self.config.index)
    }

    async fn ensure_initialized(&self) -> Result<(), ExporterError> {
        if !self.config.init.enabled {
            return Ok(());
        }
        if self.initialized.load(Ordering::Acquire) {
            return Ok(());
        }

        let _guard = self.init_lock.lock().await;
        if self.initialized.load(Ordering::Acquire) {
            return Ok(());
        }

        self.initialize().await?;
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    async fn initialize(&self) -> Result<(), ExporterError> {
        if self.config.init.ilm {
            self.create_ilm_policy().await?;
        }
        self.create_index_template().await?;
        self.create_bootstrap_index().await?;
        Ok(())
    }

    async fn create_ilm_policy(&self) -> Result<(), ExporterError> {
        let policy_name = self.ilm_policy_name();
        let policy = serde_json::json!({
            "policy": {
                "phases": {
                    "hot": {
                        "min_age": "0ms",
                        "actions": {
                            "rollover": {
                                "max_age": "1d",
                                "max_primary_shard_size": "50gb"
                            }
                        }
                    },
                    "warm": {
                        "min_age": "7d",
                        "actions": {
                            "shrink": { "number_of_shards": 1 },
                            "forcemerge": { "max_num_segments": 1 }
                        }
                    },
                    "delete": {
                        "min_age": "90d",
                        "actions": { "delete": {} }
                    }
                }
            }
        });

        let req = self
            .client
            .put(format!(
                "{}/_ilm/policy/{}",
                self.config.base_url, policy_name
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&policy);
        let req = self.apply_auth(req);
        let resp = req
            .send()
            .await
            .map_err(|e| ExporterError::Other(format!("Elastic ILM policy request failed: {e}")))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(ExporterError::Http {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }

    async fn create_index_template(&self) -> Result<(), ExporterError> {
        let policy_name = self.ilm_policy_name();
        let template_name = self.template_name();

        let template = serde_json::json!({
            "index_patterns": [self.index_pattern()],
            "template": {
                "settings": {
                    "number_of_shards": self.config.init.shards,
                    "number_of_replicas": self.config.init.replicas,
                    "index.lifecycle.name": policy_name,
                    "index.lifecycle.rollover_alias": self.config.index
                },
                "mappings": {
                    "properties": {
                        "@timestamp": { "type": "date" },
                        "event": {
                            "properties": {
                                "id": { "type": "keyword" },
                                "kind": { "type": "keyword" },
                                "category": { "type": "keyword" },
                                "type": { "type": "keyword" },
                                "outcome": { "type": "keyword" },
                                "action": { "type": "keyword" },
                                "severity": { "type": "long" }
                            }
                        },
                        "agent": {
                            "properties": {
                                "id": { "type": "keyword" },
                                "name": { "type": "keyword" },
                                "type": { "type": "keyword" },
                                "version": { "type": "keyword" }
                            }
                        },
                        "session": {
                            "properties": {
                                "id": { "type": "keyword" }
                            }
                        },
                        "user": {
                            "properties": {
                                "id": { "type": "keyword" }
                            }
                        },
                        "organization": {
                            "properties": {
                                "id": { "type": "keyword" }
                            }
                        },
                        "rule": {
                            "properties": {
                                "id": { "type": "keyword" },
                                "name": { "type": "keyword" },
                                "ruleset": { "type": "keyword" }
                            }
                        },
                        "labels": { "type": "object", "dynamic": true },
                        "message": { "type": "text" },
                        "file": {
                            "properties": {
                                "path": { "type": "keyword" },
                                "name": { "type": "keyword" }
                            }
                        },
                        "destination": {
                            "properties": {
                                "domain": { "type": "keyword" },
                                "port": { "type": "long" }
                            }
                        },
                        "process": {
                            "properties": {
                                "name": { "type": "keyword" },
                                "command_line": { "type": "text" }
                            }
                        },
                        "threat": { "type": "object", "dynamic": true },
                        "clawdstrike": {
                            "properties": {
                                "schema_version": { "type": "keyword" },
                                "session_id": { "type": "keyword" },
                                "environment": { "type": "keyword" },
                                "guard": { "type": "keyword" },
                                "policy_hash": { "type": "keyword" },
                                "ruleset": { "type": "keyword" },
                                "metadata": { "type": "object", "dynamic": true }
                            }
                        }
                    }
                }
            }
        });

        let req = self
            .client
            .put(format!(
                "{}/_index_template/{}",
                self.config.base_url, template_name
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&template);
        let req = self.apply_auth(req);
        let resp = req.send().await.map_err(|e| {
            ExporterError::Other(format!("Elastic index template request failed: {e}"))
        })?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(ExporterError::Http {
                status: resp.status().as_u16(),
                body: resp.text().await.unwrap_or_default(),
            })
        }
    }

    async fn create_bootstrap_index(&self) -> Result<(), ExporterError> {
        let name = self.bootstrap_index_name();
        let body = serde_json::json!({
            "aliases": {
                self.config.index.clone(): { "is_write_index": true }
            }
        });

        let req = self
            .client
            .put(format!("{}/{}", self.config.base_url, name))
            .header(header::CONTENT_TYPE, "application/json")
            .json(&body);
        let req = self.apply_auth(req);
        let resp = req.send().await.map_err(|e| {
            ExporterError::Other(format!("Elastic bootstrap index request failed: {e}"))
        })?;

        if resp.status().is_success() {
            return Ok(());
        }

        // If index already exists, treat as success.
        if resp.status().as_u16() == 400 {
            let text = resp.text().await.unwrap_or_default();
            if text.contains("resource_already_exists_exception") {
                return Ok(());
            }
            return Err(ExporterError::Http {
                status: 400,
                body: text,
            });
        }

        Err(ExporterError::Http {
            status: resp.status().as_u16(),
            body: resp.text().await.unwrap_or_default(),
        })
    }
}

#[async_trait]
impl Exporter for ElasticExporter {
    fn name(&self) -> &str {
        "elastic"
    }

    fn schema(&self) -> SchemaFormat {
        SchemaFormat::Ecs
    }

    async fn export(&self, events: Vec<SecurityEvent>) -> Result<ExportResult, ExporterError> {
        if events.is_empty() {
            return Ok(ExportResult::default());
        }
        self.ensure_initialized().await?;
        self.bulk_index(&events).await
    }

    async fn health_check(&self) -> Result<(), String> {
        if let Err(err) = self.ensure_initialized().await {
            return Err(err.to_string());
        }
        let req = self.client.get(self.config.base_url.clone());
        let req = self.apply_auth(req);
        let resp = req.send().await.map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("Elastic health check failed: {}", resp.status()))
        }
    }

    async fn shutdown(&self) -> Result<(), String> {
        Ok(())
    }
}
