use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Method;
use reqwest::Url;
use serde::Deserialize;

use crate::async_guards::http::{HttpClient, HttpRequestPolicy};
use crate::async_guards::types::{AsyncGuard, AsyncGuardConfig, AsyncGuardError};
use crate::guards::{GuardAction, GuardContext, GuardResult, Severity};

const DEFAULT_BASE_URL: &str = "https://safebrowsing.googleapis.com/v4";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeBrowsingPolicyConfig {
    pub api_key: String,
    pub client_id: String,
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
}

pub struct SafeBrowsingGuard {
    cfg: SafeBrowsingPolicyConfig,
    async_cfg: AsyncGuardConfig,
    base_url: String,
    request_policy: HttpRequestPolicy,
}

impl SafeBrowsingGuard {
    pub fn new(cfg: SafeBrowsingPolicyConfig, async_cfg: AsyncGuardConfig) -> Self {
        let base_url = cfg
            .base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let base_url = base_url.trim_end_matches('/').to_string();
        let request_policy = request_policy_for_base_url(&base_url).unwrap_or_default();

        Self {
            cfg,
            async_cfg,
            base_url,
            request_policy,
        }
    }
}

#[async_trait]
impl AsyncGuard for SafeBrowsingGuard {
    fn name(&self) -> &str {
        "clawdstrike-safe-browsing"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::NetworkEgress(_, _))
    }

    fn config(&self) -> &AsyncGuardConfig {
        &self.async_cfg
    }

    fn cache_key(&self, action: &GuardAction<'_>, context: &GuardContext) -> Option<String> {
        match action {
            GuardAction::NetworkEgress(host, port) => {
                let url = url_for_network_action(host, *port, context)?;
                Some(format!("url:{}", url))
            }
            _ => None,
        }
    }

    async fn check_uncached(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        http: &HttpClient,
    ) -> std::result::Result<GuardResult, AsyncGuardError> {
        let GuardAction::NetworkEgress(host, port) = action else {
            return Ok(GuardResult::allow(self.name()));
        };

        let Some(target_url) = url_for_network_action(host, *port, context) else {
            return Ok(GuardResult::warn(
                self.name(),
                "Safe Browsing: missing URL context; falling back to host only",
            )
            .with_details(serde_json::json!({ "host": host, "port": port })));
        };

        let endpoint = format!(
            "{}/threatMatches:find?key={}",
            self.base_url, self.cfg.api_key
        );

        let client_version = self
            .cfg
            .client_version
            .clone()
            .unwrap_or_else(|| "0.1.0".to_string());

        let body = serde_json::json!({
            "client": {
                "clientId": self.cfg.client_id,
                "clientVersion": client_version,
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    { "url": target_url }
                ],
            }
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let resp = http
            .request_json(
                self.name(),
                Method::POST,
                &endpoint,
                headers,
                Some(body),
                &self.request_policy,
            )
            .await?;

        let matches = resp
            .json
            .get("matches")
            .and_then(|v| v.as_array())
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        if matches {
            return Ok(GuardResult::block(
                self.name(),
                Severity::Critical,
                format!("Safe Browsing: threat match for URL {}", target_url),
            )
            .with_details(serde_json::json!({
                "url": target_url,
                "status": resp.status,
                "audit": resp.audit,
            })));
        }

        Ok(
            GuardResult::allow(self.name()).with_details(serde_json::json!({
                "url": target_url,
                "status": resp.status,
                "audit": resp.audit,
            })),
        )
    }
}

fn request_policy_for_base_url(base_url: &str) -> Option<HttpRequestPolicy> {
    let parsed = Url::parse(base_url).ok()?;
    let host = parsed.host_str()?.to_string();

    Some(HttpRequestPolicy {
        allowed_hosts: vec![host],
        allowed_methods: vec![Method::POST],
        allow_insecure_http_for_loopback: true,
        max_request_size_bytes: 1_048_576,
        max_response_size_bytes: 10_485_760,
        timeout: Duration::from_secs(30),
    })
}

fn url_for_network_action(host: &str, port: u16, context: &GuardContext) -> Option<String> {
    if let Some(url) = lookup_metadata_string(
        context.metadata.as_ref(),
        &["policy_event", "network", "url"],
    ) {
        return Some(url);
    }
    if let Some(url) = lookup_metadata_string(context.metadata.as_ref(), &["url"]) {
        return Some(url);
    }

    // Best-effort fallback.
    if port == 443 {
        Some(format!("https://{}", host))
    } else {
        Some(format!("https://{}:{}", host, port))
    }
}

fn lookup_metadata_string(meta: Option<&serde_json::Value>, path: &[&str]) -> Option<String> {
    let mut cur = meta?;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str().map(|s| s.to_string())
}
