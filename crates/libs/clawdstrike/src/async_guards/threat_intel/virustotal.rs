use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Method;
use reqwest::Url;
use serde::Deserialize;

use hush_core::sha256;

use crate::async_guards::http::{HttpClient, HttpRequestPolicy};
use crate::async_guards::types::{
    AsyncGuard, AsyncGuardConfig, AsyncGuardError, AsyncGuardErrorKind,
};
use crate::guards::{GuardAction, GuardContext, GuardResult, Severity};

const DEFAULT_BASE_URL: &str = "https://www.virustotal.com/api/v3";
const DEFAULT_MIN_DETECTIONS: u64 = 5;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VirusTotalPolicyConfig {
    pub api_key: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub min_detections: Option<u64>,
}

pub struct VirusTotalGuard {
    cfg: VirusTotalPolicyConfig,
    async_cfg: AsyncGuardConfig,
    base_url: String,
    min_detections: u64,
    request_policy: HttpRequestPolicy,
}

impl VirusTotalGuard {
    pub fn new(cfg: VirusTotalPolicyConfig, async_cfg: AsyncGuardConfig) -> Self {
        let base_url = cfg
            .base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let base_url = base_url.trim_end_matches('/').to_string();
        let min_detections = cfg.min_detections.unwrap_or(DEFAULT_MIN_DETECTIONS).max(1);

        let request_policy = request_policy_for_base_url(&base_url).unwrap_or_default();

        Self {
            cfg,
            async_cfg,
            base_url,
            min_detections,
            request_policy,
        }
    }
}

#[async_trait]
impl AsyncGuard for VirusTotalGuard {
    fn name(&self) -> &str {
        "clawdstrike-virustotal"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(
            action,
            GuardAction::FileWrite(_, _) | GuardAction::NetworkEgress(_, _)
        )
    }

    fn config(&self) -> &AsyncGuardConfig {
        &self.async_cfg
    }

    fn cache_key(&self, action: &GuardAction<'_>, context: &GuardContext) -> Option<String> {
        match action {
            GuardAction::FileWrite(_, content) => {
                file_sha256_hex(content, context).map(|h| format!("file:sha256:{}", h))
            }
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
        match action {
            GuardAction::FileWrite(_path, content) => {
                let Some(hash) = file_sha256_hex(content, context) else {
                    return Ok(GuardResult::warn(
                        self.name(),
                        "VirusTotal: missing content bytes or content hash",
                    )
                    .with_details(serde_json::json!({
                        "reason": "missing_content_hash"
                    })));
                };

                let url = format!("{}/files/{}", self.base_url, hash);

                let mut headers = HeaderMap::new();
                headers.insert(
                    "x-apikey",
                    HeaderValue::from_str(&self.cfg.api_key).map_err(|e| {
                        AsyncGuardError::new(AsyncGuardErrorKind::Other, e.to_string())
                    })?,
                );

                let resp = http
                    .request_json(
                        self.name(),
                        Method::GET,
                        &url,
                        headers,
                        None,
                        &self.request_policy,
                    )
                    .await?;

                if resp.status == 404 {
                    return Ok(
                        GuardResult::warn(self.name(), "VirusTotal: file hash not found")
                            .with_details(serde_json::json!({
                                "hash": hash,
                                "status": resp.status,
                                "audit": resp.audit,
                            })),
                    );
                }

                let (malicious, suspicious) = vt_analysis_stats(&resp.json);
                let detections = malicious.saturating_add(suspicious);

                if detections >= self.min_detections {
                    return Ok(GuardResult::block(
                        self.name(),
                        Severity::Critical,
                        format!(
                            "VirusTotal: {} detections (malicious={}, suspicious={}) for file hash {}",
                            detections, malicious, suspicious, hash
                        ),
                    )
                    .with_details(serde_json::json!({
                        "hash": hash,
                        "last_analysis_stats": {
                            "malicious": malicious,
                            "suspicious": suspicious
                        },
                        "status": resp.status,
                        "audit": resp.audit,
                    })));
                }

                if malicious > 0 {
                    return Ok(GuardResult::warn(
                        self.name(),
                        format!(
                            "VirusTotal: malicious detections below threshold (malicious={}, suspicious={})",
                            malicious, suspicious
                        ),
                    )
                    .with_details(serde_json::json!({
                        "hash": hash,
                        "last_analysis_stats": {
                            "malicious": malicious,
                            "suspicious": suspicious
                        },
                        "status": resp.status,
                        "audit": resp.audit,
                    })));
                }

                Ok(
                    GuardResult::allow(self.name()).with_details(serde_json::json!({
                        "hash": hash,
                        "status": resp.status,
                        "audit": resp.audit,
                    })),
                )
            }
            GuardAction::NetworkEgress(host, port) => {
                let Some(target_url) = url_for_network_action(host, *port, context) else {
                    return Ok(GuardResult::warn(
                        self.name(),
                        "VirusTotal: missing URL context; falling back to host only",
                    )
                    .with_details(serde_json::json!({ "host": host, "port": port })));
                };

                let id = URL_SAFE_NO_PAD.encode(target_url.as_bytes());
                let url = format!("{}/urls/{}", self.base_url, id);

                let mut headers = HeaderMap::new();
                headers.insert(
                    "x-apikey",
                    HeaderValue::from_str(&self.cfg.api_key).map_err(|e| {
                        AsyncGuardError::new(AsyncGuardErrorKind::Other, e.to_string())
                    })?,
                );

                let resp = http
                    .request_json(
                        self.name(),
                        Method::GET,
                        &url,
                        headers,
                        None,
                        &self.request_policy,
                    )
                    .await?;

                if resp.status == 404 {
                    return Ok(GuardResult::warn(self.name(), "VirusTotal: URL not found")
                        .with_details(serde_json::json!({
                            "url": target_url,
                            "status": resp.status,
                            "audit": resp.audit,
                        })));
                }

                let (malicious, suspicious) = vt_analysis_stats(&resp.json);
                let detections = malicious.saturating_add(suspicious);

                if detections >= self.min_detections {
                    return Ok(GuardResult::block(
                        self.name(),
                        Severity::Error,
                        format!(
                            "VirusTotal: {} detections (malicious={}, suspicious={}) for URL {}",
                            detections, malicious, suspicious, target_url
                        ),
                    )
                    .with_details(serde_json::json!({
                        "url": target_url,
                        "last_analysis_stats": {
                            "malicious": malicious,
                            "suspicious": suspicious
                        },
                        "status": resp.status,
                        "audit": resp.audit,
                    })));
                }

                if malicious > 0 {
                    return Ok(GuardResult::warn(
                        self.name(),
                        format!(
                            "VirusTotal: malicious detections below threshold (malicious={}, suspicious={})",
                            malicious, suspicious
                        ),
                    )
                    .with_details(serde_json::json!({
                        "url": target_url,
                        "last_analysis_stats": {
                            "malicious": malicious,
                            "suspicious": suspicious
                        },
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
            _ => Ok(GuardResult::allow(self.name())),
        }
    }
}

fn vt_analysis_stats(json: &serde_json::Value) -> (u64, u64) {
    let stats = json
        .pointer("/data/attributes/last_analysis_stats")
        .and_then(|v| v.as_object());

    let malicious = stats
        .and_then(|s| s.get("malicious"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let suspicious = stats
        .and_then(|s| s.get("suspicious"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    (malicious, suspicious)
}

fn request_policy_for_base_url(base_url: &str) -> Option<HttpRequestPolicy> {
    let parsed = Url::parse(base_url).ok()?;
    let host = parsed.host_str()?.to_string();

    Some(HttpRequestPolicy {
        allowed_hosts: vec![host],
        allowed_methods: vec![Method::GET],
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

fn file_sha256_hex(content: &[u8], context: &GuardContext) -> Option<String> {
    if !content.is_empty() {
        return Some(sha256(content).to_hex());
    }

    let raw = lookup_metadata_string(
        context.metadata.as_ref(),
        &["policy_event", "file", "content_hash"],
    )
    .or_else(|| lookup_metadata_string(context.metadata.as_ref(), &["content_hash"]))
    .or_else(|| lookup_metadata_string(context.metadata.as_ref(), &["contentHash"]))?;

    normalize_sha256_hex(&raw)
}

fn normalize_sha256_hex(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let without_prefix = if let Some(rest) = trimmed.strip_prefix("sha256:") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("0x") {
        rest
    } else {
        trimmed
    };

    let hex = without_prefix.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    Some(hex.to_ascii_lowercase())
}

fn lookup_metadata_string(meta: Option<&serde_json::Value>, path: &[&str]) -> Option<String> {
    let mut cur = meta?;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str().map(|s| s.to_string())
}
