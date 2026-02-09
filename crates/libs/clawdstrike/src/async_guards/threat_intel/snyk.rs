use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Method;
use reqwest::Url;
use serde::Deserialize;

use crate::async_guards::http::{HttpClient, HttpRequestPolicy};
use crate::async_guards::types::{
    AsyncGuard, AsyncGuardConfig, AsyncGuardError, AsyncGuardErrorKind,
};
use crate::guards::{GuardAction, GuardContext, GuardResult, Severity};

const DEFAULT_BASE_URL: &str = "https://snyk.io/api/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnykSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl SnykSeverity {
    fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnykPolicyConfig {
    pub api_token: String,
    pub org_id: String,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub severity_threshold: Option<SnykSeverity>,
    #[serde(default)]
    pub fail_on_upgradable: Option<bool>,
}

pub struct SnykGuard {
    cfg: SnykPolicyConfig,
    async_cfg: AsyncGuardConfig,
    base_url: String,
    severity_threshold: SnykSeverity,
    fail_on_upgradable: bool,
    request_policy: HttpRequestPolicy,
}

impl SnykGuard {
    pub fn new(cfg: SnykPolicyConfig, async_cfg: AsyncGuardConfig) -> Self {
        let base_url = cfg
            .base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let base_url = base_url.trim_end_matches('/').to_string();

        let severity_threshold = cfg.severity_threshold.unwrap_or(SnykSeverity::High);
        let fail_on_upgradable = cfg.fail_on_upgradable.unwrap_or(false);

        let request_policy = request_policy_for_base_url(&base_url).unwrap_or_default();

        Self {
            cfg,
            async_cfg,
            base_url,
            severity_threshold,
            fail_on_upgradable,
            request_policy,
        }
    }
}

#[async_trait]
impl AsyncGuard for SnykGuard {
    fn name(&self) -> &str {
        "clawdstrike-snyk"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::FileWrite(_, _))
    }

    fn config(&self) -> &AsyncGuardConfig {
        &self.async_cfg
    }

    fn cache_key(&self, action: &GuardAction<'_>, context: &GuardContext) -> Option<String> {
        match action {
            GuardAction::FileWrite(path, content) => {
                if !path.ends_with("package.json") {
                    return None;
                }

                if !content.is_empty() {
                    let h = hush_core::sha256(content).to_hex();
                    return Some(format!("pkg:sha256:{}", h));
                }

                // If content is missing, do not cache.
                if decision_reason_is_missing_content_bytes(context) {
                    return None;
                }

                None
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
        let GuardAction::FileWrite(path, content) = action else {
            return Ok(GuardResult::allow(self.name()));
        };

        if !path.ends_with("package.json") {
            return Ok(GuardResult::allow(self.name()));
        }

        if content.is_empty() && decision_reason_is_missing_content_bytes(context) {
            return Ok(GuardResult::warn(
                self.name(),
                "Snyk: missing content bytes for package.json",
            )
            .with_details(serde_json::json!({
                "reason": "missing_content_bytes"
            })));
        }

        let endpoint = format!("{}/test", self.base_url);
        let body = serde_json::json!({
            "orgId": self.cfg.org_id,
            "targetFile": "package.json",
            "manifest": String::from_utf8_lossy(content),
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("token {}", self.cfg.api_token))
                .map_err(|e| AsyncGuardError::new(AsyncGuardErrorKind::Other, e.to_string()))?,
        );
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

        let vulns = extract_vulnerabilities(&resp.json);

        let mut total_at_or_above: u64 = 0;
        let mut upgradable_at_or_above: u64 = 0;

        for v in vulns {
            let Some(sev) = v.severity else {
                continue;
            };
            if sev.rank() < self.severity_threshold.rank() {
                continue;
            }

            total_at_or_above = total_at_or_above.saturating_add(1);
            if v.upgradable {
                upgradable_at_or_above = upgradable_at_or_above.saturating_add(1);
            }
        }

        if total_at_or_above == 0 {
            return Ok(
                GuardResult::allow(self.name()).with_details(serde_json::json!({
                    "status": resp.status,
                    "audit": resp.audit,
                    "threshold": format!("{:?}", self.severity_threshold).to_lowercase(),
                })),
            );
        }

        if self.fail_on_upgradable && upgradable_at_or_above > 0 {
            return Ok(GuardResult::block(
                self.name(),
                Severity::Error,
                format!(
                    "Snyk: {} upgradable vulnerabilities at/above threshold",
                    upgradable_at_or_above
                ),
            )
            .with_details(serde_json::json!({
                "vulns_at_or_above_threshold": total_at_or_above,
                "upgradable_vulns_at_or_above_threshold": upgradable_at_or_above,
                "threshold": format!("{:?}", self.severity_threshold).to_lowercase(),
                "status": resp.status,
                "audit": resp.audit,
            })));
        }

        Ok(GuardResult::warn(
            self.name(),
            format!(
                "Snyk: {} vulnerabilities at/above threshold",
                total_at_or_above
            ),
        )
        .with_details(serde_json::json!({
            "vulns_at_or_above_threshold": total_at_or_above,
            "threshold": format!("{:?}", self.severity_threshold).to_lowercase(),
            "status": resp.status,
            "audit": resp.audit,
        })))
    }
}

#[derive(Clone, Debug)]
struct SnykVuln {
    severity: Option<SnykSeverity>,
    upgradable: bool,
}

fn extract_vulnerabilities(json: &serde_json::Value) -> Vec<SnykVuln> {
    let mut out: Vec<SnykVuln> = Vec::new();

    let arr = json
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .or_else(|| {
            json.pointer("/issues/vulnerabilities")
                .and_then(|v| v.as_array())
        });

    let Some(arr) = arr else {
        return out;
    };

    for v in arr {
        let severity = v.get("severity").and_then(|s| s.as_str()).and_then(|s| {
            serde_json::from_str::<SnykSeverity>(&format!("\"{}\"", s.to_lowercase())).ok()
        });

        let is_upgradable = v
            .get("isUpgradable")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);

        let upgrade_path_has_string = v
            .get("upgradePath")
            .and_then(|p| p.as_array())
            .map(|arr| arr.iter().any(|x| x.as_str().is_some()))
            .unwrap_or(false);

        out.push(SnykVuln {
            severity,
            upgradable: is_upgradable || upgrade_path_has_string,
        });
    }

    out
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

fn decision_reason_is_missing_content_bytes(context: &GuardContext) -> bool {
    let Some(meta) = context.metadata.as_ref() else {
        return false;
    };

    meta.get("policy_event")
        .and_then(|v| v.get("decision_reason"))
        .and_then(|v| v.as_str())
        .map(|s| s == "missing_content_bytes")
        .unwrap_or(false)
}
