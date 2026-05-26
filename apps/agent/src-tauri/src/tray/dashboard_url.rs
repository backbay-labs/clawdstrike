//! Dashboard URL validation, resolution, and bootstrap launch helpers.
//!
//! These helpers are extracted from `tray::menu` so the Tauri-bound menu code
//! stays focused on UI plumbing. Everything in this module is pure-data: URL
//! parsing, reachability probing, and a single HTTP call to the local agent
//! API to mint a one-time bootstrap code.

use crate::settings::Settings;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;

#[derive(Debug, Serialize)]
pub(super) struct UiBootstrapStartRequest {
    pub next_path: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct UiBootstrapStartResponse {
    pub session_id: String,
    pub user_code: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug)]
pub(super) struct DashboardLaunchTarget {
    pub url: String,
    pub bootstrap_code: Option<String>,
    pub bootstrap_ttl_seconds: Option<u64>,
}

pub(super) fn validate_dashboard_url(candidate: &str) -> Option<String> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parsed = reqwest::Url::parse(trimmed).ok()?;
    let scheme = parsed.scheme();
    if (scheme == "http" || scheme == "https") && parsed.host_str().is_some() {
        Some(parsed.to_string())
    } else {
        None
    }
}

pub(super) fn default_local_dashboard_url(agent_api_port: u16) -> String {
    format!("http://127.0.0.1:{}/ui", agent_api_port)
}

pub(super) fn is_local_dashboard_url(candidate: &str) -> bool {
    let parsed = match reqwest::Url::parse(candidate) {
        Ok(url) => url,
        Err(_) => return false,
    };
    let host = parsed
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']');
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub(super) fn is_loopback_host(parsed: &reqwest::Url) -> bool {
    let host = parsed
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']');
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub(super) fn is_local_agent_ui_url(parsed: &reqwest::Url, expected_port: u16) -> bool {
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    if !is_loopback_host(parsed) {
        return false;
    }
    if parsed.port_or_known_default() != Some(expected_port) {
        return false;
    }
    parsed.path().starts_with("/ui")
}

pub(super) fn ui_next_path(parsed: &reqwest::Url) -> String {
    let mut out = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        out.push('?');
        out.push_str(query);
    }
    if out.is_empty() || !out.starts_with("/ui") {
        "/ui".to_string()
    } else {
        out
    }
}

pub(super) fn redact_url_for_log(url: &str) -> String {
    let mut parsed = match reqwest::Url::parse(url) {
        Ok(value) => value,
        Err(_) => return "<invalid-url>".to_string(),
    };
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

pub(super) async fn request_local_ui_bootstrap(
    agent_api_port: u16,
    auth_token: &str,
    next_path: String,
) -> Option<UiBootstrapStartResponse> {
    let endpoint = format!(
        "http://127.0.0.1:{}/api/v1/ui/bootstrap/start",
        agent_api_port
    );
    let request = UiBootstrapStartRequest { next_path };
    let response = reqwest::Client::new()
        .post(&endpoint)
        .bearer_auth(auth_token)
        .json(&request)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<UiBootstrapStartResponse>().await.ok()
}

pub(super) async fn build_dashboard_launch_target(
    url: &str,
    settings: &Settings,
    auth_token: Option<&str>,
) -> Option<DashboardLaunchTarget> {
    let parsed = reqwest::Url::parse(url).ok()?;

    if !is_loopback_host(&parsed) {
        return Some(DashboardLaunchTarget {
            url: parsed.to_string(),
            bootstrap_code: None,
            bootstrap_ttl_seconds: None,
        });
    }

    if !is_local_agent_ui_url(&parsed, settings.agent_api_port) {
        return Some(DashboardLaunchTarget {
            url: parsed.to_string(),
            bootstrap_code: None,
            bootstrap_ttl_seconds: None,
        });
    }

    let auth_token = auth_token
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let bootstrap =
        request_local_ui_bootstrap(settings.agent_api_port, auth_token, ui_next_path(&parsed))
            .await?;

    let mut bootstrap_url = parsed;
    bootstrap_url.set_path("/ui/bootstrap");
    bootstrap_url.set_query(Some(&format!("session_id={}", bootstrap.session_id)));
    bootstrap_url.set_fragment(None);
    Some(DashboardLaunchTarget {
        url: bootstrap_url.to_string(),
        bootstrap_code: Some(bootstrap.user_code),
        bootstrap_ttl_seconds: Some(bootstrap.expires_in_seconds),
    })
}

pub(super) fn is_legacy_local_dev_dashboard_url(candidate: &str) -> bool {
    let parsed = match reqwest::Url::parse(candidate) {
        Ok(url) => url,
        Err(_) => return false,
    };
    let host = parsed.host_str().unwrap_or_default();
    parsed.scheme() == "http"
        && matches!(host, "localhost" | "127.0.0.1")
        && parsed.port_or_known_default() == Some(3100)
        && (parsed.path() == "/" || parsed.path().is_empty())
}

pub(super) async fn url_is_reachable(candidate: &str) -> bool {
    let parsed = match reqwest::Url::parse(candidate) {
        Ok(url) => url,
        Err(_) => return false,
    };
    let host = match parsed.host_str() {
        Some(host) => host,
        None => return false,
    };
    let port = match parsed.port_or_known_default() {
        Some(port) => port,
        None => return false,
    };
    let timeout_duration = Duration::from_millis(150);
    let addresses = match lookup_host((host, port)).await {
        Ok(addresses) => addresses,
        Err(_) => return false,
    };
    for address in addresses.take(4) {
        if let Ok(Ok(_)) = timeout(timeout_duration, TcpStream::connect(address)).await {
            return true;
        }
    }
    false
}

pub(super) async fn resolve_dashboard_url(settings: &Settings) -> Option<String> {
    let fallback = default_local_dashboard_url(settings.agent_api_port);
    let configured = if settings.dashboard_url.trim().is_empty() {
        fallback.clone()
    } else {
        settings.dashboard_url.clone()
    };

    let validated = validate_dashboard_url(&configured)?;
    if is_local_dashboard_url(&validated) && !url_is_reachable(&validated).await {
        if is_legacy_local_dev_dashboard_url(&validated) {
            tracing::warn!(
                configured_url = %validated,
                fallback_url = %fallback,
                "Dashboard URL points to localhost:3100, but no service is listening; using local agent UI fallback"
            );
        } else {
            tracing::warn!(
                configured_url = %validated,
                fallback_url = %fallback,
                "Configured local dashboard URL is unreachable; using local agent UI fallback"
            );
        }
        return validate_dashboard_url(&fallback);
    }
    Some(validated)
}

pub(super) fn build_dashboard_settings_url(base_url: &str, section: &str) -> Option<String> {
    let section = section.trim().trim_matches('/');
    if section.is_empty() {
        return None;
    }

    let mut parsed = reqwest::Url::parse(base_url).ok()?;
    parsed.set_query(None);
    parsed.set_fragment(None);

    let base_path = parsed.path().trim_end_matches('/');
    let target_path = if base_path.is_empty() || base_path == "/" {
        format!("/settings/{}", section)
    } else if base_path.ends_with("/settings") {
        format!("{}/{}", base_path, section)
    } else {
        format!("{}/settings/{}", base_path, section)
    };
    parsed.set_path(&target_path);
    Some(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        build_dashboard_settings_url, default_local_dashboard_url,
        is_legacy_local_dev_dashboard_url, is_local_agent_ui_url, is_local_dashboard_url,
        redact_url_for_log, ui_next_path, validate_dashboard_url,
    };

    #[test]
    fn validate_dashboard_url_accepts_http_https_with_host() {
        assert_eq!(
            validate_dashboard_url("https://example.com/path?q=1").as_deref(),
            Some("https://example.com/path?q=1")
        );
        assert_eq!(
            validate_dashboard_url("http://localhost:3100").as_deref(),
            Some("http://localhost:3100/")
        );
    }

    #[test]
    fn validate_dashboard_url_rejects_non_network_or_hostless_urls() {
        assert!(validate_dashboard_url("urn:isbn:0451450523").is_none());
        assert!(validate_dashboard_url("javascript:alert(1)").is_none());
        assert!(validate_dashboard_url("file:///tmp/test").is_none());
        assert!(validate_dashboard_url("not a url").is_none());
    }

    #[test]
    fn local_dashboard_url_uses_agent_api_port() {
        assert_eq!(
            default_local_dashboard_url(9878),
            "http://127.0.0.1:9878/ui"
        );
    }

    #[test]
    fn local_dashboard_url_detection_is_precise() {
        assert!(is_local_dashboard_url("http://127.0.0.1:4200"));
        assert!(is_local_dashboard_url("https://localhost:3100/path"));
        assert!(is_local_dashboard_url("https://[::1]:3100/path"));
        assert!(!is_local_dashboard_url("https://example.com/settings"));
    }

    #[test]
    fn local_agent_ui_validation_pins_expected_origin() {
        let allowed = reqwest::Url::parse("http://127.0.0.1:9878/ui/settings/siem")
            .unwrap_or_else(|_| panic!("failed to parse allowed test url"));
        let allowed_https = reqwest::Url::parse("https://127.0.0.1:9878/ui/settings/siem")
            .unwrap_or_else(|_| panic!("failed to parse allowed-https test url"));
        let wrong_port = reqwest::Url::parse("http://127.0.0.1:9999/ui")
            .unwrap_or_else(|_| panic!("failed to parse wrong-port test url"));
        let wrong_scheme = reqwest::Url::parse("ftp://127.0.0.1:9878/ui")
            .unwrap_or_else(|_| panic!("failed to parse wrong-scheme test url"));
        let wrong_path = reqwest::Url::parse("http://127.0.0.1:9878/api")
            .unwrap_or_else(|_| panic!("failed to parse wrong-path test url"));
        let remote_host = reqwest::Url::parse("http://example.com:9878/ui")
            .unwrap_or_else(|_| panic!("failed to parse remote-host test url"));

        assert!(is_local_agent_ui_url(&allowed, 9878));
        assert!(is_local_agent_ui_url(&allowed_https, 9878));
        assert!(!is_local_agent_ui_url(&wrong_port, 9878));
        assert!(!is_local_agent_ui_url(&wrong_scheme, 9878));
        assert!(!is_local_agent_ui_url(&wrong_path, 9878));
        assert!(!is_local_agent_ui_url(&remote_host, 9878));
    }

    #[test]
    fn ui_next_path_and_log_redaction_strip_sensitive_url_parts() {
        let parsed = reqwest::Url::parse("http://127.0.0.1:9878/ui/settings/siem?x=1")
            .unwrap_or_else(|_| panic!("failed to parse next-path test url"));
        assert_eq!(ui_next_path(&parsed), "/ui/settings/siem?x=1".to_string());
        assert_eq!(
            redact_url_for_log("http://127.0.0.1:9878/ui/bootstrap?session_id=abc#fragment"),
            "http://127.0.0.1:9878/ui/bootstrap"
        );
    }

    #[test]
    fn build_dashboard_settings_url_uses_path_routes() {
        assert_eq!(
            build_dashboard_settings_url("http://127.0.0.1:3100", "siem").as_deref(),
            Some("http://127.0.0.1:3100/settings/siem")
        );
        assert_eq!(
            build_dashboard_settings_url("https://dashboard.example.com/app/", "webhooks")
                .as_deref(),
            Some("https://dashboard.example.com/app/settings/webhooks")
        );
        assert_eq!(
            build_dashboard_settings_url("https://dashboard.example.com/settings", "siem")
                .as_deref(),
            Some("https://dashboard.example.com/settings/siem")
        );
        assert_eq!(
            build_dashboard_settings_url("http://127.0.0.1:9878/ui", "webhooks").as_deref(),
            Some("http://127.0.0.1:9878/ui/settings/webhooks")
        );
    }

    #[test]
    fn legacy_local_dev_dashboard_url_detection_is_precise() {
        assert!(is_legacy_local_dev_dashboard_url("http://localhost:3100"));
        assert!(is_legacy_local_dev_dashboard_url("http://127.0.0.1:3100/"));
        assert!(!is_legacy_local_dev_dashboard_url("http://localhost:4200"));
        assert!(!is_legacy_local_dev_dashboard_url("https://localhost:3100"));
        assert!(!is_legacy_local_dev_dashboard_url(
            "http://example.com:3100"
        ));
    }
}
