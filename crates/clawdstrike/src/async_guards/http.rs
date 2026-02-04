use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, Url};

use crate::async_guards::types::{AsyncGuardError, AsyncGuardErrorKind};

#[derive(Clone, Debug)]
pub struct HttpRequestPolicy {
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<Method>,
    pub allow_insecure_http_for_loopback: bool,
    pub max_request_size_bytes: usize,
    pub max_response_size_bytes: usize,
    pub timeout: Duration,
}

impl Default for HttpRequestPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_methods: vec![Method::GET, Method::POST],
            allow_insecure_http_for_loopback: true,
            max_request_size_bytes: 1_048_576,   // 1MB
            max_response_size_bytes: 10_485_760, // 10MB
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub json: serde_json::Value,
    pub audit: serde_json::Value,
}

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new() -> Self {
        let client = match reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!(error = %e, "failed to build reqwest client; falling back to default client");
                reqwest::Client::new()
            }
        };
        Self { client }
    }

    pub async fn request_json(
        &self,
        guard: &str,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<serde_json::Value>,
        policy: &HttpRequestPolicy,
    ) -> Result<HttpResponse, AsyncGuardError> {
        let url = Url::parse(url)
            .map_err(|e| AsyncGuardError::new(AsyncGuardErrorKind::Other, e.to_string()))?;

        if !policy.allowed_methods.is_empty() && !policy.allowed_methods.contains(&method) {
            return Err(AsyncGuardError::new(
                AsyncGuardErrorKind::Other,
                format!("http method not allowed: {}", method),
            ));
        }

        self.enforce_url_policy(&url, policy)?;

        let redacted_url = redact_url(&url);

        let start = Instant::now();
        tracing::info!(
            guard,
            action = "request",
            method = %method,
            url = %redacted_url,
            "async guard http request"
        );

        let (body_bytes, has_body) = if let Some(body) = body {
            let bytes = serde_json::to_vec(&body).map_err(|e| {
                AsyncGuardError::new(AsyncGuardErrorKind::Parse, format!("serialize json: {e}"))
            })?;

            if bytes.len() > policy.max_request_size_bytes {
                return Err(AsyncGuardError::new(
                    AsyncGuardErrorKind::Other,
                    format!(
                        "request too large ({} bytes > max {})",
                        bytes.len(),
                        policy.max_request_size_bytes
                    ),
                ));
            }

            (Some(bytes), true)
        } else {
            (None, false)
        };

        let mut headers = headers;
        if has_body && !headers.contains_key(reqwest::header::CONTENT_TYPE) {
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }

        let mut req = self
            .client
            .request(method.clone(), url.clone())
            .headers(headers)
            .timeout(policy.timeout);

        if let Some(bytes) = body_bytes {
            req = req.body(bytes);
        }

        let resp = req.send().await.map_err(|e| {
            tracing::warn!(
                guard,
                action = "error",
                method = %method,
                url = %redacted_url,
                duration_ms = start.elapsed().as_millis() as u64,
                error = %e,
                "async guard http error"
            );
            AsyncGuardError::new(AsyncGuardErrorKind::Http, format!("request failed: {e}"))
        })?;

        let status = resp.status().as_u16();

        if let Some(len) = resp.content_length() {
            if len as usize > policy.max_response_size_bytes {
                return Err(AsyncGuardError::new(
                    AsyncGuardErrorKind::Other,
                    format!(
                        "response too large ({} bytes > max {})",
                        len, policy.max_response_size_bytes
                    ),
                )
                .with_status(status));
            }
        }

        let bytes = resp.bytes().await.map_err(|e| {
            AsyncGuardError::new(AsyncGuardErrorKind::Http, format!("read response: {e}"))
                .with_status(status)
        })?;

        if bytes.len() > policy.max_response_size_bytes {
            return Err(AsyncGuardError::new(
                AsyncGuardErrorKind::Other,
                format!(
                    "response too large ({} bytes > max {})",
                    bytes.len(),
                    policy.max_response_size_bytes
                ),
            )
            .with_status(status));
        }

        let json: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            AsyncGuardError::new(AsyncGuardErrorKind::Parse, format!("parse json: {e}"))
                .with_status(status)
        })?;

        let duration_ms = start.elapsed().as_millis() as u64;
        tracing::info!(
            guard,
            action = "response",
            method = %method,
            url = %redacted_url,
            status,
            duration_ms,
            "async guard http response"
        );

        Ok(HttpResponse {
            status,
            json,
            audit: serde_json::json!({
                "method": method.as_str(),
                "url": redacted_url,
                "status": status,
                "duration_ms": duration_ms,
            }),
        })
    }

    fn enforce_url_policy(
        &self,
        url: &Url,
        policy: &HttpRequestPolicy,
    ) -> Result<(), AsyncGuardError> {
        let Some(host) = url.host_str() else {
            return Err(AsyncGuardError::new(
                AsyncGuardErrorKind::Other,
                "url must include host".to_string(),
            ));
        };

        if !policy.allowed_hosts.is_empty() && !policy.allowed_hosts.iter().any(|h| h == host) {
            return Err(AsyncGuardError::new(
                AsyncGuardErrorKind::Other,
                format!("host not allowed: {}", host),
            ));
        }

        match url.scheme() {
            "https" => Ok(()),
            "http" => {
                if policy.allow_insecure_http_for_loopback
                    && (host == "localhost" || host == "127.0.0.1" || host == "::1")
                {
                    Ok(())
                } else {
                    Err(AsyncGuardError::new(
                        AsyncGuardErrorKind::Other,
                        "insecure http not allowed".to_string(),
                    ))
                }
            }
            other => Err(AsyncGuardError::new(
                AsyncGuardErrorKind::Other,
                format!("unsupported url scheme: {}", other),
            )),
        }
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn redact_url(url: &Url) -> String {
    let mut out = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
    if let Some(port) = url.port() {
        out.push_str(&format!(":{}", port));
    }
    out.push_str(url.path());
    out
}
