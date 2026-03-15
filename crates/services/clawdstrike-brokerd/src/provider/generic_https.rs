use std::collections::BTreeMap;
use std::net::IpAddr;

use clawdstrike_broker_protocol::{sha256_hex, BrokerRequest};
use reqwest::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use url::Url;

use crate::api::ApiError;
use crate::provider::{
    extract_response_headers, map_method, ProviderExecutionResponse, ProviderStreamResponse,
};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum GenericHttpsSecretEnvelope {
    Bearer { value: String },
    Header { header_name: String, value: String },
}

struct InjectedHeader {
    name: HeaderName,
    value: HeaderValue,
    auth_mode: &'static str,
}

pub async fn execute_generic_https(
    state: &AppState,
    request: &BrokerRequest,
    secret: &str,
) -> Result<ProviderExecutionResponse, ApiError> {
    let (response, provider_metadata) =
        execute_generic_https_request(state, request, secret).await?;
    let status = response.status().as_u16();
    let (headers, content_type) = extract_response_headers(&response);
    let body = response
        .text()
        .await
        .map_err(|error| ApiError::bad_gateway("BROKER_UPSTREAM_READ_FAILED", error.to_string()))?;
    let bytes_received = body.len();

    let response_body_sha256 = Some(sha256_hex(&body));
    Ok(ProviderExecutionResponse {
        status,
        headers,
        body: Some(body),
        content_type,
        response_body_sha256,
        bytes_received,
        provider_metadata,
    })
}

pub async fn execute_generic_https_stream(
    state: &AppState,
    request: &BrokerRequest,
    secret: &str,
) -> Result<ProviderStreamResponse, ApiError> {
    let (response, provider_metadata) =
        execute_generic_https_request(state, request, secret).await?;
    let status = response.status().as_u16();
    let (headers, content_type) = extract_response_headers(&response);

    Ok(ProviderStreamResponse {
        status,
        headers,
        content_type,
        response,
        provider_metadata,
    })
}

async fn execute_generic_https_request(
    state: &AppState,
    request: &BrokerRequest,
    secret: &str,
) -> Result<(reqwest::Response, BTreeMap<String, String>), ApiError> {
    let pinned_addr = validate_generic_target(state, &request.url).await?;
    let auth = parse_secret(secret)?;
    let mut provider_metadata = BTreeMap::from([
        ("operation".to_string(), "generic_https".to_string()),
        ("auth_mode".to_string(), auth.auth_mode.to_string()),
    ]);
    if let Ok(parsed) = Url::parse(&request.url) {
        if let Some(host) = parsed.host_str() {
            provider_metadata.insert("target_host".to_string(), host.to_string());
        }
    }

    // When a pinned address is available (DNS was resolved during validation),
    // build a one-shot client that resolves the hostname to that address,
    // preventing DNS rebinding between validation and execution.
    let client = match pinned_addr {
        Some(addr) => {
            let parsed = Url::parse(&request.url).map_err(|error| {
                ApiError::bad_request("BROKER_REQUEST_URL_INVALID", error.to_string())
            })?;
            let host = parsed.host_str().unwrap_or_default().to_string();
            reqwest::Client::builder()
                .resolve(&host, addr)
                .build()
                .map_err(|error| {
                    ApiError::internal("BROKER_CLIENT_BUILD_FAILED", error.to_string())
                })?
        }
        None => state.upstream_client.clone(),
    };

    let mut builder = client.request(map_method(&request.method), request.url.as_str());

    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }

    builder = builder.header(auth.name, auth.value);

    if let Some(body) = &request.body {
        builder = builder.body(body.clone());
    }

    let response = builder.send().await.map_err(|error| {
        ApiError::bad_gateway("BROKER_UPSTREAM_REQUEST_FAILED", error.to_string())
    })?;

    Ok((response, provider_metadata))
}

fn parse_secret(secret: &str) -> Result<InjectedHeader, ApiError> {
    if let Ok(payload) = serde_json::from_str::<GenericHttpsSecretEnvelope>(secret) {
        return match payload {
            GenericHttpsSecretEnvelope::Bearer { value } => build_bearer_header(&value),
            GenericHttpsSecretEnvelope::Header { header_name, value } => {
                let name = HeaderName::from_bytes(header_name.as_bytes()).map_err(|error| {
                    ApiError::internal("BROKER_SECRET_FORMAT_INVALID", error.to_string())
                })?;
                let value = HeaderValue::from_str(&value).map_err(|error| {
                    ApiError::internal("BROKER_SECRET_FORMAT_INVALID", error.to_string())
                })?;
                Ok(InjectedHeader {
                    name,
                    value,
                    auth_mode: "header",
                })
            }
        };
    }

    build_bearer_header(secret)
}

fn build_bearer_header(secret: &str) -> Result<InjectedHeader, ApiError> {
    let value = HeaderValue::from_str(&format!("Bearer {secret}"))
        .map_err(|error| ApiError::internal("BROKER_SECRET_FORMAT_INVALID", error.to_string()))?;
    Ok(InjectedHeader {
        name: reqwest::header::AUTHORIZATION,
        value,
        auth_mode: "bearer",
    })
}

/// Validates the target URL is not a restricted IP. Returns a pinned
/// `SocketAddr` when DNS resolution was performed, so the caller can
/// bind the outbound request to the same address (preventing DNS
/// rebinding between validation and execution).
async fn validate_generic_target(
    state: &AppState,
    request_url: &str,
) -> Result<Option<std::net::SocketAddr>, ApiError> {
    if state.config.allow_private_upstream_hosts {
        return Ok(None);
    }

    let parsed = Url::parse(request_url)
        .map_err(|error| ApiError::bad_request("BROKER_REQUEST_URL_INVALID", error.to_string()))?;
    let host = parsed.host_str().ok_or_else(|| {
        ApiError::bad_request("BROKER_REQUEST_URL_INVALID", "request url is missing host")
    })?;

    if state.config.allow_http_loopback && crate::capability::is_loopback_host(host) {
        return Ok(None);
    }
    let port = parsed.port_or_known_default().ok_or_else(|| {
        ApiError::bad_request("BROKER_REQUEST_URL_INVALID", "request url is missing port")
    })?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_restricted_ip(ip) {
            return Err(ApiError::forbidden(
                "BROKER_TARGET_RESTRICTED",
                "generic https execution does not allow private, link-local, or loopback targets",
            ));
        }
        return Ok(Some(std::net::SocketAddr::new(ip, port)));
    }

    let resolved: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| ApiError::bad_gateway("BROKER_DNS_RESOLUTION_FAILED", error.to_string()))?
        .collect();

    if resolved.is_empty() {
        return Err(ApiError::bad_gateway(
            "BROKER_DNS_RESOLUTION_FAILED",
            "generic https execution could not resolve the upstream host",
        ));
    }

    for addr in &resolved {
        if is_restricted_ip(addr.ip()) {
            return Err(ApiError::forbidden(
                "BROKER_TARGET_RESTRICTED",
                "generic https execution resolved to a private, link-local, or loopback target",
            ));
        }
    }

    Ok(Some(resolved[0]))
}

fn is_restricted_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_restricted_ipv4(ip),
        IpAddr::V6(ip) => {
            // Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) and
            // check against IPv4 restricted ranges to prevent SSRF bypass.
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_restricted_ipv4(mapped);
            }
            ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

fn is_restricted_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_documentation()
        // Carrier-grade NAT / shared address space (RFC 6598)
        || (octets[0] == 100 && (64..128).contains(&octets[1]))
        // Benchmarking (RFC 2544)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
}
