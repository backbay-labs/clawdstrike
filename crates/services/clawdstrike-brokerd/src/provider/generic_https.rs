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

    Ok(ProviderExecutionResponse {
        status,
        headers,
        body: Some(body.clone()),
        content_type,
        response_body_sha256: Some(sha256_hex(&body)),
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
    validate_generic_target(state, &request.url).await?;
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

    let mut builder = state
        .upstream_client
        .request(map_method(&request.method), request.url.as_str());

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

async fn validate_generic_target(state: &AppState, request_url: &str) -> Result<(), ApiError> {
    if state.config.allow_private_upstream_hosts {
        return Ok(());
    }

    let parsed = Url::parse(request_url)
        .map_err(|error| ApiError::bad_request("BROKER_REQUEST_URL_INVALID", error.to_string()))?;
    let host = parsed.host_str().ok_or_else(|| {
        ApiError::bad_request("BROKER_REQUEST_URL_INVALID", "request url is missing host")
    })?;
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
        return Ok(());
    }

    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| {
            ApiError::bad_gateway("BROKER_DNS_RESOLUTION_FAILED", error.to_string())
        })?;
    let mut saw_address = false;
    for addr in resolved {
        saw_address = true;
        if is_restricted_ip(addr.ip()) {
            return Err(ApiError::forbidden(
                "BROKER_TARGET_RESTRICTED",
                "generic https execution resolved to a private, link-local, or loopback target",
            ));
        }
    }

    if !saw_address {
        return Err(ApiError::bad_gateway(
            "BROKER_DNS_RESOLUTION_FAILED",
            "generic https execution could not resolve the upstream host",
        ));
    }

    Ok(())
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
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_documentation()
}
