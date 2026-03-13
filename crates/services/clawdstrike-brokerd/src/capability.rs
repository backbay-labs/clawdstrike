use clawdstrike_broker_protocol::{
    binding_proof_message, normalize_header_name, sha256_hex, verify_capability, BrokerCapability,
    BrokerExecuteRequest, ProofBindingMode, UrlScheme,
};
use hush_core::{PublicKey, Signature};
use url::Url;

use crate::api::ApiError;
use crate::config::Config;

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

pub fn validate_execute_request(
    request: &BrokerExecuteRequest,
    config: &Config,
    require_streaming_capability: bool,
) -> Result<(BrokerCapability, Url), ApiError> {
    let capability = verify_capability(&request.capability, &config.trusted_hushd_public_keys)
        .map_err(|error| ApiError::forbidden("BROKER_CAPABILITY_INVALID", error.to_string()))?;

    if capability.expires_at <= chrono::Utc::now() {
        return Err(ApiError::forbidden(
            "BROKER_CAPABILITY_EXPIRED",
            "broker capability has expired",
        ));
    }

    if let Some(binding) = &capability.proof_binding {
        match binding.mode {
            ProofBindingMode::Loopback => {
                let binding_secret = request.binding_secret.as_deref().ok_or_else(|| {
                    ApiError::forbidden(
                        "BROKER_BINDING_REQUIRED",
                        "loopback proof binding requires binding_secret",
                    )
                })?;
                let expected = binding.binding_sha256.as_deref().ok_or_else(|| {
                    ApiError::forbidden(
                        "BROKER_BINDING_REQUIRED",
                        "loopback proof binding is missing binding_sha256",
                    )
                })?;
                if sha256_hex(binding_secret) != expected {
                    return Err(ApiError::forbidden(
                        "BROKER_BINDING_MISMATCH",
                        "binding secret did not match the issued capability",
                    ));
                }
            }
            ProofBindingMode::Dpop => {
                validate_dpop_binding(binding, request, &capability, config)?;
            }
            _ => {
                return Err(ApiError::forbidden(
                    "BROKER_BINDING_UNSUPPORTED",
                    "the requested proof binding mode is not supported by brokerd v1",
                ));
            }
        }
    }

    if require_streaming_capability && capability.request_constraints.stream_response != Some(true)
    {
        return Err(ApiError::forbidden(
            "BROKER_STREAM_NOT_AUTHORIZED",
            "the issued capability does not authorize streaming execution",
        ));
    }

    let parsed = Url::parse(&request.request.url)
        .map_err(|error| ApiError::bad_request("BROKER_REQUEST_URL_INVALID", error.to_string()))?;
    let host = parsed.host_str().ok_or_else(|| {
        ApiError::bad_request("BROKER_REQUEST_URL_INVALID", "request url is missing host")
    })?;

    let scheme = match parsed.scheme() {
        "https" => UrlScheme::Https,
        "http" => {
            if !config.allow_http_loopback || !is_loopback_host(host) {
                return Err(ApiError::forbidden(
                    "BROKER_REQUEST_INSECURE",
                    "http upstream execution is only allowed for loopback dev/test targets",
                ));
            }
            UrlScheme::Http
        }
        other => {
            return Err(ApiError::bad_request(
                "BROKER_REQUEST_SCHEME_INVALID",
                format!("unsupported request scheme: {other}"),
            ))
        }
    };

    if capability.destination.scheme != scheme {
        return Err(ApiError::forbidden(
            "BROKER_DESTINATION_MISMATCH",
            "request scheme did not match the issued capability",
        ));
    }

    if !capability.destination.host.eq_ignore_ascii_case(host) {
        return Err(ApiError::forbidden(
            "BROKER_DESTINATION_MISMATCH",
            "request host did not match the issued capability",
        ));
    }

    if capability.destination.port.is_some()
        && capability.destination.port != parsed.port_or_known_default()
    {
        return Err(ApiError::forbidden(
            "BROKER_DESTINATION_MISMATCH",
            "request port did not match the issued capability",
        ));
    }

    if capability.destination.method != request.request.method {
        return Err(ApiError::forbidden(
            "BROKER_METHOD_MISMATCH",
            "request method did not match the issued capability",
        ));
    }

    if !capability
        .destination
        .exact_paths
        .iter()
        .any(|path| path == parsed.path())
    {
        return Err(ApiError::forbidden(
            "BROKER_PATH_MISMATCH",
            "request path did not match the issued capability",
        ));
    }

    if let Some(max_body_bytes) = capability.request_constraints.max_body_bytes {
        let body_len = request
            .request
            .body
            .as_ref()
            .map(|body| body.len() as u64)
            .unwrap_or(0);
        if body_len > max_body_bytes {
            return Err(ApiError::forbidden(
                "BROKER_BODY_TOO_LARGE",
                "request body exceeded the issued capability size limit",
            ));
        }
    }

    if capability.request_constraints.require_request_body_sha256 == Some(true)
        && request.request.body_sha256.is_none()
    {
        return Err(ApiError::bad_request(
            "BROKER_BODY_HASH_REQUIRED",
            "body_sha256 is required by the issued capability",
        ));
    }

    if let Some(expected_hash) = &request.request.body_sha256 {
        let body = request.request.body.as_deref().ok_or_else(|| {
            ApiError::bad_request(
                "BROKER_BODY_HASH_INVALID",
                "body_sha256 was provided without a request body",
            )
        })?;
        if sha256_hex(body) != *expected_hash {
            return Err(ApiError::forbidden(
                "BROKER_BODY_HASH_INVALID",
                "body_sha256 did not match the request body",
            ));
        }
    }

    for header_name in request.request.headers.keys() {
        let normalized = normalize_header_name(header_name);
        if normalized == "authorization" {
            return Err(ApiError::forbidden(
                "BROKER_HEADER_FORBIDDEN",
                "authorization header injection is not allowed",
            ));
        }
        if !capability
            .request_constraints
            .allowed_headers
            .iter()
            .any(|allowed| normalize_header_name(allowed) == normalized)
        {
            return Err(ApiError::forbidden(
                "BROKER_HEADER_FORBIDDEN",
                format!("header '{normalized}' is not allowed by the issued capability"),
            ));
        }
    }

    Ok((capability, parsed))
}

fn validate_dpop_binding(
    binding: &clawdstrike_broker_protocol::ProofBinding,
    request: &BrokerExecuteRequest,
    capability: &BrokerCapability,
    config: &Config,
) -> Result<(), ApiError> {
    let proof = request.binding_proof.as_ref().ok_or_else(|| {
        ApiError::forbidden(
            "BROKER_BINDING_PROOF_REQUIRED",
            "dpop proof binding requires binding_proof",
        )
    })?;
    if !matches!(proof.mode, ProofBindingMode::Dpop) {
        return Err(ApiError::forbidden(
            "BROKER_BINDING_PROOF_INVALID",
            "binding_proof mode did not match the issued capability",
        ));
    }

    let public_key = proof.public_key.as_deref().ok_or_else(|| {
        ApiError::forbidden(
            "BROKER_BINDING_PROOF_INVALID",
            "dpop binding_proof is missing public_key",
        )
    })?;
    let signature = proof.signature.as_deref().ok_or_else(|| {
        ApiError::forbidden(
            "BROKER_BINDING_PROOF_INVALID",
            "dpop binding_proof is missing signature",
        )
    })?;
    let issued_at = proof.issued_at.as_ref().ok_or_else(|| {
        ApiError::forbidden(
            "BROKER_BINDING_PROOF_INVALID",
            "dpop binding_proof is missing issued_at",
        )
    })?;
    let nonce = proof.nonce.as_deref().ok_or_else(|| {
        ApiError::forbidden(
            "BROKER_BINDING_PROOF_INVALID",
            "dpop binding_proof is missing nonce",
        )
    })?;
    let expected_thumbprint = binding.key_thumbprint.as_deref().ok_or_else(|| {
        ApiError::forbidden(
            "BROKER_BINDING_PROOF_INVALID",
            "dpop capability binding is missing key_thumbprint",
        )
    })?;
    if sha256_hex(public_key) != expected_thumbprint {
        return Err(ApiError::forbidden(
            "BROKER_BINDING_MISMATCH",
            "binding proof public key did not match the issued capability",
        ));
    }

    let now = chrono::Utc::now();
    if issued_at > &(now + chrono::Duration::seconds(5)) {
        return Err(ApiError::forbidden(
            "BROKER_BINDING_PROOF_INVALID",
            "binding proof issued_at is too far in the future",
        ));
    }
    if now
        .signed_duration_since(issued_at.to_owned())
        .num_seconds()
        > config.binding_proof_ttl_secs as i64
    {
        return Err(ApiError::forbidden(
            "BROKER_BINDING_PROOF_EXPIRED",
            "binding proof is too old",
        ));
    }

    let public_key = PublicKey::from_hex(public_key)
        .map_err(|error| ApiError::forbidden("BROKER_BINDING_PROOF_INVALID", error.to_string()))?;
    let signature = Signature::from_hex(signature)
        .map_err(|error| ApiError::forbidden("BROKER_BINDING_PROOF_INVALID", error.to_string()))?;
    let message = binding_proof_message(
        &capability.capability_id,
        &request.request.method,
        &request.request.url,
        request.request.body_sha256.as_deref(),
        issued_at,
        nonce,
    );

    if !public_key.verify(message.as_bytes(), &signature) {
        return Err(ApiError::forbidden(
            "BROKER_BINDING_MISMATCH",
            "binding proof signature verification failed",
        ));
    }

    Ok(())
}
