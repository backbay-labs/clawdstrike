use clawdstrike_broker_protocol::{
    binding_proof_message, normalize_header_name, sha256_hex, verify_capability, BrokerCapability,
    BrokerExecuteRequest, ProofBindingMode, UrlScheme,
};
use hush_core::{PublicKey, Signature};
use url::Url;

use crate::api::ApiError;
use crate::config::Config;

pub(crate) fn is_loopback_host(host: &str) -> bool {
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

    let request_path_and_query = match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_string(),
    };
    if !capability
        .destination
        .exact_paths
        .iter()
        .any(|path| path == &request_path_and_query)
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

    if let Some(preview) = &capability.intent_preview {
        if let Some(preview_hash) = &preview.body_sha256 {
            let request_hash = request.request.body_sha256.as_deref().unwrap_or("");
            if request_hash != preview_hash {
                return Err(ApiError::forbidden(
                    "BROKER_PREVIEW_BODY_HASH_MISMATCH",
                    "request body_sha256 does not match the approved preview body hash",
                ));
            }
        }
    }

    const FORBIDDEN_HEADERS: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "host",
        "cookie",
        "transfer-encoding",
        "te",
        "connection",
        "upgrade",
    ];

    for header_name in request.request.headers.keys() {
        let normalized = normalize_header_name(header_name);
        if FORBIDDEN_HEADERS.contains(&normalized.as_str()) {
            return Err(ApiError::forbidden(
                "BROKER_HEADER_FORBIDDEN",
                format!("'{normalized}' header injection is not allowed"),
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
    if now.signed_duration_since(*issued_at).num_seconds() > config.binding_proof_ttl_secs as i64 {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use clawdstrike_broker_protocol::{
        binding_proof_message, sha256_hex, sign_capability, BindingProof, BrokerDestination,
        BrokerExecuteRequest, BrokerProvider, BrokerRequest, BrokerRequestConstraints,
        CredentialRef, HttpMethod, ProofBinding, ProofBindingMode, UrlScheme,
    };
    use hush_core::Keypair;
    use std::collections::BTreeMap;
    fn test_keypair() -> Keypair {
        Keypair::generate()
    }

    fn make_config(keypair: &Keypair) -> Config {
        Config {
            listen: "127.0.0.1:9889".to_string(),
            hushd_base_url: "http://127.0.0.1:9876".to_string(),
            hushd_token: None,
            secret_backend: crate::config::SecretBackendConfig::Env {
                prefix: "TEST_".to_string(),
            },
            trusted_hushd_public_keys: vec![keypair.public_key()],
            request_timeout_secs: 30,
            binding_proof_ttl_secs: 60,
            allow_http_loopback: false,
            allow_private_upstream_hosts: false,
            allow_invalid_upstream_tls: false,
            admin_token: None,
        }
    }

    fn make_capability(
        keypair: &Keypair,
    ) -> (clawdstrike_broker_protocol::BrokerCapability, String) {
        let capability = clawdstrike_broker_protocol::BrokerCapability {
            capability_id: "cap-test-1".to_string(),
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(300),
            policy_hash: "policy-hash-1".to_string(),
            session_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            runtime_agent_kind: None,
            origin_fingerprint: None,
            secret_ref: CredentialRef {
                id: "openai/dev".to_string(),
                provider: BrokerProvider::Openai,
                tenant_id: None,
                environment: None,
                labels: BTreeMap::new(),
            },
            proof_binding: None,
            destination: BrokerDestination {
                scheme: UrlScheme::Https,
                host: "api.openai.com".to_string(),
                port: Some(443),
                method: HttpMethod::POST,
                exact_paths: vec!["/v1/responses".to_string()],
            },
            request_constraints: BrokerRequestConstraints {
                allowed_headers: vec!["content-type".to_string()],
                max_body_bytes: None,
                require_request_body_sha256: None,
                allow_redirects: None,
                stream_response: None,
                max_executions: None,
            },
            evidence_required: true,
            intent_preview: None,
            lineage: None,
        };
        let envelope = sign_capability(&capability, keypair).expect("signed");
        (capability, envelope)
    }

    fn make_request(envelope: &str, url: &str) -> BrokerExecuteRequest {
        BrokerExecuteRequest {
            capability: envelope.to_string(),
            binding_secret: None,
            binding_proof: None,
            request: BrokerRequest {
                url: url.to_string(),
                method: HttpMethod::POST,
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: Some(r#"{"model":"gpt-4"}"#.to_string()),
                body_sha256: None,
            },
        }
    }

    // --- is_loopback_host ---

    #[test]
    fn is_loopback_host_localhost() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("Localhost"));
    }

    #[test]
    fn is_loopback_host_ipv4() {
        assert!(is_loopback_host("127.0.0.1"));
    }

    #[test]
    fn is_loopback_host_ipv6() {
        assert!(is_loopback_host("::1"));
    }

    #[test]
    fn is_loopback_host_non_loopback() {
        assert!(!is_loopback_host("api.openai.com"));
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("192.168.1.1"));
    }

    // --- validate_execute_request: happy path ---

    #[test]
    fn valid_request_succeeds() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let (cap, url) = validate_execute_request(&request, &config, false).unwrap();
        assert_eq!(cap.capability_id, "cap-test-1");
        assert_eq!(url.host_str().unwrap(), "api.openai.com");
    }

    // --- capability verification ---

    #[test]
    fn invalid_capability_signature_rejected() {
        let keypair = test_keypair();
        let other_keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&other_keypair);
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_CAPABILITY_INVALID");
    }

    // --- expired capability ---

    #[test]
    fn expired_capability_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.expires_at = chrono::Utc::now() - chrono::Duration::seconds(10);
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_CAPABILITY_EXPIRED");
    }

    // --- loopback proof binding ---

    #[test]
    fn loopback_binding_succeeds_with_correct_secret() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        let secret = "my-binding-secret";
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Loopback,
            binding_sha256: Some(sha256_hex(secret)),
            key_thumbprint: None,
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_secret = Some(secret.to_string());

        let result = validate_execute_request(&request, &config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn loopback_binding_fails_without_secret() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Loopback,
            binding_sha256: Some(sha256_hex("secret")),
            key_thumbprint: None,
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_REQUIRED");
    }

    #[test]
    fn loopback_binding_fails_without_sha256_in_capability() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Loopback,
            binding_sha256: None,
            key_thumbprint: None,
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_secret = Some("some-secret".to_string());

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_REQUIRED");
    }

    #[test]
    fn loopback_binding_fails_with_wrong_secret() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Loopback,
            binding_sha256: Some(sha256_hex("correct-secret")),
            key_thumbprint: None,
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_secret = Some("wrong-secret".to_string());

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_MISMATCH");
    }

    // --- unsupported binding mode ---

    #[test]
    fn unsupported_binding_mode_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Mtls,
            binding_sha256: None,
            key_thumbprint: None,
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_UNSUPPORTED");
    }

    // --- streaming capability check ---

    #[test]
    fn streaming_required_but_not_authorized() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let err = validate_execute_request(&request, &config, true).unwrap_err();
        assert_eq!(err.code, "BROKER_STREAM_NOT_AUTHORIZED");
    }

    #[test]
    fn streaming_authorized_succeeds() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.request_constraints.stream_response = Some(true);
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let result = validate_execute_request(&request, &config, true);
        assert!(result.is_ok());
    }

    // --- URL validation ---

    #[test]
    fn invalid_url_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let request = make_request(&envelope, "not-a-valid-url");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_REQUEST_URL_INVALID");
    }

    #[test]
    fn unsupported_scheme_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let request = make_request(&envelope, "ftp://api.openai.com/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_REQUEST_SCHEME_INVALID");
    }

    #[test]
    fn http_scheme_rejected_without_loopback_flag() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.destination.scheme = UrlScheme::Http;
        cap.destination.host = "localhost".to_string();
        cap.destination.port = Some(8080);
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "http://localhost:8080/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_REQUEST_INSECURE");
    }

    #[test]
    fn http_loopback_allowed_when_config_flag_set() {
        let keypair = test_keypair();
        let mut config = make_config(&keypair);
        config.allow_http_loopback = true;
        let mut cap = make_capability(&keypair).0;
        cap.destination.scheme = UrlScheme::Http;
        cap.destination.host = "localhost".to_string();
        cap.destination.port = Some(8080);
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "http://localhost:8080/v1/responses");

        let result = validate_execute_request(&request, &config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn http_non_loopback_rejected_even_with_flag() {
        let keypair = test_keypair();
        let mut config = make_config(&keypair);
        config.allow_http_loopback = true;
        let mut cap = make_capability(&keypair).0;
        cap.destination.scheme = UrlScheme::Http;
        cap.destination.host = "external.com".to_string();
        cap.destination.port = None;
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "http://external.com/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_REQUEST_INSECURE");
    }

    // --- destination mismatches ---

    #[test]
    fn scheme_mismatch_rejected() {
        let keypair = test_keypair();
        let mut config = make_config(&keypair);
        config.allow_http_loopback = true;
        let (_cap, envelope) = make_capability(&keypair);
        // Capability says https, request uses http
        let request = make_request(&envelope, "http://localhost/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        // http to non-loopback first check
        assert!(err.code == "BROKER_REQUEST_INSECURE" || err.code == "BROKER_DESTINATION_MISMATCH");
    }

    #[test]
    fn host_mismatch_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let request = make_request(&envelope, "https://evil.com:443/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_DESTINATION_MISMATCH");
    }

    #[test]
    fn port_mismatch_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let request = make_request(&envelope, "https://api.openai.com:8443/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_DESTINATION_MISMATCH");
    }

    #[test]
    fn method_mismatch_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.method = HttpMethod::GET;

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_METHOD_MISMATCH");
    }

    #[test]
    fn path_mismatch_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let request = make_request(&envelope, "https://api.openai.com:443/v1/chat/completions");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_PATH_MISMATCH");
    }

    // --- body size constraint ---

    #[test]
    fn body_too_large_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.request_constraints.max_body_bytes = Some(10);
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.body = Some("a".repeat(100));

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BODY_TOO_LARGE");
    }

    #[test]
    fn body_within_limit_allowed() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.request_constraints.max_body_bytes = Some(1000);
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let result = validate_execute_request(&request, &config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn no_body_counts_as_zero_bytes() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.request_constraints.max_body_bytes = Some(10);
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.body = None;

        let result = validate_execute_request(&request, &config, false);
        assert!(result.is_ok());
    }

    // --- body_sha256 ---

    #[test]
    fn body_sha256_required_but_missing() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.request_constraints.require_request_body_sha256 = Some(true);
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BODY_HASH_REQUIRED");
    }

    #[test]
    fn body_sha256_mismatch_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.body_sha256 = Some("deadbeef".to_string());

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BODY_HASH_INVALID");
    }

    #[test]
    fn body_sha256_without_body_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.body = None;
        request.request.body_sha256 = Some("deadbeef".to_string());

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BODY_HASH_INVALID");
    }

    #[test]
    fn correct_body_sha256_accepted() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let body = r#"{"model":"gpt-4"}"#;
        let hash = sha256_hex(body);
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.body = Some(body.to_string());
        request.request.body_sha256 = Some(hash);

        let result = validate_execute_request(&request, &config, false);
        assert!(result.is_ok());
    }

    // --- header validation ---

    #[test]
    fn authorization_header_always_forbidden() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.request_constraints.allowed_headers = vec!["authorization".to_string()];
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.headers =
            BTreeMap::from([("Authorization".to_string(), "Bearer evil".to_string())]);

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_HEADER_FORBIDDEN");
    }

    #[test]
    fn disallowed_header_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.headers = BTreeMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("x-custom-header".to_string(), "evil-value".to_string()),
        ]);

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_HEADER_FORBIDDEN");
    }

    #[test]
    fn allowed_header_accepted() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.headers =
            BTreeMap::from([("Content-Type".to_string(), "application/json".to_string())]);

        let result = validate_execute_request(&request, &config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn empty_headers_accepted() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let (_cap, envelope) = make_capability(&keypair);
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.request.headers = BTreeMap::new();

        let result = validate_execute_request(&request, &config, false);
        assert!(result.is_ok());
    }

    // --- DPoP binding ---

    #[test]
    fn dpop_binding_succeeds() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let proof_keypair = test_keypair();
        let pub_hex = proof_keypair.public_key().to_hex();
        let thumbprint = sha256_hex(&pub_hex);
        let nonce = "test-nonce-1";
        let issued_at = chrono::Utc::now();
        let url = "https://api.openai.com:443/v1/responses";

        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some(thumbprint),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");

        let message = binding_proof_message(
            &cap.capability_id,
            &HttpMethod::POST,
            url,
            None,
            &issued_at,
            nonce,
        );
        let signature = proof_keypair.sign(message.as_bytes());

        let mut request = make_request(&envelope, url);
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: Some(pub_hex),
            signature: Some(signature.to_hex()),
            issued_at: Some(issued_at),
            nonce: Some(nonce.to_string()),
        });

        let result = validate_execute_request(&request, &config, false);
        assert!(result.is_ok());
    }

    #[test]
    fn dpop_binding_missing_proof_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some("some-thumbprint".to_string()),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "https://api.openai.com:443/v1/responses");

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_PROOF_REQUIRED");
    }

    #[test]
    fn dpop_binding_wrong_mode_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some("some-thumbprint".to_string()),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Loopback,
            public_key: Some("key".to_string()),
            signature: Some("sig".to_string()),
            issued_at: Some(chrono::Utc::now()),
            nonce: Some("n".to_string()),
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_PROOF_INVALID");
    }

    #[test]
    fn dpop_binding_missing_public_key_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some("some-thumbprint".to_string()),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: None,
            signature: Some("sig".to_string()),
            issued_at: Some(chrono::Utc::now()),
            nonce: Some("n".to_string()),
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_PROOF_INVALID");
    }

    #[test]
    fn dpop_binding_missing_signature_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some("some-thumbprint".to_string()),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: Some("key".to_string()),
            signature: None,
            issued_at: Some(chrono::Utc::now()),
            nonce: Some("n".to_string()),
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_PROOF_INVALID");
    }

    #[test]
    fn dpop_binding_missing_issued_at_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some("some-thumbprint".to_string()),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: Some("key".to_string()),
            signature: Some("sig".to_string()),
            issued_at: None,
            nonce: Some("n".to_string()),
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_PROOF_INVALID");
    }

    #[test]
    fn dpop_binding_missing_nonce_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some("some-thumbprint".to_string()),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: Some("key".to_string()),
            signature: Some("sig".to_string()),
            issued_at: Some(chrono::Utc::now()),
            nonce: None,
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_PROOF_INVALID");
    }

    #[test]
    fn dpop_binding_missing_thumbprint_in_capability_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let proof_keypair = test_keypair();
        let pub_hex = proof_keypair.public_key().to_hex();
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: None,
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: Some(pub_hex),
            signature: Some("sig".to_string()),
            issued_at: Some(chrono::Utc::now()),
            nonce: Some("n".to_string()),
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_PROOF_INVALID");
    }

    #[test]
    fn dpop_binding_key_thumbprint_mismatch_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let proof_keypair = test_keypair();
        let pub_hex = proof_keypair.public_key().to_hex();
        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some("wrong-thumbprint".to_string()),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: Some(pub_hex),
            signature: Some("sig".to_string()),
            issued_at: Some(chrono::Utc::now()),
            nonce: Some("n".to_string()),
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_MISMATCH");
    }

    #[test]
    fn dpop_binding_future_issued_at_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let proof_keypair = test_keypair();
        let pub_hex = proof_keypair.public_key().to_hex();
        let thumbprint = sha256_hex(&pub_hex);
        let far_future = chrono::Utc::now() + chrono::Duration::seconds(120);

        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some(thumbprint),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: Some(pub_hex),
            signature: Some("sig".to_string()),
            issued_at: Some(far_future),
            nonce: Some("n".to_string()),
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_PROOF_INVALID");
    }

    #[test]
    fn dpop_binding_expired_proof_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let proof_keypair = test_keypair();
        let pub_hex = proof_keypair.public_key().to_hex();
        let thumbprint = sha256_hex(&pub_hex);
        let old_time = chrono::Utc::now() - chrono::Duration::seconds(3600);

        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some(thumbprint),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let mut request = make_request(&envelope, "https://api.openai.com:443/v1/responses");
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: Some(pub_hex),
            signature: Some("sig".to_string()),
            issued_at: Some(old_time),
            nonce: Some("n".to_string()),
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_PROOF_EXPIRED");
    }

    #[test]
    fn dpop_binding_bad_signature_rejected() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let proof_keypair = test_keypair();
        let pub_hex = proof_keypair.public_key().to_hex();
        let thumbprint = sha256_hex(&pub_hex);
        let nonce = "test-nonce";
        let issued_at = chrono::Utc::now();
        let url = "https://api.openai.com:443/v1/responses";

        let mut cap = make_capability(&keypair).0;
        cap.proof_binding = Some(ProofBinding {
            mode: ProofBindingMode::Dpop,
            binding_sha256: None,
            key_thumbprint: Some(thumbprint),
            workload_id: None,
        });
        let envelope = sign_capability(&cap, &keypair).expect("signed");

        // Sign the wrong message
        let wrong_signature = proof_keypair.sign(b"wrong-message");

        let mut request = make_request(&envelope, url);
        request.binding_proof = Some(BindingProof {
            mode: ProofBindingMode::Dpop,
            public_key: Some(pub_hex),
            signature: Some(wrong_signature.to_hex()),
            issued_at: Some(issued_at),
            nonce: Some(nonce.to_string()),
        });

        let err = validate_execute_request(&request, &config, false).unwrap_err();
        assert_eq!(err.code, "BROKER_BINDING_MISMATCH");
    }

    // --- port: None in capability means any port ---

    #[test]
    fn port_none_in_capability_accepts_any_port() {
        let keypair = test_keypair();
        let config = make_config(&keypair);
        let mut cap = make_capability(&keypair).0;
        cap.destination.port = None;
        let envelope = sign_capability(&cap, &keypair).expect("signed");
        let request = make_request(&envelope, "https://api.openai.com:8443/v1/responses");

        let result = validate_execute_request(&request, &config, false);
        assert!(result.is_ok());
    }
}
