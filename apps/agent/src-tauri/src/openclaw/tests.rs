//! Integration tests for the OpenClaw submodules.

use super::backoff::{next_reconnect_attempt, was_connected_long_enough};
use super::command::extract_json_payload;
use super::connection::CONNECT_HANDSHAKE_TIMEOUT;
use super::device_proof::{
    build_device_auth_payload, build_gateway_device_proof_from_identity, default_gateway_scopes,
    DEVICE_AUTH_MAX_CLOCK_SKEW_MS,
};
use super::dto::{GatewayConnectionStatus, OpenClawAgentEvent};
use super::identity::{
    load_openclaw_device_identity_from_candidates, load_openclaw_device_identity_from_path,
    OpenClawDeviceIdentity, OPENCLAW_IDENTITY_PATH, OPENCLAW_LEGACY_STATE_DIRS, OPENCLAW_STATE_DIR,
};
use super::manager::OpenClawManager;
use super::protocol::{parse_gateway_frame, GatewayEventFrame, GatewayFrame, GatewayResponseFrame};
use super::secret_store::GatewaySecrets;
use super::session::GatewayHandle;
use super::url_validation::{
    validate_gateway_runtime_target, validate_gateway_target_ips, validate_gateway_url,
};
use super::util::{normalize_gateway_error, normalize_secret_field, now_ms};
use crate::settings::{OpenClawGatewayMetadata, Settings};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    Signature, SigningKey, Verifier,
};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use uuid::Uuid;
use zeroize::Zeroizing;

#[test]
fn extract_json_payload_prefers_clean_payload() {
    let raw = "noise\n{\"ok\":true}\n";
    let value = match extract_json_payload(raw) {
        Ok(v) => v,
        Err(err) => panic!("expected json payload, got error: {err}"),
    };
    assert_eq!(value["ok"], Value::Bool(true));
}

#[test]
fn normalize_gateway_error_uses_fallback() {
    assert_eq!(normalize_gateway_error(None, "fallback"), "fallback");
}

#[test]
fn stable_connection_window_detection_works() {
    let stable_reset = Duration::from_secs(90);
    assert!(was_connected_long_enough(
        Some(1000),
        stable_reset,
        1000 + 90_000
    ));
    assert!(!was_connected_long_enough(
        Some(1000),
        stable_reset,
        1000 + 10_000
    ));
    assert!(!was_connected_long_enough(
        None,
        stable_reset,
        1000 + 90_000
    ));
}

#[test]
fn reconnect_attempt_resets_after_stable_session() {
    assert_eq!(next_reconnect_attempt(7, true), 1);
    assert_eq!(next_reconnect_attempt(7, false), 8);
}

#[test]
fn empty_secret_fields_are_cleared() {
    assert_eq!(normalize_secret_field(String::new()), None);
    assert_eq!(normalize_secret_field("   ".to_string()), None);
    assert_eq!(
        normalize_secret_field("token-value".to_string()),
        Some("token-value".to_string())
    );
}

#[test]
fn gateway_target_ip_validation_requires_wss_for_public_targets() {
    let err =
        match validate_gateway_target_ips("ws", &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]) {
            Ok(_) => panic!("expected ws public target validation to fail"),
            Err(err) => err,
        };
    assert!(err
        .to_string()
        .contains("non-loopback gateway_url values must use wss://"));
}

#[test]
fn gateway_target_ip_validation_rejects_private_targets() {
    let err = match validate_gateway_target_ips("wss", &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))]) {
        Ok(_) => panic!("expected private target validation to fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("private/link-local gateway_url addresses are not allowed"));
}

#[test]
fn gateway_target_ip_validation_rejects_ipv4_mapped_private_targets() {
    let mapped_private = IpAddr::V6(
        "::ffff:10.0.0.7"
            .parse::<std::net::Ipv6Addr>()
            .unwrap_or_else(|_| panic!("failed to parse mapped private ipv6 literal")),
    );
    let err = match validate_gateway_target_ips("wss", &[mapped_private]) {
        Ok(_) => panic!("expected mapped private target validation to fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("private/link-local gateway_url addresses are not allowed"));
}

#[test]
fn gateway_target_ip_validation_allows_loopback_targets() {
    assert!(validate_gateway_target_ips("ws", &[IpAddr::V4(Ipv4Addr::LOCALHOST)]).is_ok());
    assert!(
        validate_gateway_target_ips("ws", &[IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)]).is_ok()
    );
}

#[tokio::test]
async fn validate_gateway_url_rejects_private_ip_literal() {
    let err = match validate_gateway_url("wss://10.0.0.5:443").await {
        Ok(_) => panic!("expected private ip literal validation to fail"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("private/link-local gateway_url addresses are not allowed"));
}

#[tokio::test]
async fn runtime_gateway_validation_rejects_dns_drift_outside_pinned_set() {
    let err =
        match validate_gateway_runtime_target("ws://localhost:9876", &["127.0.0.2".to_string()])
            .await
        {
            Ok(_) => panic!("expected runtime pinned-IP validation to fail"),
            Err(err) => err,
        };
    assert!(err.to_string().contains("pinned allowlist"));
}

#[test]
fn device_auth_payload_matches_openclaw_v1_format() {
    let scopes = vec!["operator.read".to_string(), "operator.write".to_string()];
    let payload = build_device_auth_payload(
        "device-id",
        "cli",
        "cli",
        "operator",
        &scopes,
        1_700_000_000_123,
        Some("gateway-token"),
        None,
    );
    assert_eq!(
        payload,
        "v1|device-id|cli|cli|operator|operator.read,operator.write|1700000000123|gateway-token"
    );
}

#[test]
fn gateway_device_proof_signs_openclaw_payload() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let private_key_pem = match signing_key.to_pkcs8_pem(Default::default()) {
        Ok(value) => value.to_string(),
        Err(err) => panic!("failed to encode private key pem: {err}"),
    };
    let public_key_raw_base64url = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
    let device_id = hush_core::sha256(verifying_key.as_bytes()).to_hex();
    let identity = OpenClawDeviceIdentity {
        device_id: device_id.clone(),
        public_key_raw_base64url: public_key_raw_base64url.clone(),
        private_key_pem: Zeroizing::new(private_key_pem),
    };
    let scopes = vec![
        "operator.read".to_string(),
        "operator.write".to_string(),
        "operator.approvals".to_string(),
        "operator.pairing".to_string(),
    ];
    let signed_at = now_ms();
    let proof = match build_gateway_device_proof_from_identity(
        &identity,
        "cli",
        "cli",
        "operator",
        &scopes,
        signed_at,
        Some("gateway-token"),
        None,
        signed_at,
    ) {
        Ok(value) => value,
        Err(err) => panic!("failed to build device proof: {err}"),
    };
    assert_eq!(proof.id, device_id);
    assert_eq!(proof.public_key, public_key_raw_base64url);
    assert_eq!(proof.signed_at, signed_at);

    let payload = build_device_auth_payload(
        &proof.id,
        "cli",
        "cli",
        "operator",
        &scopes,
        proof.signed_at,
        Some("gateway-token"),
        None,
    );
    let sig_bytes = match URL_SAFE_NO_PAD.decode(&proof.signature) {
        Ok(value) => value,
        Err(err) => panic!("failed to decode signature: {err}"),
    };
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(value) => value,
        Err(err) => panic!("failed to parse signature bytes: {err}"),
    };
    assert!(
        verifying_key.verify(payload.as_bytes(), &signature).is_ok(),
        "device signature failed verification"
    );
}

#[test]
fn gateway_device_proof_with_nonce_signs_openclaw_v2_payload() {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let private_key_pem = signing_key
        .to_pkcs8_pem(Default::default())
        .unwrap_or_else(|err| panic!("failed to encode private key pem: {err}"))
        .to_string();
    let public_key_raw_base64url = URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
    let device_id = hush_core::sha256(verifying_key.as_bytes()).to_hex();
    let identity = OpenClawDeviceIdentity {
        device_id: device_id.clone(),
        public_key_raw_base64url: public_key_raw_base64url.clone(),
        private_key_pem: Zeroizing::new(private_key_pem),
    };
    let scopes = default_gateway_scopes();
    let signed_at = now_ms();
    let nonce = "nonce-123";

    let proof = build_gateway_device_proof_from_identity(
        &identity,
        "cli",
        "cli",
        "operator",
        &scopes,
        signed_at,
        Some("gateway-token"),
        Some(nonce),
        signed_at,
    )
    .unwrap_or_else(|err| panic!("failed to build v2 device proof: {err}"));

    assert_eq!(proof.id, device_id);
    assert_eq!(proof.public_key, public_key_raw_base64url);
    assert_eq!(proof.nonce.as_deref(), Some(nonce));

    let payload = build_device_auth_payload(
        &proof.id,
        "cli",
        "cli",
        "operator",
        &scopes,
        proof.signed_at,
        Some("gateway-token"),
        Some(nonce),
    );
    assert!(
        payload.starts_with("v2|"),
        "nonce-aware payload should use v2 format"
    );
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .unwrap_or_else(|err| panic!("failed to decode signature: {err}"));
    let signature = Signature::from_slice(&sig_bytes)
        .unwrap_or_else(|err| panic!("failed to parse signature bytes: {err}"));
    assert!(
        verifying_key.verify(payload.as_bytes(), &signature).is_ok(),
        "v2 device signature failed verification"
    );
}

#[test]
fn gateway_device_proof_rejects_stale_signed_at() {
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let private_key_pem = signing_key
        .to_pkcs8_pem(Default::default())
        .unwrap_or_else(|err| panic!("failed to encode private key pem: {err}"))
        .to_string();
    let identity = OpenClawDeviceIdentity {
        device_id: hush_core::sha256(verifying_key.as_bytes()).to_hex(),
        public_key_raw_base64url: URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
        private_key_pem: Zeroizing::new(private_key_pem),
    };
    let scopes = default_gateway_scopes();
    let stale_signed_at = now_ms().saturating_sub(DEVICE_AUTH_MAX_CLOCK_SKEW_MS + 5_000);

    let now = now_ms();
    let result = build_gateway_device_proof_from_identity(
        &identity,
        "cli",
        "cli",
        "operator",
        &scopes,
        stale_signed_at,
        Some("gateway-token"),
        None,
        now,
    );

    let err = result
        .err()
        .unwrap_or_else(|| anyhow::anyhow!("expected stale signed_at error"));
    assert!(
        err.to_string().contains("signed_at"),
        "unexpected error text: {err}"
    );
}

#[test]
fn gateway_device_proof_rejects_missing_required_scopes() {
    let signing_key = SigningKey::from_bytes(&[13u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let private_key_pem = signing_key
        .to_pkcs8_pem(Default::default())
        .unwrap_or_else(|err| panic!("failed to encode private key pem: {err}"))
        .to_string();
    let identity = OpenClawDeviceIdentity {
        device_id: hush_core::sha256(verifying_key.as_bytes()).to_hex(),
        public_key_raw_base64url: URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
        private_key_pem: Zeroizing::new(private_key_pem),
    };
    let scopes = vec!["operator.read".to_string(), "operator.write".to_string()];

    let now = now_ms();
    let result = build_gateway_device_proof_from_identity(
        &identity,
        "cli",
        "cli",
        "operator",
        &scopes,
        now,
        Some("gateway-token"),
        None,
        now,
    );

    let err = result
        .err()
        .unwrap_or_else(|| anyhow::anyhow!("expected missing scope error"));
    assert!(
        err.to_string().contains("missing required scope"),
        "unexpected error text: {err}"
    );
}

#[test]
fn gateway_device_proof_rejects_public_private_key_mismatch_even_with_token() {
    let signing_key_a = SigningKey::from_bytes(&[17u8; 32]);
    let signing_key_b = SigningKey::from_bytes(&[19u8; 32]);
    let verifying_key_a = signing_key_a.verifying_key();
    let private_key_pem_b = signing_key_b
        .to_pkcs8_pem(Default::default())
        .unwrap_or_else(|err| panic!("failed to encode private key pem: {err}"))
        .to_string();

    let identity = OpenClawDeviceIdentity {
        device_id: hush_core::sha256(verifying_key_a.as_bytes()).to_hex(),
        public_key_raw_base64url: URL_SAFE_NO_PAD.encode(verifying_key_a.as_bytes()),
        private_key_pem: Zeroizing::new(private_key_pem_b),
    };

    let now = now_ms();
    let result = build_gateway_device_proof_from_identity(
        &identity,
        "cli",
        "cli",
        "operator",
        &default_gateway_scopes(),
        now,
        Some("valid-token"),
        None,
        now,
    );

    let err = result
        .err()
        .unwrap_or_else(|| anyhow::anyhow!("expected key mismatch error"));
    assert!(
        err.to_string().contains("public/private key mismatch"),
        "unexpected error text: {err}"
    );
}

#[test]
fn device_auth_payload_changes_when_token_rotates() {
    let scopes = default_gateway_scopes();
    let signed_at = now_ms();
    let payload_before = build_device_auth_payload(
        "device-id",
        "cli",
        "cli",
        "operator",
        &scopes,
        signed_at,
        Some("token-v1"),
        None,
    );
    let payload_after = build_device_auth_payload(
        "device-id",
        "cli",
        "cli",
        "operator",
        &scopes,
        signed_at,
        Some("token-v2"),
        None,
    );

    assert_ne!(
        payload_before, payload_after,
        "rotating gateway token should change signed auth payload"
    );
    assert!(
        payload_after.ends_with("|token-v2"),
        "rotated payload missing updated token"
    );
}

#[test]
fn load_openclaw_identity_derives_device_id_from_public_key() {
    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let private_key_pem = match signing_key.to_pkcs8_pem(Default::default()) {
        Ok(value) => value.to_string(),
        Err(err) => panic!("failed to encode private key pem: {err}"),
    };
    let public_key_pem = match verifying_key.to_public_key_pem(Default::default()) {
        Ok(value) => value,
        Err(err) => panic!("failed to encode public key pem: {err}"),
    };
    let temp_dir = std::env::temp_dir().join(format!("openclaw-identity-test-{}", Uuid::new_v4()));
    if let Err(err) = fs::create_dir_all(&temp_dir) {
        panic!("failed to create temp identity dir: {err}");
    }
    let identity_path = temp_dir.join("device.json");
    let raw = serde_json::json!({
        "version": 1,
        "deviceId": "mismatch-id",
        "publicKeyPem": public_key_pem,
        "privateKeyPem": private_key_pem,
    });
    if let Err(err) = fs::write(&identity_path, raw.to_string()) {
        let _ = fs::remove_dir_all(&temp_dir);
        panic!("failed to write temp identity file: {err}");
    }

    let loaded = match load_openclaw_device_identity_from_path(&identity_path) {
        Ok(value) => value,
        Err(err) => {
            let _ = fs::remove_dir_all(&temp_dir);
            panic!("failed to load temp identity: {err}");
        }
    };
    let expected_device_id = hush_core::sha256(verifying_key.as_bytes()).to_hex();
    assert_eq!(loaded.device_id, expected_device_id);
    assert_eq!(
        loaded.public_key_raw_base64url,
        URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())
    );

    if let Err(err) = fs::remove_dir_all(&temp_dir) {
        panic!("failed to remove temp identity dir: {err}");
    }
}

#[test]
fn load_openclaw_identity_falls_back_to_legacy_when_primary_missing() {
    let signing_key = SigningKey::from_bytes(&[29u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let private_key_pem = signing_key
        .to_pkcs8_pem(Default::default())
        .unwrap_or_else(|err| panic!("failed to encode private key pem: {err}"))
        .to_string();
    let public_key_pem = verifying_key
        .to_public_key_pem(Default::default())
        .unwrap_or_else(|err| panic!("failed to encode public key pem: {err}"));

    let temp_home = std::env::temp_dir().join(format!("openclaw-fallback-test-{}", Uuid::new_v4()));
    let primary_identity = temp_home
        .join(OPENCLAW_STATE_DIR)
        .join(OPENCLAW_IDENTITY_PATH);
    let legacy_identity = temp_home
        .join(OPENCLAW_LEGACY_STATE_DIRS[0])
        .join(OPENCLAW_IDENTITY_PATH);

    if let Some(parent) = primary_identity.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("failed to create primary dir: {err}"));
    }
    if let Some(parent) = legacy_identity.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("failed to create legacy dir: {err}"));
    }

    let raw = serde_json::json!({
        "version": 1,
        "deviceId": "legacy-device-id",
        "publicKeyPem": public_key_pem,
        "privateKeyPem": private_key_pem,
    });
    fs::write(&legacy_identity, raw.to_string())
        .unwrap_or_else(|err| panic!("failed to write legacy identity: {err}"));

    let loaded = load_openclaw_device_identity_from_candidates(&[
        primary_identity.clone(),
        legacy_identity.clone(),
    ])
    .unwrap_or_else(|err| panic!("failed to load fallback identity: {err}"))
    .unwrap_or_else(|| panic!("expected fallback identity to load"));

    let expected_device_id = hush_core::sha256(verifying_key.as_bytes()).to_hex();
    assert_eq!(loaded.device_id, expected_device_id);

    let _ = fs::remove_dir_all(&temp_home);
}

#[tokio::test]
async fn stale_session_exit_does_not_remove_replacement_handle() {
    let settings = Arc::new(RwLock::new(Settings::default()));
    let manager = OpenClawManager::new(settings);

    let (old_tx, _old_rx) = mpsc::channel(1);
    let (new_tx, _new_rx) = mpsc::channel(1);

    manager.sessions.write().await.insert(
        "gw-1".to_string(),
        GatewayHandle {
            tx: old_tx,
            session_id: 1,
        },
    );
    manager.sessions.write().await.insert(
        "gw-1".to_string(),
        GatewayHandle {
            tx: new_tx,
            session_id: 2,
        },
    );

    manager.remove_session_if_current("gw-1", 1).await;

    let sessions = manager.sessions.read().await;
    let handle = match sessions.get("gw-1") {
        Some(value) => value,
        None => panic!("replacement session should remain present"),
    };
    assert_eq!(handle.session_id, 2);
}

#[tokio::test]
async fn connects_and_relays_request_against_mock_gateway() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(value) => value,
        Err(err) => panic!("failed to bind mock gateway listener: {}", err),
    };
    let addr = match listener.local_addr() {
        Ok(value) => value,
        Err(err) => panic!("failed to read listener address: {}", err),
    };

    let server = tokio::spawn(async move {
        let (stream, _) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => return Err(format!("accept failed: {}", err)),
        };
        let mut ws = match accept_async(stream).await {
            Ok(value) => value,
            Err(err) => return Err(format!("ws accept failed: {}", err)),
        };

        let connect_text = match ws.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(_)) => return Err("expected text connect frame".to_string()),
            Some(Err(err)) => return Err(format!("read connect frame failed: {}", err)),
            None => return Err("stream closed before connect frame".to_string()),
        };

        let (connect_id, connect_params) = match parse_gateway_frame(&connect_text) {
            Some(GatewayFrame::Req(req)) if req.method == "connect" => (req.id, req.params),
            Some(_) => return Err("unexpected first frame shape".to_string()),
            None => return Err("failed to parse connect frame".to_string()),
        };
        if let Some(params) = connect_params {
            if params
                .get("auth")
                .and_then(|value| value.get("token"))
                .and_then(|value| value.as_str())
                != Some("gateway-token")
            {
                return Err("connect auth token mismatch".to_string());
            }
        } else {
            return Err("connect params missing".to_string());
        }

        let connect_response = GatewayFrame::Res(GatewayResponseFrame {
            id: connect_id,
            ok: true,
            payload: Some(serde_json::json!({"session":"mock"})),
            error: None,
        });

        let connect_response_text = match serde_json::to_string(&connect_response) {
            Ok(value) => value,
            Err(err) => return Err(format!("serialize connect response failed: {}", err)),
        };

        if let Err(err) = ws.send(Message::Text(connect_response_text)).await {
            return Err(format!("send connect response failed: {}", err));
        }

        let presence_event = GatewayFrame::Event(GatewayEventFrame {
            event: "presence".to_string(),
            payload: Some(serde_json::json!([{"client":"mock"}])),
            seq: Some(1),
            state_version: None,
        });
        let presence_text = match serde_json::to_string(&presence_event) {
            Ok(value) => value,
            Err(err) => return Err(format!("serialize presence event failed: {}", err)),
        };
        if let Err(err) = ws.send(Message::Text(presence_text)).await {
            return Err(format!("send presence event failed: {}", err));
        }

        let request_text = match ws.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(_)) => return Err("expected text relay frame".to_string()),
            Some(Err(err)) => return Err(format!("read relay frame failed: {}", err)),
            None => return Err("stream closed before relay frame".to_string()),
        };

        let request_id = match parse_gateway_frame(&request_text) {
            Some(GatewayFrame::Req(req)) if req.method == "node.list" => req.id,
            Some(_) => return Err("unexpected relay frame method".to_string()),
            None => return Err("failed to parse relay frame".to_string()),
        };

        let relay_response = GatewayFrame::Res(GatewayResponseFrame {
            id: request_id,
            ok: true,
            payload: Some(serde_json::json!({
                "nodes": [{"nodeId":"node-1"}]
            })),
            error: None,
        });
        let relay_text = match serde_json::to_string(&relay_response) {
            Ok(value) => value,
            Err(err) => return Err(format!("serialize relay response failed: {}", err)),
        };
        if let Err(err) = ws.send(Message::Text(relay_text)).await {
            return Err(format!("send relay response failed: {}", err));
        }

        let _ = ws.next().await;
        Ok::<(), String>(())
    });

    let mut settings = Settings::default();
    settings.openclaw.gateways.push(OpenClawGatewayMetadata {
        id: "gw-test".to_string(),
        label: "Gateway Test".to_string(),
        gateway_url: format!("ws://{}", addr),
        pinned_ips: vec!["127.0.0.1".to_string()],
    });
    settings.openclaw.active_gateway_id = Some("gw-test".to_string());

    let manager = OpenClawManager::new(Arc::new(RwLock::new(settings)));
    if let Err(err) = manager
        .secrets
        .set(
            "gw-test",
            GatewaySecrets {
                token: Some("gateway-token".to_string()),
                device_token: Some("legacy-device-token".to_string()),
            },
        )
        .await
    {
        panic!("failed to set test gateway secrets: {err}");
    }
    let mut events_rx = manager.subscribe();

    if let Err(err) = manager.connect_gateway("gw-test").await {
        panic!("connect_gateway failed: {}", err);
    }

    // Wait until the session is usable by retrying the relay call.
    let payload = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match manager
                .request_gateway("gw-test", "node.list".to_string(), None, 1_500)
                .await
            {
                Ok(value) => break value,
                Err(_) => {
                    sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("gateway request did not succeed within timeout"));
    assert_eq!(
        payload["nodes"][0]["nodeId"].as_str(),
        Some("node-1"),
        "node.list relay payload mismatch"
    );

    let mut saw_presence = false;
    for _ in 0..20 {
        let event = tokio::time::timeout(Duration::from_millis(150), events_rx.recv()).await;
        if let Ok(Ok(OpenClawAgentEvent::GatewayEvent { frame, .. })) = event {
            if frame.event == "presence" {
                saw_presence = true;
                break;
            }
        }
    }
    assert!(saw_presence, "did not observe presence event fan-out");

    if let Err(err) = manager.disconnect_gateway("gw-test").await {
        panic!("disconnect_gateway failed: {}", err);
    }

    let server_result = match server.await {
        Ok(value) => value,
        Err(err) => panic!("mock gateway task join failed: {}", err),
    };
    if let Err(err) = server_result {
        panic!("mock gateway task failed: {}", err);
    }
}

#[tokio::test]
async fn device_token_only_populates_auth_token_field() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|err| panic!("failed to bind device-token listener: {err}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|err| panic!("failed to read device-token listener address: {err}"));

    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|err| format!("accept failed: {err}"))?;
        let mut ws = accept_async(stream)
            .await
            .map_err(|err| format!("ws accept failed: {err}"))?;

        let connect_text = match ws.next().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(_)) => return Err("expected text connect frame".to_string()),
            Some(Err(err)) => return Err(format!("read connect frame failed: {err}")),
            None => return Err("stream closed before connect frame".to_string()),
        };
        let (connect_id, params) = match parse_gateway_frame(&connect_text) {
            Some(GatewayFrame::Req(req)) if req.method == "connect" => (req.id, req.params),
            Some(_) => return Err("unexpected first frame shape".to_string()),
            None => return Err("failed to parse connect frame".to_string()),
        };

        let auth = params
            .as_ref()
            .and_then(|value| value.get("auth"))
            .and_then(|value| value.as_object())
            .ok_or_else(|| "connect auth missing".to_string())?;

        let token = auth
            .get("token")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "connect auth token missing".to_string())?;
        if token != "device-only-token" {
            return Err(format!(
                "connect auth token mismatch: expected device-only-token, got {token}"
            ));
        }

        let connect_response = GatewayFrame::Res(GatewayResponseFrame {
            id: connect_id,
            ok: true,
            payload: Some(serde_json::json!({"session":"mock"})),
            error: None,
        });
        let response_text = serde_json::to_string(&connect_response)
            .map_err(|err| format!("serialize connect response failed: {err}"))?;
        ws.send(Message::Text(response_text))
            .await
            .map_err(|err| format!("send connect response failed: {err}"))?;

        let _ = tokio::time::timeout(Duration::from_secs(3), ws.next()).await;
        Ok::<(), String>(())
    });

    let mut settings = Settings::default();
    settings.openclaw.gateways.push(OpenClawGatewayMetadata {
        id: "gw-device".to_string(),
        label: "Device Gateway".to_string(),
        gateway_url: format!("ws://{}", addr),
        pinned_ips: vec!["127.0.0.1".to_string()],
    });
    settings.openclaw.active_gateway_id = Some("gw-device".to_string());

    let manager = OpenClawManager::new(Arc::new(RwLock::new(settings)));
    manager
        .secrets
        .set(
            "gw-device",
            GatewaySecrets {
                token: None,
                device_token: Some("device-only-token".to_string()),
            },
        )
        .await
        .unwrap_or_else(|err| panic!("failed to set device-token secret: {err}"));

    manager
        .connect_gateway("gw-device")
        .await
        .unwrap_or_else(|err| panic!("connect_gateway failed: {err}"));

    let mut connected = false;
    for _ in 0..40 {
        let status = manager
            .list_gateways()
            .await
            .gateways
            .into_iter()
            .find(|gateway| gateway.id == "gw-device")
            .map(|gateway| gateway.runtime.status);
        if status == Some(GatewayConnectionStatus::Connected) {
            connected = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(connected, "gateway did not reach connected state");

    manager
        .disconnect_gateway("gw-device")
        .await
        .unwrap_or_else(|err| panic!("disconnect_gateway failed: {err}"));

    let server_result = server
        .await
        .unwrap_or_else(|err| panic!("device-token server join failed: {err}"));
    if let Err(err) = server_result {
        panic!("device-token server failed: {err}");
    }
}

#[tokio::test]
async fn reconnect_uses_rotated_gateway_token() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|err| panic!("failed to bind token-rotation listener: {err}"));
    let addr = listener
        .local_addr()
        .unwrap_or_else(|err| panic!("failed to read token-rotation listener address: {err}"));

    let server = tokio::spawn(async move {
        let expected_tokens = ["token-v1", "token-v2"];
        for expected in expected_tokens {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|err| format!("accept failed: {err}"))?;
            let mut ws = accept_async(stream)
                .await
                .map_err(|err| format!("ws accept failed: {err}"))?;

            let connect_text = match ws.next().await {
                Some(Ok(Message::Text(text))) => text,
                Some(Ok(_)) => return Err("expected text connect frame".to_string()),
                Some(Err(err)) => return Err(format!("read connect frame failed: {err}")),
                None => return Err("stream closed before connect frame".to_string()),
            };
            let (connect_id, params) = match parse_gateway_frame(&connect_text) {
                Some(GatewayFrame::Req(req)) if req.method == "connect" => (req.id, req.params),
                Some(_) => return Err("unexpected first frame shape".to_string()),
                None => return Err("failed to parse connect frame".to_string()),
            };

            let token = params
                .as_ref()
                .and_then(|value| value.get("auth"))
                .and_then(|value| value.get("token"))
                .and_then(|value| value.as_str())
                .ok_or_else(|| "connect auth token missing".to_string())?;
            if token != expected {
                return Err(format!(
                    "connect auth token mismatch: expected {expected}, got {token}"
                ));
            }

            let connect_response = GatewayFrame::Res(GatewayResponseFrame {
                id: connect_id,
                ok: true,
                payload: Some(serde_json::json!({"session":"mock"})),
                error: None,
            });
            let response_text = serde_json::to_string(&connect_response)
                .map_err(|err| format!("serialize connect response failed: {err}"))?;
            ws.send(Message::Text(response_text))
                .await
                .map_err(|err| format!("send connect response failed: {err}"))?;

            let _ = tokio::time::timeout(Duration::from_secs(3), ws.next()).await;
        }

        Ok::<(), String>(())
    });

    let mut settings = Settings::default();
    settings.openclaw.gateways.push(OpenClawGatewayMetadata {
        id: "gw-rotate".to_string(),
        label: "Rotate Gateway".to_string(),
        gateway_url: format!("ws://{}", addr),
        pinned_ips: vec!["127.0.0.1".to_string()],
    });
    settings.openclaw.active_gateway_id = Some("gw-rotate".to_string());

    let manager = OpenClawManager::new(Arc::new(RwLock::new(settings)));
    manager
        .secrets
        .set(
            "gw-rotate",
            GatewaySecrets {
                token: Some("token-v1".to_string()),
                device_token: None,
            },
        )
        .await
        .unwrap_or_else(|err| panic!("failed to set initial gateway token: {err}"));

    manager
        .connect_gateway("gw-rotate")
        .await
        .unwrap_or_else(|err| panic!("first connect_gateway failed: {err}"));

    let mut connected = false;
    for _ in 0..40 {
        let status = manager
            .list_gateways()
            .await
            .gateways
            .into_iter()
            .find(|gateway| gateway.id == "gw-rotate")
            .map(|gateway| gateway.runtime.status);
        if status == Some(GatewayConnectionStatus::Connected) {
            connected = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        connected,
        "gateway did not reach connected state on first token"
    );

    manager
        .disconnect_gateway("gw-rotate")
        .await
        .unwrap_or_else(|err| panic!("first disconnect_gateway failed: {err}"));

    manager
        .upsert_gateway(super::dto::GatewayUpsertRequest {
            id: Some("gw-rotate".to_string()),
            label: "Rotate Gateway".to_string(),
            gateway_url: format!("ws://{}", addr),
            token: Some("token-v2".to_string()),
            device_token: None,
        })
        .await
        .unwrap_or_else(|err| panic!("failed to rotate gateway token: {err}"));

    manager
        .connect_gateway("gw-rotate")
        .await
        .unwrap_or_else(|err| panic!("second connect_gateway failed: {err}"));

    connected = false;
    for _ in 0..40 {
        let status = manager
            .list_gateways()
            .await
            .gateways
            .into_iter()
            .find(|gateway| gateway.id == "gw-rotate")
            .map(|gateway| gateway.runtime.status);
        if status == Some(GatewayConnectionStatus::Connected) {
            connected = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        connected,
        "gateway did not reach connected state after token rotation"
    );

    manager
        .disconnect_gateway("gw-rotate")
        .await
        .unwrap_or_else(|err| panic!("second disconnect_gateway failed: {err}"));

    let server_result = server
        .await
        .unwrap_or_else(|err| panic!("token-rotation server join failed: {err}"));
    if let Err(err) = server_result {
        panic!("token-rotation server failed: {err}");
    }
}

#[tokio::test]
async fn connect_handshake_times_out_when_gateway_never_replies() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(value) => value,
        Err(err) => panic!("failed to bind timeout test listener: {}", err),
    };
    let addr = match listener.local_addr() {
        Ok(value) => value,
        Err(err) => panic!("failed to read timeout test listener address: {}", err),
    };

    let server = tokio::spawn(async move {
        let (stream, _) = match listener.accept().await {
            Ok(value) => value,
            Err(err) => return Err(format!("accept failed: {}", err)),
        };
        let mut ws = match accept_async(stream).await {
            Ok(value) => value,
            Err(err) => return Err(format!("ws accept failed: {}", err)),
        };

        // Accept the connect request but never send the response.
        let _ = ws.next().await;
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        Ok::<(), String>(())
    });

    let manager = OpenClawManager::new(Arc::new(RwLock::new(Settings::default())));
    let metadata = OpenClawGatewayMetadata {
        id: "gw-timeout".to_string(),
        label: "Timeout Gateway".to_string(),
        gateway_url: format!("ws://{}", addr),
        pinned_ips: vec!["127.0.0.1".to_string()],
    };
    let secrets = GatewaySecrets::default();
    let (_tx, mut rx) = mpsc::channel(4);

    let started_at = Instant::now();
    let result = manager
        .run_gateway_connection_once("gw-timeout", &metadata, &secrets, &mut rx)
        .await;

    assert!(result.is_err(), "expected handshake timeout error");
    let err_text = format!(
        "{}",
        result
            .err()
            .unwrap_or_else(|| anyhow::anyhow!("missing error"))
    );
    assert!(
        err_text.contains("timeout waiting for connect response"),
        "unexpected error text: {err_text}"
    );
    assert!(
        started_at.elapsed() >= CONNECT_HANDSHAKE_TIMEOUT,
        "handshake timeout elapsed too quickly"
    );

    server.abort();
}
