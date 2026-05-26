//! Device-proof generation, signing, and validation for OpenClaw connect.

use super::identity::{load_openclaw_device_identity, OpenClawDeviceIdentity};
use super::protocol::{GatewayClientIdentity, GatewayDeviceProof};
use super::util::now_ms;
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{pkcs8::DecodePrivateKey, Signature, Signer, SigningKey, VerifyingKey};
use std::collections::HashSet;

pub(super) const DEVICE_AUTH_MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
pub(super) const REQUIRED_GATEWAY_SCOPES: [&str; 4] = [
    "operator.read",
    "operator.write",
    "operator.approvals",
    "operator.pairing",
];

pub(super) fn default_gateway_scopes() -> Vec<String> {
    REQUIRED_GATEWAY_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect()
}

pub(super) fn build_gateway_device_proof(
    client: &GatewayClientIdentity,
    role: &str,
    scopes: &[String],
    auth_token: Option<&str>,
    nonce: Option<&str>,
) -> Result<Option<GatewayDeviceProof>> {
    let identity = match load_openclaw_device_identity()? {
        Some(value) => value,
        None => return Ok(None),
    };

    // Newer gateways require `device.nonce` whenever a device proof is present.
    // Prefer challenge-bound nonce; otherwise generate a fallback nonce.
    let nonce_value = nonce
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let client_mode = client.mode.as_deref().unwrap_or("cli");
    let now = now_ms();
    let proof = build_gateway_device_proof_from_identity(
        &identity,
        &client.id,
        client_mode,
        role,
        scopes,
        now,
        auth_token,
        Some(nonce_value.as_str()),
        now,
    )?;
    Ok(Some(proof))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_gateway_device_proof_from_identity(
    identity: &OpenClawDeviceIdentity,
    client_id: &str,
    client_mode: &str,
    role: &str,
    scopes: &[String],
    signed_at_ms: u64,
    token: Option<&str>,
    nonce: Option<&str>,
    now_ms_value: u64,
) -> Result<GatewayDeviceProof> {
    validate_gateway_scopes(scopes)?;
    validate_signed_at_window(signed_at_ms, now_ms_value)?;

    let signing_key = load_identity_signing_key(identity)?;
    validate_identity_key_consistency(identity, &signing_key)?;

    let payload = build_device_auth_payload(
        &identity.device_id,
        client_id,
        client_mode,
        role,
        scopes,
        signed_at_ms,
        token,
        nonce,
    );
    let signature: Signature = signing_key.sign(payload.as_bytes());

    Ok(GatewayDeviceProof {
        id: identity.device_id.clone(),
        public_key: identity.public_key_raw_base64url.clone(),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        signed_at: signed_at_ms,
        nonce: nonce.map(|value| value.to_string()),
    })
}

fn validate_gateway_scopes(scopes: &[String]) -> Result<()> {
    if scopes.is_empty() {
        return Err(anyhow::anyhow!("OpenClaw connect scopes cannot be empty"));
    }

    let scope_set: HashSet<String> = scopes
        .iter()
        .map(|scope| scope.trim().to_string())
        .filter(|scope| !scope.is_empty())
        .collect();

    if scope_set.is_empty() {
        return Err(anyhow::anyhow!("OpenClaw connect scopes cannot be blank"));
    }

    for required in REQUIRED_GATEWAY_SCOPES {
        if !scope_set.contains(required) {
            return Err(anyhow::anyhow!(
                "OpenClaw connect scopes missing required scope '{}'",
                required
            ));
        }
    }

    Ok(())
}

fn validate_signed_at_window(signed_at_ms: u64, now_ms_value: u64) -> Result<()> {
    let lower_bound = now_ms_value.saturating_sub(DEVICE_AUTH_MAX_CLOCK_SKEW_MS);
    let upper_bound = now_ms_value.saturating_add(DEVICE_AUTH_MAX_CLOCK_SKEW_MS);
    if signed_at_ms < lower_bound || signed_at_ms > upper_bound {
        return Err(anyhow::anyhow!(
            "OpenClaw device proof signed_at is outside allowable replay window"
        ));
    }
    Ok(())
}

fn load_identity_signing_key(identity: &OpenClawDeviceIdentity) -> Result<SigningKey> {
    SigningKey::from_pkcs8_pem(identity.private_key_pem.trim())
        .map_err(|err| anyhow::anyhow!("invalid OpenClaw identity private key PEM: {err}"))
}

fn validate_identity_key_consistency(
    identity: &OpenClawDeviceIdentity,
    signing_key: &SigningKey,
) -> Result<()> {
    let declared_public_raw = URL_SAFE_NO_PAD
        .decode(identity.public_key_raw_base64url.as_bytes())
        .map_err(|err| anyhow::anyhow!("invalid OpenClaw identity public key encoding: {err}"))?;

    let declared_public_bytes: [u8; 32] = declared_public_raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid OpenClaw identity public key length"))?;
    let declared_public = VerifyingKey::from_bytes(&declared_public_bytes)
        .map_err(|err| anyhow::anyhow!("invalid OpenClaw identity public key bytes: {err}"))?;
    let derived_public = signing_key.verifying_key();

    if declared_public.as_bytes() != derived_public.as_bytes() {
        return Err(anyhow::anyhow!(
            "OpenClaw identity public/private key mismatch"
        ));
    }

    let expected_device_id = hush_core::sha256(derived_public.as_bytes()).to_hex();
    if identity.device_id != expected_device_id {
        return Err(anyhow::anyhow!(
            "OpenClaw identity device id mismatch for configured keypair"
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_device_auth_payload(
    device_id: &str,
    client_id: &str,
    client_mode: &str,
    role: &str,
    scopes: &[String],
    signed_at_ms: u64,
    token: Option<&str>,
    nonce: Option<&str>,
) -> String {
    let version = if nonce.is_some() { "v2" } else { "v1" };
    let scopes_csv = scopes.join(",");
    let token_value = token.unwrap_or_default();
    let mut pieces = vec![
        version.to_string(),
        device_id.to_string(),
        client_id.to_string(),
        client_mode.to_string(),
        role.to_string(),
        scopes_csv,
        signed_at_ms.to_string(),
        token_value.to_string(),
    ];
    if version == "v2" {
        pieces.push(nonce.unwrap_or_default().to_string());
    }
    pieces.join("|")
}
