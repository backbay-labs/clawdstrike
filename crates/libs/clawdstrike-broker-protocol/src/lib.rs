#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use chrono::{DateTime, Utc};
use hush_core::{sha256, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const BROKER_EXECUTION_ID_HEADER: &str = "x-clawdstrike-execution-id";
pub const BROKER_CAPABILITY_ID_HEADER: &str = "x-clawdstrike-capability-id";
pub const BROKER_PROVIDER_HEADER: &str = "x-clawdstrike-provider";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerProvider {
    Openai,
    Github,
    Slack,
    GenericHttps,
}

impl BrokerProvider {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Github => "github",
            Self::Slack => "slack",
            Self::GenericHttps => "generic_https",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
}

impl HttpMethod {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::PATCH => "PATCH",
            Self::DELETE => "DELETE",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UrlScheme {
    Http,
    Https,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBindingMode {
    Loopback,
    Dpop,
    Mtls,
    Spiffe,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    pub id: String,
    pub provider: BrokerProvider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofBinding {
    pub mode: ProofBindingMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingProof {
    pub mode: ProofBindingMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerDestination {
    pub scheme: UrlScheme,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub method: HttpMethod,
    pub exact_paths: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequestConstraints {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_request_body_sha256: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_redirects: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_response: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_executions: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCapability {
    pub capability_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_fingerprint: Option<String>,
    pub secret_ref: CredentialRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_binding: Option<ProofBinding>,
    pub destination: BrokerDestination,
    pub request_constraints: BrokerRequestConstraints,
    pub evidence_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_preview: Option<BrokerIntentPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<BrokerDelegationLineage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCapabilityIssueRequest {
    pub provider: BrokerProvider,
    pub url: String,
    pub method: HttpMethod,
    pub secret_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_binding: Option<ProofBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCapabilityIssueResponse {
    pub capability: String,
    pub capability_id: String,
    pub expires_at: DateTime<Utc>,
    pub policy_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequest {
    pub url: String,
    pub method: HttpMethod,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerExecuteRequest {
    pub capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_proof: Option<BindingProof>,
    pub request: BrokerRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerExecuteResponse {
    pub execution_id: String,
    pub capability_id: String,
    pub provider: BrokerProvider,
    pub status: u16,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCompletionBundle {
    pub generated_at: DateTime<Utc>,
    pub capability: BrokerCapabilityStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executions: Vec<BrokerExecutionEvidence>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerExecutionPhase {
    Started,
    #[default]
    Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerExecutionOutcome {
    Success,
    UpstreamError,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerIntentRiskLevel {
    #[default]
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerApprovalState {
    #[default]
    NotRequired,
    Pending,
    Approved,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerMintedIdentityKind {
    Static,
    GithubAppInstallation,
    SlackAppSession,
    AwsStsSession,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerCapabilityState {
    #[default]
    Active,
    Revoked,
    Frozen,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerMintedIdentity {
    pub kind: BrokerMintedIdentityKind,
    pub subject: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerIntentResource {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerIntentPreview {
    pub preview_id: String,
    pub provider: BrokerProvider,
    pub operation: String,
    pub summary: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub risk_level: BrokerIntentRiskLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<BrokerIntentResource>,
    pub egress_host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd_micros: Option<u64>,
    #[serde(default)]
    pub approval_required: bool,
    #[serde(default)]
    pub approval_state: BrokerApprovalState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerDelegationLineage {
    pub token_jti: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_token_jti: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
    pub depth: usize,
    pub issuer: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerExecutionEvidence {
    pub execution_id: String,
    pub capability_id: String,
    pub provider: BrokerProvider,
    #[serde(default)]
    pub phase: BrokerExecutionPhase,
    pub executed_at: DateTime<Utc>,
    pub secret_ref_id: String,
    pub url: String,
    pub method: HttpMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_chunk_count: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<BrokerExecutionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minted_identity: Option<BrokerMintedIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<BrokerDelegationLineage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspicion_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerCapabilityStatus {
    pub capability_id: String,
    pub provider: BrokerProvider,
    pub state: BrokerCapabilityState,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_fingerprint: Option<String>,
    pub secret_ref_id: String,
    pub url: String,
    pub method: HttpMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub execution_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_executions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_executed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_outcome: Option<BrokerExecutionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_preview: Option<BrokerIntentPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minted_identity: Option<BrokerMintedIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<BrokerDelegationLineage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspicion_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerProviderFreezeStatus {
    pub provider: BrokerProvider,
    pub frozen_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SignedBrokerCapabilityEnvelope {
    payload: BrokerCapability,
    signature_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBrokerCompletionBundleEnvelope {
    payload: BrokerCompletionBundle,
    signature_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CapabilityEnvelopeError {
    #[error("failed to serialize capability payload: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to decode signature: {0}")]
    DecodeSignature(#[from] hush_core::Error),
    #[error("capability signature did not match any trusted key")]
    InvalidSignature,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleEnvelopeError {
    #[error("failed to serialize completion bundle payload: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to decode signature: {0}")]
    DecodeSignature(#[from] hush_core::Error),
    #[error("completion bundle signature did not match any trusted key")]
    InvalidSignature,
}

pub fn sign_capability(
    capability: &BrokerCapability,
    keypair: &Keypair,
) -> Result<String, CapabilityEnvelopeError> {
    let payload = serde_json::to_vec(capability)?;
    let envelope = SignedBrokerCapabilityEnvelope {
        payload: capability.clone(),
        signature_hex: keypair.sign(&payload).to_hex(),
    };
    Ok(serde_json::to_string(&envelope)?)
}

pub fn verify_capability(
    envelope: &str,
    trusted_keys: &[PublicKey],
) -> Result<BrokerCapability, CapabilityEnvelopeError> {
    let envelope: SignedBrokerCapabilityEnvelope = serde_json::from_str(envelope)?;
    let payload = serde_json::to_vec(&envelope.payload)?;
    let signature = Signature::from_hex(&envelope.signature_hex)?;

    if trusted_keys
        .iter()
        .any(|key| key.verify(&payload, &signature))
    {
        return Ok(envelope.payload);
    }

    Err(CapabilityEnvelopeError::InvalidSignature)
}

pub fn sign_completion_bundle(
    bundle: &BrokerCompletionBundle,
    keypair: &Keypair,
) -> Result<String, BundleEnvelopeError> {
    let payload = serde_json::to_vec(bundle)?;
    let envelope = SignedBrokerCompletionBundleEnvelope {
        payload: bundle.clone(),
        signature_hex: keypair.sign(&payload).to_hex(),
    };
    Ok(serde_json::to_string(&envelope)?)
}

pub fn verify_completion_bundle(
    envelope: &str,
    trusted_keys: &[PublicKey],
) -> Result<BrokerCompletionBundle, BundleEnvelopeError> {
    let envelope: SignedBrokerCompletionBundleEnvelope = serde_json::from_str(envelope)?;
    let payload = serde_json::to_vec(&envelope.payload)?;
    let signature = Signature::from_hex(&envelope.signature_hex)?;

    if trusted_keys
        .iter()
        .any(|key| key.verify(&payload, &signature))
    {
        return Ok(envelope.payload);
    }

    Err(BundleEnvelopeError::InvalidSignature)
}

#[must_use]
pub fn normalize_header_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[must_use]
pub fn sha256_hex(value: &str) -> String {
    sha256(value.as_bytes()).to_hex()
}

#[must_use]
pub fn binding_proof_message(
    capability_id: &str,
    method: &HttpMethod,
    url: &str,
    body_sha256: Option<&str>,
    issued_at: &DateTime<Utc>,
    nonce: &str,
) -> String {
    format!(
        "broker-capability:{capability_id}\nmethod:{}\nurl:{url}\nbody-sha256:{}\nissued-at:{}\nnonce:{nonce}",
        method.as_str(),
        body_sha256.unwrap_or("-"),
        issued_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_capability() -> BrokerCapability {
        BrokerCapability {
            capability_id: "cap-123".to_string(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
            policy_hash: "abc123".to_string(),
            session_id: Some("sess-1".to_string()),
            endpoint_agent_id: Some("agent-1".to_string()),
            runtime_agent_id: None,
            runtime_agent_kind: None,
            origin_fingerprint: None,
            secret_ref: CredentialRef {
                id: "openai/dev".to_string(),
                provider: BrokerProvider::Openai,
                tenant_id: None,
                environment: Some("dev".to_string()),
                labels: std::collections::BTreeMap::new(),
            },
            proof_binding: Some(ProofBinding {
                mode: ProofBindingMode::Loopback,
                binding_sha256: Some("deadbeef".to_string()),
                key_thumbprint: None,
                workload_id: None,
            }),
            destination: BrokerDestination {
                scheme: UrlScheme::Https,
                host: "api.openai.com".to_string(),
                port: Some(443),
                method: HttpMethod::POST,
                exact_paths: vec!["/v1/responses".to_string()],
            },
            request_constraints: BrokerRequestConstraints {
                allowed_headers: vec!["content-type".to_string()],
                max_body_bytes: Some(1024),
                require_request_body_sha256: Some(true),
                allow_redirects: Some(false),
                stream_response: Some(false),
                max_executions: None,
            },
            evidence_required: true,
            intent_preview: None,
            lineage: None,
        }
    }

    #[test]
    fn signed_capability_round_trips() {
        let capability = sample_capability();
        let keypair = Keypair::generate();
        let envelope = sign_capability(&capability, &keypair).expect("capability signed");
        let verified = verify_capability(&envelope, &[keypair.public_key()]).expect("verified");
        assert_eq!(verified, capability);
    }

    #[test]
    fn verify_rejects_untrusted_key() {
        let capability = sample_capability();
        let keypair = Keypair::generate();
        let other = Keypair::generate();
        let envelope = sign_capability(&capability, &keypair).expect("capability signed");
        let err =
            verify_capability(&envelope, &[other.public_key()]).expect_err("should reject key");
        assert!(matches!(err, CapabilityEnvelopeError::InvalidSignature));
    }

    #[test]
    fn signed_completion_bundle_round_trips() {
        let capability = BrokerCapabilityStatus {
            capability_id: "cap-123".to_string(),
            provider: BrokerProvider::Openai,
            state: BrokerCapabilityState::Active,
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
            policy_hash: "abc123".to_string(),
            session_id: Some("sess-1".to_string()),
            endpoint_agent_id: Some("agent-1".to_string()),
            runtime_agent_id: None,
            runtime_agent_kind: None,
            origin_fingerprint: None,
            secret_ref_id: "openai/dev".to_string(),
            url: "https://api.openai.com/v1/responses".to_string(),
            method: HttpMethod::POST,
            state_reason: None,
            revoked_at: None,
            execution_count: 1,
            max_executions: None,
            last_executed_at: Some(Utc::now()),
            last_status_code: Some(200),
            last_outcome: Some(BrokerExecutionOutcome::Success),
            intent_preview: None,
            minted_identity: None,
            lineage: None,
            suspicion_reason: None,
        };
        let bundle = BrokerCompletionBundle {
            generated_at: Utc::now(),
            capability,
            executions: Vec::new(),
        };
        let keypair = Keypair::generate();
        let envelope = sign_completion_bundle(&bundle, &keypair).expect("bundle signed");
        let verified =
            verify_completion_bundle(&envelope, &[keypair.public_key()]).expect("bundle verified");
        assert_eq!(verified, bundle);
    }

    #[test]
    fn sha256_hex_matches_expected_digest() {
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn binding_proof_message_is_stable() {
        let issued_at = DateTime::parse_from_rfc3339("2026-03-12T21:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            binding_proof_message(
                "cap-123",
                &HttpMethod::POST,
                "https://broker.example/v1/execute",
                Some("abc123"),
                &issued_at,
                "nonce-1",
            ),
            "broker-capability:cap-123\nmethod:POST\nurl:https://broker.example/v1/execute\nbody-sha256:abc123\nissued-at:2026-03-12T21:30:00.000Z\nnonce:nonce-1"
        );
    }
}
