//! Sentinel Swarm Hub MVP routes backed by ControlDb.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use hush_core::{canonical::canonicalize, sha256_hex, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::api::v1::V1Error;
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::control_db::{
    ControlDbError, SwarmBlobRefInput, SwarmFindingInput, SwarmHeadRecord,
    SwarmRevocationInput, SwarmTargetReferenceInput,
};
use crate::rbac::{Action, ResourceType};
use crate::state::AppState;

const FINDING_ENVELOPE_SCHEMA: &str = "clawdstrike.swarm.finding_envelope.v1";
const FINDING_BLOB_SCHEMA: &str = "clawdstrike.swarm.finding_blob.v1";
const HEAD_ANNOUNCEMENT_SCHEMA: &str = "clawdstrike.swarm.head_announcement.v1";
const REVOCATION_ENVELOPE_SCHEMA: &str = "clawdstrike.swarm.revocation_envelope.v1";
const HUB_CONFIG_SCHEMA: &str = "clawdstrike.swarm.hub_config.v1";
const REPLAY_SCHEMA: &str = "clawdstrike.swarm.replay.v1";
const BLOB_LOOKUP_SCHEMA: &str = "clawdstrike.swarm.blob_lookup.v1";
const SWARM_HUB_TRUST_POLICY_KEY: &str = "swarm_hub_trust_policy";
const ISSUER_ID_PREFIX: &str = "aegis:ed25519:";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_REPLAY_ENTRIES_PER_SYNC: u64 = 500;
const CHECKPOINT_INTERVAL: u64 = 50;
const RETENTION_MS: u64 = 86_400_000;
const MAX_INLINE_BLOB_BYTES: u64 = 0;
const MAX_TITLE_LEN: usize = 512;
const MAX_SUMMARY_LEN: usize = 4096;
const MAX_TAGS_COUNT: usize = 50;
const MAX_BLOB_REFS_COUNT: usize = 100;
const MAX_RELATED_FINDING_IDS_COUNT: usize = 200;
const ALLOWED_TRUST_POLICY_SCHEMAS: &[&str] = &[
    FINDING_ENVELOPE_SCHEMA,
    FINDING_BLOB_SCHEMA,
    HEAD_ANNOUNCEMENT_SCHEMA,
    REVOCATION_ENVELOPE_SCHEMA,
    HUB_CONFIG_SCHEMA,
];

const FINDING_ENVELOPE_KEYS: &[&str] = &[
    "schema",
    "findingId",
    "issuerId",
    "feedId",
    "feedSeq",
    "publishedAt",
    "title",
    "summary",
    "severity",
    "confidence",
    "status",
    "signalCount",
    "tags",
    "relatedFindingIds",
    "blobRefs",
    "attestation",
    "publish",
];
const FINDING_BLOB_REF_KEYS: &[&str] =
    &["blobId", "digest", "mediaType", "byteLength", "publish"];
const DURABLE_PUBLISH_KEYS: &[&str] = &[
    "uri",
    "publishedAt",
    "notaryRecordId",
    "notaryEnvelopeHash",
    "witnessProofs",
];
const WITNESS_PROOF_KEYS: &[&str] = &["provider", "digest", "uri"];
const ATTESTATION_KEYS: &[&str] = &["algorithm", "publicKey", "signature"];
const TARGET_REFERENCE_SCHEMAS: &[&str] = &[
    FINDING_ENVELOPE_SCHEMA,
    FINDING_BLOB_SCHEMA,
    REVOCATION_ENVELOPE_SCHEMA,
];

const ALLOWED_SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];
const ALLOWED_STATUSES: &[&str] = &[
    "emerging",
    "confirmed",
    "promoted",
    "dismissed",
    "false_positive",
    "archived",
];
const ALLOWED_WITNESS_PROVIDERS: &[&str] = &["witness", "notary", "spine", "other"];
const ALLOWED_REVOCATION_ACTIONS: &[&str] = &["revoke", "supersede"];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FindingEnvelopeStatus {
    Emerging,
    Confirmed,
    Promoted,
    Dismissed,
    FalsePositive,
    Archived,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AttestationAlgorithm {
    Ed25519,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WitnessProofProvider {
    Witness,
    Notary,
    Spine,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WitnessProofRef {
    provider: WitnessProofProvider,
    digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurablePublishMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notary_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notary_envelope_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    witness_proofs: Option<Vec<WitnessProofRef>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolAttestation {
    algorithm: AttestationAlgorithm,
    public_key: String,
    signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingBlobRef {
    blob_id: String,
    digest: String,
    media_type: String,
    byte_length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publish: Option<DurablePublishMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingEnvelope {
    schema: String,
    finding_id: String,
    issuer_id: String,
    feed_id: String,
    feed_seq: u64,
    published_at: u64,
    title: String,
    summary: String,
    severity: FindingSeverity,
    confidence: f64,
    status: FindingEnvelopeStatus,
    signal_count: u64,
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    related_finding_ids: Option<Vec<String>>,
    blob_refs: Vec<FindingBlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attestation: Option<ProtocolAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publish: Option<DurablePublishMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolTargetReference {
    schema: String,
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RevocationAction {
    Revoke,
    Supersede,
}

impl RevocationAction {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Revoke => "revoke",
            Self::Supersede => "supersede",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationEnvelope {
    schema: String,
    revocation_id: String,
    issuer_id: String,
    feed_id: String,
    feed_seq: u64,
    issued_at: u64,
    action: RevocationAction,
    target: ProtocolTargetReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replacement: Option<ProtocolTargetReference>,
    reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attestation: Option<ProtocolAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publish: Option<DurablePublishMetadata>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadAnnouncementCheckpointRef {
    log_id: String,
    checkpoint_seq: u64,
    envelope_hash: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadAnnouncement {
    schema: &'static str,
    fact_id: String,
    feed_id: String,
    issuer_id: String,
    head_seq: u64,
    head_envelope_hash: String,
    entry_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_ref: Option<HeadAnnouncementCheckpointRef>,
    announced_at: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HubEndpoint {
    id: String,
    url: String,
    protocols: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HubReplayConfig {
    max_entries_per_sync: u64,
    checkpoint_interval: u64,
    retention_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HubBlobConfig {
    max_inline_bytes: u64,
    require_digest: bool,
    providers: Vec<HubEndpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HubTrustPolicy {
    trusted_issuers: Vec<String>,
    blocked_issuers: Vec<String>,
    require_attestation: bool,
    require_witness_proofs: bool,
    allowed_schemas: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HubConfig {
    schema: &'static str,
    hub_id: String,
    display_name: String,
    updated_at: u64,
    bootstrap_peers: Vec<HubEndpoint>,
    relay_peers: Vec<HubEndpoint>,
    replay: HubReplayConfig,
    blobs: HubBlobConfig,
    trust_policy: HubTrustPolicy,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishFindingResponse {
    accepted: bool,
    idempotent: bool,
    feed_id: String,
    issuer_id: String,
    feed_seq: u64,
    finding_id: String,
    head_announcement: HeadAnnouncement,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishRevocationResponse {
    accepted: bool,
    idempotent: bool,
    feed_id: String,
    issuer_id: String,
    feed_seq: u64,
    revocation_id: String,
    head_announcement: HeadAnnouncement,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayResponse {
    schema: &'static str,
    feed_id: String,
    issuer_id: String,
    from_seq: u64,
    to_seq: u64,
    envelopes: Vec<FindingEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    head_announcement: Option<HeadAnnouncement>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationReplayResponse {
    schema: &'static str,
    feed_id: String,
    issuer_id: String,
    from_seq: u64,
    to_seq: u64,
    envelopes: Vec<RevocationEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    head_announcement: Option<HeadAnnouncement>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobLookupRef {
    blob_id: String,
    feed_id: String,
    issuer_id: String,
    feed_seq: u64,
    finding_id: String,
    media_type: String,
    byte_length: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    publish: Option<DurablePublishMetadata>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobLookupResponse {
    schema: &'static str,
    digest: String,
    bytes_available: bool,
    refs: Vec<BlobLookupRef>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlobPinRequest {
    digest: String,
    #[serde(default)]
    requested_by: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobPinResponse {
    accepted: bool,
    recorded: bool,
    request_id: String,
    digest: String,
    status: String,
    recorded_at: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeadQueryRaw {
    issuer_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayQueryRaw {
    issuer_id: Option<String>,
    from_seq: Option<String>,
    to_seq: Option<String>,
}

pub async fn get_swarm_hub_config(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<HubConfig>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    Ok(Json(build_hub_config(&state).await?))
}

pub async fn put_swarm_hub_trust_policy(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(trust_policy): Json<HubTrustPolicy>,
) -> Result<Json<HubConfig>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::AuditLog,
        Action::Update,
    )?;

    validate_hub_trust_policy(&trust_policy)
        .map_err(invalid_trust_policy)?;
    let serialized = serde_json::to_string(&trust_policy)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to serialize trust policy");
            V1Error::internal("SWARM_SERIALIZATION_ERROR", "internal serialization error")
        })?;
    state
        .control_db
        .set_control_metadata(SWARM_HUB_TRUST_POLICY_KEY.to_string(), serialized)
        .await
        .map_err(map_swarm_store_error)?;

    Ok(Json(build_hub_config_with_trust_policy(
        &state,
        trust_policy,
    )))
}

pub async fn publish_finding(
    State(state): State<AppState>,
    Path(feed_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(payload): Json<Value>,
) -> Result<Json<PublishFindingResponse>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::AuditLog,
        Action::Create,
    )?;

    let feed_id = require_non_empty_string(feed_id.trim(), "feedId")?;
    validate_finding_envelope(&payload)?;
    let finding = serde_json::from_value::<FindingEnvelope>(payload)
        .map_err(|err| invalid_finding(format!("schema-mismatched finding envelope: {err}")))?;

    if finding.feed_id != feed_id {
        return Err(invalid_finding(
            "path feedId must match finding envelope feedId",
        ));
    }
    let trust_policy = load_hub_trust_policy(&state).await?;
    enforce_finding_trust_policy(&trust_policy, &finding)?;

    let envelope_hash = hash_finding_envelope_for_head(&finding)?;
    let envelope_json = serde_json::to_string(&finding)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to serialize finding envelope");
            V1Error::internal("SWARM_SERIALIZATION_ERROR", "internal serialization error")
        })?;
    let blob_refs = finding
        .blob_refs
        .iter()
        .map(|blob_ref| -> Result<SwarmBlobRefInput, V1Error> {
            let publish_json = blob_ref
                .publish
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|err| {
                    tracing::error!(error = %err, "failed to serialize blob ref publish metadata");
                    V1Error::internal("SWARM_SERIALIZATION_ERROR", "internal serialization error")
                })?;
            Ok(SwarmBlobRefInput {
                blob_id: blob_ref.blob_id.clone(),
                digest: blob_ref.digest.clone(),
                media_type: blob_ref.media_type.clone(),
                byte_length: blob_ref.byte_length,
                publish_json,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let outcome = state
        .control_db
        .append_swarm_finding(SwarmFindingInput {
            feed_id: finding.feed_id.clone(),
            issuer_id: finding.issuer_id.clone(),
            finding_id: finding.finding_id.clone(),
            feed_seq: finding.feed_seq,
            published_at: finding.published_at,
            envelope_hash,
            envelope_json,
            announced_at: finding.published_at,
            blob_refs,
        })
        .await
        .map_err(map_swarm_store_error)?;

    tracing::info!(
        operation = "publish_finding",
        feed_id = %finding.feed_id,
        issuer_id = %finding.issuer_id,
        finding_id = %finding.finding_id,
        feed_seq = finding.feed_seq,
        idempotent = outcome.idempotent,
        severity = %serde_json::to_value(&finding.severity).unwrap_or_default(),
        "swarm finding published"
    );

    Ok(Json(PublishFindingResponse {
        accepted: true,
        idempotent: outcome.idempotent,
        feed_id: finding.feed_id.clone(),
        issuer_id: finding.issuer_id.clone(),
        feed_seq: finding.feed_seq,
        finding_id: finding.finding_id.clone(),
        head_announcement: synthesize_head_announcement(&outcome.head),
    }))
}

pub async fn publish_revocation(
    State(state): State<AppState>,
    Path(feed_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(payload): Json<Value>,
) -> Result<Json<PublishRevocationResponse>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::AuditLog,
        Action::Create,
    )?;

    let feed_id = require_non_empty_string(feed_id.trim(), "feedId")?;
    let revocation = parse_revocation_envelope(payload)?;

    if revocation.feed_id != feed_id {
        return Err(invalid_revocation(
            "path feedId must match revocation envelope feedId",
        ));
    }
    let trust_policy = load_hub_trust_policy(&state).await?;
    enforce_revocation_trust_policy(&trust_policy, &revocation)?;

    let envelope_hash = hash_revocation_envelope_for_head(&revocation)?;
    let envelope_json = serde_json::to_string(&revocation)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to serialize revocation envelope");
            V1Error::internal("SWARM_SERIALIZATION_ERROR", "internal serialization error")
        })?;

    let outcome = state
        .control_db
        .append_swarm_revocation(SwarmRevocationInput {
            feed_id: revocation.feed_id.clone(),
            issuer_id: revocation.issuer_id.clone(),
            revocation_id: revocation.revocation_id.clone(),
            feed_seq: revocation.feed_seq,
            issued_at: revocation.issued_at,
            action: revocation.action.as_str().to_string(),
            target: to_swarm_target_reference_input(&revocation.target),
            replacement: revocation
                .replacement
                .as_ref()
                .map(to_swarm_target_reference_input),
            envelope_hash,
            envelope_json,
            announced_at: revocation.issued_at,
        })
        .await
        .map_err(map_swarm_store_error)?;

    tracing::info!(
        operation = "publish_revocation",
        feed_id = %revocation.feed_id,
        issuer_id = %revocation.issuer_id,
        revocation_id = %revocation.revocation_id,
        feed_seq = revocation.feed_seq,
        action = %revocation.action.as_str(),
        target_id = %revocation.target.id,
        idempotent = outcome.idempotent,
        "swarm revocation published"
    );

    Ok(Json(PublishRevocationResponse {
        accepted: true,
        idempotent: outcome.idempotent,
        feed_id: revocation.feed_id.clone(),
        issuer_id: revocation.issuer_id.clone(),
        feed_seq: revocation.feed_seq,
        revocation_id: revocation.revocation_id.clone(),
        head_announcement: synthesize_head_announcement(&outcome.head),
    }))
}

pub async fn get_swarm_feed_head(
    State(state): State<AppState>,
    Path(feed_id): Path<String>,
    Query(query): Query<HeadQueryRaw>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<HeadAnnouncement>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let feed_id = require_non_empty_string(feed_id.trim(), "feedId")?;
    let issuer_id = parse_issuer_query(query.issuer_id)?;
    let head = state
        .control_db
        .get_swarm_head(feed_id, issuer_id)
        .await
        .map_err(map_swarm_store_error)?
        .ok_or_else(|| V1Error::not_found("SWARM_HEAD_NOT_FOUND", "swarm_head_not_found"))?;

    Ok(Json(synthesize_head_announcement(&head)))
}

pub async fn get_swarm_revocation_head(
    State(state): State<AppState>,
    Path(feed_id): Path<String>,
    Query(query): Query<HeadQueryRaw>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<HeadAnnouncement>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let feed_id = require_non_empty_string(feed_id.trim(), "feedId")?;
    let issuer_id = parse_issuer_query(query.issuer_id)?;
    let head = state
        .control_db
        .get_swarm_revocation_head(feed_id, issuer_id)
        .await
        .map_err(map_swarm_store_error)?
        .ok_or_else(|| {
            V1Error::not_found("SWARM_HEAD_NOT_FOUND", "swarm_revocation_head_not_found")
        })?;

    Ok(Json(synthesize_head_announcement(&head)))
}

pub async fn replay_swarm_feed(
    State(state): State<AppState>,
    Path(feed_id): Path<String>,
    Query(query): Query<ReplayQueryRaw>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<ReplayResponse>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let feed_id = require_non_empty_string(feed_id.trim(), "feedId")?;
    let issuer_id = parse_issuer_query(query.issuer_id)?;
    let from_seq = parse_required_query_u64(query.from_seq, "fromSeq")?;
    let to_seq = parse_required_query_u64(query.to_seq, "toSeq")?;
    if from_seq < 1 {
        return Err(V1Error::bad_request(
            "INVALID_REPLAY_QUERY",
            "fromSeq must be >= 1",
        ));
    }
    if to_seq < from_seq {
        return Err(V1Error::bad_request(
            "INVALID_REPLAY_QUERY",
            "toSeq must be >= fromSeq",
        ));
    }
    let range = to_seq - from_seq + 1;
    if range > MAX_REPLAY_ENTRIES_PER_SYNC {
        return Err(V1Error::bad_request(
            "INVALID_REPLAY_QUERY",
            format!(
                "requested replay range exceeds maxEntriesPerSync ({MAX_REPLAY_ENTRIES_PER_SYNC})"
            ),
        ));
    }

    let head = state
        .control_db
        .get_swarm_head(feed_id.clone(), issuer_id.clone())
        .await
        .map_err(map_swarm_store_error)?
        .ok_or_else(|| V1Error::not_found("SWARM_HEAD_NOT_FOUND", "swarm_head_not_found"))?;
    if to_seq > head.head_seq {
        return Err(V1Error::bad_request(
            "INVALID_REPLAY_QUERY",
            format!("toSeq must be <= current head ({})", head.head_seq),
        ));
    }

    let stored = state
        .control_db
        .replay_swarm_findings(feed_id.clone(), issuer_id.clone(), from_seq, to_seq)
        .await
        .map_err(map_swarm_store_error)?;
    let envelopes = stored
        .into_iter()
        .map(|record| {
            serde_json::from_str::<FindingEnvelope>(&record.envelope_json).map_err(|err| {
                tracing::error!(error = %err, "failed to deserialize stored finding envelope");
                V1Error::internal("SWARM_REPLAY_DESERIALIZATION_ERROR", "internal deserialization error")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if envelopes.len() as u64 != range {
        return Err(V1Error::internal(
            "SWARM_REPLAY_INCONSISTENT",
            "requested replay range is not fully stored",
        ));
    }

    // Verify that the computed head hash of the last envelope in the
    // replay matches the stored head hash when the replay reaches the
    // current head.  This guards against silent data corruption.
    if to_seq == head.head_seq {
        if let Some(last_envelope) = envelopes.last() {
            let computed_hash = hash_finding_envelope_for_head(last_envelope)?;
            if computed_hash != head.head_envelope_hash {
                tracing::error!(
                    feed_id = %feed_id,
                    issuer_id = %issuer_id,
                    head_seq = head.head_seq,
                    stored_hash = %head.head_envelope_hash,
                    computed_hash = %computed_hash,
                    "replay head hash verification failed"
                );
                return Err(V1Error::internal(
                    "SWARM_REPLAY_INTEGRITY_ERROR",
                    "computed head hash does not match stored head hash — data integrity issue",
                ));
            }
        }
    }

    Ok(Json(ReplayResponse {
        schema: REPLAY_SCHEMA,
        feed_id,
        issuer_id,
        from_seq,
        to_seq,
        envelopes,
        head_announcement: (head.head_seq == to_seq).then(|| synthesize_head_announcement(&head)),
    }))
}

pub async fn replay_swarm_revocations(
    State(state): State<AppState>,
    Path(feed_id): Path<String>,
    Query(query): Query<ReplayQueryRaw>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<RevocationReplayResponse>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let feed_id = require_non_empty_string(feed_id.trim(), "feedId")?;
    let issuer_id = parse_issuer_query(query.issuer_id)?;
    let from_seq = parse_required_query_u64(query.from_seq, "fromSeq")?;
    let to_seq = parse_required_query_u64(query.to_seq, "toSeq")?;
    if from_seq < 1 {
        return Err(V1Error::bad_request(
            "INVALID_REPLAY_QUERY",
            "fromSeq must be >= 1",
        ));
    }
    if to_seq < from_seq {
        return Err(V1Error::bad_request(
            "INVALID_REPLAY_QUERY",
            "toSeq must be >= fromSeq",
        ));
    }
    let range = to_seq - from_seq + 1;
    if range > MAX_REPLAY_ENTRIES_PER_SYNC {
        return Err(V1Error::bad_request(
            "INVALID_REPLAY_QUERY",
            format!(
                "requested replay range exceeds maxEntriesPerSync ({MAX_REPLAY_ENTRIES_PER_SYNC})"
            ),
        ));
    }

    let head = state
        .control_db
        .get_swarm_revocation_head(feed_id.clone(), issuer_id.clone())
        .await
        .map_err(map_swarm_store_error)?
        .ok_or_else(|| {
            V1Error::not_found("SWARM_HEAD_NOT_FOUND", "swarm_revocation_head_not_found")
        })?;
    if to_seq > head.head_seq {
        return Err(V1Error::bad_request(
            "INVALID_REPLAY_QUERY",
            format!("toSeq must be <= current head ({})", head.head_seq),
        ));
    }

    let stored = state
        .control_db
        .replay_swarm_revocations(feed_id.clone(), issuer_id.clone(), from_seq, to_seq)
        .await
        .map_err(map_swarm_store_error)?;
    let envelopes = stored
        .into_iter()
        .map(|record| {
            serde_json::from_str::<RevocationEnvelope>(&record.envelope_json).map_err(|err| {
                tracing::error!(error = %err, "failed to deserialize stored revocation envelope");
                V1Error::internal("SWARM_REPLAY_DESERIALIZATION_ERROR", "internal deserialization error")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if envelopes.len() as u64 != range {
        return Err(V1Error::internal(
            "SWARM_REPLAY_INCONSISTENT",
            "requested replay range is not fully stored",
        ));
    }

    // Verify that the computed head hash of the last revocation envelope
    // matches the stored head hash when the replay reaches the current head.
    if to_seq == head.head_seq {
        if let Some(last_envelope) = envelopes.last() {
            let computed_hash = hash_revocation_envelope_for_head(last_envelope)?;
            if computed_hash != head.head_envelope_hash {
                tracing::error!(
                    feed_id = %feed_id,
                    issuer_id = %issuer_id,
                    head_seq = head.head_seq,
                    stored_hash = %head.head_envelope_hash,
                    computed_hash = %computed_hash,
                    "revocation replay head hash verification failed"
                );
                return Err(V1Error::internal(
                    "SWARM_REPLAY_INTEGRITY_ERROR",
                    "computed head hash does not match stored head hash — data integrity issue",
                ));
            }
        }
    }

    Ok(Json(RevocationReplayResponse {
        schema: REPLAY_SCHEMA,
        feed_id,
        issuer_id,
        from_seq,
        to_seq,
        envelopes,
        head_announcement: (head.head_seq == to_seq).then(|| synthesize_head_announcement(&head)),
    }))
}

pub async fn get_swarm_blob_refs(
    State(state): State<AppState>,
    Path(digest): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<BlobLookupResponse>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let digest = normalize_digest(digest.trim())?;
    let refs = state
        .control_db
        .lookup_swarm_blob_refs(digest.clone())
        .await
        .map_err(map_swarm_store_error)?;
    if refs.is_empty() {
        return Err(V1Error::not_found("SWARM_BLOB_NOT_FOUND", "swarm_blob_not_found"));
    }

    let refs = refs
        .into_iter()
        .map(|record| {
            let publish = record
                .publish_json
                .as_deref()
                .map(serde_json::from_str::<DurablePublishMetadata>)
                .transpose()
                .map_err(|err| {
                    tracing::error!(error = %err, "failed to deserialize blob publish metadata");
                    V1Error::internal("SWARM_BLOB_DESERIALIZATION_ERROR", "internal deserialization error")
                })?;
            Ok(BlobLookupRef {
                blob_id: record.blob_id,
                feed_id: record.feed_id,
                issuer_id: record.issuer_id,
                feed_seq: record.feed_seq,
                finding_id: record.finding_id,
                media_type: record.media_type,
                byte_length: record.byte_length,
                publish,
            })
        })
        .collect::<Result<Vec<_>, V1Error>>()?;

    Ok(Json(BlobLookupResponse {
        schema: BLOB_LOOKUP_SCHEMA,
        digest,
        bytes_available: false,
        refs,
    }))
}

pub async fn pin_swarm_blob(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(request): Json<BlobPinRequest>,
) -> Result<(StatusCode, Json<BlobPinResponse>), V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|value| &value.0),
        &state.rbac,
        Scope::Admin,
        ResourceType::AuditLog,
        Action::Create,
    )?;

    let digest = normalize_digest(request.digest.trim())?;
    let actor_label = actor.as_ref().map(|value| format!("{:?}", value.0));
    let requested_by = request.requested_by.and_then(|value| {
        let trimmed = value.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let note = request.note.and_then(|value| {
        let trimmed = value.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    let request_json = serde_json::to_string(&serde_json::json!({
        "digest": digest.clone(),
        "requestedBy": requested_by,
        "note": note.clone(),
        "actor": actor_label.clone(),
    }))
    .map_err(|err| {
        tracing::error!(error = %err, "failed to serialize blob pin request");
        V1Error::internal("SWARM_SERIALIZATION_ERROR", "internal serialization error")
    })?;
    let record = state
        .control_db
        .record_swarm_blob_pin_request(
            digest.clone(),
            actor_label.clone(),
            note,
            request_json,
        )
        .await
        .map_err(map_swarm_store_error)?;

    tracing::info!(
        operation = "pin_blob",
        digest = %record.digest,
        request_id = %record.request_id,
        status = %record.status,
        actor = ?actor_label,
        deduplicated = %record.status == "deduplicated",
        "swarm blob pin request recorded"
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(BlobPinResponse {
            accepted: true,
            recorded: true,
            request_id: record.request_id,
            digest: record.digest,
            status: record.status,
            recorded_at: record.requested_at,
        }),
    ))
}

fn default_hub_trust_policy() -> HubTrustPolicy {
    HubTrustPolicy {
        trusted_issuers: Vec::new(),
        blocked_issuers: Vec::new(),
        require_attestation: false,
        require_witness_proofs: false,
        allowed_schemas: vec![
            FINDING_ENVELOPE_SCHEMA.to_string(),
            REVOCATION_ENVELOPE_SCHEMA.to_string(),
        ],
    }
}

async fn load_hub_trust_policy(state: &AppState) -> Result<HubTrustPolicy, V1Error> {
    let stored = state
        .control_db
        .get_control_metadata(SWARM_HUB_TRUST_POLICY_KEY.to_string())
        .await
        .map_err(map_swarm_store_error)?;
    let trust_policy = match stored {
        Some(raw) => serde_json::from_str::<HubTrustPolicy>(&raw)
            .map_err(|err| {
                tracing::error!(error = %err, "failed to deserialize stored hub trust policy");
                V1Error::internal("SWARM_STATE_INCONSISTENT", "internal state error")
            })?,
        None => default_hub_trust_policy(),
    };
    validate_hub_trust_policy(&trust_policy)
        .map_err(|message| V1Error::internal("SWARM_STATE_INCONSISTENT", message))?;
    Ok(trust_policy)
}

async fn build_hub_config(state: &AppState) -> Result<HubConfig, V1Error> {
    Ok(build_hub_config_with_trust_policy(
        state,
        load_hub_trust_policy(state).await?,
    ))
}

fn build_hub_config_with_trust_policy(state: &AppState, trust_policy: HubTrustPolicy) -> HubConfig {
    let protocol = if state.config.tls.is_some() {
        "https"
    } else {
        "http"
    };
    let blob_url = format!("{protocol}://{}/api/v1/swarm/blobs", state.config.listen);
    HubConfig {
        schema: HUB_CONFIG_SCHEMA,
        hub_id: format!("hushd:{}", state.config.listen),
        display_name: "hushd Swarm Hub".to_string(),
        updated_at: state.started_at.timestamp_millis().max(0) as u64,
        bootstrap_peers: Vec::new(),
        relay_peers: Vec::new(),
        replay: HubReplayConfig {
            max_entries_per_sync: MAX_REPLAY_ENTRIES_PER_SYNC,
            checkpoint_interval: CHECKPOINT_INTERVAL,
            retention_ms: RETENTION_MS,
        },
        blobs: HubBlobConfig {
            max_inline_bytes: MAX_INLINE_BLOB_BYTES,
            require_digest: true,
            providers: vec![HubEndpoint {
                id: "self".to_string(),
                url: blob_url,
                protocols: vec![protocol.to_string()],
            }],
        },
        trust_policy,
    }
}

fn validate_hub_trust_policy(trust_policy: &HubTrustPolicy) -> std::result::Result<(), String> {
    for issuer in &trust_policy.trusted_issuers {
        validate_issuer_id_message(issuer)
            .map_err(|msg| format!("invalid trusted issuer: {msg}"))?;
    }
    for issuer in &trust_policy.blocked_issuers {
        validate_issuer_id_message(issuer)
            .map_err(|msg| format!("invalid blocked issuer: {msg}"))?;
    }
    for schema in &trust_policy.allowed_schemas {
        if !ALLOWED_TRUST_POLICY_SCHEMAS.contains(&schema.as_str()) {
            return Err(format!("allowedSchemas contains unsupported schema `{schema}`"));
        }
    }
    Ok(())
}

fn has_witness_proofs(publish: Option<&DurablePublishMetadata>) -> bool {
    publish
        .and_then(|p| p.witness_proofs.as_deref())
        .is_some_and(|entries| !entries.is_empty())
}

fn finding_has_witness_proofs(finding: &FindingEnvelope) -> bool {
    has_witness_proofs(finding.publish.as_ref())
        || finding
            .blob_refs
            .iter()
            .any(|blob_ref| has_witness_proofs(blob_ref.publish.as_ref()))
}

fn revocation_has_witness_proofs(revocation: &RevocationEnvelope) -> bool {
    has_witness_proofs(revocation.publish.as_ref())
}

fn requires_verified_attestation(trust_policy: &HubTrustPolicy) -> bool {
    trust_policy.require_attestation
        || !trust_policy.trusted_issuers.is_empty()
        || !trust_policy.blocked_issuers.is_empty()
}

fn hash_finding_attestation_payload(finding: &FindingEnvelope) -> Result<String, V1Error> {
    let mut value = serde_json::to_value(finding)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to serialize finding for attestation hash");
            V1Error::internal("SWARM_SERIALIZATION_ERROR", "internal serialization error")
        })?;
    let value_map = value.as_object_mut().ok_or_else(|| {
        V1Error::internal(
            "SWARM_SERIALIZATION_ERROR",
            "serialized finding envelope was not an object",
        )
    })?;
    value_map.remove("attestation");
    value_map.remove("publish");
    if let Some(blob_refs) = value_map.get_mut("blobRefs").and_then(Value::as_array_mut) {
        for blob_ref in blob_refs {
            if let Some(blob_ref_map) = blob_ref.as_object_mut() {
                blob_ref_map.remove("publish");
            }
        }
    }
    let canonical = canonicalize(&value)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to canonicalize finding for attestation hash");
            V1Error::internal("SWARM_HASH_ERROR", "internal hash error")
        })?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn verify_finding_attestation(finding: &FindingEnvelope) -> Result<bool, V1Error> {
    let Some(attestation) = finding.attestation.as_ref() else {
        return Ok(false);
    };
    let Ok(public_key) = PublicKey::from_hex(&attestation.public_key) else {
        return Ok(false);
    };
    let Ok(signature) = Signature::from_hex(&attestation.signature) else {
        return Ok(false);
    };
    let digest = hash_finding_attestation_payload(finding)?;
    Ok(public_key.verify(digest.as_bytes(), &signature))
}

fn hash_revocation_attestation_payload(revocation: &RevocationEnvelope) -> Result<String, V1Error> {
    let mut value = serde_json::to_value(revocation)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to serialize revocation for attestation hash");
            V1Error::internal("SWARM_SERIALIZATION_ERROR", "internal serialization error")
        })?;
    let value_map = value.as_object_mut().ok_or_else(|| {
        V1Error::internal(
            "SWARM_SERIALIZATION_ERROR",
            "serialized revocation envelope was not an object",
        )
    })?;
    value_map.remove("attestation");
    value_map.remove("publish");
    let canonical = canonicalize(&value)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to canonicalize revocation for attestation hash");
            V1Error::internal("SWARM_HASH_ERROR", "internal hash error")
        })?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn verify_revocation_attestation(revocation: &RevocationEnvelope) -> Result<bool, V1Error> {
    let Some(attestation) = revocation.attestation.as_ref() else {
        return Ok(false);
    };
    let Ok(public_key) = PublicKey::from_hex(&attestation.public_key) else {
        return Ok(false);
    };
    let Ok(signature) = Signature::from_hex(&attestation.signature) else {
        return Ok(false);
    };
    let digest = hash_revocation_attestation_payload(revocation)?;
    Ok(public_key.verify(digest.as_bytes(), &signature))
}

/// Shared issuer/schema checks used by both finding and revocation trust enforcement.
fn enforce_common_trust_policy(
    trust_policy: &HubTrustPolicy,
    issuer_id: &str,
    schema: &str,
) -> Result<(), V1Error> {
    if trust_policy
        .blocked_issuers
        .iter()
        .any(|issuer| issuer == issuer_id)
    {
        return Err(trust_policy_rejection(format!(
            "issuer `{issuer_id}` is blocked by hub trust policy",
        )));
    }
    if !trust_policy.trusted_issuers.is_empty()
        && !trust_policy
            .trusted_issuers
            .iter()
            .any(|issuer| issuer == issuer_id)
    {
        return Err(trust_policy_rejection(format!(
            "issuer `{issuer_id}` is not in the trusted issuer allowlist",
        )));
    }
    if !trust_policy
        .allowed_schemas
        .iter()
        .any(|s| s == schema)
    {
        return Err(trust_policy_rejection(format!(
            "schema `{schema}` is not allowed by hub trust policy",
        )));
    }
    Ok(())
}

fn enforce_finding_trust_policy(
    trust_policy: &HubTrustPolicy,
    finding: &FindingEnvelope,
) -> Result<(), V1Error> {
    enforce_common_trust_policy(trust_policy, &finding.issuer_id, &finding.schema)?;
    if requires_verified_attestation(trust_policy) && finding.attestation.is_none() {
        return Err(trust_policy_rejection(
            "finding attestation is required by hub trust policy",
        ));
    }
    if trust_policy.require_witness_proofs && !finding_has_witness_proofs(finding) {
        return Err(trust_policy_rejection(
            "witness proofs are required by hub trust policy",
        ));
    }
    if requires_verified_attestation(trust_policy) && !verify_finding_attestation(finding)? {
        return Err(trust_policy_rejection(
            "finding attestation must verify against the canonical signable finding payload",
        ));
    }
    Ok(())
}

fn enforce_revocation_trust_policy(
    trust_policy: &HubTrustPolicy,
    revocation: &RevocationEnvelope,
) -> Result<(), V1Error> {
    enforce_common_trust_policy(trust_policy, &revocation.issuer_id, &revocation.schema)?;
    if requires_verified_attestation(trust_policy) && revocation.attestation.is_none() {
        return Err(trust_policy_rejection(
            "revocation attestation is required by hub trust policy",
        ));
    }
    if trust_policy.require_witness_proofs && !revocation_has_witness_proofs(revocation) {
        return Err(trust_policy_rejection(
            "witness proofs are required by hub trust policy",
        ));
    }
    if requires_verified_attestation(trust_policy) && !verify_revocation_attestation(revocation)? {
        return Err(trust_policy_rejection(
            "revocation attestation must verify against the canonical signable revocation payload",
        ));
    }
    Ok(())
}

fn synthesize_head_announcement(head: &SwarmHeadRecord) -> HeadAnnouncement {
    HeadAnnouncement {
        schema: HEAD_ANNOUNCEMENT_SCHEMA,
        fact_id: format!("head:{}:{}:{}", head.feed_id, head.issuer_id, head.head_seq),
        feed_id: head.feed_id.clone(),
        issuer_id: head.issuer_id.clone(),
        head_seq: head.head_seq,
        head_envelope_hash: head.head_envelope_hash.clone(),
        entry_count: head.entry_count,
        checkpoint_ref: None,
        announced_at: head.announced_at,
    }
}

fn map_swarm_store_error(err: ControlDbError) -> V1Error {
    match err {
        ControlDbError::Gap(message) => V1Error::conflict("SWARM_SEQ_GAP", message),
        ControlDbError::Conflict(message) => V1Error::conflict("SWARM_SEQ_CONFLICT", message),
        ControlDbError::Invariant(_) => {
            tracing::error!(error = %err, "swarm state inconsistency");
            V1Error::internal("SWARM_STATE_INCONSISTENT", "internal state error")
        }
        ControlDbError::Database(ref db_err) => {
            tracing::error!(error = %db_err, "swarm store database error");
            V1Error::internal("SWARM_STORE_ERROR", "internal store error")
        }
        ControlDbError::Io(ref io_err) => {
            tracing::error!(error = %io_err, "swarm store I/O error");
            V1Error::internal("SWARM_STORE_ERROR", "internal store error")
        }
    }
}

fn invalid_finding(message: impl Into<String>) -> V1Error {
    V1Error::bad_request("INVALID_FINDING_ENVELOPE", message.into())
}

fn invalid_revocation(message: impl Into<String>) -> V1Error {
    V1Error::bad_request("INVALID_REVOCATION_ENVELOPE", message.into())
}

fn invalid_trust_policy(message: impl Into<String>) -> V1Error {
    V1Error::bad_request("INVALID_SWARM_TRUST_POLICY", message.into())
}

fn trust_policy_rejection(message: impl Into<String>) -> V1Error {
    V1Error::bad_request("SWARM_TRUST_POLICY_REJECTED", message.into())
}

fn parse_issuer_query(raw: Option<String>) -> Result<String, V1Error> {
    let issuer = require_non_empty_string(
        raw.as_deref().unwrap_or_default().trim(),
        "issuerId",
    )?;
    validate_issuer_id(&issuer)?;
    Ok(issuer)
}

fn parse_required_query_u64(raw: Option<String>, field: &str) -> Result<u64, V1Error> {
    let raw = require_non_empty_string(raw.as_deref().unwrap_or_default().trim(), field)?;
    raw.parse::<u64>().map_err(|_| {
        V1Error::bad_request(
            "INVALID_REPLAY_QUERY",
            format!("{field} must be an unsigned integer"),
        )
    })
}

fn require_non_empty_string(value: &str, field: &str) -> Result<String, V1Error> {
    if value.is_empty() {
        return Err(V1Error::bad_request(
            "INVALID_SWARM_REQUEST",
            format!("{field} must be a non-empty string"),
        ));
    }
    Ok(value.to_string())
}

fn parse_revocation_envelope(value: Value) -> Result<RevocationEnvelope, V1Error> {
    if !value.is_object() {
        return Err(invalid_revocation("revocation envelope must be a JSON object"));
    }
    let revocation = serde_json::from_value::<RevocationEnvelope>(value)
        .map_err(|err| invalid_revocation(format!("schema-mismatched revocation envelope: {err}")))?;
    validate_revocation_envelope_fields(&revocation)?;
    Ok(revocation)
}

fn validate_revocation_envelope_fields(revocation: &RevocationEnvelope) -> Result<(), V1Error> {
    if revocation.schema != REVOCATION_ENVELOPE_SCHEMA {
        return Err(invalid_revocation(format!(
            "schema must equal `{REVOCATION_ENVELOPE_SCHEMA}`"
        )));
    }
    validate_non_empty_protocol_string(&revocation.revocation_id, "revocationId")
        .map_err(invalid_revocation)?;
    validate_non_empty_protocol_string(&revocation.feed_id, "feedId").map_err(invalid_revocation)?;
    validate_non_empty_protocol_string(&revocation.reason, "reason").map_err(invalid_revocation)?;
    validate_issuer_id_message(&revocation.issuer_id).map_err(invalid_revocation)?;
    validate_safe_integer_bound(revocation.feed_seq, "feedSeq").map_err(invalid_revocation)?;
    validate_safe_integer_bound(revocation.issued_at, "issuedAt").map_err(invalid_revocation)?;
    if revocation.feed_seq < 1 {
        return Err(invalid_revocation("feedSeq must be >= 1"));
    }
    let action = revocation.action.as_str();
    if !ALLOWED_REVOCATION_ACTIONS.contains(&action) {
        return Err(invalid_revocation(format!(
            "action must be one of {}",
            ALLOWED_REVOCATION_ACTIONS.join(", ")
        )));
    }
    validate_protocol_target_reference(&revocation.target, "target").map_err(invalid_revocation)?;
    if let Some(replacement) = revocation.replacement.as_ref() {
        validate_protocol_target_reference(replacement, "replacement").map_err(invalid_revocation)?;
    }
    match revocation.action {
        RevocationAction::Revoke if revocation.replacement.is_some() => {
            return Err(invalid_revocation(
                "replacement must be omitted when action is `revoke`",
            ));
        }
        RevocationAction::Supersede if revocation.replacement.is_none() => {
            return Err(invalid_revocation(
                "replacement is required when action is `supersede`",
            ));
        }
        _ => {}
    }
    if let Some(attestation) = revocation.attestation.as_ref() {
        validate_protocol_attestation_value(attestation).map_err(invalid_revocation)?;
        let expected_issuer = format!("{ISSUER_ID_PREFIX}{}", attestation.public_key);
        if revocation.issuer_id != expected_issuer {
            return Err(invalid_revocation(
                "attestation.publicKey must match issuerId suffix",
            ));
        }
    }
    if let Some(publish) = revocation.publish.as_ref() {
        validate_durable_publish_metadata_value(publish, "publish").map_err(invalid_revocation)?;
    }
    Ok(())
}

fn validate_non_empty_protocol_string(value: &str, field: &str) -> std::result::Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must be a non-empty string"));
    }
    Ok(())
}

fn validate_safe_integer_bound(value: u64, field: &str) -> std::result::Result<(), String> {
    if value > MAX_SAFE_INTEGER {
        return Err(format!(
            "{field} exceeds JavaScript safe integer range"
        ));
    }
    Ok(())
}

fn validate_protocol_target_reference(
    target: &ProtocolTargetReference,
    field: &str,
) -> std::result::Result<(), String> {
    if !TARGET_REFERENCE_SCHEMAS.contains(&target.schema.as_str()) {
        return Err(format!(
            "{field}.schema must be one of {}",
            TARGET_REFERENCE_SCHEMAS.join(", ")
        ));
    }
    validate_non_empty_protocol_string(&target.id, &format!("{field}.id"))?;
    if let Some(digest) = target.digest.as_deref() {
        normalize_digest_message(digest).map_err(|message| format!("{field}.digest {message}"))?;
    }
    Ok(())
}

fn validate_protocol_attestation_value(
    attestation: &ProtocolAttestation,
) -> std::result::Result<(), String> {
    if !is_lower_hex(&attestation.public_key, 64) {
        return Err("attestation.publicKey must be 64 lowercase hex characters".to_string());
    }
    if !is_lower_hex(&attestation.signature, 128) {
        return Err("attestation.signature must be 128 lowercase hex characters".to_string());
    }
    Ok(())
}

fn validate_durable_publish_metadata_value(
    publish: &DurablePublishMetadata,
    context: &str,
) -> std::result::Result<(), String> {
    if let Some(published_at) = publish.published_at {
        validate_safe_integer_bound(published_at, &format!("{context}.publishedAt"))?;
    }
    if let Some(envelope_hash) = publish.notary_envelope_hash.as_deref() {
        normalize_digest_message(envelope_hash)
            .map_err(|message| format!("{context}.notaryEnvelopeHash {message}"))?;
    }
    if let Some(witness_proofs) = publish.witness_proofs.as_ref() {
        for proof in witness_proofs {
            normalize_digest_message(&proof.digest)
                .map_err(|message| format!("{context}.witnessProofs.digest {message}"))?;
        }
    }
    Ok(())
}

fn to_swarm_target_reference_input(target: &ProtocolTargetReference) -> SwarmTargetReferenceInput {
    SwarmTargetReferenceInput {
        schema: target.schema.clone(),
        id: target.id.clone(),
        digest: target.digest.clone(),
    }
}

fn validate_finding_envelope(value: &Value) -> Result<(), V1Error> {
    let Some(map) = value.as_object() else {
        return Err(invalid_finding("finding envelope must be a JSON object"));
    };
    ensure_only_keys(map, FINDING_ENVELOPE_KEYS, "finding envelope")?;

    expect_exact_string(map, "schema", FINDING_ENVELOPE_SCHEMA)?;
    require_non_empty_json_string(map, "findingId")?;
    let issuer_id = require_non_empty_json_string(map, "issuerId")?;
    validate_issuer_id(issuer_id)?;
    require_non_empty_json_string(map, "feedId")?;
    let feed_seq = require_safe_u64(map, "feedSeq")?;
    if feed_seq < 1 {
        return Err(invalid_finding("feedSeq must be >= 1"));
    }
    require_safe_u64(map, "publishedAt")?;
    let title = require_non_empty_json_string(map, "title")?;
    if title.len() > MAX_TITLE_LEN {
        return Err(invalid_finding(format!(
            "title must not exceed {MAX_TITLE_LEN} characters"
        )));
    }
    let summary = require_non_empty_json_string(map, "summary")?;
    if summary.len() > MAX_SUMMARY_LEN {
        return Err(invalid_finding(format!(
            "summary must not exceed {MAX_SUMMARY_LEN} characters"
        )));
    }
    expect_one_of_string(map, "severity", ALLOWED_SEVERITIES)?;
    require_unit_interval(map, "confidence")?;
    expect_one_of_string(map, "status", ALLOWED_STATUSES)?;
    require_safe_u64(map, "signalCount")?;
    let tags_value = map.get("tags")
        .ok_or_else(|| invalid_finding("tags is required"))?;
    validate_string_array(tags_value, "tags")?;
    if let Some(tags_arr) = tags_value.as_array() {
        if tags_arr.len() > MAX_TAGS_COUNT {
            return Err(invalid_finding(format!(
                "tags must not exceed {MAX_TAGS_COUNT} entries"
            )));
        }
    }

    if let Some(value) = map.get("relatedFindingIds") {
        validate_string_array(value, "relatedFindingIds")?;
        if let Some(arr) = value.as_array() {
            if arr.len() > MAX_RELATED_FINDING_IDS_COUNT {
                return Err(invalid_finding(format!(
                    "relatedFindingIds must not exceed {MAX_RELATED_FINDING_IDS_COUNT} entries"
                )));
            }
        }
    }

    let blob_refs = map
        .get("blobRefs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_finding("blobRefs must be an array"))?;
    if blob_refs.len() > MAX_BLOB_REFS_COUNT {
        return Err(invalid_finding(format!(
            "blobRefs must not exceed {MAX_BLOB_REFS_COUNT} entries"
        )));
    }
    for blob_ref in blob_refs {
        validate_blob_ref(blob_ref)?;
    }

    let attestation = if let Some(attestation) = map.get("attestation") {
        validate_attestation(attestation)?;
        let attestation_map = attestation
            .as_object()
            .ok_or_else(|| invalid_finding("attestation must be an object"))?;
        let public_key = attestation_map
            .get("publicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_finding("attestation.publicKey must be a string"))?;
        Some(public_key)
    } else {
        None
    };

    if let Some(public_key) = attestation {
        let expected_issuer = format!("{ISSUER_ID_PREFIX}{public_key}");
        if issuer_id != expected_issuer {
            return Err(invalid_finding(
                "attestation.publicKey must match issuerId suffix",
            ));
        }
    }

    if let Some(publish) = map.get("publish") {
        validate_durable_publish(publish, "publish")?;
    }

    Ok(())
}

fn validate_blob_ref(value: &Value) -> Result<(), V1Error> {
    let Some(map) = value.as_object() else {
        return Err(invalid_finding("blobRefs entries must be objects"));
    };
    ensure_only_keys(map, FINDING_BLOB_REF_KEYS, "blobRefs entry")?;
    require_non_empty_json_string(map, "blobId")?;
    normalize_digest(require_non_empty_json_string(map, "digest")?)?;
    require_non_empty_json_string(map, "mediaType")?;
    require_safe_u64(map, "byteLength")?;
    if let Some(publish) = map.get("publish") {
        validate_durable_publish(publish, "blobRefs.publish")?;
    }
    Ok(())
}

fn validate_attestation(value: &Value) -> Result<(), V1Error> {
    let Some(map) = value.as_object() else {
        return Err(invalid_finding("attestation must be an object"));
    };
    ensure_only_keys(map, ATTESTATION_KEYS, "attestation")?;
    expect_exact_string(map, "algorithm", "ed25519")?;
    let public_key = require_non_empty_json_string(map, "publicKey")?;
    if !is_lower_hex(public_key, 64) {
        return Err(invalid_finding(
            "attestation.publicKey must be 64 lowercase hex characters",
        ));
    }
    let signature = require_non_empty_json_string(map, "signature")?;
    if !is_lower_hex(signature, 128) {
        return Err(invalid_finding(
            "attestation.signature must be 128 lowercase hex characters",
        ));
    }
    Ok(())
}

fn validate_durable_publish(value: &Value, context: &str) -> Result<(), V1Error> {
    let Some(map) = value.as_object() else {
        return Err(invalid_finding(format!("{context} must be an object")));
    };
    ensure_only_keys(map, DURABLE_PUBLISH_KEYS, context)?;
    if let Some(uri) = map.get("uri") {
        if !uri.is_string() {
            return Err(invalid_finding(format!("{context}.uri must be a string")));
        }
    }
    if let Some(published_at) = map.get("publishedAt") {
        validate_safe_integer_value(published_at, &format!("{context}.publishedAt"))?;
    }
    if let Some(notary_record_id) = map.get("notaryRecordId") {
        if !notary_record_id.is_string() {
            return Err(invalid_finding(format!(
                "{context}.notaryRecordId must be a string"
            )));
        }
    }
    if let Some(envelope_hash) = map.get("notaryEnvelopeHash") {
        let hash = envelope_hash.as_str().ok_or_else(|| {
            invalid_finding(format!("{context}.notaryEnvelopeHash must be a string"))
        })?;
        normalize_digest(hash)?;
    }
    if let Some(witness_proofs) = map.get("witnessProofs") {
        let Some(entries) = witness_proofs.as_array() else {
            return Err(invalid_finding(format!(
                "{context}.witnessProofs must be an array"
            )));
        };
        for proof in entries {
            let Some(proof_map) = proof.as_object() else {
                return Err(invalid_finding(format!(
                    "{context}.witnessProofs entries must be objects"
                )));
            };
            ensure_only_keys(proof_map, WITNESS_PROOF_KEYS, "witness proof")?;
            expect_one_of_string(proof_map, "provider", ALLOWED_WITNESS_PROVIDERS)?;
            normalize_digest(require_non_empty_json_string(proof_map, "digest")?)?;
            if let Some(uri) = proof_map.get("uri") {
                if !uri.is_string() {
                    return Err(invalid_finding("witnessProofs.uri must be a string"));
                }
            }
        }
    }
    Ok(())
}

fn ensure_only_keys(
    map: &Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), V1Error> {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid_finding(format!(
                "{context} contains unknown field `{key}`"
            )));
        }
    }
    Ok(())
}

fn expect_exact_string(
    map: &Map<String, Value>,
    field: &str,
    expected: &str,
) -> Result<(), V1Error> {
    let actual = require_non_empty_json_string(map, field)?;
    if actual != expected {
        return Err(invalid_finding(format!(
            "{field} must equal `{expected}`"
        )));
    }
    Ok(())
}

fn expect_one_of_string(
    map: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<(), V1Error> {
    let actual = require_non_empty_json_string(map, field)?;
    if !allowed.contains(&actual) {
        return Err(invalid_finding(format!(
            "{field} must be one of {}",
            allowed.join(", ")
        )));
    }
    Ok(())
}

fn require_non_empty_json_string<'a>(
    map: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, V1Error> {
    let value = map.get(field).ok_or_else(|| {
        invalid_finding(format!("{field} is required"))
    })?;
    let string = value.as_str().ok_or_else(|| {
        invalid_finding(format!("{field} must be a string"))
    })?;
    if string.trim().is_empty() {
        return Err(invalid_finding(format!(
            "{field} must be a non-empty string"
        )));
    }
    Ok(string)
}

fn require_safe_u64(map: &Map<String, Value>, field: &str) -> Result<u64, V1Error> {
    let value = map
        .get(field)
        .ok_or_else(|| invalid_finding(format!("{field} is required")))?;
    validate_safe_integer_value(value, field)
}

fn validate_safe_integer_value(value: &Value, field: &str) -> Result<u64, V1Error> {
    let number = value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
        .or_else(|| {
            value.as_f64().and_then(|number| {
                if number.is_finite()
                    && number >= 0.0
                    && number.fract() == 0.0
                    && number <= MAX_SAFE_INTEGER as f64
                {
                    Some(number as u64)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| invalid_finding(format!("{field} must be a safe non-negative integer")))?;
    if number > MAX_SAFE_INTEGER {
        return Err(invalid_finding(format!(
            "{field} exceeds JavaScript safe integer range"
        )));
    }
    Ok(number)
}

fn require_unit_interval(map: &Map<String, Value>, field: &str) -> Result<f64, V1Error> {
    let value = map
        .get(field)
        .ok_or_else(|| invalid_finding(format!("{field} is required")))?;
    let number = value
        .as_f64()
        .ok_or_else(|| invalid_finding(format!("{field} must be a finite number")))?;
    if !(0.0..=1.0).contains(&number) {
        return Err(invalid_finding(format!(
            "{field} must be within [0, 1]"
        )));
    }
    Ok(number)
}

fn validate_string_array(value: &Value, field: &str) -> Result<(), V1Error> {
    let Some(entries) = value.as_array() else {
        return Err(invalid_finding(format!("{field} must be an array")));
    };
    if entries.iter().any(|entry| !entry.is_string()) {
        return Err(invalid_finding(format!(
            "{field} entries must all be strings"
        )));
    }
    Ok(())
}

fn validate_issuer_id_message(value: &str) -> std::result::Result<(), String> {
    if !value.starts_with(ISSUER_ID_PREFIX) {
        return Err(format!(
            "issuerId must start with `{ISSUER_ID_PREFIX}`"
        ));
    }
    let suffix = &value[ISSUER_ID_PREFIX.len()..];
    if !is_lower_hex(suffix, 64) {
        return Err("issuerId must end with 64 lowercase hex characters".to_string());
    }
    Ok(())
}

fn validate_issuer_id(value: &str) -> Result<(), V1Error> {
    validate_issuer_id_message(value).map_err(invalid_finding)
}

fn normalize_digest_message(value: &str) -> std::result::Result<String, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        if is_lower_hex(hex, 64) {
            return Ok(value.to_string());
        }
    }
    Err("blob digest must be 0x-prefixed lowercase 64-byte hex".to_string())
}

fn normalize_digest(value: &str) -> Result<String, V1Error> {
    normalize_digest_message(value).map_err(invalid_finding)
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_finding_envelope_for_head(finding: &FindingEnvelope) -> Result<String, V1Error> {
    let mut value = serde_json::to_value(finding)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to serialize finding for head hash");
            V1Error::internal("SWARM_SERIALIZATION_ERROR", "internal serialization error")
        })?;
    let value_map = value.as_object_mut().ok_or_else(|| {
        V1Error::internal(
            "SWARM_SERIALIZATION_ERROR",
            "serialized finding envelope was not an object",
        )
    })?;
    value_map.remove("publish");
    if let Some(blob_refs) = value_map.get_mut("blobRefs").and_then(Value::as_array_mut) {
        for blob_ref in blob_refs {
            if let Some(blob_ref_map) = blob_ref.as_object_mut() {
                blob_ref_map.remove("publish");
            }
        }
    }
    let canonical = canonicalize(&value)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to canonicalize finding for head hash");
            V1Error::internal("SWARM_HASH_ERROR", "internal hash error")
        })?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn hash_revocation_envelope_for_head(revocation: &RevocationEnvelope) -> Result<String, V1Error> {
    let mut value = serde_json::to_value(revocation)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to serialize revocation for head hash");
            V1Error::internal("SWARM_SERIALIZATION_ERROR", "internal serialization error")
        })?;
    let value_map = value.as_object_mut().ok_or_else(|| {
        V1Error::internal(
            "SWARM_SERIALIZATION_ERROR",
            "serialized revocation envelope was not an object",
        )
    })?;
    value_map.remove("publish");
    let canonical = canonicalize(&value)
        .map_err(|err| {
            tracing::error!(error = %err, "failed to canonicalize revocation for head hash");
            V1Error::internal("SWARM_HASH_ERROR", "internal hash error")
        })?;
    Ok(sha256_hex(canonical.as_bytes()))
}
