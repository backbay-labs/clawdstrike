use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use clawdstrike_ocsf::fleet::{
    FleetEventEnvelope, FleetEventKind, FleetEventSeverity, FleetEventSource, FleetEventVerdict,
};
use hunt_correlate::service::{
    build_ioc_database, correlate_hunt_events, match_hunt_events, CorrelateRequest,
    CorrelationFinding, IocEventMatch, IocMatchRequest,
};
use hunt_query::query::{EventSource, QueryVerdict};
use hunt_query::service::{
    CreateSavedHuntRequest, HuntEvent, HuntEventKind, HuntEventSource, HuntJobRecord,
    HuntQueryRequest, HuntQueryResponse, HuntTimelineResponse, SavedHuntRecord, TimelineGroupedBy,
    UpdateSavedHuntRequest,
};
use hunt_query::timeline::NormalizedVerdict;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::executor::Executor;
use sqlx::query_builder::QueryBuilder;
use sqlx::row::Row;
use sqlx::transaction::Transaction;
use sqlx_postgres::Postgres;
use uuid::Uuid;

use crate::db::{PgPool, PgRow};
use crate::error::{is_unique_violation, ApiError};
use crate::models::hunt::{
    AgentSecretTouchEndpointSummary, AgentSecretTouchesRequest, AgentSecretTouchesResponse,
    EndpointEvidenceArchiveDownload, EndpointEvidenceArchiveRecord,
    EndpointEvidenceArchiveUploadRequest, StoredSearchCursor,
};

const EVENT_ID_CONFLICT: &str = "hunt event conflict: eventId already ingested";
const RAW_REF_CONFLICT: &str = "hunt evidence conflict: rawRef already ingested";
const ENDPOINT_ARCHIVE_RAW_REF_PREFIX: &str = "endpoint-evidence-bundle-archive";

struct VerifiedHuntIngest {
    event: FleetEventEnvelope,
    raw_envelope: Value,
    envelope_issuer: String,
    occurred_at: DateTime<Utc>,
    ingested_at: DateTime<Utc>,
    hunt_event: HuntEvent,
}

struct StoredHuntEnvelope {
    id: Uuid,
    source: String,
    issuer: Option<String>,
    issued_at: DateTime<Utc>,
    ingested_at: DateTime<Utc>,
    envelope_hash: Option<String>,
    schema_name: Option<String>,
    raw_envelope: Value,
    signature_valid: Option<bool>,
}

#[derive(Debug)]
struct PreparedEndpointEvidenceArchiveUpload {
    record: EndpointEvidenceArchiveRecord,
    archive: Value,
}

pub async fn ingest_event(
    db: &PgPool,
    tenant_id: Uuid,
    event: FleetEventEnvelope,
    raw_envelope: Value,
    trusted_signing_keypair: Option<&hush_core::Keypair>,
) -> Result<HuntEvent, ApiError> {
    let ingest = verify_ingest_event(tenant_id, event, raw_envelope, trusted_signing_keypair)?;
    let mut tx = db.begin().await.map_err(ApiError::Database)?;

    if let Some(existing) = find_existing_hunt_event(&mut tx, tenant_id, &ingest).await? {
        tx.rollback().await.map_err(ApiError::Database)?;
        return Ok(existing);
    }

    let envelope_id = persist_hunt_envelope(&mut tx, tenant_id, &ingest).await?;
    let existing = persist_hunt_event(&mut tx, tenant_id, envelope_id, &ingest).await?;

    match existing {
        Some(existing) => {
            tx.rollback().await.map_err(ApiError::Database)?;
            Ok(existing)
        }
        None => {
            tx.commit().await.map_err(ApiError::Database)?;
            get_event(db, tenant_id, &ingest.event.event_id).await
        }
    }
}

pub async fn search_events(
    db: &PgPool,
    tenant_id: Uuid,
    request: &HuntQueryRequest,
) -> Result<HuntQueryResponse, ApiError> {
    let total = count_events(db, tenant_id, request).await?;
    let (events, has_more) = list_events(db, tenant_id, request, false, true).await?;
    let next_cursor = has_more
        .then(|| {
            events
                .last()
                .map(|event| StoredSearchCursor {
                    timestamp: event.timestamp,
                    event_id: event.event_id.clone(),
                })
                .map(|cursor| cursor.encode())
        })
        .flatten();

    Ok(HuntQueryResponse {
        events,
        total,
        next_cursor,
    })
}

pub async fn timeline_events(
    db: &PgPool,
    tenant_id: Uuid,
    request: &HuntQueryRequest,
) -> Result<HuntTimelineResponse, ApiError> {
    let (events, _) = list_events(db, tenant_id, request, true, false).await?;
    Ok(HuntTimelineResponse {
        entity: request.entity.clone(),
        grouped_by: grouped_by(request),
        events,
    })
}

pub async fn agent_secret_touches(
    db: &PgPool,
    tenant_id: Uuid,
    request: &AgentSecretTouchesRequest,
) -> Result<AgentSecretTouchesResponse, ApiError> {
    let events = list_agent_secret_touch_events(db, tenant_id, request).await?;
    Ok(build_agent_secret_touch_response(events))
}

pub async fn upload_endpoint_evidence_archive(
    db: &PgPool,
    tenant_id: Uuid,
    request: EndpointEvidenceArchiveUploadRequest,
) -> Result<EndpointEvidenceArchiveRecord, ApiError> {
    let tenant_retention_days = tenant_retention_days(db, tenant_id).await?;
    let prepared = validate_endpoint_evidence_archive_upload(
        tenant_id,
        request,
        tenant_retention_days,
        Utc::now(),
    )?;

    if let Some(existing) =
        get_endpoint_evidence_archive_optional(db, tenant_id, &prepared.record.archive_id).await?
    {
        if existing.raw_ref == prepared.record.raw_ref
            && existing.archive_hash == prepared.record.archive_hash
            && existing.bundle_id == prepared.record.bundle_id
        {
            return Ok(existing);
        }
        return Err(ApiError::Conflict(
            "endpoint evidence archive id already exists with different content".to_string(),
        ));
    }

    let row = sqlx::query::query(
        r#"INSERT INTO endpoint_evidence_archives (
               tenant_id,
               archive_id,
               raw_ref,
               archive_hash,
               bundle_id,
               endpoint_agent_id,
               event_id,
               content_hash,
               graph_slice_id,
               uploaded_at,
               expires_at,
               retention_days,
               size_bytes,
               archive,
               verification,
               metadata
           ) VALUES (
               $1, $2, $3, $4, $5, $6, $7, $8,
               $9, $10, $11, $12, $13, $14, $15, $16
           )
           RETURNING tenant_id, archive_id, raw_ref, archive_hash, bundle_id, endpoint_agent_id,
                     event_id, content_hash, graph_slice_id, uploaded_at, expires_at,
                     retention_days, size_bytes, verification, metadata"#,
    )
    .bind(prepared.record.tenant_id)
    .bind(&prepared.record.archive_id)
    .bind(&prepared.record.raw_ref)
    .bind(&prepared.record.archive_hash)
    .bind(&prepared.record.bundle_id)
    .bind(prepared.record.endpoint_agent_id.as_deref())
    .bind(prepared.record.event_id.as_deref())
    .bind(prepared.record.content_hash.as_deref())
    .bind(prepared.record.graph_slice_id.as_deref())
    .bind(prepared.record.uploaded_at)
    .bind(prepared.record.expires_at)
    .bind(prepared.record.retention_days)
    .bind(prepared.record.size_bytes)
    .bind(&prepared.archive)
    .bind(&prepared.record.verification)
    .bind(&prepared.record.metadata)
    .fetch_one(db)
    .await
    .map_err(|err| {
        if is_unique_violation(&err) {
            ApiError::Conflict(
                "endpoint evidence archive already exists for this rawRef or archiveHash"
                    .to_string(),
            )
        } else {
            ApiError::Database(err)
        }
    })?;
    map_endpoint_archive_record(row)
}

pub async fn get_endpoint_evidence_archive(
    db: &PgPool,
    tenant_id: Uuid,
    archive_id: &str,
) -> Result<EndpointEvidenceArchiveRecord, ApiError> {
    get_endpoint_evidence_archive_optional(db, tenant_id, archive_id)
        .await?
        .ok_or(ApiError::NotFound)
}

pub async fn download_endpoint_evidence_archive(
    db: &PgPool,
    tenant_id: Uuid,
    archive_id: &str,
) -> Result<EndpointEvidenceArchiveDownload, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT tenant_id, archive_id, raw_ref, archive_hash, bundle_id, endpoint_agent_id,
                  event_id, content_hash, graph_slice_id, uploaded_at, expires_at,
                  retention_days, size_bytes, verification, metadata, archive
           FROM endpoint_evidence_archives
           WHERE tenant_id = $1 AND archive_id = $2"#,
    )
    .bind(tenant_id)
    .bind(archive_id)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(ApiError::Database)?;
    if expires_at <= Utc::now() {
        return Err(ApiError::BadRequest(
            "endpoint evidence archive has expired".to_string(),
        ));
    }
    let archive = row.try_get("archive").map_err(ApiError::Database)?;
    let record = map_endpoint_archive_record(row)?;
    Ok(EndpointEvidenceArchiveDownload { record, archive })
}

pub async fn record_endpoint_evidence_archive_download_audit(
    db: &PgPool,
    tenant_id: Uuid,
    actor_id: &str,
    actor_type: &str,
    actor_role: &str,
    record: &EndpointEvidenceArchiveRecord,
) -> Result<(), ApiError> {
    record_endpoint_evidence_archive_audit(
        db,
        tenant_id,
        "endpoint_evidence_archive.raw_downloaded",
        actor_id,
        actor_type,
        actor_role,
        record,
    )
    .await
}

pub async fn record_endpoint_evidence_archive_upload_audit(
    db: &PgPool,
    tenant_id: Uuid,
    actor_id: &str,
    actor_type: &str,
    actor_role: &str,
    record: &EndpointEvidenceArchiveRecord,
) -> Result<(), ApiError> {
    record_endpoint_evidence_archive_audit(
        db,
        tenant_id,
        "endpoint_evidence_archive.raw_uploaded",
        actor_id,
        actor_type,
        actor_role,
        record,
    )
    .await
}

pub async fn record_endpoint_evidence_archive_upload_denied_audit(
    db: &PgPool,
    tenant_id: Uuid,
    actor_id: &str,
    actor_type: &str,
    actor_role: &str,
    request: &EndpointEvidenceArchiveUploadRequest,
    denied_reason: &str,
) -> Result<(), ApiError> {
    let metadata = serde_json::json!({
        "archiveId": request.archive_id.as_str(),
        "archiveHash": request.archive_hash.as_str(),
        "rawRef": request.raw_ref.as_str(),
        "bundleId": request.bundle_id.as_str(),
        "endpointAgentId": request.endpoint_agent_id.as_deref(),
        "eventId": request.event_id.as_deref(),
        "rawArtifactApprovalId": request.raw_artifact_approval_id.as_deref(),
        "rawArtifactApprovalReasonHash": request.raw_artifact_approval_reason_hash.as_deref(),
        "retentionDays": request.retention_days,
        "actorId": actor_id,
        "actorType": actor_type,
        "actorRole": actor_role,
        "deniedReason": denied_reason,
    });
    record_endpoint_evidence_archive_audit_metadata(
        db,
        tenant_id,
        "endpoint_evidence_archive.raw_upload_denied",
        metadata,
    )
    .await
}

pub async fn record_endpoint_evidence_archive_download_denied_audit(
    db: &PgPool,
    tenant_id: Uuid,
    actor_id: &str,
    actor_type: &str,
    actor_role: &str,
    archive_id: &str,
    denied_reason: &str,
) -> Result<(), ApiError> {
    let metadata = serde_json::json!({
        "archiveId": archive_id,
        "actorId": actor_id,
        "actorType": actor_type,
        "actorRole": actor_role,
        "deniedReason": denied_reason,
    });
    record_endpoint_evidence_archive_audit_metadata(
        db,
        tenant_id,
        "endpoint_evidence_archive.raw_download_denied",
        metadata,
    )
    .await
}

async fn record_endpoint_evidence_archive_audit(
    db: &PgPool,
    tenant_id: Uuid,
    event_type: &str,
    actor_id: &str,
    actor_type: &str,
    actor_role: &str,
    record: &EndpointEvidenceArchiveRecord,
) -> Result<(), ApiError> {
    let metadata = serde_json::json!({
        "archiveId": record.archive_id,
        "archiveHash": record.archive_hash,
        "rawRef": record.raw_ref,
        "bundleId": record.bundle_id,
        "endpointAgentId": record.endpoint_agent_id,
        "eventId": record.event_id,
        "contentHash": record.content_hash,
        "graphSliceId": record.graph_slice_id,
        "rawArtifactApprovalId": record.raw_artifact_approval_id,
        "rawArtifactApprovalReasonHash": record.raw_artifact_approval_reason_hash,
        "sizeBytes": record.size_bytes,
        "retentionDays": record.retention_days,
        "expiresAt": record.expires_at,
        "actorId": actor_id,
        "actorType": actor_type,
        "actorRole": actor_role,
    });
    record_endpoint_evidence_archive_audit_metadata(db, tenant_id, event_type, metadata).await
}

async fn record_endpoint_evidence_archive_audit_metadata(
    db: &PgPool,
    tenant_id: Uuid,
    event_type: &str,
    metadata: Value,
) -> Result<(), ApiError> {
    sqlx::query::query(
        r#"INSERT INTO usage_events (tenant_id, event_type, quantity, metadata)
           VALUES ($1, $2, 1, $3)"#,
    )
    .bind(tenant_id)
    .bind(event_type)
    .bind(metadata)
    .execute(db)
    .await
    .map_err(ApiError::Database)?;
    Ok(())
}

async fn get_endpoint_evidence_archive_optional(
    db: &PgPool,
    tenant_id: Uuid,
    archive_id: &str,
) -> Result<Option<EndpointEvidenceArchiveRecord>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT tenant_id, archive_id, raw_ref, archive_hash, bundle_id, endpoint_agent_id,
                  event_id, content_hash, graph_slice_id, uploaded_at, expires_at,
                  retention_days, size_bytes, verification, metadata
           FROM endpoint_evidence_archives
           WHERE tenant_id = $1 AND archive_id = $2"#,
    )
    .bind(tenant_id)
    .bind(archive_id)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?;
    row.map(map_endpoint_archive_record).transpose()
}

async fn tenant_retention_days(db: &PgPool, tenant_id: Uuid) -> Result<i32, ApiError> {
    let row = sqlx::query::query("SELECT retention_days FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
    row.try_get("retention_days").map_err(ApiError::Database)
}

fn map_endpoint_archive_record(row: PgRow) -> Result<EndpointEvidenceArchiveRecord, ApiError> {
    let metadata: Value = row.try_get("metadata").map_err(ApiError::Database)?;
    Ok(EndpointEvidenceArchiveRecord {
        tenant_id: row.try_get("tenant_id").map_err(ApiError::Database)?,
        archive_id: row.try_get("archive_id").map_err(ApiError::Database)?,
        raw_ref: row.try_get("raw_ref").map_err(ApiError::Database)?,
        archive_hash: row.try_get("archive_hash").map_err(ApiError::Database)?,
        bundle_id: row.try_get("bundle_id").map_err(ApiError::Database)?,
        endpoint_agent_id: row
            .try_get("endpoint_agent_id")
            .map_err(ApiError::Database)?,
        event_id: row.try_get("event_id").map_err(ApiError::Database)?,
        content_hash: row.try_get("content_hash").map_err(ApiError::Database)?,
        graph_slice_id: row.try_get("graph_slice_id").map_err(ApiError::Database)?,
        raw_artifact_approval_id: optional_archive_string(&metadata, "/rawArtifactApprovalId"),
        raw_artifact_approval_reason_hash: optional_archive_string(
            &metadata,
            "/rawArtifactApprovalReasonHash",
        ),
        uploaded_at: row.try_get("uploaded_at").map_err(ApiError::Database)?,
        expires_at: row.try_get("expires_at").map_err(ApiError::Database)?,
        retention_days: row.try_get("retention_days").map_err(ApiError::Database)?,
        size_bytes: row.try_get("size_bytes").map_err(ApiError::Database)?,
        verification: row.try_get("verification").map_err(ApiError::Database)?,
        metadata,
    })
}

fn endpoint_archive_hash(archive: &Value) -> Result<String, ApiError> {
    let canonical = hush_core::canonicalize_json(archive).map_err(|err| {
        ApiError::BadRequest(format!("archive is not canonicalizable JSON: {err}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(format!("0x{}", hex::encode(hasher.finalize())))
}

fn required_archive_string<'a>(value: &'a Value, path: &'static str) -> Result<&'a str, ApiError> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::BadRequest(format!("archive is missing required field {path}")))
}

fn optional_archive_string(value: &Value, path: &'static str) -> Option<String> {
    value
        .pointer(path)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn non_empty_archive_request_field(
    name: &'static str,
    value: String,
    max_len: usize,
) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(ApiError::BadRequest(format!("{name} must not be empty")));
    }
    if value.len() > max_len {
        return Err(ApiError::BadRequest(format!(
            "{name} must be at most {max_len} bytes"
        )));
    }
    Ok(value)
}

fn raw_artifact_approval_reason_hash_field(value: String) -> Result<String, ApiError> {
    let value = non_empty_archive_request_field("rawArtifactApprovalReasonHash", value, 128)?;
    if !value.starts_with("0x") {
        return Err(ApiError::BadRequest(
            "rawArtifactApprovalReasonHash must be a 0x-prefixed hash".to_string(),
        ));
    }
    Ok(value)
}

fn archive_metadata_with_raw_artifact_approval(
    metadata: Value,
    approval_id: &str,
    approval_reason_hash: &str,
) -> Value {
    let mut object = metadata.as_object().cloned().unwrap_or_default();
    object.insert(
        "rawArtifactApprovalId".to_string(),
        Value::String(approval_id.to_string()),
    );
    object.insert(
        "rawArtifactApprovalReasonHash".to_string(),
        Value::String(approval_reason_hash.to_string()),
    );
    Value::Object(object)
}

fn endpoint_archive_canonical_size_bytes(archive: &Value) -> Result<i64, ApiError> {
    let canonical = hush_core::canonicalize_json(archive).map_err(|err| {
        ApiError::BadRequest(format!("archive is not canonicalizable JSON: {err}"))
    })?;
    i64::try_from(canonical.len())
        .map_err(|_| ApiError::BadRequest("archive canonical JSON is too large".to_string()))
}

fn validate_endpoint_evidence_archive_upload(
    tenant_id: Uuid,
    request: EndpointEvidenceArchiveUploadRequest,
    tenant_retention_days: i32,
    now: DateTime<Utc>,
) -> Result<PreparedEndpointEvidenceArchiveUpload, ApiError> {
    let archive_id = non_empty_archive_request_field("archiveId", request.archive_id, 256)?;
    let archive_hash = non_empty_archive_request_field("archiveHash", request.archive_hash, 128)?;
    let raw_ref = non_empty_archive_request_field("rawRef", request.raw_ref, 512)?;
    let bundle_id = non_empty_archive_request_field("bundleId", request.bundle_id, 256)?;
    let endpoint_agent_id = request
        .endpoint_agent_id
        .map(|value| non_empty_archive_request_field("endpointAgentId", value, 256))
        .transpose()?;
    let event_id = request
        .event_id
        .map(|value| non_empty_archive_request_field("eventId", value, 512))
        .transpose()?;
    let raw_artifact_approval_id = request
        .raw_artifact_approval_id
        .map(|value| non_empty_archive_request_field("rawArtifactApprovalId", value, 128))
        .transpose()?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "rawArtifactApprovalId is required for raw archive upload".to_string(),
            )
        })?;
    let raw_artifact_approval_reason_hash = request
        .raw_artifact_approval_reason_hash
        .map(raw_artifact_approval_reason_hash_field)
        .transpose()?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "rawArtifactApprovalReasonHash is required for raw archive upload".to_string(),
            )
        })?;

    if !archive_hash.starts_with("0x") {
        return Err(ApiError::BadRequest(
            "archiveHash must be a 0x-prefixed sha256 hash".to_string(),
        ));
    }
    let computed_hash = endpoint_archive_hash(&request.archive)?;
    if archive_hash != computed_hash {
        return Err(ApiError::BadRequest(format!(
            "archiveHash does not match canonical archive hash: expected {computed_hash}"
        )));
    }

    let expected_raw_ref = format!("{ENDPOINT_ARCHIVE_RAW_REF_PREFIX}:{archive_id}:{archive_hash}");
    if raw_ref != expected_raw_ref {
        return Err(ApiError::BadRequest(format!(
            "rawRef must be {expected_raw_ref}"
        )));
    }

    let archive_bundle_id = required_archive_string(&request.archive, "/bundle/bundleId")?;
    if archive_bundle_id != bundle_id {
        return Err(ApiError::BadRequest(
            "bundleId does not match archive.bundle.bundleId".to_string(),
        ));
    }

    if !request
        .verification
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ApiError::BadRequest(
            "verification.verified must be true before archive upload".to_string(),
        ));
    }

    let tenant_retention_days = tenant_retention_days.max(1);
    let requested_retention_days = request
        .retention_days
        .unwrap_or(tenant_retention_days)
        .max(1);
    let retention_days = requested_retention_days.min(tenant_retention_days);
    let expires_at = now + chrono::Duration::days(i64::from(retention_days));
    let size_bytes = endpoint_archive_canonical_size_bytes(&request.archive)?;
    let metadata = archive_metadata_with_raw_artifact_approval(
        request.metadata,
        &raw_artifact_approval_id,
        &raw_artifact_approval_reason_hash,
    );

    Ok(PreparedEndpointEvidenceArchiveUpload {
        record: EndpointEvidenceArchiveRecord {
            tenant_id,
            archive_id,
            raw_ref,
            archive_hash,
            bundle_id,
            endpoint_agent_id,
            event_id,
            content_hash: optional_archive_string(&request.archive, "/bundle/contentHash"),
            graph_slice_id: optional_archive_string(&request.archive, "/bundle/graphSliceId"),
            raw_artifact_approval_id: Some(raw_artifact_approval_id),
            raw_artifact_approval_reason_hash: Some(raw_artifact_approval_reason_hash),
            uploaded_at: now,
            expires_at,
            retention_days,
            size_bytes,
            verification: request.verification,
            metadata,
        },
        archive: request.archive,
    })
}

pub async fn create_saved_hunt(
    db: &PgPool,
    tenant_id: Uuid,
    created_by: &str,
    request: &CreateSavedHuntRequest,
) -> Result<SavedHuntRecord, ApiError> {
    let row = sqlx::query::query(
        r#"INSERT INTO saved_hunts (tenant_id, name, description, query, created_by)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, tenant_id, name, description, query, created_by, created_at, updated_at"#,
    )
    .bind(tenant_id)
    .bind(&request.name)
    .bind(request.description.as_deref())
    .bind(serde_json::to_value(&request.query).map_err(|e| ApiError::Internal(e.to_string()))?)
    .bind(created_by)
    .fetch_one(db)
    .await
    .map_err(ApiError::Database)?;
    map_saved_hunt_row(row)
}

pub async fn list_saved_hunts(
    db: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<SavedHuntRecord>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT id, tenant_id, name, description, query, created_by, created_at, updated_at
           FROM saved_hunts
           WHERE tenant_id = $1
           ORDER BY updated_at DESC, id DESC"#,
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;
    rows.into_iter().map(map_saved_hunt_row).collect()
}

pub async fn get_saved_hunt(
    db: &PgPool,
    tenant_id: Uuid,
    hunt_id: Uuid,
) -> Result<SavedHuntRecord, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT id, tenant_id, name, description, query, created_by, created_at, updated_at
           FROM saved_hunts
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(hunt_id)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    map_saved_hunt_row(row)
}

pub async fn update_saved_hunt(
    db: &PgPool,
    tenant_id: Uuid,
    hunt_id: Uuid,
    request: &UpdateSavedHuntRequest,
) -> Result<SavedHuntRecord, ApiError> {
    let query_json = request
        .query
        .as_ref()
        .map(|query| serde_json::to_value(query).map_err(|e| ApiError::Internal(e.to_string())))
        .transpose()?;
    let row = sqlx::query::query(
        r#"UPDATE saved_hunts
           SET name = COALESCE($3, name),
               description = COALESCE($4, description),
               query = COALESCE($5, query),
               updated_at = now()
           WHERE tenant_id = $1 AND id = $2
           RETURNING id, tenant_id, name, description, query, created_by, created_at, updated_at"#,
    )
    .bind(tenant_id)
    .bind(hunt_id)
    .bind(request.name.as_deref())
    .bind(request.description.as_deref())
    .bind(query_json)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    map_saved_hunt_row(row)
}

pub async fn delete_saved_hunt(
    db: &PgPool,
    tenant_id: Uuid,
    hunt_id: Uuid,
) -> Result<(), ApiError> {
    let result = sqlx::query::query("DELETE FROM saved_hunts WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(hunt_id)
        .execute(db)
        .await
        .map_err(ApiError::Database)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

pub async fn run_saved_hunt(
    db: &PgPool,
    tenant_id: Uuid,
    hunt_id: Uuid,
    created_by: &str,
) -> Result<HuntJobRecord, ApiError> {
    let saved = get_saved_hunt(db, tenant_id, hunt_id).await?;
    let result = search_events(db, tenant_id, &saved.query).await?;
    create_job(
        db,
        tenant_id,
        "saved_hunt",
        serde_json::to_value(&saved).map_err(|e| ApiError::Internal(e.to_string()))?,
        serde_json::to_value(&result).map_err(|e| ApiError::Internal(e.to_string()))?,
        created_by,
    )
    .await
}

pub async fn run_correlation_job(
    db: &PgPool,
    tenant_id: Uuid,
    created_by: &str,
    request: &CorrelateRequest,
) -> Result<HuntJobRecord, ApiError> {
    let search_request = request.query.clone().unwrap_or_default();
    let (events, _) = list_events(db, tenant_id, &search_request, true, false).await?;
    let findings: Vec<CorrelationFinding> = correlate_hunt_events(request.rules.clone(), &events)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    create_job(
        db,
        tenant_id,
        "correlate",
        serde_json::to_value(request).map_err(|e| ApiError::Internal(e.to_string()))?,
        serde_json::json!({ "findings": findings }),
        created_by,
    )
    .await
}

pub async fn run_ioc_job(
    db: &PgPool,
    tenant_id: Uuid,
    created_by: &str,
    request: &IocMatchRequest,
) -> Result<HuntJobRecord, ApiError> {
    let search_request = request.query.clone().unwrap_or_default();
    let (events, _) = list_events(db, tenant_id, &search_request, false, false).await?;
    let database = build_ioc_database(request).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let matches: Vec<IocEventMatch> = match_hunt_events(&database, &events);
    create_job(
        db,
        tenant_id,
        "ioc_match",
        serde_json::to_value(request).map_err(|e| ApiError::Internal(e.to_string()))?,
        serde_json::json!({ "matches": matches }),
        created_by,
    )
    .await
}

pub async fn get_job(
    db: &PgPool,
    tenant_id: Uuid,
    job_id: Uuid,
) -> Result<HuntJobRecord, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT id, tenant_id, job_type, status, request, result, created_by, created_at, completed_at
           FROM hunt_jobs
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(job_id)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    map_job_row(row)
}

pub async fn get_event(
    db: &PgPool,
    tenant_id: Uuid,
    event_id: &str,
) -> Result<HuntEvent, ApiError> {
    get_event_optional(db, tenant_id, event_id)
        .await?
        .ok_or(ApiError::NotFound)
}

fn verify_ingest_event(
    tenant_id: Uuid,
    event: FleetEventEnvelope,
    raw_envelope: Value,
    trusted_signing_keypair: Option<&hush_core::Keypair>,
) -> Result<VerifiedHuntIngest, ApiError> {
    let trusted_issuer = trusted_hunt_issuer(trusted_signing_keypair)?;
    let (verified_event, envelope_issuer) =
        verify_signed_hunt_envelope(&raw_envelope, &trusted_issuer)?;
    if verified_event != event {
        return Err(ApiError::BadRequest(
            "event must match the signed rawEnvelope fact".to_string(),
        ));
    }

    let event_tenant_id = Uuid::parse_str(&verified_event.tenant_id)
        .map_err(|_| ApiError::BadRequest("event.tenantId must be a UUID".to_string()))?;
    if event_tenant_id != tenant_id {
        return Err(ApiError::BadRequest(
            "event.tenantId must match authenticated tenant".to_string(),
        ));
    }

    let occurred_at = DateTime::parse_from_rfc3339(&verified_event.occurred_at)
        .map_err(|_| ApiError::BadRequest("event.occurredAt must be RFC3339".to_string()))?
        .with_timezone(&Utc);
    let ingested_at = DateTime::parse_from_rfc3339(&verified_event.ingested_at)
        .map_err(|_| ApiError::BadRequest("event.ingestedAt must be RFC3339".to_string()))?
        .with_timezone(&Utc);
    let canonical_event = canonicalize_verified_event(verified_event, &envelope_issuer);
    let hunt_event =
        HuntEvent::try_from_fleet_event(&canonical_event).map_err(ApiError::BadRequest)?;

    Ok(VerifiedHuntIngest {
        event: canonical_event,
        raw_envelope,
        envelope_issuer,
        occurred_at,
        ingested_at,
        hunt_event,
    })
}

fn canonicalize_verified_event(
    mut event: FleetEventEnvelope,
    envelope_issuer: &str,
) -> FleetEventEnvelope {
    event.evidence.issuer = Some(envelope_issuer.to_string());
    event.evidence.signature_valid = Some(true);
    event
}

async fn find_existing_hunt_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    ingest: &VerifiedHuntIngest,
) -> Result<Option<HuntEvent>, ApiError> {
    if let Some(existing) = get_event_optional(&mut **tx, tenant_id, &ingest.event.event_id).await?
    {
        return ensure_matching_hunt_event(existing, &ingest.hunt_event, EVENT_ID_CONFLICT)
            .map(Some);
    }

    if let Some(existing) =
        get_event_by_raw_ref_optional(&mut **tx, tenant_id, &ingest.event.evidence.raw_ref).await?
    {
        return ensure_matching_hunt_event(existing, &ingest.hunt_event, RAW_REF_CONFLICT)
            .map(Some);
    }

    Ok(None)
}

async fn persist_hunt_envelope(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    ingest: &VerifiedHuntIngest,
) -> Result<Uuid, ApiError> {
    // Evidence is immutable: concurrent or duplicate ingests reuse the existing row only if the
    // stored envelope still matches byte-for-byte and metadata-for-metadata.
    let row = sqlx::query::query(
        r#"INSERT INTO hunt_envelopes (
               tenant_id,
               source,
               issuer,
               issued_at,
               ingested_at,
               envelope_hash,
               schema_name,
               raw_ref,
               raw_envelope,
               signature_valid,
               created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
           ON CONFLICT (tenant_id, raw_ref)
           DO NOTHING
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(fleet_source_to_str(ingest.event.source))
    .bind(Some(ingest.envelope_issuer.as_str()))
    .bind(ingest.occurred_at)
    .bind(ingest.ingested_at)
    .bind(ingest.event.evidence.envelope_hash.as_deref())
    .bind(ingest.event.evidence.schema_name.as_deref())
    .bind(&ingest.event.evidence.raw_ref)
    .bind(ingest.raw_envelope.clone())
    .bind(Some(true))
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    if let Some(row) = row {
        return row.try_get("id").map_err(ApiError::Database);
    }

    let existing = get_envelope_by_raw_ref(&mut **tx, tenant_id, &ingest.event.evidence.raw_ref)
        .await?
        .ok_or_else(|| ApiError::Conflict(RAW_REF_CONFLICT.to_string()))?;
    ensure_matching_hunt_envelope(&existing, ingest)?;
    Ok(existing.id)
}

async fn persist_hunt_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    envelope_id: Uuid,
    ingest: &VerifiedHuntIngest,
) -> Result<Option<HuntEvent>, ApiError> {
    // We never rewrite a previously ingested event on key collision. Exact duplicates are
    // idempotent; everything else is an explicit conflict.
    let row = sqlx::query::query(
        r#"INSERT INTO hunt_events (
               event_id, tenant_id, envelope_id, source, kind, timestamp, ingested_at, verdict,
               severity, summary, action_type, process, namespace, pod, session_id,
               endpoint_agent_id, runtime_agent_id, principal_id, grant_id,
               response_action_id, detection_ids, target_kind, target_id, target_name,
               envelope_hash, issuer, schema_name, signature_valid, raw_ref, attributes
           )
           VALUES (
               $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
               $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
               $21, $22, $23, $24, $25, $26, $27, $28, $29, $30
           )
           ON CONFLICT (tenant_id, event_id)
           DO NOTHING
           RETURNING event_id"#,
    )
    .bind(&ingest.event.event_id)
    .bind(tenant_id)
    .bind(envelope_id)
    .bind(fleet_source_to_str(ingest.event.source))
    .bind(fleet_kind_to_str(ingest.event.kind))
    .bind(ingest.occurred_at)
    .bind(ingest.ingested_at)
    .bind(fleet_verdict_to_str(ingest.event.verdict).unwrap_or("none"))
    .bind(ingest.event.severity.map(fleet_severity_to_str))
    .bind(&ingest.event.summary)
    .bind(ingest.event.action_type.as_deref())
    .bind(
        ingest
            .event
            .attributes
            .get("process")
            .and_then(Value::as_str),
    )
    .bind(
        ingest
            .event
            .attributes
            .get("namespace")
            .and_then(Value::as_str),
    )
    .bind(ingest.event.attributes.get("pod").and_then(Value::as_str))
    .bind(ingest.event.session_id.as_deref())
    .bind(
        ingest
            .event
            .principal
            .as_ref()
            .and_then(|principal| principal.endpoint_agent_id.as_deref()),
    )
    .bind(
        ingest
            .event
            .principal
            .as_ref()
            .and_then(|principal| principal.runtime_agent_id.as_deref()),
    )
    .bind(
        ingest
            .event
            .principal
            .as_ref()
            .and_then(|principal| principal.principal_id.as_deref()),
    )
    .bind(ingest.event.grant_id.as_deref())
    .bind(ingest.event.response_action_id.as_deref())
    .bind(&ingest.event.detection_ids)
    .bind(
        ingest
            .event
            .target
            .as_ref()
            .and_then(|target| target.kind.as_deref()),
    )
    .bind(
        ingest
            .event
            .target
            .as_ref()
            .and_then(|target| target.id.as_deref()),
    )
    .bind(
        ingest
            .event
            .target
            .as_ref()
            .and_then(|target| target.name.as_deref()),
    )
    .bind(ingest.event.evidence.envelope_hash.as_deref())
    .bind(Some(ingest.envelope_issuer.as_str()))
    .bind(ingest.event.evidence.schema_name.as_deref())
    .bind(Some(true))
    .bind(&ingest.event.evidence.raw_ref)
    .bind(&ingest.event.attributes)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    if row.is_some() {
        return Ok(None);
    }

    let existing = get_event_optional(&mut **tx, tenant_id, &ingest.event.event_id)
        .await?
        .ok_or_else(|| ApiError::Conflict(EVENT_ID_CONFLICT.to_string()))?;
    ensure_matching_hunt_event(existing, &ingest.hunt_event, EVENT_ID_CONFLICT).map(Some)
}

async fn get_event_optional(
    executor: impl Executor<'_, Database = Postgres>,
    tenant_id: Uuid,
    event_id: &str,
) -> Result<Option<HuntEvent>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT event_id, tenant_id, source, kind, timestamp, verdict, severity, summary,
                  action_type, process, namespace, pod, session_id, endpoint_agent_id,
                  runtime_agent_id, principal_id, grant_id, response_action_id, detection_ids,
                  target_kind, target_id, target_name, envelope_hash, issuer, schema_name,
                  signature_valid, raw_ref, attributes
           FROM hunt_events
           WHERE tenant_id = $1 AND event_id = $2"#,
    )
    .bind(tenant_id)
    .bind(event_id)
    .fetch_optional(executor)
    .await
    .map_err(ApiError::Database)?;
    row.map(map_event_row).transpose()
}

async fn get_event_by_raw_ref_optional(
    executor: impl Executor<'_, Database = Postgres>,
    tenant_id: Uuid,
    raw_ref: &str,
) -> Result<Option<HuntEvent>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT event_id, tenant_id, source, kind, timestamp, verdict, severity, summary,
                  action_type, process, namespace, pod, session_id, endpoint_agent_id,
                  runtime_agent_id, principal_id, grant_id, response_action_id, detection_ids,
                  target_kind, target_id, target_name, envelope_hash, issuer, schema_name,
                  signature_valid, raw_ref, attributes
           FROM hunt_events
           WHERE tenant_id = $1 AND raw_ref = $2
           ORDER BY timestamp DESC, event_id DESC
           LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(raw_ref)
    .fetch_optional(executor)
    .await
    .map_err(ApiError::Database)?;
    row.map(map_event_row).transpose()
}

async fn get_envelope_by_raw_ref(
    executor: impl Executor<'_, Database = Postgres>,
    tenant_id: Uuid,
    raw_ref: &str,
) -> Result<Option<StoredHuntEnvelope>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT id, source, issuer, issued_at, ingested_at, envelope_hash, schema_name,
                  raw_envelope, signature_valid
           FROM hunt_envelopes
           WHERE tenant_id = $1 AND raw_ref = $2"#,
    )
    .bind(tenant_id)
    .bind(raw_ref)
    .fetch_optional(executor)
    .await
    .map_err(ApiError::Database)?;
    row.map(map_envelope_row).transpose()
}

fn ensure_matching_hunt_event(
    existing: HuntEvent,
    incoming: &HuntEvent,
    conflict_message: &str,
) -> Result<HuntEvent, ApiError> {
    if existing == *incoming {
        return Ok(existing);
    }
    Err(ApiError::Conflict(conflict_message.to_string()))
}

fn ensure_matching_hunt_envelope(
    existing: &StoredHuntEnvelope,
    ingest: &VerifiedHuntIngest,
) -> Result<(), ApiError> {
    let incoming = StoredHuntEnvelope {
        id: existing.id,
        source: fleet_source_to_str(ingest.event.source).to_string(),
        issuer: Some(ingest.envelope_issuer.clone()),
        issued_at: ingest.occurred_at,
        ingested_at: ingest.ingested_at,
        envelope_hash: ingest.event.evidence.envelope_hash.clone(),
        schema_name: ingest.event.evidence.schema_name.clone(),
        raw_envelope: ingest.raw_envelope.clone(),
        signature_valid: Some(true),
    };

    if existing.source == incoming.source
        && existing.issuer == incoming.issuer
        && existing.issued_at == incoming.issued_at
        && existing.ingested_at == incoming.ingested_at
        && existing.envelope_hash == incoming.envelope_hash
        && existing.schema_name == incoming.schema_name
        && existing.raw_envelope == incoming.raw_envelope
        && existing.signature_valid == incoming.signature_valid
    {
        return Ok(());
    }

    Err(ApiError::Conflict(RAW_REF_CONFLICT.to_string()))
}

fn map_envelope_row(row: PgRow) -> Result<StoredHuntEnvelope, ApiError> {
    Ok(StoredHuntEnvelope {
        id: row.try_get("id").map_err(ApiError::Database)?,
        source: row.try_get("source").map_err(ApiError::Database)?,
        issuer: row.try_get("issuer").map_err(ApiError::Database)?,
        issued_at: row.try_get("issued_at").map_err(ApiError::Database)?,
        ingested_at: row.try_get("ingested_at").map_err(ApiError::Database)?,
        envelope_hash: row.try_get("envelope_hash").map_err(ApiError::Database)?,
        schema_name: row.try_get("schema_name").map_err(ApiError::Database)?,
        raw_envelope: row.try_get("raw_envelope").map_err(ApiError::Database)?,
        signature_valid: row.try_get("signature_valid").map_err(ApiError::Database)?,
    })
}

async fn create_job(
    db: &PgPool,
    tenant_id: Uuid,
    job_type: &str,
    request: Value,
    result: Value,
    created_by: &str,
) -> Result<HuntJobRecord, ApiError> {
    let row = sqlx::query::query(
        r#"INSERT INTO hunt_jobs (tenant_id, job_type, status, request, result, created_by, completed_at)
           VALUES ($1, $2, 'completed', $3, $4, $5, now())
           RETURNING id, tenant_id, job_type, status, request, result, created_by, created_at, completed_at"#,
    )
    .bind(tenant_id)
    .bind(job_type)
    .bind(request)
    .bind(result)
    .bind(created_by)
    .fetch_one(db)
    .await
    .map_err(ApiError::Database)?;
    map_job_row(row)
}

async fn count_events(
    db: &PgPool,
    tenant_id: Uuid,
    request: &HuntQueryRequest,
) -> Result<usize, ApiError> {
    let mut builder: QueryBuilder<Postgres> =
        QueryBuilder::new("SELECT count(*)::bigint AS total FROM hunt_events");
    apply_filters(&mut builder, tenant_id, request, false, false);
    let row = builder
        .build()
        .fetch_one(db)
        .await
        .map_err(ApiError::Database)?;
    let total: i64 = row.try_get("total").map_err(ApiError::Database)?;
    usize::try_from(total).map_err(|e| ApiError::Internal(e.to_string()))
}

async fn list_events(
    db: &PgPool,
    tenant_id: Uuid,
    request: &HuntQueryRequest,
    ascending: bool,
    include_cursor: bool,
) -> Result<(Vec<HuntEvent>, bool), ApiError> {
    let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"SELECT event_id, tenant_id, source, kind, timestamp, verdict, severity, summary,
                  action_type, process, namespace, pod, session_id, endpoint_agent_id,
                  runtime_agent_id, principal_id, grant_id, response_action_id, detection_ids,
                  target_kind, target_id, target_name, envelope_hash, issuer, schema_name,
                  signature_valid, raw_ref, attributes
           FROM hunt_events"#,
    );
    apply_filters(&mut builder, tenant_id, request, include_cursor, ascending);
    if ascending {
        builder.push(" ORDER BY timestamp ASC, event_id ASC");
    } else {
        builder.push(" ORDER BY timestamp DESC, event_id DESC");
    }
    let limit = request.limit_or_default();
    let fetch_limit = if include_cursor {
        limit.saturating_add(1)
    } else {
        limit
    };
    builder.push(" LIMIT ");
    builder.push_bind(i64::try_from(fetch_limit).map_err(|e| ApiError::Internal(e.to_string()))?);

    let mut events = builder
        .build()
        .fetch_all(db)
        .await
        .map_err(ApiError::Database)?
        .into_iter()
        .map(map_event_row)
        .collect::<Result<Vec<_>, _>>()?;

    let has_more = include_cursor && events.len() > limit;
    if has_more {
        events.truncate(limit);
    }

    Ok((events, has_more))
}

async fn list_agent_secret_touch_events(
    db: &PgPool,
    tenant_id: Uuid,
    request: &AgentSecretTouchesRequest,
) -> Result<Vec<HuntEvent>, ApiError> {
    let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"SELECT event_id, tenant_id, source, kind, timestamp, verdict, severity, summary,
                  action_type, process, namespace, pod, session_id, endpoint_agent_id,
                  runtime_agent_id, principal_id, grant_id, response_action_id, detection_ids,
                  target_kind, target_id, target_name, envelope_hash, issuer, schema_name,
                  signature_valid, raw_ref, attributes
           FROM hunt_events"#,
    );
    apply_agent_secret_touch_filters(&mut builder, tenant_id, request);
    builder.push(" ORDER BY timestamp DESC, event_id DESC LIMIT ");
    builder.push_bind(
        i64::try_from(request.limit_or_default()).map_err(|e| ApiError::Internal(e.to_string()))?,
    );

    builder
        .build()
        .fetch_all(db)
        .await
        .map_err(ApiError::Database)?
        .into_iter()
        .map(map_event_row)
        .collect::<Result<Vec<_>, _>>()
        .map(|events| {
            events
                .into_iter()
                .filter(event_matches_agent_secret_touch)
                .collect()
        })
}

fn apply_agent_secret_touch_filters<'a>(
    builder: &mut QueryBuilder<'a, Postgres>,
    tenant_id: Uuid,
    request: &'a AgentSecretTouchesRequest,
) {
    builder.push(" WHERE tenant_id = ");
    builder.push_bind(tenant_id);

    if let Some(start) = request.start {
        builder.push(" AND timestamp >= ");
        builder.push_bind(start);
    }
    if let Some(end) = request.end {
        builder.push(" AND timestamp <= ");
        builder.push_bind(end);
    }
    if let Some(endpoint_agent_id) = request.endpoint_agent_id.as_deref() {
        builder.push(" AND endpoint_agent_id = ");
        builder.push_bind(endpoint_agent_id);
    }
    if let Some(runtime_agent_id) = request.runtime_agent_id.as_deref() {
        builder.push(" AND runtime_agent_id = ");
        builder.push_bind(runtime_agent_id);
    }
    if let Some(principal_id) = request.principal_id.as_deref() {
        builder.push(" AND principal_id = ");
        builder.push_bind(principal_id);
    }
    if let Some(session_id) = request.session_id.as_deref() {
        builder.push(" AND session_id = ");
        builder.push_bind(session_id);
    }
    if let Some(agent_id) = request.agent_id.as_deref() {
        builder.push(
            r#" AND (
                endpoint_agent_id = "#,
        );
        builder.push_bind(agent_id);
        builder.push(" OR runtime_agent_id = ");
        builder.push_bind(agent_id);
        builder.push(" OR principal_id = ");
        builder.push_bind(agent_id);
        builder.push(" OR attributes ->> 'agentId' = ");
        builder.push_bind(agent_id);
        builder.push(" OR attributes ->> 'agent_id' = ");
        builder.push_bind(agent_id);
        builder.push(" OR attributes ->> 'runtimeAgentId' = ");
        builder.push_bind(agent_id);
        builder.push(" OR attributes ->> 'runtime_agent_id' = ");
        builder.push_bind(agent_id);
        builder.push(")");
    }
    if let Some(credential_kind) = request.credential_kind.as_deref() {
        let kind_pattern = format!(
            "%{}%",
            escape_like_pattern(&normalize_credential_label(credential_kind))
        );
        builder.push(" AND (lower(coalesce(target_kind, '')) = ");
        builder.push_bind(normalize_credential_label(credential_kind));
        builder.push(" OR lower(coalesce(target_name, '')) LIKE ");
        builder.push_bind(kind_pattern);
        builder.push(" ESCAPE '\\'");
        for key in [
            "credentialKind",
            "credential_kind",
            "secretKind",
            "secret_kind",
            "credentialScope",
            "credential_scope",
            "secretScope",
            "secret_scope",
        ] {
            builder.push(" OR lower(coalesce(attributes ->> ");
            builder.push_bind(key);
            builder.push(", '')) = ");
            builder.push_bind(normalize_credential_label(credential_kind));
        }
        builder.push(")");
    }

    builder.push(
        r#" AND (
            endpoint_agent_id IS NOT NULL
            OR runtime_agent_id IS NOT NULL
            OR principal_id IS NOT NULL
            OR attributes ? 'agentId'
            OR attributes ? 'agent_id'
            OR attributes ? 'runtimeAgentId'
            OR attributes ? 'runtime_agent_id'
            OR attributes ? 'tool'
            OR attributes ? 'toolName'
            OR attributes ? 'tool_name'
        )"#,
    );
    builder.push(
        r#" AND (
            lower(coalesce(action_type, '')) IN ('secret_access', 'credential_access', 'secret', 'credential')
            OR lower(coalesce(target_kind, '')) IN (
                'secret',
                'credential',
                'api_key',
                'api_token',
                'cloud_credential',
                'ssh_key',
                'signing_key',
                'browser_cookie',
                'package_registry_token',
                'token',
                'private_key'
            )
            OR lower(coalesce(summary, '')) LIKE ANY("#,
    );
    builder.push_bind(secret_touch_like_patterns());
    builder.push(")");
    builder.push(" OR lower(coalesce(target_name, '')) LIKE ANY(");
    builder.push_bind(secret_touch_like_patterns());
    builder.push(")");
    builder.push(" OR EXISTS (SELECT 1 FROM unnest(detection_ids) AS detection_id WHERE lower(detection_id) LIKE ANY(");
    builder.push_bind(secret_touch_like_patterns());
    builder.push("))");
    builder.push(
        r#" OR attributes ? 'credentialKind'
            OR attributes ? 'credential_kind'
            OR attributes ? 'credentialName'
            OR attributes ? 'credential_name'
            OR attributes ? 'secretKind'
            OR attributes ? 'secret_kind'
            OR attributes ? 'secretName'
            OR attributes ? 'secret_name'
        )"#,
    );
}

fn apply_filters<'a>(
    builder: &mut QueryBuilder<'a, Postgres>,
    tenant_id: Uuid,
    request: &'a HuntQueryRequest,
    include_cursor: bool,
    ascending: bool,
) {
    builder.push(" WHERE tenant_id = ");
    builder.push_bind(tenant_id);

    if let Some(sources) = request
        .sources
        .as_ref()
        .filter(|sources| !sources.is_empty())
    {
        let source_values = sources
            .iter()
            .map(|source| match source {
                EventSource::Tetragon => "tetragon",
                EventSource::Hubble => "hubble",
                EventSource::Receipt => "receipt",
                EventSource::Scan => "scan",
                EventSource::Response => "response",
                EventSource::Directory => "directory",
                EventSource::Detection => "detection",
            })
            .collect::<Vec<_>>();
        builder.push(" AND source = ANY(");
        builder.push_bind(source_values);
        builder.push(")");
    }
    if let Some(verdict) = request.verdict {
        builder.push(" AND verdict = ");
        builder.push_bind(match verdict {
            QueryVerdict::Allow => "allow",
            QueryVerdict::Deny => "deny",
            QueryVerdict::Warn => "warn",
            QueryVerdict::Forwarded => "forwarded",
            QueryVerdict::Dropped => "dropped",
        });
    }
    if let Some(start) = request.start {
        builder.push(" AND timestamp >= ");
        builder.push_bind(start);
    }
    if let Some(end) = request.end {
        builder.push(" AND timestamp <= ");
        builder.push_bind(end);
    }
    if let Some(action_type) = request.action_type.as_deref() {
        builder.push(" AND lower(action_type) = lower(");
        builder.push_bind(action_type);
        builder.push(")");
    }
    if let Some(process) = request.process.as_deref() {
        builder.push(" AND lower(coalesce(process, '')) LIKE ");
        builder.push_bind(format!(
            "%{}%",
            escape_like_pattern(&process.to_lowercase())
        ));
        builder.push(" ESCAPE '\\'");
    }
    if let Some(namespace) = request.namespace.as_deref() {
        builder.push(" AND lower(coalesce(namespace, '')) = lower(");
        builder.push_bind(namespace);
        builder.push(")");
    }
    if let Some(pod) = request.pod.as_deref() {
        builder.push(" AND lower(coalesce(pod, '')) LIKE ");
        builder.push_bind(format!("%{}%", escape_like_pattern(&pod.to_lowercase())));
        builder.push(" ESCAPE '\\'");
    }
    if let Some(entity) = request.entity.as_deref() {
        let entity_pattern = format!("%{}%", escape_like_pattern(&entity.to_lowercase()));
        builder.push(" AND (");
        builder.push(" lower(coalesce(pod, '')) LIKE ");
        builder.push_bind(entity_pattern.clone());
        builder.push(" ESCAPE '\\'");
        builder.push(" OR lower(coalesce(namespace, '')) LIKE ");
        builder.push_bind(entity_pattern);
        builder.push(" ESCAPE '\\'");
        builder.push(" )");
    }
    if let Some(principal_id) = request.principal_id.as_deref() {
        builder.push(" AND principal_id = ");
        builder.push_bind(principal_id);
    }
    if let Some(session_id) = request.session_id.as_deref() {
        builder.push(" AND session_id = ");
        builder.push_bind(session_id);
    }
    if let Some(endpoint_agent_id) = request.endpoint_agent_id.as_deref() {
        builder.push(" AND endpoint_agent_id = ");
        builder.push_bind(endpoint_agent_id);
    }
    if let Some(runtime_agent_id) = request.runtime_agent_id.as_deref() {
        builder.push(" AND runtime_agent_id = ");
        builder.push_bind(runtime_agent_id);
    }
    if include_cursor {
        if let Some(cursor) = request
            .cursor
            .as_deref()
            .and_then(StoredSearchCursor::decode)
        {
            builder.push(" AND (timestamp, event_id) ");
            builder.push(if ascending { ">" } else { "<" });
            builder.push(" (");
            builder.push_bind(cursor.timestamp);
            builder.push(", ");
            builder.push_bind(cursor.event_id);
            builder.push(")");
        }
    }
}

fn grouped_by(request: &HuntQueryRequest) -> Option<TimelineGroupedBy> {
    if request.principal_id.is_some() {
        Some(TimelineGroupedBy::Principal)
    } else if request.session_id.is_some() {
        Some(TimelineGroupedBy::Session)
    } else if request.endpoint_agent_id.is_some() {
        Some(TimelineGroupedBy::Endpoint)
    } else if request.runtime_agent_id.is_some() {
        Some(TimelineGroupedBy::Runtime)
    } else {
        None
    }
}

fn escape_like_pattern(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn secret_touch_like_patterns() -> Vec<String> {
    [
        "%secret%",
        "%credential%",
        "%api key%",
        "%api_key%",
        "%api token%",
        "%api_token%",
        "%token%",
        "%ssh key%",
        "%ssh_key%",
        "%private key%",
        "%private_key%",
        "%signing key%",
        "%signing_key%",
        "%browser cookie%",
        "%browser_cookie%",
        "%cloud credential%",
        "%cloud_credential%",
        "%package registry%",
        "%package_registry%",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

fn build_agent_secret_touch_response(events: Vec<HuntEvent>) -> AgentSecretTouchesResponse {
    let mut endpoint_ids = BTreeSet::new();
    let mut runtime_agent_ids = BTreeSet::new();
    let mut principal_ids = BTreeSet::new();
    let mut groups = BTreeMap::<String, EndpointAccumulator>::new();

    for event in &events {
        if let Some(endpoint_agent_id) = event.endpoint_agent_id.as_ref() {
            endpoint_ids.insert(endpoint_agent_id.clone());
        }
        if let Some(runtime_agent_id) = event.runtime_agent_id.as_ref() {
            runtime_agent_ids.insert(runtime_agent_id.clone());
        }
        if let Some(principal_id) = event.principal_id.as_ref() {
            principal_ids.insert(principal_id.clone());
        }

        let group_key = agent_secret_touch_group_key(event);
        let credential_kind = credential_kind_for_event(event);
        groups
            .entry(group_key.clone())
            .or_insert_with(|| EndpointAccumulator::new(group_key, event))
            .record(event, credential_kind);
    }

    let mut endpoints = groups
        .into_values()
        .map(EndpointAccumulator::into_summary)
        .collect::<Vec<_>>();
    endpoints.sort_by(|left, right| {
        right
            .last_seen
            .cmp(&left.last_seen)
            .then_with(|| left.group_key.cmp(&right.group_key))
    });

    AgentSecretTouchesResponse {
        secret_touch_count: events.len(),
        endpoint_count: endpoint_ids.len(),
        runtime_agent_count: runtime_agent_ids.len(),
        principal_count: principal_ids.len(),
        events,
        endpoints,
    }
}

struct EndpointAccumulator {
    group_key: String,
    endpoint_agent_id: Option<String>,
    event_count: usize,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    runtime_agent_ids: BTreeSet<String>,
    principal_ids: BTreeSet<String>,
    session_ids: BTreeSet<String>,
    credential_kinds: BTreeSet<String>,
    event_ids: Vec<String>,
}

impl EndpointAccumulator {
    fn new(group_key: String, event: &HuntEvent) -> Self {
        Self {
            group_key,
            endpoint_agent_id: event.endpoint_agent_id.clone(),
            event_count: 0,
            first_seen: event.timestamp,
            last_seen: event.timestamp,
            runtime_agent_ids: BTreeSet::new(),
            principal_ids: BTreeSet::new(),
            session_ids: BTreeSet::new(),
            credential_kinds: BTreeSet::new(),
            event_ids: Vec::new(),
        }
    }

    fn record(&mut self, event: &HuntEvent, credential_kind: String) {
        self.event_count += 1;
        self.first_seen = self.first_seen.min(event.timestamp);
        self.last_seen = self.last_seen.max(event.timestamp);
        push_optional_set(&mut self.runtime_agent_ids, event.runtime_agent_id.as_ref());
        push_optional_set(&mut self.principal_ids, event.principal_id.as_ref());
        push_optional_set(&mut self.session_ids, event.session_id.as_ref());
        self.credential_kinds.insert(credential_kind);
        self.event_ids.push(event.event_id.clone());
    }

    fn into_summary(self) -> AgentSecretTouchEndpointSummary {
        AgentSecretTouchEndpointSummary {
            group_key: self.group_key,
            endpoint_agent_id: self.endpoint_agent_id,
            event_count: self.event_count,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            runtime_agent_ids: self.runtime_agent_ids.into_iter().collect(),
            principal_ids: self.principal_ids.into_iter().collect(),
            session_ids: self.session_ids.into_iter().collect(),
            credential_kinds: self.credential_kinds.into_iter().collect(),
            event_ids: self.event_ids,
        }
    }
}

fn push_optional_set(set: &mut BTreeSet<String>, value: Option<&String>) {
    if let Some(value) = value {
        set.insert(value.clone());
    }
}

fn agent_secret_touch_group_key(event: &HuntEvent) -> String {
    event.endpoint_agent_id.clone().unwrap_or_else(|| {
        event.runtime_agent_id.clone().unwrap_or_else(|| {
            event
                .principal_id
                .clone()
                .unwrap_or_else(|| "unattributed-agent".to_string())
        })
    })
}

fn event_matches_agent_secret_touch(event: &HuntEvent) -> bool {
    event_has_agent_identity(event) && event_has_secret_touch_marker(event)
}

fn event_has_agent_identity(event: &HuntEvent) -> bool {
    event.endpoint_agent_id.is_some()
        || event.runtime_agent_id.is_some()
        || event.principal_id.is_some()
        || string_attribute(event, "agentId").is_some()
        || string_attribute(event, "agent_id").is_some()
        || string_attribute(event, "runtimeAgentId").is_some()
        || string_attribute(event, "runtime_agent_id").is_some()
        || string_attribute(event, "tool").is_some()
        || string_attribute(event, "toolName").is_some()
        || string_attribute(event, "tool_name").is_some()
}

fn event_has_secret_touch_marker(event: &HuntEvent) -> bool {
    event
        .action_type
        .as_deref()
        .map(is_secret_touch_text)
        .unwrap_or(false)
        || event
            .target_kind
            .as_deref()
            .map(is_secret_touch_text)
            .unwrap_or(false)
        || event
            .target_name
            .as_deref()
            .map(is_secret_touch_text)
            .unwrap_or(false)
        || is_secret_touch_text(&event.summary)
        || event
            .detection_ids
            .iter()
            .any(|detection_id| is_secret_touch_text(detection_id))
        || [
            "credentialKind",
            "credential_kind",
            "credentialName",
            "credential_name",
            "secretKind",
            "secret_kind",
            "secretName",
            "secret_name",
            "credentialScope",
            "credential_scope",
            "secretScope",
            "secret_scope",
        ]
        .iter()
        .any(|key| string_attribute(event, key).is_some())
}

fn credential_kind_for_event(event: &HuntEvent) -> String {
    for key in [
        "credentialKind",
        "credential_kind",
        "secretKind",
        "secret_kind",
        "credentialScope",
        "credential_scope",
        "secretScope",
        "secret_scope",
    ] {
        if let Some(value) = string_attribute(event, key) {
            return normalize_credential_label(value);
        }
    }
    for value in [
        event.target_kind.as_deref(),
        event.target_name.as_deref(),
        event.action_type.as_deref(),
        Some(event.summary.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if is_secret_touch_text(value) {
            return normalize_credential_label(value);
        }
    }
    for detection_id in &event.detection_ids {
        if is_secret_touch_text(detection_id) {
            return normalize_credential_label(detection_id);
        }
    }
    "secret".to_string()
}

fn string_attribute<'a>(event: &'a HuntEvent, key: &str) -> Option<&'a str> {
    event.attributes.get(key).and_then(Value::as_str)
}

fn is_secret_touch_text(value: &str) -> bool {
    let normalized = normalize_credential_label(value);
    matches!(
        normalized.as_str(),
        "secret"
            | "credential"
            | "api_key"
            | "api_token"
            | "token"
            | "ssh_key"
            | "private_key"
            | "signing_key"
            | "browser_cookie"
            | "cloud_credential"
            | "package_registry_token"
    ) || normalized.contains("secret")
        || normalized.contains("credential")
        || normalized.contains("token")
}

fn normalize_credential_label(value: &str) -> String {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    let normalized = normalized
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_");

    if normalized.contains("browser") && normalized.contains("cookie") {
        "browser_cookie".to_string()
    } else if (normalized.contains("package") || normalized.contains("registry"))
        && normalized.contains("token")
    {
        "package_registry_token".to_string()
    } else if normalized.contains("api") && normalized.contains("key") {
        "api_key".to_string()
    } else if normalized.contains("api") && normalized.contains("token") {
        "api_token".to_string()
    } else if normalized.contains("ssh") {
        "ssh_key".to_string()
    } else if normalized.contains("private") && normalized.contains("key") {
        "private_key".to_string()
    } else if normalized.contains("signing") || normalized.contains("codesign") {
        "signing_key".to_string()
    } else if normalized.contains("cloud")
        || normalized.contains("aws")
        || normalized.contains("gcp")
        || normalized.contains("azure")
    {
        "cloud_credential".to_string()
    } else if normalized.contains("credential") {
        "credential".to_string()
    } else if normalized.contains("secret") {
        "secret".to_string()
    } else if normalized.contains("token") {
        "token".to_string()
    } else {
        normalized
    }
}

fn trusted_hunt_issuer(signing_keypair: Option<&hush_core::Keypair>) -> Result<String, ApiError> {
    let keypair = signing_keypair.ok_or_else(|| {
        ApiError::Internal("hunt ingest requires a configured signing keypair".to_string())
    })?;
    let probe = spine::build_signed_envelope(
        keypair,
        0,
        None,
        serde_json::json!({ "probe": true }),
        spine::now_rfc3339(),
    )
    .map_err(|err| ApiError::Internal(format!("failed to derive trusted hunt issuer: {err}")))?;
    probe
        .get("issuer")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ApiError::Internal("signed hunt envelope is missing an issuer".to_string()))
}

fn verify_signed_hunt_envelope(
    raw_envelope: &Value,
    trusted_issuer: &str,
) -> Result<(FleetEventEnvelope, String), ApiError> {
    if !spine::verify_envelope(raw_envelope)
        .map_err(|err| ApiError::BadRequest(format!("rawEnvelope verification failed: {err}")))?
    {
        return Err(ApiError::BadRequest(
            "rawEnvelope signature verification failed".to_string(),
        ));
    }

    let issuer = raw_envelope
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::BadRequest("rawEnvelope is missing issuer".to_string()))?;
    if issuer != trusted_issuer {
        return Err(ApiError::Forbidden);
    }

    let fact = raw_envelope
        .get("fact")
        .cloned()
        .ok_or_else(|| ApiError::BadRequest("rawEnvelope is missing fact".to_string()))?;
    let event: FleetEventEnvelope = serde_json::from_value(fact)
        .map_err(|err| ApiError::BadRequest(format!("rawEnvelope fact is invalid: {err}")))?;
    Ok((event, issuer.to_string()))
}

fn map_event_row(row: sqlx_postgres::PgRow) -> Result<HuntEvent, ApiError> {
    let source: String = row.try_get("source").map_err(ApiError::Database)?;
    let kind: String = row.try_get("kind").map_err(ApiError::Database)?;
    let verdict: String = row.try_get("verdict").map_err(ApiError::Database)?;

    Ok(HuntEvent {
        event_id: row.try_get("event_id").map_err(ApiError::Database)?,
        tenant_id: row.try_get("tenant_id").map_err(ApiError::Database)?,
        source: HuntEventSource::parse(&source)
            .ok_or_else(|| ApiError::Internal(format!("unsupported hunt source: {source}")))?,
        kind: HuntEventKind::parse(&kind)
            .ok_or_else(|| ApiError::Internal(format!("unsupported hunt kind: {kind}")))?,
        timestamp: row.try_get("timestamp").map_err(ApiError::Database)?,
        verdict: NormalizedVerdict::parse(&verdict)
            .ok_or_else(|| ApiError::Internal(format!("unsupported verdict: {verdict}")))?,
        severity: row.try_get("severity").map_err(ApiError::Database)?,
        summary: row.try_get("summary").map_err(ApiError::Database)?,
        action_type: row.try_get("action_type").map_err(ApiError::Database)?,
        process: row.try_get("process").map_err(ApiError::Database)?,
        namespace: row.try_get("namespace").map_err(ApiError::Database)?,
        pod: row.try_get("pod").map_err(ApiError::Database)?,
        session_id: row.try_get("session_id").map_err(ApiError::Database)?,
        endpoint_agent_id: row
            .try_get("endpoint_agent_id")
            .map_err(ApiError::Database)?,
        runtime_agent_id: row
            .try_get("runtime_agent_id")
            .map_err(ApiError::Database)?,
        principal_id: row.try_get("principal_id").map_err(ApiError::Database)?,
        grant_id: row.try_get("grant_id").map_err(ApiError::Database)?,
        response_action_id: row
            .try_get("response_action_id")
            .map_err(ApiError::Database)?,
        detection_ids: row.try_get("detection_ids").map_err(ApiError::Database)?,
        target_kind: row.try_get("target_kind").map_err(ApiError::Database)?,
        target_id: row.try_get("target_id").map_err(ApiError::Database)?,
        target_name: row.try_get("target_name").map_err(ApiError::Database)?,
        envelope_hash: row.try_get("envelope_hash").map_err(ApiError::Database)?,
        issuer: row.try_get("issuer").map_err(ApiError::Database)?,
        schema_name: row.try_get("schema_name").map_err(ApiError::Database)?,
        signature_valid: row.try_get("signature_valid").map_err(ApiError::Database)?,
        raw_ref: row.try_get("raw_ref").map_err(ApiError::Database)?,
        attributes: row.try_get("attributes").map_err(ApiError::Database)?,
    })
}

fn map_saved_hunt_row(row: sqlx_postgres::PgRow) -> Result<SavedHuntRecord, ApiError> {
    let query: Value = row.try_get("query").map_err(ApiError::Database)?;
    Ok(SavedHuntRecord {
        id: row.try_get("id").map_err(ApiError::Database)?,
        tenant_id: row.try_get("tenant_id").map_err(ApiError::Database)?,
        name: row.try_get("name").map_err(ApiError::Database)?,
        description: row.try_get("description").map_err(ApiError::Database)?,
        query: serde_json::from_value(query).map_err(|e| ApiError::Internal(e.to_string()))?,
        created_by: row.try_get("created_by").map_err(ApiError::Database)?,
        created_at: row.try_get("created_at").map_err(ApiError::Database)?,
        updated_at: row.try_get("updated_at").map_err(ApiError::Database)?,
    })
}

fn map_job_row(row: sqlx_postgres::PgRow) -> Result<HuntJobRecord, ApiError> {
    Ok(HuntJobRecord {
        id: row.try_get("id").map_err(ApiError::Database)?,
        tenant_id: row.try_get("tenant_id").map_err(ApiError::Database)?,
        job_type: row.try_get("job_type").map_err(ApiError::Database)?,
        status: row.try_get("status").map_err(ApiError::Database)?,
        request: row.try_get("request").map_err(ApiError::Database)?,
        result: row.try_get("result").map_err(ApiError::Database)?,
        created_by: row.try_get("created_by").map_err(ApiError::Database)?,
        created_at: row.try_get("created_at").map_err(ApiError::Database)?,
        completed_at: row.try_get("completed_at").map_err(ApiError::Database)?,
    })
}

fn fleet_source_to_str(source: FleetEventSource) -> &'static str {
    match source {
        FleetEventSource::Receipt => "receipt",
        FleetEventSource::Tetragon => "tetragon",
        FleetEventSource::Hubble => "hubble",
        FleetEventSource::Scan => "scan",
        FleetEventSource::Response => "response",
        FleetEventSource::Directory => "directory",
        FleetEventSource::Detection => "detection",
    }
}

fn fleet_kind_to_str(kind: FleetEventKind) -> &'static str {
    match kind {
        FleetEventKind::GuardDecision => "guard_decision",
        FleetEventKind::ProcessExec => "process_exec",
        FleetEventKind::ProcessExit => "process_exit",
        FleetEventKind::ProcessKprobe => "process_kprobe",
        FleetEventKind::NetworkFlow => "network_flow",
        FleetEventKind::ScanResult => "scan_result",
        FleetEventKind::JoinCompleted => "join_completed",
        FleetEventKind::PrincipalStateChanged => "principal_state_changed",
        FleetEventKind::ResponseActionCreated => "response_action_created",
        FleetEventKind::ResponseActionUpdated => "response_action_updated",
        FleetEventKind::DetectionFired => "detection_fired",
    }
}

fn fleet_verdict_to_str(verdict: Option<FleetEventVerdict>) -> Option<&'static str> {
    verdict.map(|verdict| match verdict {
        FleetEventVerdict::Allow => "allow",
        FleetEventVerdict::Deny => "deny",
        FleetEventVerdict::Warn => "warn",
        FleetEventVerdict::None => "none",
        FleetEventVerdict::Forwarded => "forwarded",
        FleetEventVerdict::Dropped => "dropped",
    })
}

fn fleet_severity_to_str(severity: FleetEventSeverity) -> &'static str {
    match severity {
        FleetEventSeverity::Info => "info",
        FleetEventSeverity::Low => "low",
        FleetEventSeverity::Medium => "medium",
        FleetEventSeverity::High => "high",
        FleetEventSeverity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sha256_hex_for_test(value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        format!("0x{}", hex::encode(hasher.finalize()))
    }

    struct TestEventSpec {
        event_id: &'static str,
        timestamp_minute: u32,
        endpoint_agent_id: Option<&'static str>,
        runtime_agent_id: Option<&'static str>,
        principal_id: Option<&'static str>,
        target_kind: Option<&'static str>,
        target_name: Option<&'static str>,
        attributes: Value,
    }

    fn test_event(spec: TestEventSpec) -> HuntEvent {
        HuntEvent {
            event_id: spec.event_id.to_string(),
            tenant_id: Uuid::nil(),
            source: HuntEventSource::Receipt,
            kind: HuntEventKind::GuardDecision,
            timestamp: Utc
                .with_ymd_and_hms(2026, 3, 6, 12, spec.timestamp_minute, 0)
                .unwrap(),
            verdict: NormalizedVerdict::Warn,
            severity: Some("high".to_string()),
            summary: "AI agent accessed developer credential".to_string(),
            action_type: Some("secret_access".to_string()),
            process: None,
            namespace: None,
            pod: None,
            session_id: Some("session-1".to_string()),
            endpoint_agent_id: spec.endpoint_agent_id.map(ToOwned::to_owned),
            runtime_agent_id: spec.runtime_agent_id.map(ToOwned::to_owned),
            principal_id: spec.principal_id.map(ToOwned::to_owned),
            grant_id: None,
            response_action_id: None,
            detection_ids: Vec::new(),
            target_kind: spec.target_kind.map(ToOwned::to_owned),
            target_id: None,
            target_name: spec.target_name.map(ToOwned::to_owned),
            envelope_hash: Some(format!("hash-{}", spec.event_id)),
            issuer: Some("spiffe://tenant/acme".to_string()),
            schema_name: Some("clawdstrike.sdr.fact.receipt.v1".to_string()),
            signature_valid: Some(true),
            raw_ref: format!("hunt-envelope:{}", spec.event_id),
            attributes: spec.attributes,
        }
    }

    #[test]
    fn agent_secret_touch_classifier_requires_agent_identity_and_secret_marker() {
        let secret_touch = test_event(TestEventSpec {
            event_id: "evt-secret",
            timestamp_minute: 0,
            endpoint_agent_id: Some("endpoint-1"),
            runtime_agent_id: Some("runtime-1"),
            principal_id: Some("principal-1"),
            target_kind: Some("credential"),
            target_name: Some("OPENAI_API_KEY"),
            attributes: serde_json::json!({"credentialKind": "API token"}),
        });
        assert!(event_matches_agent_secret_touch(&secret_touch));
        assert_eq!(credential_kind_for_event(&secret_touch), "api_token");

        let no_agent = HuntEvent {
            endpoint_agent_id: None,
            runtime_agent_id: None,
            principal_id: None,
            attributes: serde_json::json!({"credentialKind": "ssh_key"}),
            ..secret_touch.clone()
        };
        assert!(!event_matches_agent_secret_touch(&no_agent));

        let no_secret = HuntEvent {
            summary: "ordinary process execution".to_string(),
            action_type: Some("process".to_string()),
            target_kind: Some("process".to_string()),
            target_name: Some("curl".to_string()),
            attributes: serde_json::json!({"process": "/usr/bin/curl"}),
            ..secret_touch
        };
        assert!(!event_matches_agent_secret_touch(&no_secret));
    }

    #[test]
    fn agent_secret_touch_response_groups_by_endpoint_then_runtime() {
        let endpoint_first = test_event(TestEventSpec {
            event_id: "evt-endpoint-1",
            timestamp_minute: 0,
            endpoint_agent_id: Some("endpoint-1"),
            runtime_agent_id: Some("runtime-1"),
            principal_id: Some("principal-1"),
            target_kind: Some("credential"),
            target_name: Some("OPENAI_API_KEY"),
            attributes: serde_json::json!({"credentialKind": "api_token"}),
        });
        let endpoint_second = test_event(TestEventSpec {
            event_id: "evt-endpoint-2",
            timestamp_minute: 5,
            endpoint_agent_id: Some("endpoint-1"),
            runtime_agent_id: Some("runtime-2"),
            principal_id: Some("principal-1"),
            target_kind: Some("credential"),
            target_name: Some("id_rsa"),
            attributes: serde_json::json!({"credentialKind": "ssh_key"}),
        });
        let runtime_only = test_event(TestEventSpec {
            event_id: "evt-runtime-1",
            timestamp_minute: 6,
            endpoint_agent_id: None,
            runtime_agent_id: Some("runtime-3"),
            principal_id: Some("principal-2"),
            target_kind: Some("secret"),
            target_name: Some("cloud credential"),
            attributes: serde_json::json!({"secretKind": "aws credential"}),
        });

        let response =
            build_agent_secret_touch_response(vec![endpoint_first, endpoint_second, runtime_only]);

        assert_eq!(response.secret_touch_count, 3);
        assert_eq!(response.endpoint_count, 1);
        assert_eq!(response.runtime_agent_count, 3);
        assert_eq!(response.principal_count, 2);
        assert_eq!(response.endpoints.len(), 2);
        assert_eq!(response.endpoints[0].group_key, "runtime-3");
        assert_eq!(
            response.endpoints[0].credential_kinds,
            vec!["cloud_credential"]
        );
        assert_eq!(response.endpoints[1].group_key, "endpoint-1");
        assert_eq!(
            response.endpoints[1].credential_kinds,
            vec!["api_token", "ssh_key"]
        );
        assert_eq!(response.endpoints[1].event_count, 2);
    }

    #[test]
    fn endpoint_archive_upload_validates_hash_raw_ref_and_retention() {
        let archive = serde_json::json!({
            "schemaVersion": 1,
            "bundle": {
                "bundleId": "evidence_bundle-valid",
                "graphSliceId": "graph_slice-valid",
                "contentHash": "0xcontent"
            },
            "artifact": {
                "byteCount": 42
            },
            "graph": {
                "nodes": {},
                "edges": []
            },
            "receipts": []
        });
        let archive_hash = endpoint_archive_hash(&archive).expect("archive hash should compute");
        let request = EndpointEvidenceArchiveUploadRequest {
            archive_id: "evidence_bundle_archive-valid".to_string(),
            archive_hash: archive_hash.clone(),
            raw_ref: format!(
                "endpoint-evidence-bundle-archive:evidence_bundle_archive-valid:{archive_hash}"
            ),
            bundle_id: "evidence_bundle-valid".to_string(),
            endpoint_agent_id: Some("endpoint-agent-1".to_string()),
            event_id: Some(
                "evidence-bundle-archive:endpoint-agent-1:evidence_bundle_archive-valid"
                    .to_string(),
            ),
            raw_artifact_approval_id: Some("approval-archive-valid".to_string()),
            raw_artifact_approval_reason_hash: Some(sha256_hex_for_test(
                "incident archive upload approved",
            )),
            archive,
            verification: serde_json::json!({
                "verified": true,
                "archiveHashMatches": true
            }),
            retention_days: Some(90),
            metadata: serde_json::json!({"source": "agent"}),
        };

        let prepared = validate_endpoint_evidence_archive_upload(
            Uuid::nil(),
            request,
            30,
            Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
        )
        .expect("valid archive upload should be prepared");

        let record = prepared.record;
        assert_eq!(record.archive_id, "evidence_bundle_archive-valid");
        assert_eq!(record.archive_hash, archive_hash);
        assert_eq!(
            record.raw_ref,
            format!(
                "endpoint-evidence-bundle-archive:evidence_bundle_archive-valid:{}",
                record.archive_hash
            )
        );
        assert_eq!(record.bundle_id, "evidence_bundle-valid");
        assert_eq!(record.graph_slice_id.as_deref(), Some("graph_slice-valid"));
        assert_eq!(record.content_hash.as_deref(), Some("0xcontent"));
        assert_eq!(
            record.raw_artifact_approval_id.as_deref(),
            Some("approval-archive-valid")
        );
        assert!(record
            .raw_artifact_approval_reason_hash
            .as_deref()
            .is_some_and(|hash| hash.starts_with("0x")));
        assert_eq!(
            record.metadata["rawArtifactApprovalId"],
            "approval-archive-valid"
        );
        assert_eq!(
            record.endpoint_agent_id.as_deref(),
            Some("endpoint-agent-1")
        );
        assert_eq!(record.retention_days, 30);
        assert!(record.expires_at > record.uploaded_at);
        assert!(record.size_bytes > 0);
        assert_eq!(
            prepared.archive["bundle"]["bundleId"],
            "evidence_bundle-valid"
        );
    }

    #[test]
    fn endpoint_archive_upload_rejects_hash_and_raw_ref_mismatch() {
        let archive = serde_json::json!({
            "bundle": {
                "bundleId": "evidence_bundle-mismatch"
            },
            "receipts": []
        });

        let hash_error = validate_endpoint_evidence_archive_upload(
            Uuid::nil(),
            EndpointEvidenceArchiveUploadRequest {
                archive_id: "evidence_bundle_archive-mismatch".to_string(),
                archive_hash: "0xdeadbeef".to_string(),
                raw_ref:
                    "endpoint-evidence-bundle-archive:evidence_bundle_archive-mismatch:0xdeadbeef"
                        .to_string(),
                bundle_id: "evidence_bundle-mismatch".to_string(),
                endpoint_agent_id: None,
                event_id: None,
                raw_artifact_approval_id: Some("approval-archive-mismatch".to_string()),
                raw_artifact_approval_reason_hash: Some(sha256_hex_for_test(
                    "incident archive mismatch approved",
                )),
                archive: archive.clone(),
                verification: serde_json::json!({"verified": true}),
                retention_days: Some(7),
                metadata: serde_json::json!({}),
            },
            30,
            Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
        )
        .expect_err("wrong archive hash should be rejected");
        assert!(matches!(
            hash_error,
            ApiError::BadRequest(message) if message.contains("archiveHash does not match")
        ));

        let archive_hash = endpoint_archive_hash(&archive).expect("archive hash should compute");
        let raw_ref_error = validate_endpoint_evidence_archive_upload(
            Uuid::nil(),
            EndpointEvidenceArchiveUploadRequest {
                archive_id: "evidence_bundle_archive-mismatch".to_string(),
                archive_hash,
                raw_ref: "endpoint-evidence-bundle-archive:other:0xwrong".to_string(),
                bundle_id: "evidence_bundle-mismatch".to_string(),
                endpoint_agent_id: None,
                event_id: None,
                raw_artifact_approval_id: Some("approval-archive-mismatch".to_string()),
                raw_artifact_approval_reason_hash: Some(sha256_hex_for_test(
                    "incident archive mismatch approved",
                )),
                archive,
                verification: serde_json::json!({"verified": true}),
                retention_days: Some(7),
                metadata: serde_json::json!({}),
            },
            30,
            Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
        )
        .expect_err("wrong rawRef should be rejected");
        assert!(matches!(
            raw_ref_error,
            ApiError::BadRequest(message) if message.contains("rawRef must be")
        ));
    }

    #[test]
    fn endpoint_archive_upload_requires_raw_artifact_approval_evidence() {
        let archive = serde_json::json!({
            "bundle": {
                "bundleId": "evidence_bundle-approval-required"
            },
            "receipts": []
        });
        let archive_hash = endpoint_archive_hash(&archive).expect("archive hash should compute");
        let missing_approval = validate_endpoint_evidence_archive_upload(
            Uuid::nil(),
            EndpointEvidenceArchiveUploadRequest {
                archive_id: "evidence_bundle_archive-approval-required".to_string(),
                archive_hash: archive_hash.clone(),
                raw_ref: format!(
                    "endpoint-evidence-bundle-archive:evidence_bundle_archive-approval-required:{archive_hash}"
                ),
                bundle_id: "evidence_bundle-approval-required".to_string(),
                endpoint_agent_id: None,
                event_id: None,
                raw_artifact_approval_id: None,
                raw_artifact_approval_reason_hash: Some(sha256_hex_for_test(
                    "incident archive approval required",
                )),
                archive: archive.clone(),
                verification: serde_json::json!({"verified": true}),
                retention_days: Some(7),
                metadata: serde_json::json!({}),
            },
            30,
            Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
        )
        .expect_err("missing raw artifact approval id should be rejected");
        assert!(matches!(
            missing_approval,
            ApiError::BadRequest(message) if message.contains("rawArtifactApprovalId")
        ));

        let malformed_approval_hash = validate_endpoint_evidence_archive_upload(
            Uuid::nil(),
            EndpointEvidenceArchiveUploadRequest {
                archive_id: "evidence_bundle_archive-approval-required".to_string(),
                archive_hash: archive_hash.clone(),
                raw_ref: format!(
                    "endpoint-evidence-bundle-archive:evidence_bundle_archive-approval-required:{archive_hash}"
                ),
                bundle_id: "evidence_bundle-approval-required".to_string(),
                endpoint_agent_id: None,
                event_id: None,
                raw_artifact_approval_id: Some("approval-archive-required".to_string()),
                raw_artifact_approval_reason_hash: Some("not-a-hash".to_string()),
                archive,
                verification: serde_json::json!({"verified": true}),
                retention_days: Some(7),
                metadata: serde_json::json!({}),
            },
            30,
            Utc.with_ymd_and_hms(2026, 5, 16, 12, 0, 0).unwrap(),
        )
        .expect_err("malformed raw artifact approval reason hash should be rejected");
        assert!(matches!(
            malformed_approval_hash,
            ApiError::BadRequest(message) if message.contains("rawArtifactApprovalReasonHash")
        ));
    }
}
