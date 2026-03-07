use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use hush_certification::evidence::{
    build_signed_evidence_bundle_zip, GenericEvidenceBundleEntry, GenericEvidenceBundleSubject,
};
use serde_json::{json, Value};
use sqlx::row::Row;
use sqlx::transaction::Transaction;
use uuid::Uuid;

use crate::db::PgPool;
use crate::error::ApiError;
#[cfg(test)]
use crate::integration_tests::case_evidence::{
    AddCaseArtifactRequest, CaseArtifactRef, CaseTimelineEvent, CreateFleetCaseRequest,
    ExportEvidenceBundleRequest, FleetCase, FleetCaseDetail, FleetEvidenceBundle,
    UpdateFleetCaseRequest,
};
#[cfg(not(test))]
use crate::models::case_evidence::{
    AddCaseArtifactRequest, CaseArtifactRef, CaseTimelineEvent, CreateFleetCaseRequest,
    ExportEvidenceBundleRequest, FleetCase, FleetCaseDetail, FleetEvidenceBundle,
    UpdateFleetCaseRequest,
};

const VALID_SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];
const VALID_STATUSES: &[&str] = &["open", "in_progress", "contained", "closed"];
const VALID_ARTIFACT_KINDS: &[&str] = &[
    "fleet_event",
    "raw_envelope",
    "saved_hunt",
    "hunt_job",
    "detection",
    "response_action",
    "grant",
    "graph_snapshot",
    "note",
    "bundle_export",
];

struct PreparedCaseArtifact {
    artifact_kind: String,
    artifact_id: String,
    summary: Option<String>,
    metadata: Value,
}

pub async fn list_cases(db: &PgPool, tenant_id: Uuid) -> Result<Vec<FleetCase>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM fleet_cases
           WHERE tenant_id = $1
           ORDER BY updated_at DESC, created_at DESC"#,
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(FleetCase::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)
}

pub async fn create_case(
    db: &PgPool,
    tenant_id: Uuid,
    actor_id: &str,
    req: CreateFleetCaseRequest,
) -> Result<FleetCase, ApiError> {
    validate_severity(&req.severity)?;
    let status = req.status.unwrap_or_else(|| "open".to_string());
    validate_status(&status)?;

    let principal_ids = normalize_strings(req.principal_ids);
    let detection_ids = normalize_strings(req.detection_ids);
    let response_action_ids = normalize_strings(req.response_action_ids);
    let grant_ids = normalize_strings(req.grant_ids);
    let tags = normalize_strings(req.tags);
    let metadata = normalize_metadata(req.metadata)?;

    let mut tx = db.begin().await.map_err(ApiError::Database)?;
    let row = sqlx::query::query(
        r#"INSERT INTO fleet_cases (
               tenant_id,
               title,
               summary,
               severity,
               status,
               created_by,
               principal_ids,
               detection_ids,
               response_action_ids,
               grant_ids,
               tags,
               metadata
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           RETURNING *"#,
    )
    .bind(tenant_id)
    .bind(req.title.trim())
    .bind(req.summary.as_deref())
    .bind(&req.severity)
    .bind(&status)
    .bind(actor_id)
    .bind(&principal_ids)
    .bind(&detection_ids)
    .bind(&response_action_ids)
    .bind(&grant_ids)
    .bind(&tags)
    .bind(&metadata)
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::Database)?;

    let case = FleetCase::from_row(row).map_err(ApiError::Database)?;
    insert_case_event(
        &mut tx,
        tenant_id,
        case.id,
        "case_created",
        actor_id,
        serde_json::json!({
            "title": case.title,
            "severity": case.severity,
            "status": case.status,
        }),
    )
    .await?;

    tx.commit().await.map_err(ApiError::Database)?;
    Ok(case)
}

pub async fn get_case_detail(
    db: &PgPool,
    tenant_id: Uuid,
    case_id: Uuid,
) -> Result<FleetCaseDetail, ApiError> {
    let case_row = sqlx::query::query("SELECT * FROM fleet_cases WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(case_id)
        .fetch_optional(db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
    let case = FleetCase::from_row(case_row).map_err(ApiError::Database)?;

    let artifact_rows = sqlx::query::query(
        r#"SELECT *
           FROM fleet_case_artifacts
           WHERE tenant_id = $1 AND case_id = $2
           ORDER BY added_at DESC, id DESC"#,
    )
    .bind(tenant_id)
    .bind(case_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;
    let artifacts = artifact_rows
        .into_iter()
        .map(CaseArtifactRef::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;

    let bundle_rows = sqlx::query::query(
        r#"SELECT *
           FROM fleet_evidence_bundles
           WHERE tenant_id = $1 AND case_id = $2
           ORDER BY requested_at DESC, export_id DESC"#,
    )
    .bind(tenant_id)
    .bind(case_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;
    let evidence_bundles = bundle_rows
        .into_iter()
        .map(FleetEvidenceBundle::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;

    Ok(FleetCaseDetail {
        case,
        artifacts,
        evidence_bundles,
    })
}

pub async fn update_case(
    db: &PgPool,
    tenant_id: Uuid,
    case_id: Uuid,
    actor_id: &str,
    req: UpdateFleetCaseRequest,
) -> Result<FleetCase, ApiError> {
    if let Some(severity) = req.severity.as_deref() {
        validate_severity(severity)?;
    }
    if let Some(status) = req.status.as_deref() {
        validate_status(status)?;
    }

    let principal_ids = req.principal_ids.map(normalize_strings);
    let detection_ids = req.detection_ids.map(normalize_strings);
    let response_action_ids = req.response_action_ids.map(normalize_strings);
    let grant_ids = req.grant_ids.map(normalize_strings);
    let tags = req.tags.map(normalize_strings);
    let metadata = req.metadata.map(normalize_metadata).transpose()?;

    let mut tx = db.begin().await.map_err(ApiError::Database)?;

    let before_row =
        sqlx::query::query("SELECT * FROM fleet_cases WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(case_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::Database)?
            .ok_or(ApiError::NotFound)?;
    let before = FleetCase::from_row(before_row).map_err(ApiError::Database)?;

    let row = sqlx::query::query(
        r#"UPDATE fleet_cases
           SET title = COALESCE($3, title),
               summary = COALESCE($4, summary),
               severity = COALESCE($5, severity),
               status = COALESCE($6, status),
               principal_ids = COALESCE($7, principal_ids),
               detection_ids = COALESCE($8, detection_ids),
               response_action_ids = COALESCE($9, response_action_ids),
               grant_ids = COALESCE($10, grant_ids),
               tags = COALESCE($11, tags),
               metadata = COALESCE($12, metadata),
               updated_at = now()
           WHERE tenant_id = $1 AND id = $2
           RETURNING *"#,
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(req.title.as_deref().map(str::trim))
    .bind(req.summary.as_deref())
    .bind(req.severity.as_deref())
    .bind(req.status.as_deref())
    .bind(principal_ids.as_ref())
    .bind(detection_ids.as_ref())
    .bind(response_action_ids.as_ref())
    .bind(grant_ids.as_ref())
    .bind(tags.as_ref())
    .bind(metadata.as_ref())
    .fetch_one(&mut *tx)
    .await
    .map_err(ApiError::Database)?;
    let updated = FleetCase::from_row(row).map_err(ApiError::Database)?;

    let mut payload = serde_json::json!({
        "title": updated.title,
        "severity": updated.severity,
        "status": updated.status,
    });
    if before.status != updated.status {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "previousStatus".to_string(),
                Value::String(before.status.clone()),
            );
        }
        insert_case_event(
            &mut tx,
            tenant_id,
            case_id,
            "status_changed",
            actor_id,
            serde_json::json!({
                "previousStatus": before.status,
                "status": updated.status,
            }),
        )
        .await?;
    }
    insert_case_event(
        &mut tx,
        tenant_id,
        case_id,
        "case_updated",
        actor_id,
        payload,
    )
    .await?;

    tx.commit().await.map_err(ApiError::Database)?;
    Ok(updated)
}

pub async fn add_artifact(
    db: &PgPool,
    tenant_id: Uuid,
    case_id: Uuid,
    actor_id: &str,
    req: AddCaseArtifactRequest,
) -> Result<CaseArtifactRef, ApiError> {
    validate_artifact_kind(&req.artifact_kind)?;
    ensure_case_exists(db, tenant_id, case_id).await?;

    let mut tx = db.begin().await.map_err(ApiError::Database)?;
    let prepared = prepare_case_artifact(&mut tx, tenant_id, req).await?;
    let row = sqlx::query::query(
        r#"INSERT INTO fleet_case_artifacts (
               tenant_id,
               case_id,
               artifact_kind,
               artifact_id,
               summary,
               metadata,
               added_by
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING *"#,
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(&prepared.artifact_kind)
    .bind(&prepared.artifact_id)
    .bind(prepared.summary.as_deref())
    .bind(&prepared.metadata)
    .bind(actor_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_artifact_insert_error)?;
    let artifact = CaseArtifactRef::from_row(row).map_err(ApiError::Database)?;

    insert_case_event(
        &mut tx,
        tenant_id,
        case_id,
        "artifact_added",
        actor_id,
        serde_json::json!({
            "artifactKind": artifact.artifact_kind,
            "artifactId": artifact.artifact_id,
            "summary": artifact.summary,
        }),
    )
    .await?;

    tx.commit().await.map_err(ApiError::Database)?;
    Ok(artifact)
}

async fn prepare_case_artifact(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    req: AddCaseArtifactRequest,
) -> Result<PreparedCaseArtifact, ApiError> {
    match req.artifact_kind.as_str() {
        "fleet_event" => resolve_fleet_event_artifact(tx, tenant_id, req.artifact_id.trim()).await,
        "raw_envelope" => {
            resolve_raw_envelope_artifact(tx, tenant_id, req.artifact_id.trim()).await
        }
        "saved_hunt" => resolve_saved_hunt_artifact(tx, tenant_id, req.artifact_id.trim()).await,
        "hunt_job" => resolve_hunt_job_artifact(tx, tenant_id, req.artifact_id.trim()).await,
        "detection" => resolve_detection_artifact(tx, tenant_id, req.artifact_id.trim()).await,
        "response_action" => {
            resolve_response_action_artifact(tx, tenant_id, req.artifact_id.trim()).await
        }
        "grant" => resolve_grant_artifact(tx, tenant_id, req.artifact_id.trim()).await,
        "note" => prepare_annotation_artifact(req, "operator_annotation"),
        "graph_snapshot" => prepare_annotation_artifact(req, "operator_annotation"),
        "bundle_export" => Err(ApiError::BadRequest(
            "bundle_export artifacts are managed by the evidence service".to_string(),
        )),
        other => Err(ApiError::BadRequest(format!(
            "invalid artifactKind: {other}"
        ))),
    }
}

fn prepare_annotation_artifact(
    req: AddCaseArtifactRequest,
    artifact_class: &str,
) -> Result<PreparedCaseArtifact, ApiError> {
    let mut metadata = normalize_metadata(req.metadata)?;
    metadata["artifactClass"] = Value::String(artifact_class.to_string());

    Ok(PreparedCaseArtifact {
        artifact_kind: req.artifact_kind,
        artifact_id: req.artifact_id.trim().to_string(),
        summary: normalize_summary(req.summary),
        metadata,
    })
}

async fn resolve_fleet_event_artifact(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    event_id: &str,
) -> Result<PreparedCaseArtifact, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT event_id,
                  summary,
                  source,
                  kind,
                  timestamp,
                  ingested_at,
                  verdict,
                  severity,
                  session_id,
                  endpoint_agent_id,
                  runtime_agent_id,
                  principal_id,
                  grant_id,
                  response_action_id,
                  detection_ids,
                  target_kind,
                  target_id,
                  target_name,
                  raw_ref,
                  envelope_hash,
                  issuer,
                  schema_name,
                  signature_valid
           FROM hunt_events
           WHERE tenant_id = $1 AND event_id = $2"#,
    )
    .bind(tenant_id)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let summary: String = row.try_get("summary").map_err(ApiError::Database)?;
    Ok(PreparedCaseArtifact {
        artifact_kind: "fleet_event".to_string(),
        artifact_id: row.try_get("event_id").map_err(ApiError::Database)?,
        summary: Some(summary.clone()),
        metadata: json!({
            "artifactClass": "verified_reference",
            "sourceTable": "hunt_events",
            "eventId": event_id,
            "summary": summary,
            "source": row.try_get::<String, _>("source").map_err(ApiError::Database)?,
            "kind": row.try_get::<String, _>("kind").map_err(ApiError::Database)?,
            "timestamp": row.try_get::<DateTime<Utc>, _>("timestamp").map_err(ApiError::Database)?.to_rfc3339(),
            "ingestedAt": row.try_get::<DateTime<Utc>, _>("ingested_at").map_err(ApiError::Database)?.to_rfc3339(),
            "verdict": row.try_get::<String, _>("verdict").map_err(ApiError::Database)?,
            "severity": row.try_get::<Option<String>, _>("severity").map_err(ApiError::Database)?,
            "sessionId": row.try_get::<Option<String>, _>("session_id").map_err(ApiError::Database)?,
            "endpointAgentId": row.try_get::<Option<String>, _>("endpoint_agent_id").map_err(ApiError::Database)?,
            "runtimeAgentId": row.try_get::<Option<String>, _>("runtime_agent_id").map_err(ApiError::Database)?,
            "principalId": row.try_get::<Option<String>, _>("principal_id").map_err(ApiError::Database)?,
            "grantId": row.try_get::<Option<String>, _>("grant_id").map_err(ApiError::Database)?,
            "responseActionId": row.try_get::<Option<String>, _>("response_action_id").map_err(ApiError::Database)?,
            "detectionIds": row.try_get::<Vec<String>, _>("detection_ids").map_err(ApiError::Database)?,
            "targetKind": row.try_get::<Option<String>, _>("target_kind").map_err(ApiError::Database)?,
            "targetId": row.try_get::<Option<String>, _>("target_id").map_err(ApiError::Database)?,
            "targetName": row.try_get::<Option<String>, _>("target_name").map_err(ApiError::Database)?,
            "rawRef": row.try_get::<String, _>("raw_ref").map_err(ApiError::Database)?,
            "envelopeHash": row.try_get::<Option<String>, _>("envelope_hash").map_err(ApiError::Database)?,
            "issuer": row.try_get::<Option<String>, _>("issuer").map_err(ApiError::Database)?,
            "schemaName": row.try_get::<Option<String>, _>("schema_name").map_err(ApiError::Database)?,
            "signatureValid": row.try_get::<Option<bool>, _>("signature_valid").map_err(ApiError::Database)?,
        }),
    })
}

async fn resolve_raw_envelope_artifact(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    raw_ref: &str,
) -> Result<PreparedCaseArtifact, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT raw_ref,
                  source,
                  issuer,
                  issued_at,
                  ingested_at,
                  envelope_hash,
                  schema_name,
                  signature_valid
           FROM hunt_envelopes
           WHERE tenant_id = $1 AND raw_ref = $2"#,
    )
    .bind(tenant_id)
    .bind(raw_ref)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let schema_name: Option<String> = row.try_get("schema_name").map_err(ApiError::Database)?;
    let artifact_id: String = row.try_get("raw_ref").map_err(ApiError::Database)?;
    Ok(PreparedCaseArtifact {
        artifact_kind: "raw_envelope".to_string(),
        artifact_id: artifact_id.clone(),
        summary: Some(
            schema_name
                .clone()
                .unwrap_or_else(|| format!("raw envelope {artifact_id}")),
        ),
        metadata: json!({
            "artifactClass": "verified_reference",
            "sourceTable": "hunt_envelopes",
            "rawRef": artifact_id,
            "source": row.try_get::<String, _>("source").map_err(ApiError::Database)?,
            "issuer": row.try_get::<Option<String>, _>("issuer").map_err(ApiError::Database)?,
            "issuedAt": row.try_get::<DateTime<Utc>, _>("issued_at").map_err(ApiError::Database)?.to_rfc3339(),
            "ingestedAt": row.try_get::<DateTime<Utc>, _>("ingested_at").map_err(ApiError::Database)?.to_rfc3339(),
            "envelopeHash": row.try_get::<Option<String>, _>("envelope_hash").map_err(ApiError::Database)?,
            "schemaName": schema_name,
            "signatureValid": row.try_get::<Option<bool>, _>("signature_valid").map_err(ApiError::Database)?,
        }),
    })
}

async fn resolve_saved_hunt_artifact(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    artifact_id: &str,
) -> Result<PreparedCaseArtifact, ApiError> {
    let hunt_id = parse_uuid_artifact_id(artifact_id, "saved_hunt")?;
    let row = sqlx::query::query(
        r#"SELECT id, name, description, query, created_by, created_at, updated_at
           FROM saved_hunts
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(hunt_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    let name: String = row.try_get("name").map_err(ApiError::Database)?;
    Ok(PreparedCaseArtifact {
        artifact_kind: "saved_hunt".to_string(),
        artifact_id: hunt_id.to_string(),
        summary: Some(name.clone()),
        metadata: json!({
            "artifactClass": "verified_reference",
            "sourceTable": "saved_hunts",
            "savedHuntId": hunt_id,
            "name": name,
            "description": row.try_get::<Option<String>, _>("description").map_err(ApiError::Database)?,
            "query": row.try_get::<Value, _>("query").map_err(ApiError::Database)?,
            "createdBy": row.try_get::<String, _>("created_by").map_err(ApiError::Database)?,
            "createdAt": row.try_get::<DateTime<Utc>, _>("created_at").map_err(ApiError::Database)?.to_rfc3339(),
            "updatedAt": row.try_get::<DateTime<Utc>, _>("updated_at").map_err(ApiError::Database)?.to_rfc3339(),
        }),
    })
}

async fn resolve_hunt_job_artifact(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    artifact_id: &str,
) -> Result<PreparedCaseArtifact, ApiError> {
    let job_id = parse_uuid_artifact_id(artifact_id, "hunt_job")?;
    let row = sqlx::query::query(
        r#"SELECT id, job_type, status, request, result, created_by, created_at, completed_at
           FROM hunt_jobs
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(job_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    let job_type: String = row.try_get("job_type").map_err(ApiError::Database)?;
    Ok(PreparedCaseArtifact {
        artifact_kind: "hunt_job".to_string(),
        artifact_id: job_id.to_string(),
        summary: Some(format!("{job_type} hunt job")),
        metadata: json!({
            "artifactClass": "verified_reference",
            "sourceTable": "hunt_jobs",
            "huntJobId": job_id,
            "jobType": job_type,
            "status": row.try_get::<String, _>("status").map_err(ApiError::Database)?,
            "request": row.try_get::<Value, _>("request").map_err(ApiError::Database)?,
            "result": row.try_get::<Option<Value>, _>("result").map_err(ApiError::Database)?,
            "createdBy": row.try_get::<String, _>("created_by").map_err(ApiError::Database)?,
            "createdAt": row.try_get::<DateTime<Utc>, _>("created_at").map_err(ApiError::Database)?.to_rfc3339(),
            "completedAt": row.try_get::<Option<DateTime<Utc>>, _>("completed_at").map_err(ApiError::Database)?.map(|value| value.to_rfc3339()),
        }),
    })
}

async fn resolve_detection_artifact(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    artifact_id: &str,
) -> Result<PreparedCaseArtifact, ApiError> {
    let detection_id = parse_uuid_artifact_id(artifact_id, "detection")?;
    let row = sqlx::query::query(
        r#"SELECT id,
                  rule_id,
                  rule_name,
                  source_format,
                  severity,
                  status,
                  title,
                  summary,
                  principal_id,
                  session_id,
                  grant_id,
                  response_action_ids,
                  first_seen_at,
                  last_seen_at,
                  metadata
           FROM detection_findings
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(detection_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    let evidence_rows = sqlx::query::query(
        r#"SELECT artifact_ref
           FROM detection_finding_evidence
           WHERE tenant_id = $1 AND finding_id = $2
           ORDER BY artifact_ref ASC"#,
    )
    .bind(tenant_id)
    .bind(detection_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(ApiError::Database)?;
    let evidence_refs = evidence_rows
        .into_iter()
        .map(|evidence_row| evidence_row.try_get("artifact_ref"))
        .collect::<Result<Vec<String>, _>>()
        .map_err(ApiError::Database)?;
    let response_action_ids: Value = row
        .try_get("response_action_ids")
        .map_err(ApiError::Database)?;
    let primary_response_action_id = response_action_ids
        .as_array()
        .and_then(|ids| (ids.len() == 1).then_some(ids))
        .and_then(|ids| ids.first())
        .and_then(Value::as_str)
        .map(ToString::to_string);

    let title: String = row.try_get("title").map_err(ApiError::Database)?;
    Ok(PreparedCaseArtifact {
        artifact_kind: "detection".to_string(),
        artifact_id: detection_id.to_string(),
        summary: Some(title.clone()),
        metadata: json!({
            "artifactClass": "verified_reference",
            "sourceTable": "detection_findings",
            "detectionId": detection_id,
            "ruleId": row.try_get::<Uuid, _>("rule_id").map_err(ApiError::Database)?.to_string(),
            "ruleName": row.try_get::<String, _>("rule_name").map_err(ApiError::Database)?,
            "sourceFormat": row.try_get::<String, _>("source_format").map_err(ApiError::Database)?,
            "severity": row.try_get::<String, _>("severity").map_err(ApiError::Database)?,
            "status": row.try_get::<String, _>("status").map_err(ApiError::Database)?,
            "title": title,
            "summary": row.try_get::<String, _>("summary").map_err(ApiError::Database)?,
            "principalId": row.try_get::<Option<Uuid>, _>("principal_id").map_err(ApiError::Database)?.map(|value| value.to_string()),
            "sessionId": row.try_get::<Option<String>, _>("session_id").map_err(ApiError::Database)?,
            "grantId": row.try_get::<Option<Uuid>, _>("grant_id").map_err(ApiError::Database)?.map(|value| value.to_string()),
            "responseActionId": primary_response_action_id,
            "responseActionIds": response_action_ids,
            "firstSeenAt": row.try_get::<DateTime<Utc>, _>("first_seen_at").map_err(ApiError::Database)?.to_rfc3339(),
            "lastSeenAt": row.try_get::<DateTime<Utc>, _>("last_seen_at").map_err(ApiError::Database)?.to_rfc3339(),
            "evidenceRefs": evidence_refs,
            "metadata": row.try_get::<Value, _>("metadata").map_err(ApiError::Database)?,
        }),
    })
}

async fn resolve_response_action_artifact(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    artifact_id: &str,
) -> Result<PreparedCaseArtifact, ApiError> {
    let action_id = parse_uuid_artifact_id(artifact_id, "response_action")?;
    let row = sqlx::query::query(
        r#"SELECT id,
                  action_type,
                  target_kind,
                  target_id,
                  requested_by_type,
                  requested_by_id,
                  requested_at,
                  expires_at,
                  reason,
                  case_id,
                  source_detection_id,
                  source_approval_id,
                  require_acknowledgement,
                  payload,
                  status,
                  metadata
           FROM response_actions
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(action_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let action_type: String = row.try_get("action_type").map_err(ApiError::Database)?;
    let target_kind: String = row.try_get("target_kind").map_err(ApiError::Database)?;
    let target_id: String = row.try_get("target_id").map_err(ApiError::Database)?;
    let source_detection_id: Option<Uuid> = row
        .try_get("source_detection_id")
        .map_err(ApiError::Database)?;
    let source_detection_principal_id = if let Some(source_detection_id) = source_detection_id {
        sqlx::query_scalar::query_scalar::<_, Option<Uuid>>(
            r#"SELECT principal_id
               FROM detection_findings
               WHERE tenant_id = $1 AND id = $2"#,
        )
        .bind(tenant_id)
        .bind(source_detection_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(ApiError::Database)?
        .flatten()
        .map(|value| value.to_string())
    } else {
        None
    };

    Ok(PreparedCaseArtifact {
        artifact_kind: "response_action".to_string(),
        artifact_id: action_id.to_string(),
        summary: Some(format!("{action_type} -> {target_kind}:{target_id}")),
        metadata: json!({
            "artifactClass": "verified_reference",
            "sourceTable": "response_actions",
            "responseActionId": action_id,
            "actionType": action_type,
            "targetKind": target_kind,
            "targetId": target_id,
            "requestedByType": row.try_get::<String, _>("requested_by_type").map_err(ApiError::Database)?,
            "requestedById": row.try_get::<String, _>("requested_by_id").map_err(ApiError::Database)?,
            "requestedAt": row.try_get::<DateTime<Utc>, _>("requested_at").map_err(ApiError::Database)?.to_rfc3339(),
            "expiresAt": row.try_get::<Option<DateTime<Utc>>, _>("expires_at").map_err(ApiError::Database)?.map(|value| value.to_rfc3339()),
            "reason": row.try_get::<String, _>("reason").map_err(ApiError::Database)?,
            "principalId": source_detection_principal_id,
            "caseId": row.try_get::<Option<Uuid>, _>("case_id").map_err(ApiError::Database)?.map(|value| value.to_string()),
            "detectionId": source_detection_id.map(|value| value.to_string()),
            "sourceDetectionId": source_detection_id.map(|value| value.to_string()),
            "sourceApprovalId": row.try_get::<Option<Uuid>, _>("source_approval_id").map_err(ApiError::Database)?.map(|value| value.to_string()),
            "requireAcknowledgement": row.try_get::<bool, _>("require_acknowledgement").map_err(ApiError::Database)?,
            "payload": row.try_get::<Value, _>("payload").map_err(ApiError::Database)?,
            "status": row.try_get::<String, _>("status").map_err(ApiError::Database)?,
            "metadata": row.try_get::<Value, _>("metadata").map_err(ApiError::Database)?,
        }),
    })
}

async fn resolve_grant_artifact(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    artifact_id: &str,
) -> Result<PreparedCaseArtifact, ApiError> {
    let grant_id = parse_uuid_artifact_id(artifact_id, "grant")?;
    let row = sqlx::query::query(
        r#"SELECT id,
                  issuer_principal_id,
                  subject_principal_id,
                  grant_type,
                  audience,
                  token_jti,
                  parent_grant_id,
                  parent_token_jti,
                  capabilities,
                  capability_ceiling,
                  purpose,
                  context,
                  source_approval_id,
                  source_session_id,
                  issued_at,
                  not_before,
                  expires_at,
                  status,
                  revoked_at,
                  revoked_by,
                  revoke_reason
           FROM fleet_grants
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(grant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let token_jti: String = row.try_get("token_jti").map_err(ApiError::Database)?;
    Ok(PreparedCaseArtifact {
        artifact_kind: "grant".to_string(),
        artifact_id: grant_id.to_string(),
        summary: Some(
            row.try_get::<Option<String>, _>("purpose")
                .map_err(ApiError::Database)?
                .unwrap_or_else(|| format!("grant {token_jti}")),
        ),
        metadata: json!({
            "artifactClass": "verified_reference",
            "sourceTable": "fleet_grants",
            "grantId": grant_id,
            "issuerPrincipalId": row.try_get::<String, _>("issuer_principal_id").map_err(ApiError::Database)?,
            "subjectPrincipalId": row.try_get::<String, _>("subject_principal_id").map_err(ApiError::Database)?,
            "grantType": row.try_get::<String, _>("grant_type").map_err(ApiError::Database)?,
            "audience": row.try_get::<String, _>("audience").map_err(ApiError::Database)?,
            "tokenJti": token_jti,
            "parentGrantId": row.try_get::<Option<Uuid>, _>("parent_grant_id").map_err(ApiError::Database)?.map(|value| value.to_string()),
            "parentTokenJti": row.try_get::<Option<String>, _>("parent_token_jti").map_err(ApiError::Database)?,
            "capabilities": row.try_get::<Value, _>("capabilities").map_err(ApiError::Database)?,
            "capabilityCeiling": row.try_get::<Value, _>("capability_ceiling").map_err(ApiError::Database)?,
            "purpose": row.try_get::<Option<String>, _>("purpose").map_err(ApiError::Database)?,
            "context": row.try_get::<Value, _>("context").map_err(ApiError::Database)?,
            "sourceApprovalId": row.try_get::<Option<String>, _>("source_approval_id").map_err(ApiError::Database)?,
            "sourceSessionId": row.try_get::<Option<String>, _>("source_session_id").map_err(ApiError::Database)?,
            "issuedAt": row.try_get::<DateTime<Utc>, _>("issued_at").map_err(ApiError::Database)?.to_rfc3339(),
            "notBefore": row.try_get::<Option<DateTime<Utc>>, _>("not_before").map_err(ApiError::Database)?.map(|value| value.to_rfc3339()),
            "expiresAt": row.try_get::<DateTime<Utc>, _>("expires_at").map_err(ApiError::Database)?.to_rfc3339(),
            "status": row.try_get::<String, _>("status").map_err(ApiError::Database)?,
            "revokedAt": row.try_get::<Option<DateTime<Utc>>, _>("revoked_at").map_err(ApiError::Database)?.map(|value| value.to_rfc3339()),
            "revokedBy": row.try_get::<Option<String>, _>("revoked_by").map_err(ApiError::Database)?,
            "revokeReason": row.try_get::<Option<String>, _>("revoke_reason").map_err(ApiError::Database)?,
        }),
    })
}

fn parse_uuid_artifact_id(artifact_id: &str, artifact_kind: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(artifact_id).map_err(|_| {
        ApiError::BadRequest(format!(
            "{artifact_kind} artifacts must use a UUID artifactId"
        ))
    })
}

fn normalize_summary(summary: Option<String>) -> Option<String> {
    summary.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

pub async fn list_timeline(
    db: &PgPool,
    tenant_id: Uuid,
    case_id: Uuid,
) -> Result<Vec<CaseTimelineEvent>, ApiError> {
    ensure_case_exists(db, tenant_id, case_id).await?;

    let rows = sqlx::query::query(
        r#"SELECT *
           FROM fleet_case_events
           WHERE tenant_id = $1 AND case_id = $2
           ORDER BY created_at ASC, id ASC"#,
    )
    .bind(tenant_id)
    .bind(case_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(CaseTimelineEvent::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)
}

pub async fn create_evidence_bundle(
    db: &PgPool,
    tenant_id: Uuid,
    case_id: Uuid,
    actor_id: &str,
    req: ExportEvidenceBundleRequest,
    signer: &hush_core::Keypair,
) -> Result<FleetEvidenceBundle, ApiError> {
    let case_detail = get_case_detail(db, tenant_id, case_id).await?;
    let tenant_retention_days = tenant_retention_days(db, tenant_id).await?;
    let requested_retention_days = req.retention_days.unwrap_or(tenant_retention_days);
    if requested_retention_days < 1 {
        return Err(ApiError::BadRequest(
            "retentionDays must be greater than or equal to 1".to_string(),
        ));
    }
    let retention_days = requested_retention_days.min(tenant_retention_days);
    let requested_at = Utc::now();
    let expires_at = requested_at + Duration::days(i64::from(retention_days));
    let export_id = format!("caseexp_{}", Uuid::now_v7());
    let filters = export_filters_json(&req);

    let mut tx = db.begin().await.map_err(ApiError::Database)?;
    sqlx::query::query(
        r#"INSERT INTO fleet_evidence_bundles (
               export_id,
               tenant_id,
               case_id,
               status,
               requested_by,
               requested_at,
               expires_at,
               retention_days,
               filters
           )
           VALUES ($1, $2, $3, 'processing', $4, $5, $6, $7, $8)"#,
    )
    .bind(&export_id)
    .bind(tenant_id)
    .bind(case_id)
    .bind(actor_id)
    .bind(requested_at)
    .bind(expires_at)
    .bind(retention_days)
    .bind(&filters)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::Database)?;
    insert_case_event(
        &mut tx,
        tenant_id,
        case_id,
        "bundle_requested",
        actor_id,
        serde_json::json!({
            "exportId": export_id,
            "expiresAt": expires_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
            "filters": filters,
        }),
    )
    .await?;
    tx.commit().await.map_err(ApiError::Database)?;

    match build_case_bundle(
        BuildCaseBundleInput {
            tenant_id,
            actor_id,
            export_id: &export_id,
            case: &case_detail.case,
            artifacts: &case_detail.artifacts,
            req: &req,
            expires_at,
        },
        signer,
    )
    .await
    {
        Ok(bundle_build) => {
            let mut tx = db.begin().await.map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE fleet_evidence_bundles
                   SET status = 'completed',
                       completed_at = $2,
                       file_path = $3,
                       sha256 = $4,
                       size_bytes = $5,
                       manifest_ref = 'manifest.json',
                       artifact_counts = $6,
                       metadata = $7
                   WHERE export_id = $1"#,
            )
            .bind(&export_id)
            .bind(bundle_build.completed_at)
            .bind(&bundle_build.file_path)
            .bind(&bundle_build.sha256)
            .bind(bundle_build.size_bytes)
            .bind(&bundle_build.artifact_counts)
            .bind(&bundle_build.metadata)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;

            sqlx::query::query(
                r#"INSERT INTO fleet_case_artifacts (
                       tenant_id,
                       case_id,
                       artifact_kind,
                       artifact_id,
                       summary,
                       metadata,
                       added_by
                   )
                   VALUES ($1, $2, 'bundle_export', $3, $4, $5, $6)
                   ON CONFLICT (case_id, artifact_kind, artifact_id) DO NOTHING"#,
            )
            .bind(tenant_id)
            .bind(case_id)
            .bind(&export_id)
            .bind("evidence bundle export")
            .bind(serde_json::json!({
                "sha256": bundle_build.sha256,
                "sizeBytes": bundle_build.size_bytes,
                "expiresAt": expires_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
                "manifestRef": "manifest.json",
            }))
            .bind(actor_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;

            insert_case_event(
                &mut tx,
                tenant_id,
                case_id,
                "bundle_completed",
                actor_id,
                serde_json::json!({
                    "exportId": export_id,
                    "sha256": bundle_build.sha256,
                    "sizeBytes": bundle_build.size_bytes,
                    "artifactCounts": bundle_build.artifact_counts,
                }),
            )
            .await?;
            tx.commit().await.map_err(ApiError::Database)?;
        }
        Err(err) => {
            let mut tx = db.begin().await.map_err(ApiError::Database)?;
            sqlx::query::query(
                "UPDATE fleet_evidence_bundles SET status = 'failed' WHERE export_id = $1",
            )
            .bind(&export_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            insert_case_event(
                &mut tx,
                tenant_id,
                case_id,
                "bundle_failed",
                actor_id,
                serde_json::json!({
                    "exportId": export_id,
                    "error": err.to_string(),
                }),
            )
            .await?;
            tx.commit().await.map_err(ApiError::Database)?;
            return Err(err);
        }
    }

    get_bundle(db, tenant_id, &export_id).await
}

pub async fn get_bundle(
    db: &PgPool,
    tenant_id: Uuid,
    export_id: &str,
) -> Result<FleetEvidenceBundle, ApiError> {
    let row = sqlx::query::query(
        "SELECT * FROM fleet_evidence_bundles WHERE tenant_id = $1 AND export_id = $2",
    )
    .bind(tenant_id)
    .bind(export_id)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    FleetEvidenceBundle::from_row(row).map_err(ApiError::Database)
}

pub async fn bundle_download_path(
    db: &PgPool,
    tenant_id: Uuid,
    export_id: &str,
) -> Result<PathBuf, ApiError> {
    let bundle = get_bundle(db, tenant_id, export_id).await?;
    if bundle_has_expired(&bundle, Utc::now()) {
        sqlx::query::query(
            r#"UPDATE fleet_evidence_bundles
               SET status = 'expired'
               WHERE tenant_id = $1
                 AND export_id = $2
                 AND status = 'completed'
                 AND expires_at IS NOT NULL
                 AND expires_at <= now()"#,
        )
        .bind(tenant_id)
        .bind(export_id)
        .execute(db)
        .await
        .map_err(ApiError::Database)?;
        return Err(ApiError::BadRequest(
            "evidence bundle has expired".to_string(),
        ));
    }
    if bundle.status != "completed" {
        return Err(ApiError::BadRequest(
            "evidence bundle is not ready for download".to_string(),
        ));
    }
    let path = bundle.file_path.map(PathBuf::from).ok_or_else(|| {
        ApiError::Internal("completed evidence bundle is missing a file path".to_string())
    })?;
    if !path.exists() {
        return Err(ApiError::NotFound);
    }
    Ok(path)
}

fn bundle_has_expired(bundle: &FleetEvidenceBundle, now: DateTime<Utc>) -> bool {
    bundle.status == "expired" || bundle.expires_at.is_some_and(|ts| ts <= now)
}

async fn ensure_case_exists(db: &PgPool, tenant_id: Uuid, case_id: Uuid) -> Result<(), ApiError> {
    let exists = sqlx::query::query("SELECT 1 FROM fleet_cases WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(case_id)
        .fetch_optional(db)
        .await
        .map_err(ApiError::Database)?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(ApiError::NotFound)
    }
}

async fn tenant_retention_days(db: &PgPool, tenant_id: Uuid) -> Result<i32, ApiError> {
    let row = sqlx::query::query("SELECT retention_days FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_one(db)
        .await
        .map_err(ApiError::Database)?;
    row.try_get("retention_days").map_err(ApiError::Database)
}

async fn insert_case_event(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    case_id: Uuid,
    event_kind: &str,
    actor_id: &str,
    payload: Value,
) -> Result<(), ApiError> {
    sqlx::query::query(
        r#"INSERT INTO fleet_case_events (tenant_id, case_id, event_kind, actor_id, payload)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(tenant_id)
    .bind(case_id)
    .bind(event_kind)
    .bind(actor_id)
    .bind(payload)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;
    Ok(())
}

fn validate_severity(severity: &str) -> Result<(), ApiError> {
    if VALID_SEVERITIES.contains(&severity) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "invalid severity: {severity}"
        )))
    }
}

fn validate_status(status: &str) -> Result<(), ApiError> {
    if VALID_STATUSES.contains(&status) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!("invalid status: {status}")))
    }
}

fn validate_artifact_kind(artifact_kind: &str) -> Result<(), ApiError> {
    if VALID_ARTIFACT_KINDS.contains(&artifact_kind) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "invalid artifactKind: {artifact_kind}"
        )))
    }
}

fn normalize_strings(values: Vec<String>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn normalize_metadata(metadata: Value) -> Result<Value, ApiError> {
    if metadata.is_object() {
        Ok(metadata)
    } else {
        Err(ApiError::BadRequest(
            "metadata must be a JSON object".to_string(),
        ))
    }
}

fn map_artifact_insert_error(err: sqlx::error::Error) -> ApiError {
    if let sqlx::error::Error::Database(db_err) = &err {
        if db_err.is_unique_violation() {
            return ApiError::BadRequest("artifact already exists on this case".to_string());
        }
    }
    ApiError::Database(err)
}

fn export_filters_json(req: &ExportEvidenceBundleRequest) -> Value {
    serde_json::json!({
        "start": req.start.map(|value: DateTime<Utc>| value.to_rfc3339_opts(SecondsFormat::Nanos, true)),
        "end": req.end.map(|value: DateTime<Utc>| value.to_rfc3339_opts(SecondsFormat::Nanos, true)),
        "principalIds": req.principal_ids.clone().map(normalize_strings),
        "detectionIds": req.detection_ids.clone().map(normalize_strings),
        "responseActionIds": req.response_action_ids.clone().map(normalize_strings),
        "sourceFamilies": req.source_families.clone().map(normalize_strings),
        "includeRawEnvelopes": req.include_raw_envelopes.unwrap_or(false),
        "includeOcsf": req.include_ocsf.unwrap_or(false),
    })
}

struct BuiltCaseBundle {
    completed_at: DateTime<Utc>,
    file_path: String,
    sha256: String,
    size_bytes: i64,
    artifact_counts: Value,
    metadata: Value,
}

struct BuildCaseBundleInput<'a> {
    tenant_id: Uuid,
    actor_id: &'a str,
    export_id: &'a str,
    case: &'a FleetCase,
    artifacts: &'a [CaseArtifactRef],
    req: &'a ExportEvidenceBundleRequest,
    expires_at: DateTime<Utc>,
}

async fn build_case_bundle(
    input: BuildCaseBundleInput<'_>,
    signer: &hush_core::Keypair,
) -> Result<BuiltCaseBundle, ApiError> {
    let filtered_artifacts = filter_artifacts(input.artifacts, input.req);
    let artifact_counts = artifact_counts(
        &filtered_artifacts,
        input.req.include_raw_envelopes.unwrap_or(false),
    );

    let events = filtered_artifacts
        .iter()
        .copied()
        .filter(|artifact| artifact.artifact_kind == "fleet_event")
        .map(artifact_export_line)
        .collect::<Result<Vec<_>, _>>()?;
    let raw_envelopes = filtered_artifacts
        .iter()
        .copied()
        .filter(|artifact| artifact.artifact_kind == "raw_envelope")
        .map(artifact_export_line)
        .collect::<Result<Vec<_>, _>>()?;
    let detections = filtered_artifacts
        .iter()
        .copied()
        .filter(|artifact| artifact.artifact_kind == "detection")
        .map(artifact_export_value)
        .collect::<Vec<_>>();
    let response_actions = filtered_artifacts
        .iter()
        .copied()
        .filter(|artifact| artifact.artifact_kind == "response_action")
        .map(artifact_export_value)
        .collect::<Vec<_>>();
    let graph_snapshots = filtered_artifacts
        .iter()
        .copied()
        .filter(|artifact| artifact.artifact_kind == "graph_snapshot")
        .map(artifact_export_value)
        .collect::<Vec<_>>();
    let notes = filtered_artifacts
        .iter()
        .copied()
        .filter(|artifact| artifact.artifact_kind == "note")
        .map(artifact_export_value)
        .collect::<Vec<_>>();
    let ocsf_lines = if input.req.include_ocsf.unwrap_or(false) {
        filtered_artifacts
            .iter()
            .filter_map(|artifact| artifact.metadata.get("ocsf").cloned())
            .map(|value| {
                serde_json::to_string(&value).map_err(|err| ApiError::Internal(err.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };

    let case_json =
        serde_json::to_vec_pretty(input.case).map_err(|err| ApiError::Internal(err.to_string()))?;
    let artifacts_json = serde_json::to_vec_pretty(&filtered_artifacts)
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    let detections_json = serde_json::to_vec_pretty(&detections)
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    let response_actions_json = serde_json::to_vec_pretty(&response_actions)
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    let graph_json = serde_json::to_vec_pretty(&graph_snapshots)
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    let notes_json =
        serde_json::to_vec_pretty(&notes).map_err(|err| ApiError::Internal(err.to_string()))?;

    let mut entries = vec![
        GenericEvidenceBundleEntry {
            path: "artifacts.json".to_string(),
            bytes: newline_terminated(artifacts_json),
        },
        GenericEvidenceBundleEntry {
            path: "case.json".to_string(),
            bytes: newline_terminated(case_json),
        },
        GenericEvidenceBundleEntry {
            path: "detections.json".to_string(),
            bytes: newline_terminated(detections_json),
        },
        GenericEvidenceBundleEntry {
            path: "events.jsonl".to_string(),
            bytes: jsonl_bytes(&events),
        },
        GenericEvidenceBundleEntry {
            path: "graph.json".to_string(),
            bytes: newline_terminated(graph_json),
        },
        GenericEvidenceBundleEntry {
            path: "notes.json".to_string(),
            bytes: newline_terminated(notes_json),
        },
        GenericEvidenceBundleEntry {
            path: "response-actions.json".to_string(),
            bytes: newline_terminated(response_actions_json),
        },
    ];

    if input.req.include_raw_envelopes.unwrap_or(false) {
        entries.push(GenericEvidenceBundleEntry {
            path: "raw/references.jsonl".to_string(),
            bytes: jsonl_bytes(&raw_envelopes),
        });
    }
    if input.req.include_ocsf.unwrap_or(false) {
        entries.push(GenericEvidenceBundleEntry {
            path: "ocsf.jsonl".to_string(),
            bytes: jsonl_bytes(&ocsf_lines),
        });
    }

    let completed_at = Utc::now();
    let manifest_metadata = serde_json::json!({
        "caseId": input.case.id,
        "tenantId": input.tenant_id,
        "requestedBy": input.actor_id,
        "expiresAt": input.expires_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
        "artifactCounts": artifact_counts,
        "filters": export_filters_json(input.req),
    });

    let out_dir = bundle_output_dir()?;
    let output = build_signed_evidence_bundle_zip(
        &out_dir,
        input.export_id,
        GenericEvidenceBundleSubject {
            kind: "fleet_case".to_string(),
            id: input.case.id.to_string(),
        },
        &completed_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
        Some(manifest_metadata.clone()),
        &entries,
        signer,
    )
    .map_err(|err| ApiError::Internal(err.to_string()))?;

    let file_path = output.file_path.to_string_lossy().into_owned();
    let size_bytes = i64::try_from(output.size_bytes)
        .map_err(|_| ApiError::Internal("bundle size exceeds i64".to_string()))?;

    Ok(BuiltCaseBundle {
        completed_at,
        file_path,
        sha256: output.sha256_hex,
        size_bytes,
        artifact_counts,
        metadata: serde_json::json!({
            "manifestRef": "manifest.json",
            "merkleRoot": output.merkle_root,
            "reproducibleZipTimestamps": true,
        }),
    })
}

fn artifact_counts(artifacts: &[&CaseArtifactRef], include_raw_envelopes: bool) -> Value {
    let mut counts = BTreeMap::new();
    for artifact in artifacts {
        if artifact.artifact_kind == "raw_envelope" && !include_raw_envelopes {
            continue;
        }
        *counts
            .entry(artifact.artifact_kind.clone())
            .or_insert(0usize) += 1;
    }
    serde_json::to_value(counts).unwrap_or_else(|_| Value::Object(Default::default()))
}

fn artifact_export_value(artifact: &CaseArtifactRef) -> Value {
    serde_json::json!({
        "id": artifact.id,
        "caseId": artifact.case_id,
        "artifactKind": artifact.artifact_kind,
        "artifactId": artifact.artifact_id,
        "summary": artifact.summary,
        "metadata": artifact.metadata,
        "addedBy": artifact.added_by,
        "addedAt": artifact.added_at,
    })
}

fn artifact_export_line(artifact: &CaseArtifactRef) -> Result<String, ApiError> {
    serde_json::to_string(&artifact_export_value(artifact))
        .map_err(|err| ApiError::Internal(err.to_string()))
}

fn filter_artifacts<'a>(
    artifacts: &'a [CaseArtifactRef],
    req: &ExportEvidenceBundleRequest,
) -> Vec<&'a CaseArtifactRef> {
    let principal_ids: Option<Vec<String>> = req.principal_ids.clone().map(normalize_strings);
    let detection_ids: Option<Vec<String>> = req.detection_ids.clone().map(normalize_strings);
    let response_action_ids: Option<Vec<String>> =
        req.response_action_ids.clone().map(normalize_strings);
    let include_raw_envelopes = req.include_raw_envelopes.unwrap_or(false);

    let eligible = artifacts
        .iter()
        .filter(|artifact| include_artifact_for_export_window(artifact, req, include_raw_envelopes))
        .collect::<Vec<_>>();

    if principal_ids.is_none() && detection_ids.is_none() && response_action_ids.is_none() {
        return eligible;
    }

    let mut included = BTreeSet::new();
    let mut detection_closure = detection_ids
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut response_action_closure = response_action_ids
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut raw_ref_closure = BTreeSet::new();

    for artifact in &eligible {
        if artifact_matches_seed_filters(
            artifact,
            principal_ids.as_ref(),
            detection_ids.as_ref(),
            response_action_ids.as_ref(),
        ) {
            included.insert(artifact.id);
            extend_case_artifact_closure(
                artifact,
                &mut detection_closure,
                &mut response_action_closure,
                &mut raw_ref_closure,
            );
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for artifact in &eligible {
            if included.contains(&artifact.id) {
                continue;
            }
            if artifact_matches_authoritative_closure(
                artifact,
                principal_ids.as_ref(),
                &detection_closure,
                &response_action_closure,
                &raw_ref_closure,
            ) {
                included.insert(artifact.id);
                extend_case_artifact_closure(
                    artifact,
                    &mut detection_closure,
                    &mut response_action_closure,
                    &mut raw_ref_closure,
                );
                changed = true;
            }
        }
    }

    eligible
        .into_iter()
        .filter(|artifact| included.contains(&artifact.id))
        .collect()
}

fn include_artifact_for_export_window(
    artifact: &CaseArtifactRef,
    req: &ExportEvidenceBundleRequest,
    include_raw_envelopes: bool,
) -> bool {
    if artifact.artifact_kind == "raw_envelope" && !include_raw_envelopes {
        return false;
    }

    let artifact_time = artifact_time(artifact);
    if let Some(start) = req.start {
        if artifact_time < start {
            return false;
        }
    }
    if let Some(end) = req.end {
        if artifact_time > end {
            return false;
        }
    }

    if let Some(source_families) = req.source_families.as_ref() {
        let normalized = normalize_strings(source_families.clone());
        if let Some(source) = artifact_source_family(artifact) {
            return normalized.iter().any(|value| value == source);
        }
    }

    true
}

fn artifact_matches_seed_filters(
    artifact: &CaseArtifactRef,
    principal_ids: Option<&Vec<String>>,
    detection_ids: Option<&Vec<String>>,
    response_action_ids: Option<&Vec<String>>,
) -> bool {
    let principal_match =
        principal_ids.is_some_and(|ids| artifact_matches_principal_ids(artifact, ids));
    let detection_match =
        detection_ids.is_some_and(|ids| artifact_matches_detection_ids(artifact, ids));
    let response_action_match =
        response_action_ids.is_some_and(|ids| artifact_matches_response_action_ids(artifact, ids));

    principal_match || detection_match || response_action_match
}

fn artifact_matches_authoritative_closure(
    artifact: &CaseArtifactRef,
    principal_ids: Option<&Vec<String>>,
    detection_closure: &BTreeSet<String>,
    response_action_closure: &BTreeSet<String>,
    raw_ref_closure: &BTreeSet<String>,
) -> bool {
    match artifact.artifact_kind.as_str() {
        "detection" => artifact
            .metadata
            .get("detectionId")
            .and_then(Value::as_str)
            .is_some_and(|value| detection_closure.contains(value)),
        "response_action" => {
            artifact
                .metadata
                .get("responseActionId")
                .and_then(Value::as_str)
                .is_some_and(|value| response_action_closure.contains(value))
                || artifact
                    .metadata
                    .get("detectionId")
                    .and_then(Value::as_str)
                    .is_some_and(|value| detection_closure.contains(value))
        }
        "fleet_event" => {
            artifact
                .metadata
                .get("detectionIds")
                .and_then(Value::as_array)
                .is_some_and(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|value| detection_closure.contains(value))
                })
                || artifact
                    .metadata
                    .get("responseActionId")
                    .and_then(Value::as_str)
                    .is_some_and(|value| response_action_closure.contains(value))
                || principal_ids.is_some_and(|ids| artifact_matches_principal_ids(artifact, ids))
        }
        "raw_envelope" => artifact
            .metadata
            .get("rawRef")
            .and_then(Value::as_str)
            .is_some_and(|value| raw_ref_closure.contains(value)),
        "graph_snapshot" | "note" => artifact_matches_seed_filters(
            artifact,
            principal_ids,
            Some(&detection_closure.iter().cloned().collect::<Vec<_>>()),
            Some(&response_action_closure.iter().cloned().collect::<Vec<_>>()),
        ),
        "saved_hunt" | "hunt_job" | "grant" => {
            principal_ids.is_some_and(|ids| artifact_matches_principal_ids(artifact, ids))
        }
        _ => false,
    }
}

fn extend_case_artifact_closure(
    artifact: &CaseArtifactRef,
    detection_closure: &mut BTreeSet<String>,
    response_action_closure: &mut BTreeSet<String>,
    raw_ref_closure: &mut BTreeSet<String>,
) {
    match artifact.artifact_kind.as_str() {
        "detection" => {
            if let Some(detection_id) = artifact.metadata.get("detectionId").and_then(Value::as_str)
            {
                detection_closure.insert(detection_id.to_string());
            }
            if let Some(response_action_id) = artifact
                .metadata
                .get("responseActionId")
                .and_then(Value::as_str)
            {
                response_action_closure.insert(response_action_id.to_string());
            }
            for response_action_id in artifact
                .metadata
                .get("responseActionIds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                response_action_closure.insert(response_action_id.to_string());
            }
            for evidence_ref in artifact
                .metadata
                .get("evidenceRefs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                raw_ref_closure.insert(evidence_ref.to_string());
            }
        }
        "response_action" => {
            if let Some(response_action_id) = artifact
                .metadata
                .get("responseActionId")
                .and_then(Value::as_str)
            {
                response_action_closure.insert(response_action_id.to_string());
            }
            if let Some(detection_id) = artifact.metadata.get("detectionId").and_then(Value::as_str)
            {
                detection_closure.insert(detection_id.to_string());
            }
        }
        "fleet_event" => {
            if let Some(response_action_id) = artifact
                .metadata
                .get("responseActionId")
                .and_then(Value::as_str)
            {
                response_action_closure.insert(response_action_id.to_string());
            }
            for detection_id in artifact
                .metadata
                .get("detectionIds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                detection_closure.insert(detection_id.to_string());
            }
            if let Some(raw_ref) = artifact.metadata.get("rawRef").and_then(Value::as_str) {
                raw_ref_closure.insert(raw_ref.to_string());
            }
        }
        "raw_envelope" => {
            if let Some(raw_ref) = artifact.metadata.get("rawRef").and_then(Value::as_str) {
                raw_ref_closure.insert(raw_ref.to_string());
            }
        }
        _ => {}
    }
}

fn artifact_matches_principal_ids(artifact: &CaseArtifactRef, ids: &[String]) -> bool {
    artifact_principal_id(artifact)
        .is_some_and(|artifact_id| ids.iter().any(|value| value == artifact_id))
}

fn artifact_matches_detection_ids(artifact: &CaseArtifactRef, ids: &[String]) -> bool {
    match artifact.artifact_kind.as_str() {
        "detection" => ids.iter().any(|value| value == &artifact.artifact_id),
        "fleet_event" => artifact
            .metadata
            .get("detectionIds")
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|value| ids.iter().any(|candidate| candidate == value))
            }),
        _ => artifact
            .metadata
            .get("detectionId")
            .and_then(Value::as_str)
            .is_some_and(|artifact_id| ids.iter().any(|value| value == artifact_id)),
    }
}

fn artifact_matches_response_action_ids(artifact: &CaseArtifactRef, ids: &[String]) -> bool {
    match artifact.artifact_kind.as_str() {
        "response_action" => ids.iter().any(|value| value == &artifact.artifact_id),
        "detection" => {
            artifact
                .metadata
                .get("responseActionIds")
                .and_then(Value::as_array)
                .is_some_and(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|value| ids.iter().any(|candidate| candidate == value))
                })
                || artifact
                    .metadata
                    .get("responseActionId")
                    .and_then(Value::as_str)
                    .is_some_and(|artifact_id| ids.iter().any(|value| value == artifact_id))
        }
        _ => artifact
            .metadata
            .get("responseActionId")
            .and_then(Value::as_str)
            .is_some_and(|artifact_id| ids.iter().any(|value| value == artifact_id)),
    }
}

fn artifact_principal_id(artifact: &CaseArtifactRef) -> Option<&str> {
    artifact
        .metadata
        .get("principalId")
        .and_then(Value::as_str)
        .or_else(|| {
            artifact
                .metadata
                .get("principal_id")
                .and_then(Value::as_str)
        })
}

fn artifact_source_family(artifact: &CaseArtifactRef) -> Option<&str> {
    artifact
        .metadata
        .get("source")
        .and_then(Value::as_str)
        .or_else(|| {
            artifact
                .metadata
                .get("sourceFamily")
                .and_then(Value::as_str)
        })
}

fn artifact_time(artifact: &CaseArtifactRef) -> DateTime<Utc> {
    artifact
        .metadata
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value: chrono::DateTime<chrono::FixedOffset>| value.with_timezone(&Utc))
        .unwrap_or(artifact.added_at)
}

fn newline_terminated(mut bytes: Vec<u8>) -> Vec<u8> {
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    bytes
}

fn jsonl_bytes(lines: &[String]) -> Vec<u8> {
    let mut bytes = lines.join("\n").into_bytes();
    if !bytes.is_empty() {
        bytes.push(b'\n');
    }
    bytes
}

fn bundle_output_dir() -> Result<PathBuf, ApiError> {
    let base = if let Ok(dir) = std::env::var("CLAWDSTRIKE_EVIDENCE_EXPORT_DIR") {
        PathBuf::from(dir)
    } else {
        let cwd = std::env::current_dir().map_err(|err| ApiError::Internal(err.to_string()))?;
        cwd.join("target").join("control-api-evidence-bundles")
    };
    std::fs::create_dir_all(Path::new(&base)).map_err(|err| ApiError::Internal(err.to_string()))?;
    Ok(base)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn artifact(kind: &str, artifact_id: &str, metadata: Value) -> CaseArtifactRef {
        CaseArtifactRef {
            id: Uuid::new_v4(),
            case_id: Uuid::new_v4(),
            artifact_kind: kind.to_string(),
            artifact_id: artifact_id.to_string(),
            summary: None,
            metadata,
            added_by: "tester".to_string(),
            added_at: Utc::now(),
        }
    }

    #[test]
    fn normalize_strings_sorts_and_deduplicates() {
        assert_eq!(
            normalize_strings(vec![" b ".into(), "a".into(), "b".into(), "".into()]),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn filter_artifacts_keeps_clean_hunt_and_response_links() {
        let artifacts = vec![
            artifact(
                "fleet_event",
                "evt-1",
                serde_json::json!({
                    "timestamp": "2026-03-06T12:00:00Z",
                    "principalId": "pr-1",
                    "responseActionId": "ra-1",
                    "source": "tetragon"
                }),
            ),
            artifact(
                "response_action",
                "ra-1",
                serde_json::json!({
                    "timestamp": "2026-03-06T12:01:00Z",
                    "principalId": "pr-1"
                }),
            ),
            artifact(
                "raw_envelope",
                "env-1",
                serde_json::json!({
                    "timestamp": "2026-03-06T12:00:00Z",
                    "source": "tetragon"
                }),
            ),
        ];

        let filtered = filter_artifacts(
            &artifacts,
            &ExportEvidenceBundleRequest {
                start: None,
                end: None,
                principal_ids: Some(vec!["pr-1".to_string()]),
                detection_ids: None,
                response_action_ids: Some(vec!["ra-1".to_string()]),
                source_families: Some(vec!["tetragon".to_string()]),
                include_raw_envelopes: Some(false),
                include_ocsf: Some(false),
                retention_days: None,
            },
        );

        assert_eq!(filtered.len(), 2);
        assert!(filtered
            .iter()
            .any(|artifact| artifact.artifact_id == "evt-1"));
        assert!(filtered
            .iter()
            .any(|artifact| artifact.artifact_id == "ra-1"));
    }

    #[test]
    fn filter_artifacts_expands_trusted_detection_and_response_closure() {
        let artifacts = vec![
            artifact(
                "detection",
                "det-1",
                serde_json::json!({
                    "timestamp": "2026-03-06T12:00:00Z",
                    "principalId": "pr-1",
                    "detectionId": "det-1",
                    "responseActionIds": ["ra-1"],
                    "evidenceRefs": ["env-1"]
                }),
            ),
            artifact(
                "response_action",
                "ra-1",
                serde_json::json!({
                    "timestamp": "2026-03-06T12:01:00Z",
                    "principalId": "pr-1",
                    "responseActionId": "ra-1",
                    "detectionId": "det-1"
                }),
            ),
            artifact(
                "fleet_event",
                "evt-1",
                serde_json::json!({
                    "timestamp": "2026-03-06T12:02:00Z",
                    "principalId": "pr-1",
                    "responseActionId": "ra-1",
                    "detectionIds": ["det-1"],
                    "rawRef": "env-1",
                    "source": "tetragon"
                }),
            ),
            artifact(
                "raw_envelope",
                "env-1",
                serde_json::json!({
                    "timestamp": "2026-03-06T12:02:00Z",
                    "rawRef": "env-1",
                    "source": "tetragon"
                }),
            ),
        ];

        let filtered = filter_artifacts(
            &artifacts,
            &ExportEvidenceBundleRequest {
                start: None,
                end: None,
                principal_ids: Some(vec!["pr-1".to_string()]),
                detection_ids: Some(vec!["det-1".to_string()]),
                response_action_ids: Some(vec!["ra-1".to_string()]),
                source_families: Some(vec!["tetragon".to_string()]),
                include_raw_envelopes: Some(true),
                include_ocsf: Some(false),
                retention_days: None,
            },
        );

        assert_eq!(filtered.len(), 4);
        assert!(filtered
            .iter()
            .any(|artifact| artifact.artifact_id == "det-1"));
        assert!(filtered
            .iter()
            .any(|artifact| artifact.artifact_id == "ra-1"));
        assert!(filtered
            .iter()
            .any(|artifact| artifact.artifact_id == "evt-1"));
        assert!(filtered
            .iter()
            .any(|artifact| artifact.artifact_id == "env-1"));
    }

    #[test]
    fn bundle_has_expired_when_retention_deadline_passes() {
        let bundle = FleetEvidenceBundle {
            export_id: "exp-1".to_string(),
            tenant_id: Uuid::new_v4(),
            case_id: None,
            status: "completed".to_string(),
            requested_by: "operator".to_string(),
            requested_at: Utc::now(),
            completed_at: Some(Utc::now()),
            file_path: Some("/tmp/fleet-evidence.zip".to_string()),
            sha256: None,
            size_bytes: None,
            manifest_ref: None,
            expires_at: Some(Utc::now() - Duration::seconds(1)),
            retention_days: 1,
            filters: serde_json::json!({}),
            artifact_counts: serde_json::json!({}),
            metadata: serde_json::json!({}),
        };

        assert!(bundle_has_expired(&bundle, Utc::now()));
    }
}
