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
use sqlx::query_builder::QueryBuilder;
use sqlx::row::Row;
use sqlx_postgres::Postgres;
use uuid::Uuid;

use crate::db::PgPool;
use crate::error::ApiError;
use crate::models::hunt::StoredSearchCursor;

pub async fn ingest_event(
    db: &PgPool,
    tenant_id: Uuid,
    event: FleetEventEnvelope,
    raw_envelope: Value,
    trusted_signing_keypair: Option<&hush_core::Keypair>,
) -> Result<HuntEvent, ApiError> {
    let trusted_issuer = trusted_hunt_issuer(trusted_signing_keypair)?;
    let (verified_event, envelope_issuer) =
        verify_signed_hunt_envelope(&raw_envelope, &trusted_issuer)?;
    if verified_event != event {
        return Err(ApiError::BadRequest(
            "event must match the signed rawEnvelope fact".to_string(),
        ));
    }
    let event = verified_event;
    let event_tenant_id = Uuid::parse_str(&event.tenant_id)
        .map_err(|_| ApiError::BadRequest("event.tenantId must be a UUID".to_string()))?;
    if event_tenant_id != tenant_id {
        return Err(ApiError::BadRequest(
            "event.tenantId must match authenticated tenant".to_string(),
        ));
    }

    let occurred_at = DateTime::parse_from_rfc3339(&event.occurred_at)
        .map_err(|_| ApiError::BadRequest("event.occurredAt must be RFC3339".to_string()))?
        .with_timezone(&Utc);
    let ingested_at = DateTime::parse_from_rfc3339(&event.ingested_at)
        .map_err(|_| ApiError::BadRequest("event.ingestedAt must be RFC3339".to_string()))?
        .with_timezone(&Utc);

    let envelope_row = sqlx::query::query(
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
           DO UPDATE SET
               source = EXCLUDED.source,
               issuer = EXCLUDED.issuer,
               issued_at = EXCLUDED.issued_at,
               ingested_at = EXCLUDED.ingested_at,
               envelope_hash = EXCLUDED.envelope_hash,
               schema_name = EXCLUDED.schema_name,
               raw_envelope = EXCLUDED.raw_envelope,
               signature_valid = EXCLUDED.signature_valid
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(fleet_source_to_str(event.source))
    .bind(Some(envelope_issuer.as_str()))
    .bind(occurred_at)
    .bind(ingested_at)
    .bind(event.evidence.envelope_hash.as_deref())
    .bind(event.evidence.schema_name.as_deref())
    .bind(&event.evidence.raw_ref)
    .bind(raw_envelope.clone())
    .bind(Some(true))
    .fetch_one(db)
    .await
    .map_err(ApiError::Database)?;
    let envelope_id: Uuid = envelope_row.try_get("id").map_err(ApiError::Database)?;

    sqlx::query::query(
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
           DO UPDATE SET
               envelope_id = EXCLUDED.envelope_id,
               source = EXCLUDED.source,
               kind = EXCLUDED.kind,
               timestamp = EXCLUDED.timestamp,
               ingested_at = EXCLUDED.ingested_at,
               verdict = EXCLUDED.verdict,
               severity = EXCLUDED.severity,
               summary = EXCLUDED.summary,
               action_type = EXCLUDED.action_type,
               process = EXCLUDED.process,
               namespace = EXCLUDED.namespace,
               pod = EXCLUDED.pod,
               session_id = EXCLUDED.session_id,
               endpoint_agent_id = EXCLUDED.endpoint_agent_id,
               runtime_agent_id = EXCLUDED.runtime_agent_id,
               principal_id = EXCLUDED.principal_id,
               grant_id = EXCLUDED.grant_id,
               response_action_id = EXCLUDED.response_action_id,
               detection_ids = EXCLUDED.detection_ids,
               target_kind = EXCLUDED.target_kind,
               target_id = EXCLUDED.target_id,
               target_name = EXCLUDED.target_name,
               envelope_hash = EXCLUDED.envelope_hash,
               issuer = EXCLUDED.issuer,
               schema_name = EXCLUDED.schema_name,
               signature_valid = EXCLUDED.signature_valid,
               raw_ref = EXCLUDED.raw_ref,
               attributes = EXCLUDED.attributes"#,
    )
    .bind(&event.event_id)
    .bind(tenant_id)
    .bind(envelope_id)
    .bind(fleet_source_to_str(event.source))
    .bind(fleet_kind_to_str(event.kind))
    .bind(occurred_at)
    .bind(ingested_at)
    .bind(fleet_verdict_to_str(event.verdict).unwrap_or("none"))
    .bind(event.severity.map(fleet_severity_to_str))
    .bind(&event.summary)
    .bind(event.action_type.as_deref())
    .bind(event.attributes.get("process").and_then(Value::as_str))
    .bind(event.attributes.get("namespace").and_then(Value::as_str))
    .bind(event.attributes.get("pod").and_then(Value::as_str))
    .bind(event.session_id.as_deref())
    .bind(
        event
            .principal
            .as_ref()
            .and_then(|principal| principal.endpoint_agent_id.as_deref()),
    )
    .bind(
        event
            .principal
            .as_ref()
            .and_then(|principal| principal.runtime_agent_id.as_deref()),
    )
    .bind(
        event
            .principal
            .as_ref()
            .and_then(|principal| principal.principal_id.as_deref()),
    )
    .bind(event.grant_id.as_deref())
    .bind(event.response_action_id.as_deref())
    .bind(&event.detection_ids)
    .bind(
        event
            .target
            .as_ref()
            .and_then(|target| target.kind.as_deref()),
    )
    .bind(
        event
            .target
            .as_ref()
            .and_then(|target| target.id.as_deref()),
    )
    .bind(
        event
            .target
            .as_ref()
            .and_then(|target| target.name.as_deref()),
    )
    .bind(event.evidence.envelope_hash.as_deref())
    .bind(Some(envelope_issuer.as_str()))
    .bind(event.evidence.schema_name.as_deref())
    .bind(Some(true))
    .bind(&event.evidence.raw_ref)
    .bind(&event.attributes)
    .execute(db)
    .await
    .map_err(ApiError::Database)?;

    get_event(db, tenant_id, &event.event_id).await
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
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    map_event_row(row)
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
