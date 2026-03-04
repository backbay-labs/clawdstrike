//! Endpoint/runtime liveness telemetry endpoints.

use axum::extract::{ConnectInfo, Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::api::v1::V1Error;
use crate::auth::{AuthenticatedActor, Scope};
use crate::authz::require_api_key_scope_or_user_permission;
use crate::rbac::{Action, ResourceType};
use crate::state::{AppState, DaemonEvent};

const DEFAULT_STATUS_LIMIT: usize = 200;
const MAX_STATUS_LIMIT: usize = 1000;
const DEFAULT_STALE_AFTER_SECS: i64 = 90;
const HEARTBEAT_HISTORY_LIMIT: i64 = 50_000;

#[derive(Clone, Debug, Deserialize)]
pub struct AgentHeartbeatRequest {
    pub endpoint_agent_id: String,
    #[serde(default)]
    pub runtime_agent_id: Option<String>,
    #[serde(default)]
    pub runtime_agent_kind: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub posture: Option<String>,
    #[serde(default)]
    pub policy_version: Option<String>,
    #[serde(default)]
    pub last_policy_version: Option<String>,
    #[serde(default)]
    pub daemon_version: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentHeartbeatResponse {
    pub accepted: bool,
    pub endpoint_agent_id: String,
    pub runtime_agent_id: Option<String>,
    pub runtime_agent_kind: Option<String>,
    pub heartbeat_at: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct AgentStatusQuery {
    pub endpoint_agent_id: Option<String>,
    pub runtime_agent_id: Option<String>,
    pub runtime_agent_kind: Option<String>,
    pub limit: Option<usize>,
    pub include_stale: Option<bool>,
    pub stale_after_secs: Option<i64>,
    pub expected_policy_version: Option<String>,
    pub expected_daemon_version: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DriftFlags {
    pub policy_drift: bool,
    pub daemon_drift: bool,
    pub stale: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointStatus {
    pub endpoint_agent_id: String,
    pub last_heartbeat_at: String,
    pub last_seen_ip: Option<String>,
    pub last_session_id: Option<String>,
    pub posture: Option<String>,
    pub policy_version: Option<String>,
    pub daemon_version: Option<String>,
    pub runtime_count: usize,
    pub seconds_since_heartbeat: i64,
    pub online: bool,
    pub drift: DriftFlags,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuntimeStatus {
    pub runtime_agent_id: String,
    pub endpoint_agent_id: String,
    pub runtime_agent_kind: String,
    pub last_heartbeat_at: String,
    pub last_session_id: Option<String>,
    pub posture: Option<String>,
    pub policy_version: Option<String>,
    pub daemon_version: Option<String>,
    pub seconds_since_heartbeat: i64,
    pub online: bool,
    pub drift: DriftFlags,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentStatusResponse {
    pub generated_at: String,
    pub stale_after_secs: i64,
    pub endpoints: Vec<EndpointStatus>,
    pub runtimes: Vec<RuntimeStatus>,
}

fn normalized_opt(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn parse_or_now(raw: Option<&str>) -> DateTime<Utc> {
    let Some(raw) = raw else {
        return Utc::now();
    };
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn seconds_since_heartbeat(last_heartbeat_at: &str) -> i64 {
    let Some(parsed) = DateTime::parse_from_rfc3339(last_heartbeat_at)
        .ok()
        .map(|value| value.with_timezone(&Utc))
    else {
        return i64::MAX / 4;
    };
    (Utc::now() - parsed).num_seconds().max(0)
}

fn require_service_principal(actor: Option<&AuthenticatedActor>) -> Result<(), V1Error> {
    if matches!(actor, Some(AuthenticatedActor::User(_))) {
        return Err(V1Error::forbidden(
            "SERVICE_PRINCIPAL_REQUIRED",
            "service_principal_required",
        ));
    }
    Ok(())
}

/// POST /api/v1/agent/heartbeat
pub async fn ingest_agent_heartbeat(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(request): Json<AgentHeartbeatRequest>,
) -> Result<Json<AgentHeartbeatResponse>, V1Error> {
    require_service_principal(actor.as_ref().map(|e| &e.0))?;

    let endpoint_agent_id =
        normalized_opt(Some(request.endpoint_agent_id.as_str())).ok_or_else(|| {
            V1Error::bad_request(
                "INVALID_HEARTBEAT",
                "endpoint_agent_id must be a non-empty string",
            )
        })?;
    let runtime_agent_id = normalized_opt(request.runtime_agent_id.as_deref());
    let runtime_agent_kind = normalized_opt(request.runtime_agent_kind.as_deref())
        .map(|value| value.to_ascii_lowercase());
    if runtime_agent_id.is_some() ^ runtime_agent_kind.is_some() {
        return Err(V1Error::bad_request(
            "INVALID_HEARTBEAT",
            "runtime_agent_id and runtime_agent_kind must be provided together",
        ));
    }

    let heartbeat_at = parse_or_now(request.timestamp.as_deref()).to_rfc3339();
    let source_ip = Some(addr.ip().to_string());
    let session_id = normalized_opt(request.session_id.as_deref());
    let posture = normalized_opt(request.posture.as_deref());
    let policy_version = normalized_opt(request.policy_version.as_deref())
        .or_else(|| normalized_opt(request.last_policy_version.as_deref()));
    let daemon_version = normalized_opt(request.daemon_version.as_deref());

    let db = state.control_db.clone();
    let endpoint_for_db = endpoint_agent_id.clone();
    let heartbeat_for_db = heartbeat_at.clone();
    let runtime_id_for_db = runtime_agent_id.clone();
    let runtime_kind_for_db = runtime_agent_kind.clone();
    let session_for_db = session_id.clone();
    let posture_for_db = posture.clone();
    let policy_for_db = policy_version.clone();
    let daemon_for_db = daemon_version.clone();
    let source_ip_for_db = source_ip.clone();
    db.spawn_blocking(move |conn| {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            r#"
            INSERT INTO endpoint_liveness (
              endpoint_agent_id,
              last_heartbeat_at,
              last_seen_ip,
              last_session_id,
              posture,
              policy_version,
              daemon_version,
              updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(endpoint_agent_id) DO UPDATE SET
              last_heartbeat_at = excluded.last_heartbeat_at,
              last_seen_ip = excluded.last_seen_ip,
              last_session_id = excluded.last_session_id,
              posture = excluded.posture,
              policy_version = excluded.policy_version,
              daemon_version = excluded.daemon_version,
              updated_at = excluded.updated_at
            "#,
            params![
                endpoint_for_db,
                heartbeat_for_db,
                source_ip_for_db,
                session_for_db,
                posture_for_db,
                policy_for_db,
                daemon_for_db,
                now,
            ],
        )?;

        if let (Some(runtime_id), Some(runtime_kind)) =
            (runtime_id_for_db.as_ref(), runtime_kind_for_db.as_ref())
        {
            conn.execute(
                r#"
                INSERT INTO runtime_liveness (
                  runtime_agent_id,
                  endpoint_agent_id,
                  runtime_agent_kind,
                  last_heartbeat_at,
                  last_session_id,
                  posture,
                  policy_version,
                  daemon_version,
                  updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(runtime_agent_id) DO UPDATE SET
                  endpoint_agent_id = excluded.endpoint_agent_id,
                  runtime_agent_kind = excluded.runtime_agent_kind,
                  last_heartbeat_at = excluded.last_heartbeat_at,
                  last_session_id = excluded.last_session_id,
                  posture = excluded.posture,
                  policy_version = excluded.policy_version,
                  daemon_version = excluded.daemon_version,
                  updated_at = excluded.updated_at
                "#,
                params![
                    runtime_id,
                    endpoint_for_db,
                    runtime_kind,
                    heartbeat_for_db,
                    session_for_db,
                    posture_for_db,
                    policy_for_db,
                    daemon_for_db,
                    now,
                ],
            )?;
        }

        let runtime_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM runtime_liveness WHERE endpoint_agent_id = ?1",
            params![endpoint_for_db],
            |row| row.get(0),
        )?;
        conn.execute(
            "UPDATE endpoint_liveness SET runtime_count = ?1 WHERE endpoint_agent_id = ?2",
            params![runtime_count, endpoint_for_db],
        )?;

        conn.execute(
            r#"
            INSERT INTO heartbeat_history (
              endpoint_agent_id,
              runtime_agent_id,
              runtime_agent_kind,
              session_id,
              posture,
              policy_version,
              daemon_version,
              heartbeat_at,
              source_ip
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                endpoint_for_db,
                runtime_id_for_db,
                runtime_kind_for_db,
                session_for_db,
                posture_for_db,
                policy_for_db,
                daemon_for_db,
                heartbeat_for_db,
                source_ip_for_db,
            ],
        )?;

        conn.execute(
            "DELETE FROM heartbeat_history WHERE id NOT IN (SELECT id FROM heartbeat_history ORDER BY id DESC LIMIT ?1)",
            params![HEARTBEAT_HISTORY_LIMIT],
        )?;

        Ok(())
    })
    .await
    .map_err(|err| V1Error::internal("HEARTBEAT_PERSIST_ERROR", err.to_string()))?;

    state.broadcast(DaemonEvent {
        event_type: "agent_heartbeat".to_string(),
        data: serde_json::json!({
            "endpoint_agent_id": endpoint_agent_id,
            "runtime_agent_id": runtime_agent_id,
            "runtime_agent_kind": runtime_agent_kind,
            "session_id": session_id,
            "posture": posture,
            "policy_version": policy_version,
            "daemon_version": daemon_version,
            "timestamp": heartbeat_at,
        }),
    });

    Ok(Json(AgentHeartbeatResponse {
        accepted: true,
        endpoint_agent_id,
        runtime_agent_id,
        runtime_agent_kind,
        heartbeat_at,
    }))
}

/// GET /api/v1/agents/status
pub async fn list_agent_status(
    State(state): State<AppState>,
    Query(query): Query<AgentStatusQuery>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<AgentStatusResponse>, V1Error> {
    require_api_key_scope_or_user_permission(
        actor.as_ref().map(|e| &e.0),
        &state.rbac,
        Scope::Read,
        ResourceType::AuditLog,
        Action::Read,
    )?;

    let limit = query
        .limit
        .unwrap_or(DEFAULT_STATUS_LIMIT)
        .min(MAX_STATUS_LIMIT);
    let include_stale = query.include_stale.unwrap_or(true);
    let stale_after_secs = query
        .stale_after_secs
        .unwrap_or(DEFAULT_STALE_AFTER_SECS)
        .max(10);
    let expected_policy = normalized_opt(query.expected_policy_version.as_deref());
    let expected_daemon = normalized_opt(query.expected_daemon_version.as_deref());

    let endpoint_filter = normalized_opt(query.endpoint_agent_id.as_deref());
    let runtime_id_filter = normalized_opt(query.runtime_agent_id.as_deref());
    let runtime_kind_filter =
        normalized_opt(query.runtime_agent_kind.as_deref()).map(|value| value.to_ascii_lowercase());

    let db = state.control_db.clone();
    let records = db
        .spawn_blocking(move |conn| {
            let mut endpoint_sql = String::from(
                r#"
                SELECT endpoint_agent_id, last_heartbeat_at, last_seen_ip, last_session_id,
                       posture, policy_version, daemon_version, runtime_count
                FROM endpoint_liveness
                "#,
            );
            if endpoint_filter.is_some() {
                endpoint_sql.push_str(" WHERE endpoint_agent_id = ?");
            }
            endpoint_sql.push_str(" ORDER BY last_heartbeat_at DESC LIMIT ?");
            let mut endpoint_stmt = conn.prepare(&endpoint_sql)?;
            let endpoint_rows = if let Some(endpoint) = endpoint_filter.as_ref() {
                let mut rows = endpoint_stmt
                    .query(params![endpoint, i64::try_from(limit).unwrap_or(i64::MAX)])?;
                let mut out = Vec::new();
                while let Some(row) = rows.next()? {
                    out.push((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, i64>(7)?,
                    ));
                }
                out
            } else {
                let mut rows =
                    endpoint_stmt.query(params![i64::try_from(limit).unwrap_or(i64::MAX)])?;
                let mut out = Vec::new();
                while let Some(row) = rows.next()? {
                    out.push((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, i64>(7)?,
                    ));
                }
                out
            };

            let mut runtime_sql = String::from(
                r#"
                SELECT runtime_agent_id, endpoint_agent_id, runtime_agent_kind,
                       last_heartbeat_at, last_session_id, posture, policy_version, daemon_version
                FROM runtime_liveness
                WHERE 1=1
                "#,
            );
            let mut runtime_params: Vec<String> = Vec::new();
            if let Some(endpoint) = endpoint_filter.as_ref() {
                runtime_sql.push_str(" AND endpoint_agent_id = ?");
                runtime_params.push(endpoint.clone());
            }
            if let Some(runtime_id) = runtime_id_filter.as_ref() {
                runtime_sql.push_str(" AND runtime_agent_id = ?");
                runtime_params.push(runtime_id.clone());
            }
            if let Some(runtime_kind) = runtime_kind_filter.as_ref() {
                runtime_sql.push_str(" AND runtime_agent_kind = ?");
                runtime_params.push(runtime_kind.clone());
            }
            runtime_sql.push_str(" ORDER BY last_heartbeat_at DESC LIMIT ?");

            let mut stmt = conn.prepare(&runtime_sql)?;
            let mut params_dyn: Vec<&dyn rusqlite::ToSql> = runtime_params
                .iter()
                .map(|value| value as &dyn rusqlite::ToSql)
                .collect();
            let limit_sql = i64::try_from(limit).unwrap_or(i64::MAX);
            params_dyn.push(&limit_sql);
            let mut rows = stmt.query(params_dyn.as_slice())?;
            let mut runtime_rows = Vec::new();
            while let Some(row) = rows.next()? {
                runtime_rows.push((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ));
            }

            Ok((endpoint_rows, runtime_rows))
        })
        .await
        .map_err(|err| V1Error::internal("AGENT_STATUS_QUERY_ERROR", err.to_string()))?;

    let mut endpoints = Vec::new();
    for (
        endpoint_agent_id,
        last_heartbeat_at,
        last_seen_ip,
        last_session_id,
        posture,
        policy_version,
        daemon_version,
        runtime_count,
    ) in records.0
    {
        let seconds = seconds_since_heartbeat(&last_heartbeat_at);
        let online = seconds <= stale_after_secs;
        let drift = DriftFlags {
            policy_drift: expected_policy.as_ref().is_some_and(|expected| {
                policy_version
                    .as_ref()
                    .is_some_and(|value| value != expected)
            }),
            daemon_drift: expected_daemon.as_ref().is_some_and(|expected| {
                daemon_version
                    .as_ref()
                    .is_some_and(|value| value != expected)
            }),
            stale: !online,
        };
        if !include_stale && drift.stale {
            continue;
        }
        endpoints.push(EndpointStatus {
            endpoint_agent_id,
            last_heartbeat_at,
            last_seen_ip,
            last_session_id,
            posture,
            policy_version,
            daemon_version,
            runtime_count: usize::try_from(runtime_count.max(0)).unwrap_or(0),
            seconds_since_heartbeat: seconds,
            online,
            drift,
        });
    }

    let mut runtimes = Vec::new();
    for (
        runtime_agent_id,
        endpoint_agent_id,
        runtime_agent_kind,
        last_heartbeat_at,
        last_session_id,
        posture,
        policy_version,
        daemon_version,
    ) in records.1
    {
        let seconds = seconds_since_heartbeat(&last_heartbeat_at);
        let online = seconds <= stale_after_secs;
        let drift = DriftFlags {
            policy_drift: expected_policy.as_ref().is_some_and(|expected| {
                policy_version
                    .as_ref()
                    .is_some_and(|value| value != expected)
            }),
            daemon_drift: expected_daemon.as_ref().is_some_and(|expected| {
                daemon_version
                    .as_ref()
                    .is_some_and(|value| value != expected)
            }),
            stale: !online,
        };
        if !include_stale && drift.stale {
            continue;
        }
        runtimes.push(RuntimeStatus {
            runtime_agent_id,
            endpoint_agent_id,
            runtime_agent_kind,
            last_heartbeat_at,
            last_session_id,
            posture,
            policy_version,
            daemon_version,
            seconds_since_heartbeat: seconds,
            online,
            drift,
        });
    }

    Ok(Json(AgentStatusResponse {
        generated_at: Utc::now().to_rfc3339(),
        stale_after_secs,
        endpoints,
        runtimes,
    }))
}
