use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgPool;
use crate::error::ApiError;
use crate::models::console::{
    ConsoleActiveGrant, ConsoleCounts, ConsoleDetectionListItem, ConsoleEffectivePolicy,
    ConsoleGraphEdge, ConsoleGraphNode, ConsoleGraphNodeKind, ConsoleGraphView,
    ConsoleLivenessSummaryItem, ConsoleMembership, ConsolePolicySourceAttachment,
    ConsolePostureSummaryItem, ConsolePrincipalDetail, ConsolePrincipalListItem,
    ConsolePrincipalListQuery, ConsoleRecentSession, ConsoleResponseActionListItem,
    ConsoleResponseActionListQuery, ConsoleStreamEvent, ConsoleStreamEventKind,
    ConsoleTimelineEvent, ConsoleTimelineQuery, FleetConsoleOverview,
};
use crate::services::policy_distribution;
use crate::services::principal_resolution;

const DEFAULT_LIST_LIMIT: i64 = 100;
const MAX_LIST_LIMIT: i64 = 500;
const INDEFINITE_GRANT_EXPIRY: &str = "9999-12-31T23:59:59Z";

#[derive(Debug, Clone)]
struct PrincipalBaseRow {
    id: Uuid,
    principal_type: String,
    display_name: String,
    stable_ref: String,
    lifecycle_state: String,
    liveness_state: Option<String>,
    trust_level: String,
    principal_metadata: Value,
    agent_id: Option<String>,
    last_heartbeat_at: Option<DateTime<Utc>>,
    agent_metadata: Option<Value>,
    open_response_action_count: i64,
}

#[derive(Debug, Clone, Default)]
struct PrincipalMembershipScope {
    memberships: Vec<ConsoleMembership>,
    swarm_names: Vec<String>,
    project_names: Vec<String>,
    capability_group_names: Vec<String>,
    swarm_ids: HashSet<Uuid>,
    project_ids: HashSet<Uuid>,
    capability_group_ids: HashSet<Uuid>,
}

#[derive(Debug, Clone)]
struct ResolvedEffectivePolicy {
    effective_policy: ConsoleEffectivePolicy,
    compiled_policy_yaml: Option<String>,
    source_attachments: Option<Vec<ConsolePolicySourceAttachment>>,
}

struct PrincipalDetailContext {
    principal: PrincipalBaseRow,
    principal_item: ConsolePrincipalListItem,
    scope: PrincipalMembershipScope,
    policy: ResolvedEffectivePolicy,
    active_grants: Vec<ConsoleActiveGrant>,
    recent_sessions: Vec<ConsoleRecentSession>,
}

struct TimelineQueryContext {
    principal_aliases: Vec<String>,
    filter_principal: bool,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    limit: i64,
}

#[derive(Debug, Clone)]
struct PolicyAttachmentRow {
    id: Uuid,
    target_kind: String,
    target_id: Option<Uuid>,
    priority: i32,
    policy_ref: Option<String>,
    policy_yaml: Option<String>,
    checksum_sha256: Option<String>,
}

impl PolicyAttachmentRow {
    fn from_row(row: sqlx_postgres::PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            target_kind: row.try_get("target_kind")?,
            target_id: row.try_get("target_id")?,
            priority: row.try_get("priority")?,
            policy_ref: row.try_get("policy_ref")?,
            policy_yaml: row.try_get("policy_yaml")?,
            checksum_sha256: row.try_get("checksum_sha256")?,
        })
    }

    fn matches(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        scope: &PrincipalMembershipScope,
    ) -> bool {
        match self.target_kind.as_str() {
            "tenant" => self.target_id.is_none(),
            "swarm" => self
                .target_id
                .is_some_and(|id| scope.swarm_ids.contains(&id)),
            "project" => self
                .target_id
                .is_some_and(|id| scope.project_ids.contains(&id)),
            "capability_group" => self
                .target_id
                .is_some_and(|id| scope.capability_group_ids.contains(&id)),
            "principal" => self.target_id == Some(principal_id),
            _ => self.target_id == Some(tenant_id) && self.target_kind == "tenant",
        }
    }

    fn resolved_policy_yaml(&self) -> Result<Option<&str>, ApiError> {
        match (self.policy_yaml.as_deref(), self.policy_ref.as_deref()) {
            (Some(policy_yaml), _) => Ok(Some(policy_yaml)),
            (None, Some(policy_ref)) => Err(ApiError::Conflict(format!(
                "policy attachment {} references unresolved policy_ref `{policy_ref}`",
                self.id
            ))),
            (None, None) => Ok(None),
        }
    }
}

pub async fn overview(db: &PgPool, tenant_id: Uuid) -> Result<FleetConsoleOverview, ApiError> {
    let counts_row = sqlx::query::query(
        r#"SELECT
               (SELECT COUNT(*)::bigint FROM principals WHERE tenant_id = $1) AS principals,
               (SELECT COUNT(*)::bigint FROM agents WHERE tenant_id = $1) AS endpoint_agents,
               (SELECT COUNT(DISTINCT runtime_agent_id)::bigint
                  FROM hunt_events
                 WHERE tenant_id = $1
                   AND runtime_agent_id IS NOT NULL) AS runtime_agents,
               (SELECT COUNT(*)::bigint FROM swarms WHERE tenant_id = $1) AS swarms,
               (SELECT COUNT(*)::bigint FROM projects WHERE tenant_id = $1) AS projects,
               (SELECT COUNT(*)::bigint
                  FROM principals
                 WHERE tenant_id = $1
                   AND lifecycle_state = 'quarantined') AS quarantined_principals,
               (SELECT COUNT(*)::bigint
                  FROM principals
                 WHERE tenant_id = $1
                   AND liveness_state = 'stale') AS stale_principals,
               (SELECT COUNT(*)::bigint
                  FROM response_actions
                 WHERE tenant_id = $1
                   AND status IN ('queued', 'approved', 'published')) AS active_response_actions,
               (SELECT COUNT(*)::bigint
                  FROM detection_findings
                 WHERE tenant_id = $1
                   AND status = 'open') AS open_detections"#,
    )
    .bind(tenant_id)
    .fetch_one(db)
    .await
    .map_err(ApiError::Database)?;

    let posture_rows = sqlx::query::query(
        r#"SELECT lifecycle_state, COUNT(*)::bigint AS count
           FROM principals
           WHERE tenant_id = $1
           GROUP BY lifecycle_state
           ORDER BY lifecycle_state ASC"#,
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let liveness_rows = sqlx::query::query(
        r#"SELECT COALESCE(liveness_state, 'unknown') AS liveness_state,
                  COUNT(*)::bigint AS count
           FROM principals
           WHERE tenant_id = $1
           GROUP BY COALESCE(liveness_state, 'unknown')
           ORDER BY COALESCE(liveness_state, 'unknown') ASC"#,
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    Ok(FleetConsoleOverview {
        tenant_id: tenant_id.to_string(),
        generated_at: Utc::now(),
        counts: ConsoleCounts {
            principals: counts_row
                .try_get("principals")
                .map_err(ApiError::Database)?,
            endpoint_agents: counts_row
                .try_get("endpoint_agents")
                .map_err(ApiError::Database)?,
            runtime_agents: counts_row
                .try_get("runtime_agents")
                .map_err(ApiError::Database)?,
            swarms: counts_row.try_get("swarms").map_err(ApiError::Database)?,
            projects: counts_row.try_get("projects").map_err(ApiError::Database)?,
            quarantined_principals: counts_row
                .try_get("quarantined_principals")
                .map_err(ApiError::Database)?,
            stale_principals: counts_row
                .try_get("stale_principals")
                .map_err(ApiError::Database)?,
            active_response_actions: counts_row
                .try_get("active_response_actions")
                .map_err(ApiError::Database)?,
            open_detections: counts_row
                .try_get("open_detections")
                .map_err(ApiError::Database)?,
        },
        posture_summary: posture_rows
            .into_iter()
            .map(|row| {
                Ok(ConsolePostureSummaryItem {
                    lifecycle_state: row.try_get("lifecycle_state").map_err(ApiError::Database)?,
                    count: row.try_get("count").map_err(ApiError::Database)?,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
        liveness_summary: liveness_rows
            .into_iter()
            .map(|row| {
                Ok(ConsoleLivenessSummaryItem {
                    liveness_state: normalize_liveness_state(
                        row.try_get::<Option<String>, _>("liveness_state")
                            .map_err(ApiError::Database)?
                            .as_deref(),
                    ),
                    count: row.try_get("count").map_err(ApiError::Database)?,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
        recent_response_actions: list_response_actions_with_limit(db, tenant_id, None, None, 10)
            .await?,
        recent_detections: list_recent_detections(db, tenant_id, 10).await?,
    })
}

pub async fn list_principals(
    db: &PgPool,
    tenant_id: Uuid,
    query: &ConsolePrincipalListQuery,
) -> Result<Vec<ConsolePrincipalListItem>, ApiError> {
    let principals = load_principal_rows(db, tenant_id, query).await?;
    let principal_ids = principals.iter().map(|row| row.id).collect::<Vec<_>>();
    let membership_map = load_membership_scope_map(db, tenant_id, &principal_ids).await?;

    Ok(principals
        .into_iter()
        .map(|row| {
            let scope = membership_map.get(&row.id).cloned().unwrap_or_default();
            principal_list_item_from_parts(&row, &scope)
        })
        .collect())
}

pub async fn get_principal_detail(
    db: &PgPool,
    tenant_id: Uuid,
    principal_identifier: &str,
) -> Result<ConsolePrincipalDetail, ApiError> {
    let context = load_principal_detail_context(db, tenant_id, principal_identifier).await?;

    Ok(ConsolePrincipalDetail {
        principal: context.principal_item,
        metadata: merge_metadata_values(
            &context.principal.principal_metadata,
            context.principal.agent_metadata.as_ref(),
        ),
        memberships: context.scope.memberships,
        effective_policy: context.policy.effective_policy,
        active_grants: context.active_grants,
        recent_sessions: context.recent_sessions,
        compiled_policy_yaml: context.policy.compiled_policy_yaml,
        source_attachments: context.policy.source_attachments,
    })
}

pub async fn list_timeline_events(
    db: &PgPool,
    tenant_id: Uuid,
    principal_id: Option<&str>,
    query: &ConsoleTimelineQuery,
) -> Result<Vec<ConsoleTimelineEvent>, ApiError> {
    let context = resolve_timeline_query_context(db, tenant_id, principal_id, query).await?;

    let rows = sqlx::query::query(
        r#"SELECT event_id,
                  timestamp,
                  tenant_id,
                  principal_id,
                  session_id,
                  grant_id,
                  kind,
                  action_type,
                  severity,
                  verdict,
                  summary,
                  source,
                  endpoint_agent_id,
                  runtime_agent_id,
                  response_action_id,
                  detection_ids,
                  target_kind,
                  target_id,
                  target_name,
                  attributes
           FROM hunt_events
           WHERE tenant_id = $1
             AND ($2 = false OR principal_id = ANY($3))
             AND ($4::timestamptz IS NULL OR timestamp >= $4)
             AND ($5::timestamptz IS NULL OR timestamp <= $5)
           ORDER BY timestamp DESC, event_id DESC
           LIMIT $6"#,
    )
    .bind(tenant_id)
    .bind(context.filter_principal)
    .bind(&context.principal_aliases)
    .bind(context.from)
    .bind(context.to)
    .bind(context.limit)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter().map(map_timeline_row).collect()
}

pub async fn list_response_actions(
    db: &PgPool,
    tenant_id: Uuid,
    query: &ConsoleResponseActionListQuery,
) -> Result<Vec<ConsoleResponseActionListItem>, ApiError> {
    list_response_actions_with_limit(
        db,
        tenant_id,
        query.status.as_deref(),
        query.target_kind.as_deref(),
        normalize_limit(query.limit),
    )
    .await
}

pub fn build_principal_graph_from_detail(detail: &ConsolePrincipalDetail) -> ConsoleGraphView {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut seen_nodes = HashSet::new();

    push_graph_node(
        &mut nodes,
        &mut seen_nodes,
        ConsoleGraphNode {
            id: detail.principal.principal_id.clone(),
            kind: ConsoleGraphNodeKind::Principal,
            label: detail.principal.display_name.clone(),
            state: Some(detail.principal.lifecycle_state.clone()),
        },
    );

    for grant in &detail.active_grants {
        push_graph_node(
            &mut nodes,
            &mut seen_nodes,
            ConsoleGraphNode {
                id: grant.grant_id.clone(),
                kind: ConsoleGraphNodeKind::Grant,
                label: grant.subject_principal_id.clone(),
                state: Some(grant.status.clone()),
            },
        );
        edges.push(ConsoleGraphEdge {
            id: format!("grant-{}", grant.grant_id),
            from: detail.principal.principal_id.clone(),
            to: grant.grant_id.clone(),
            kind: "holds_grant".to_string(),
        });
    }

    for session in &detail.recent_sessions {
        push_graph_node(
            &mut nodes,
            &mut seen_nodes,
            ConsoleGraphNode {
                id: session.session_id.clone(),
                kind: ConsoleGraphNodeKind::Session,
                label: session.session_id.clone(),
                state: session.posture.clone(),
            },
        );
        edges.push(ConsoleGraphEdge {
            id: format!("session-{}", session.session_id),
            from: detail.principal.principal_id.clone(),
            to: session.session_id.clone(),
            kind: "started_session".to_string(),
        });
    }

    ConsoleGraphView {
        root_principal_id: detail.principal.principal_id.clone(),
        nodes,
        edges,
        generated_at: Utc::now(),
    }
}

pub fn normalize_console_stream_event(payload: Value, tenant_id: Uuid) -> ConsoleStreamEvent {
    if let Some(object) = payload.as_object() {
        if let Some(kind) = parse_console_stream_kind(string_field(object, &["kind"])) {
            return build_console_stream_event(kind, payload.clone(), tenant_id);
        }

        if let Some(fact) = object.get("fact").cloned() {
            let mut projected = normalize_console_stream_event(fact, tenant_id);
            if let Some(envelope_hash) = string_field(object, &["envelope_hash"]) {
                if projected.id.starts_with("console-stream-") {
                    projected.id = envelope_hash;
                }
            }
            if let Some(issued_at) = string_field(object, &["issued_at"]) {
                if let Ok(timestamp) = parse_rfc3339(&issued_at, "issued_at") {
                    projected.timestamp = timestamp;
                }
            }
            projected.payload = payload_object(payload);
            return projected;
        }

        if object.contains_key("eventId") || object.contains_key("event_id") {
            return build_console_stream_event(
                map_fleet_event_kind_to_console(string_field(object, &["kind"])),
                payload,
                tenant_id,
            );
        }

        if let Some(kind) = infer_console_kind_from_fact(object) {
            return build_console_stream_event(kind, payload, tenant_id);
        }
    }

    build_console_stream_event(ConsoleStreamEventKind::TimelineEvent, payload, tenant_id)
}

fn build_console_stream_event(
    kind: ConsoleStreamEventKind,
    payload: Value,
    tenant_id: Uuid,
) -> ConsoleStreamEvent {
    let object = payload.as_object();
    let tenant_id_value = object
        .and_then(|map| string_field(map, &["tenantId", "tenant_id"]))
        .unwrap_or_else(|| tenant_id.to_string());
    let principal_id = object
        .and_then(|map| string_field(map, &["principalId", "principal_id"]))
        .or_else(|| {
            object.and_then(|map| {
                nested_string_field(map, "principal", &["principalId", "principal_id"])
            })
        });
    let session_id = object
        .and_then(|map| string_field(map, &["sessionId", "session_id"]))
        .or_else(|| {
            object.and_then(|map| nested_string_field(map, "payload", &["sessionId", "session_id"]))
        });
    let grant_id = object
        .and_then(|map| string_field(map, &["grantId", "grant_id"]))
        .or_else(|| {
            object.and_then(|map| nested_string_field(map, "payload", &["grantId", "grant_id"]))
        });
    let response_action_id = object
        .and_then(|map| string_field(map, &["responseActionId", "response_action_id"]))
        .or_else(|| {
            object.and_then(|map| {
                nested_string_field(map, "payload", &["responseActionId", "response_action_id"])
            })
        });

    let id = object
        .and_then(|map| {
            string_field(
                map,
                &[
                    "id",
                    "eventId",
                    "event_id",
                    "envelope_hash",
                    "responseActionId",
                    "response_action_id",
                ],
            )
        })
        .unwrap_or_else(|| format!("console-stream-{}", Uuid::new_v4()));

    let timestamp = object
        .and_then(|map| {
            string_field(
                map,
                &[
                    "timestamp",
                    "occurredAt",
                    "occurred_at",
                    "issued_at",
                    "requestedAt",
                    "requested_at",
                ],
            )
        })
        .and_then(|raw| parse_rfc3339(&raw, "timestamp").ok())
        .unwrap_or_else(Utc::now);

    let payload_value =
        if let Some(inner_payload) = object.and_then(|map| map.get("payload").cloned()) {
            payload_object(inner_payload)
        } else {
            payload_object(payload)
        };

    ConsoleStreamEvent {
        id,
        kind,
        tenant_id: tenant_id_value,
        principal_id,
        session_id,
        grant_id,
        response_action_id,
        timestamp,
        payload: payload_value,
    }
}

async fn load_principal_rows(
    db: &PgPool,
    tenant_id: Uuid,
    query: &ConsolePrincipalListQuery,
) -> Result<Vec<PrincipalBaseRow>, ApiError> {
    let query_pattern = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{}%", value.to_lowercase()));

    let rows = sqlx::query::query(
        r#"SELECT p.id,
                  p.principal_type,
                  p.display_name,
                  p.stable_ref,
                  p.lifecycle_state,
                  p.liveness_state,
                  p.trust_level,
                  p.metadata AS principal_metadata,
                  a.agent_id,
                  a.last_heartbeat_at,
                  a.metadata AS agent_metadata,
                  COALESCE(open_actions.open_response_action_count, 0)::bigint
                      AS open_response_action_count
           FROM principals AS p
           LEFT JOIN agents AS a
             ON a.tenant_id = p.tenant_id
            AND a.principal_id = p.id
           LEFT JOIN LATERAL (
               SELECT COUNT(*)::bigint AS open_response_action_count
               FROM response_actions AS ra
               WHERE ra.tenant_id = p.tenant_id
                 AND ra.target_kind = 'principal'
                 AND ra.target_id = p.id::text
                 AND ra.status IN ('queued', 'approved', 'published')
           ) AS open_actions ON TRUE
           WHERE p.tenant_id = $1
             AND ($2::text IS NULL OR p.lifecycle_state = $2)
             AND (
                 $3::text IS NULL
                 OR lower(p.display_name) LIKE $3
                 OR lower(p.stable_ref) LIKE $3
                 OR lower(p.id::text) LIKE $3
             )
           ORDER BY p.display_name ASC, p.id ASC
           LIMIT $4"#,
    )
    .bind(tenant_id)
    .bind(query.lifecycle_state.as_deref())
    .bind(query_pattern.as_deref())
    .bind(normalize_limit(query.limit))
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter().map(map_principal_row).collect()
}

async fn load_principal_detail_context(
    db: &PgPool,
    tenant_id: Uuid,
    principal_identifier: &str,
) -> Result<PrincipalDetailContext, ApiError> {
    let principal = load_principal_by_identifier(db, tenant_id, principal_identifier).await?;
    let membership_map = load_membership_scope_map(db, tenant_id, &[principal.id]).await?;
    let scope = membership_map
        .get(&principal.id)
        .cloned()
        .unwrap_or_default();
    let principal_item = principal_list_item_from_parts(&principal, &scope);
    let policy = resolve_effective_policy(
        db,
        tenant_id,
        principal.id,
        &principal.lifecycle_state,
        &scope,
    )
    .await?;
    let active_grants =
        load_active_grants(db, tenant_id, principal.id, &principal.stable_ref).await?;
    let recent_sessions = load_recent_sessions(
        db,
        tenant_id,
        &principal_item.principal_id,
        &principal.stable_ref,
        principal.agent_id.as_deref(),
        principal.last_heartbeat_at,
        principal_item.endpoint_posture.clone(),
    )
    .await?;

    Ok(PrincipalDetailContext {
        principal,
        principal_item,
        scope,
        policy,
        active_grants,
        recent_sessions,
    })
}

async fn load_principal_by_identifier(
    db: &PgPool,
    tenant_id: Uuid,
    principal_identifier: &str,
) -> Result<PrincipalBaseRow, ApiError> {
    let principal =
        principal_resolution::resolve_principal_identifier(db, tenant_id, principal_identifier)
            .await?;
    load_principal_by_id(db, tenant_id, principal.id)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn load_principal_by_id(
    db: &PgPool,
    tenant_id: Uuid,
    principal_id: Uuid,
) -> Result<Option<PrincipalBaseRow>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT p.id,
                  p.principal_type,
                  p.display_name,
                  p.stable_ref,
                  p.lifecycle_state,
                  p.liveness_state,
                  p.trust_level,
                  p.metadata AS principal_metadata,
                  a.agent_id,
                  a.last_heartbeat_at,
                  a.metadata AS agent_metadata,
                  COALESCE(open_actions.open_response_action_count, 0)::bigint
                      AS open_response_action_count
           FROM principals AS p
           LEFT JOIN agents AS a
             ON a.tenant_id = p.tenant_id
            AND a.principal_id = p.id
           LEFT JOIN LATERAL (
               SELECT COUNT(*)::bigint AS open_response_action_count
               FROM response_actions AS ra
               WHERE ra.tenant_id = p.tenant_id
                 AND ra.target_kind = 'principal'
                 AND ra.target_id = p.id::text
                 AND ra.status IN ('queued', 'approved', 'published')
           ) AS open_actions ON TRUE
           WHERE p.tenant_id = $1
             AND p.id = $2"#,
    )
    .bind(tenant_id)
    .bind(principal_id)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?;

    row.map(map_principal_row).transpose()
}

async fn load_membership_scope_map(
    db: &PgPool,
    tenant_id: Uuid,
    principal_ids: &[Uuid],
) -> Result<HashMap<Uuid, PrincipalMembershipScope>, ApiError> {
    if principal_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = sqlx::query::query(
        r#"SELECT pm.principal_id,
                  pm.target_kind,
                  pm.target_id,
                  pm.role,
                  CASE pm.target_kind
                      WHEN 'swarm' THEN s.name
                      WHEN 'project' THEN pr.name
                      WHEN 'capability_group' THEN cg.name
                      ELSE NULL
                  END AS target_name
           FROM principal_memberships AS pm
           LEFT JOIN swarms AS s
             ON pm.target_kind = 'swarm'
            AND s.id = pm.target_id
           LEFT JOIN projects AS pr
             ON pm.target_kind = 'project'
            AND pr.id = pm.target_id
           LEFT JOIN capability_groups AS cg
             ON pm.target_kind = 'capability_group'
            AND cg.id = pm.target_id
           WHERE pm.tenant_id = $1
             AND pm.principal_id = ANY($2)
           ORDER BY pm.created_at ASC, pm.id ASC"#,
    )
    .bind(tenant_id)
    .bind(principal_ids)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let mut scopes = HashMap::<Uuid, PrincipalMembershipScope>::new();

    for row in rows {
        let principal_id: Uuid = row.try_get("principal_id").map_err(ApiError::Database)?;
        let target_kind: String = row.try_get("target_kind").map_err(ApiError::Database)?;
        let target_id: Uuid = row.try_get("target_id").map_err(ApiError::Database)?;
        let target_name: Option<String> = row.try_get("target_name").map_err(ApiError::Database)?;
        let role: Option<String> = row.try_get("role").map_err(ApiError::Database)?;

        let scope = scopes.entry(principal_id).or_default();
        scope.memberships.push(ConsoleMembership {
            target_kind: target_kind.clone(),
            target_id: target_id.to_string(),
            target_name: target_name.clone(),
            role,
        });

        match target_kind.as_str() {
            "swarm" => {
                scope.swarm_ids.insert(target_id);
                if let Some(name) = target_name {
                    push_unique(&mut scope.swarm_names, name);
                }
            }
            "project" => {
                scope.project_ids.insert(target_id);
                if let Some(name) = target_name {
                    push_unique(&mut scope.project_names, name);
                }
            }
            "capability_group" => {
                scope.capability_group_ids.insert(target_id);
                if let Some(name) = target_name {
                    push_unique(&mut scope.capability_group_names, name);
                }
            }
            _ => {}
        }
    }

    for scope in scopes.values_mut() {
        scope.swarm_names.sort();
        scope.project_names.sort();
        scope.capability_group_names.sort();
    }

    Ok(scopes)
}

async fn resolve_timeline_query_context(
    db: &PgPool,
    tenant_id: Uuid,
    principal_id: Option<&str>,
    query: &ConsoleTimelineQuery,
) -> Result<TimelineQueryContext, ApiError> {
    let effective_principal_id = principal_id.or(query.principal_id.as_deref());
    let from = parse_optional_rfc3339(query.from.as_deref(), "from")?;
    let to = parse_optional_rfc3339(query.to.as_deref(), "to")?;
    let principal_aliases = if let Some(principal_identifier) = effective_principal_id {
        resolve_principal_filter_aliases(db, tenant_id, principal_identifier).await?
    } else {
        Vec::new()
    };

    Ok(TimelineQueryContext {
        filter_principal: effective_principal_id.is_some(),
        principal_aliases,
        from,
        to,
        limit: normalize_limit(query.limit),
    })
}

async fn resolve_effective_policy(
    db: &PgPool,
    tenant_id: Uuid,
    principal_id: Uuid,
    lifecycle_state: &str,
    scope: &PrincipalMembershipScope,
) -> Result<ResolvedEffectivePolicy, ApiError> {
    let active_policy = policy_distribution::fetch_active_policy_by_tenant_id(db, tenant_id)
        .await
        .map_err(ApiError::Database)?;
    let mut compiled = match active_policy.as_ref() {
        Some(policy) => parse_yaml_value(&policy.policy_yaml).map_err(|err| {
            ApiError::Internal(format!("active tenant policy is invalid YAML: {err}"))
        })?,
        None => serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
    };

    let attachment_rows = sqlx::query::query(
        r#"SELECT id,
                  target_kind,
                  target_id,
                  priority,
                  policy_ref,
                  policy_yaml,
                  checksum_sha256,
                  created_at
           FROM policy_attachments
           WHERE tenant_id = $1
           ORDER BY CASE target_kind
                        WHEN 'tenant' THEN 1
                        WHEN 'swarm' THEN 2
                        WHEN 'project' THEN 3
                        WHEN 'capability_group' THEN 4
                        WHEN 'principal' THEN 5
                        ELSE 6
                    END ASC,
                    priority ASC,
                    created_at ASC,
                    id ASC"#,
    )
    .bind(tenant_id)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let mut source_attachments = Vec::new();
    let mut applied_attachment_count = 0_i64;

    for row in attachment_rows {
        let attachment = PolicyAttachmentRow::from_row(row).map_err(ApiError::Database)?;
        if !attachment.matches(tenant_id, principal_id, scope) {
            continue;
        }

        if let Some(policy_yaml) = attachment.resolved_policy_yaml()? {
            let overlay = parse_yaml_value(policy_yaml).map_err(|err| {
                ApiError::Internal(format!(
                    "policy attachment {} contains invalid YAML: {err}",
                    attachment.id
                ))
            })?;
            merge_yaml_value(&mut compiled, overlay);
        }

        source_attachments.push(ConsolePolicySourceAttachment {
            attachment_id: attachment.id.to_string(),
            target_kind: attachment.target_kind.clone(),
            target_id: attachment.target_id.unwrap_or(tenant_id).to_string(),
            priority: attachment.priority,
            policy_ref: attachment.policy_ref.clone(),
            checksum_sha256: attachment.checksum_sha256.clone(),
        });
        applied_attachment_count += 1;
    }

    let applied_overlays = lifecycle_overlay_names(lifecycle_state);
    let compiled_policy_yaml = serialize_compiled_policy(&compiled).map_err(|err| {
        ApiError::Internal(format!("failed to serialize effective policy YAML: {err}"))
    })?;
    let resolution_version = active_policy
        .as_ref()
        .map(|policy| policy.version)
        .unwrap_or(0)
        + applied_attachment_count;

    Ok(ResolvedEffectivePolicy {
        effective_policy: ConsoleEffectivePolicy {
            checksum_sha256: checksum_sha256_hex(&compiled_policy_yaml),
            resolution_version,
            overlays: applied_overlays,
        },
        compiled_policy_yaml: Some(compiled_policy_yaml),
        source_attachments: (!source_attachments.is_empty()).then_some(source_attachments),
    })
}

async fn load_active_grants(
    db: &PgPool,
    tenant_id: Uuid,
    principal_id: Uuid,
    principal_stable_ref: &str,
) -> Result<Vec<ConsoleActiveGrant>, ApiError> {
    let principal_id_text = principal_id.to_string();
    let rows = sqlx::query::query(
        r#"SELECT id::text AS grant_id,
                  subject_principal_id::text AS subject_principal_id,
                  COALESCE(expires_at, $3::timestamptz) AS expires_at,
                  status
           FROM grants
           WHERE tenant_id = $1
             AND status = 'active'
             AND (issuer_principal_id = $2 OR subject_principal_id = $2)
           UNION ALL
           SELECT id::text AS grant_id,
                  subject_principal_id,
                  expires_at,
                  status
           FROM fleet_grants
           WHERE tenant_id = $1
             AND status = 'active'
             AND (
                  issuer_principal_id = $4
                  OR subject_principal_id = $4
                  OR issuer_principal_id = $5
                  OR subject_principal_id = $5
             )
           ORDER BY expires_at ASC, grant_id ASC"#,
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(parse_rfc3339(
        INDEFINITE_GRANT_EXPIRY,
        "grant_expiry_fallback",
    )?)
    .bind(principal_stable_ref)
    .bind(&principal_id_text)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let mut grants_by_id = BTreeMap::new();
    for row in rows {
        let grant = ConsoleActiveGrant {
            grant_id: row.try_get("grant_id").map_err(ApiError::Database)?,
            subject_principal_id: row
                .try_get("subject_principal_id")
                .map_err(ApiError::Database)?,
            expires_at: row.try_get("expires_at").map_err(ApiError::Database)?,
            status: row.try_get("status").map_err(ApiError::Database)?,
        };
        grants_by_id.entry(grant.grant_id.clone()).or_insert(grant);
    }

    Ok(grants_by_id.into_values().collect())
}

async fn load_recent_sessions(
    db: &PgPool,
    tenant_id: Uuid,
    principal_id: &str,
    principal_stable_ref: &str,
    agent_id: Option<&str>,
    last_heartbeat_at: Option<DateTime<Utc>>,
    default_posture: Option<String>,
) -> Result<Vec<ConsoleRecentSession>, ApiError> {
    let principal_aliases = principal_aliases(principal_id, Some(principal_stable_ref));
    let rows = sqlx::query::query(
        r#"SELECT session_id,
                  MIN(timestamp) AS started_at,
                  MAX(timestamp) AS ended_at
           FROM hunt_events
           WHERE tenant_id = $1
             AND principal_id = ANY($2)
             AND session_id IS NOT NULL
           GROUP BY session_id
           ORDER BY MAX(timestamp) DESC, session_id DESC
           LIMIT 10"#,
    )
    .bind(tenant_id)
    .bind(&principal_aliases)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let mut sessions = rows
        .into_iter()
        .map(|row| {
            let started_at: DateTime<Utc> =
                row.try_get("started_at").map_err(ApiError::Database)?;
            let ended_at: DateTime<Utc> = row.try_get("ended_at").map_err(ApiError::Database)?;
            Ok(ConsoleRecentSession {
                session_id: row.try_get("session_id").map_err(ApiError::Database)?,
                started_at,
                ended_at: (ended_at > started_at).then_some(ended_at),
                posture: default_posture.clone(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    if sessions.is_empty() {
        if let (Some(agent_id), Some(last_heartbeat_at)) = (agent_id, last_heartbeat_at) {
            sessions.push(ConsoleRecentSession {
                session_id: format!("{agent_id}:latest"),
                started_at: last_heartbeat_at,
                ended_at: None,
                posture: default_posture,
            });
        }
    }

    Ok(sessions)
}

async fn list_response_actions_with_limit(
    db: &PgPool,
    tenant_id: Uuid,
    status: Option<&str>,
    target_kind: Option<&str>,
    limit: i64,
) -> Result<Vec<ConsoleResponseActionListItem>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT ra.id,
                  ra.action_type,
                  ra.status,
                  ra.target_kind,
                  ra.target_id,
                  ra.requested_at,
                  ra.requested_by_type,
                  ra.requested_by_id,
                  ra.reason,
                  ra.source_detection_id,
                  COALESCE(
                      p.display_name,
                      a.name,
                      sw.name,
                      pr.name,
                      fg.subject_principal_id,
                      g.subject_principal_id::text,
                      NULLIF(ra.target_id, '')
                  ) AS target_display_name
           FROM response_actions AS ra
           LEFT JOIN principals AS p
             ON ra.target_kind = 'principal'
            AND p.tenant_id = ra.tenant_id
            AND p.id::text = ra.target_id
           LEFT JOIN agents AS a
             ON ra.target_kind = 'endpoint'
            AND a.tenant_id = ra.tenant_id
            AND (a.id::text = ra.target_id OR a.agent_id = ra.target_id)
           LEFT JOIN swarms AS sw
             ON ra.target_kind = 'swarm'
            AND sw.tenant_id = ra.tenant_id
            AND (sw.id::text = ra.target_id OR sw.slug = ra.target_id)
           LEFT JOIN projects AS pr
             ON ra.target_kind = 'project'
            AND pr.tenant_id = ra.tenant_id
            AND (pr.id::text = ra.target_id OR pr.slug = ra.target_id)
           LEFT JOIN fleet_grants AS fg
             ON ra.target_kind = 'grant'
            AND fg.tenant_id = ra.tenant_id
            AND fg.id::text = ra.target_id
           LEFT JOIN grants AS g
             ON ra.target_kind = 'grant'
            AND g.tenant_id = ra.tenant_id
            AND g.id::text = ra.target_id
           WHERE ra.tenant_id = $1
             AND ($2::text IS NULL OR ra.status = $2)
             AND ($3::text IS NULL OR ra.target_kind = $3)
           ORDER BY ra.requested_at DESC, ra.id DESC
           LIMIT $4"#,
    )
    .bind(tenant_id)
    .bind(status)
    .bind(target_kind)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(|row| {
            let requested_by_type: String = row
                .try_get("requested_by_type")
                .map_err(ApiError::Database)?;
            let requested_by_id: String =
                row.try_get("requested_by_id").map_err(ApiError::Database)?;
            let source_detection_id = row
                .try_get::<Option<Uuid>, _>("source_detection_id")
                .map_err(ApiError::Database)?
                .map(|value| value.to_string());
            Ok(ConsoleResponseActionListItem {
                action_id: row
                    .try_get::<Uuid, _>("id")
                    .map_err(ApiError::Database)?
                    .to_string(),
                action_type: row.try_get("action_type").map_err(ApiError::Database)?,
                status: row.try_get("status").map_err(ApiError::Database)?,
                target_kind: row.try_get("target_kind").map_err(ApiError::Database)?,
                target_id: row.try_get("target_id").map_err(ApiError::Database)?,
                target_display_name: row
                    .try_get("target_display_name")
                    .map_err(ApiError::Database)?,
                requested_at: row.try_get("requested_at").map_err(ApiError::Database)?,
                requested_by: format_requested_by(&requested_by_type, requested_by_id),
                reason: row.try_get("reason").map_err(ApiError::Database)?,
                source_detection_id,
            })
        })
        .collect()
}

async fn list_recent_detections(
    db: &PgPool,
    tenant_id: Uuid,
    limit: i64,
) -> Result<Vec<ConsoleDetectionListItem>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT id, title, severity, status, created_at, principal_id
           FROM detection_findings
           WHERE tenant_id = $1
           ORDER BY created_at DESC, id DESC
           LIMIT $2"#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(|row| {
            Ok(ConsoleDetectionListItem {
                detection_id: row
                    .try_get::<Uuid, _>("id")
                    .map_err(ApiError::Database)?
                    .to_string(),
                title: row.try_get("title").map_err(ApiError::Database)?,
                severity: row.try_get("severity").map_err(ApiError::Database)?,
                status: row.try_get("status").map_err(ApiError::Database)?,
                created_at: row.try_get("created_at").map_err(ApiError::Database)?,
                principal_id: row
                    .try_get::<Option<Uuid>, _>("principal_id")
                    .map_err(ApiError::Database)?
                    .map(|value| value.to_string()),
            })
        })
        .collect()
}

fn map_principal_row(row: sqlx_postgres::PgRow) -> Result<PrincipalBaseRow, ApiError> {
    Ok(PrincipalBaseRow {
        id: row.try_get("id").map_err(ApiError::Database)?,
        principal_type: row.try_get("principal_type").map_err(ApiError::Database)?,
        display_name: row.try_get("display_name").map_err(ApiError::Database)?,
        stable_ref: row.try_get("stable_ref").map_err(ApiError::Database)?,
        lifecycle_state: row.try_get("lifecycle_state").map_err(ApiError::Database)?,
        liveness_state: row.try_get("liveness_state").map_err(ApiError::Database)?,
        trust_level: row.try_get("trust_level").map_err(ApiError::Database)?,
        principal_metadata: row
            .try_get("principal_metadata")
            .map_err(ApiError::Database)?,
        agent_id: row.try_get("agent_id").map_err(ApiError::Database)?,
        last_heartbeat_at: row
            .try_get("last_heartbeat_at")
            .map_err(ApiError::Database)?,
        agent_metadata: row.try_get("agent_metadata").map_err(ApiError::Database)?,
        open_response_action_count: row
            .try_get("open_response_action_count")
            .map_err(ApiError::Database)?,
    })
}

fn principal_list_item_from_parts(
    row: &PrincipalBaseRow,
    scope: &PrincipalMembershipScope,
) -> ConsolePrincipalListItem {
    ConsolePrincipalListItem {
        principal_id: row.id.to_string(),
        principal_type: normalize_principal_type(&row.principal_type),
        display_name: row.display_name.clone(),
        stable_ref: row.stable_ref.clone(),
        lifecycle_state: row.lifecycle_state.clone(),
        liveness_state: normalize_liveness_state(row.liveness_state.as_deref()),
        endpoint_posture: derive_endpoint_posture(
            &row.principal_type,
            &row.lifecycle_state,
            &row.principal_metadata,
            row.agent_metadata.as_ref(),
        ),
        trust_level: row.trust_level.clone(),
        swarm_names: scope.swarm_names.clone(),
        project_names: scope.project_names.clone(),
        capability_group_names: scope.capability_group_names.clone(),
        last_heartbeat_at: row.last_heartbeat_at,
        open_response_action_count: row.open_response_action_count,
    }
}

fn map_timeline_row(row: sqlx_postgres::PgRow) -> Result<ConsoleTimelineEvent, ApiError> {
    let verdict: String = row.try_get("verdict").map_err(ApiError::Database)?;
    let source: String = row.try_get("source").map_err(ApiError::Database)?;
    let target_kind: Option<String> = row.try_get("target_kind").map_err(ApiError::Database)?;
    let target_id: Option<String> = row.try_get("target_id").map_err(ApiError::Database)?;
    let target_name: Option<String> = row.try_get("target_name").map_err(ApiError::Database)?;
    let endpoint_agent_id: Option<String> = row
        .try_get("endpoint_agent_id")
        .map_err(ApiError::Database)?;
    let runtime_agent_id: Option<String> = row
        .try_get("runtime_agent_id")
        .map_err(ApiError::Database)?;
    let response_action_id: Option<String> = row
        .try_get("response_action_id")
        .map_err(ApiError::Database)?;
    let detection_ids: Vec<String> = row.try_get("detection_ids").map_err(ApiError::Database)?;
    let attributes: Value = row.try_get("attributes").map_err(ApiError::Database)?;

    let mut metadata = Map::new();
    metadata.insert("source".to_string(), Value::String(source));
    metadata.insert("verdict".to_string(), Value::String(verdict.clone()));

    if let Some(target_kind) = target_kind {
        metadata.insert("targetKind".to_string(), Value::String(target_kind));
    }
    if let Some(target_id) = target_id {
        metadata.insert("targetId".to_string(), Value::String(target_id));
    }
    if let Some(target_name) = target_name {
        metadata.insert("targetName".to_string(), Value::String(target_name));
    }
    if let Some(endpoint_agent_id) = endpoint_agent_id {
        metadata.insert(
            "endpointAgentId".to_string(),
            Value::String(endpoint_agent_id),
        );
    }
    if let Some(runtime_agent_id) = runtime_agent_id {
        metadata.insert(
            "runtimeAgentId".to_string(),
            Value::String(runtime_agent_id),
        );
    }
    if let Some(response_action_id) = response_action_id {
        metadata.insert(
            "responseActionId".to_string(),
            Value::String(response_action_id),
        );
    }
    if !detection_ids.is_empty() {
        metadata.insert("detectionIds".to_string(), json!(detection_ids));
    }
    if !is_empty_json_object(&attributes) {
        metadata.insert("attributes".to_string(), attributes);
    }

    Ok(ConsoleTimelineEvent {
        event_id: row.try_get("event_id").map_err(ApiError::Database)?,
        timestamp: row.try_get("timestamp").map_err(ApiError::Database)?,
        tenant_id: row
            .try_get::<Uuid, _>("tenant_id")
            .map_err(ApiError::Database)?
            .to_string(),
        principal_id: row.try_get("principal_id").map_err(ApiError::Database)?,
        session_id: row.try_get("session_id").map_err(ApiError::Database)?,
        grant_id: row.try_get("grant_id").map_err(ApiError::Database)?,
        event_type: row.try_get("kind").map_err(ApiError::Database)?,
        action_type: row.try_get("action_type").map_err(ApiError::Database)?,
        severity: row.try_get("severity").map_err(ApiError::Database)?,
        allowed: allowed_from_verdict(&verdict),
        summary: row.try_get("summary").map_err(ApiError::Database)?,
        metadata: (!metadata.is_empty()).then_some(Value::Object(metadata)),
    })
}

fn normalize_principal_type(value: &str) -> String {
    match value {
        "endpoint_agent" => "endpoint",
        "runtime_agent" => "runtime",
        "delegated_agent" => "delegated",
        other => other,
    }
    .to_string()
}

fn normalize_liveness_state(value: Option<&str>) -> String {
    match value {
        Some("active") => "online",
        Some("stale") => "stale",
        Some("dead") => "offline",
        Some("unknown") | None => "unknown",
        Some(other) => other,
    }
    .to_string()
}

fn derive_endpoint_posture(
    principal_type: &str,
    lifecycle_state: &str,
    principal_metadata: &Value,
    agent_metadata: Option<&Value>,
) -> Option<String> {
    if let Some(posture) = agent_metadata
        .and_then(|metadata| metadata.get("posture"))
        .and_then(Value::as_str)
        .or_else(|| principal_metadata.get("posture").and_then(Value::as_str))
    {
        return Some(posture.to_string());
    }

    if principal_type != "endpoint_agent" {
        return None;
    }

    match lifecycle_state {
        "active" => Some("nominal".to_string()),
        "inactive" => Some("inactive".to_string()),
        "restricted" => Some("restricted".to_string()),
        "observe_only" => Some("observe_only".to_string()),
        "quarantined" => Some("quarantined".to_string()),
        "revoked" => Some("revoked".to_string()),
        _ => None,
    }
}

fn merge_metadata_values(
    principal_metadata: &Value,
    agent_metadata: Option<&Value>,
) -> Option<Value> {
    let mut merged = Map::new();

    if let Some(principal_object) = principal_metadata.as_object() {
        for (key, value) in principal_object {
            merged.insert(key.clone(), value.clone());
        }
    }
    if let Some(agent_object) = agent_metadata.and_then(Value::as_object) {
        for (key, value) in agent_object {
            merged.insert(key.clone(), value.clone());
        }
    }

    if merged.is_empty() {
        None
    } else {
        Some(Value::Object(merged))
    }
}

fn normalize_limit(limit: Option<u32>) -> i64 {
    limit
        .map(i64::from)
        .map(|value| value.clamp(1, MAX_LIST_LIMIT))
        .unwrap_or(DEFAULT_LIST_LIMIT)
}

async fn resolve_principal_filter_aliases(
    db: &PgPool,
    tenant_id: Uuid,
    principal_identifier: &str,
) -> Result<Vec<String>, ApiError> {
    if let Some(principal) = principal_resolution::resolve_principal_identifier_optional(
        db,
        tenant_id,
        principal_identifier,
    )
    .await?
    {
        Ok(principal_aliases(
            &principal.id.to_string(),
            Some(&principal.stable_ref),
        ))
    } else {
        Ok(principal_aliases(principal_identifier, None))
    }
}

fn principal_aliases(principal_id: &str, principal_stable_ref: Option<&str>) -> Vec<String> {
    let mut aliases = Vec::new();
    push_unique(&mut aliases, principal_id.to_string());
    if let Some(principal_stable_ref) = principal_stable_ref {
        push_unique(&mut aliases, principal_stable_ref.to_string());
    }
    aliases
}

fn parse_optional_rfc3339(
    value: Option<&str>,
    field_name: &str,
) -> Result<Option<DateTime<Utc>>, ApiError> {
    value.map(|raw| parse_rfc3339(raw, field_name)).transpose()
}

fn parse_rfc3339(value: &str, field_name: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| ApiError::BadRequest(format!("{field_name} must be RFC3339")))
}

fn format_requested_by(requested_by_type: &str, requested_by_id: String) -> String {
    if requested_by_type == "user" {
        requested_by_id
    } else {
        format!("{requested_by_type}:{requested_by_id}")
    }
}

fn push_unique(values: &mut Vec<String>, candidate: String) {
    if !values.iter().any(|value| value == &candidate) {
        values.push(candidate);
    }
}

fn push_graph_node(
    nodes: &mut Vec<ConsoleGraphNode>,
    seen_nodes: &mut HashSet<String>,
    node: ConsoleGraphNode,
) {
    if seen_nodes.insert(node.id.clone()) {
        nodes.push(node);
    }
}

fn checksum_sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_yaml_value(input: &str) -> Result<serde_yaml::Value, serde_yaml::Error> {
    serde_yaml::from_str::<serde_yaml::Value>(input)
}

fn serialize_compiled_policy(value: &serde_yaml::Value) -> Result<String, serde_yaml::Error> {
    match value {
        serde_yaml::Value::Mapping(map) if map.is_empty() => Ok(String::new()),
        serde_yaml::Value::Null => Ok(String::new()),
        _ => serde_yaml::to_string(value),
    }
}

fn merge_yaml_value(base: &mut serde_yaml::Value, overlay: serde_yaml::Value) {
    match (base, overlay) {
        (serde_yaml::Value::Mapping(base_map), serde_yaml::Value::Mapping(overlay_map)) => {
            for (key, value) in overlay_map {
                if value.is_null() {
                    base_map.remove(&key);
                    continue;
                }

                if let Some(existing) = base_map.get_mut(&key) {
                    merge_yaml_value(existing, value);
                } else {
                    base_map.insert(key, value);
                }
            }
        }
        (base_slot, replacement) => {
            *base_slot = replacement;
        }
    }
}

fn lifecycle_overlay_names(lifecycle_state: &str) -> Vec<String> {
    match lifecycle_state {
        "restricted" => vec!["restricted".to_string()],
        "observe_only" => vec!["observe_only".to_string()],
        "quarantined" => vec!["quarantined".to_string()],
        "revoked" => vec!["revoked".to_string()],
        _ => Vec::new(),
    }
}

fn allowed_from_verdict(verdict: &str) -> Option<bool> {
    match verdict {
        "allow" => Some(true),
        "deny" => Some(false),
        _ => None,
    }
}

fn string_field(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    })
}

fn nested_string_field(
    object: &Map<String, Value>,
    outer_key: &str,
    inner_keys: &[&str],
) -> Option<String> {
    object
        .get(outer_key)
        .and_then(Value::as_object)
        .and_then(|inner| string_field(inner, inner_keys))
}

fn parse_console_stream_kind(value: Option<String>) -> Option<ConsoleStreamEventKind> {
    match value.as_deref()? {
        "principal_state_changed" => Some(ConsoleStreamEventKind::PrincipalStateChanged),
        "effective_policy_updated" => Some(ConsoleStreamEventKind::EffectivePolicyUpdated),
        "response_action_updated" => Some(ConsoleStreamEventKind::ResponseActionUpdated),
        "detection_created" => Some(ConsoleStreamEventKind::DetectionCreated),
        "timeline_event" => Some(ConsoleStreamEventKind::TimelineEvent),
        "graph_updated" => Some(ConsoleStreamEventKind::GraphUpdated),
        _ => None,
    }
}

fn map_fleet_event_kind_to_console(kind: Option<String>) -> ConsoleStreamEventKind {
    match kind.as_deref() {
        Some("principal_state_changed") => ConsoleStreamEventKind::PrincipalStateChanged,
        Some("response_action_created") | Some("response_action_updated") => {
            ConsoleStreamEventKind::ResponseActionUpdated
        }
        Some("detection_fired") | Some("detection_created") => {
            ConsoleStreamEventKind::DetectionCreated
        }
        Some("effective_policy_updated") => ConsoleStreamEventKind::EffectivePolicyUpdated,
        Some("graph_updated") => ConsoleStreamEventKind::GraphUpdated,
        _ => ConsoleStreamEventKind::TimelineEvent,
    }
}

fn infer_console_kind_from_fact(object: &Map<String, Value>) -> Option<ConsoleStreamEventKind> {
    let raw = string_field(object, &["type", "event_type", "schema"])?;
    let lowered = raw.to_lowercase();

    if lowered.contains("policy") {
        return Some(ConsoleStreamEventKind::EffectivePolicyUpdated);
    }
    if lowered.contains("response") {
        return Some(ConsoleStreamEventKind::ResponseActionUpdated);
    }
    if lowered.contains("principal") {
        return Some(ConsoleStreamEventKind::PrincipalStateChanged);
    }
    if lowered.contains("detection") {
        return Some(ConsoleStreamEventKind::DetectionCreated);
    }
    if lowered.contains("graph") || lowered.contains("delegation") || lowered.contains("grant") {
        return Some(ConsoleStreamEventKind::GraphUpdated);
    }

    Some(ConsoleStreamEventKind::TimelineEvent)
}

fn payload_object(payload: Value) -> Value {
    match payload {
        Value::Object(_) => payload,
        other => json!({ "raw": other }),
    }
}

fn is_empty_json_object(value: &Value) -> bool {
    value.as_object().is_some_and(Map::is_empty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_from_detail_uses_plain_console_ids() {
        let graph = build_principal_graph_from_detail(&ConsolePrincipalDetail {
            principal: ConsolePrincipalListItem {
                principal_id: "principal-1".to_string(),
                principal_type: "endpoint".to_string(),
                display_name: "Planner".to_string(),
                stable_ref: "agent-1".to_string(),
                lifecycle_state: "active".to_string(),
                liveness_state: "online".to_string(),
                endpoint_posture: Some("nominal".to_string()),
                trust_level: "high".to_string(),
                swarm_names: Vec::new(),
                project_names: Vec::new(),
                capability_group_names: Vec::new(),
                last_heartbeat_at: None,
                open_response_action_count: 1,
            },
            metadata: None,
            memberships: Vec::new(),
            effective_policy: ConsoleEffectivePolicy {
                checksum_sha256: "hash".to_string(),
                resolution_version: 1,
                overlays: Vec::new(),
            },
            active_grants: vec![ConsoleActiveGrant {
                grant_id: "grant-1".to_string(),
                subject_principal_id: "principal-1".to_string(),
                expires_at: Utc::now(),
                status: "active".to_string(),
            }],
            recent_sessions: vec![ConsoleRecentSession {
                session_id: "session-1".to_string(),
                started_at: Utc::now(),
                ended_at: None,
                posture: Some("nominal".to_string()),
            }],
            compiled_policy_yaml: None,
            source_attachments: None,
        });

        assert_eq!(graph.root_principal_id, "principal-1");
        assert!(graph.nodes.iter().any(|node| node.id == "principal-1"));
        assert!(graph.nodes.iter().any(|node| node.id == "grant-1"));
        assert!(graph.nodes.iter().any(|node| node.id == "session-1"));
    }

    #[test]
    fn normalize_console_stream_event_projects_existing_contract() {
        let tenant_id = Uuid::new_v4();
        let event = normalize_console_stream_event(
            json!({
                "id": "evt-1",
                "kind": "response_action_updated",
                "tenant_id": tenant_id.to_string(),
                "principal_id": "principal-1",
                "response_action_id": "action-1",
                "timestamp": "2026-03-06T12:00:00Z",
                "payload": { "status": "published" }
            }),
            tenant_id,
        );

        assert_eq!(event.id, "evt-1");
        assert_eq!(event.kind, ConsoleStreamEventKind::ResponseActionUpdated);
        assert_eq!(event.principal_id.as_deref(), Some("principal-1"));
        assert_eq!(event.response_action_id.as_deref(), Some("action-1"));
        assert_eq!(event.payload["status"], "published");
    }

    #[test]
    fn normalize_console_stream_event_projects_fleet_events() {
        let tenant_id = Uuid::new_v4();
        let event = normalize_console_stream_event(
            json!({
                "eventId": "hunt-evt-1",
                "tenantId": tenant_id.to_string(),
                "kind": "detection_fired",
                "occurredAt": "2026-03-06T12:01:00Z",
                "principal": {
                    "principalId": "principal-1"
                },
                "responseActionId": "action-2",
                "attributes": {
                    "title": "Suspicious curl"
                }
            }),
            tenant_id,
        );

        assert_eq!(event.id, "hunt-evt-1");
        assert_eq!(event.kind, ConsoleStreamEventKind::DetectionCreated);
        assert_eq!(event.principal_id.as_deref(), Some("principal-1"));
        assert_eq!(event.response_action_id.as_deref(), Some("action-2"));
        assert_eq!(event.payload["attributes"]["title"], "Suspicious curl");
    }

    #[test]
    fn normalize_console_stream_event_unwraps_spine_envelopes() {
        let tenant_id = Uuid::new_v4();
        let event = normalize_console_stream_event(
            json!({
                "envelope_hash": "env-1",
                "issued_at": "2026-03-06T12:05:00Z",
                "fact": {
                    "tenantId": tenant_id.to_string(),
                    "kind": "principal_state_changed",
                    "principal": {
                        "principalId": "principal-1"
                    }
                }
            }),
            tenant_id,
        );

        assert_eq!(event.id, "env-1");
        assert_eq!(event.kind, ConsoleStreamEventKind::PrincipalStateChanged);
        assert_eq!(event.principal_id.as_deref(), Some("principal-1"));
        assert_eq!(
            event.timestamp,
            parse_rfc3339("2026-03-06T12:05:00Z", "issued_at").expect("issued_at")
        );
        assert!(event.payload.get("fact").is_some());
    }
}
