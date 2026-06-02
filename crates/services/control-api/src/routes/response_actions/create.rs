//! Create-action validation, target resolution, and persistence.

use super::*;

pub(crate) async fn prepare_create_action(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    auth: &AuthenticatedTenant,
    input: CreateResponseActionRequest,
) -> Result<ValidatedCreateAction, ApiError> {
    let action_type = ResponseActionType::from_str(&input.action_type)?;
    let target_kind = ResponseTargetKind::from_str(&input.target.kind)?;
    let require_acknowledgement = input.require_acknowledgement.unwrap_or(false);
    validate_create_request(&input, &action_type, &target_kind, require_acknowledgement)?;

    let resolved_target_id =
        resolve_action_target_id(tx, auth.tenant_id, &target_kind, input.target.id.trim()).await?;
    validate_action_links(
        tx,
        auth.tenant_id,
        input.case_id,
        input.source_detection_id,
        input.source_approval_id,
    )
    .await?;

    Ok(ValidatedCreateAction {
        action_type,
        target_kind,
        resolved_target_id,
        reason: input.reason.trim().to_string(),
        expires_at: input.expires_at,
        case_id: input.case_id,
        source_detection_id: input.source_detection_id,
        source_approval_id: input.source_approval_id,
        require_acknowledgement,
        payload: input.payload.unwrap_or_else(|| json!({})),
        metadata: json!({
            "requested_by_slug": auth.slug,
        }),
    })
}

pub(crate) async fn insert_action(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    auth: &AuthenticatedTenant,
    draft: ValidatedCreateAction,
) -> Result<ResponseActionRecord, ApiError> {
    let row = sqlx::query::query(
        r#"INSERT INTO response_actions (
               tenant_id,
               action_type,
               target_kind,
               target_id,
               requested_by_type,
               requested_by_id,
               expires_at,
               reason,
               case_id,
               source_detection_id,
               source_approval_id,
               require_acknowledgement,
               payload,
               metadata
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(draft.action_type.as_str())
    .bind(draft.target_kind.as_str())
    .bind(&draft.resolved_target_id)
    .bind(auth.actor_type())
    .bind(auth.actor_id())
    .bind(draft.expires_at)
    .bind(&draft.reason)
    .bind(draft.case_id)
    .bind(draft.source_detection_id)
    .bind(draft.source_approval_id)
    .bind(draft.require_acknowledgement)
    .bind(draft.payload)
    .bind(draft.metadata)
    .fetch_one(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    ResponseActionRecord::from_row(row).map_err(ApiError::Database)
}

pub(crate) fn validate_create_request(
    input: &CreateResponseActionRequest,
    action_type: &ResponseActionType,
    target_kind: &ResponseTargetKind,
    require_acknowledgement: bool,
) -> Result<(), ApiError> {
    let reason = input.reason.trim();
    if reason.is_empty() {
        return Err(ApiError::BadRequest("reason is required".to_string()));
    }
    validate_response_action_field_len("reason", reason, ACTION_REASON_MAX_BYTES)?;

    let target_id = input.target.id.trim();
    if target_id.is_empty() {
        return Err(ApiError::BadRequest("target.id is required".to_string()));
    }
    validate_response_action_field_len("target.id", target_id, ACTION_TARGET_ID_MAX_BYTES)?;

    if let Some(payload) = input.payload.as_ref() {
        validate_response_action_payload(payload)?;
    }

    if let Some(expires_at) = input.expires_at {
        if expires_at <= Utc::now() {
            return Err(ApiError::BadRequest(
                "expires_at must be in the future".to_string(),
            ));
        }
    }
    if require_acknowledgement
        && !matches!(action_type, ResponseActionType::PolicyRuleDiffValidation)
    {
        return Err(ApiError::BadRequest(
            "response acknowledgements are not supported for the current executor set".to_string(),
        ));
    }
    if matches!(action_type, ResponseActionType::PolicyRuleDiffValidation)
        && !require_acknowledgement
    {
        return Err(ApiError::BadRequest(
            "policy_rule_diff_validation actions require acknowledgement".to_string(),
        ));
    }
    if matches!(target_kind, ResponseTargetKind::Endpoint)
        && !endpoint_delivery_action_supported(action_type)
    {
        return Err(ApiError::BadRequest(
            "endpoint response-action delivery currently supports only policy_rule_diff_validation"
                .to_string(),
        ));
    }
    if matches!(action_type, ResponseActionType::TransitionPosture)
        && transition_posture_value(input.payload.as_ref().unwrap_or(&Value::Null)).is_none()
    {
        return Err(ApiError::BadRequest(
            "transition_posture actions require payload.toState or payload.posture".to_string(),
        ));
    }

    match (action_type, target_kind) {
        (ResponseActionType::PolicyRuleDiffValidation, ResponseTargetKind::Endpoint)
        | (ResponseActionType::QuarantinePrincipal, ResponseTargetKind::Principal)
        | (ResponseActionType::RevokeGrant, ResponseTargetKind::Grant)
        | (ResponseActionType::RevokePrincipal, ResponseTargetKind::Principal) => Ok(()),
        _ => Err(ApiError::BadRequest(format!(
            "action '{}' is not valid for target kind '{}'",
            input.action_type, input.target.kind
        ))),
    }
}

fn endpoint_delivery_action_supported(action_type: &ResponseActionType) -> bool {
    matches!(action_type, ResponseActionType::PolicyRuleDiffValidation)
}

fn validate_response_action_field_len(
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<(), ApiError> {
    if value.len() > max_len {
        return Err(ApiError::BadRequest(format!(
            "response-action {field} must be at most {max_len} bytes"
        )));
    }
    Ok(())
}

fn validate_response_action_payload(value: &Value) -> Result<(), ApiError> {
    let serialized = serde_json::to_vec(value).map_err(|err| {
        ApiError::BadRequest(format!("response-action payload is invalid: {err}"))
    })?;
    if serialized.len() > ACTION_PAYLOAD_MAX_BYTES {
        return Err(ApiError::BadRequest(format!(
            "response-action payload must be at most {ACTION_PAYLOAD_MAX_BYTES} bytes"
        )));
    }
    Ok(())
}

pub(crate) fn validate_control_discriminator_len(
    field: &str,
    value: &str,
    max_len: usize,
) -> Result<(), ApiError> {
    if value.len() > max_len {
        return Err(ApiError::BadRequest(format!(
            "control {field} must be at most {max_len} bytes"
        )));
    }
    Ok(())
}

async fn resolve_action_target_id(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    target_kind: &ResponseTargetKind,
    target_id: &str,
) -> Result<String, ApiError> {
    let resolved = match target_kind {
        ResponseTargetKind::Endpoint => {
            if let Some(row) = sqlx::query::query(
                "SELECT agent_id FROM agents WHERE tenant_id = $1 AND agent_id = $2",
            )
            .bind(tenant_id)
            .bind(target_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(ApiError::Database)?
            {
                row.try_get("agent_id").map_err(ApiError::Database)?
            } else if let Ok(agent_row_id) = Uuid::parse_str(target_id) {
                let row = sqlx::query::query(
                    "SELECT agent_id FROM agents WHERE tenant_id = $1 AND id = $2",
                )
                .bind(tenant_id)
                .bind(agent_row_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(ApiError::Database)?
                .ok_or(ApiError::NotFound)?;
                row.try_get("agent_id").map_err(ApiError::Database)?
            } else {
                return Err(ApiError::NotFound);
            }
        }
        ResponseTargetKind::Principal => {
            principal_resolution::resolve_principal_identifier(&mut **tx, tenant_id, target_id)
                .await?
                .id
                .to_string()
        }
        ResponseTargetKind::Grant => {
            let grant_id = Uuid::parse_str(target_id).map_err(|_| {
                ApiError::BadRequest("grant targets must use a UUID grant id".to_string())
            })?;
            let exists =
                sqlx::query::query("SELECT 1 FROM fleet_grants WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant_id)
                    .bind(grant_id)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(ApiError::Database)?
                    .is_some();
            if !exists {
                return Err(ApiError::NotFound);
            }
            grant_id.to_string()
        }
        ResponseTargetKind::Runtime
        | ResponseTargetKind::Session
        | ResponseTargetKind::Swarm
        | ResponseTargetKind::Project => {
            return Err(ApiError::BadRequest(format!(
                "target kind '{}' does not have a registered executor",
                target_kind.as_str()
            )));
        }
    };

    Ok(resolved)
}

async fn validate_action_links(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    case_id: Option<Uuid>,
    source_detection_id: Option<Uuid>,
    source_approval_id: Option<Uuid>,
) -> Result<(), ApiError> {
    if let Some(case_id) = case_id {
        let exists = sqlx::query_scalar::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1
                   FROM fleet_cases
                   WHERE tenant_id = $1 AND id = $2
               )"#,
        )
        .bind(tenant_id)
        .bind(case_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(ApiError::Database)?;
        if !exists {
            return Err(ApiError::NotFound);
        }
    }

    if let Some(finding_id) = source_detection_id {
        let exists = sqlx::query_scalar::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1
                   FROM detection_findings
                   WHERE tenant_id = $1 AND id = $2
               )"#,
        )
        .bind(tenant_id)
        .bind(finding_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(ApiError::Database)?;
        if !exists {
            return Err(ApiError::NotFound);
        }
    }

    if let Some(approval_id) = source_approval_id {
        let exists = sqlx::query_scalar::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1
                   FROM approvals
                   WHERE tenant_id = $1 AND id = $2
               )"#,
        )
        .bind(tenant_id)
        .bind(approval_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(ApiError::Database)?;
        if !exists {
            return Err(ApiError::NotFound);
        }
    }

    Ok(())
}

pub(crate) async fn link_action_to_source_detection(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    action_id: Uuid,
    source_detection_id: Option<Uuid>,
) -> Result<(), ApiError> {
    let Some(finding_id) = source_detection_id else {
        return Ok(());
    };

    let result = sqlx::query::query(
        r#"UPDATE detection_findings
           SET response_action_ids = CASE
                   WHEN COALESCE(response_action_ids, '[]'::jsonb)
                        @> jsonb_build_array($3::text) THEN COALESCE(response_action_ids, '[]'::jsonb)
                   ELSE COALESCE(response_action_ids, '[]'::jsonb) || jsonb_build_array($3::text)
               END
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(finding_id)
    .bind(action_id.to_string())
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    Ok(())
}
