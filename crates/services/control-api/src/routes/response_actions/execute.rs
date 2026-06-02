//! Control-plane execution of cloud-only response actions.

use super::*;

pub(crate) async fn execute_cloud_only_action(
    state: &AppState,
    action: &ResponseActionRecord,
) -> Result<DeliveryExecution, ApiError> {
    match (
        ResponseActionType::from_str(&action.action_type)?,
        &action.target.kind,
    ) {
        (ResponseActionType::RevokeGrant, ResponseTargetKind::Grant) => {
            let grant_id = Uuid::parse_str(&action.target.id).map_err(|_| {
                ApiError::BadRequest("grant targets must use a UUID grant id".to_string())
            })?;
            let response = delegation_graph_service::revoke_grant(
                &state.db,
                action.tenant_id,
                grant_id,
                RevokeGrantRequest {
                    reason: action.reason.clone(),
                    revoke_descendants: Some(true),
                    revoked_by: Some(action.requested_by.actor_id.clone()),
                    response_action_id: Some(action.id.to_string()),
                    response_action_label: Some(action.action_type.clone()),
                    response_action_state: Some("acknowledged".to_string()),
                    response_action_metadata: Some(json!({
                        "response_action_id": action.id.to_string(),
                        "action_type": action.action_type.as_str(),
                    })),
                },
            )
            .await?;

            Ok(DeliveryExecution::Acknowledged {
                observed_at: Utc::now(),
                message: Some("grant revoked".to_string()),
                resulting_state: Some("revoked".to_string()),
                raw_payload: json!({
                    "grantId": grant_id,
                    "revokedGrantIds": response.revoked_grant_ids,
                    "status": "acknowledged",
                }),
            })
        }
        (ResponseActionType::QuarantinePrincipal, ResponseTargetKind::Principal) => {
            execute_principal_lifecycle_action(state, action, "quarantined").await
        }
        (ResponseActionType::RevokePrincipal, ResponseTargetKind::Principal) => {
            execute_principal_lifecycle_action(state, action, "revoked").await
        }
        _ => Err(ApiError::BadRequest(format!(
            "action '{}' does not have an executable control-plane handler",
            action.action_type
        ))),
    }
}

async fn execute_principal_lifecycle_action(
    state: &AppState,
    action: &ResponseActionRecord,
    lifecycle_state: &str,
) -> Result<DeliveryExecution, ApiError> {
    let target = update_principal_lifecycle_target(
        &state.db,
        action.tenant_id,
        &action.target.id,
        lifecycle_state,
    )
    .await?;
    sync_principal_graph_state(&state.db, action.tenant_id, &target, lifecycle_state).await?;
    let revoked_grant_ids = delegation_graph_service::revoke_principal_grants(
        &state.db,
        action.tenant_id,
        delegation_graph_service::RevokePrincipalGrantsRequest {
            principal_id: target.principal_id,
            principal_stable_ref: target.stable_ref.clone(),
            reason: action.reason.clone(),
            revoked_by: Some(action.requested_by.actor_id.clone()),
            response_action_id: Some(action.id.to_string()),
            response_action_label: Some(action.action_type.clone()),
            response_action_state: Some("acknowledged".to_string()),
            response_action_metadata: Some(json!({
                "response_action_id": action.id.to_string(),
                "action_type": action.action_type.as_str(),
            })),
        },
    )
    .await?;

    Ok(DeliveryExecution::Acknowledged {
        observed_at: Utc::now(),
        message: Some(format!("principal transitioned to {lifecycle_state}")),
        resulting_state: Some(lifecycle_state.to_string()),
        raw_payload: json!({
            "principalId": target.principal_id,
            "stableRef": target.stable_ref,
            "status": "acknowledged",
            "lifecycleState": lifecycle_state,
            "revokedGrantIds": revoked_grant_ids,
        }),
    })
}

async fn update_principal_lifecycle_target(
    db: &crate::db::PgPool,
    tenant_id: Uuid,
    target_id: &str,
    lifecycle_state: &str,
) -> Result<PrincipalLifecycleTarget, ApiError> {
    let principal_id = Uuid::parse_str(target_id.trim()).map_err(|_| {
        ApiError::Internal("principal response targets must be canonical UUID ids".to_string())
    })?;
    let row = sqlx::query::query(
        r#"UPDATE principals
           SET lifecycle_state = $3,
               updated_at = now()
           WHERE tenant_id = $1
             AND id = $2
           RETURNING id, stable_ref"#,
    )
    .bind(tenant_id)
    .bind(principal_id)
    .bind(lifecycle_state)
    .fetch_optional(db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    Ok(PrincipalLifecycleTarget {
        principal_id: row.try_get("id").map_err(ApiError::Database)?,
        stable_ref: row.try_get("stable_ref").map_err(ApiError::Database)?,
    })
}

async fn sync_principal_graph_state(
    db: &crate::db::PgPool,
    tenant_id: Uuid,
    target: &PrincipalLifecycleTarget,
    lifecycle_state: &str,
) -> Result<(), ApiError> {
    let node_ids = vec![
        format!("principal:{}", target.principal_id),
        format!("principal:{}", target.stable_ref),
    ];
    sqlx::query::query(
        r#"UPDATE delegation_graph_nodes
           SET state = $3,
               updated_at = now()
           WHERE tenant_id = $1
             AND id = ANY($2)"#,
    )
    .bind(tenant_id)
    .bind(&node_ids)
    .bind(lifecycle_state)
    .execute(db)
    .await
    .map_err(ApiError::Database)?;
    Ok(())
}
