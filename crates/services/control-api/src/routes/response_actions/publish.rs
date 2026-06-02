//! Response-action publication: delivery preparation, dispatch, and ledger updates.

use super::*;

pub(crate) async fn publish_action(
    state: &AppState,
    tenant_slug: &str,
    tenant_id: Uuid,
    action_id: Uuid,
    allow_retry: bool,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    match prepare_publish(state, tenant_slug, tenant_id, action_id, allow_retry).await? {
        PublishPreparation::Expired => {}
        PublishPreparation::Ready(context) => {
            let execution = execute_delivery(state, &context).await;
            apply_delivery_execution(state, &context, execution).await?;
        }
    }

    Ok(Json(
        fetch_action_detail(state, tenant_id, action_id).await?,
    ))
}

async fn prepare_publish(
    state: &AppState,
    tenant_slug: &str,
    tenant_id: Uuid,
    action_id: Uuid,
    allow_retry: bool,
) -> Result<PublishPreparation, ApiError> {
    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let row = sqlx::query::query(
        "SELECT * FROM response_actions WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(action_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    let action = ResponseActionRecord::from_row(row).map_err(ApiError::Database)?;
    ensure_publishable(&action.status, allow_retry)?;
    validate_publish_delivery_contract(&action)?;

    if action
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now())
    {
        sqlx::query::query(
            "UPDATE response_actions SET status = 'expired', updated_at = now() WHERE id = $1",
        )
        .bind(action.id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::Database)?;
        tx.commit().await.map_err(ApiError::Database)?;
        return Ok(PublishPreparation::Expired);
    }

    let delivery = upsert_delivery_plan(&mut tx, &action, tenant_slug).await?;
    sqlx::query::query(
        "UPDATE response_actions SET status = 'approved', updated_at = now() WHERE id = $1",
    )
    .bind(action.id)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::Database)?;
    tx.commit().await.map_err(ApiError::Database)?;

    Ok(PublishPreparation::Ready(Box::new(PublishContext {
        action,
        delivery,
    })))
}

async fn upsert_delivery_plan(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    action: &ResponseActionRecord,
    tenant_slug: &str,
) -> Result<ResponseActionDelivery, ApiError> {
    let plan = delivery_plan(action, tenant_slug);
    let delivery_row = sqlx::query::query(
        r#"INSERT INTO response_action_deliveries (
               action_id,
               tenant_id,
               target_kind,
               target_id,
               executor_kind,
               delivery_subject,
               status,
               attempt_count,
               acknowledgement_deadline,
               metadata
           )
           VALUES ($1, $2, $3, $4, $5, $6, 'approved', 0, $7, $8)
           ON CONFLICT (action_id, target_kind, target_id) DO UPDATE
           SET executor_kind = EXCLUDED.executor_kind,
               delivery_subject = EXCLUDED.delivery_subject,
               acknowledgement_deadline = EXCLUDED.acknowledgement_deadline,
               metadata = EXCLUDED.metadata,
               status = 'approved',
               updated_at = now()
           RETURNING *"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .bind(plan.target_kind)
    .bind(plan.target_id)
    .bind(plan.executor_kind)
    .bind(plan.delivery_subject)
    .bind(plan.acknowledgement_deadline)
    .bind(plan.metadata)
    .fetch_one(&mut **tx)
    .await
    .map_err(ApiError::Database)?;
    ResponseActionDelivery::from_row(delivery_row).map_err(ApiError::Database)
}

async fn execute_delivery(
    state: &AppState,
    context: &PublishContext,
) -> Result<DeliveryExecution, ApiError> {
    if let Some(subject) = context.delivery.delivery_subject.clone() {
        let payload_bytes = build_delivery_payload_bytes(
            &context.action,
            &context.delivery,
            state.config.approval_signing_enabled,
            state.signing_keypair.as_deref(),
        )?;
        state
            .nats
            .publish(subject, payload_bytes.into())
            .await
            .map_err(|err| ApiError::Nats(err.to_string()))?;

        if let Some(compat_subject) = context
            .delivery
            .metadata
            .get("compat_mirror_subject")
            .and_then(Value::as_str)
        {
            let compat_payload = legacy_posture_command_payload(&context.action)?;
            let compat_payload_bytes = build_signed_payload_bytes(
                compat_payload,
                state.config.approval_signing_enabled,
                state.signing_keypair.as_deref(),
            )?;
            state
                .nats
                .publish(compat_subject.to_string(), compat_payload_bytes.into())
                .await
                .map_err(|err| ApiError::Nats(err.to_string()))?;
        }

        return Ok(DeliveryExecution::Published);
    }

    execute_cloud_only_action(state, &context.action).await
}

async fn apply_delivery_execution(
    state: &AppState,
    context: &PublishContext,
    execution: Result<DeliveryExecution, ApiError>,
) -> Result<(), ApiError> {
    match execution {
        Ok(DeliveryExecution::Published) => {
            let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_actions
                   SET status = 'published',
                       updated_at = now()
                   WHERE id = $1 AND tenant_id = $2"#,
            )
            .bind(context.action.id)
            .bind(context.action.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_action_deliveries
                   SET status = 'published',
                       attempt_count = attempt_count + 1,
                       published_at = now(),
                       last_error = NULL,
                       updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(context.delivery.id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            tx.commit().await.map_err(ApiError::Database)?;
        }
        Ok(DeliveryExecution::Acknowledged {
            observed_at,
            message,
            resulting_state,
            raw_payload,
        }) => {
            let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"INSERT INTO response_action_acks (
                       delivery_id,
                       action_id,
                       tenant_id,
                       target_kind,
                       target_id,
                       observed_at,
                       status,
                       message,
                       resulting_state,
                       raw_payload
                   )
                   VALUES ($1, $2, $3, $4, $5, $6, 'acknowledged', $7, $8, $9)"#,
            )
            .bind(context.delivery.id)
            .bind(context.action.id)
            .bind(context.action.tenant_id)
            .bind(&context.delivery.target_kind)
            .bind(&context.delivery.target_id)
            .bind(observed_at)
            .bind(message.as_deref())
            .bind(resulting_state.as_deref())
            .bind(raw_payload)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_actions
                   SET status = 'acknowledged',
                       updated_at = now()
                   WHERE id = $1 AND tenant_id = $2"#,
            )
            .bind(context.action.id)
            .bind(context.action.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_action_deliveries
                   SET status = 'acknowledged',
                       attempt_count = attempt_count + 1,
                       published_at = COALESCE(published_at, $2),
                       acknowledged_at = $2,
                       last_error = NULL,
                       updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(context.delivery.id)
            .bind(observed_at)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            tx.commit().await.map_err(ApiError::Database)?;
        }
        Err(err) => {
            let err_string = err.to_string();
            let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_actions
                   SET status = 'failed',
                       metadata = jsonb_set(metadata, '{last_error}', to_jsonb($3::text), true),
                       updated_at = now()
                   WHERE id = $1 AND tenant_id = $2"#,
            )
            .bind(context.action.id)
            .bind(context.action.tenant_id)
            .bind(&err_string)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            sqlx::query::query(
                r#"UPDATE response_action_deliveries
                   SET status = 'failed',
                       attempt_count = attempt_count + 1,
                       last_error = $2,
                       updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(context.delivery.id)
            .bind(&err_string)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Database)?;
            tx.commit().await.map_err(ApiError::Database)?;
        }
    }

    Ok(())
}

pub(crate) fn validate_publish_delivery_contract(
    action: &ResponseActionRecord,
) -> Result<(), ApiError> {
    if matches!(action.target.kind, ResponseTargetKind::Endpoint)
        && action.action_type != ResponseActionType::PolicyRuleDiffValidation.as_str()
    {
        return Err(ApiError::BadRequest(
            "endpoint response-action delivery currently supports only policy_rule_diff_validation"
                .to_string(),
        ));
    }
    if action.action_type == ResponseActionType::PolicyRuleDiffValidation.as_str()
        && !action.require_acknowledgement
    {
        return Err(ApiError::BadRequest(
            "policy_rule_diff_validation actions require acknowledgement".to_string(),
        ));
    }
    Ok(())
}

fn ensure_publishable(current_status: &str, allow_retry: bool) -> Result<(), ApiError> {
    match (current_status, allow_retry) {
        ("queued", false) | ("approved", false) => Ok(()),
        ("failed", true) | ("expired", true) | ("approved", true) | ("published", true) => Ok(()),
        ("cancelled", _) => Err(ApiError::BadRequest(
            "cancelled actions cannot be published".to_string(),
        )),
        ("acknowledged", _) => Err(ApiError::BadRequest(
            "acknowledged actions cannot be republished".to_string(),
        )),
        (status, true) => Err(ApiError::BadRequest(format!(
            "status '{status}' cannot be retried"
        ))),
        (status, false) => Err(ApiError::BadRequest(format!(
            "status '{status}' cannot be approved"
        ))),
    }
}
