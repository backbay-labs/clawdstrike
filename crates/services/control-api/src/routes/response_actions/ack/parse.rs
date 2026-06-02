//! Acknowledgement parsing, validation, window enforcement, and context loading.

use crate::routes::response_actions::*;
pub(crate) async fn load_ack_action_tenant_id(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    action_id: Uuid,
) -> Result<Uuid, ApiError> {
    let row = sqlx::query::query("SELECT tenant_id FROM response_actions WHERE id = $1")
        .bind(action_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
    row.try_get("tenant_id").map_err(ApiError::Database)
}

pub(crate) fn parse_ack_submission(
    input: RecordResponseAckRequest,
) -> Result<AckSubmission, ApiError> {
    let ack_status = normalize_ack_status(&input.status)?;
    let target_kind = ResponseTargetKind::from_str(input.target_kind.trim())?;
    let target_id = input.target_id.trim();
    if target_id.is_empty() {
        return Err(ApiError::BadRequest("target_id is required".to_string()));
    }
    validate_ack_field_len("target_id", target_id, ACK_TARGET_ID_MAX_BYTES)?;

    let ack_token = input.ack_token.trim();
    if ack_token.is_empty() {
        return Err(ApiError::BadRequest("ack_token is required".to_string()));
    }
    validate_ack_field_len("ack_token", ack_token, ACK_TOKEN_MAX_BYTES)?;

    if let Some(message) = input.message.as_deref() {
        validate_ack_field_len("message", message, ACK_MESSAGE_MAX_BYTES)?;
    }
    if let Some(resulting_state) = input.resulting_state.as_deref() {
        validate_ack_field_len(
            "resulting_state",
            resulting_state,
            ACK_RESULTING_STATE_MAX_BYTES,
        )?;
    }

    let now = Utc::now();
    let observed_at = input.observed_at.unwrap_or(now);
    validate_ack_observed_at(observed_at, now)?;
    let raw_payload = input.raw_payload.unwrap_or_else(|| {
        json!({
            "status": ack_status,
            "message": input.message.clone(),
            "resulting_state": input.resulting_state.clone(),
        })
    });
    validate_ack_raw_payload(&raw_payload)?;

    Ok(AckSubmission {
        target_kind,
        target_id: target_id.to_string(),
        ack_token: ack_token.to_string(),
        ack_status,
        observed_at,
        message: input.message,
        resulting_state: input.resulting_state,
        raw_payload,
    })
}

fn validate_ack_field_len(field: &str, value: &str, max_len: usize) -> Result<(), ApiError> {
    if value.len() > max_len {
        return Err(ApiError::BadRequest(format!(
            "acknowledgement {field} must be at most {max_len} bytes"
        )));
    }
    Ok(())
}

fn validate_ack_raw_payload(value: &Value) -> Result<(), ApiError> {
    let serialized = serde_json::to_vec(value).map_err(|err| {
        ApiError::BadRequest(format!("acknowledgement raw_payload is invalid: {err}"))
    })?;
    if serialized.len() > ACK_RAW_PAYLOAD_MAX_BYTES {
        return Err(ApiError::BadRequest(format!(
            "acknowledgement raw_payload must be at most {ACK_RAW_PAYLOAD_MAX_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_ack_observed_at(
    observed_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if observed_at > now + Duration::seconds(ACK_OBSERVED_AT_FUTURE_SKEW_SECONDS) {
        return Err(ApiError::BadRequest(format!(
            "acknowledgement observed_at must not be more than {ACK_OBSERVED_AT_FUTURE_SKEW_SECONDS} seconds in the future"
        )));
    }
    if observed_at < now - Duration::seconds(ACK_OBSERVED_AT_MAX_AGE_SECONDS) {
        return Err(ApiError::BadRequest(format!(
            "acknowledgement observed_at must be within the last {ACK_OBSERVED_AT_MAX_AGE_SECONDS} seconds"
        )));
    }
    Ok(())
}

pub(crate) async fn load_ack_context(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    action_id: Uuid,
    ack: &AckSubmission,
) -> Result<Option<AckContext>, ApiError> {
    let action = sqlx::query::query(
        "SELECT * FROM response_actions WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(action_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;
    let action = ResponseActionRecord::from_row(action).map_err(ApiError::Database)?;
    if !action.require_acknowledgement {
        return Err(ApiError::BadRequest(
            "acknowledgements are not enabled for this action".to_string(),
        ));
    }

    let delivery = sqlx::query::query(
        r#"SELECT id, status, acknowledgement_deadline, metadata
           FROM response_action_deliveries
           WHERE action_id = $1
             AND tenant_id = $2
             AND target_kind = $3
             AND target_id = $4
           FOR UPDATE"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .bind(ack.target_kind.as_str())
    .bind(&ack.target_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or_else(|| {
        ApiError::BadRequest("acknowledgement target does not match a known delivery".to_string())
    })?;
    let delivery_id: Uuid = delivery.try_get("id").map_err(ApiError::Database)?;
    let delivery_status: String = delivery.try_get("status").map_err(ApiError::Database)?;
    let acknowledgement_deadline: Option<DateTime<Utc>> = delivery
        .try_get("acknowledgement_deadline")
        .map_err(ApiError::Database)?;
    let delivery_metadata: Value = delivery.try_get("metadata").map_err(ApiError::Database)?;
    let expected_ack_token = delivery_metadata
        .get("ack_token")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError::BadRequest("delivery is not acknowledgement-enabled".to_string())
        })?;
    if expected_ack_token != ack.ack_token {
        return Err(ApiError::Forbidden);
    }
    let ack_exists = sqlx::query_scalar::query_scalar::<_, bool>(
        r#"SELECT EXISTS(
                   SELECT 1
                   FROM response_action_acks
                   WHERE delivery_id = $1
               )"#,
    )
    .bind(delivery_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(ApiError::Database)?;
    if ack_exists {
        return Err(ApiError::Conflict(
            "delivery acknowledgement has already been recorded".to_string(),
        ));
    }

    if ensure_ack_window_open(
        tx,
        &action,
        delivery_id,
        &delivery_status,
        acknowledgement_deadline,
        Utc::now(),
    )
    .await?
    {
        return Ok(None);
    }

    Ok(Some(AckContext {
        action,
        delivery_id,
    }))
}

pub(crate) fn requires_endpoint_ack_signed_receipt(
    action: &ResponseActionRecord,
    ack: &AckSubmission,
) -> bool {
    action.target.kind.as_str() == "endpoint"
        && matches!(
            ack.ack_status,
            "acknowledged" | "rolled_back" | "failed" | "rejected" | "expired"
        )
}

async fn ensure_ack_window_open(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    action: &ResponseActionRecord,
    delivery_id: Uuid,
    delivery_status: &str,
    acknowledgement_deadline: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<bool, ApiError> {
    if action.status != "published" {
        return Err(ApiError::Conflict(format!(
            "action status '{}' cannot accept acknowledgements",
            action.status
        )));
    }

    if delivery_status != "published" {
        return Err(ApiError::Conflict(format!(
            "delivery status '{}' cannot accept acknowledgements",
            delivery_status
        )));
    }

    let window_expired = action
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
        || acknowledgement_deadline.is_some_and(|deadline| deadline <= now);
    if !window_expired {
        return Ok(false);
    }

    expire_ack_window(tx, action, delivery_id).await?;
    Ok(true)
}

async fn expire_ack_window(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    action: &ResponseActionRecord,
    delivery_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query::query(
        r#"UPDATE response_actions
           SET status = 'expired',
               updated_at = now()
           WHERE id = $1
             AND tenant_id = $2
             AND status = 'published'"#,
    )
    .bind(action.id)
    .bind(action.tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    sqlx::query::query(
        r#"UPDATE response_action_deliveries
           SET status = 'expired',
               updated_at = now(),
               last_error = COALESCE(last_error, 'acknowledgement window expired')
           WHERE id = $1
             AND action_id = $2
             AND tenant_id = $3
             AND status = 'published'"#,
    )
    .bind(delivery_id)
    .bind(action.id)
    .bind(action.tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    Ok(())
}

pub(crate) fn normalize_ack_status(status: &str) -> Result<&'static str, ApiError> {
    let status = status.trim();
    validate_control_discriminator_len("status", status, ACK_STATUS_MAX_BYTES)?;
    match status {
        "acknowledged" => Ok("acknowledged"),
        "rejected" => Ok("rejected"),
        "failed" => Ok("failed"),
        "expired" => Ok("expired"),
        "rolled_back" => Ok("rolled_back"),
        _ => Err(ApiError::BadRequest(format!(
            "unsupported ack status; allowed values: {ACK_STATUS_ALLOWLIST}"
        ))),
    }
}
