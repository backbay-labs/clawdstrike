//! Acknowledgement persistence and delivery-ledger updates.

use crate::routes::response_actions::*;
pub(crate) async fn persist_ack_submission(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    context: &AckContext,
    ack: &AckSubmission,
) -> Result<(), ApiError> {
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
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(context.delivery_id)
    .bind(context.action.id)
    .bind(context.action.tenant_id)
    .bind(ack.target_kind.as_str())
    .bind(&ack.target_id)
    .bind(ack.observed_at)
    .bind(ack.ack_status)
    .bind(ack.message.as_deref())
    .bind(ack.resulting_state.as_deref())
    .bind(&ack.raw_payload)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    sqlx::query::query(
        r#"UPDATE response_action_deliveries
           SET status = $4,
               acknowledged_at = $3,
               updated_at = now(),
               last_error = CASE WHEN $4 IN ('failed', 'rejected', 'expired') THEN COALESCE($5, last_error) ELSE last_error END
           WHERE id = $6
             AND action_id = $1
             AND tenant_id = $2"#,
    )
    .bind(context.action.id)
    .bind(context.action.tenant_id)
    .bind(ack.observed_at)
    .bind(ack.ack_status)
    .bind(ack.message.as_deref())
    .bind(context.delivery_id)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    sqlx::query::query(
        r#"UPDATE response_actions
           SET status = $3,
               updated_at = now()
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(context.action.id)
    .bind(context.action.tenant_id)
    .bind(ack.ack_status)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    Ok(())
}
