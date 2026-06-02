//! Read-side queries for response actions, deliveries, and acknowledgements.

use super::*;

pub(crate) async fn fetch_action(
    state: &AppState,
    tenant_id: Uuid,
    action_id: Uuid,
) -> Result<ResponseActionRecord, ApiError> {
    let row = sqlx::query::query("SELECT * FROM response_actions WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(action_id)
        .fetch_optional(&state.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;
    ResponseActionRecord::from_row(row).map_err(ApiError::Database)
}

pub(crate) async fn fetch_deliveries(
    state: &AppState,
    tenant_id: Uuid,
    action_id: Uuid,
) -> Result<Vec<ResponseActionDelivery>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM response_action_deliveries
           WHERE tenant_id = $1 AND action_id = $2
           ORDER BY created_at DESC, id DESC"#,
    )
    .bind(tenant_id)
    .bind(action_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(ResponseActionDelivery::from_row)
        .map(|delivery| {
            let mut delivery = delivery?;
            delivery.metadata = scrub_delivery_metadata(delivery.metadata);
            Ok(delivery)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)
}

pub(crate) async fn fetch_acks(
    state: &AppState,
    tenant_id: Uuid,
    action_id: Uuid,
) -> Result<Vec<ResponseActionAckRecord>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM response_action_acks
           WHERE tenant_id = $1 AND action_id = $2
           ORDER BY observed_at DESC, id DESC"#,
    )
    .bind(tenant_id)
    .bind(action_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    rows.into_iter()
        .map(ResponseActionAckRecord::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)
}

pub(crate) async fn fetch_action_detail(
    state: &AppState,
    tenant_id: Uuid,
    action_id: Uuid,
) -> Result<ResponseActionDetail, ApiError> {
    let action = fetch_action(state, tenant_id, action_id).await?;
    let deliveries = fetch_deliveries(state, tenant_id, action_id).await?;
    let acknowledgements = fetch_acks(state, tenant_id, action_id).await?;
    Ok(ResponseActionDetail {
        action,
        deliveries,
        acknowledgements,
    })
}
