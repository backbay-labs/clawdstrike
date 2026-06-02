//! Axum request handlers for the response-action lifecycle endpoints.

use super::*;

pub(crate) async fn create_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(input): Json<CreateResponseActionRequest>,
) -> Result<Json<ResponseActionRecord>, ApiError> {
    ensure_write_access(&auth)?;
    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let draft = prepare_create_action(&mut tx, &auth, input).await?;
    let action = insert_action(&mut tx, &auth, draft).await?;
    link_action_to_source_detection(
        &mut tx,
        auth.tenant_id,
        action.id,
        action.source_detection_id,
    )
    .await?;
    tx.commit().await.map_err(ApiError::Database)?;

    Ok(Json(action))
}

pub async fn create_and_publish_internal_action(
    state: &AppState,
    auth: &AuthenticatedTenant,
    input: CreateResponseActionRequest,
) -> Result<ResponseActionDetail, ApiError> {
    ensure_write_access(auth)?;
    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let draft = prepare_create_action(&mut tx, auth, input).await?;
    let action = insert_action(&mut tx, auth, draft).await?;
    link_action_to_source_detection(
        &mut tx,
        auth.tenant_id,
        action.id,
        action.source_detection_id,
    )
    .await?;
    tx.commit().await.map_err(ApiError::Database)?;

    publish_action(state, &auth.slug, auth.tenant_id, action.id, false)
        .await
        .map(|Json(detail)| detail)
}

pub(crate) async fn list_actions(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<ResponseActionRecord>>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM response_actions
           WHERE tenant_id = $1
           ORDER BY requested_at DESC, id DESC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let actions = rows
        .into_iter()
        .map(ResponseActionRecord::from_row)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::Database)?;
    Ok(Json(actions))
}

pub(crate) async fn get_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    let action = fetch_action(&state, auth.tenant_id, id).await?;
    let deliveries = fetch_deliveries(&state, auth.tenant_id, id).await?;
    let acknowledgements = fetch_acks(&state, auth.tenant_id, id).await?;

    Ok(Json(ResponseActionDetail {
        action,
        deliveries,
        acknowledgements,
    }))
}

pub(crate) async fn approve_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    ensure_write_access(&auth)?;
    publish_action(&state, &auth.slug, auth.tenant_id, id, false).await
}

pub(crate) async fn retry_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    ensure_write_access(&auth)?;
    publish_action(&state, &auth.slug, auth.tenant_id, id, true).await
}

pub(crate) async fn cancel_action(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<ResponseActionRecord>, ApiError> {
    ensure_write_access(&auth)?;

    let row = sqlx::query::query(
        r#"UPDATE response_actions
           SET status = 'cancelled',
               updated_at = now()
           WHERE id = $1
             AND tenant_id = $2
             AND status IN ('queued', 'approved', 'published', 'failed')
           RETURNING *"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    sqlx::query::query(
        r#"UPDATE response_action_deliveries
           SET status = 'cancelled',
               updated_at = now()
           WHERE action_id = $1
             AND tenant_id = $2
             AND status IN ('queued', 'approved', 'published', 'failed')"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .execute(&state.db)
    .await
    .map_err(ApiError::Database)?;

    Ok(Json(
        ResponseActionRecord::from_row(row).map_err(ApiError::Database)?,
    ))
}

pub(crate) async fn record_ack(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(input): Json<RecordResponseAckRequest>,
) -> Result<Json<ResponseActionDetail>, ApiError> {
    ensure_api_key_executor(&auth)?;
    let ack = parse_ack_submission(input)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let context = match load_ack_context(&mut tx, auth.tenant_id, id, &ack).await? {
        Some(context) => context,
        None => {
            tx.commit().await.map_err(ApiError::Database)?;
            return Err(ApiError::Conflict(
                "acknowledgement window has expired".to_string(),
            ));
        }
    };
    validate_endpoint_ack_signed_receipt(&mut tx, &context, &ack).await?;
    persist_ack_submission(&mut tx, &context, &ack).await?;
    tx.commit().await.map_err(ApiError::Database)?;
    get_action(State(state), auth, Path(id)).await
}

pub(crate) async fn record_agent_ack(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(input): Json<RecordResponseAckRequest>,
) -> Result<Json<RecordAgentAckResponse>, ApiError> {
    let ack = parse_ack_submission(input)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let tenant_id = load_ack_action_tenant_id(&mut tx, id).await?;
    let context = match load_ack_context(&mut tx, tenant_id, id, &ack).await? {
        Some(context) => context,
        None => {
            tx.commit().await.map_err(ApiError::Database)?;
            return Err(ApiError::Conflict(
                "acknowledgement window has expired".to_string(),
            ));
        }
    };
    validate_endpoint_ack_signed_receipt(&mut tx, &context, &ack).await?;
    persist_ack_submission(&mut tx, &context, &ack).await?;
    tx.commit().await.map_err(ApiError::Database)?;

    Ok(Json(RecordAgentAckResponse {
        accepted: true,
        action_id: id,
        target_kind: ack.target_kind.as_str().to_string(),
        target_id: ack.target_id,
        status: ack.ack_status.to_string(),
        observed_at: ack.observed_at,
    }))
}
