//! Cloud-side approval routes for NATS-escalated approval requests.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::approval::{Approval, ResolveApprovalInput};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/approvals", get(list_approvals))
        .route("/approvals/{id}/resolve", post(resolve_approval))
}

/// List pending approvals for the authenticated tenant.
async fn list_approvals(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<Approval>>, ApiError> {
    let rows = sqlx::query::query(
        "SELECT * FROM approvals WHERE tenant_id = $1 AND status = 'pending' ORDER BY created_at DESC",
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let approvals: Vec<Approval> = rows
        .into_iter()
        .map(Approval::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;

    Ok(Json(approvals))
}

/// Resolve a pending approval request (approve or deny).
async fn resolve_approval(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(input): Json<ResolveApprovalInput>,
) -> Result<Json<Approval>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let resolved_by = input.resolved_by.unwrap_or_else(|| "cloud-api".to_string());

    let row = sqlx::query::query(
        r#"UPDATE approvals
           SET status = $3, resolved_by = $4, resolved_at = now()
           WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
           RETURNING *"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .bind(&input.resolution)
    .bind(&resolved_by)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let approval = Approval::from_row(row).map_err(ApiError::Database)?;

    // Publish resolution to NATS so the agent picks it up.
    // When a signing keypair is available, wrap the payload in a Spine signed envelope
    // so the agent can verify authenticity (review item #4).
    let subject = format!(
        "approvals.{}.{}.response",
        auth.tenant_id, approval.agent_id
    );
    let payload = serde_json::json!({
        "approval_id": approval.id,
        "resolution": input.resolution,
        "resolved_by": resolved_by,
    });

    let payload_bytes = if let Some(ref keypair) = state.signing_keypair {
        match spine::build_signed_envelope(keypair, 0, None, payload.clone(), spine::now_rfc3339())
        {
            Ok(envelope) => serde_json::to_vec(&envelope).unwrap_or_default(),
            Err(err) => {
                tracing::warn!(error = %err, "Failed to sign approval resolution; sending unsigned");
                serde_json::to_vec(&payload).unwrap_or_default()
            }
        }
    } else {
        serde_json::to_vec(&payload).unwrap_or_default()
    };

    if let Err(err) = state
        .nats
        .publish(subject.clone(), payload_bytes.into())
        .await
    {
        tracing::warn!(
            error = %err,
            subject = %subject,
            "Failed to publish approval resolution to NATS"
        );
    }

    Ok(Json(approval))
}
