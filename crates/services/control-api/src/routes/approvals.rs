//! Cloud-side approval routes for NATS-escalated approval requests.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::approval::{Approval, ResolveApprovalInput};
use crate::services::approval_resolution_outbox;
use crate::services::tenant_provisioner::tenant_subject_prefix;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/approvals", get(list_approvals))
        .route("/approvals/{id}/resolve", post(resolve_approval))
}

fn is_valid_resolution(resolution: &str) -> bool {
    resolution == "approved" || resolution == "denied"
}

fn approval_response_subject(tenant_slug: &str, agent_id: &str) -> String {
    format!(
        "{}.approval.response.{}",
        tenant_subject_prefix(tenant_slug),
        agent_id
    )
}

fn build_resolution_payload_bytes(
    payload: serde_json::Value,
    signing_enabled: bool,
    signing_keypair: Option<&hush_core::Keypair>,
) -> Result<Vec<u8>, ApiError> {
    if signing_enabled {
        let keypair = signing_keypair.ok_or_else(|| {
            ApiError::Internal("approval signing is enabled but keypair is not loaded".to_string())
        })?;
        let envelope =
            spine::build_signed_envelope(keypair, 0, None, payload, spine::now_rfc3339()).map_err(
                |e| ApiError::Internal(format!("failed to sign approval resolution: {e}")),
            )?;
        return serde_json::to_vec(&envelope).map_err(|e| {
            ApiError::Internal(format!("failed to serialize signed approval envelope: {e}"))
        });
    }

    if let Some(keypair) = signing_keypair {
        return match spine::build_signed_envelope(
            keypair,
            0,
            None,
            payload.clone(),
            spine::now_rfc3339(),
        ) {
            Ok(envelope) => Ok(serde_json::to_vec(&envelope).unwrap_or_default()),
            Err(err) => {
                tracing::warn!(error = %err, "Failed to sign approval resolution; sending unsigned");
                Ok(serde_json::to_vec(&payload).unwrap_or_default())
            }
        };
    }

    Ok(serde_json::to_vec(&payload).unwrap_or_default())
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

    // Validate resolution against known values.
    if !is_valid_resolution(&input.resolution) {
        return Err(ApiError::BadRequest(format!(
            "Invalid resolution '{}'. Must be 'approved' or 'denied'",
            input.resolution
        )));
    }

    let resolved_by = input.resolved_by.unwrap_or_else(|| "control-api".to_string());

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
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
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let approval = Approval::from_row(row).map_err(ApiError::Database)?;

    // Publish resolution to NATS so the agent picks it up.
    // When a signing keypair is available, wrap the payload in a Spine signed envelope
    // so the agent can verify authenticity (review item #4).
    let subject = approval_response_subject(&auth.slug, &approval.agent_id);
    let payload = serde_json::json!({
        "approval_id": approval.id,
        "request_id": approval.request_id,
        "resolution": input.resolution,
        "resolved_by": resolved_by,
    });

    let payload_bytes = build_resolution_payload_bytes(
        payload,
        state.config.approval_signing_enabled,
        state.signing_keypair.as_deref(),
    )?;

    let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|err| ApiError::Internal(format!("failed to serialize outbox payload: {err}")))?;

    approval_resolution_outbox::enqueue(
        &mut *tx,
        approval.id,
        approval.tenant_id,
        &auth.slug,
        &approval.agent_id,
        &subject,
        &payload_json,
    )
    .await
    .map_err(ApiError::Database)?;

    tx.commit().await.map_err(ApiError::Database)?;

    // Best-effort immediate dispatch; background outbox worker guarantees retry.
    if let Err(err) =
        approval_resolution_outbox::process_due_for_approval(&state.nats, &state.db, approval.id)
            .await
    {
        tracing::warn!(
            error = %err,
            approval_id = %approval.id,
            "Failed immediate dispatch for approval resolution outbox entry"
        );
    }

    Ok(Json(approval))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn resolution_validation_accepts_only_known_values() {
        assert!(is_valid_resolution("approved"));
        assert!(is_valid_resolution("denied"));
        assert!(!is_valid_resolution("pending"));
        assert!(!is_valid_resolution("approve"));
    }

    #[test]
    fn approval_subject_uses_tenant_prefix_contract() {
        assert_eq!(
            approval_response_subject("acme", "agent-123"),
            "tenant-acme.clawdstrike.approval.response.agent-123"
        );
    }

    #[test]
    fn signing_enabled_requires_keypair() {
        let err =
            build_resolution_payload_bytes(serde_json::json!({"approval_id": "a-1"}), true, None)
                .unwrap_err();
        assert!(matches!(err, ApiError::Internal(_)));
    }

    #[test]
    fn signing_enabled_produces_signed_envelope() {
        let kp = hush_core::Keypair::generate();
        let bytes = build_resolution_payload_bytes(
            serde_json::json!({
                "approval_id": "a-1",
                "resolution": "approved",
                "resolved_by": "control-api",
            }),
            true,
            Some(&kp),
        )
        .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(spine::verify_envelope(&envelope).unwrap());
    }
}
