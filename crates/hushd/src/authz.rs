//! Authorization helpers for hushd endpoints.

use axum::http::StatusCode;

use crate::auth::{AuthenticatedActor, Scope};
use crate::rbac::{Action, ResourceRef, ResourceType, RoleScope};

pub fn require_api_key_scope_or_user_permission(
    actor: Option<&AuthenticatedActor>,
    rbac: &crate::rbac::RbacManager,
    required_scope_for_api_keys: Scope,
    resource: ResourceType,
    action: Action,
) -> Result<(), (StatusCode, String)> {
    let Some(actor) = actor else {
        // Auth disabled: allow (hushd is in a trusted environment).
        return Ok(());
    };

    match actor {
        AuthenticatedActor::ApiKey(key) => {
            if !key.has_scope(required_scope_for_api_keys) {
                return Err((StatusCode::FORBIDDEN, "insufficient_scope".to_string()));
            }
            Ok(())
        }
        AuthenticatedActor::User(principal) => {
            let result = rbac
                .check_permission_for_identity(principal, resource, action)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            if result.allowed {
                return Ok(());
            }

            if result.requires_approval == Some(true) {
                return Err((StatusCode::FORBIDDEN, "approval_required".to_string()));
            }

            Err((StatusCode::FORBIDDEN, result.reason))
        }
    }
}

pub fn require_api_key_scope_or_user_permission_with_context(
    actor: Option<&AuthenticatedActor>,
    rbac: &crate::rbac::RbacManager,
    required_scope_for_api_keys: Scope,
    resource: ResourceRef,
    action: Action,
    scope: Option<RoleScope>,
) -> Result<(), (StatusCode, String)> {
    let Some(actor) = actor else {
        // Auth disabled: allow (hushd is in a trusted environment).
        return Ok(());
    };

    match actor {
        AuthenticatedActor::ApiKey(key) => {
            if !key.has_scope(required_scope_for_api_keys) {
                return Err((StatusCode::FORBIDDEN, "insufficient_scope".to_string()));
            }
            Ok(())
        }
        AuthenticatedActor::User(principal) => {
            let result = rbac
                .check_permission_for_identity_with_context(principal, resource, action, scope)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            if result.allowed {
                return Ok(());
            }

            if result.requires_approval == Some(true) {
                return Err((StatusCode::FORBIDDEN, "approval_required".to_string()));
            }

            Err((StatusCode::FORBIDDEN, result.reason))
        }
    }
}
