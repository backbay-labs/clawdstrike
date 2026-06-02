//! Authorization guards for response-action mutations.

use super::*;

pub(crate) fn ensure_write_access(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if !matches!(auth.role.as_str(), "owner" | "admin") {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

pub(crate) fn ensure_api_key_executor(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if auth.role == "viewer" || !auth.is_api_key() {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}
