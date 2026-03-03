//! DELETE /api/v1/packages/{name}/{version} — yank a package version.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;

use crate::error::RegistryError;
use crate::index;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct YankResponse {
    pub name: String,
    pub version: String,
    pub yanked: bool,
}

/// DELETE /api/v1/packages/{name}/{version}
pub async fn yank(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<YankResponse>, RegistryError> {
    let yanked = {
        let db = state
            .db
            .lock()
            .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

        let payload = format!("yank:{name}:{version}");
        let caller_key = crate::auth::verify_signed_caller(&headers, &payload)?;
        if let Some((scope, _basename)) = crate::auth::parse_package_scope(&name) {
            crate::auth::authorize_scoped_publish(&db, &scope, &caller_key)?;
        } else {
            crate::auth::authorize_unscoped_package_admin(&db, &name, &caller_key)?;
        }

        // Verify the version exists.
        db.get_version(&name, &version)?.ok_or_else(|| {
            RegistryError::NotFound(format!("version {version} of {name} not found"))
        })?;

        db.yank_version(&name, &version)?
    };

    // Always regenerate sparse index after a successful yank request.
    // This keeps retries self-healing if a previous request already toggled
    // the DB row but failed while writing index files.
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;
    index::update_index(&db, &state.config.index_dir(), &name)?;

    if yanked {
        tracing::info!(name = %name, version = %version, "Version yanked");
    }

    Ok(Json(YankResponse {
        name,
        version,
        yanked,
    }))
}
