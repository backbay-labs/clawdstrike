//! GET /api/v1/packages/{name}/{version}/download — download a .cpkg blob.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};

use crate::error::RegistryError;
use crate::state::AppState;

/// GET /api/v1/packages/{name}/{version}/download
pub async fn download(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Response, RegistryError> {
    let checksum = {
        let db = state
            .db
            .lock()
            .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

        let v = db.get_version(&name, &version)?.ok_or_else(|| {
            RegistryError::NotFound(format!("version {version} of {name} not found"))
        })?;
        v.checksum
    };

    let data = state.blobs.load(&checksum)?;

    // Increment download counter (non-blocking: log warning on failure).
    {
        let db = state
            .db
            .lock()
            .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;
        if let Err(e) = db.increment_download(&name, &version) {
            tracing::warn!(name = %name, version = %version, error = %e, "Failed to increment download counter");
        }
    }

    let filename = format!("{}-{}.cpkg", name.replace('/', "-"), version);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(val) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, val);
    }

    Ok((headers, Body::from(data)).into_response())
}
