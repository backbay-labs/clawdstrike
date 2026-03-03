//! GET /api/v1/index/{name} — serve sparse index entries.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::error::RegistryError;
use crate::index::build_index_entry;
use crate::state::AppState;

/// GET /api/v1/index/{name}
///
/// Returns the sparse index JSON for a package, with an ETag header for caching.
pub async fn sparse_index(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let entry = build_index_entry(&db, &name)?
        .ok_or_else(|| RegistryError::NotFound(format!("package not found: {name}")))?;

    let body = serde_json::to_string(&entry)
        .map_err(|e| RegistryError::Internal(format!("serialize error: {e}")))?;

    // ETag based on SHA-256 of the response body.
    let etag = format!("\"{}\"", hush_core::sha256_hex(body.as_bytes()));

    // Conditional request support.
    if let Some(if_none_match) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        let matches = if_none_match
            .split(',')
            .map(|v| v.trim())
            .any(|candidate| candidate == etag || candidate == "*");
        if matches {
            let mut not_modified_headers = HeaderMap::new();
            if let Ok(val) = HeaderValue::from_str(&etag) {
                not_modified_headers.insert(header::ETAG, val);
            }
            not_modified_headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );
            return Ok((StatusCode::NOT_MODIFIED, not_modified_headers).into_response());
        }
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(val) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, val);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );

    Ok((headers, body).into_response())
}
