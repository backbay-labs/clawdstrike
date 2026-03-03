//! Trusted publisher management API endpoints for OIDC-based CI/CD publishing.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::RegistryError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AddTrustedPublisherRequest {
    /// OIDC provider: "github" or "gitlab".
    pub provider: String,
    /// Repository identifier, e.g., "owner/repo".
    pub repository: String,
    /// Optional workflow filter (e.g., "release.yml").
    pub workflow: Option<String>,
    /// Optional environment filter (e.g., "production").
    pub environment: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrustedPublisherResponse {
    pub id: i64,
    pub package_name: String,
    pub provider: String,
    pub repository: String,
    pub workflow: Option<String>,
    pub environment: Option<String>,
    pub created_at: String,
    pub created_by: String,
}

#[derive(Serialize)]
pub struct TrustedPublishersListResponse {
    pub trusted_publishers: Vec<TrustedPublisherResponse>,
}

fn encode_signed_field(value: &str) -> String {
    format!("{}:{value}", value.len())
}

pub(crate) fn add_trusted_publisher_signed_payload(
    package_name: &str,
    provider: &str,
    repository: &str,
    workflow: Option<&str>,
    environment: Option<&str>,
) -> String {
    format!(
        "trusted-publisher:add:v2:name={};provider={};repository={};workflow={};environment={}",
        encode_signed_field(package_name),
        encode_signed_field(provider),
        encode_signed_field(repository),
        encode_signed_field(workflow.unwrap_or("")),
        encode_signed_field(environment.unwrap_or("")),
    )
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/v1/packages/{name}/trusted-publishers — add a trusted publisher (auth required).
pub async fn add_trusted_publisher(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AddTrustedPublisherRequest>,
) -> Result<(StatusCode, Json<TrustedPublisherResponse>), RegistryError> {
    let provider = req.provider.to_ascii_lowercase();

    // Validate provider.
    if !matches!(provider.as_str(), "github" | "gitlab") {
        return Err(RegistryError::BadRequest(format!(
            "unsupported OIDC provider '{}'. Must be 'github' or 'gitlab'",
            req.provider
        )));
    }

    // Validate repository format.
    if !req.repository.contains('/') {
        return Err(RegistryError::BadRequest(
            "repository must be in 'owner/repo' format".into(),
        ));
    }

    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let payload = add_trusted_publisher_signed_payload(
        &name,
        &provider,
        &req.repository,
        req.workflow.as_deref(),
        req.environment.as_deref(),
    );
    let caller_key = crate::auth::verify_signed_caller(&headers, &payload)?;

    // For scoped packages, verify org role. For unscoped packages, require
    // package-level admin rights for existing packages. Brand-new unscoped
    // packages are allowed to bootstrap trusted publishers before first
    // release so OIDC publish can complete.
    if let Some((scope, _basename)) = crate::auth::parse_package_scope(&name) {
        crate::auth::authorize_scoped_publish(&db, &scope, &caller_key)?;
    } else if db.get_package(&name)?.is_some() {
        crate::auth::authorize_unscoped_package_admin(&db, &name, &caller_key)?;
    }

    let id = db.add_trusted_publisher(
        &name,
        &provider,
        &req.repository,
        req.workflow.as_deref(),
        req.environment.as_deref(),
        &caller_key,
    )?;

    let publishers = db.get_trusted_publishers(&name)?;
    let publisher = publishers.into_iter().find(|p| p.id == id).ok_or_else(|| {
        RegistryError::Internal("trusted publisher just created but not found".into())
    })?;

    Ok((
        StatusCode::CREATED,
        Json(TrustedPublisherResponse {
            id: publisher.id,
            package_name: publisher.package_name,
            provider: publisher.provider,
            repository: publisher.repository,
            workflow: publisher.workflow,
            environment: publisher.environment,
            created_at: publisher.created_at,
            created_by: publisher.created_by,
        }),
    ))
}

/// GET /api/v1/packages/{name}/trusted-publishers — list trusted publishers (public).
pub async fn list_trusted_publishers(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<TrustedPublishersListResponse>, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let publishers = db.get_trusted_publishers(&name)?;

    Ok(Json(TrustedPublishersListResponse {
        trusted_publishers: publishers
            .into_iter()
            .map(|p| TrustedPublisherResponse {
                id: p.id,
                package_name: p.package_name,
                provider: p.provider,
                repository: p.repository,
                workflow: p.workflow,
                environment: p.environment,
                created_at: p.created_at,
                created_by: p.created_by,
            })
            .collect(),
    }))
}

/// DELETE /api/v1/packages/{name}/trusted-publishers/{id} — remove a trusted publisher (auth required).
pub async fn remove_trusted_publisher(
    State(state): State<AppState>,
    Path((name, id)): Path<(String, i64)>,
    headers: HeaderMap,
) -> Result<StatusCode, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let payload = format!("trusted-publisher:remove:{name}:{id}");
    let caller_key = crate::auth::verify_signed_caller(&headers, &payload)?;

    if let Some((scope, _basename)) = crate::auth::parse_package_scope(&name) {
        crate::auth::authorize_scoped_publish(&db, &scope, &caller_key)?;
    } else {
        crate::auth::authorize_unscoped_package_admin(&db, &name, &caller_key)?;
    }

    let deleted = db.remove_trusted_publisher_for_package(&name, id)?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(RegistryError::NotFound(format!(
            "trusted publisher with id {id} not found"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::add_trusted_publisher_signed_payload;

    #[test]
    fn add_payload_distinguishes_fields_with_colons() {
        // These two tuples collide under the legacy colon-delimited payload format.
        let payload_a =
            add_trusted_publisher_signed_payload("pkg:owner", "github", "acme/repo", None, None);
        let payload_b =
            add_trusted_publisher_signed_payload("pkg", "owner", "github:acme/repo", None, None);

        assert_ne!(payload_a, payload_b);
    }

    #[test]
    fn add_payload_treats_absent_optional_fields_as_empty() {
        let with_none =
            add_trusted_publisher_signed_payload("pkg", "github", "acme/repo", None, None);
        let with_empty =
            add_trusted_publisher_signed_payload("pkg", "github", "acme/repo", Some(""), Some(""));

        assert_eq!(with_none, with_empty);
    }
}
