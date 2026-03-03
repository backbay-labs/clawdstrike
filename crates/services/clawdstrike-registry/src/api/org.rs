//! Organization management API endpoints.

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
pub struct CreateOrgRequest {
    pub name: String,
    pub display_name: Option<String>,
    /// Ed25519 public key hex of the creator.
    pub publisher_key: String,
}

#[derive(Debug, Serialize)]
pub struct CreateOrgResponse {
    pub name: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct OrgInfoResponse {
    pub name: String,
    pub display_name: Option<String>,
    pub verified: bool,
    pub member_count: i64,
    pub package_count: i64,
}

#[derive(Serialize)]
pub struct OrgMembersResponse {
    pub members: Vec<MemberEntry>,
}

#[derive(Serialize)]
pub struct MemberEntry {
    pub publisher_key: String,
    pub role: String,
    pub joined_at: String,
}

#[derive(Deserialize)]
pub struct InviteMemberRequest {
    pub publisher_key: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "member".to_string()
}

fn is_valid_org_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }

    let bytes = name.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    let starts_and_ends_alnum = (first.is_ascii_lowercase() || first.is_ascii_digit())
        && (last.is_ascii_lowercase() || last.is_ascii_digit());
    starts_and_ends_alnum
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

#[derive(Serialize)]
pub struct OrgPackagesResponse {
    pub packages: Vec<OrgPackageEntry>,
}

#[derive(Serialize)]
pub struct OrgPackageEntry {
    pub name: String,
    pub description: Option<String>,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/v1/orgs — create a new organization (auth required).
pub async fn create_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateOrgRequest>,
) -> Result<(StatusCode, Json<CreateOrgResponse>), RegistryError> {
    if !is_valid_org_name(&req.name) {
        return Err(RegistryError::BadRequest(
            "organization name must match [a-z0-9]([a-z0-9-]*[a-z0-9])? and be 1-64 characters"
                .into(),
        ));
    }

    let create_payload = format!(
        "org:create:{}:{}:{}",
        req.name,
        req.publisher_key,
        req.display_name.as_deref().unwrap_or("")
    );
    let caller_key = crate::auth::verify_signed_caller(&headers, &create_payload)?;
    if caller_key != req.publisher_key {
        return Err(RegistryError::Unauthorized(
            "caller key must match create_org.publisher_key".into(),
        ));
    }

    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    db.create_organization(&req.name, req.display_name.as_deref(), &req.publisher_key)?;

    let org = db
        .get_organization(&req.name)?
        .ok_or_else(|| RegistryError::Internal("organization just created but not found".into()))?;

    Ok((
        StatusCode::CREATED,
        Json(CreateOrgResponse {
            name: org.name,
            created_at: org.created_at,
        }),
    ))
}

/// GET /api/v1/orgs/{name} — get organization details (public).
pub async fn get_org(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<OrgInfoResponse>, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let org = db
        .get_organization(&name)?
        .ok_or_else(|| RegistryError::NotFound(format!("organization '{}' not found", name)))?;

    let member_count = db.count_org_members(org.id)?;
    let package_count = db.count_org_packages(&name)?;

    Ok(Json(OrgInfoResponse {
        name: org.name,
        display_name: org.display_name,
        verified: org.verified,
        member_count,
        package_count,
    }))
}

/// GET /api/v1/orgs/{name}/members — list members.
pub async fn list_members(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<OrgMembersResponse>, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let org = db
        .get_organization(&name)?
        .ok_or_else(|| RegistryError::NotFound(format!("organization '{}' not found", name)))?;

    let members = db.get_org_members(org.id)?;

    Ok(Json(OrgMembersResponse {
        members: members
            .into_iter()
            .map(|m| MemberEntry {
                publisher_key: m.publisher_key,
                role: m.role,
                joined_at: m.joined_at,
            })
            .collect(),
    }))
}

/// POST /api/v1/orgs/{name}/members — invite a member (auth required).
pub async fn invite_member(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(req): Json<InviteMemberRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), RegistryError> {
    if !matches!(req.role.as_str(), "owner" | "maintainer" | "member") {
        return Err(RegistryError::BadRequest(format!(
            "invalid role '{}'. Must be one of: owner, maintainer, member",
            req.role
        )));
    }

    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let org = db
        .get_organization(&name)?
        .ok_or_else(|| RegistryError::NotFound(format!("organization '{}' not found", name)))?;

    let payload = format!("org:invite:{name}:{}:{}", req.publisher_key, req.role);
    let caller_key = crate::auth::verify_signed_caller(&headers, &payload)?;

    // Verify the caller is an owner or maintainer of the organization.
    let caller_role = db.get_member_role(org.id, &caller_key)?;
    match caller_role.as_deref() {
        Some("owner" | "maintainer") => {}
        Some(_) => {
            return Err(RegistryError::Unauthorized(format!(
                "caller does not have permission to invite members to @{}",
                name
            )));
        }
        None => {
            return Err(RegistryError::Unauthorized(format!(
                "caller is not a member of @{}",
                name
            )));
        }
    }

    // Maintainers may invite members/maintainers but cannot mint new owners.
    if caller_role.as_deref() == Some("maintainer") && req.role == "owner" {
        return Err(RegistryError::Unauthorized(
            "maintainers cannot promote members to owner".into(),
        ));
    }

    db.add_org_member(org.id, &req.publisher_key, &req.role, Some(&caller_key))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "publisher_key": req.publisher_key,
            "role": req.role,
            "org": name,
        })),
    ))
}

/// DELETE /api/v1/orgs/{name}/members/{key} — remove a member (auth required).
pub async fn remove_member(
    State(state): State<AppState>,
    Path((name, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let org = db
        .get_organization(&name)?
        .ok_or_else(|| RegistryError::NotFound(format!("organization '{}' not found", name)))?;

    let payload = format!("org:remove:{name}:{key}");
    let caller_key = crate::auth::verify_signed_caller(&headers, &payload)?;
    let caller_role = db.get_member_role(org.id, &caller_key)?;
    match caller_role.as_deref() {
        Some("owner" | "maintainer") => {}
        Some(_) => {
            return Err(RegistryError::Unauthorized(format!(
                "caller does not have permission to remove members from @{}",
                name
            )));
        }
        None => {
            return Err(RegistryError::Unauthorized(format!(
                "caller is not a member of @{}",
                name
            )));
        }
    }

    // Maintainers cannot remove organization owners.
    if caller_role.as_deref() == Some("maintainer")
        && db.get_member_role(org.id, &key)?.as_deref() == Some("owner")
    {
        return Err(RegistryError::Unauthorized(
            "maintainers cannot remove organization owners".into(),
        ));
    }

    db.remove_org_member(org.id, &key)?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/v1/orgs/{name}/packages — list organization packages (public).
pub async fn list_org_packages(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<OrgPackagesResponse>, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    db.get_organization(&name)?
        .ok_or_else(|| RegistryError::NotFound(format!("organization '{}' not found", name)))?;

    let packages = db.list_org_packages(&name)?;

    Ok(Json(OrgPackagesResponse {
        packages: packages
            .into_iter()
            .map(|p| OrgPackageEntry {
                name: p.name,
                description: p.description,
                updated_at: p.updated_at,
            })
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::is_valid_org_name;

    #[test]
    fn org_name_validation_accepts_scope_compatible_names() {
        assert!(is_valid_org_name("acme"));
        assert!(is_valid_org_name("acme-1"));
        assert!(is_valid_org_name("1acme"));
    }

    #[test]
    fn org_name_validation_rejects_non_scope_compatible_names() {
        assert!(!is_valid_org_name(""));
        assert!(!is_valid_org_name("-acme"));
        assert!(!is_valid_org_name("acme-"));
        assert!(!is_valid_org_name("Acme"));
        assert!(!is_valid_org_name("acme_org"));
        assert!(!is_valid_org_name(&"a".repeat(65)));
    }
}
