//! GET /api/v1/packages/{name} and GET /api/v1/packages/{name}/{version}

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;

use crate::error::RegistryError;
use crate::state::AppState;

// -----------------------------------------------------------------------
// Package info (all versions)
// -----------------------------------------------------------------------

#[derive(Serialize)]
pub struct PackageInfoResponse {
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub total_downloads: u64,
    pub versions: Vec<VersionSummary>,
}

#[derive(Serialize)]
pub struct VersionSummary {
    pub version: String,
    pub pkg_type: String,
    pub checksum: String,
    pub yanked: bool,
    pub published_at: String,
    pub downloads: u64,
}

/// GET /api/v1/packages/{name}
pub async fn package_info(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<PackageInfoResponse>, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let pkg = db
        .get_package(&name)?
        .ok_or_else(|| RegistryError::NotFound(format!("package not found: {name}")))?;

    let versions = db.list_versions(&name)?;
    let version_summaries: Vec<VersionSummary> = versions
        .iter()
        .map(|v| VersionSummary {
            version: v.version.clone(),
            pkg_type: v.pkg_type.clone(),
            checksum: v.checksum.clone(),
            yanked: v.yanked,
            published_at: v.published_at.clone(),
            downloads: v.download_count,
        })
        .collect();

    Ok(Json(PackageInfoResponse {
        name: pkg.name,
        description: pkg.description,
        created_at: pkg.created_at,
        updated_at: pkg.updated_at,
        total_downloads: pkg.total_downloads,
        versions: version_summaries,
    }))
}

// -----------------------------------------------------------------------
// Version info
// -----------------------------------------------------------------------

#[derive(Serialize)]
pub struct VersionInfoResponse {
    pub name: String,
    pub version: String,
    pub pkg_type: String,
    pub checksum: String,
    pub manifest_toml: String,
    pub publisher_key: String,
    pub publisher_sig: String,
    pub registry_sig: Option<String>,
    pub dependencies: serde_json::Value,
    pub yanked: bool,
    pub published_at: String,
    pub downloads: u64,
}

/// GET /api/v1/packages/{name}/{version}
pub async fn version_info(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<VersionInfoResponse>, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let v = db
        .get_version(&name, &version)?
        .ok_or_else(|| RegistryError::NotFound(format!("version {version} of {name} not found")))?;

    let dependencies: serde_json::Value = serde_json::from_str(&v.dependencies_json)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    Ok(Json(VersionInfoResponse {
        name: v.name,
        version: v.version,
        pkg_type: v.pkg_type,
        checksum: v.checksum,
        manifest_toml: v.manifest_toml,
        publisher_key: v.publisher_key,
        publisher_sig: v.publisher_sig,
        registry_sig: v.registry_sig,
        dependencies,
        yanked: v.yanked,
        published_at: v.published_at,
        downloads: v.download_count,
    }))
}
