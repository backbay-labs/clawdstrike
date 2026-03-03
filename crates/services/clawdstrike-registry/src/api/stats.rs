//! GET /api/v1/packages/{name}/stats and GET /api/v1/popular — download statistics.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;

use crate::db::{PackageStats, PopularPackage};
use crate::error::RegistryError;
use crate::state::AppState;

/// GET /api/v1/packages/{name}/stats
pub async fn get_package_stats(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<PackageStats>, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let stats = db
        .get_package_stats(&name)?
        .ok_or_else(|| RegistryError::NotFound(format!("package not found: {name}")))?;

    Ok(Json(stats))
}

#[derive(Deserialize)]
pub struct PopularQuery {
    pub limit: Option<u32>,
}

/// GET /api/v1/popular?limit=20
pub async fn get_popular(
    State(state): State<AppState>,
    Query(query): Query<PopularQuery>,
) -> Result<Json<Vec<PopularPackage>>, RegistryError> {
    let limit = query.limit.unwrap_or(20).min(100);
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let packages = db.get_popular_packages(limit)?;
    Ok(Json(packages))
}
