//! GET /api/v1/search — full-text search for packages.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::db::SearchResult;
use crate::error::RegistryError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_limit() -> u32 {
    20
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub packages: Vec<SearchResult>,
    pub total: usize,
}

/// GET /api/v1/search?q=...&limit=...&offset=...
pub async fn search(
    State(state): State<AppState>,
    Query(params): Query<SearchQuery>,
) -> Result<Json<SearchResponse>, RegistryError> {
    let limit = params.limit.min(100);

    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let total = db.count_search_results(&params.q)? as usize;
    let results = db.search(&params.q, limit, params.offset)?;

    Ok(Json(SearchResponse {
        packages: results,
        total,
    }))
}
