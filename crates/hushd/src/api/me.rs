//! Debug endpoint to show the authenticated actor.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

use crate::auth::{AuthenticatedActor, Scope};
use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct MeResponse {
    pub actor_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<ApiKeyInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<clawdstrike::IdentityPrincipal>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
}

/// GET /api/v1/me
pub async fn me(
    State(_state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
) -> Result<Json<MeResponse>, (StatusCode, String)> {
    let Some(axum::extract::Extension(actor)) = actor else {
        return Err((StatusCode::UNAUTHORIZED, "unauthenticated".to_string()));
    };

    match actor {
        AuthenticatedActor::ApiKey(key) => {
            let mut scopes: Vec<String> = key
                .scopes
                .iter()
                .map(Scope::as_str)
                .map(str::to_string)
                .collect();
            scopes.sort();
            Ok(Json(MeResponse {
                actor_type: "api_key".to_string(),
                api_key: Some(ApiKeyInfo {
                    id: key.id,
                    name: key.name,
                    scopes,
                }),
                user: None,
            }))
        }
        AuthenticatedActor::User(principal) => Ok(Json(MeResponse {
            actor_type: "user".to_string(),
            api_key: None,
            user: Some(principal),
        })),
    }
}
