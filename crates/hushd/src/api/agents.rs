//! Agent and delegation endpoints for multi-agent orchestration.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;

use crate::state::AppState;

/// Single agent identity as returned by the API.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentResponse {
    pub id: String,
    pub name: String,
    pub role: String,
    pub trust_level: String,
    pub public_key: String,
    pub capabilities: Vec<serde_json::Value>,
    pub created_at: Option<String>,
}

/// Response wrapper for the agents list.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAgentsResponse {
    pub agents: Vec<AgentResponse>,
}

/// Single delegation token as returned by the API.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationResponse {
    pub id: String,
    pub from: String,
    pub to: String,
    pub capabilities: Vec<serde_json::Value>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub purpose: Option<String>,
    pub revoked: bool,
}

/// Response wrapper for the delegations list.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDelegationsResponse {
    pub delegations: Vec<DelegationResponse>,
}

/// GET /api/v1/agents
pub async fn list_agents(
    State(state): State<AppState>,
) -> Result<Json<ListAgentsResponse>, (StatusCode, String)> {
    let identities = state
        .agent_registry
        .list()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let agents = identities
        .into_iter()
        .map(|identity| {
            let capabilities: Vec<serde_json::Value> = identity
                .capabilities
                .iter()
                .filter_map(|c| serde_json::to_value(c).ok())
                .collect();

            let role = serde_json::to_value(&identity.role)
                .ok()
                .and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s),
                    serde_json::Value::Object(map) => {
                        map.get("custom").and_then(|v| v.as_str()).map(String::from)
                    }
                    _ => None,
                })
                .unwrap_or_default();

            let trust_level = serde_json::to_value(identity.trust_level)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();

            let public_key = serde_json::to_value(&identity.public_key)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();

            AgentResponse {
                id: identity.id.to_string(),
                name: identity.name,
                role,
                trust_level,
                public_key,
                capabilities,
                created_at: identity.metadata.get("created_at").cloned(),
            }
        })
        .collect();

    Ok(Json(ListAgentsResponse { agents }))
}

/// GET /api/v1/delegations
pub async fn list_delegations(
    State(state): State<AppState>,
) -> Result<Json<ListDelegationsResponse>, (StatusCode, String)> {
    let tokens = state.delegation_tokens.read().await;

    let delegations = tokens
        .iter()
        .map(|token| {
            let capabilities: Vec<serde_json::Value> = token
                .claims
                .cap
                .iter()
                .filter_map(|c| serde_json::to_value(c).ok())
                .collect();

            DelegationResponse {
                id: token.claims.jti.clone(),
                from: token.claims.iss.to_string(),
                to: token.claims.sub.to_string(),
                capabilities,
                issued_at: token.claims.iat,
                expires_at: token.claims.exp,
                purpose: token.claims.pur.clone(),
                revoked: false,
            }
        })
        .collect();

    Ok(Json(ListDelegationsResponse { delegations }))
}
