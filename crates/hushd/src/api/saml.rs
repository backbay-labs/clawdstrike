//! SAML assertion exchange endpoint.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::auth::AuthenticatedActor;
use crate::session::CreateSessionOptions;
use crate::session::SessionError;
use crate::state::AppState;

#[derive(Clone, Debug, Deserialize)]
pub struct SamlExchangeRequest {
    pub assertion: String,
    #[serde(default)]
    pub session: Option<CreateSessionOptions>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlExchangeResponse {
    pub session: clawdstrike::SessionContext,
}

/// POST /api/v1/auth/saml
pub async fn exchange_saml(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(request): Json<SamlExchangeRequest>,
) -> Result<Json<SamlExchangeResponse>, (StatusCode, String)> {
    let Some(axum::extract::Extension(actor)) = actor else {
        return Err((StatusCode::UNAUTHORIZED, "unauthenticated".to_string()));
    };

    let Some(saml_cfg) = state.config.identity.saml.as_ref() else {
        return Err((StatusCode::NOT_FOUND, "saml_not_configured".to_string()));
    };

    let identity = crate::identity::saml::parse_assertion(saml_cfg, &request.assertion)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let mut options = request.session.unwrap_or_default();

    // Server-derived request context takes precedence.
    options.request = Some(clawdstrike::RequestContext {
        request_id: uuid::Uuid::new_v4().to_string(),
        source_ip: Some(addr.ip().to_string()),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geo_location: headers
            .get("X-Hush-Country")
            .and_then(|v| v.to_str().ok())
            .map(|c| clawdstrike::GeoLocation {
                country: Some(c.to_string()),
                region: None,
                city: None,
                latitude: None,
                longitude: None,
            }),
        is_vpn: None,
        is_corporate_network: None,
        timestamp: chrono::Utc::now().to_rfc3339(),
    });

    // Bind sessions created via service accounts to the API key id.
    if let AuthenticatedActor::ApiKey(key) = &actor {
        let mut state_obj = match options.state.take() {
            Some(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        };
        state_obj.insert(
            "bound_api_key_id".to_string(),
            serde_json::Value::String(key.id.clone()),
        );
        options.state = Some(serde_json::Value::Object(state_obj));
    }

    let session = match state.sessions.create_session(identity, Some(options)) {
        Ok(session) => session,
        Err(SessionError::InvalidBinding(_)) => {
            return Err((
                StatusCode::BAD_REQUEST,
                "invalid_session_binding".to_string(),
            ));
        }
        Err(err) => return Err((StatusCode::INTERNAL_SERVER_ERROR, err.to_string())),
    };

    // Audit + broadcast.
    let mut audit = crate::audit::AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "saml_session_created".to_string();
    audit.action_type = "session".to_string();
    audit.target = Some(session.session_id.clone());
    audit.message = Some("SAML session created".to_string());
    audit.metadata = Some(serde_json::json!({ "principal": session.identity }));
    let _ = state.ledger.record(&audit);

    state.broadcast(crate::state::DaemonEvent {
        event_type: "saml_session_created".to_string(),
        data: serde_json::json!({ "session_id": session.session_id }),
    });

    Ok(Json(SamlExchangeResponse { session }))
}
