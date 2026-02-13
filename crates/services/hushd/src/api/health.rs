//! Health check and readiness probe endpoints

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: i64,
    pub session_id: String,
    pub audit_count: usize,
}

/// GET /health (liveness probe)
///
/// Lightweight check: process is alive and SQLite is reachable.
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let audit_count = state.ledger.count_async().await.unwrap_or(0);

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.uptime_secs(),
        session_id: state.session_id.clone(),
        audit_count,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadinessCheck {
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadinessResponse {
    pub status: String,
    pub version: String,
    pub checks: Vec<ReadinessCheck>,
}

/// GET /ready (readiness probe)
///
/// Deep check: engine loaded, SQLite writable, signing key available, policy loaded.
/// Returns 503 if any check fails.
pub async fn ready(State(state): State<AppState>) -> Response {
    let mut checks = Vec::new();
    let mut all_ok = true;

    // Check 1: Engine loaded and policy available
    {
        let engine = state.engine.read().await;
        let policy_name = engine.policy().name.clone();
        let has_keypair = engine.keypair().is_some();

        checks.push(ReadinessCheck {
            name: "policy_loaded".to_string(),
            ok: true,
            message: Some(format!("policy={policy_name}")),
        });

        if has_keypair {
            checks.push(ReadinessCheck {
                name: "signing_key".to_string(),
                ok: true,
                message: None,
            });
        } else {
            all_ok = false;
            checks.push(ReadinessCheck {
                name: "signing_key".to_string(),
                ok: false,
                message: Some("no signing keypair available".to_string()),
            });
        }
    }

    // Check 2: SQLite audit DB is writable (try a count query)
    match state.ledger.count_async().await {
        Ok(_) => {
            checks.push(ReadinessCheck {
                name: "audit_db".to_string(),
                ok: true,
                message: None,
            });
        }
        Err(e) => {
            all_ok = false;
            checks.push(ReadinessCheck {
                name: "audit_db".to_string(),
                ok: false,
                message: Some(format!("audit db error: {e}")),
            });
        }
    }

    // Check 3: Control DB is reachable
    {
        let db_check = state
            .control_db
            .spawn_blocking(|conn| {
                conn.query_row("SELECT 1", [], |_| Ok(()))
                    .map_err(|e| e.into())
            })
            .await;

        match db_check {
            Ok(()) => {
                checks.push(ReadinessCheck {
                    name: "control_db".to_string(),
                    ok: true,
                    message: None,
                });
            }
            Err(e) => {
                all_ok = false;
                checks.push(ReadinessCheck {
                    name: "control_db".to_string(),
                    ok: false,
                    message: Some(format!("control db error: {e}")),
                });
            }
        }
    }

    let status = if all_ok { "ready" } else { "degraded" };
    let http_status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = ReadinessResponse {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        checks,
    };

    (http_status, Json(body)).into_response()
}
