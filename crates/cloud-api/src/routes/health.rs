use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/health/ready", get(readiness))
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    // Check database connectivity
    let db_ok = sqlx::query::query("SELECT 1")
        .execute(&state.db)
        .await
        .is_ok();

    // Check NATS connectivity
    let nats_ok = state.nats.connection_state() == async_nats::connection::State::Connected;

    let status = if db_ok && nats_ok { "ready" } else { "degraded" };
    let code = if db_ok && nats_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = serde_json::json!({
        "status": status,
        "checks": {
            "database": if db_ok { "ok" } else { "error" },
            "nats": if nats_ok { "ok" } else { "error" },
        }
    });

    (code, Json(body))
}
