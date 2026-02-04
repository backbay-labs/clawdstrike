//! Prometheus metrics endpoint and middleware.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::metrics::Metrics;
use crate::state::AppState;

/// GET /metrics
pub async fn metrics(State(state): State<AppState>) -> Response {
    let body = state.metrics.render_prometheus();
    ([(
        header::CONTENT_TYPE,
        "text/plain; version=0.0.4; charset=utf-8",
    )], body)
        .into_response()
}

/// Request-level metrics middleware (method/path/status + latency).
pub async fn metrics_middleware(
    State(metrics): State<Arc<Metrics>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();

    let start = std::time::Instant::now();
    let resp = next.run(req).await;
    metrics.observe_http_request(&method, &path, resp.status().as_u16(), start.elapsed());
    resp
}

