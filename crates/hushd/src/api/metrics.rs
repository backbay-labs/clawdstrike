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
    let dropped = state.audit_forwarder.as_ref().map(|f| f.dropped_total());
    let mut body = state
        .metrics
        .render_prometheus(state.uptime_secs(), dropped);

    // SIEM exporter metrics (best-effort; this endpoint should never fail due to exporter state).
    body.push_str("# HELP hushd_siem_enabled Whether SIEM export is enabled.\n");
    body.push_str("# TYPE hushd_siem_enabled gauge\n");
    body.push_str(&format!(
        "hushd_siem_enabled {}\n",
        if state.config.siem.enabled { 1 } else { 0 }
    ));

    body.push_str("# HELP hushd_siem_exported_total SIEM events exported.\n");
    body.push_str("# TYPE hushd_siem_exported_total counter\n");
    body.push_str("# HELP hushd_siem_failed_total SIEM export failures.\n");
    body.push_str("# TYPE hushd_siem_failed_total counter\n");
    body.push_str("# HELP hushd_siem_dlq_total SIEM events sent to dead-letter queue.\n");
    body.push_str("# TYPE hushd_siem_dlq_total counter\n");
    body.push_str("# HELP hushd_siem_dropped_total SIEM events dropped.\n");
    body.push_str("# TYPE hushd_siem_dropped_total counter\n");
    body.push_str("# HELP hushd_siem_queue_depth Current SIEM exporter queue depth.\n");
    body.push_str("# TYPE hushd_siem_queue_depth gauge\n");
    body.push_str("# HELP hushd_siem_exporter_running Whether SIEM exporter worker is running.\n");
    body.push_str("# TYPE hushd_siem_exporter_running gauge\n");

    let exporters = state.siem_exporters.read().await.clone();
    for handle in exporters {
        let health = handle.health.read().await.clone();
        let name = escape_label_value(&handle.name);
        body.push_str(&format!(
            "hushd_siem_exported_total{{exporter=\"{}\"}} {}\n",
            name, health.exported_total
        ));
        body.push_str(&format!(
            "hushd_siem_failed_total{{exporter=\"{}\"}} {}\n",
            name, health.failed_total
        ));
        body.push_str(&format!(
            "hushd_siem_dlq_total{{exporter=\"{}\"}} {}\n",
            name, health.dlq_total
        ));
        body.push_str(&format!(
            "hushd_siem_dropped_total{{exporter=\"{}\"}} {}\n",
            name, health.dropped_total
        ));
        body.push_str(&format!(
            "hushd_siem_queue_depth{{exporter=\"{}\"}} {}\n",
            name, health.queue_depth
        ));
        body.push_str(&format!(
            "hushd_siem_exporter_running{{exporter=\"{}\"}} {}\n",
            name,
            if health.running { 1 } else { 0 }
        ));
    }

    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
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

fn escape_label_value(value: &str) -> String {
    // Prometheus label escaping: backslash, double-quote, and newlines.
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

