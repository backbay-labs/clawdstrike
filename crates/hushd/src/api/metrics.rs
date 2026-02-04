//! Prometheus-style metrics endpoint

use axum::{extract::State, response::IntoResponse};

use crate::state::AppState;

/// GET /metrics
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let mut out = String::new();

    let audit_count = state.ledger.count().unwrap_or(0) as u64;
    out.push_str("# TYPE hushd_uptime_seconds gauge\n");
    out.push_str(&format!("hushd_uptime_seconds {}\n", state.uptime_secs()));
    out.push_str("# TYPE hushd_audit_count gauge\n");
    out.push_str(&format!("hushd_audit_count {audit_count}\n"));
    out.push_str("# TYPE hushd_siem_enabled gauge\n");
    out.push_str(&format!(
        "hushd_siem_enabled {}\n",
        if state.config.siem.enabled { 1 } else { 0 }
    ));

    let exporters = state.siem_exporters.read().await.clone();
    for handle in exporters {
        let health = handle.health.read().await.clone();
        let name = sanitize_label_value(&handle.name);
        out.push_str("# TYPE hushd_siem_exported_total counter\n");
        out.push_str(&format!(
            "hushd_siem_exported_total{{exporter=\"{}\"}} {}\n",
            name, health.exported_total
        ));
        out.push_str("# TYPE hushd_siem_failed_total counter\n");
        out.push_str(&format!(
            "hushd_siem_failed_total{{exporter=\"{}\"}} {}\n",
            name, health.failed_total
        ));
        out.push_str("# TYPE hushd_siem_dlq_total counter\n");
        out.push_str(&format!(
            "hushd_siem_dlq_total{{exporter=\"{}\"}} {}\n",
            name, health.dlq_total
        ));
        out.push_str("# TYPE hushd_siem_dropped_total counter\n");
        out.push_str(&format!(
            "hushd_siem_dropped_total{{exporter=\"{}\"}} {}\n",
            name, health.dropped_total
        ));
        out.push_str("# TYPE hushd_siem_queue_depth gauge\n");
        out.push_str(&format!(
            "hushd_siem_queue_depth{{exporter=\"{}\"}} {}\n",
            name, health.queue_depth
        ));
        out.push_str("# TYPE hushd_siem_exporter_running gauge\n");
        out.push_str(&format!(
            "hushd_siem_exporter_running{{exporter=\"{}\"}} {}\n",
            name,
            if health.running { 1 } else { 0 }
        ));
    }

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        out,
    )
}

fn sanitize_label_value(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '"' | '\\' => '_',
            _ => c,
        })
        .collect()
}
