//! SIEM/SOAR exporter status endpoints

use axum::{extract::State, Json};
use serde::Serialize;

use crate::state::AppState;

#[derive(Clone, Debug, Serialize)]
pub struct SiemExportersResponse {
    pub enabled: bool,
    pub exporters: Vec<ExporterStatusResponse>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExporterStatusResponse {
    pub name: String,
    pub health: crate::siem::manager::ExporterHealth,
}

/// GET /api/v1/siem/exporters
pub async fn exporters(State(state): State<AppState>) -> Json<SiemExportersResponse> {
    let handles = state.siem_exporters.read().await.clone();

    let mut exporters = Vec::with_capacity(handles.len());
    for handle in handles {
        let health = handle.health.read().await.clone();
        exporters.push(ExporterStatusResponse {
            name: handle.name,
            health,
        });
    }

    Json(SiemExportersResponse {
        enabled: state.config.siem.enabled,
        exporters,
    })
}
