use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::header;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use futures::stream;
use serde_json::Value;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
#[cfg(test)]
use crate::integration_tests::case_evidence::{
    AddCaseArtifactRequest, CreateFleetCaseRequest, ExportEvidenceBundleRequest,
    UpdateFleetCaseRequest,
};
#[cfg(test)]
use crate::integration_tests::case_evidence_service as case_evidence;
#[cfg(not(test))]
use crate::models::case_evidence::{
    AddCaseArtifactRequest, CreateFleetCaseRequest, ExportEvidenceBundleRequest,
    UpdateFleetCaseRequest,
};
#[cfg(not(test))]
use crate::services::case_evidence;
use crate::state::AppState;

pub(crate) const SINGLE_ARTIFACT_REQUEST_ERROR: &str =
    "artifact request body must be a single artifact object";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/cases", get(list_cases))
        .route("/cases", post(create_case))
        .route("/cases/{id}", get(get_case))
        .route("/cases/{id}", patch(update_case))
        .route("/cases/{id}/artifacts", post(add_artifact))
        .route("/cases/{id}/timeline", get(get_timeline))
        .route("/cases/{id}/evidence/export", post(export_evidence_bundle))
        .route("/evidence-bundles/{export_id}", get(get_bundle))
        .route(
            "/evidence-bundles/{export_id}/download",
            get(download_bundle),
        )
}

async fn list_cases(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<crate_case::FleetCase>>, ApiError> {
    let cases = case_evidence::list_cases(&state.db, auth.tenant_id).await?;
    Ok(Json(cases))
}

async fn create_case(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateFleetCaseRequest>,
) -> Result<Json<crate_case::FleetCase>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let actor_id = auth.actor_id();
    let case = case_evidence::create_case(&state.db, auth.tenant_id, &actor_id, req).await?;
    Ok(Json(case))
}

async fn get_case(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<crate_case::FleetCaseDetail>, ApiError> {
    let detail = case_evidence::get_case_detail(&state.db, auth.tenant_id, id).await?;
    Ok(Json(detail))
}

async fn update_case(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateFleetCaseRequest>,
) -> Result<Json<crate_case::FleetCase>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let actor_id = auth.actor_id();
    let case = case_evidence::update_case(&state.db, auth.tenant_id, id, &actor_id, req).await?;
    Ok(Json(case))
}

async fn add_artifact(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(payload): Json<Value>,
) -> Result<Json<crate_case::CaseArtifactRef>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let req = parse_add_artifact_request(payload)?;

    let actor_id = auth.actor_id();
    let artifact =
        case_evidence::add_artifact(&state.db, auth.tenant_id, id, &actor_id, req).await?;
    Ok(Json(artifact))
}

fn parse_add_artifact_request(payload: Value) -> Result<AddCaseArtifactRequest, ApiError> {
    let Value::Object(fields) = payload else {
        return Err(ApiError::BadRequest(
            SINGLE_ARTIFACT_REQUEST_ERROR.to_string(),
        ));
    };

    if fields.contains_key("artifacts") {
        return Err(ApiError::BadRequest(
            SINGLE_ARTIFACT_REQUEST_ERROR.to_string(),
        ));
    }

    serde_json::from_value(Value::Object(fields))
        .map_err(|err| ApiError::BadRequest(err.to_string()))
}

async fn get_timeline(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<crate_case::CaseTimelineEvent>>, ApiError> {
    let timeline = case_evidence::list_timeline(&state.db, auth.tenant_id, id).await?;
    Ok(Json(timeline))
}

async fn export_evidence_bundle(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<ExportEvidenceBundleRequest>,
) -> Result<Json<crate_case::FleetEvidenceBundle>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    let signer = state.signing_keypair.as_deref().ok_or_else(|| {
        ApiError::Internal("approval response signing keypair is not configured".to_string())
    })?;
    let actor_id = auth.actor_id();

    let bundle = case_evidence::create_evidence_bundle(
        &state.db,
        auth.tenant_id,
        id,
        &actor_id,
        req,
        signer,
    )
    .await?;
    Ok(Json(bundle))
}

async fn get_bundle(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(export_id): Path<String>,
) -> Result<Json<crate_case::FleetEvidenceBundle>, ApiError> {
    let bundle = case_evidence::get_bundle(&state.db, auth.tenant_id, &export_id).await?;
    Ok(Json(bundle))
}

async fn download_bundle(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(export_id): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    let path = case_evidence::bundle_download_path(&state.db, auth.tenant_id, &export_id).await?;
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    let stream = stream::try_unfold(file, |mut file| async move {
        let mut buffer = vec![0_u8; 64 * 1024];
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            Ok::<_, std::io::Error>(None)
        } else {
            buffer.truncate(read);
            Ok(Some((Bytes::from(buffer), file)))
        }
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    let disposition = HeaderValue::from_str(&format!("attachment; filename={export_id}.zip"))
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    Ok((headers, Body::from_stream(stream)).into_response())
}

#[cfg(test)]
use crate::integration_tests::case_evidence as crate_case;
#[cfg(not(test))]
use crate::models::case_evidence as crate_case;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_add_artifact_request_accepts_single_object_shape() {
        let request = parse_add_artifact_request(serde_json::json!({
            "artifactKind": "response_action",
            "artifactId": "ra-1",
            "summary": "endpoint quarantine",
            "metadata": {"targetKind": "endpoint"}
        }))
        .expect("single artifact payload should deserialize");

        assert_eq!(request.artifact_kind, "response_action");
        assert_eq!(request.artifact_id, "ra-1");
        assert_eq!(request.summary.as_deref(), Some("endpoint quarantine"));
    }

    #[test]
    fn parse_add_artifact_request_rejects_batch_array_shape() {
        let error = parse_add_artifact_request(serde_json::json!([
            {
                "artifactKind": "response_action",
                "artifactId": "ra-1",
                "metadata": {}
            }
        ]))
        .expect_err("array payload should be rejected");

        assert!(matches!(
            error,
            ApiError::BadRequest(message) if message == SINGLE_ARTIFACT_REQUEST_ERROR
        ));
    }

    #[test]
    fn parse_add_artifact_request_rejects_wrapped_batch_shape() {
        let error = parse_add_artifact_request(serde_json::json!({
            "artifacts": [
                {
                    "artifactKind": "response_action",
                    "artifactId": "ra-1",
                    "metadata": {}
                }
            ]
        }))
        .expect_err("wrapped batch payload should be rejected");

        assert!(matches!(
            error,
            ApiError::BadRequest(message) if message == SINGLE_ARTIFACT_REQUEST_ERROR
        ));
    }
}
