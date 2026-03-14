use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use clawdstrike_broker_protocol::{
    BrokerCapability, BrokerCapabilityState, BrokerCapabilityStatus, BrokerExecuteRequest,
    BrokerExecuteResponse, BrokerExecutionEvidence, BrokerExecutionOutcome, BrokerExecutionPhase,
    BrokerMintedIdentity, BrokerRequest, BROKER_CAPABILITY_ID_HEADER, BROKER_EXECUTION_ID_HEADER,
    BROKER_PROVIDER_HEADER,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::capability::validate_execute_request;
use crate::lease::resolve_execution_credential;
use crate::operator::{CapabilityRecord, ExecutionRecord, ExecutionTimelineEvent};
use crate::provider::{execute_provider, execute_provider_stream, ProviderStreamResponse};
use crate::state::AppState;

#[derive(Debug)]
pub struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) code: String,
    pub(crate) message: String,
}

impl ApiError {
    pub fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn bad_gateway(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn internal(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: code.into(),
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": {
                    "code": self.code,
                    "message": self.message,
                }
            })),
        )
            .into_response()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProvidersResponse {
    pub providers: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapabilitiesResponse {
    pub frozen: bool,
    pub revoked_capability_ids: Vec<String>,
    pub capabilities: Vec<CapabilityRecord>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionsResponse {
    pub frozen: bool,
    pub executions: Vec<ExecutionRecord>,
    pub timeline: Vec<ExecutionTimelineEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RevokeCapabilityResponse {
    pub capability_id: String,
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FreezeRequest {
    pub frozen: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FreezeResponse {
    pub frozen: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct CapabilityStatusEnvelope {
    capability: BrokerCapabilityStatus,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/providers", get(providers))
        .route("/v1/capabilities", get(capabilities))
        .route(
            "/v1/capabilities/{capability_id}/revoke",
            post(revoke_capability),
        )
        .route("/v1/executions", get(executions))
        .route("/v1/admin/freeze", post(set_freeze))
        .route("/v1/execute", post(execute))
        .route("/v1/execute/stream", post(execute_stream))
        .with_state(state)
}

/// Constant-time byte comparison to prevent timing side-channels on token
/// validation.  Returns `true` when both slices have equal length and
/// identical contents.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Verify the `Authorization: Bearer <token>` header against the configured
/// admin token.  When no admin token is configured the check is a no-op
/// (backward compatible).
fn require_admin_auth(headers: &HeaderMap, state: &AppState) -> Result<(), ApiError> {
    let expected = match state.config.admin_token.as_deref() {
        Some(token) => token,
        None => return Ok(()), // No token configured — auth disabled.
    };
    let header_value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let provided = header_value.strip_prefix("Bearer ").unwrap_or("");
    if provided.is_empty() || !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return Err(ApiError::unauthorized(
            "BROKER_AUTH_REQUIRED",
            "valid admin bearer token required",
        ));
    }
    Ok(())
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        timestamp: Utc::now().to_rfc3339(),
    })
}

pub async fn providers() -> Json<ProvidersResponse> {
    Json(ProvidersResponse {
        providers: vec!["openai", "github", "slack", "generic_https"],
    })
}

pub async fn capabilities(State(state): State<AppState>) -> Json<CapabilitiesResponse> {
    let snapshot = state.operator_state.snapshot().await;
    Json(CapabilitiesResponse {
        frozen: snapshot.frozen,
        revoked_capability_ids: snapshot.revoked_capability_ids,
        capabilities: snapshot.capabilities,
    })
}

pub async fn executions(State(state): State<AppState>) -> Json<ExecutionsResponse> {
    let snapshot = state.operator_state.snapshot().await;
    Json(ExecutionsResponse {
        frozen: snapshot.frozen,
        executions: snapshot.executions,
        timeline: snapshot.timeline,
    })
}

pub async fn revoke_capability(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(capability_id): Path<String>,
) -> Result<Json<RevokeCapabilityResponse>, ApiError> {
    require_admin_auth(&headers, &state)?;
    let revoked = state.operator_state.revoke_capability(&capability_id).await;
    Ok(Json(RevokeCapabilityResponse {
        capability_id,
        revoked,
    }))
}

pub async fn set_freeze(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FreezeRequest>,
) -> Result<Json<FreezeResponse>, ApiError> {
    require_admin_auth(&headers, &state)?;
    state.operator_state.set_frozen(request.frozen).await;
    Ok(Json(FreezeResponse {
        frozen: request.frozen,
    }))
}

fn build_execution_evidence(
    capability: &BrokerCapability,
    request: &BrokerRequest,
    context: ExecutionEvidenceContext,
) -> BrokerExecutionEvidence {
    BrokerExecutionEvidence {
        execution_id: context.execution_id,
        capability_id: capability.capability_id.clone(),
        provider: capability.secret_ref.provider,
        phase: context.phase,
        executed_at: Utc::now(),
        secret_ref_id: capability.secret_ref.id.clone(),
        url: request.url.clone(),
        method: request.method,
        request_body_sha256: request.body_sha256.clone(),
        response_body_sha256: context.response_body_sha256,
        status_code: context.status_code,
        bytes_sent: context.bytes_sent,
        bytes_received: context.bytes_received,
        stream_chunk_count: context.stream_chunk_count,
        provider_metadata: context.provider_metadata,
        outcome: context.outcome,
        minted_identity: context.minted_identity,
        preview_id: capability
            .intent_preview
            .as_ref()
            .map(|preview| preview.preview_id.clone()),
        lineage: capability.lineage.clone(),
        suspicion_reason: context.suspicion_reason,
    }
}

struct ExecutionEvidenceContext {
    execution_id: String,
    bytes_sent: usize,
    phase: BrokerExecutionPhase,
    status_code: Option<u16>,
    response_body_sha256: Option<String>,
    bytes_received: usize,
    stream_chunk_count: Option<u64>,
    provider_metadata: std::collections::BTreeMap<String, String>,
    outcome: Option<BrokerExecutionOutcome>,
    minted_identity: Option<BrokerMintedIdentity>,
    suspicion_reason: Option<String>,
}

async fn freeze_for_tripwire(
    state: &AppState,
    capability: &BrokerCapability,
    request: &BrokerRequest,
    execution_id: String,
    bytes_sent: usize,
    minted_identity: Option<BrokerMintedIdentity>,
    reason: String,
) -> Result<ApiError, ApiError> {
    state.operator_state.set_frozen(true).await;
    let error_message = format!("broker execution blocked by tripwire: {reason}");
    let evidence = build_execution_evidence(
        capability,
        request,
        ExecutionEvidenceContext {
            execution_id,
            bytes_sent,
            phase: BrokerExecutionPhase::Completed,
            status_code: None,
            response_body_sha256: None,
            bytes_received: 0,
            stream_chunk_count: Some(0),
            provider_metadata: Default::default(),
            outcome: Some(BrokerExecutionOutcome::Incomplete),
            minted_identity,
            suspicion_reason: Some(reason),
        },
    );
    record_and_submit_evidence(state, &evidence).await?;
    Ok(ApiError::forbidden(
        "BROKER_TRIPWIRE_TRIGGERED",
        error_message,
    ))
}

pub async fn execute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<BrokerExecuteRequest>,
) -> Result<Json<BrokerExecuteResponse>, ApiError> {
    require_admin_auth(&headers, &state)?;
    let (capability, _url) = validate_execute_request(&request, &state.config, false)?;
    ensure_operator_allows(&state, &capability).await?;
    ensure_hushd_allows(&state, &capability.capability_id).await?;
    let credential = resolve_execution_credential(&state, &capability.secret_ref.id).await?;
    let execution_id = Uuid::now_v7().to_string();
    let bytes_sent = request
        .request
        .body
        .as_ref()
        .map(|body| body.len())
        .unwrap_or(0);
    if let Some(reason) = credential.suspicion_reason.clone() {
        return Err(freeze_for_tripwire(
            &state,
            &capability,
            &request.request,
            execution_id,
            bytes_sent,
            credential.minted_identity.clone(),
            reason,
        )
        .await?);
    }

    let started_evidence = build_execution_evidence(
        &capability,
        &request.request,
        ExecutionEvidenceContext {
            execution_id: execution_id.clone(),
            bytes_sent,
            phase: BrokerExecutionPhase::Started,
            status_code: None,
            response_body_sha256: None,
            bytes_received: 0,
            stream_chunk_count: None,
            provider_metadata: Default::default(),
            outcome: None,
            minted_identity: credential.minted_identity.clone(),
            suspicion_reason: None,
        },
    );
    if let Err(evidence_error) = record_and_submit_evidence(&state, &started_evidence).await {
        tracing::error!(
            error = %evidence_error.message,
            "failed to submit broker execution start evidence"
        );
    }

    let response = match execute_provider(
        &state,
        &capability,
        &request.request,
        &credential.provider_secret,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            let failed_evidence = build_execution_evidence(
                &capability,
                &request.request,
                ExecutionEvidenceContext {
                    execution_id: execution_id.clone(),
                    bytes_sent,
                    phase: BrokerExecutionPhase::Completed,
                    status_code: None,
                    response_body_sha256: None,
                    bytes_received: 0,
                    stream_chunk_count: None,
                    provider_metadata: Default::default(),
                    outcome: Some(BrokerExecutionOutcome::Incomplete),
                    minted_identity: credential.minted_identity.clone(),
                    suspicion_reason: None,
                },
            );
            if let Err(evidence_error) = record_and_submit_evidence(&state, &failed_evidence).await
            {
                tracing::error!(
                    error = %evidence_error.message,
                    "failed to submit broker execution failure evidence"
                );
            }
            return Err(error);
        }
    };
    let evidence = build_execution_evidence(
        &capability,
        &request.request,
        ExecutionEvidenceContext {
            execution_id: execution_id.clone(),
            bytes_sent,
            phase: BrokerExecutionPhase::Completed,
            status_code: Some(response.status),
            response_body_sha256: response.response_body_sha256.clone(),
            bytes_received: response.bytes_received,
            stream_chunk_count: None,
            provider_metadata: response.provider_metadata.clone(),
            outcome: Some(if response.status >= 400 {
                BrokerExecutionOutcome::UpstreamError
            } else {
                BrokerExecutionOutcome::Success
            }),
            minted_identity: credential.minted_identity.clone(),
            suspicion_reason: None,
        },
    );
    if let Err(evidence_error) = record_and_submit_evidence(&state, &evidence).await {
        tracing::error!(
            error = %evidence_error.message,
            "failed to submit broker execution completion evidence; upstream call already succeeded"
        );
    }

    Ok(Json(BrokerExecuteResponse {
        execution_id,
        capability_id: capability.capability_id,
        provider: capability.secret_ref.provider,
        status: response.status,
        headers: response.headers,
        body: response.body,
        content_type: response.content_type,
    }))
}

pub async fn execute_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<BrokerExecuteRequest>,
) -> Result<Response, ApiError> {
    require_admin_auth(&headers, &state)?;
    let (capability, _url) = validate_execute_request(&request, &state.config, true)?;
    ensure_operator_allows(&state, &capability).await?;
    ensure_hushd_allows(&state, &capability.capability_id).await?;
    let credential = resolve_execution_credential(&state, &capability.secret_ref.id).await?;
    let execution_id = Uuid::now_v7().to_string();
    let bytes_sent = request
        .request
        .body
        .as_ref()
        .map(|body| body.len())
        .unwrap_or(0);
    if let Some(reason) = credential.suspicion_reason.clone() {
        return Err(freeze_for_tripwire(
            &state,
            &capability,
            &request.request,
            execution_id,
            bytes_sent,
            credential.minted_identity.clone(),
            reason,
        )
        .await?);
    }
    let response = match execute_provider_stream(
        &state,
        &capability,
        &request.request,
        &credential.provider_secret,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            let failed_evidence = build_execution_evidence(
                &capability,
                &request.request,
                ExecutionEvidenceContext {
                    execution_id,
                    bytes_sent,
                    phase: BrokerExecutionPhase::Completed,
                    status_code: None,
                    response_body_sha256: None,
                    bytes_received: 0,
                    stream_chunk_count: Some(0),
                    provider_metadata: Default::default(),
                    outcome: Some(BrokerExecutionOutcome::Incomplete),
                    minted_identity: credential.minted_identity.clone(),
                    suspicion_reason: None,
                },
            );
            if let Err(evidence_error) = record_and_submit_evidence(&state, &failed_evidence).await
            {
                tracing::error!(
                    error = %evidence_error.message,
                    "failed to submit broker stream failure evidence"
                );
            }
            return Err(error);
        }
    };

    let started_evidence = build_execution_evidence(
        &capability,
        &request.request,
        ExecutionEvidenceContext {
            execution_id: execution_id.clone(),
            bytes_sent,
            phase: BrokerExecutionPhase::Started,
            status_code: Some(response.status),
            response_body_sha256: None,
            bytes_received: 0,
            stream_chunk_count: Some(0),
            provider_metadata: response.provider_metadata.clone(),
            outcome: None,
            minted_identity: credential.minted_identity.clone(),
            suspicion_reason: None,
        },
    );
    if let Err(evidence_error) = record_and_submit_evidence(&state, &started_evidence).await {
        tracing::error!(
            error = %evidence_error.message,
            "failed to submit broker stream start evidence; upstream stream already initiated"
        );
    }

    let ProviderStreamResponse {
        status,
        headers,
        content_type,
        response: upstream_response,
        provider_metadata,
    } = response;
    let capability_id = capability.capability_id.clone();
    let provider = capability.secret_ref.provider;
    let secret_ref_id = capability.secret_ref.id;
    let request_url = request.request.url;
    let request_method = request.request.method;
    let request_body_sha256 = request.request.body_sha256;
    let preview_id = capability
        .intent_preview
        .as_ref()
        .map(|preview| preview.preview_id.clone());
    let lineage = capability.lineage.clone();
    let minted_identity = credential.minted_identity;
    let mut upstream_stream = upstream_response.bytes_stream();
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    let state_for_task = state.clone();
    let execution_id_for_task = execution_id.clone();

    tokio::spawn(async move {
        let mut hasher = Sha256::new();
        let mut bytes_received = 0usize;
        let mut stream_chunk_count = 0u64;
        let mut outcome = if status >= 400 {
            BrokerExecutionOutcome::UpstreamError
        } else {
            BrokerExecutionOutcome::Success
        };

        while let Some(item) = upstream_stream.next().await {
            match item {
                Ok(chunk) => {
                    stream_chunk_count = stream_chunk_count.saturating_add(1);
                    bytes_received = bytes_received.saturating_add(chunk.len());
                    hasher.update(&chunk);

                    if tx.send(Ok(chunk)).await.is_err() {
                        outcome = BrokerExecutionOutcome::Incomplete;
                        break;
                    }
                }
                Err(error) => {
                    outcome = BrokerExecutionOutcome::Incomplete;
                    let _ = tx.send(Err(std::io::Error::other(error.to_string()))).await;
                    break;
                }
            }
        }
        drop(tx);

        let completed_evidence = BrokerExecutionEvidence {
            execution_id: execution_id_for_task,
            capability_id,
            provider,
            phase: BrokerExecutionPhase::Completed,
            executed_at: Utc::now(),
            secret_ref_id,
            url: request_url,
            method: request_method,
            request_body_sha256,
            response_body_sha256: Some(format!("{:x}", hasher.finalize())),
            status_code: Some(status),
            bytes_sent,
            bytes_received,
            stream_chunk_count: Some(stream_chunk_count),
            provider_metadata,
            outcome: Some(outcome),
            minted_identity,
            preview_id,
            lineage,
            suspicion_reason: None,
        };

        if let Err(error) = record_and_submit_evidence(&state_for_task, &completed_evidence).await {
            tracing::error!(error = %error.message, "failed to submit broker stream completion evidence");
        }
    });

    let mut builder = Response::builder().status(status);
    if let Some(content_type) = &content_type {
        builder = builder.header(axum::http::header::CONTENT_TYPE, content_type);
    }
    builder = builder
        .header(BROKER_EXECUTION_ID_HEADER, execution_id.as_str())
        .header(
            BROKER_CAPABILITY_ID_HEADER,
            capability.capability_id.as_str(),
        )
        .header(
            BROKER_PROVIDER_HEADER,
            capability.secret_ref.provider.as_str(),
        );
    for (name, value) in &headers {
        builder = builder.header(name.as_str(), value.as_str());
    }

    builder
        .body(Body::from_stream(ReceiverStream::new(rx)))
        .map_err(|error| {
            ApiError::internal("BROKER_STREAM_RESPONSE_BUILD_FAILED", error.to_string())
        })
}

async fn ensure_operator_allows(
    state: &AppState,
    capability: &clawdstrike_broker_protocol::BrokerCapability,
) -> Result<(), ApiError> {
    state.operator_state.register_capability(capability).await;
    if state.operator_state.is_frozen().await {
        return Err(ApiError::forbidden(
            "BROKER_FROZEN",
            "broker execution is currently frozen by operator control",
        ));
    }
    if state
        .operator_state
        .is_capability_revoked(&capability.capability_id)
        .await
    {
        return Err(ApiError::forbidden(
            "BROKER_CAPABILITY_REVOKED",
            "broker capability has been revoked by operator control",
        ));
    }
    Ok(())
}

async fn ensure_hushd_allows(state: &AppState, capability_id: &str) -> Result<(), ApiError> {
    let mut request = state.hushd_client.get(format!(
        "{}/api/v1/broker/capabilities/{capability_id}/status",
        state.config.hushd_base_url.trim_end_matches('/'),
    ));
    if let Some(token) = &state.config.hushd_token {
        request = request.bearer_auth(token);
    }

    let response = request.send().await.map_err(|error| {
        ApiError::bad_gateway("BROKER_AUTHORITY_STATUS_UNAVAILABLE", error.to_string())
    })?;
    if !response.status().is_success() {
        return Err(ApiError::bad_gateway(
            "BROKER_AUTHORITY_STATUS_UNAVAILABLE",
            format!(
                "hushd capability status endpoint returned {}",
                response.status()
            ),
        ));
    }

    let payload = response
        .json::<CapabilityStatusEnvelope>()
        .await
        .map_err(|error| {
            ApiError::bad_gateway("BROKER_AUTHORITY_STATUS_INVALID", error.to_string())
        })?;
    match payload.capability.state {
        BrokerCapabilityState::Active => {}
        BrokerCapabilityState::Expired => {
            return Err(ApiError::forbidden(
                "BROKER_CAPABILITY_EXPIRED",
                "broker capability is no longer active",
            ))
        }
        BrokerCapabilityState::Revoked => {
            return Err(ApiError::forbidden(
                "BROKER_CAPABILITY_REVOKED",
                "broker capability has been revoked by hushd authority",
            ))
        }
        BrokerCapabilityState::Frozen => {
            return Err(ApiError::forbidden(
                "BROKER_PROVIDER_FROZEN",
                "broker provider is currently frozen by hushd authority",
            ))
        }
    }

    if let Some(max_executions) = payload.capability.max_executions {
        if payload.capability.execution_count >= u64::from(max_executions) {
            return Err(ApiError::forbidden(
                "BROKER_CAPABILITY_EXHAUSTED",
                format!("broker capability has reached its execution limit ({max_executions})"),
            ));
        }
    }

    Ok(())
}

async fn record_and_submit_evidence(
    state: &AppState,
    evidence: &BrokerExecutionEvidence,
) -> Result<(), ApiError> {
    state.operator_state.record_execution(evidence).await;
    submit_evidence(state, evidence).await
}

async fn submit_evidence(
    state: &AppState,
    evidence: &BrokerExecutionEvidence,
) -> Result<(), ApiError> {
    let url = format!(
        "{}/api/v1/broker/evidence",
        state.config.hushd_base_url.trim_end_matches('/')
    );
    let mut request = state.hushd_client.post(url).json(evidence);
    if let Some(token) = &state.config.hushd_token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.map_err(|error| {
        ApiError::bad_gateway("BROKER_EVIDENCE_SUBMISSION_FAILED", error.to_string())
    })?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::bad_gateway(
            "BROKER_EVIDENCE_SUBMISSION_FAILED",
            format!("hushd evidence endpoint returned {}: {}", status, body),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    // ── constant_time_eq ────────────────────────────────────────────

    #[test]
    fn constant_time_eq_equal_slices() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
    }

    #[test]
    fn constant_time_eq_different_slices() {
        assert!(!constant_time_eq(b"secret-token", b"wrong-token!"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer-string"));
    }

    #[test]
    fn constant_time_eq_empty_slices() {
        assert!(constant_time_eq(b"", b""));
    }

    // ── require_admin_auth ──────────────────────────────────────────

    fn make_test_state(admin_token: Option<String>) -> AppState {
        use crate::config::{Config, SecretBackendConfig};
        use crate::operator::OperatorState;
        use hush_core::Keypair;
        use std::sync::Arc;

        let keypair = Keypair::generate();
        let config = Config {
            listen: "127.0.0.1:9889".to_string(),
            hushd_base_url: "http://127.0.0.1:9876".to_string(),
            hushd_token: None,
            secret_backend: SecretBackendConfig::Env {
                prefix: "TEST_".to_string(),
            },
            trusted_hushd_public_keys: vec![keypair.public_key()],
            request_timeout_secs: 5,
            binding_proof_ttl_secs: 60,
            allow_http_loopback: false,
            allow_private_upstream_hosts: false,
            allow_invalid_upstream_tls: false,
            admin_token,
        };
        AppState {
            config: Arc::new(config),
            secret_provider: Arc::new(crate::secret_provider::EnvSecretProvider::new(
                "TEST_".to_string(),
            )),
            operator_state: OperatorState::default(),
            hushd_client: reqwest::Client::new(),
            upstream_client: reqwest::Client::new(),
        }
    }

    #[test]
    fn auth_skipped_when_no_token_configured() {
        let state = make_test_state(None);
        let headers = HeaderMap::new();
        assert!(require_admin_auth(&headers, &state).is_ok());
    }

    #[test]
    fn auth_passes_with_correct_bearer_token() {
        let state = make_test_state(Some("my-secret".to_string()));
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer my-secret".parse().unwrap(),
        );
        assert!(require_admin_auth(&headers, &state).is_ok());
    }

    #[test]
    fn auth_rejects_wrong_token() {
        let state = make_test_state(Some("my-secret".to_string()));
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer wrong-token".parse().unwrap(),
        );
        let err = require_admin_auth(&headers, &state).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.code, "BROKER_AUTH_REQUIRED");
    }

    #[test]
    fn auth_rejects_missing_header() {
        let state = make_test_state(Some("my-secret".to_string()));
        let headers = HeaderMap::new();
        let err = require_admin_auth(&headers, &state).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_rejects_non_bearer_scheme() {
        let state = make_test_state(Some("my-secret".to_string()));
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic my-secret".parse().unwrap(),
        );
        let err = require_admin_auth(&headers, &state).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_rejects_empty_bearer_value() {
        let state = make_test_state(Some("my-secret".to_string()));
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer ".parse().unwrap(),
        );
        let err = require_admin_auth(&headers, &state).unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
}
