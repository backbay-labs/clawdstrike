use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use clawdstrike::{
    guards::GuardContext,
    policy::{
        BrokerConfig as PolicyBrokerConfig, BrokerMethod as PolicyBrokerMethod,
        BrokerProviderPolicy,
    },
    HushEngine, RequestContext,
};
use clawdstrike_broker_protocol::{
    sign_capability, sign_completion_bundle, BrokerCapability, BrokerCapabilityIssueRequest,
    BrokerCapabilityIssueResponse, BrokerCapabilityState, BrokerCapabilityStatus,
    BrokerCompletionBundle, BrokerDestination, BrokerExecutionEvidence, BrokerExecutionOutcome,
    BrokerExecutionPhase, BrokerIntentPreview, BrokerIntentResource, BrokerIntentRiskLevel,
    BrokerProvider, BrokerProviderFreezeStatus, BrokerRequestConstraints, CredentialRef,
    HttpMethod, ProofBindingMode, UrlScheme,
};
use hush_multi_agent::{
    AgentId, InMemoryRevocationStore, SignedDelegationToken, DELEGATION_AUDIENCE,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::api::v1::V1Error;
use crate::audit::AuditEvent;
use crate::auth::AuthenticatedActor;
use crate::broker_state::BrokerPreviewRecord;
use crate::state::{AppState, DaemonEvent};

#[derive(Clone, Debug, Serialize)]
pub struct BrokerEvidenceAck {
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerPublicKeyResponse {
    pub public_key: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerCapabilitiesResponse {
    pub capabilities: Vec<BrokerCapabilityStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerCapabilityDetailResponse {
    pub capability: BrokerCapabilityStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executions: Vec<BrokerExecutionEvidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerPreviewResponse {
    pub preview: BrokerIntentPreview,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerPreviewListResponse {
    pub previews: Vec<BrokerIntentPreview>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerCompletionBundleResponse {
    pub envelope: String,
    pub bundle: BrokerCompletionBundle,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BrokerIntentPreviewRequest {
    pub provider: BrokerProvider,
    pub url: String,
    pub method: HttpMethod,
    pub secret_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_agent_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BrokerPreviewListQuery {
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BrokerPreviewApprovalRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BrokerCapabilityListQuery {
    #[serde(default)]
    pub state: Option<BrokerCapabilityState>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BrokerRevokeCapabilityRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerRevokeAllResponse {
    pub revoked_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerFrozenProvidersResponse {
    pub frozen_providers: Vec<BrokerProviderFreezeStatus>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BrokerFreezeProviderRequest {
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerReplayResponse {
    pub capability_id: String,
    pub current_policy_hash: String,
    pub current_state: BrokerCapabilityState,
    pub provider_frozen: bool,
    pub egress_allowed: bool,
    pub provider_allowed: bool,
    pub policy_changed: bool,
    pub approval_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview_still_approved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minted_identity_kind: Option<String>,
    pub would_allow: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diffs: Vec<BrokerReplayDiff>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrokerReplayDiff {
    pub field: String,
    pub previous: String,
    pub current: String,
}

type AgentIdentity = (Option<String>, Option<String>, Option<String>);

#[derive(Clone, Debug)]
struct BrokerRequestAttribution {
    session_id: Option<String>,
    endpoint_agent_id: Option<String>,
    runtime_agent_id: Option<String>,
    runtime_agent_kind: Option<String>,
}

impl From<&BrokerCapabilityIssueRequest> for BrokerRequestAttribution {
    fn from(request: &BrokerCapabilityIssueRequest) -> Self {
        Self {
            session_id: request.session_id.clone(),
            endpoint_agent_id: request.endpoint_agent_id.clone(),
            runtime_agent_id: request.runtime_agent_id.clone(),
            runtime_agent_kind: request.runtime_agent_kind.clone(),
        }
    }
}

impl From<&BrokerIntentPreviewRequest> for BrokerRequestAttribution {
    fn from(request: &BrokerIntentPreviewRequest) -> Self {
        Self {
            session_id: request.session_id.clone(),
            endpoint_agent_id: request.endpoint_agent_id.clone(),
            runtime_agent_id: request.runtime_agent_id.clone(),
            runtime_agent_kind: request.runtime_agent_kind.clone(),
        }
    }
}

fn normalize_identity_component(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn normalize_and_validate_agent_identity(
    endpoint_agent_id: Option<&str>,
    runtime_agent_id: Option<&str>,
    runtime_agent_kind: Option<&str>,
) -> Result<AgentIdentity, V1Error> {
    let endpoint_agent_id = normalize_identity_component(endpoint_agent_id);
    let runtime_agent_id = normalize_identity_component(runtime_agent_id);
    let runtime_agent_kind =
        normalize_identity_component(runtime_agent_kind).map(|value| value.to_ascii_lowercase());

    if runtime_agent_id.is_some() ^ runtime_agent_kind.is_some() {
        return Err(V1Error::bad_request(
            "INVALID_AGENT_IDENTITY",
            "runtime_agent_id and runtime_agent_kind must be provided together",
        ));
    }

    if runtime_agent_id.is_some() && endpoint_agent_id.is_none() {
        return Err(V1Error::bad_request(
            "INVALID_AGENT_IDENTITY",
            "endpoint_agent_id is required when runtime attribution is present",
        ));
    }

    Ok((endpoint_agent_id, runtime_agent_id, runtime_agent_kind))
}

fn provider_name(provider: &BrokerProvider) -> &'static str {
    provider.as_str()
}

fn parse_provider(value: &str) -> Result<BrokerProvider, V1Error> {
    match value.trim().to_ascii_lowercase().as_str() {
        "openai" => Ok(BrokerProvider::Openai),
        "github" => Ok(BrokerProvider::Github),
        "slack" => Ok(BrokerProvider::Slack),
        "generic_https" | "generic-https" => Ok(BrokerProvider::GenericHttps),
        other => Err(V1Error::bad_request(
            "BROKER_PROVIDER_INVALID",
            format!("unsupported broker provider '{other}'"),
        )),
    }
}

fn policy_method_matches(methods: &[PolicyBrokerMethod], requested: &HttpMethod) -> bool {
    methods.iter().any(|method| {
        matches!(
            (method, requested),
            (PolicyBrokerMethod::GET, HttpMethod::GET)
                | (PolicyBrokerMethod::POST, HttpMethod::POST)
                | (PolicyBrokerMethod::PUT, HttpMethod::PUT)
                | (PolicyBrokerMethod::PATCH, HttpMethod::PATCH)
                | (PolicyBrokerMethod::DELETE, HttpMethod::DELETE)
        )
    })
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn policy_match<'a>(
    broker: &'a PolicyBrokerConfig,
    provider: &BrokerProvider,
    host: &str,
    port: Option<u16>,
    path: &str,
    method: &HttpMethod,
    secret_ref: &str,
) -> Option<&'a BrokerProviderPolicy> {
    if !broker.enabled {
        return None;
    }

    broker.providers.iter().find(|candidate| {
        candidate.name.eq_ignore_ascii_case(provider_name(provider))
            && candidate.host.eq_ignore_ascii_case(host)
            && (candidate.port.is_none() || candidate.port == port)
            && candidate.secret_ref == secret_ref
            && candidate
                .exact_paths
                .iter()
                .any(|candidate_path| candidate_path == path)
            && policy_method_matches(&candidate.methods, method)
    })
}

async fn build_guard_context(
    state: &AppState,
    actor: Option<&axum::extract::Extension<AuthenticatedActor>>,
    headers: &axum::http::HeaderMap,
    addr: std::net::SocketAddr,
    attribution: &BrokerRequestAttribution,
) -> Result<(GuardContext, Option<String>, Option<String>), V1Error> {
    let request_context = RequestContext {
        request_id: uuid::Uuid::new_v4().to_string(),
        source_ip: Some(addr.ip().to_string()),
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string),
        geo_location: None,
        is_vpn: None,
        is_corporate_network: None,
        timestamp: Utc::now().to_rfc3339(),
    };

    let mut context = GuardContext::new().with_request(request_context.clone());
    let mut session_for_audit = attribution.session_id.clone();
    let mut agent_for_audit: Option<String> = None;

    if let Some(session_id) = attribution.session_id.as_deref() {
        let validation = state
            .sessions
            .validate_session(session_id)
            .map_err(|error| V1Error::internal("INTERNAL_ERROR", error.to_string()))?;

        if !validation.valid {
            return Err(V1Error::forbidden(
                "INVALID_SESSION",
                format!(
                    "invalid_session: {}",
                    validation
                        .reason
                        .as_ref()
                        .map(|reason| format!("{reason:?}"))
                        .unwrap_or_else(|| "unknown".to_string())
                ),
            ));
        }

        let session = validation.session.ok_or_else(|| {
            V1Error::internal(
                "SESSION_VALIDATION_ERROR",
                "session_validation_missing_session",
            )
        })?;

        if let Some(ext) = actor {
            match &ext.0 {
                AuthenticatedActor::User(principal) => {
                    if principal.id != session.identity.id
                        || principal.issuer != session.identity.issuer
                    {
                        return Err(V1Error::forbidden(
                            "SESSION_IDENTITY_MISMATCH",
                            "session_identity_mismatch",
                        ));
                    }
                }
                AuthenticatedActor::ApiKey(key) => {
                    let bound = session
                        .state
                        .as_ref()
                        .and_then(|state| state.get("bound_api_key_id"))
                        .and_then(|value| value.as_str());
                    let Some(bound_id) = bound else {
                        return Err(V1Error::forbidden(
                            "API_KEY_UNBOUND_SESSION",
                            "api_key_cannot_use_unbound_sessions",
                        ));
                    };
                    if bound_id != key.id.as_str() {
                        return Err(V1Error::forbidden(
                            "API_KEY_SESSION_BINDING_MISMATCH",
                            "api_key_session_binding_mismatch",
                        ));
                    }
                }
            }
        }

        state
            .sessions
            .validate_session_binding(&session, &request_context)
            .map_err(|error| V1Error::forbidden("FORBIDDEN", error.to_string()))?;

        context = state
            .sessions
            .create_guard_context(&session, Some(&request_context));
    }

    let (endpoint_agent_id, _, _) = normalize_and_validate_agent_identity(
        attribution.endpoint_agent_id.as_deref(),
        attribution.runtime_agent_id.as_deref(),
        attribution.runtime_agent_kind.as_deref(),
    )?;

    if let Some(agent_id) = endpoint_agent_id {
        agent_for_audit = Some(agent_id.clone());
        context = context.with_agent_id(agent_id);
    }

    Ok((context, session_for_audit.take(), agent_for_audit))
}

#[allow(clippy::too_many_arguments)]
fn record_broker_audit(
    state: &AppState,
    event_type: &str,
    decision: &str,
    message: &str,
    target: Option<String>,
    session_id: Option<String>,
    agent_id: Option<String>,
    metadata: serde_json::Value,
) {
    state.record_audit_event(AuditEvent {
        id: uuid::Uuid::now_v7().to_string(),
        timestamp: Utc::now(),
        event_type: event_type.to_string(),
        action_type: "broker".to_string(),
        target,
        decision: decision.to_string(),
        guard: None,
        severity: None,
        message: Some(message.to_string()),
        session_id,
        agent_id,
        metadata: Some(metadata),
    });
}

fn broadcast_broker_event(state: &AppState, event_type: &str, data: serde_json::Value) {
    state.broadcast(DaemonEvent {
        event_type: event_type.to_string(),
        data,
    });
}

fn actor_label(actor: Option<&axum::extract::Extension<AuthenticatedActor>>) -> Option<String> {
    actor.map(|actor| match &actor.0 {
        AuthenticatedActor::ApiKey(key) => format!("api_key:{}", key.name),
        AuthenticatedActor::User(principal) => format!("user:{}", principal.id),
    })
}

fn parse_request_body_json(body: Option<&str>, code: &str) -> Result<Option<Value>, V1Error> {
    let Some(body) = body else {
        return Ok(None);
    };
    if body.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(body).map(Some).map_err(|error| {
        V1Error::bad_request(code, format!("request body must be valid JSON: {error}"))
    })
}

fn body_cost_micros(body: Option<&str>) -> Option<u64> {
    body.map(|body| (body.len() as u64).saturating_mul(25))
}

fn preview_requires_approval(
    provider_policy: &BrokerProviderPolicy,
    preview: &BrokerIntentPreview,
) -> bool {
    let risk_match = provider_policy
        .approval_required_risk_levels
        .iter()
        .any(|value| {
            value.eq_ignore_ascii_case(match preview.risk_level {
                BrokerIntentRiskLevel::Low => "low",
                BrokerIntentRiskLevel::Medium => "medium",
                BrokerIntentRiskLevel::High => "high",
            })
        });
    let data_class_match = preview.data_classes.iter().any(|data_class| {
        provider_policy
            .approval_required_data_classes
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(data_class))
    });
    risk_match || data_class_match
}

fn build_intent_preview_record(
    request: &BrokerIntentPreviewRequest,
    provider_policy: &BrokerProviderPolicy,
    policy_hash: &str,
    host: &str,
    parsed: &Url,
) -> Result<BrokerPreviewRecord, V1Error> {
    let request_body =
        parse_request_body_json(request.body.as_deref(), "BROKER_PREVIEW_BODY_INVALID")?;
    let (operation, summary, risk_level, data_classes, resources) = match request.provider {
        BrokerProvider::Openai => {
            let model = request_body
                .as_ref()
                .and_then(|value| value.get("model"))
                .and_then(Value::as_str)
                .unwrap_or("unknown-model")
                .to_string();
            let tool_count = request_body
                .as_ref()
                .and_then(|value| value.get("tools"))
                .and_then(Value::as_array)
                .map(|tools| tools.len())
                .unwrap_or(0);
            let risk = if tool_count > 0 {
                BrokerIntentRiskLevel::High
            } else {
                BrokerIntentRiskLevel::Medium
            };
            let mut resources = vec![BrokerIntentResource {
                kind: "model".to_string(),
                value: model.clone(),
            }];
            if tool_count > 0 {
                resources.push(BrokerIntentResource {
                    kind: "tool_count".to_string(),
                    value: tool_count.to_string(),
                });
            }
            (
                "responses.create".to_string(),
                if tool_count > 0 {
                    format!("Run OpenAI responses.create against {model} with {tool_count} tools")
                } else {
                    format!("Run OpenAI responses.create against {model}")
                },
                risk,
                vec!["llm_prompt".to_string()],
                resources,
            )
        }
        BrokerProvider::Github => {
            let segments = parsed
                .path_segments()
                .map(|segments| segments.collect::<Vec<_>>())
                .unwrap_or_default();
            match (request.method.clone(), segments.as_slice()) {
                (HttpMethod::POST, ["repos", owner, repo, "issues"]) => (
                    "issues.create".to_string(),
                    format!("Create GitHub issue in {owner}/{repo}"),
                    BrokerIntentRiskLevel::Medium,
                    vec!["issue_content".to_string()],
                    vec![BrokerIntentResource {
                        kind: "repository".to_string(),
                        value: format!("{owner}/{repo}"),
                    }],
                ),
                (HttpMethod::POST, ["repos", owner, repo, "issues", issue_number, "comments"]) => (
                    "issues.comment.create".to_string(),
                    format!("Create GitHub issue comment on {owner}/{repo}#{issue_number}"),
                    BrokerIntentRiskLevel::Medium,
                    vec!["issue_comment".to_string()],
                    vec![
                        BrokerIntentResource {
                            kind: "repository".to_string(),
                            value: format!("{owner}/{repo}"),
                        },
                        BrokerIntentResource {
                            kind: "issue_number".to_string(),
                            value: (*issue_number).to_string(),
                        },
                    ],
                ),
                (HttpMethod::POST, ["repos", owner, repo, "check-runs"]) => (
                    "checks.create".to_string(),
                    format!("Create GitHub check run in {owner}/{repo}"),
                    BrokerIntentRiskLevel::Medium,
                    vec!["ci_status".to_string()],
                    vec![BrokerIntentResource {
                        kind: "repository".to_string(),
                        value: format!("{owner}/{repo}"),
                    }],
                ),
                _ => (
                    "github.request".to_string(),
                    format!(
                        "Execute GitHub {} {}",
                        request.method.as_str(),
                        parsed.path()
                    ),
                    BrokerIntentRiskLevel::High,
                    vec!["github_payload".to_string()],
                    vec![BrokerIntentResource {
                        kind: "path".to_string(),
                        value: parsed.path().to_string(),
                    }],
                ),
            }
        }
        BrokerProvider::Slack => match (request.method.clone(), parsed.path()) {
            (HttpMethod::POST, "/api/chat.postMessage") => {
                let channel = request_body
                    .as_ref()
                    .and_then(|value| value.get("channel"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown-channel")
                    .to_string();
                (
                    "chat.postMessage".to_string(),
                    format!("Post Slack message to {channel}"),
                    BrokerIntentRiskLevel::Medium,
                    vec!["chat_message".to_string()],
                    vec![BrokerIntentResource {
                        kind: "channel".to_string(),
                        value: channel,
                    }],
                )
            }
            (HttpMethod::POST, "/api/chat.update") => {
                let channel = request_body
                    .as_ref()
                    .and_then(|value| value.get("channel"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown-channel")
                    .to_string();
                (
                    "chat.update".to_string(),
                    format!("Update Slack message in {channel}"),
                    BrokerIntentRiskLevel::Medium,
                    vec!["chat_message".to_string()],
                    vec![BrokerIntentResource {
                        kind: "channel".to_string(),
                        value: channel,
                    }],
                )
            }
            _ => (
                "slack.request".to_string(),
                format!(
                    "Execute Slack {} {}",
                    request.method.as_str(),
                    parsed.path()
                ),
                BrokerIntentRiskLevel::High,
                vec!["slack_payload".to_string()],
                vec![BrokerIntentResource {
                    kind: "path".to_string(),
                    value: parsed.path().to_string(),
                }],
            ),
        },
        BrokerProvider::GenericHttps => (
            "generic_https".to_string(),
            format!(
                "Send {} request to {}",
                request.method.as_str(),
                parsed.path()
            ),
            BrokerIntentRiskLevel::High,
            vec!["opaque_http_payload".to_string()],
            vec![
                BrokerIntentResource {
                    kind: "host".to_string(),
                    value: host.to_string(),
                },
                BrokerIntentResource {
                    kind: "path".to_string(),
                    value: parsed.path().to_string(),
                },
            ],
        ),
    };

    let mut preview = BrokerIntentPreview {
        preview_id: uuid::Uuid::now_v7().to_string(),
        provider: request.provider.clone(),
        operation,
        summary,
        created_at: Utc::now(),
        risk_level,
        data_classes,
        resources,
        egress_host: host.to_string(),
        estimated_cost_usd_micros: body_cost_micros(request.body.as_deref()),
        approval_required: false,
        approval_state: clawdstrike_broker_protocol::BrokerApprovalState::NotRequired,
        approved_at: None,
        approver: None,
    };
    if preview_requires_approval(provider_policy, &preview) {
        preview.approval_required = true;
        preview.approval_state = clawdstrike_broker_protocol::BrokerApprovalState::Pending;
    }

    Ok(BrokerPreviewRecord {
        preview,
        url: request.url.clone(),
        method: request.method.clone(),
        secret_ref_id: provider_policy.secret_ref.clone(),
        policy_hash: policy_hash.to_string(),
    })
}

fn validate_preview_matches_request(
    record: &BrokerPreviewRecord,
    request: &BrokerCapabilityIssueRequest,
    policy_hash: &str,
) -> Result<(), V1Error> {
    if record.preview.provider != request.provider
        || record.url != request.url
        || record.method != request.method
        || record.secret_ref_id != request.secret_ref
        || record.policy_hash != policy_hash
    {
        return Err(V1Error::forbidden(
            "BROKER_PREVIEW_MISMATCH",
            "preview does not match the requested provider, destination, secret, or resolved policy",
        ));
    }

    Ok(())
}

fn resolve_delegation_lineage(
    request: &BrokerCapabilityIssueRequest,
) -> Result<Option<clawdstrike_broker_protocol::BrokerDelegationLineage>, V1Error> {
    let Some(token) = request.delegation_token.as_deref() else {
        return Ok(None);
    };
    let signed: SignedDelegationToken = serde_json::from_str(token).map_err(|error| {
        V1Error::bad_request(
            "BROKER_DELEGATION_TOKEN_INVALID",
            format!("delegation token is not valid JSON: {error}"),
        )
    })?;
    let issuer_public_key = signed.public_key.clone().ok_or_else(|| {
        V1Error::bad_request(
            "BROKER_DELEGATION_TOKEN_INVALID",
            "delegation token must embed the issuer public key",
        )
    })?;
    let expected_subject = request
        .runtime_agent_id
        .as_deref()
        .or(request.endpoint_agent_id.as_deref())
        .ok_or_else(|| {
            V1Error::bad_request(
                "BROKER_DELEGATION_TOKEN_INVALID",
                "delegated capability issuance requires runtime_agent_id or endpoint_agent_id attribution",
            )
        })?;
    let expected_subject = AgentId::new(expected_subject).map_err(|error| {
        V1Error::bad_request("BROKER_DELEGATION_TOKEN_INVALID", error.to_string())
    })?;
    let revocations = InMemoryRevocationStore::default();
    signed
        .verify_and_validate(
            &issuer_public_key,
            Utc::now().timestamp(),
            &revocations,
            DELEGATION_AUDIENCE,
            Some(&expected_subject),
        )
        .map_err(|error| {
            V1Error::forbidden("BROKER_DELEGATION_TOKEN_INVALID", error.to_string())
        })?;

    Ok(Some(clawdstrike_broker_protocol::BrokerDelegationLineage {
        token_jti: signed.claims.jti.clone(),
        parent_token_jti: signed.claims.chn.last().cloned(),
        chain: signed.claims.chn.clone(),
        depth: signed.claims.chn.len(),
        issuer: signed.claims.iss.to_string(),
        subject: signed.claims.sub.to_string(),
        purpose: signed.claims.pur.clone(),
    }))
}

pub async fn create_preview(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(request): Json<BrokerIntentPreviewRequest>,
) -> Result<Json<BrokerPreviewResponse>, V1Error> {
    if !state.config.broker.enabled {
        return Err(V1Error::forbidden(
            "BROKER_AUTHORITY_UNAVAILABLE",
            "broker authority is not enabled on hushd",
        ));
    }

    let parsed = Url::parse(&request.url)
        .map_err(|error| V1Error::bad_request("INVALID_BROKER_URL", error.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| V1Error::bad_request("INVALID_BROKER_URL", "broker url is missing host"))?;
    let port = parsed.port_or_known_default();
    match parsed.scheme() {
        "https" => {}
        "http" if state.config.broker.allow_http_loopback && is_loopback_host(host) => {}
        "http" => return Err(V1Error::forbidden(
            "INSECURE_BROKER_URL",
            "http broker preview requests are only allowed for loopback targets in dev/test mode",
        )),
        other => {
            return Err(V1Error::bad_request(
                "INVALID_BROKER_SCHEME",
                format!("unsupported broker url scheme: {other}"),
            ))
        }
    }

    let (default_policy, keypair) = {
        let engine = state.engine.read().await;
        (engine.policy().clone(), engine.keypair().cloned())
    };
    let attribution = BrokerRequestAttribution::from(&request);
    let (context, session_for_audit, agent_for_audit) =
        build_guard_context(&state, actor.as_ref(), &headers, addr, &attribution).await?;
    let resolved = state
        .policy_resolver
        .resolve_policy(&default_policy, &context)
        .map_err(|error| V1Error::internal("INTERNAL_ERROR", error.to_string()))?;
    let resolved_yaml = resolved
        .policy
        .to_yaml()
        .map_err(|error| V1Error::internal("INTERNAL_ERROR", error.to_string()))?;
    let policy_hash = hush_core::sha256(resolved_yaml.as_bytes()).to_hex();
    let engine: Arc<HushEngine> = match keypair {
        Some(keypair) => state
            .policy_engine_cache
            .get_or_insert_with(&policy_hash, || {
                Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_keypair(keypair))
            }),
        None => Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_generated_keypair()),
    };
    let egress = engine
        .check_egress(host, port.unwrap_or(443), &context)
        .await
        .map_err(|error| V1Error::internal("BROKER_POLICY_ERROR", error.to_string()))?;
    if !egress.allowed {
        return Err(V1Error::forbidden("BROKER_EGRESS_DENIED", egress.message));
    }

    let broker = resolved.policy.broker.as_ref().ok_or_else(|| {
        V1Error::forbidden(
            "BROKER_POLICY_MISSING",
            "resolved policy does not define a broker configuration",
        )
    })?;
    let provider_policy = policy_match(
        broker,
        &request.provider,
        host,
        port,
        parsed.path(),
        &request.method,
        &request.secret_ref,
    )
    .ok_or_else(|| {
        V1Error::forbidden(
            "BROKER_PROVIDER_DENIED",
            "requested provider, host, path, method, or secret_ref is not authorized by policy",
        )
    })?;

    let preview = state
        .broker_state
        .store_preview(build_intent_preview_record(
            &request,
            provider_policy,
            &policy_hash,
            host,
            &parsed,
        )?)
        .await;

    record_broker_audit(
        &state,
        "broker_preview_created",
        "allowed",
        "broker intent preview created",
        Some(request.url.clone()),
        session_for_audit,
        agent_for_audit,
        serde_json::json!({
            "preview_id": preview.preview_id,
            "provider": provider_name(&preview.provider),
            "operation": preview.operation,
            "approval_required": preview.approval_required,
            "policy_hash": policy_hash,
        }),
    );
    broadcast_broker_event(
        &state,
        "broker_preview_created",
        serde_json::json!({
            "timestamp": preview.created_at.to_rfc3339(),
            "preview_id": preview.preview_id.clone(),
            "provider": provider_name(&preview.provider),
            "operation": preview.operation.clone(),
            "approval_required": preview.approval_required,
            "approval_state": preview.approval_state,
            "summary": preview.summary.clone(),
            "egress_host": preview.egress_host.clone(),
        }),
    );

    Ok(Json(BrokerPreviewResponse { preview }))
}

pub async fn list_previews(
    State(state): State<AppState>,
    Query(query): Query<BrokerPreviewListQuery>,
) -> Result<Json<BrokerPreviewListResponse>, V1Error> {
    let previews = state
        .broker_state
        .list_previews()
        .await
        .into_iter()
        .filter(|preview| {
            query.provider.as_deref().is_none_or(|provider| {
                provider_name(&preview.provider).eq_ignore_ascii_case(provider)
            })
        })
        .take(query.limit.unwrap_or(200))
        .collect();
    Ok(Json(BrokerPreviewListResponse { previews }))
}

pub async fn get_preview(
    State(state): State<AppState>,
    Path(preview_id): Path<String>,
) -> Result<Json<BrokerPreviewResponse>, V1Error> {
    let preview = state
        .broker_state
        .get_preview(&preview_id)
        .await
        .ok_or_else(|| {
            V1Error::not_found(
                "BROKER_PREVIEW_NOT_FOUND",
                "broker intent preview was not found",
            )
        })?;
    Ok(Json(BrokerPreviewResponse { preview }))
}

pub async fn approve_preview(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Path(preview_id): Path<String>,
    Json(request): Json<BrokerPreviewApprovalRequest>,
) -> Result<Json<BrokerPreviewResponse>, V1Error> {
    let approver = request.approver.or_else(|| actor_label(actor.as_ref()));
    let preview = state
        .broker_state
        .approve_preview(&preview_id, approver.clone())
        .await
        .ok_or_else(|| {
            V1Error::not_found(
                "BROKER_PREVIEW_NOT_FOUND",
                "broker intent preview was not found",
            )
        })?;

    record_broker_audit(
        &state,
        "broker_preview_approved",
        "allowed",
        "broker intent preview approved",
        None,
        None,
        None,
        serde_json::json!({
            "preview_id": preview.preview_id,
            "provider": provider_name(&preview.provider),
            "approver": approver,
        }),
    );
    broadcast_broker_event(
        &state,
        "broker_preview_approved",
        serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "preview_id": preview.preview_id.clone(),
            "provider": provider_name(&preview.provider),
            "approver": preview.approver.clone(),
            "approval_state": preview.approval_state,
        }),
    );

    Ok(Json(BrokerPreviewResponse { preview }))
}

pub async fn export_completion_bundle(
    State(state): State<AppState>,
    Path(capability_id): Path<String>,
) -> Result<Json<BrokerCompletionBundleResponse>, V1Error> {
    let (capability, executions) = state
        .broker_state
        .get_capability_detail(&capability_id)
        .await
        .ok_or_else(|| {
            V1Error::not_found(
                "BROKER_CAPABILITY_NOT_FOUND",
                "broker capability status was not found",
            )
        })?;
    let keypair = state
        .engine
        .read()
        .await
        .keypair()
        .cloned()
        .ok_or_else(|| {
            V1Error::internal(
                "BROKER_SIGNING_KEY_UNAVAILABLE",
                "resolved hushd engine is missing a signing keypair",
            )
        })?;
    let bundle = BrokerCompletionBundle {
        generated_at: Utc::now(),
        capability,
        executions,
    };
    let envelope = sign_completion_bundle(&bundle, &keypair).map_err(|error| {
        V1Error::internal("BROKER_COMPLETION_BUNDLE_SIGN_FAILED", error.to_string())
    })?;

    broadcast_broker_event(
        &state,
        "broker_completion_bundle_exported",
        serde_json::json!({
            "timestamp": bundle.generated_at.to_rfc3339(),
            "capability_id": bundle.capability.capability_id.clone(),
            "provider": provider_name(&bundle.capability.provider),
            "execution_count": bundle.executions.len(),
        }),
    );

    Ok(Json(BrokerCompletionBundleResponse { envelope, bundle }))
}

pub async fn issue_capability(
    State(state): State<AppState>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(request): Json<BrokerCapabilityIssueRequest>,
) -> Result<Json<BrokerCapabilityIssueResponse>, V1Error> {
    if !state.config.broker.enabled {
        return Err(V1Error::forbidden(
            "BROKER_AUTHORITY_UNAVAILABLE",
            "broker authority is not enabled on hushd",
        ));
    }

    let parsed = Url::parse(&request.url)
        .map_err(|error| V1Error::bad_request("INVALID_BROKER_URL", error.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| V1Error::bad_request("INVALID_BROKER_URL", "broker url is missing host"))?;
    let path = parsed.path();
    let port = parsed.port_or_known_default();

    let scheme = match parsed.scheme() {
        "https" => UrlScheme::Https,
        "http" => {
            if !state.config.broker.allow_http_loopback || !is_loopback_host(host) {
                return Err(V1Error::forbidden(
                    "INSECURE_BROKER_URL",
                    "http broker capability requests are only allowed for loopback targets in dev/test mode",
                ));
            }
            UrlScheme::Http
        }
        other => {
            return Err(V1Error::bad_request(
                "INVALID_BROKER_SCHEME",
                format!("unsupported broker url scheme: {other}"),
            ))
        }
    };

    let (default_policy, keypair) = {
        let engine = state.engine.read().await;
        (engine.policy().clone(), engine.keypair().cloned())
    };

    let attribution = BrokerRequestAttribution::from(&request);
    let (context, session_for_audit, agent_for_audit) =
        build_guard_context(&state, actor.as_ref(), &headers, addr, &attribution).await?;

    let resolved = state
        .policy_resolver
        .resolve_policy(&default_policy, &context)
        .map_err(|error| V1Error::internal("INTERNAL_ERROR", error.to_string()))?;

    let resolved_yaml = resolved
        .policy
        .to_yaml()
        .map_err(|error| V1Error::internal("INTERNAL_ERROR", error.to_string()))?;
    let policy_hash = hush_core::sha256(resolved_yaml.as_bytes()).to_hex();
    let engine: Arc<HushEngine> = match keypair {
        Some(keypair) => state
            .policy_engine_cache
            .get_or_insert_with(&policy_hash, || {
                Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_keypair(keypair))
            }),
        None => Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_generated_keypair()),
    };

    let egress = engine
        .check_egress(host, port.unwrap_or(443), &context)
        .await
        .map_err(|error| V1Error::internal("BROKER_POLICY_ERROR", error.to_string()))?;
    if !egress.allowed {
        record_broker_audit(
            &state,
            "broker_capability_denied",
            "blocked",
            &egress.message,
            Some(request.url.clone()),
            session_for_audit.clone(),
            agent_for_audit.clone(),
            serde_json::json!({
                "provider": provider_name(&request.provider),
                "secret_ref": request.secret_ref,
                "guard": egress.guard,
            }),
        );
        return Err(V1Error::forbidden("BROKER_EGRESS_DENIED", egress.message));
    }

    let broker = resolved.policy.broker.as_ref().ok_or_else(|| {
        V1Error::forbidden(
            "BROKER_POLICY_MISSING",
            "resolved policy does not define a broker configuration",
        )
    })?;
    let provider_policy = policy_match(
        broker,
        &request.provider,
        host,
        port,
        path,
        &request.method,
        &request.secret_ref,
    )
    .ok_or_else(|| {
        V1Error::forbidden(
            "BROKER_PROVIDER_DENIED",
            "requested provider, host, path, method, or secret_ref is not authorized by policy",
        )
    })?;

    if state
        .broker_state
        .is_provider_frozen(&request.provider)
        .await
    {
        return Err(V1Error::forbidden(
            "BROKER_PROVIDER_FROZEN",
            "requested broker provider is currently frozen by operator control",
        ));
    }

    if provider_policy.require_body_sha256 == Some(true) && request.body_sha256.is_none() {
        return Err(V1Error::bad_request(
            "BROKER_BODY_HASH_REQUIRED",
            "body_sha256 is required for this broker policy",
        ));
    }

    if let Some(proof_binding) = &request.proof_binding {
        match proof_binding.mode {
            ProofBindingMode::Loopback if proof_binding.binding_sha256.is_none() => {
                return Err(V1Error::bad_request(
                    "BROKER_PROOF_BINDING_INVALID",
                    "loopback proof binding requires binding_sha256",
                ));
            }
            ProofBindingMode::Dpop if proof_binding.key_thumbprint.is_none() => {
                return Err(V1Error::bad_request(
                    "BROKER_PROOF_BINDING_INVALID",
                    "dpop proof binding requires key_thumbprint",
                ));
            }
            _ => {}
        }
    }

    let intent_preview = match request.preview_id.as_deref() {
        Some(preview_id) => {
            let record = state
                .broker_state
                .get_preview_record(preview_id)
                .await
                .ok_or_else(|| {
                    V1Error::not_found(
                        "BROKER_PREVIEW_NOT_FOUND",
                        "broker intent preview was not found",
                    )
                })?;
            validate_preview_matches_request(&record, &request, &policy_hash)?;
            if record.preview.approval_required
                && !matches!(
                    record.preview.approval_state,
                    clawdstrike_broker_protocol::BrokerApprovalState::Approved
                )
            {
                return Err(V1Error::forbidden(
                    "BROKER_PREVIEW_APPROVAL_REQUIRED",
                    "broker intent preview exists but has not been approved",
                ));
            }
            Some(record.preview)
        }
        None if provider_policy.require_intent_preview == Some(true) => {
            return Err(V1Error::forbidden(
                "BROKER_PREVIEW_REQUIRED",
                "policy requires an intent preview before issuing this capability",
            ));
        }
        None => None,
    };
    let lineage = resolve_delegation_lineage(&request)?;

    let keypair = engine.keypair().cloned().ok_or_else(|| {
        V1Error::internal(
            "BROKER_SIGNING_KEY_UNAVAILABLE",
            "resolved hushd engine is missing a signing keypair",
        )
    })?;
    let issued_at = Utc::now();
    let capability = BrokerCapability {
        capability_id: uuid::Uuid::now_v7().to_string(),
        issued_at,
        expires_at: issued_at
            + chrono::Duration::seconds(state.config.broker.capability_ttl_secs as i64),
        policy_hash: policy_hash.clone(),
        session_id: request.session_id.clone(),
        endpoint_agent_id: request.endpoint_agent_id.clone(),
        runtime_agent_id: request.runtime_agent_id.clone(),
        runtime_agent_kind: request.runtime_agent_kind.clone(),
        origin_fingerprint: request.origin_fingerprint.clone(),
        secret_ref: CredentialRef {
            id: provider_policy.secret_ref.clone(),
            provider: request.provider.clone(),
            tenant_id: None,
            environment: None,
            labels: std::collections::BTreeMap::new(),
        },
        proof_binding: request.proof_binding.clone(),
        destination: BrokerDestination {
            scheme,
            host: host.to_string(),
            port,
            method: request.method.clone(),
            exact_paths: vec![path.to_string()],
        },
        request_constraints: BrokerRequestConstraints {
            allowed_headers: provider_policy.allowed_headers.clone(),
            max_body_bytes: provider_policy.max_body_bytes,
            require_request_body_sha256: provider_policy.require_body_sha256,
            allow_redirects: Some(false),
            stream_response: provider_policy.stream_response,
        },
        evidence_required: true,
        intent_preview: intent_preview.clone(),
        lineage: lineage.clone(),
    };

    let envelope = sign_capability(&capability, &keypair).map_err(|error| {
        V1Error::internal("BROKER_CAPABILITY_SIGNING_FAILED", error.to_string())
    })?;
    state
        .broker_state
        .register_capability(&capability, request.url.clone())
        .await;

    record_broker_audit(
        &state,
        "broker_capability_issued",
        "allowed",
        "broker capability issued",
        Some(request.url.clone()),
        session_for_audit,
        agent_for_audit,
        serde_json::json!({
            "capability_id": capability.capability_id,
            "provider": provider_name(&request.provider),
            "policy_hash": policy_hash,
            "secret_ref": capability.secret_ref.id,
            "host": capability.destination.host,
            "path": path,
            "method": format!("{:?}", capability.destination.method),
            "preview_id": capability.intent_preview.as_ref().map(|preview| preview.preview_id.clone()),
            "delegated_subject": capability.lineage.as_ref().map(|lineage| lineage.subject.clone()),
        }),
    );
    broadcast_broker_event(
        &state,
        "broker_capability_issued",
        serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "capability_id": capability.capability_id.clone(),
            "provider": provider_name(&request.provider),
            "policy_hash": policy_hash,
            "secret_ref_id": capability.secret_ref.id.clone(),
            "url": request.url.clone(),
            "session_id": capability.session_id.clone(),
            "endpoint_agent_id": capability.endpoint_agent_id.clone(),
            "runtime_agent_id": capability.runtime_agent_id.clone(),
            "runtime_agent_kind": capability.runtime_agent_kind.clone(),
            "origin_fingerprint": capability.origin_fingerprint.clone(),
            "preview_id": capability.intent_preview.as_ref().map(|preview| preview.preview_id.clone()),
            "delegated_subject": capability.lineage.as_ref().map(|lineage| lineage.subject.clone()),
            "state": "active",
        }),
    );

    Ok(Json(BrokerCapabilityIssueResponse {
        capability: envelope,
        capability_id: capability.capability_id,
        expires_at: capability.expires_at,
        policy_hash,
    }))
}

pub async fn ingest_evidence(
    State(state): State<AppState>,
    Json(evidence): Json<BrokerExecutionEvidence>,
) -> Result<Json<BrokerEvidenceAck>, V1Error> {
    if !state.config.broker.enabled {
        return Err(V1Error::forbidden(
            "BROKER_AUTHORITY_UNAVAILABLE",
            "broker authority is not enabled on hushd",
        ));
    }

    let message = match (&evidence.phase, &evidence.outcome) {
        (BrokerExecutionPhase::Started, _) => "broker execution start evidence recorded",
        (_, _) if evidence.suspicion_reason.is_some() => {
            "broker execution suspicion evidence recorded"
        }
        (_, Some(BrokerExecutionOutcome::Success)) => "broker execution evidence recorded",
        (_, Some(BrokerExecutionOutcome::UpstreamError)) => {
            "broker execution error evidence recorded"
        }
        (_, Some(BrokerExecutionOutcome::Incomplete)) => {
            "broker execution incomplete evidence recorded"
        }
        (_, None) => "broker execution evidence recorded",
    };

    record_broker_audit(
        &state,
        "broker_evidence_recorded",
        "allowed",
        message,
        Some(evidence.url.clone()),
        None,
        None,
        serde_json::to_value(&evidence).map_err(|error| {
            V1Error::internal("BROKER_EVIDENCE_SERIALIZE_FAILED", error.to_string())
        })?,
    );
    state.broker_state.record_evidence(&evidence).await;
    broadcast_broker_event(
        &state,
        "broker_evidence_recorded",
        serde_json::json!({
            "timestamp": evidence.executed_at.to_rfc3339(),
            "execution_id": evidence.execution_id,
            "capability_id": evidence.capability_id,
            "provider": provider_name(&evidence.provider),
            "phase": evidence.phase,
            "outcome": evidence.outcome,
            "url": evidence.url,
            "status_code": evidence.status_code,
            "bytes_received": evidence.bytes_received,
            "stream_chunk_count": evidence.stream_chunk_count,
            "preview_id": evidence.preview_id,
            "minted_identity": evidence.minted_identity,
            "lineage": evidence.lineage,
            "suspicion_reason": evidence.suspicion_reason,
            "session_id": serde_json::Value::Null,
            "endpoint_agent_id": serde_json::Value::Null,
        }),
    );

    Ok(Json(BrokerEvidenceAck { accepted: true }))
}

pub async fn list_capabilities(
    State(state): State<AppState>,
    Query(query): Query<BrokerCapabilityListQuery>,
) -> Result<Json<BrokerCapabilitiesResponse>, V1Error> {
    let capabilities = state.broker_state.list_capabilities().await;
    let filtered = capabilities
        .into_iter()
        .filter(|capability| {
            query
                .state
                .as_ref()
                .is_none_or(|state| &capability.state == state)
        })
        .filter(|capability| {
            query.provider.as_deref().is_none_or(|provider| {
                provider_name(&capability.provider).eq_ignore_ascii_case(provider)
            })
        })
        .take(query.limit.unwrap_or(200))
        .collect();

    Ok(Json(BrokerCapabilitiesResponse {
        capabilities: filtered,
    }))
}

pub async fn capability_status(
    State(state): State<AppState>,
    Path(capability_id): Path<String>,
) -> Result<Json<BrokerCapabilityDetailResponse>, V1Error> {
    let (capability, mut executions) = state
        .broker_state
        .get_capability_detail(&capability_id)
        .await
        .ok_or_else(|| {
            V1Error::not_found(
                "BROKER_CAPABILITY_NOT_FOUND",
                "broker capability status was not found",
            )
        })?;
    executions.sort_by(|left, right| right.executed_at.cmp(&left.executed_at));

    Ok(Json(BrokerCapabilityDetailResponse {
        capability,
        executions,
    }))
}

pub async fn revoke_capability(
    State(state): State<AppState>,
    Path(capability_id): Path<String>,
    Json(request): Json<BrokerRevokeCapabilityRequest>,
) -> Result<Json<BrokerCapabilityDetailResponse>, V1Error> {
    let capability = state
        .broker_state
        .revoke_capability(&capability_id, request.reason.clone())
        .await
        .ok_or_else(|| {
            V1Error::not_found(
                "BROKER_CAPABILITY_NOT_FOUND",
                "broker capability status was not found",
            )
        })?;

    record_broker_audit(
        &state,
        "broker_capability_revoked",
        "allowed",
        "broker capability revoked",
        Some(capability.url.clone()),
        capability.session_id.clone(),
        capability.endpoint_agent_id.clone(),
        serde_json::json!({
            "capability_id": capability.capability_id,
            "provider": provider_name(&capability.provider),
            "reason": capability.state_reason,
        }),
    );
    broadcast_broker_event(
        &state,
        "broker_capability_revoked",
        serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "capability_id": capability.capability_id.clone(),
            "provider": provider_name(&capability.provider),
            "url": capability.url.clone(),
            "reason": capability.state_reason.clone(),
            "session_id": capability.session_id.clone(),
            "endpoint_agent_id": capability.endpoint_agent_id.clone(),
            "runtime_agent_id": capability.runtime_agent_id.clone(),
            "runtime_agent_kind": capability.runtime_agent_kind.clone(),
            "state": capability.state.clone(),
        }),
    );

    let (capability, mut executions) = state
        .broker_state
        .get_capability_detail(&capability_id)
        .await
        .ok_or_else(|| {
            V1Error::not_found(
                "BROKER_CAPABILITY_NOT_FOUND",
                "broker capability status was not found",
            )
        })?;
    executions.sort_by(|left, right| right.executed_at.cmp(&left.executed_at));

    Ok(Json(BrokerCapabilityDetailResponse {
        capability,
        executions,
    }))
}

pub async fn revoke_all_capabilities(
    State(state): State<AppState>,
    Json(request): Json<BrokerRevokeCapabilityRequest>,
) -> Result<Json<BrokerRevokeAllResponse>, V1Error> {
    let revoked_count = state
        .broker_state
        .revoke_all_active(request.reason.clone())
        .await;

    record_broker_audit(
        &state,
        "broker_capabilities_revoked",
        "allowed",
        "broker panic revoke executed",
        None,
        None,
        None,
        serde_json::json!({
            "revoked_count": revoked_count,
            "reason": request.reason.clone(),
        }),
    );
    broadcast_broker_event(
        &state,
        "broker_capabilities_revoked",
        serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "revoked_count": revoked_count,
            "reason": request.reason,
        }),
    );

    Ok(Json(BrokerRevokeAllResponse { revoked_count }))
}

pub async fn list_frozen_providers(
    State(state): State<AppState>,
) -> Result<Json<BrokerFrozenProvidersResponse>, V1Error> {
    Ok(Json(BrokerFrozenProvidersResponse {
        frozen_providers: state.broker_state.list_frozen_providers().await,
    }))
}

pub async fn freeze_provider(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Json(request): Json<BrokerFreezeProviderRequest>,
) -> Result<Json<BrokerFrozenProvidersResponse>, V1Error> {
    if request.reason.trim().is_empty() {
        return Err(V1Error::bad_request(
            "BROKER_FREEZE_REASON_REQUIRED",
            "provider freeze requests require a non-empty reason",
        ));
    }

    let provider = parse_provider(&provider)?;
    let freeze = state
        .broker_state
        .freeze_provider(provider.clone(), request.reason.clone())
        .await;

    record_broker_audit(
        &state,
        "broker_provider_frozen",
        "allowed",
        "broker provider frozen",
        None,
        None,
        None,
        serde_json::json!({
            "provider": provider_name(&provider),
            "reason": freeze.reason,
        }),
    );
    broadcast_broker_event(
        &state,
        "broker_provider_frozen",
        serde_json::json!({
            "timestamp": freeze.frozen_at.to_rfc3339(),
            "provider": provider_name(&provider),
            "reason": freeze.reason,
        }),
    );

    Ok(Json(BrokerFrozenProvidersResponse {
        frozen_providers: state.broker_state.list_frozen_providers().await,
    }))
}

pub async fn unfreeze_provider(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> Result<Json<BrokerFrozenProvidersResponse>, V1Error> {
    let provider = parse_provider(&provider)?;
    let removed = state.broker_state.unfreeze_provider(&provider).await;
    if removed.is_none() {
        return Err(V1Error::not_found(
            "BROKER_PROVIDER_NOT_FROZEN",
            "broker provider freeze state was not found",
        ));
    }

    record_broker_audit(
        &state,
        "broker_provider_unfrozen",
        "allowed",
        "broker provider unfrozen",
        None,
        None,
        None,
        serde_json::json!({
            "provider": provider_name(&provider),
        }),
    );
    broadcast_broker_event(
        &state,
        "broker_provider_unfrozen",
        serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "provider": provider_name(&provider),
        }),
    );

    Ok(Json(BrokerFrozenProvidersResponse {
        frozen_providers: state.broker_state.list_frozen_providers().await,
    }))
}

pub async fn replay_capability(
    State(state): State<AppState>,
    Path(capability_id): Path<String>,
) -> Result<Json<BrokerReplayResponse>, V1Error> {
    let capability = state
        .broker_state
        .get_capability_status(&capability_id)
        .await
        .ok_or_else(|| {
            V1Error::not_found(
                "BROKER_CAPABILITY_NOT_FOUND",
                "broker capability status was not found",
            )
        })?;
    let parsed = Url::parse(&capability.url)
        .map_err(|error| V1Error::bad_request("BROKER_REPLAY_URL_INVALID", error.to_string()))?;
    let host = parsed.host_str().ok_or_else(|| {
        V1Error::bad_request(
            "BROKER_REPLAY_URL_INVALID",
            "broker replay url is missing host",
        )
    })?;
    let port = parsed.port_or_known_default();

    let (default_policy, keypair) = {
        let engine = state.engine.read().await;
        (engine.policy().clone(), engine.keypair().cloned())
    };

    let mut context = GuardContext::new();
    let mut notes = Vec::new();
    if let Some(session_id) = capability.session_id.as_deref() {
        match state
            .sessions
            .get_session(session_id)
            .map_err(|error| V1Error::internal("BROKER_REPLAY_SESSION_ERROR", error.to_string()))?
        {
            Some(session) => {
                context = state.sessions.create_guard_context(&session, None);
            }
            None => notes.push(
                "session context unavailable; replay used a reduced guard context".to_string(),
            ),
        }
    }
    if let Some(agent_id) = capability.endpoint_agent_id.clone() {
        context = context.with_agent_id(agent_id);
    }

    let resolved = state
        .policy_resolver
        .resolve_policy(&default_policy, &context)
        .map_err(|error| V1Error::internal("BROKER_POLICY_ERROR", error.to_string()))?;
    let resolved_yaml = resolved
        .policy
        .to_yaml()
        .map_err(|error| V1Error::internal("BROKER_POLICY_ERROR", error.to_string()))?;
    let policy_hash = hush_core::sha256(resolved_yaml.as_bytes()).to_hex();
    let engine: Arc<HushEngine> = match keypair {
        Some(keypair) => state
            .policy_engine_cache
            .get_or_insert_with(&policy_hash, || {
                Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_keypair(keypair))
            }),
        None => Arc::new(HushEngine::with_policy(resolved.policy.clone()).with_generated_keypair()),
    };
    let broker = resolved.policy.broker.as_ref().ok_or_else(|| {
        V1Error::forbidden(
            "BROKER_POLICY_MISSING",
            "current policy does not define a broker configuration",
        )
    })?;
    let egress = engine
        .check_egress(host, port.unwrap_or(443), &context)
        .await
        .map_err(|error| V1Error::internal("BROKER_POLICY_ERROR", error.to_string()))?;
    let provider_policy = policy_match(
        broker,
        &capability.provider,
        host,
        port,
        parsed.path(),
        &capability.method,
        &capability.secret_ref_id,
    );
    let provider_frozen = state
        .broker_state
        .is_provider_frozen(&capability.provider)
        .await;
    let provider_allowed = provider_policy.is_some();
    let policy_changed = capability.policy_hash != policy_hash;
    let approval_required = capability
        .intent_preview
        .as_ref()
        .map(|preview| preview.approval_required)
        .unwrap_or(false);
    let preview_still_approved = capability.intent_preview.as_ref().map(|preview| {
        !preview.approval_required
            || matches!(
                preview.approval_state,
                clawdstrike_broker_protocol::BrokerApprovalState::Approved
                    | clawdstrike_broker_protocol::BrokerApprovalState::NotRequired
            )
    });
    let mut diffs = Vec::new();
    if policy_changed {
        diffs.push(BrokerReplayDiff {
            field: "policy_hash".to_string(),
            previous: capability.policy_hash.clone(),
            current: policy_hash.clone(),
        });
    }
    if provider_frozen {
        diffs.push(BrokerReplayDiff {
            field: "provider_freeze".to_string(),
            previous: "unfrozen".to_string(),
            current: "frozen".to_string(),
        });
    }
    if matches!(
        capability.state,
        BrokerCapabilityState::Revoked | BrokerCapabilityState::Expired
    ) {
        diffs.push(BrokerReplayDiff {
            field: "capability_state".to_string(),
            previous: "active".to_string(),
            current: match capability.state {
                BrokerCapabilityState::Revoked => "revoked".to_string(),
                BrokerCapabilityState::Expired => "expired".to_string(),
                BrokerCapabilityState::Frozen => "frozen".to_string(),
                BrokerCapabilityState::Active => "active".to_string(),
            },
        });
    }
    if approval_required && preview_still_approved == Some(false) {
        diffs.push(BrokerReplayDiff {
            field: "preview_approval".to_string(),
            previous: "approved".to_string(),
            current: "missing".to_string(),
        });
    }
    let would_allow = egress.allowed
        && provider_allowed
        && !provider_frozen
        && preview_still_approved.unwrap_or(true)
        && matches!(capability.state, BrokerCapabilityState::Active);
    let reason = if !egress.allowed {
        egress.message
    } else if provider_frozen {
        "provider is currently frozen by broker operator control".to_string()
    } else if approval_required && preview_still_approved == Some(false) {
        "intent preview approval is no longer satisfied".to_string()
    } else if matches!(
        capability.state,
        BrokerCapabilityState::Revoked | BrokerCapabilityState::Expired
    ) {
        match capability.state {
            BrokerCapabilityState::Revoked => "capability has been revoked".to_string(),
            BrokerCapabilityState::Expired => "capability has expired".to_string(),
            _ => "capability is not active".to_string(),
        }
    } else if provider_policy.is_none() {
        "requested provider, host, path, method, or secret_ref is not authorized by current broker policy"
            .to_string()
    } else {
        "current policy would still authorize this capability".to_string()
    };
    if provider_frozen {
        notes.push("provider is frozen".to_string());
    }
    if !egress.allowed {
        notes.push("egress allowlist would block this destination".to_string());
    }
    if !provider_allowed {
        notes.push("broker provider policy would deny this capability".to_string());
    }
    if policy_changed {
        notes.push("resolved policy hash has changed since issuance".to_string());
    }
    if approval_required && preview_still_approved == Some(false) {
        notes.push("intent preview is approval-gated and no longer approved".to_string());
    }
    if matches!(
        capability.state,
        BrokerCapabilityState::Revoked | BrokerCapabilityState::Expired
    ) {
        notes.push(format!(
            "capability is currently {}",
            match capability.state {
                BrokerCapabilityState::Revoked => "revoked",
                BrokerCapabilityState::Expired => "expired",
                _ => "inactive",
            }
        ));
    }

    let response = BrokerReplayResponse {
        capability_id,
        current_policy_hash: policy_hash,
        current_state: capability.state,
        provider_frozen,
        egress_allowed: egress.allowed,
        provider_allowed,
        policy_changed,
        approval_required,
        preview_still_approved,
        delegated_subject: capability
            .lineage
            .as_ref()
            .map(|lineage| lineage.subject.clone()),
        minted_identity_kind: capability
            .minted_identity
            .as_ref()
            .map(|identity| format!("{:?}", identity.kind).to_ascii_lowercase()),
        would_allow,
        reason,
        diffs,
        notes,
    };
    broadcast_broker_event(
        &state,
        "broker_capability_replayed",
        serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "capability_id": response.capability_id.clone(),
            "current_policy_hash": response.current_policy_hash.clone(),
            "current_state": response.current_state.clone(),
            "provider_frozen": response.provider_frozen,
            "egress_allowed": response.egress_allowed,
            "provider_allowed": response.provider_allowed,
            "policy_changed": response.policy_changed,
            "approval_required": response.approval_required,
            "preview_still_approved": response.preview_still_approved,
            "delegated_subject": response.delegated_subject.clone(),
            "minted_identity_kind": response.minted_identity_kind.clone(),
            "would_allow": response.would_allow,
            "reason": response.reason.clone(),
        }),
    );

    Ok(Json(response))
}

pub async fn public_key(
    State(state): State<AppState>,
) -> Result<Json<BrokerPublicKeyResponse>, V1Error> {
    let engine = state.engine.read().await;
    let public_key = engine
        .keypair()
        .map(|keypair| keypair.public_key().to_hex())
        .ok_or_else(|| {
            V1Error::internal(
                "BROKER_SIGNING_KEY_UNAVAILABLE",
                "resolved hushd engine is missing a signing keypair",
            )
        })?;

    Ok(Json(BrokerPublicKeyResponse { public_key }))
}
