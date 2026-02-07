//! `/v1/*` Certification API (issuance, verification, badges, evidence).

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use hush_certification::badge::{
    render_badge_svg, BadgeSvgInput, BadgeTheme, BadgeVariant, CertificationTier,
};
use hush_certification::certification::{
    build_badge_from_record, effective_status, parse_rfc3339, CertificationRecord,
    CertificationStatus, CreateCertificationInput, CreateCertificationResult,
    ListCertificationsFilter, RevokeInput,
};
use hush_certification::evidence::{EvidenceExportRequest, EvidenceExportStatus};
use hush_certification::webhooks::{CreateWebhookInput, UpdateWebhookInput, WebhookRecord};

use crate::api::v1::{
    new_request_id, now_rfc3339, v1_ok_with_links, v1_ok_with_meta, V1Error, V1Links, V1Meta,
    V1Response,
};
use crate::auth::{AuthenticatedActor, Scope};
use crate::certification_webhooks::emit_webhook_event;
use crate::state::AppState;

fn looks_like_jwt(token: &str) -> bool {
    let mut parts = token.split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(_), Some(_), Some(_), None)
    )
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    if auth_header.len() > 7 && auth_header[..7].eq_ignore_ascii_case("Bearer ") {
        Some(&auth_header[7..])
    } else {
        None
    }
}

/// Middleware: require auth for `/v1` endpoints and return v1 error envelopes.
pub async fn require_auth_v1(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, V1Error> {
    if !state.auth_enabled() {
        return Ok(next.run(req).await);
    }

    let token = extract_bearer_token(req.headers()).ok_or_else(|| {
        V1Error::new(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "Missing bearer token",
        )
    })?;

    if looks_like_jwt(token) {
        if let Some(oidc) = state.oidc.as_ref() {
            if let Ok(principal) = oidc.validate_token(token).await {
                req.extensions_mut()
                    .insert(AuthenticatedActor::User(principal));
                return Ok(next.run(req).await);
            }
        }
    }

    let key = state.auth_store.validate_key(token).await.map_err(|_| {
        V1Error::new(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "Invalid or expired API key",
        )
    })?;

    req.extensions_mut().insert(AuthenticatedActor::ApiKey(key));
    Ok(next.run(req).await)
}

/// Middleware: optional auth for public endpoints (badge). If a token is present but invalid, returns 401.
pub async fn optional_auth_v1(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, V1Error> {
    if !state.auth_enabled() {
        return Ok(next.run(req).await);
    }

    let Some(token) = extract_bearer_token(req.headers()) else {
        return Ok(next.run(req).await);
    };

    if looks_like_jwt(token) {
        if let Some(oidc) = state.oidc.as_ref() {
            if let Ok(principal) = oidc.validate_token(token).await {
                req.extensions_mut()
                    .insert(AuthenticatedActor::User(principal));
                return Ok(next.run(req).await);
            }
        }
    }

    let key = state.auth_store.validate_key(token).await.map_err(|_| {
        V1Error::new(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "Invalid or expired API key",
        )
    })?;

    req.extensions_mut().insert(AuthenticatedActor::ApiKey(key));
    Ok(next.run(req).await)
}

type ScopeLayerFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, V1Error>> + Send>>;

pub fn scope_layer_v1(
    scope: Scope,
) -> impl Fn(Request<Body>, Next) -> ScopeLayerFuture + Clone + Send + 'static {
    move |req, next| {
        let scope = scope;
        Box::pin(async move { require_scope_v1(scope, req, next).await })
    }
}

async fn require_scope_v1(
    scope: Scope,
    req: Request<Body>,
    next: Next,
) -> Result<Response, V1Error> {
    let Some(actor) = req.extensions().get::<AuthenticatedActor>() else {
        // When auth is disabled, allow.
        return Ok(next.run(req).await);
    };

    match actor {
        AuthenticatedActor::ApiKey(key) => {
            if !key.has_scope(scope) {
                return Err(V1Error::new(
                    StatusCode::FORBIDDEN,
                    "INSUFFICIENT_SCOPE",
                    format!("Missing required scope: {scope}"),
                ));
            }
        }
        AuthenticatedActor::User(principal) => {
            // Same temporary scope mapping as the legacy middleware.
            let ok = match scope {
                Scope::Check => true,
                Scope::Read => principal.roles.iter().any(|r| {
                    r == "policy-viewer"
                        || r == "audit-viewer"
                        || r == "policy-admin"
                        || r == "super-admin"
                }),
                Scope::Admin => principal
                    .roles
                    .iter()
                    .any(|r| r == "policy-admin" || r == "super-admin"),
                Scope::CertificationsRead | Scope::CertificationsVerify | Scope::EvidenceRead => {
                    principal.roles.iter().any(|r| {
                        r == "policy-viewer"
                            || r == "audit-viewer"
                            || r == "policy-admin"
                            || r == "super-admin"
                            || r == "certification-viewer"
                            || r == "certification-admin"
                    })
                }
                Scope::CertificationsWrite
                | Scope::EvidenceExport
                | Scope::BadgesGenerate
                | Scope::WebhooksManage => principal.roles.iter().any(|r| {
                    r == "policy-admin" || r == "super-admin" || r == "certification-admin"
                }),
                Scope::All => true,
            };

            if !ok {
                return Err(V1Error::new(
                    StatusCode::FORBIDDEN,
                    "INSUFFICIENT_SCOPE",
                    format!("Missing required scope: {scope}"),
                ));
            }
        }
    }

    Ok(next.run(req).await)
}

fn decode_cursor(cursor: &str) -> Option<usize> {
    let raw = URL_SAFE_NO_PAD.decode(cursor).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    json.get("offset")?.as_u64()?.try_into().ok()
}

fn encode_cursor(offset: usize) -> String {
    let bytes = serde_json::to_vec(&serde_json::json!({ "offset": offset })).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn actor_id(actor: Option<&AuthenticatedActor>) -> String {
    match actor {
        Some(AuthenticatedActor::ApiKey(k)) => format!("api_key:{}", k.id),
        Some(AuthenticatedActor::User(p)) => format!("user:{}", p.id),
        None => "anonymous".to_string(),
    }
}

fn parse_tier(s: &str) -> Option<CertificationTier> {
    match s.to_ascii_lowercase().as_str() {
        "certified" => Some(CertificationTier::Certified),
        "silver" => Some(CertificationTier::Silver),
        "gold" => Some(CertificationTier::Gold),
        "platinum" => Some(CertificationTier::Platinum),
        _ => None,
    }
}

fn parse_status(s: &str) -> Option<CertificationStatus> {
    match s.to_ascii_lowercase().as_str() {
        "active" => Some(CertificationStatus::Active),
        "expired" => Some(CertificationStatus::Expired),
        "revoked" => Some(CertificationStatus::Revoked),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
pub struct ListCertificationsQuery {
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default, rename = "agent_id")]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub framework: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationSummary {
    pub tier: CertificationTier,
    pub issue_date: String,
    pub expiry_date: String,
    pub frameworks: Vec<String>,
    pub status: CertificationStatus,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySummary {
    pub hash: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruleset: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSummary {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificationListItem {
    pub certification_id: String,
    pub subject: hush_certification::certification::Subject,
    pub certification: CertificationSummary,
    pub policy: PolicySummary,
    pub issuer: IssuerSummary,
}

fn to_list_item(record: CertificationRecord) -> CertificationListItem {
    let status = effective_status(&record);
    CertificationListItem {
        certification_id: record.certification_id.clone(),
        subject: record.subject.clone(),
        certification: CertificationSummary {
            tier: record.tier,
            issue_date: record.issue_date,
            expiry_date: record.expiry_date,
            frameworks: record.frameworks,
            status,
        },
        policy: PolicySummary {
            hash: record.policy.hash,
            version: record.policy.version,
            ruleset: record.policy.ruleset,
        },
        issuer: IssuerSummary {
            id: record.issuer.id,
            name: record.issuer.name,
        },
    }
}

/// GET /v1/certifications
pub async fn list_certifications(
    State(state): State<AppState>,
    Query(query): Query<ListCertificationsQuery>,
    original_uri: axum::extract::OriginalUri,
) -> Result<Json<V1Response<Vec<CertificationListItem>>>, V1Error> {
    let offset = query.cursor.as_deref().and_then(decode_cursor).unwrap_or(0);

    let tier = query.tier.as_deref().and_then(parse_tier).or(None);
    let status = query.status.as_deref().and_then(parse_status);

    let limit = query.limit.unwrap_or(20).min(100);
    let filter = ListCertificationsFilter {
        organization_id: query.organization_id.clone(),
        subject_id: query.agent_id.clone(),
        tier,
        status,
        framework: query.framework.clone(),
        limit: Some(limit),
        offset: Some(offset),
    };

    let total = state
        .certification_store
        .count_certifications(&filter)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?;

    let records = state
        .certification_store
        .list_certifications(&filter)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?;

    let items: Vec<CertificationListItem> = records.into_iter().map(to_list_item).collect();

    let next = if (offset + items.len()) < (total as usize) {
        let mut next_query = original_uri.0.query().unwrap_or("").to_string();
        // Replace/append cursor in query string (simple heuristic).
        let cursor = encode_cursor(offset + items.len());
        if next_query.contains("cursor=") {
            next_query = next_query
                .split('&')
                .filter(|kv| !kv.starts_with("cursor="))
                .collect::<Vec<_>>()
                .join("&");
        }
        if !next_query.is_empty() {
            next_query.push('&');
        }
        next_query.push_str(&format!("cursor={cursor}"));
        Some(format!("{}?{}", original_uri.0.path(), next_query))
    } else {
        None
    };

    let links = V1Links {
        self_link: Some(original_uri.0.to_string()),
        next,
        ..V1Links::default()
    };

    let meta = V1Meta {
        request_id: new_request_id(),
        timestamp: now_rfc3339(),
        total_count: Some(total),
    };

    Ok(v1_ok_with_meta(items, meta, Some(links)))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCertificationData {
    pub certification_id: String,
    pub version: String,
    pub subject: hush_certification::certification::Subject,
    pub certification: CertificationSummary,
    pub policy: PolicySummary,
    pub evidence: hush_certification::certification::EvidenceBinding,
    pub issuer: hush_certification::certification::Issuer,
}

/// GET /v1/certifications/{id}
pub async fn get_certification(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
    original_uri: axum::extract::OriginalUri,
) -> Result<Json<V1Response<GetCertificationData>>, V1Error> {
    let record = state
        .certification_store
        .get_certification(&certification_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            V1Error::new(
                StatusCode::NOT_FOUND,
                "CERTIFICATION_NOT_FOUND",
                format!("Certification with ID '{certification_id}' not found"),
            )
            .with_details(serde_json::json!({ "certificationId": certification_id }))
        })?;

    let data = GetCertificationData {
        certification_id: record.certification_id.clone(),
        version: record.version.clone(),
        subject: record.subject.clone(),
        certification: CertificationSummary {
            tier: record.tier,
            issue_date: record.issue_date.clone(),
            expiry_date: record.expiry_date.clone(),
            frameworks: record.frameworks.clone(),
            status: effective_status(&record),
        },
        policy: PolicySummary {
            hash: record.policy.hash.clone(),
            version: record.policy.version.clone(),
            ruleset: record.policy.ruleset.clone(),
        },
        evidence: record.evidence.clone(),
        issuer: record.issuer.clone(),
    };

    let id = data.certification_id.clone();
    let links = V1Links {
        self_link: Some(original_uri.0.to_string()),
        verify: Some(format!("/v1/certifications/{id}/verify")),
        badge: Some(format!("/v1/certifications/{id}/badge")),
        evidence: Some(format!("/v1/certifications/{id}/evidence")),
        ..V1Links::default()
    };

    Ok(v1_ok_with_links(data, links))
}

/// POST /v1/certifications
pub async fn create_certification(
    State(state): State<AppState>,
    Json(input): Json<CreateCertificationInput>,
) -> Result<Json<V1Response<CreateCertificationResult>>, V1Error> {
    let event_input = input.clone();
    let keypair = {
        let engine = state.engine.read().await;
        engine.keypair().cloned().ok_or_else(|| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "issuer_keypair_missing",
            )
        })?
    };

    let res = state
        .certification_store
        .create_certification(input, &state.issuer, &keypair)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?;

    emit_webhook_event(
        state.clone(),
        "certification.issued",
        serde_json::json!({
            "certificationId": res.certification_id,
            "subject": { "type": event_input.subject.subject_type, "id": event_input.subject.id },
            "tier": event_input.tier,
            "frameworks": event_input.frameworks,
        }),
    );

    Ok(crate::api::v1::v1_ok(res))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCertificationRequest {
    #[serde(default)]
    pub verification_context: Option<VerificationContext>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationContext {
    #[serde(default)]
    pub required_tier: Option<CertificationTier>,
    #[serde(default)]
    pub required_frameworks: Option<Vec<String>>,
    #[serde(default)]
    pub check_revocation: Option<bool>,
    #[serde(default)]
    pub check_expiry: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCheck {
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_remaining: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyChecks {
    pub signature: VerifyCheck,
    pub expiry: VerifyCheck,
    pub revocation: VerifyCheck,
    pub tier_requirement: VerifyCheck,
    pub framework_requirement: VerifyCheck,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCertificationData {
    pub valid: bool,
    pub certification_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<hush_certification::certification::Subject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<CertificationTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<CertificationStatus>,
    pub checks: VerifyChecks,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reasons: Option<Vec<String>>,
    pub verified_at: String,
}

fn tier_rank(tier: CertificationTier) -> u8 {
    match tier {
        CertificationTier::Certified => 0,
        CertificationTier::Silver => 1,
        CertificationTier::Gold => 2,
        CertificationTier::Platinum => 3,
    }
}

fn verify_record(
    record: &CertificationRecord,
    ctx: Option<&VerificationContext>,
) -> VerifyCertificationData {
    let ctx = ctx.cloned().unwrap_or(VerificationContext {
        required_tier: None,
        required_frameworks: None,
        check_revocation: Some(true),
        check_expiry: Some(true),
    });

    let now = Utc::now();
    let verified_at = now.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let status = effective_status(record);

    let badge = build_badge_from_record(record).ok();
    let sig_ok = badge
        .as_ref()
        .and_then(|b| hush_certification::badge::verify_badge(b).ok())
        .unwrap_or(false);

    let expiry_check = if ctx.check_expiry.unwrap_or(true) {
        let expiry = parse_rfc3339(&record.expiry_date);
        match expiry {
            Some(expiry) if expiry >= now => VerifyCheck {
                passed: true,
                reason: None,
                days_remaining: Some((expiry - now).num_days()),
                actual: None,
                required: None,
            },
            Some(expiry) => VerifyCheck {
                passed: false,
                reason: Some(format!("Certification expired on {}", expiry.to_rfc3339())),
                days_remaining: Some((expiry - now).num_days()),
                actual: None,
                required: None,
            },
            None => VerifyCheck {
                passed: false,
                reason: Some("Invalid expiryDate".to_string()),
                days_remaining: None,
                actual: None,
                required: None,
            },
        }
    } else {
        VerifyCheck {
            passed: true,
            reason: None,
            days_remaining: None,
            actual: None,
            required: None,
        }
    };

    let revocation_check = if ctx.check_revocation.unwrap_or(true) {
        VerifyCheck {
            passed: !matches!(status, CertificationStatus::Revoked),
            reason: if matches!(status, CertificationStatus::Revoked) {
                Some("Certification is revoked".to_string())
            } else {
                None
            },
            days_remaining: None,
            actual: None,
            required: None,
        }
    } else {
        VerifyCheck {
            passed: true,
            reason: None,
            days_remaining: None,
            actual: None,
            required: None,
        }
    };

    let tier_check = if let Some(required) = ctx.required_tier {
        let passed = tier_rank(record.tier) >= tier_rank(required);
        VerifyCheck {
            passed,
            reason: if passed {
                None
            } else {
                Some(format!("Tier requirement not met: required {required:?}"))
            },
            days_remaining: None,
            actual: Some(serde_json::Value::String(
                format!("{:?}", record.tier).to_ascii_lowercase(),
            )),
            required: Some(serde_json::Value::String(
                format!("{required:?}").to_ascii_lowercase(),
            )),
        }
    } else {
        VerifyCheck {
            passed: true,
            reason: None,
            days_remaining: None,
            actual: None,
            required: None,
        }
    };

    let framework_check = if let Some(required) = ctx.required_frameworks.clone() {
        let actual = record.frameworks.clone();
        let missing: Vec<String> = required
            .iter()
            .filter(|r| !actual.iter().any(|a| a.eq_ignore_ascii_case(r)))
            .cloned()
            .collect();
        let passed = missing.is_empty();
        VerifyCheck {
            passed,
            reason: if passed {
                None
            } else {
                Some(format!(
                    "Missing required framework(s): {}",
                    missing.join(", ")
                ))
            },
            days_remaining: None,
            actual: Some(serde_json::to_value(actual).unwrap_or(serde_json::Value::Null)),
            required: Some(serde_json::to_value(required).unwrap_or(serde_json::Value::Null)),
        }
    } else {
        VerifyCheck {
            passed: true,
            reason: None,
            days_remaining: None,
            actual: None,
            required: None,
        }
    };

    let signature_check = VerifyCheck {
        passed: sig_ok,
        reason: if sig_ok {
            None
        } else {
            Some("Signature verification failed".to_string())
        },
        days_remaining: None,
        actual: None,
        required: None,
    };

    let mut failures = Vec::new();
    for check in [
        &signature_check,
        &expiry_check,
        &revocation_check,
        &tier_check,
        &framework_check,
    ] {
        if !check.passed {
            if let Some(reason) = check.reason.clone() {
                failures.push(reason);
            }
        }
    }

    let valid = failures.is_empty();
    VerifyCertificationData {
        valid,
        certification_id: record.certification_id.clone(),
        subject: Some(record.subject.clone()),
        tier: Some(record.tier),
        status: Some(status),
        checks: VerifyChecks {
            signature: signature_check,
            expiry: expiry_check,
            revocation: revocation_check,
            tier_requirement: tier_check,
            framework_requirement: framework_check,
        },
        failure_reasons: if valid { None } else { Some(failures) },
        verified_at,
    }
}

/// POST /v1/certifications/{id}/verify
pub async fn verify_certification(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
    Json(req): Json<VerifyCertificationRequest>,
) -> Result<Json<V1Response<VerifyCertificationData>>, V1Error> {
    let record = state
        .certification_store
        .get_certification(&certification_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            V1Error::new(
                StatusCode::NOT_FOUND,
                "CERTIFICATION_NOT_FOUND",
                format!("Certification with ID '{certification_id}' not found"),
            )
        })?;

    let data = verify_record(&record, req.verification_context.as_ref());
    Ok(crate::api::v1::v1_ok(data))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVerifyRequest {
    pub certifications: Vec<BatchVerifyItem>,
    #[serde(default)]
    pub verification_context: Option<VerificationContext>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVerifyItem {
    #[serde(default)]
    pub certification_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVerifyResultItem {
    pub certification_id: String,
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<CertificationTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVerifySummary {
    pub total: u64,
    pub valid: u64,
    pub invalid: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVerifyData {
    pub results: Vec<BatchVerifyResultItem>,
    pub summary: BatchVerifySummary,
}

/// POST /v1/certifications/verify-batch
pub async fn verify_batch(
    State(state): State<AppState>,
    Json(req): Json<BatchVerifyRequest>,
) -> Result<Json<V1Response<BatchVerifyData>>, V1Error> {
    let mut results = Vec::new();
    let mut valid = 0u64;
    let mut invalid = 0u64;

    for item in req.certifications {
        let mut record = None;
        if let Some(id) = item.certification_id.as_deref() {
            record = state
                .certification_store
                .get_certification(id)
                .map_err(|e| {
                    V1Error::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        e.to_string(),
                    )
                })?;
        } else if let Some(agent_id) = item.agent_id.as_deref() {
            let filter = ListCertificationsFilter {
                subject_id: Some(agent_id.to_string()),
                limit: Some(1),
                offset: Some(0),
                ..ListCertificationsFilter::default()
            };
            let list = state
                .certification_store
                .list_certifications(&filter)
                .map_err(|e| {
                    V1Error::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        e.to_string(),
                    )
                })?;
            record = list.into_iter().next();
        }

        match record {
            Some(rec) => {
                let verified = verify_record(&rec, req.verification_context.as_ref());
                if verified.valid {
                    valid += 1;
                } else {
                    invalid += 1;
                }
                results.push(BatchVerifyResultItem {
                    certification_id: rec.certification_id,
                    valid: verified.valid,
                    tier: Some(rec.tier),
                    reason: verified
                        .failure_reasons
                        .as_ref()
                        .and_then(|v| v.first().cloned()),
                });
            }
            None => {
                invalid += 1;
                results.push(BatchVerifyResultItem {
                    certification_id: item
                        .certification_id
                        .or_else(|| item.agent_id.map(|a| format!("agent:{a}")))
                        .unwrap_or_else(|| "unknown".to_string()),
                    valid: false,
                    tier: None,
                    reason: Some("not_found".to_string()),
                });
            }
        }
    }

    let data = BatchVerifyData {
        results,
        summary: BatchVerifySummary {
            total: valid + invalid,
            valid,
            invalid,
        },
    };

    Ok(crate::api::v1::v1_ok(data))
}

#[derive(Clone, Debug, Deserialize)]
pub struct BadgeQuery {
    #[serde(default)]
    pub variant: Option<String>,
    #[serde(default)]
    pub theme: Option<String>,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
}

fn parse_badge_variant(s: Option<&str>) -> BadgeVariant {
    match s.unwrap_or("full").to_ascii_lowercase().as_str() {
        "icon" => BadgeVariant::Icon,
        "compact" => BadgeVariant::Compact,
        _ => BadgeVariant::Full,
    }
}

fn parse_badge_theme(s: Option<&str>) -> BadgeTheme {
    match s.unwrap_or("auto").to_ascii_lowercase().as_str() {
        "light" => BadgeTheme::Light,
        "dark" => BadgeTheme::Dark,
        _ => BadgeTheme::Auto,
    }
}

fn parse_png_scale(s: Option<&str>) -> Result<f32, V1Error> {
    let raw = s.unwrap_or("1x").trim().to_ascii_lowercase();
    if raw == "1x" {
        return Ok(1.0);
    }
    if raw == "2x" {
        return Ok(2.0);
    }

    Err(V1Error::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "INVALID_SIZE",
        "Unsupported PNG size (use 1x or 2x).",
    ))
}

fn render_badge_png_bytes(svg: &str, scale: f32) -> Result<Vec<u8>, V1Error> {
    let options = resvg::usvg::Options::default();
    let tree = resvg::usvg::Tree::from_str(svg, &options).map_err(|e| {
        V1Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PNG_RENDER_FAILED",
            format!("failed to parse badge SVG: {}", e),
        )
    })?;

    let size = tree.size();
    let width = ((size.width() * scale).round() as u32).max(1);
    let height = ((size.height() * scale).round() as u32).max(1);
    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height).ok_or_else(|| {
        V1Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PNG_RENDER_FAILED",
            "failed to allocate PNG pixel buffer",
        )
    })?;

    let transform = resvg::tiny_skia::Transform::from_scale(scale, scale);
    let mut pixmap_mut = pixmap.as_mut();
    resvg::render(&tree, transform, &mut pixmap_mut);

    pixmap.encode_png().map_err(|e| {
        V1Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PNG_RENDER_FAILED",
            format!("failed to encode PNG badge: {}", e),
        )
    })
}

fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"))
}

fn wants_svg(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("image/svg+xml"))
}

fn wants_png(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("image/png"))
}

fn accepts_any(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("*/*"))
}

/// GET /v1/certifications/{id}/badge
pub async fn get_badge(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
    Query(query): Query<BadgeQuery>,
    headers: HeaderMap,
) -> Result<Response, V1Error> {
    let record = state
        .certification_store
        .get_certification(&certification_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            V1Error::new(
                StatusCode::NOT_FOUND,
                "CERTIFICATION_NOT_FOUND",
                "not_found",
            )
        })?;

    let verification_url = format!("/verify/{}", record.certification_id);

    enum BadgeFormat {
        Svg,
        Json,
        Png,
    }

    let format = if let Some(format) = query
        .format
        .as_deref()
        .map(str::trim)
        .filter(|format| !format.is_empty())
    {
        match format.to_ascii_lowercase().as_str() {
            "svg" => BadgeFormat::Svg,
            "json" => BadgeFormat::Json,
            "png" => BadgeFormat::Png,
            _ => {
                return Err(V1Error::new(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "UNSUPPORTED_FORMAT",
                    "Unsupported badge format (use svg|json|png).",
                ));
            }
        }
    } else if wants_svg(&headers) {
        BadgeFormat::Svg
    } else if wants_json(&headers) {
        BadgeFormat::Json
    } else if wants_png(&headers) && !accepts_any(&headers) {
        BadgeFormat::Png
    } else {
        BadgeFormat::Svg
    };

    if matches!(format, BadgeFormat::Json) {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct EmbedCode {
            html: String,
            markdown: String,
            react: String,
        }

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct DirectUrls {
            svg: String,
            png: String,
            png2x: String,
        }

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct BadgeJsonData {
            certification_id: String,
            embed_code: EmbedCode,
            direct_urls: DirectUrls,
            verification_url: String,
        }

        let svg_url = format!(
            "/v1/certifications/{}/badge?format=svg&variant=full",
            record.certification_id
        );
        let png_url = format!(
            "/v1/certifications/{}/badge?format=png",
            record.certification_id
        );
        let data = BadgeJsonData {
            certification_id: record.certification_id.clone(),
            embed_code: EmbedCode {
                html: format!(
                    "<a href=\"{verification_url}\"><img src=\"{svg_url}\" alt=\"OpenClaw Certified\" /></a>"
                ),
                markdown: format!(
                    "[![OpenClaw Certified]({svg_url})]({verification_url})"
                ),
                react: format!(
                    "<OpenClawBadge certificationId=\"{}\" />",
                    record.certification_id
                ),
            },
            direct_urls: DirectUrls {
                svg: svg_url,
                png: png_url.clone(),
                png2x: format!("{png_url}&size=2x"),
            },
            verification_url,
        };

        let resp = v1_ok_with_links(data, V1Links::default());
        return Ok(resp.into_response());
    }

    let svg = render_badge_svg(
        BadgeSvgInput {
            certification_id: &record.certification_id,
            tier: record.tier,
            subject_name: &record.subject.name,
            issue_date: Some(&record.issue_date),
            expiry_date: Some(&record.expiry_date),
            verification_url: &verification_url,
        },
        parse_badge_variant(query.variant.as_deref()),
        parse_badge_theme(query.theme.as_deref()),
    );

    if matches!(format, BadgeFormat::Png) {
        let scale = parse_png_scale(query.size.as_deref())?;
        let png = render_badge_png_bytes(&svg, scale)?;
        let mut resp = png.into_response();
        resp.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
        resp.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
        return Ok(resp);
    }

    let mut resp = svg.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml; charset=utf-8"),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    Ok(resp)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceListData {
    pub evidence_summary: serde_json::Value,
    pub items: Vec<EvidenceItem>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceItem {
    pub evidence_id: String,
    #[serde(rename = "type")]
    pub evidence_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
}

/// GET /v1/certifications/{id}/evidence
pub async fn list_evidence(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
    original_uri: axum::extract::OriginalUri,
) -> Result<Json<V1Response<EvidenceListData>>, V1Error> {
    let record = state
        .certification_store
        .get_certification(&certification_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            V1Error::new(
                StatusCode::NOT_FOUND,
                "CERTIFICATION_NOT_FOUND",
                "not_found",
            )
        })?;

    let exports = state
        .evidence_exports
        .list_for_certification(&record.certification_id, Some(50), Some(0))
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?;

    let items = exports
        .into_iter()
        .filter(|e| matches!(e.status, EvidenceExportStatus::Completed))
        .map(|e| EvidenceItem {
            evidence_id: e.export_id.clone(),
            evidence_type: "audit_log".to_string(),
            period: match (e.date_start.as_ref(), e.date_end.as_ref()) {
                (Some(start), Some(end)) => Some(serde_json::json!({ "start": start, "end": end })),
                _ => None,
            },
            event_count: None,
            hash: e.sha256.clone().map(|h| format!("sha256:{h}")),
            size: e.size_bytes,
            download_url: Some(format!("/v1/evidence-exports/{}/download", e.export_id)),
        })
        .collect::<Vec<_>>();

    let summary = serde_json::json!({
        "auditEvents": record.evidence.receipt_count,
        "signedReceipts": record.evidence.receipt_count,
        "policySnapshots": 1,
        "guardConfigurations": 0,
    });

    let links = V1Links {
        self_link: Some(original_uri.0.to_string()),
        export: Some(format!(
            "/v1/certifications/{}/evidence/export",
            record.certification_id
        )),
        ..V1Links::default()
    };

    Ok(v1_ok_with_links(
        EvidenceListData {
            evidence_summary: summary,
            items,
        },
        links,
    ))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportEvidenceRequestBody {
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub date_range: Option<DateRange>,
    #[serde(default)]
    pub include_types: Option<Vec<String>>,
    #[serde(default)]
    pub compliance_template: Option<String>,
    #[serde(default)]
    pub notify_email: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DateRange {
    pub start: String,
    pub end: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportEvidenceResponseData {
    pub export_id: String,
    pub status: EvidenceExportStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_completion: Option<String>,
}

/// POST /v1/certifications/{id}/evidence/export
pub async fn export_evidence(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(body): Json<ExportEvidenceRequestBody>,
) -> Result<Json<V1Response<ExportEvidenceResponseData>>, V1Error> {
    if !matches!(body.format.as_deref(), Some("zip") | None) {
        return Err(V1Error::new(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "Only format=zip is supported",
        ));
    }

    let record = state
        .certification_store
        .get_certification(&certification_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            V1Error::new(
                StatusCode::NOT_FOUND,
                "CERTIFICATION_NOT_FOUND",
                "not_found",
            )
        })?;

    let request = EvidenceExportRequest {
        date_start: body.date_range.as_ref().map(|r| r.start.clone()),
        date_end: body.date_range.as_ref().map(|r| r.end.clone()),
        include_types: body.include_types.clone(),
        compliance_template: body.compliance_template.clone(),
    };

    let job = state
        .evidence_exports
        .create_job(&record.certification_id, request.clone())
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?;

    // Spawn background export task.
    let export_id = job.export_id.clone();
    let export_id_for_task = export_id.clone();
    let state_bg = state.clone();
    let actor_id = actor_id(actor.as_ref().map(|a| &a.0));
    tokio::spawn(async move {
        if let Err(err) = run_evidence_export_job(
            &state_bg,
            &record.certification_id,
            &export_id_for_task,
            &request,
            &actor_id,
        )
        .await
        {
            tracing::warn!(export_id = %export_id_for_task, error = %err, "Evidence export failed");
            let _ = state_bg.evidence_exports.mark_failed(&export_id_for_task);
        }
    });

    let links = V1Links {
        status: Some(format!("/v1/evidence-exports/{export_id}")),
        ..V1Links::default()
    };

    Ok(v1_ok_with_links(
        ExportEvidenceResponseData {
            export_id,
            status: EvidenceExportStatus::Processing,
            estimated_size: None,
            estimated_completion: None,
        },
        links,
    ))
}

async fn run_evidence_export_job(
    state: &AppState,
    certification_id: &str,
    export_id: &str,
    request: &EvidenceExportRequest,
    _requested_by: &str,
) -> anyhow::Result<()> {
    let record = state
        .certification_store
        .get_certification(certification_id)?
        .ok_or_else(|| anyhow::anyhow!("certification_not_found"))?;

    let org_id = record
        .subject
        .organization_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("certification_missing_organization_id"))?;

    let start = request.date_start.as_deref().and_then(parse_rfc3339);
    let end = request.date_end.as_deref().and_then(parse_rfc3339);

    let events = state
        .audit_v2
        .query_by_org_range(&org_id, start, end, Some(50_000))?;

    let badge = build_badge_from_record(&record)?;
    let signer = {
        let engine = state.engine.read().await;
        engine.keypair().cloned()
    }
    .ok_or_else(|| anyhow::anyhow!("issuer_keypair_missing"))?;

    let out = hush_certification::evidence::build_evidence_bundle_zip(
        &state.evidence_dir,
        export_id,
        &record,
        &badge,
        &events,
        request,
        &signer,
    )?;

    state.evidence_exports.mark_completed(
        export_id,
        &out.file_path,
        &out.sha256_hex,
        out.size_bytes,
    )?;

    Ok(())
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceExportStatusData {
    pub export_id: String,
    pub status: EvidenceExportStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// GET /v1/evidence-exports/{exportId}
pub async fn get_evidence_export(
    State(state): State<AppState>,
    Path(export_id): Path<String>,
    original_uri: axum::extract::OriginalUri,
) -> Result<Json<V1Response<EvidenceExportStatusData>>, V1Error> {
    let record = state
        .evidence_exports
        .get(&export_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            V1Error::new(
                StatusCode::NOT_FOUND,
                "EVIDENCE_EXPORT_NOT_FOUND",
                "not_found",
            )
        })?;

    let data = EvidenceExportStatusData {
        export_id: record.export_id.clone(),
        status: record.status,
        download_url: match record.status {
            EvidenceExportStatus::Completed => {
                Some(format!("/v1/evidence-exports/{export_id}/download"))
            }
            _ => None,
        },
        expires_at: record.expires_at.clone(),
        size: record.size_bytes,
        hash: record.sha256.map(|h| format!("sha256:{h}")),
    };

    let links = V1Links {
        self_link: Some(original_uri.0.to_string()),
        download: data.download_url.clone(),
        ..V1Links::default()
    };

    Ok(v1_ok_with_links(data, links))
}

/// GET /v1/evidence-exports/{exportId}/download
pub async fn download_evidence_export(
    State(state): State<AppState>,
    Path(export_id): Path<String>,
) -> Result<Response, V1Error> {
    let record = state
        .evidence_exports
        .get(&export_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            V1Error::new(
                StatusCode::NOT_FOUND,
                "EVIDENCE_EXPORT_NOT_FOUND",
                "not_found",
            )
        })?;

    if !matches!(record.status, EvidenceExportStatus::Completed) {
        return Err(V1Error::new(
            StatusCode::ACCEPTED,
            "EVIDENCE_EXPORT_PROCESSING",
            "Export is still processing",
        ));
    }

    let Some(path) = record.file_path.as_deref() else {
        return Err(V1Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "missing_file_path",
        ));
    };

    let bytes = std::fs::read(path).map_err(|e| {
        V1Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        )
    })?;

    let mut resp = bytes.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{export_id}.zip\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    Ok(resp)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeRequestBody {
    pub reason: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub notify_organization: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResponseData {
    pub certification_id: String,
    pub status: CertificationStatus,
    pub revoked_at: String,
    pub reason: String,
    pub revoked_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// POST /v1/certifications/{id}/revoke
pub async fn revoke_certification(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
    actor: Option<axum::extract::Extension<AuthenticatedActor>>,
    Json(body): Json<RevokeRequestBody>,
) -> Result<Json<V1Response<RevokeResponseData>>, V1Error> {
    let revoked_by = actor_id(actor.as_ref().map(|a| &a.0));
    let _ = body.notify_organization;

    let rev = state
        .certification_store
        .revoke(
            &certification_id,
            RevokeInput {
                reason: body.reason.clone(),
                details: body.details.clone(),
                revoked_by: revoked_by.clone(),
            },
        )
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?;

    let response = RevokeResponseData {
        certification_id: rev.certification_id.clone(),
        status: CertificationStatus::Revoked,
        revoked_at: rev.revoked_at.clone(),
        reason: rev.reason.clone(),
        revoked_by: rev.revoked_by.clone(),
        details: rev.details.clone(),
    };

    emit_webhook_event(
        state.clone(),
        "certification.revoked",
        serde_json::json!({
            "certificationId": response.certification_id.clone(),
            "revokedAt": response.revoked_at.clone(),
            "reason": response.reason.clone(),
            "revokedBy": response.revoked_by.clone(),
            "details": response.details.clone(),
        }),
    );

    Ok(crate::api::v1::v1_ok(response))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationStatusData {
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
}

/// GET /v1/certifications/{id}/revocation
pub async fn get_revocation_status(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
) -> Result<Json<V1Response<RevocationStatusData>>, V1Error> {
    let rev = state
        .certification_store
        .get_revocation(&certification_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?;

    let data = match rev {
        Some(r) => RevocationStatusData {
            revoked: true,
            revoked_at: Some(r.revoked_at),
            reason: Some(r.reason),
            details: r.details,
            revoked_by: Some(r.revoked_by),
            superseded_by: r.superseded_by,
        },
        None => RevocationStatusData {
            revoked: false,
            revoked_at: None,
            reason: None,
            details: None,
            revoked_by: None,
            superseded_by: None,
        },
    };

    Ok(crate::api::v1::v1_ok(data))
}

/// GET /v1/certifications/{id}/policy
pub async fn get_policy_snapshot(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
) -> Result<Json<V1Response<serde_json::Value>>, V1Error> {
    let record = state
        .certification_store
        .get_certification(&certification_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            V1Error::new(
                StatusCode::NOT_FOUND,
                "CERTIFICATION_NOT_FOUND",
                "not_found",
            )
        })?;

    let policy = { state.engine.read().await.policy().clone() };
    let yaml =
        serde_yaml::to_string(&policy).unwrap_or_else(|_| "version: \"1.0.0\"\n".to_string());

    let guards = serde_json::json!({
        "forbidden_path": { "enabled": policy.guards.forbidden_path.as_ref().map(|g| g.enabled).unwrap_or(true) },
        "egress_allowlist": { "enabled": policy.guards.egress_allowlist.as_ref().map(|g| g.enabled).unwrap_or(true) },
        "secret_leak": { "enabled": policy.guards.secret_leak.as_ref().map(|g| g.enabled).unwrap_or(true) },
        "patch_integrity": { "enabled": policy.guards.patch_integrity.as_ref().map(|g| g.enabled).unwrap_or(true) },
        "mcp_tool": { "enabled": policy.guards.mcp_tool.as_ref().map(|g| g.enabled).unwrap_or(true) },
        "prompt_injection": { "enabled": policy.guards.prompt_injection.as_ref().map(|g| g.enabled).unwrap_or(true) },
    });

    let data = serde_json::json!({
        "policyHash": record.policy.hash,
        "version": record.policy.version,
        "ruleset": record.policy.ruleset,
        "effectiveFrom": record.issue_date,
        "yaml": yaml,
        "guards": guards,
    });

    Ok(crate::api::v1::v1_ok(data))
}

/// GET /v1/certifications/{id}/policy/history
pub async fn get_policy_history(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
) -> Result<Json<V1Response<serde_json::Value>>, V1Error> {
    let record = state
        .certification_store
        .get_certification(&certification_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| {
            V1Error::new(
                StatusCode::NOT_FOUND,
                "CERTIFICATION_NOT_FOUND",
                "not_found",
            )
        })?;

    let data = serde_json::json!({
        "items": [{
            "policyHash": record.policy.hash,
            "version": record.policy.version,
            "effectiveFrom": record.issue_date,
            "effectiveTo": null,
            "changeSummary": "Current policy",
        }]
    });

    Ok(crate::api::v1::v1_ok(data))
}

/// GET /v1/openapi.json
pub async fn openapi_json() -> Result<Json<serde_json::Value>, V1Error> {
    // Minimal OpenAPI document (enough for tooling to discover endpoints).
    let spec = serde_json::json!({
        "openapi": "3.0.3",
        "info": { "title": "Clawdstrike Certification API", "version": "1.0.0" },
        "paths": {
            "/v1/certifications": {},
            "/v1/certifications/{certificationId}": {},
            "/v1/certifications/{certificationId}/verify": {},
            "/v1/certifications/verify-batch": {},
            "/v1/certifications/{certificationId}/badge": {},
            "/v1/certifications/{certificationId}/evidence": {},
            "/v1/certifications/{certificationId}/evidence/export": {},
            "/v1/evidence-exports/{exportId}": {},
            "/v1/webhooks": {},
            "/v1/webhooks/{webhookId}": {},
        }
    });
    Ok(Json(spec))
}

/// GET /.well-known/ca.json
pub async fn well_known_ca(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, V1Error> {
    let public_key = {
        let engine = state.engine.read().await;
        engine
            .keypair()
            .map(hush_certification::badge::keypair_public_key_base64url)
            .unwrap_or_else(|| "unknown".to_string())
    };

    Ok(Json(serde_json::json!({
        "version": "1.0.0",
        "issuer": {
            "id": state.issuer.id,
            "name": state.issuer.name,
            "algorithm": "Ed25519",
            "publicKey": public_key,
        }
    })))
}

/// GET /verify/{certificationId}
pub async fn verify_page(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
) -> Result<Html<String>, V1Error> {
    let record = state
        .certification_store
        .get_certification(&certification_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?;

    let Some(record) = record else {
        let html = format!(
            r#"<!doctype html><html><head><meta charset="utf-8"><title>Certification Not Found</title></head>
<body style="font-family: ui-sans-serif, system-ui; padding: 24px;">
  <h1>Certification not found</h1>
  <p>No certification with ID <code>{}</code>.</p>
</body></html>"#,
            certification_id
        );
        return Ok(Html(html));
    };

    let verified = verify_record(&record, None);
    let status = effective_status(&record);
    let badge_url = format!(
        "/v1/certifications/{}/badge?variant=full",
        record.certification_id
    );

    fn escape_html(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                _ => out.push(ch),
            }
        }
        out
    }

    let html = format!(
        r#"<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>OpenClaw Certification Verification</title>
    <style>
      body {{ font-family: ui-sans-serif, system-ui, -apple-system; padding: 24px; color: #111827; }}
      .card {{ max-width: 860px; margin: 0 auto; border: 1px solid #E5E7EB; border-radius: 16px; padding: 20px; }}
      .row {{ display: flex; gap: 20px; flex-wrap: wrap; align-items: center; }}
      .muted {{ color: #6B7280; }}
      code {{ background: #F3F4F6; padding: 2px 6px; border-radius: 6px; }}
      .badge {{ border: 1px solid #E5E7EB; border-radius: 12px; padding: 10px; background: #fff; }}
      .pill {{ display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; background: #F3F4F6; }}
      .ok {{ background: #DCFCE7; color: #166534; }}
      .bad {{ background: #FEE2E2; color: #991B1B; }}
      ul {{ margin: 8px 0 0 20px; }}
    </style>
  </head>
  <body>
    <div class="card">
      <div class="row">
        <div class="badge"><img src="{badge_url}" alt="OpenClaw Badge" /></div>
        <div>
          <h1 style="margin: 0;">Certification Verification</h1>
          <div class="muted">Certification ID: <code>{cert_id}</code></div>
          <div style="margin-top: 8px;">
            <span class="pill {valid_class}">{valid_text}</span>
            <span class="pill">{tier}</span>
            <span class="pill">{status:?}</span>
          </div>
        </div>
      </div>

      <hr style="border: none; border-top: 1px solid #E5E7EB; margin: 18px 0;" />

      <div><strong>Subject</strong>: {subject_name} (<code>{subject_id}</code>)</div>
      <div class="muted">Frameworks: {frameworks}</div>
      <div class="muted">Issued: {issue_date} • Expires: {expiry_date}</div>

      <h2 style="margin-top: 18px;">Checks</h2>
      <ul>
        <li>Signature: {sig}</li>
        <li>Expiry: {expiry}</li>
        <li>Revocation: {rev}</li>
      </ul>

      {failures}
    </div>
  </body>
</html>"#,
        badge_url = badge_url,
        cert_id = record.certification_id,
        valid_class = if verified.valid { "ok" } else { "bad" },
        valid_text = if verified.valid { "VALID" } else { "INVALID" },
        tier = format!("{:?}", record.tier).to_ascii_uppercase(),
        status = status,
        subject_name = escape_html(&record.subject.name),
        subject_id = escape_html(&record.subject.id),
        frameworks = escape_html(&record.frameworks.join(", ")),
        issue_date = escape_html(&record.issue_date),
        expiry_date = escape_html(&record.expiry_date),
        sig = if verified.checks.signature.passed {
            "passed"
        } else {
            "failed"
        },
        expiry = if verified.checks.expiry.passed {
            "passed"
        } else {
            "failed"
        },
        rev = if verified.checks.revocation.passed {
            "passed"
        } else {
            "failed"
        },
        failures = if let Some(reasons) = verified.failure_reasons {
            format!(
                "<h3>Failure reasons</h3><ul>{}</ul>",
                reasons
                    .into_iter()
                    .map(|r| format!("<li>{}</li>", escape_html(&r)))
                    .collect::<String>()
            )
        } else {
            "".to_string()
        }
    );

    Ok(Html(html))
}

#[derive(Clone, Debug, Deserialize)]
pub struct ListWebhooksQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// GET /v1/webhooks
pub async fn list_webhooks(
    State(state): State<AppState>,
    Query(query): Query<ListWebhooksQuery>,
    original_uri: axum::extract::OriginalUri,
) -> Result<Json<V1Response<Vec<WebhookRecord>>>, V1Error> {
    let offset = query.cursor.as_deref().and_then(decode_cursor).unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(100);

    let items = state
        .webhook_store
        .list(Some(limit), Some(offset))
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?;

    let next = if items.len() == limit {
        Some(format!(
            "{}?cursor={}",
            original_uri.0.path(),
            encode_cursor(offset + items.len())
        ))
    } else {
        None
    };

    let links = V1Links {
        self_link: Some(original_uri.0.to_string()),
        next,
        ..V1Links::default()
    };

    Ok(v1_ok_with_links(items, links))
}

/// POST /v1/webhooks
pub async fn create_webhook(
    State(state): State<AppState>,
    Json(input): Json<CreateWebhookInput>,
) -> Result<Json<V1Response<WebhookRecord>>, V1Error> {
    let created = state.webhook_store.create(input).map_err(|e| {
        V1Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        )
    })?;
    Ok(crate::api::v1::v1_ok(created))
}

/// GET /v1/webhooks/{webhookId}
pub async fn get_webhook(
    State(state): State<AppState>,
    Path(webhook_id): Path<String>,
) -> Result<Json<V1Response<WebhookRecord>>, V1Error> {
    let webhook = state
        .webhook_store
        .get(&webhook_id)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| V1Error::new(StatusCode::NOT_FOUND, "WEBHOOK_NOT_FOUND", "not_found"))?;
    Ok(crate::api::v1::v1_ok(webhook))
}

/// PATCH /v1/webhooks/{webhookId}
pub async fn update_webhook(
    State(state): State<AppState>,
    Path(webhook_id): Path<String>,
    Json(input): Json<UpdateWebhookInput>,
) -> Result<Json<V1Response<WebhookRecord>>, V1Error> {
    let updated = state
        .webhook_store
        .update(&webhook_id, input)
        .map_err(|e| {
            V1Error::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                e.to_string(),
            )
        })?
        .ok_or_else(|| V1Error::new(StatusCode::NOT_FOUND, "WEBHOOK_NOT_FOUND", "not_found"))?;
    Ok(crate::api::v1::v1_ok(updated))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteWebhookData {
    pub deleted: bool,
}

/// DELETE /v1/webhooks/{webhookId}
pub async fn delete_webhook(
    State(state): State<AppState>,
    Path(webhook_id): Path<String>,
) -> Result<Json<V1Response<DeleteWebhookData>>, V1Error> {
    let deleted = state.webhook_store.delete(&webhook_id).map_err(|e| {
        V1Error::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            e.to_string(),
        )
    })?;
    Ok(crate::api::v1::v1_ok(DeleteWebhookData { deleted }))
}
