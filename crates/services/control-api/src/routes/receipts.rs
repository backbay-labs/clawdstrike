use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use hush_core::receipt::{PublicKeySet, VerificationResult};
use hush_core::{PublicKey, Signature, SignedReceipt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Size limits for in-memory stores
// ---------------------------------------------------------------------------

/// Maximum number of receipts per tenant before inserts are rejected.
const MAX_RECEIPTS_PER_TENANT: usize = 10_000;

/// Maximum serialized size (in bytes) for evidence, metadata, or signed_receipt fields.
const MAX_RECEIPT_PAYLOAD_BYTES: usize = 1_048_576; // 1 MB

// ---------------------------------------------------------------------------
// In-memory receipt store
// ---------------------------------------------------------------------------

/// Tenant-scoped in-memory receipt store.
///
/// Keyed by `(tenant_id, receipt_id)` for isolation. A production implementation
/// would back this with Postgres, but the in-memory approach matches the
/// early-stage pattern used elsewhere in the control-api scaffold.
#[derive(Clone, Default)]
pub struct ReceiptStore {
    inner: Arc<RwLock<ReceiptStoreInner>>,
}

#[derive(Default)]
struct ReceiptStoreInner {
    /// Primary index: receipt UUID -> stored receipt.
    by_id: HashMap<Uuid, StoredReceipt>,
    /// Secondary index: (tenant_id, receipt_id) for tenant-scoped lookups.
    by_tenant: HashMap<Uuid, Vec<Uuid>>,
    /// Chain index: (tenant_id, policy_name) -> ordered receipt IDs.
    by_chain: HashMap<(Uuid, String), Vec<Uuid>>,
}

impl ReceiptStore {
    pub fn new() -> Self {
        Self::default()
    }

    async fn insert(
        &self,
        tenant_id: Uuid,
        receipt: StoredReceipt,
    ) -> Result<StoredReceipt, ApiError> {
        // Validate payload sizes before acquiring lock.
        Self::validate_payload_size(&receipt)?;

        let mut store = self.inner.write().await;

        let id = receipt.id;
        if store.by_id.contains_key(&id) {
            return Err(ApiError::Conflict(format!("receipt '{id}' already exists")));
        }

        // Enforce per-tenant receipt limit.
        let tenant_count = store.by_tenant.get(&tenant_id).map_or(0, Vec::len);
        if tenant_count >= MAX_RECEIPTS_PER_TENANT {
            return Err(ApiError::Conflict(format!(
                "tenant receipt limit reached ({MAX_RECEIPTS_PER_TENANT})"
            )));
        }

        // Update chain index.
        let chain_key = (tenant_id, receipt.policy_name.clone());
        store.by_chain.entry(chain_key).or_default().push(id);

        // Update tenant index.
        store.by_tenant.entry(tenant_id).or_default().push(id);

        store.by_id.insert(id, receipt.clone());
        Ok(receipt)
    }

    /// Validate that individual JSON payload fields do not exceed the size limit.
    fn validate_payload_size(receipt: &StoredReceipt) -> Result<(), ApiError> {
        if let Some(ref evidence) = receipt.evidence {
            let size = serde_json::to_string(evidence)
                .map(|s| s.len())
                .unwrap_or(0);
            if size > MAX_RECEIPT_PAYLOAD_BYTES {
                return Err(ApiError::BadRequest(format!(
                    "evidence field exceeds maximum size ({MAX_RECEIPT_PAYLOAD_BYTES} bytes)"
                )));
            }
        }
        if let Some(ref metadata) = receipt.metadata {
            let size = serde_json::to_string(metadata)
                .map(|s| s.len())
                .unwrap_or(0);
            if size > MAX_RECEIPT_PAYLOAD_BYTES {
                return Err(ApiError::BadRequest(format!(
                    "metadata field exceeds maximum size ({MAX_RECEIPT_PAYLOAD_BYTES} bytes)"
                )));
            }
        }
        if let Some(ref signed_receipt) = receipt.signed_receipt {
            let size = serde_json::to_string(signed_receipt)
                .map(|s| s.len())
                .unwrap_or(0);
            if size > MAX_RECEIPT_PAYLOAD_BYTES {
                return Err(ApiError::BadRequest(format!(
                    "signed_receipt field exceeds maximum size ({MAX_RECEIPT_PAYLOAD_BYTES} bytes)"
                )));
            }
        }
        Ok(())
    }

    async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<StoredReceipt>, ApiError> {
        let store = self.inner.read().await;

        let receipt = store.by_id.get(&id).cloned();
        // Ensure tenant isolation.
        match receipt {
            Some(r) if r.tenant_id == tenant_id => Ok(Some(r)),
            Some(_) => Ok(None),
            None => Ok(None),
        }
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<StoredReceipt>, usize), ApiError> {
        let store = self.inner.read().await;

        let ids = store.by_tenant.get(&tenant_id);
        let total = ids.map_or(0, Vec::len);

        let items: Vec<StoredReceipt> = ids
            .map(|ids| {
                ids.iter()
                    .rev() // newest first
                    .skip(offset)
                    .take(limit)
                    .filter_map(|id| store.by_id.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default();

        Ok((items, total))
    }

    async fn chain(
        &self,
        tenant_id: Uuid,
        policy_name: &str,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<StoredReceipt>, usize), ApiError> {
        let store = self.inner.read().await;

        let chain_key = (tenant_id, policy_name.to_string());
        let ids = store.by_chain.get(&chain_key);
        let total = ids.map_or(0, Vec::len);

        let items: Vec<StoredReceipt> = ids
            .map(|ids| {
                ids.iter()
                    .skip(offset)
                    .take(limit)
                    .filter_map(|id| store.by_id.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default();

        Ok((items, total))
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A receipt persisted in the store with server-side metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredReceipt {
    /// Server-assigned unique ID.
    pub id: Uuid,
    /// Owning tenant (excluded from API responses).
    #[serde(skip_serializing)]
    pub tenant_id: Uuid,
    /// ISO-8601 timestamp from the original receipt.
    pub timestamp: String,
    /// Overall verdict: "allow", "deny", or "warn".
    pub verdict: String,
    /// Guard that produced this receipt (e.g., "ForbiddenPathGuard").
    pub guard: String,
    /// Policy name / ruleset that was active.
    pub policy_name: String,
    /// Hex-encoded Ed25519 signature.
    pub signature: String,
    /// Hex-encoded Ed25519 public key of the signer.
    pub public_key: String,
    /// Hex-encoded SHA-256 chain hash linking to the previous receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_hash: Option<String>,
    /// Guard-specific evidence payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
    /// Arbitrary metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Original signed receipt payload used for exact verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_receipt: Option<serde_json::Value>,
}

/// Paginated response wrapper.
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}

/// Query parameters for listing receipts.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReceiptsQuery {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

/// Query parameters for the receipt chain endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainReceiptsQuery {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

/// Request body for storing a single receipt.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreReceiptRequest {
    pub timestamp: String,
    pub verdict: String,
    pub guard: String,
    pub policy_name: String,
    pub signature: String,
    pub public_key: String,
    #[serde(default)]
    pub chain_hash: Option<String>,
    #[serde(default)]
    pub evidence: Option<serde_json::Value>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub signed_receipt: Option<serde_json::Value>,
}

/// Request body for storing multiple receipts at once.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchStoreReceiptsRequest {
    pub receipts: Vec<StoreReceiptRequest>,
}

/// Response for a batch store operation.
#[derive(Debug, Serialize)]
pub struct BatchStoreReceiptsResponse {
    pub stored: Vec<StoredReceipt>,
    pub count: usize,
}

/// Request body for server-side receipt verification.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyReceiptRequest {
    /// Optional override public key (hex). If omitted, uses the key stored on the receipt.
    #[serde(default)]
    pub public_key: Option<String>,
}

/// Response for receipt verification.
#[derive(Debug, Serialize)]
pub struct VerifyReceiptResponse {
    pub valid: bool,
    pub signer_valid: bool,
    pub receipt_id: Uuid,
    /// Indicates whether the public key used for verification matches the stored key.
    /// `false` when a caller-supplied public key override differs from the stored key.
    pub key_matches_stored: bool,
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/receipts", get(list_receipts))
        .route("/receipts", post(store_receipt))
        .route("/receipts/batch", post(batch_store_receipts))
        .route("/receipts/{id}", get(get_receipt))
        .route("/receipts/{id}/verify", post(verify_receipt))
        .route("/receipts/chain/{policy_name}", get(get_receipt_chain))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /api/v1/receipts?offset=0&limit=50
async fn list_receipts(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<ListReceiptsQuery>,
) -> Result<Json<PaginatedResponse<StoredReceipt>>, ApiError> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).min(500);

    let (items, total) = state
        .receipt_store
        .list(auth.tenant_id, offset, limit)
        .await?;

    Ok(Json(PaginatedResponse {
        items,
        total,
        offset,
        limit,
    }))
}

/// GET /api/v1/receipts/{id}
async fn get_receipt(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<StoredReceipt>, ApiError> {
    state
        .receipt_store
        .get(auth.tenant_id, id)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}

/// POST /api/v1/receipts
async fn store_receipt(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<StoreReceiptRequest>,
) -> Result<Json<StoredReceipt>, ApiError> {
    ensure_write_access(&auth)?;
    validate_store_request(&req)?;

    let receipt = stored_receipt_from_request(auth.tenant_id, req);
    let stored = state.receipt_store.insert(auth.tenant_id, receipt).await?;

    tracing::info!(
        receipt_id = %stored.id,
        tenant = %auth.slug,
        guard = %stored.guard,
        verdict = %stored.verdict,
        "Receipt stored"
    );

    Ok(Json(stored))
}

/// POST /api/v1/receipts/batch
async fn batch_store_receipts(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<BatchStoreReceiptsRequest>,
) -> Result<Json<BatchStoreReceiptsResponse>, ApiError> {
    ensure_write_access(&auth)?;

    if req.receipts.is_empty() {
        return Err(ApiError::BadRequest(
            "receipts array must not be empty".to_string(),
        ));
    }

    if req.receipts.len() > 1000 {
        return Err(ApiError::BadRequest(
            "batch size must not exceed 1000 receipts".to_string(),
        ));
    }

    for r in &req.receipts {
        validate_store_request(r)?;
    }

    let mut stored = Vec::with_capacity(req.receipts.len());
    for r in req.receipts {
        let receipt = stored_receipt_from_request(auth.tenant_id, r);
        let s = state.receipt_store.insert(auth.tenant_id, receipt).await?;
        stored.push(s);
    }

    let count = stored.len();

    tracing::info!(
        tenant = %auth.slug,
        count,
        "Batch receipts stored"
    );

    Ok(Json(BatchStoreReceiptsResponse { stored, count }))
}

/// GET /api/v1/receipts/chain/{policy_name}?offset=0&limit=100
async fn get_receipt_chain(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(policy_name): Path<String>,
    Query(query): Query<ChainReceiptsQuery>,
) -> Result<Json<PaginatedResponse<StoredReceipt>>, ApiError> {
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(500);

    let (items, total) = state
        .receipt_store
        .chain(auth.tenant_id, &policy_name, offset, limit)
        .await?;

    Ok(Json(PaginatedResponse {
        items,
        total,
        offset,
        limit,
    }))
}

/// POST /api/v1/receipts/{id}/verify
async fn verify_receipt(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<VerifyReceiptRequest>,
) -> Result<Json<VerifyReceiptResponse>, ApiError> {
    let receipt = state
        .receipt_store
        .get(auth.tenant_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;

    let public_key_hex = req.public_key.as_deref().unwrap_or(&receipt.public_key);
    let key_matches_stored = public_key_hex == receipt.public_key;

    let public_key = hush_core::PublicKey::from_hex(public_key_hex)
        .map_err(|_| ApiError::BadRequest("invalid public key hex".to_string()))?;

    let verification = verify_exact_signed_receipt(&receipt, public_key);

    Ok(Json(VerifyReceiptResponse {
        valid: verification.valid,
        signer_valid: verification.signer_valid,
        receipt_id: id,
        key_matches_stored,
        errors: verification.errors,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn has_write_access(auth: &AuthenticatedTenant) -> bool {
    matches!(auth.role.as_str(), "member" | "admin" | "owner")
}

fn ensure_write_access(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if !has_write_access(auth) {
        return Err(ApiError::Forbidden);
    }

    Ok(())
}

fn validate_store_request(req: &StoreReceiptRequest) -> Result<(), ApiError> {
    if req.signature.is_empty() {
        return Err(ApiError::BadRequest(
            "signature must not be empty".to_string(),
        ));
    }
    if req.public_key.is_empty() {
        return Err(ApiError::BadRequest(
            "public_key must not be empty".to_string(),
        ));
    }
    if req.guard.is_empty() {
        return Err(ApiError::BadRequest("guard must not be empty".to_string()));
    }
    if req.policy_name.is_empty() {
        return Err(ApiError::BadRequest(
            "policy_name must not be empty".to_string(),
        ));
    }

    // Validate verdict against an allow-list.
    if !matches!(req.verdict.as_str(), "allow" | "deny" | "warn") {
        return Err(ApiError::BadRequest(
            "verdict must be one of: allow, deny, warn".to_string(),
        ));
    }

    // Validate timestamp as RFC 3339.
    chrono::DateTime::parse_from_rfc3339(&req.timestamp).map_err(|_| {
        ApiError::BadRequest("timestamp must be a valid RFC 3339 datetime".to_string())
    })?;

    let public_key = PublicKey::from_hex(&req.public_key).map_err(|_| {
        ApiError::BadRequest("invalid public_key: not a valid Ed25519 public key hex".to_string())
    })?;
    Signature::from_hex(&req.signature).map_err(|_| {
        ApiError::BadRequest("invalid signature: not a valid Ed25519 signature hex".to_string())
    })?;

    let signed_receipt_json = req.signed_receipt.as_ref().ok_or_else(|| {
        ApiError::BadRequest("signed_receipt is required for receipt storage".to_string())
    })?;
    let signed_receipt: SignedReceipt = serde_json::from_value(signed_receipt_json.clone())
        .map_err(|e| ApiError::BadRequest(format!("invalid signed_receipt: {}", e)))?;

    if signed_receipt.signatures.signer.to_hex() != req.signature {
        return Err(ApiError::BadRequest(
            "signed_receipt.signatures.signer must match signature".to_string(),
        ));
    }

    if signed_receipt.receipt.timestamp != req.timestamp {
        return Err(ApiError::BadRequest(
            "signed_receipt.receipt.timestamp must match timestamp".to_string(),
        ));
    }

    let expected_passed = matches!(req.verdict.as_str(), "allow");
    if signed_receipt.receipt.verdict.passed != expected_passed {
        return Err(ApiError::BadRequest(
            "signed_receipt.receipt.verdict must match verdict".to_string(),
        ));
    }

    let verification = signed_receipt.verify(&PublicKeySet::new(public_key));
    if !verification.valid {
        return Err(ApiError::BadRequest(format!(
            "signed_receipt failed verification: {}",
            verification.errors.join("; ")
        )));
    }

    Ok(())
}

fn stored_receipt_from_request(tenant_id: Uuid, req: StoreReceiptRequest) -> StoredReceipt {
    StoredReceipt {
        id: Uuid::new_v4(),
        tenant_id,
        timestamp: req.timestamp,
        verdict: req.verdict,
        guard: req.guard,
        policy_name: req.policy_name,
        signature: req.signature,
        public_key: req.public_key,
        chain_hash: req.chain_hash,
        evidence: req.evidence,
        metadata: req.metadata,
        signed_receipt: req.signed_receipt,
    }
}

fn verify_exact_signed_receipt(
    receipt: &StoredReceipt,
    public_key: hush_core::PublicKey,
) -> VerificationResult {
    let Some(signed_receipt_json) = &receipt.signed_receipt else {
        return VerificationResult {
            valid: false,
            signer_valid: false,
            cosigner_valid: None,
            errors: vec![
                "receipt does not include signed_receipt; exact payload unavailable".to_string(),
            ],
            error_codes: vec!["VFY_RECEIPT_PAYLOAD_MISSING".to_string()],
            policy_subcode: None,
        };
    };

    let signed_receipt: hush_core::SignedReceipt =
        match serde_json::from_value(signed_receipt_json.clone()) {
            Ok(signed_receipt) => signed_receipt,
            Err(e) => {
                return VerificationResult {
                    valid: false,
                    signer_valid: false,
                    cosigner_valid: None,
                    errors: vec![format!("stored signed_receipt is invalid: {}", e)],
                    error_codes: vec!["VFY_RECEIPT_PAYLOAD_INVALID".to_string()],
                    policy_subcode: None,
                };
            }
        };

    if signed_receipt.signatures.signer.to_hex() != receipt.signature {
        return VerificationResult {
            valid: false,
            signer_valid: false,
            cosigner_valid: None,
            errors: vec![
                "stored signature field does not match signed_receipt.signatures.signer"
                    .to_string(),
            ],
            error_codes: vec!["VFY_RECEIPT_SIGNATURE_MISMATCH".to_string()],
            policy_subcode: None,
        };
    }

    signed_receipt.verify(&PublicKeySet::new(public_key))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_auth(role: &str) -> AuthenticatedTenant {
        AuthenticatedTenant {
            tenant_id: Uuid::new_v4(),
            slug: "test-tenant".to_string(),
            plan: "enterprise".to_string(),
            agent_limit: 100,
            user_id: None,
            api_key_id: None,
            role: role.to_string(),
            auth_source: crate::auth::AuthSource::Jwt,
        }
    }

    fn make_store() -> ReceiptStore {
        ReceiptStore::new()
    }

    fn make_receipt(tenant_id: Uuid, policy: &str) -> StoredReceipt {
        StoredReceipt {
            id: Uuid::new_v4(),
            tenant_id,
            timestamp: "2026-03-09T00:00:00Z".to_string(),
            verdict: "allow".to_string(),
            guard: "ForbiddenPathGuard".to_string(),
            policy_name: policy.to_string(),
            signature: "abcd1234".to_string(),
            public_key: "deadbeef".to_string(),
            chain_hash: None,
            evidence: None,
            metadata: None,
            signed_receipt: None,
        }
    }

    #[tokio::test]
    async fn insert_and_get_receipt() {
        let store = make_store();
        let tenant = Uuid::new_v4();
        let receipt = make_receipt(tenant, "default");
        let id = receipt.id;

        store.insert(tenant, receipt).await.unwrap();
        let fetched = store.get(tenant, id).await.unwrap().unwrap();
        assert_eq!(fetched.id, id);
        assert_eq!(fetched.policy_name, "default");
    }

    #[tokio::test]
    async fn tenant_isolation() {
        let store = make_store();
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let receipt = make_receipt(tenant_a, "default");
        let id = receipt.id;

        store.insert(tenant_a, receipt).await.unwrap();

        // Tenant B cannot see tenant A's receipt.
        assert!(store.get(tenant_b, id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn duplicate_id_rejected() {
        let store = make_store();
        let tenant = Uuid::new_v4();
        let receipt = make_receipt(tenant, "default");
        let dup = receipt.clone();

        store.insert(tenant, receipt).await.unwrap();
        let err = store.insert(tenant, dup).await.unwrap_err();
        assert!(matches!(err, ApiError::Conflict(_)));
    }

    #[tokio::test]
    async fn list_with_pagination() {
        let store = make_store();
        let tenant = Uuid::new_v4();

        for _ in 0..5 {
            let r = make_receipt(tenant, "default");
            store.insert(tenant, r).await.unwrap();
        }

        let (items, total) = store.list(tenant, 0, 3).await.unwrap();
        assert_eq!(total, 5);
        assert_eq!(items.len(), 3);

        let (items, total) = store.list(tenant, 3, 10).await.unwrap();
        assert_eq!(total, 5);
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn chain_by_policy() {
        let store = make_store();
        let tenant = Uuid::new_v4();

        for _ in 0..3 {
            store
                .insert(tenant, make_receipt(tenant, "strict"))
                .await
                .unwrap();
        }
        store
            .insert(tenant, make_receipt(tenant, "permissive"))
            .await
            .unwrap();

        let (chain, _) = store.chain(tenant, "strict", 0, 500).await.unwrap();
        assert_eq!(chain.len(), 3);
        assert!(chain.iter().all(|r| r.policy_name == "strict"));

        let (chain, _) = store.chain(tenant, "permissive", 0, 500).await.unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[tokio::test]
    async fn empty_store_returns_empty() {
        let store = make_store();
        let tenant = Uuid::new_v4();

        let (items, total) = store.list(tenant, 0, 10).await.unwrap();
        assert!(items.is_empty());
        assert_eq!(total, 0);

        let (chain, total) = store.chain(tenant, "missing", 0, 100).await.unwrap();
        assert!(chain.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn exact_verification_uses_stored_signed_receipt() {
        let tenant = Uuid::new_v4();
        let keypair = hush_core::Keypair::generate();
        let signed_receipt = hush_core::SignedReceipt::sign(
            hush_core::Receipt::new(hush_core::Hash::zero(), hush_core::Verdict::pass()),
            &keypair,
        )
        .unwrap();
        let public_key = keypair.public_key();

        let mut receipt = make_receipt(tenant, "default");
        receipt.signature = signed_receipt.signatures.signer.to_hex();
        receipt.signed_receipt = Some(serde_json::to_value(&signed_receipt).unwrap());

        let verification = verify_exact_signed_receipt(&receipt, public_key);
        assert!(verification.valid);
        assert!(verification.signer_valid);
        assert!(verification.errors.is_empty());
    }

    #[test]
    fn exact_verification_rejects_signature_mismatch() {
        let tenant = Uuid::new_v4();
        let keypair = hush_core::Keypair::generate();
        let other_keypair = hush_core::Keypair::generate();
        let signed_receipt = hush_core::SignedReceipt::sign(
            hush_core::Receipt::new(hush_core::Hash::zero(), hush_core::Verdict::pass()),
            &keypair,
        )
        .unwrap();

        let mut receipt = make_receipt(tenant, "default");
        receipt.signature = other_keypair.sign(b"wrong").to_hex();
        receipt.signed_receipt = Some(serde_json::to_value(&signed_receipt).unwrap());

        let verification = verify_exact_signed_receipt(&receipt, keypair.public_key());
        assert!(!verification.valid);
        assert!(!verification.signer_valid);
        assert_eq!(
            verification.errors,
            vec![
                "stored signature field does not match signed_receipt.signatures.signer"
                    .to_string()
            ]
        );
    }

    #[test]
    fn validate_rejects_empty_fields() {
        let req = StoreReceiptRequest {
            timestamp: "2026-03-09T00:00:00Z".to_string(),
            verdict: String::new(),
            guard: "TestGuard".to_string(),
            policy_name: "default".to_string(),
            signature: "abcd".to_string(),
            public_key: "deadbeef".to_string(),
            chain_hash: None,
            evidence: None,
            metadata: None,
            signed_receipt: None,
        };
        assert!(validate_store_request(&req).is_err());
    }

    fn make_signed_store_request(verdict: &str) -> StoreReceiptRequest {
        let keypair = hush_core::Keypair::generate();
        let receipt_verdict = if verdict == "allow" {
            hush_core::Verdict::pass()
        } else {
            hush_core::Verdict::fail()
        };
        let signed_receipt = hush_core::SignedReceipt::sign(
            hush_core::Receipt::new(hush_core::Hash::zero(), receipt_verdict),
            &keypair,
        )
        .unwrap();

        StoreReceiptRequest {
            timestamp: signed_receipt.receipt.timestamp.clone(),
            verdict: verdict.to_string(),
            guard: "TestGuard".to_string(),
            policy_name: "default".to_string(),
            signature: signed_receipt.signatures.signer.to_hex(),
            public_key: keypair.public_key().to_hex(),
            chain_hash: None,
            evidence: None,
            metadata: None,
            signed_receipt: Some(serde_json::to_value(&signed_receipt).unwrap()),
        }
    }

    #[test]
    fn validate_accepts_warn_verdict_with_signed_receipt() {
        let req = make_signed_store_request("warn");
        assert!(validate_store_request(&req).is_ok());
    }

    #[test]
    fn validate_requires_signed_receipt() {
        let mut req = make_signed_store_request("allow");
        req.signed_receipt = None;
        let err = validate_store_request(&req).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn validate_rejects_invalid_signed_receipt_signature() {
        let mut req = make_signed_store_request("deny");
        req.signature = "00".repeat(64);
        let err = validate_store_request(&req).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn write_access_allows_member_admin_and_owner() {
        assert!(ensure_write_access(&make_auth("member")).is_ok());
        assert!(ensure_write_access(&make_auth("admin")).is_ok());
        assert!(ensure_write_access(&make_auth("owner")).is_ok());
    }

    #[test]
    fn write_access_rejects_viewer() {
        assert!(matches!(
            ensure_write_access(&make_auth("viewer")),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn write_access_rejects_unknown_role() {
        assert!(matches!(
            ensure_write_access(&make_auth("superuser")),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn paginated_response_serializes() {
        let resp = PaginatedResponse {
            items: vec![1, 2, 3],
            total: 10,
            offset: 0,
            limit: 3,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"total\":10"));
        assert!(json.contains("\"items\":[1,2,3]"));
    }
}
