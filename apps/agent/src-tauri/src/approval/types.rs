//! Approval request types and enums shared across the agent.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Default TTL for approval requests.
pub(super) const DEFAULT_TTL_SECS: u64 = 60;

/// Maximum TTL for approval requests (1 hour).
pub(super) const MAX_TTL_SECS: u64 = 3600;

/// Maximum number of entries (pending + resolved) in the approval queue.
pub(super) const MAX_QUEUE_SIZE: usize = 500;

pub(super) fn compute_expires_at(now: DateTime<Utc>, ttl_secs: u64) -> DateTime<Utc> {
    now.checked_add_signed(chrono::Duration::seconds(ttl_secs as i64))
        // If the addition ever overflows (e.g., extreme clock skew), clamp to the max
        // representable time rather than shortening the requested TTL.
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

pub(super) fn is_duplicate_pending(existing: &ApprovalRequest, incoming: &ApprovalRequest) -> bool {
    existing.status == ApprovalStatus::Pending
        && existing.tool == incoming.tool
        && existing.resource == incoming.resource
        && existing.guard == incoming.guard
        && existing.reason == incoming.reason
        && existing.severity == incoming.severity
        && existing.session_id == incoming.session_id
}

/// How the user resolved the approval request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalResolution {
    /// Allow this specific action once.
    AllowOnce,
    /// Allow this action for the rest of the session.
    AllowSession,
    /// Allow this action "always" (not persisted by the agent; adapters may treat this as in-memory).
    AllowAlways,
    /// Deny the action.
    Deny,
}

/// Current status of an approval request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Waiting for user decision.
    Pending,
    /// User resolved the request.
    Resolved,
    /// Request expired without user action.
    Expired,
}

/// An approval request submitted by an adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub tool: String,
    pub resource: String,
    pub guard: String,
    pub reason: String,
    pub severity: String,
    pub session_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: ApprovalStatus,
    pub resolution: Option<ApprovalResolution>,
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub resolved_by_trusted_authority: bool,
}

/// Input for creating an approval request.
#[derive(Debug, Deserialize)]
pub struct ApprovalRequestInput {
    pub tool: String,
    pub resource: String,
    pub guard: String,
    pub reason: String,
    pub severity: String,
    #[serde(default)]
    pub session_id: Option<String>,
    /// Custom TTL in seconds. Defaults to 60.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// Input for resolving an approval request.
#[derive(Debug, Deserialize)]
pub struct ApprovalResolveInput {
    pub resolution: ApprovalResolution,
}

/// Response for approval status queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStatusResponse {
    pub id: String,
    pub status: ApprovalStatus,
    pub resolution: Option<ApprovalResolution>,
    pub resolved_by_trusted_authority: bool,
    pub tool: String,
    pub resource: String,
    pub guard: String,
    pub reason: String,
    pub severity: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

impl From<&ApprovalRequest> for ApprovalStatusResponse {
    fn from(req: &ApprovalRequest) -> Self {
        Self {
            id: req.id.clone(),
            status: req.status.clone(),
            resolution: req.resolution.clone(),
            resolved_by_trusted_authority: req.resolved_by_trusted_authority,
            tool: req.tool.clone(),
            resource: req.resource.clone(),
            guard: req.guard.clone(),
            reason: req.reason.clone(),
            severity: req.severity.clone(),
            created_at: req.created_at,
            expires_at: req.expires_at,
            resolved_at: req.resolved_at,
        }
    }
}

/// Events emitted by the approval queue.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApprovalEvent {
    /// A new approval request was created.
    NewRequest { request: ApprovalStatusResponse },
    /// An approval request was resolved.
    Resolved { request: ApprovalStatusResponse },
    /// An approval request expired.
    Expired { id: String },
}

/// Errors from approval operations.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("Approval request not found")]
    NotFound,
    #[error("Approval request already resolved")]
    AlreadyResolved,
    #[error("Approval request expired")]
    Expired,
    #[error("Approval queue is full — resolve existing approvals first")]
    QueueFull,
}
