//! Per-action approval mechanism for the desktop agent.
//!
//! When a pre-flight guard denies a non-critical action, the adapter can submit
//! an approval request. The agent queues it, surfaces it via OS notification and
//! tray badge, and the user resolves it. Unresolved requests expire after a
//! configurable TTL (default 60s) and are treated as denied.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;

/// Default TTL for approval requests.
const DEFAULT_TTL_SECS: u64 = 60;

/// Maximum TTL for approval requests (1 hour).
const MAX_TTL_SECS: u64 = 3600;

/// Maximum number of entries (pending + resolved) in the approval queue.
const MAX_QUEUE_SIZE: usize = 500;

fn compute_expires_at(now: DateTime<Utc>, ttl_secs: u64) -> DateTime<Utc> {
    now.checked_add_signed(chrono::Duration::seconds(ttl_secs as i64))
        // If the addition ever overflows (e.g., extreme clock skew), clamp to the max
        // representable time rather than shortening the requested TTL.
        .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

fn is_duplicate_pending(existing: &ApprovalRequest, incoming: &ApprovalRequest) -> bool {
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

/// Manages the in-memory approval queue.
pub struct ApprovalQueue {
    requests: Mutex<HashMap<String, ApprovalRequest>>,
    event_tx: broadcast::Sender<ApprovalEvent>,
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

impl ApprovalQueue {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(64);
        Self {
            requests: Mutex::new(HashMap::new()),
            event_tx,
        }
    }

    /// Subscribe to approval events (for tray/notification integration).
    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalEvent> {
        self.event_tx.subscribe()
    }

    /// Submit a new approval request. Returns the created request or an error
    /// if the queue is full (all entries pending).
    pub async fn submit(
        &self,
        input: ApprovalRequestInput,
    ) -> Result<ApprovalRequest, ApprovalError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let ttl_secs = input.ttl_secs.unwrap_or(DEFAULT_TTL_SECS).min(MAX_TTL_SECS);
        let expires_at = compute_expires_at(now, ttl_secs);

        let request = ApprovalRequest {
            id: id.clone(),
            tool: input.tool,
            resource: input.resource,
            guard: input.guard,
            reason: input.reason,
            severity: input.severity,
            session_id: input.session_id,
            created_at: now,
            expires_at,
            status: ApprovalStatus::Pending,
            resolution: None,
            resolved_at: None,
        };

        {
            let mut requests = self.requests.lock().await;
            // Expire stale pending entries before checking capacity.
            let now_expire = Utc::now();
            for request_entry in requests.values_mut() {
                if request_entry.status == ApprovalStatus::Pending
                    && now_expire >= request_entry.expires_at
                {
                    request_entry.status = ApprovalStatus::Expired;
                    request_entry.resolution = Some(ApprovalResolution::Deny);
                    request_entry.resolved_at = Some(now_expire);
                    let _ = self.event_tx.send(ApprovalEvent::Expired {
                        id: request_entry.id.clone(),
                    });
                }
            }

            if let Some(existing) = requests
                .values()
                .find(|existing| is_duplicate_pending(existing, &request))
            {
                return Ok(existing.clone());
            }

            // Evict resolved/expired entries first when at capacity.
            if requests.len() >= MAX_QUEUE_SIZE {
                let to_evict: Vec<String> = requests
                    .iter()
                    .filter(|(_, r)| r.status != ApprovalStatus::Pending)
                    .map(|(id, _)| id.clone())
                    .collect();
                for evict_id in to_evict {
                    requests.remove(&evict_id);
                    if requests.len() < MAX_QUEUE_SIZE {
                        break;
                    }
                }
                // If still at capacity (all entries are pending), reject submission.
                if requests.len() >= MAX_QUEUE_SIZE {
                    return Err(ApprovalError::QueueFull);
                }
            }
            requests.insert(id, request.clone());
        }

        let _ = self.event_tx.send(ApprovalEvent::NewRequest {
            request: ApprovalStatusResponse::from(&request),
        });

        Ok(request)
    }

    /// Get the current status of an approval request. Checks expiry.
    pub async fn get_status(&self, id: &str) -> Option<ApprovalStatusResponse> {
        let mut requests = self.requests.lock().await;

        let request = requests.get_mut(id)?;

        // Check if expired.
        if request.status == ApprovalStatus::Pending && Utc::now() >= request.expires_at {
            request.status = ApprovalStatus::Expired;
            request.resolution = Some(ApprovalResolution::Deny);
            request.resolved_at = Some(Utc::now());

            let _ = self
                .event_tx
                .send(ApprovalEvent::Expired { id: id.to_string() });
        }

        Some(ApprovalStatusResponse::from(&*request))
    }

    /// Resolve an approval request.
    pub async fn resolve(
        &self,
        id: &str,
        resolution: ApprovalResolution,
    ) -> Result<ApprovalStatusResponse, ApprovalError> {
        let mut requests = self.requests.lock().await;

        let request = requests.get_mut(id).ok_or(ApprovalError::NotFound)?;

        // Preserve precise semantics for clients:
        // - Resolved -> 409 (AlreadyResolved)
        // - Expired -> 410 (Expired)
        match request.status {
            ApprovalStatus::Pending => {}
            ApprovalStatus::Resolved => return Err(ApprovalError::AlreadyResolved),
            ApprovalStatus::Expired => return Err(ApprovalError::Expired),
        }

        // Check if expired.
        if Utc::now() >= request.expires_at {
            request.status = ApprovalStatus::Expired;
            request.resolution = Some(ApprovalResolution::Deny);
            request.resolved_at = Some(Utc::now());
            let _ = self
                .event_tx
                .send(ApprovalEvent::Expired { id: id.to_string() });
            return Err(ApprovalError::Expired);
        }

        request.status = ApprovalStatus::Resolved;
        request.resolution = Some(resolution);
        request.resolved_at = Some(Utc::now());

        let response = ApprovalStatusResponse::from(&*request);
        let _ = self.event_tx.send(ApprovalEvent::Resolved {
            request: response.clone(),
        });

        Ok(response)
    }

    /// List all pending approval requests.
    pub async fn list_pending(&self) -> Vec<ApprovalStatusResponse> {
        let mut requests = self.requests.lock().await;
        let now = Utc::now();

        let mut pending = Vec::new();
        for (id, request) in requests.iter_mut() {
            if request.status == ApprovalStatus::Pending {
                if now >= request.expires_at {
                    request.status = ApprovalStatus::Expired;
                    request.resolution = Some(ApprovalResolution::Deny);
                    request.resolved_at = Some(now);
                    let _ = self
                        .event_tx
                        .send(ApprovalEvent::Expired { id: id.clone() });
                } else {
                    pending.push(ApprovalStatusResponse::from(&*request));
                }
            }
        }

        pending
    }

    /// Number of pending approval requests.
    pub async fn pending_count(&self) -> usize {
        let requests = self.requests.lock().await;
        let now = Utc::now();
        requests
            .values()
            .filter(|r| r.status == ApprovalStatus::Pending && now < r.expires_at)
            .count()
    }

    /// Start a background cleanup task that expires old requests.
    pub fn start_cleanup(self: &Arc<Self>, mut shutdown_rx: broadcast::Receiver<()>) {
        let queue = Arc::clone(self);
        tokio::spawn(async move {
            let cleanup_interval = Duration::from_secs(10);
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    _ = tokio::time::sleep(cleanup_interval) => {
                        queue.expire_stale().await;
                    }
                }
            }
        });
    }

    /// Expire stale requests and remove very old resolved ones.
    async fn expire_stale(&self) {
        let mut requests = self.requests.lock().await;
        let now = Utc::now();
        let gc_threshold = now - chrono::Duration::minutes(10);

        let mut to_remove = Vec::new();
        for (id, request) in requests.iter_mut() {
            if request.status == ApprovalStatus::Pending && now >= request.expires_at {
                request.status = ApprovalStatus::Expired;
                request.resolution = Some(ApprovalResolution::Deny);
                request.resolved_at = Some(now);
                let _ = self
                    .event_tx
                    .send(ApprovalEvent::Expired { id: id.clone() });
            }

            // GC resolved/expired requests older than 10 minutes.
            if request.status != ApprovalStatus::Pending {
                if let Some(resolved_at) = request.resolved_at {
                    if resolved_at < gc_threshold {
                        to_remove.push(id.clone());
                    }
                }
            }
        }

        for id in to_remove {
            requests.remove(&id);
        }
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn expires_at_clamps_to_max_on_overflow() {
        let now = DateTime::<Utc>::MAX_UTC;
        let expires_at = compute_expires_at(now, 1);
        assert_eq!(expires_at, DateTime::<Utc>::MAX_UTC);
    }

    #[tokio::test]
    async fn submit_and_get_status() {
        let queue = ApprovalQueue::new();
        let request = queue
            .submit(ApprovalRequestInput {
                tool: "file_write".to_string(),
                resource: "/etc/hosts".to_string(),
                guard: "fs_blocklist".to_string(),
                reason: "Forbidden path".to_string(),
                severity: "high".to_string(),
                session_id: None,
                ttl_secs: Some(60),
            })
            .await
            .unwrap_or_else(|e| panic!("submit failed: {e}"));

        let status = queue.get_status(&request.id).await;
        assert!(status.is_some());
        let status = status.unwrap_or_else(|| panic!("expected status"));
        assert_eq!(status.status, ApprovalStatus::Pending);
        assert!(status.resolution.is_none());
    }

    #[tokio::test]
    async fn resolve_allow_once() {
        let queue = ApprovalQueue::new();
        let request = queue
            .submit(ApprovalRequestInput {
                tool: "file_write".to_string(),
                resource: "/etc/hosts".to_string(),
                guard: "fs_blocklist".to_string(),
                reason: "Forbidden path".to_string(),
                severity: "high".to_string(),
                session_id: None,
                ttl_secs: Some(60),
            })
            .await
            .unwrap_or_else(|e| panic!("submit failed: {e}"));

        let result = queue
            .resolve(&request.id, ApprovalResolution::AllowOnce)
            .await;
        assert!(result.is_ok());
        let resolved = result.unwrap_or_else(|e| panic!("expected ok: {e}"));
        assert_eq!(resolved.status, ApprovalStatus::Resolved);
        assert_eq!(resolved.resolution, Some(ApprovalResolution::AllowOnce));
    }

    #[tokio::test]
    async fn double_resolve_fails() {
        let queue = ApprovalQueue::new();
        let request = queue
            .submit(ApprovalRequestInput {
                tool: "file_write".to_string(),
                resource: "/etc/hosts".to_string(),
                guard: "fs_blocklist".to_string(),
                reason: "Forbidden path".to_string(),
                severity: "high".to_string(),
                session_id: None,
                ttl_secs: Some(60),
            })
            .await
            .unwrap_or_else(|e| panic!("submit failed: {e}"));

        let _ = queue
            .resolve(&request.id, ApprovalResolution::AllowOnce)
            .await;
        let second = queue.resolve(&request.id, ApprovalResolution::Deny).await;
        assert!(second.is_err());
    }

    #[tokio::test]
    async fn expired_request_resolves_as_deny() {
        let queue = ApprovalQueue::new();
        let request = queue
            .submit(ApprovalRequestInput {
                tool: "file_write".to_string(),
                resource: "/etc/hosts".to_string(),
                guard: "fs_blocklist".to_string(),
                reason: "Forbidden path".to_string(),
                severity: "high".to_string(),
                session_id: None,
                ttl_secs: Some(0), // Expires immediately.
            })
            .await
            .unwrap_or_else(|e| panic!("submit failed: {e}"));

        // Give it a moment to be past the expiry.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let status = queue.get_status(&request.id).await;
        assert!(status.is_some());
        let status = status.unwrap_or_else(|| panic!("expected status"));
        assert_eq!(status.status, ApprovalStatus::Expired);
        assert_eq!(status.resolution, Some(ApprovalResolution::Deny));
    }

    #[tokio::test]
    async fn resolve_returns_expired_error_when_request_already_expired() {
        let queue = ApprovalQueue::new();
        let request = queue
            .submit(ApprovalRequestInput {
                tool: "file_write".to_string(),
                resource: "/etc/hosts".to_string(),
                guard: "fs_blocklist".to_string(),
                reason: "Forbidden path".to_string(),
                severity: "high".to_string(),
                session_id: None,
                ttl_secs: Some(0), // Expires immediately.
            })
            .await
            .unwrap_or_else(|e| panic!("submit failed: {e}"));

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Ensure the request transitions to Expired before resolve() runs.
        let _ = queue.get_status(&request.id).await;

        let err = queue
            .resolve(&request.id, ApprovalResolution::AllowOnce)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::Expired),
            "expected Expired error, got: {err}"
        );
    }

    #[tokio::test]
    async fn list_pending_filters_correctly() {
        let queue = ApprovalQueue::new();

        queue
            .submit(ApprovalRequestInput {
                tool: "file_write".to_string(),
                resource: "/a".to_string(),
                guard: "g".to_string(),
                reason: "r".to_string(),
                severity: "high".to_string(),
                session_id: None,
                ttl_secs: Some(60),
            })
            .await
            .unwrap_or_else(|e| panic!("submit failed: {e}"));

        let expired_req = queue
            .submit(ApprovalRequestInput {
                tool: "file_write".to_string(),
                resource: "/b".to_string(),
                guard: "g".to_string(),
                reason: "r".to_string(),
                severity: "high".to_string(),
                session_id: None,
                ttl_secs: Some(0),
            })
            .await
            .unwrap_or_else(|e| panic!("submit failed: {e}"));

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Trigger expiry check on the expired one.
        let _ = queue.get_status(&expired_req.id).await;

        let pending = queue.list_pending().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].resource, "/a");
    }

    #[tokio::test]
    async fn pending_count_accurate() {
        let queue = ApprovalQueue::new();

        queue
            .submit(ApprovalRequestInput {
                tool: "t".to_string(),
                resource: "r".to_string(),
                guard: "g".to_string(),
                reason: "r".to_string(),
                severity: "medium".to_string(),
                session_id: None,
                ttl_secs: Some(60),
            })
            .await
            .unwrap_or_else(|e| panic!("submit failed: {e}"));

        assert_eq!(queue.pending_count().await, 1);
    }

    #[tokio::test]
    async fn submit_coalesces_duplicate_pending_requests() {
        let queue = ApprovalQueue::new();
        let first = queue
            .submit(ApprovalRequestInput {
                tool: "shell.exec".to_string(),
                resource: "cat /etc/passwd".to_string(),
                guard: "shell_guard".to_string(),
                reason: "command denied".to_string(),
                severity: "high".to_string(),
                session_id: Some("sess-1".to_string()),
                ttl_secs: Some(60),
            })
            .await
            .unwrap_or_else(|e| panic!("first submit failed: {e}"));
        let second = queue
            .submit(ApprovalRequestInput {
                tool: "shell.exec".to_string(),
                resource: "cat /etc/passwd".to_string(),
                guard: "shell_guard".to_string(),
                reason: "command denied".to_string(),
                severity: "high".to_string(),
                session_id: Some("sess-1".to_string()),
                ttl_secs: Some(60),
            })
            .await
            .unwrap_or_else(|e| panic!("second submit failed: {e}"));

        assert_eq!(first.id, second.id);
        assert_eq!(queue.pending_count().await, 1);
    }

    #[test]
    fn resolution_serializes_kebab_case() {
        let json = serde_json::to_string(&ApprovalResolution::AllowOnce)
            .unwrap_or_else(|e| panic!("serialize failed: {e}"));
        assert_eq!(json, r#""allow-once""#);

        let json = serde_json::to_string(&ApprovalResolution::AllowSession)
            .unwrap_or_else(|e| panic!("serialize failed: {e}"));
        assert_eq!(json, r#""allow-session""#);
    }

    #[test]
    fn resolution_deserializes_kebab_case() {
        let parsed: ApprovalResolution = serde_json::from_str(r#""allow-always""#)
            .unwrap_or_else(|e| panic!("deserialize failed: {e}"));
        assert_eq!(parsed, ApprovalResolution::AllowAlways);
    }

    #[tokio::test]
    async fn submit_expires_stale_before_capacity_check() {
        let queue = ApprovalQueue::new();

        // Fill up to near capacity with immediately-expiring requests.
        for i in 0..MAX_QUEUE_SIZE {
            queue
                .submit(ApprovalRequestInput {
                    tool: "t".to_string(),
                    resource: format!("/r{}", i),
                    guard: "g".to_string(),
                    reason: "r".to_string(),
                    severity: "high".to_string(),
                    session_id: None,
                    ttl_secs: Some(0), // Expires immediately.
                })
                .await
                .unwrap_or_else(|e| panic!("submit {} failed: {e}", i));
        }

        // Give them time to expire.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should succeed because submit() now expires stale entries first.
        let result = queue
            .submit(ApprovalRequestInput {
                tool: "t".to_string(),
                resource: "/fresh".to_string(),
                guard: "g".to_string(),
                reason: "r".to_string(),
                severity: "medium".to_string(),
                session_id: None,
                ttl_secs: Some(60),
            })
            .await;

        assert!(
            result.is_ok(),
            "submit should succeed after expiring stale entries"
        );
    }
}
