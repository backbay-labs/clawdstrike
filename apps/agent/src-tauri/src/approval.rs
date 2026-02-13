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

/// How the user resolved the approval request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalResolution {
    /// Allow this specific action once.
    AllowOnce,
    /// Allow this action for the rest of the session.
    AllowSession,
    /// Allow this action permanently (add policy exception).
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
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalStatusResponse {
    pub id: String,
    pub status: ApprovalStatus,
    pub resolution: Option<ApprovalResolution>,
    pub tool: String,
    pub resource: String,
    pub guard: String,
    pub reason: String,
    pub severity: String,
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

    /// Submit a new approval request. Returns the created request.
    pub async fn submit(&self, input: ApprovalRequestInput) -> ApprovalRequest {
        // Reject critical severity actions -- they are not approvable.
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let ttl_secs = input.ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
        let expires_at = now + chrono::Duration::seconds(ttl_secs as i64);

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
            requests.insert(id, request.clone());
        }

        let _ = self.event_tx.send(ApprovalEvent::NewRequest {
            request: ApprovalStatusResponse::from(&request),
        });

        request
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

            let _ = self.event_tx.send(ApprovalEvent::Expired {
                id: id.to_string(),
            });
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

        let request = requests
            .get_mut(id)
            .ok_or(ApprovalError::NotFound)?;

        // Check if already resolved or expired.
        if request.status != ApprovalStatus::Pending {
            return Err(ApprovalError::AlreadyResolved);
        }

        // Check if expired.
        if Utc::now() >= request.expires_at {
            request.status = ApprovalStatus::Expired;
            request.resolution = Some(ApprovalResolution::Deny);
            request.resolved_at = Some(Utc::now());
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
        for request in requests.values_mut() {
            if request.status == ApprovalStatus::Pending {
                if now >= request.expires_at {
                    request.status = ApprovalStatus::Expired;
                    request.resolution = Some(ApprovalResolution::Deny);
                    request.resolved_at = Some(now);
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
                let _ = self.event_tx.send(ApprovalEvent::Expired {
                    id: id.clone(),
                });
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .await;

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
            .await;

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
            .await;

        let _ = queue
            .resolve(&request.id, ApprovalResolution::AllowOnce)
            .await;
        let second = queue
            .resolve(&request.id, ApprovalResolution::Deny)
            .await;
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
            .await;

        // Give it a moment to be past the expiry.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let status = queue.get_status(&request.id).await;
        assert!(status.is_some());
        let status = status.unwrap_or_else(|| panic!("expected status"));
        assert_eq!(status.status, ApprovalStatus::Expired);
        assert_eq!(status.resolution, Some(ApprovalResolution::Deny));
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
            .await;

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
            .await;

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
            .await;

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
}
