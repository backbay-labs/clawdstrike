//! Approval queue: in-memory store, submission, resolution, and lifecycle.

use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;

use super::types::{
    compute_expires_at, is_duplicate_pending, ApprovalError, ApprovalEvent, ApprovalRequest,
    ApprovalRequestInput, ApprovalResolution, ApprovalStatus, ApprovalStatusResponse,
    DEFAULT_TTL_SECS, MAX_QUEUE_SIZE, MAX_TTL_SECS,
};

/// Manages the in-memory approval queue.
pub struct ApprovalQueue {
    requests: Mutex<HashMap<String, ApprovalRequest>>,
    event_tx: broadcast::Sender<ApprovalEvent>,
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
            resolved_by_trusted_authority: false,
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

    /// Consume a resolved one-shot approval. Session and always approvals remain reusable.
    pub async fn consume_allow_once(&self, id: &str) -> Result<bool, ApprovalError> {
        let mut requests = self.requests.lock().await;
        let should_remove = {
            let request = requests.get_mut(id).ok_or(ApprovalError::NotFound)?;

            if request.status == ApprovalStatus::Pending && Utc::now() >= request.expires_at {
                request.status = ApprovalStatus::Expired;
                request.resolution = Some(ApprovalResolution::Deny);
                request.resolved_at = Some(Utc::now());
                let _ = self
                    .event_tx
                    .send(ApprovalEvent::Expired { id: id.to_string() });
                return Err(ApprovalError::Expired);
            }

            if request.status != ApprovalStatus::Resolved {
                return Ok(false);
            }
            request.resolution == Some(ApprovalResolution::AllowOnce)
        };
        if should_remove {
            requests.remove(id);
            return Ok(true);
        }
        Ok(false)
    }

    /// Resolve an approval request.
    pub async fn resolve(
        &self,
        id: &str,
        resolution: ApprovalResolution,
    ) -> Result<ApprovalStatusResponse, ApprovalError> {
        self.resolve_with_trust(id, resolution, true).await
    }

    /// Resolve an approval request through the local API. These resolutions are
    /// intentionally not trusted for gates that require an independent operator
    /// or signed-control-plane decision.
    pub async fn resolve_local_api(
        &self,
        id: &str,
        resolution: ApprovalResolution,
    ) -> Result<ApprovalStatusResponse, ApprovalError> {
        self.resolve_with_trust(id, resolution, false).await
    }

    async fn resolve_with_trust(
        &self,
        id: &str,
        resolution: ApprovalResolution,
        resolved_by_trusted_authority: bool,
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
        request.resolved_by_trusted_authority = resolved_by_trusted_authority;

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
