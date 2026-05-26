use super::types::{compute_expires_at, MAX_QUEUE_SIZE};
use super::*;
use chrono::{DateTime, Utc};
use std::time::Duration;

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
