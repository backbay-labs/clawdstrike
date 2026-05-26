#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::manager::SessionManager;
use super::state::SessionState;
use anyhow::Result;
use axum::{
    extract::Path,
    http::StatusCode,
    routing::{delete, post},
    Json, Router,
};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

#[test]
fn session_state_default_summary() {
    let state = SessionState::default();
    assert_eq!(state.summary(), "Session: inactive");
}

#[test]
fn session_state_active_summary() {
    let state = SessionState {
        session_id: Some("sess-123".to_string()),
        posture: "restricted".to_string(),
        budget_used: 45,
        budget_limit: 100,
    };
    assert_eq!(
        state.summary(),
        "Session: active | Posture: restricted | Budget: 45/100"
    );
}

#[test]
fn session_state_active_without_budget() {
    let state = SessionState {
        session_id: Some("sess-123".to_string()),
        posture: "standard".to_string(),
        budget_used: 0,
        budget_limit: 0,
    };
    assert_eq!(state.summary(), "Session: active | Posture: standard");
}

#[tokio::test]
async fn session_manager_initial_state() {
    let manager = SessionManager::new();
    let state = manager.state().await;
    assert!(state.session_id.is_none());
    assert_eq!(state.posture, "unknown");
}

#[tokio::test]
async fn update_posture_from_daemon_event_updates_current_session() {
    let manager = SessionManager::new();

    {
        let mut state = manager.state.write().await;
        state.session_id = Some("sess-123".to_string());
        state.posture = "restricted".to_string();
    }

    let applied = manager
        .update_posture_from_daemon_event(Some("sess-123"), "standard".to_string())
        .await;
    assert!(applied);

    let state = manager.state().await;
    assert_eq!(state.posture, "standard");

    let applied = manager
        .update_posture_from_daemon_event(Some("sess-other"), "restricted".to_string())
        .await;
    assert!(!applied);

    let state = manager.state().await;
    assert_eq!(state.posture, "standard");

    let applied = manager
        .update_posture_from_daemon_event(None, "restricted".to_string())
        .await;
    assert!(applied);

    let state = manager.state().await;
    assert_eq!(state.posture, "restricted");
}

#[tokio::test]
async fn heartbeat_does_not_clear_new_session_state() {
    let manager = SessionManager::new();

    {
        let mut state = manager.state.write().await;
        state.session_id = Some("old".to_string());
        state.posture = "restricted".to_string();
    }

    // If the session has been replaced since the heartbeat started, the CAS should fail.
    {
        let mut state = manager.state.write().await;
        state.session_id = Some("new".to_string());
        state.posture = "standard".to_string();
    }

    let cleared = manager
        .with_state_if_current_session_id("old", |state| {
            *state = SessionState::default();
        })
        .await;
    assert!(cleared.is_none());

    let state = manager.state().await;
    assert_eq!(state.session_id.as_deref(), Some("new"));
    assert_eq!(state.posture, "standard");
}

async fn start_test_server(
    post_behavior: impl Fn() -> Result<String, StatusCode> + Send + Sync + 'static,
    events: Arc<StdMutex<Vec<String>>>,
) -> String {
    let post_behavior = Arc::new(post_behavior);
    let events_post = events.clone();
    let events_delete = events.clone();
    let events_transition = events.clone();
    let app = Router::new()
        .route(
            "/api/v1/session",
            post({
                let post_behavior = post_behavior.clone();
                move || async move {
                    match post_behavior() {
                        Ok(session_id) => {
                            events_post
                                .lock()
                                .unwrap()
                                .push(format!("post:{}", session_id));
                            (
                                StatusCode::OK,
                                Json(
                                    serde_json::json!({ "session": { "session_id": session_id } }),
                                ),
                            )
                        }
                        Err(code) => (code, Json(serde_json::json!({ "error": "fail" }))),
                    }
                }
            }),
        )
        .route(
            "/api/v1/session/{id}",
            delete({
                move |Path(id): Path<String>| async move {
                    events_delete.lock().unwrap().push(format!("delete:{}", id));
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .route(
            "/api/v1/session/{id}/transition",
            post({
                move |Path(id): Path<String>, Json(body): Json<serde_json::Value>| async move {
                    let to_state = body
                        .get("to_state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let trigger = body
                        .get("trigger")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    events_transition
                        .lock()
                        .unwrap()
                        .push(format!("transition:{}:{}:{}", id, to_state, trigger));
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "success": true,
                            "from_state": "standard",
                            "to_state": to_state,
                        })),
                    )
                }
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

#[tokio::test]
async fn create_session_terminates_existing_before_replacement() {
    let events: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let daemon_url = start_test_server(
        {
            let counter = counter.clone();
            move || {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                Ok(format!("sess-{}", n))
            }
        },
        events.clone(),
    )
    .await;

    let manager = SessionManager::new();
    let s1 = manager.create_session(&daemon_url, None).await.unwrap();
    assert_eq!(s1, "sess-1");

    let s2 = manager.create_session(&daemon_url, None).await.unwrap();
    assert_eq!(s2, "sess-2");

    let got = events.lock().unwrap().clone();
    assert_eq!(
        got,
        vec![
            "post:sess-1".to_string(),
            "delete:sess-1".to_string(),
            "post:sess-2".to_string(),
        ]
    );
}

#[tokio::test]
async fn ensure_session_retries_until_success() {
    let events: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let daemon_url = start_test_server(
        {
            let attempts = attempts.clone();
            move || {
                let n = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if n <= 2 {
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
                Ok("sess-ok".to_string())
            }
        },
        events.clone(),
    )
    .await;

    let manager = Arc::new(SessionManager::new());
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    manager.start_ensure_session(daemon_url, None, shutdown_rx);

    let sid = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(sid) = manager.session_id().await {
                return sid;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("timed out waiting for session");
    assert_eq!(sid, "sess-ok");

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn transition_current_session_posture_updates_state_via_hushd_api() {
    let events: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
    let daemon_url = start_test_server(|| Ok("sess-1".to_string()), events.clone()).await;

    let manager = SessionManager::new();
    manager.create_session(&daemon_url, None).await.unwrap();

    let transitioned = manager
        .transition_current_session_posture(&daemon_url, None, "locked", "user_denial")
        .await
        .unwrap();
    assert!(transitioned);

    let state = manager.state().await;
    assert_eq!(state.posture, "locked");

    let got = events.lock().unwrap().clone();
    assert!(got.contains(&"post:sess-1".to_string()));
    assert!(got.contains(&"transition:sess-1:locked:user_denial".to_string()));
}

#[tokio::test]
async fn transition_current_session_posture_without_session_returns_false() {
    let manager = SessionManager::new();
    let transitioned = manager
        .transition_current_session_posture("http://127.0.0.1:9", None, "locked", "user_denial")
        .await
        .unwrap();
    assert!(!transitioned);
}
