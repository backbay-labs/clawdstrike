#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn sample_audit_event(id: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "id": id.into(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event_type": "violation",
        "action_type": "shell",
        "target": "echo test",
        "decision": "blocked",
        "guard": "policy_guard",
        "severity": "high",
        "message": "blocked by policy",
        "session_id": "session-1",
        "agent_id": "agent-1"
    })
}

#[tokio::test]
async fn audit_queue_enqueue_and_len() {
    let queue = AuditQueue::new_test_isolated();
    assert_eq!(queue.len().await, 0);
    queue.enqueue(sample_audit_event("1")).await;
    queue.enqueue(sample_audit_event("2")).await;
    assert_eq!(queue.len().await, 2);
}

#[tokio::test]
async fn audit_queue_assigns_id_when_missing() {
    let queue = AuditQueue::new_test_isolated();
    queue
        .enqueue(serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": "violation",
            "action_type": "shell",
            "target": "echo test",
            "decision": "blocked"
        }))
        .await;
    let guard = queue.queue.lock().await;
    assert_eq!(guard.len(), 1);
    let id = guard[0].get("id").and_then(|value| value.as_str());
    assert!(id.is_some());
    assert!(!id.unwrap_or_default().is_empty());
}

#[tokio::test]
async fn audit_queue_dedupes_duplicate_ids() {
    let queue = AuditQueue::new_test_isolated();
    queue.enqueue(sample_audit_event("dup-1")).await;
    let mut duplicate = sample_audit_event("dup-1");
    duplicate["target"] = serde_json::Value::String("/tmp/file".to_string());
    queue.enqueue(duplicate).await;
    assert_eq!(queue.len().await, 1);
}

#[tokio::test]
async fn audit_queue_caps_at_limit() {
    let queue = AuditQueue::new_test_isolated();
    {
        let mut guard = queue.queue.lock().await;
        for i in 0..MAX_AUDIT_QUEUE_LEN {
            guard.push_back(sample_audit_event(i.to_string()));
        }
    }
    queue.enqueue(sample_audit_event("overflow")).await;
    assert_eq!(queue.len().await, MAX_AUDIT_QUEUE_LEN);
    let guard = queue.queue.lock().await;
    assert_eq!(
        guard
            .front()
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str()),
        Some("1")
    );
    assert_eq!(
        guard
            .back()
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str()),
        Some("overflow")
    );
}

#[tokio::test]
async fn audit_queue_flush_failure_preserves_order_and_requeues_new_events() {
    use axum::{http::StatusCode, routing::post, Json, Router};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::net::TcpListener;
    use tokio::sync::{oneshot, Notify};

    let queue = Arc::new(AuditQueue::new_test_isolated());
    let initial_events = 512usize;

    for i in 0..initial_events {
        queue.enqueue(sample_audit_event(i.to_string())).await;
    }
    assert_eq!(queue.len().await, initial_events);

    let notify = Arc::new(Notify::new());
    let notify_for_handler = notify.clone();

    let (started_tx, started_rx) = oneshot::channel::<()>();
    let started_tx = Arc::new(StdMutex::new(Some(started_tx)));
    let started_tx_for_handler = started_tx.clone();

    let app = Router::new().route(
        "/api/v1/audit/batch",
        post(move || {
            let notify_for_handler = notify_for_handler.clone();
            let started_tx_for_handler = started_tx_for_handler.clone();
            async move {
                if let Some(tx) = started_tx_for_handler.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                // Hold the response so the caller can enqueue new events mid-flush.
                notify_for_handler.notified().await;
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "fail"})),
                )
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let daemon_url = format!("http://{}", addr);

    let queue_for_flush = queue.clone();
    let daemon_url_for_flush = daemon_url.clone();
    let flush_task =
        tokio::spawn(async move { queue_for_flush.flush(&daemon_url_for_flush, None).await });

    // Wait until the server has received the batch request.
    let _ = started_rx.await;

    // Enqueue new events while flush is in-flight.
    for i in initial_events..(initial_events + 5) {
        queue.enqueue(sample_audit_event(i.to_string())).await;
    }

    // Now let the server respond with failure.
    notify.notify_one();

    let res = flush_task.await.unwrap();
    assert!(res.is_err());

    let guard = queue.queue.lock().await;
    assert_eq!(guard.len(), initial_events + 5);

    let ids: Vec<usize> = guard
        .iter()
        .map(|v| {
            v.get("id")
                .and_then(|x| x.as_str())
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap()
        })
        .collect();

    assert_eq!(ids.first().copied(), Some(0usize));
    // Newest should be preserved.
    assert_eq!(ids.last().copied(), Some(initial_events + 4));

    // Queue must preserve chronological order (strictly increasing IDs).
    for w in ids.windows(2) {
        assert!(w[0] < w[1]);
    }
}

#[tokio::test]
async fn audit_queue_flush_chunks_large_batches() {
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::net::TcpListener;

    #[derive(Clone)]
    struct BatchState {
        sizes: Arc<StdMutex<Vec<usize>>>,
    }

    let queue = AuditQueue::new_test_isolated();
    let total_events = MAX_AUDIT_BATCH_LEN + 37;
    {
        let mut guard = queue.queue.lock().await;
        for i in 0..total_events {
            guard.push_back(sample_audit_event(format!("evt-{i}")));
        }
        persist_audit_queue(&queue.path, &guard).unwrap();
    }

    let state = BatchState {
        sizes: Arc::new(StdMutex::new(Vec::new())),
    };
    let sizes = state.sizes.clone();
    let app =
        Router::new()
            .route(
                "/api/v1/audit/batch",
                post(
                    |State(state): State<BatchState>,
                     Json(payload): Json<serde_json::Value>| async move {
                        let len = payload
                            .get("events")
                            .and_then(|events| events.as_array())
                            .map(|events| events.len())
                            .unwrap_or(0);
                        state.sizes.lock().unwrap().push(len);
                        Json(serde_json::json!({
                            "accepted": len,
                            "duplicates": 0,
                            "rejected": 0
                        }))
                    },
                ),
            )
            .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let flushed = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .unwrap();
    assert_eq!(flushed.accepted, total_events);
    assert_eq!(flushed.rejected, 0);
    assert_eq!(queue.len().await, 0);
    assert_eq!(&*sizes.lock().unwrap(), &[MAX_AUDIT_BATCH_LEN, 37]);
}

#[tokio::test]
async fn audit_queue_flush_does_not_count_duplicates_as_new_uploads() {
    use axum::{routing::post, Json, Router};
    use tokio::net::TcpListener;

    let queue = AuditQueue::new_test_isolated();
    queue.enqueue(sample_audit_event("dup-1")).await;
    queue.enqueue(sample_audit_event("dup-2")).await;

    let app = Router::new().route(
        "/api/v1/audit/batch",
        post(|| async {
            Json(serde_json::json!({
                "accepted": 0,
                "duplicates": 2,
                "rejected": 0
            }))
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let flushed = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .unwrap();
    assert_eq!(flushed.accepted, 0);
    assert_eq!(flushed.duplicates, 2);
    assert_eq!(queue.len().await, 0);
}

#[tokio::test]
async fn audit_queue_flush_persists_empty_outbox_after_acceptance() {
    use axum::{routing::post, Json, Router};
    use tokio::net::TcpListener;

    let queue = AuditQueue::new_test_isolated();
    queue.enqueue(sample_audit_event("evt-1")).await;
    queue.enqueue(sample_audit_event("evt-2")).await;

    let app = Router::new().route(
        "/api/v1/audit/batch",
        post(|| async {
            Json(serde_json::json!({
                "accepted": 2,
                "duplicates": 0,
                "rejected": 0,
                "accepted_ids": ["evt-1", "evt-2"]
            }))
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let flushed = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .unwrap();
    assert_eq!(flushed.accepted, 2);
    assert_eq!(queue.len().await, 0);

    let persisted: PersistedAuditQueue =
        serde_json::from_slice(&std::fs::read(&queue.path).unwrap()).unwrap();
    assert!(persisted.entries.is_empty());

    let _ = std::fs::remove_file(&queue.path);
}

#[tokio::test]
async fn audit_queue_flush_keeps_batch_persisted_until_daemon_acknowledges() {
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::Arc;
    use tokio::{net::TcpListener, sync::Notify};

    #[derive(Clone)]
    struct FlushGate {
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    let queue = Arc::new(AuditQueue::new_test_isolated());
    queue.enqueue(sample_audit_event("evt-1")).await;
    queue.enqueue(sample_audit_event("evt-2")).await;

    let gate = FlushGate {
        started: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
    };

    let app = Router::new()
        .route(
            "/api/v1/audit/batch",
            post(|State(gate): State<FlushGate>| async move {
                gate.started.notify_one();
                gate.release.notified().await;
                Json(serde_json::json!({
                    "accepted": 2,
                    "duplicates": 0,
                    "rejected": 0,
                    "accepted_ids": ["evt-1", "evt-2"]
                }))
            }),
        )
        .with_state(gate.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let queue_for_flush = Arc::clone(&queue);
    let flush_task = tokio::spawn(async move {
        queue_for_flush
            .flush(&format!("http://{}", addr), None)
            .await
    });

    gate.started.notified().await;

    let persisted: PersistedAuditQueue =
        serde_json::from_slice(&std::fs::read(&queue.path).unwrap()).unwrap();
    let ids: Vec<_> = persisted
        .entries
        .iter()
        .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
        .collect();
    assert_eq!(ids, vec!["evt-1", "evt-2"]);

    gate.release.notify_one();

    let flushed = flush_task.await.unwrap().unwrap();
    assert_eq!(flushed.accepted, 2);

    let persisted: PersistedAuditQueue =
        serde_json::from_slice(&std::fs::read(&queue.path).unwrap()).unwrap();
    assert!(persisted.entries.is_empty());

    let _ = std::fs::remove_file(&queue.path);
}

#[tokio::test]
async fn audit_queue_flush_requeues_batch_when_response_body_is_invalid() {
    use axum::{routing::post, Router};
    use tokio::net::TcpListener;

    let queue = AuditQueue::new_test_isolated();
    queue.enqueue(sample_audit_event("evt-1")).await;
    queue.enqueue(sample_audit_event("evt-2")).await;

    let app = Router::new().route("/api/v1/audit/batch", post(|| async { "not-json" }));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let err = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .expect_err("invalid response bodies must requeue the batch");
    assert!(err
        .to_string()
        .contains("Failed to parse audit batch response"));

    let guard = queue.queue.lock().await;
    let ids: Vec<_> = guard
        .iter()
        .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
        .collect();
    assert_eq!(ids, vec!["evt-1", "evt-2"]);
}

#[tokio::test]
async fn audit_queue_flush_requeues_partially_rejected_batches() {
    use axum::{routing::post, Json, Router};
    use tokio::net::TcpListener;

    let queue = AuditQueue::new_test_isolated();
    queue.enqueue(sample_audit_event("evt-1")).await;
    queue.enqueue(sample_audit_event("evt-2")).await;
    queue.enqueue(sample_audit_event("evt-3")).await;

    let app = Router::new().route(
        "/api/v1/audit/batch",
        post(|| async {
            Json(serde_json::json!({
                "accepted": 2,
                "duplicates": 0,
                "rejected": 1,
                "accepted_ids": ["evt-1", "evt-2"],
                "rejected_ids": ["evt-3"]
            }))
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let outcome = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .expect("complete rejected_ids should return a partial flush outcome");
    assert_eq!(outcome.accepted, 2);
    assert_eq!(outcome.rejected, 1);
    assert!(outcome.partial_rejection);

    let guard = queue.queue.lock().await;
    let ids: Vec<_> = guard
        .iter()
        .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
        .collect();
    assert_eq!(ids, vec!["evt-3"]);
}

#[tokio::test]
async fn audit_queue_flush_requeues_full_batch_when_rejected_ids_are_missing() {
    use axum::{routing::post, Json, Router};
    use tokio::net::TcpListener;

    let queue = AuditQueue::new_test_isolated();
    queue.enqueue(sample_audit_event("evt-1")).await;
    queue.enqueue(sample_audit_event("evt-2")).await;
    queue.enqueue(sample_audit_event("evt-3")).await;

    let app = Router::new().route(
        "/api/v1/audit/batch",
        post(|| async {
            Json(serde_json::json!({
                "accepted": 2,
                "duplicates": 0,
                "rejected": 1
            }))
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let err = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .expect_err("partial rejection should fail the flush");
    assert!(err
        .to_string()
        .contains("Audit batch upload partially rejected"));
    assert!(err
        .to_string()
        .contains("after previously flushing 0 accepted events"));

    let guard = queue.queue.lock().await;
    let ids: Vec<_> = guard
        .iter()
        .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
        .collect();
    assert_eq!(ids, vec!["evt-1", "evt-2", "evt-3"]);
}

#[tokio::test]
async fn audit_queue_flush_reports_prior_accepted_count_on_later_batch_rejection() {
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::net::TcpListener;

    #[derive(Clone)]
    struct BatchState {
        calls: Arc<StdMutex<usize>>,
    }

    let queue = AuditQueue::new_test_isolated();
    let total_events = MAX_AUDIT_BATCH_LEN + 2;
    {
        let mut guard = queue.queue.lock().await;
        for i in 0..total_events {
            guard.push_back(sample_audit_event(format!("evt-{i}")));
        }
        persist_audit_queue(&queue.path, &guard).unwrap();
    }

    let state = BatchState {
        calls: Arc::new(StdMutex::new(0)),
    };
    let app =
        Router::new()
            .route(
                "/api/v1/audit/batch",
                post(
                    |State(state): State<BatchState>,
                     Json(payload): Json<serde_json::Value>| async move {
                        let len = payload
                            .get("events")
                            .and_then(|events| events.as_array())
                            .map(|events| events.len())
                            .unwrap_or(0);
                        let mut calls = state.calls.lock().unwrap();
                        *calls += 1;
                        if *calls == 1 {
                            Json(serde_json::json!({
                                "accepted": len,
                                "duplicates": 0,
                                "rejected": 0
                            }))
                        } else {
                            Json(serde_json::json!({
                                "accepted": 1,
                                "duplicates": 0,
                                "rejected": 1,
                                "accepted_ids": [format!("evt-{}", MAX_AUDIT_BATCH_LEN)],
                                "rejected_ids": [format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)]
                            }))
                        }
                    },
                ),
            )
            .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let outcome = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .expect("later partial rejection should still report prior accepted batches");
    assert_eq!(outcome.accepted, MAX_AUDIT_BATCH_LEN + 1);
    assert_eq!(outcome.rejected, 1);
    assert!(outcome.partial_rejection);

    let guard = queue.queue.lock().await;
    let ids: Vec<String> = guard
        .iter()
        .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
        .map(ToString::to_string)
        .collect();
    assert_eq!(ids, vec![format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)]);
}

#[tokio::test]
async fn audit_queue_flush_reports_prior_progress_when_rejected_ids_are_incomplete() {
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::net::TcpListener;

    #[derive(Clone)]
    struct BatchState {
        calls: Arc<StdMutex<usize>>,
    }

    let queue = AuditQueue::new_test_isolated();
    let total_events = MAX_AUDIT_BATCH_LEN + 2;
    {
        let mut guard = queue.queue.lock().await;
        for i in 0..total_events {
            guard.push_back(sample_audit_event(format!("evt-{i}")));
        }
        persist_audit_queue(&queue.path, &guard).unwrap();
    }

    let state = BatchState {
        calls: Arc::new(StdMutex::new(0)),
    };
    let app =
        Router::new()
            .route(
                "/api/v1/audit/batch",
                post(
                    |State(state): State<BatchState>,
                     Json(payload): Json<serde_json::Value>| async move {
                        let len = payload
                            .get("events")
                            .and_then(|events| events.as_array())
                            .map(|events| events.len())
                            .unwrap_or(0);
                        let mut calls = state.calls.lock().unwrap();
                        *calls += 1;
                        if *calls == 1 {
                            Json(serde_json::json!({
                                "accepted": len,
                                "duplicates": 0,
                                "rejected": 0
                            }))
                        } else {
                            Json(serde_json::json!({
                                "accepted": 1,
                                "duplicates": 0,
                                "rejected": 1
                            }))
                        }
                    },
                ),
            )
            .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let err = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .expect_err("incomplete rejected_ids should preserve prior flush progress");
    let progress = err
        .downcast_ref::<AuditFlushProgressError>()
        .expect("incomplete rejected_ids should return a structured progress error");
    assert_eq!(progress.outcome.accepted, MAX_AUDIT_BATCH_LEN);
    assert_eq!(progress.outcome.duplicates, 0);
    assert_eq!(progress.outcome.rejected, 0);
    assert!(progress
        .message
        .contains("Audit batch upload partially rejected"));

    let guard = queue.queue.lock().await;
    let ids: Vec<String> = guard
        .iter()
        .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        ids,
        vec![
            format!("evt-{}", MAX_AUDIT_BATCH_LEN),
            format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)
        ]
    );
}

#[tokio::test]
async fn audit_queue_flush_reports_prior_accepted_count_on_later_http_failure() {
    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::net::TcpListener;

    #[derive(Clone)]
    struct BatchState {
        calls: Arc<StdMutex<usize>>,
    }

    let queue = AuditQueue::new_test_isolated();
    let total_events = MAX_AUDIT_BATCH_LEN + 2;
    {
        let mut guard = queue.queue.lock().await;
        for i in 0..total_events {
            guard.push_back(sample_audit_event(format!("evt-{i}")));
        }
        persist_audit_queue(&queue.path, &guard).unwrap();
    }

    let state = BatchState {
        calls: Arc::new(StdMutex::new(0)),
    };
    let app =
        Router::new()
            .route(
                "/api/v1/audit/batch",
                post(
                    |State(state): State<BatchState>,
                     Json(payload): Json<serde_json::Value>| async move {
                        let len = payload
                            .get("events")
                            .and_then(|events| events.as_array())
                            .map(|events| events.len())
                            .unwrap_or(0);
                        let mut calls = state.calls.lock().unwrap();
                        *calls += 1;
                        if *calls == 1 {
                            Ok::<_, StatusCode>(Json(serde_json::json!({
                                "accepted": len,
                                "duplicates": 0,
                                "rejected": 0
                            })))
                        } else {
                            Err(StatusCode::INTERNAL_SERVER_ERROR)
                        }
                    },
                ),
            )
            .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let err = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .expect_err("later HTTP failure should preserve prior accepted counts");
    let progress = err
        .downcast_ref::<AuditFlushProgressError>()
        .expect("later HTTP failure should preserve flush progress");
    assert_eq!(progress.outcome.accepted, MAX_AUDIT_BATCH_LEN);
    assert_eq!(progress.outcome.duplicates, 0);
    assert_eq!(progress.outcome.rejected, 0);
    assert!(progress
        .message
        .contains("Audit batch upload returned 500 Internal Server Error"));

    let guard = queue.queue.lock().await;
    let ids: Vec<String> = guard
        .iter()
        .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        ids,
        vec![
            format!("evt-{}", MAX_AUDIT_BATCH_LEN),
            format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)
        ]
    );
}

#[tokio::test]
async fn audit_queue_flush_reports_prior_accepted_count_on_later_parse_failure() {
    use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::net::TcpListener;

    #[derive(Clone)]
    struct BatchState {
        calls: Arc<StdMutex<usize>>,
    }

    let queue = AuditQueue::new_test_isolated();
    let total_events = MAX_AUDIT_BATCH_LEN + 2;
    {
        let mut guard = queue.queue.lock().await;
        for i in 0..total_events {
            guard.push_back(sample_audit_event(format!("evt-{i}")));
        }
        persist_audit_queue(&queue.path, &guard).unwrap();
    }

    let state = BatchState {
        calls: Arc::new(StdMutex::new(0)),
    };
    let app =
        Router::new()
            .route(
                "/api/v1/audit/batch",
                post(
                    |State(state): State<BatchState>,
                     Json(payload): Json<serde_json::Value>| async move {
                        let len = payload
                            .get("events")
                            .and_then(|events| events.as_array())
                            .map(|events| events.len())
                            .unwrap_or(0);
                        let mut calls = state.calls.lock().unwrap();
                        *calls += 1;
                        if *calls == 1 {
                            Json(serde_json::json!({
                                "accepted": len,
                                "duplicates": 0,
                                "rejected": 0
                            }))
                            .into_response()
                        } else {
                            "not-json".into_response()
                        }
                    },
                ),
            )
            .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let err = queue
        .flush(&format!("http://{}", addr), None)
        .await
        .expect_err("later parse failure should preserve prior accepted counts");
    let progress = err
        .downcast_ref::<AuditFlushProgressError>()
        .expect("later parse failure should preserve flush progress");
    assert_eq!(progress.outcome.accepted, MAX_AUDIT_BATCH_LEN);
    assert_eq!(progress.outcome.duplicates, 0);
    assert_eq!(progress.outcome.rejected, 0);
    assert!(progress
        .message
        .contains("Failed to parse audit batch response"));

    let guard = queue.queue.lock().await;
    let ids: Vec<String> = guard
        .iter()
        .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        ids,
        vec![
            format!("evt-{}", MAX_AUDIT_BATCH_LEN),
            format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)
        ]
    );
}

#[tokio::test]
async fn audit_queue_load_drops_invalid_persisted_entries() {
    use std::collections::VecDeque;

    let dir = std::env::temp_dir().join(format!(
        "clawdstrike-audit-outbox-load-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit-outbox.json");
    let persisted = PersistedAuditQueue {
        entries: VecDeque::from([
            serde_json::json!({"id": 1}),
            sample_audit_event("valid-1"),
            serde_json::json!({"id": "missing-fields"}),
            sample_audit_event("valid-2"),
        ]),
    };
    std::fs::write(&path, serde_json::to_vec(&persisted).unwrap()).unwrap();

    let queue = AuditQueue::with_path(path.clone());
    let guard = queue.queue.lock().await;
    assert_eq!(guard.len(), 2);
    assert_eq!(
        guard
            .iter()
            .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
            .collect::<Vec<_>>(),
        vec!["valid-1", "valid-2"]
    );
    drop(guard);

    let persisted_after: PersistedAuditQueue =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted_after.entries.len(), 2);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}
