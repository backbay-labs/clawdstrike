#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clawdstrike::{GuardContext, HushEngine, Policy};
use hush_core::sha256;
use tokio::net::TcpListener;

async fn serve(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

#[tokio::test]
async fn virustotal_file_hash_denies_and_caches() {
    let calls = Arc::new(AtomicUsize::new(0));
    let state = calls.clone();

    let content = b"definitely-malicious";
    let hash = sha256(content).to_hex();

    let app = Router::new()
        .route(
            "/api/v3/files/{hash}",
            get(
                |Path(path_hash): Path<String>, State(calls): State<Arc<AtomicUsize>>| async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    if path_hash != hash {
                        return (StatusCode::NOT_FOUND, Json(serde_json::json!({})));
                    }

                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "data": {
                                "attributes": {
                                    "last_analysis_stats": {
                                        "malicious": 3,
                                        "suspicious": 0
                                    }
                                }
                            }
                        })),
                    )
                },
            ),
        )
        .with_state(state);

    let base = serve(app).await;

    std::env::set_var("VT_API_KEY_TEST", "dummy");
    std::env::set_var("VT_BASE_URL_TEST", format!("{}/api/v3", base));

    let yaml = r#"
version: "1.0.0"
name: "ti"
guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: true
      config:
        api_key: "${VT_API_KEY_TEST}"
        base_url: "${VT_BASE_URL_TEST}"
        min_detections: 2
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    let engine = HushEngine::with_policy(policy);

    let ctx = GuardContext::new();
    let r1 = engine
        .check_file_write("/tmp/ok.txt", content, &ctx)
        .await
        .unwrap();
    assert!(!r1.allowed);
    assert_eq!(r1.guard, "clawdstrike-virustotal");

    let r2 = engine
        .check_file_write("/tmp/ok.txt", content, &ctx)
        .await
        .unwrap();
    assert!(!r2.allowed);
    assert_eq!(r2.guard, "clawdstrike-virustotal");

    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn safe_browsing_denies_on_match() {
    let app = Router::new().route(
        "/v4/threatMatches:find",
        post(|| async move {
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "matches": [
                        { "threatType": "MALWARE" }
                    ]
                })),
            )
        }),
    );
    let base = serve(app).await;

    std::env::set_var("GSB_API_KEY_TEST", "dummy");
    std::env::set_var("GSB_CLIENT_ID_TEST", "clawdstrike-test");
    std::env::set_var("GSB_BASE_URL_TEST", format!("{}/v4", base));

    let yaml = r#"
version: "1.0.0"
name: "ti"
guards:
  egress_allowlist:
    allow: ["evil.example"]
    default_action: block
  custom:
    - package: "clawdstrike-safe-browsing"
      enabled: true
      config:
        api_key: "${GSB_API_KEY_TEST}"
        client_id: "${GSB_CLIENT_ID_TEST}"
        base_url: "${GSB_BASE_URL_TEST}"
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    let engine = HushEngine::with_policy(policy);

    let mut ctx = GuardContext::new();
    ctx.metadata = Some(serde_json::json!({
        "policy_event": {
            "network": {
                "url": "https://evil.example/malware"
            }
        }
    }));

    let result = engine
        .check_egress("evil.example", 443, &ctx)
        .await
        .unwrap();
    assert!(!result.allowed);
    assert_eq!(result.guard, "clawdstrike-safe-browsing");
}

#[tokio::test]
async fn snyk_denies_on_upgradable_vulns() {
    let app = Router::new().route(
        "/api/v1/test",
        post(|| async move {
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "vulnerabilities": [
                        { "severity": "high", "isUpgradable": true }
                    ]
                })),
            )
        }),
    );
    let base = serve(app).await;

    std::env::set_var("SNYK_API_TOKEN_TEST", "dummy");
    std::env::set_var("SNYK_ORG_ID_TEST", "org-123");
    std::env::set_var("SNYK_BASE_URL_TEST", format!("{}/api/v1", base));

    let yaml = r#"
version: "1.0.0"
name: "ti"
guards:
  custom:
    - package: "clawdstrike-snyk"
      enabled: true
      config:
        api_token: "${SNYK_API_TOKEN_TEST}"
        org_id: "${SNYK_ORG_ID_TEST}"
        base_url: "${SNYK_BASE_URL_TEST}"
        severity_threshold: high
        fail_on_upgradable: true
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    let engine = HushEngine::with_policy(policy);

    let ctx = GuardContext::new();
    let pkg = br#"{"name":"demo","version":"1.0.0"}"#;
    let result = engine
        .check_file_write("/tmp/package.json", pkg, &ctx)
        .await
        .unwrap();
    assert!(!result.allowed);
    assert_eq!(result.guard, "clawdstrike-snyk");
}
