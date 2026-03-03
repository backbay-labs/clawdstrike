//! HTTP API for the package registry.

pub mod attestation;
pub mod audit;
pub mod checkpoint;
pub mod consistency;
pub mod download;
pub mod health;
pub mod index;
pub mod info;
pub mod org;
pub mod proof;
pub mod publish;
pub mod search;
pub mod stats;
pub mod trusted_publishers;
pub mod yank;

use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::auth::require_publish_auth;
use crate::state::AppState;

/// Create the top-level router for the registry.
pub fn create_router(state: AppState) -> Router {
    let max_upload = state.config.max_upload_bytes;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes (no auth required).
    let public_routes = Router::new()
        .route("/health", get(health::health))
        .route("/api/v1/packages/{name}", get(info::package_info))
        .route("/api/v1/packages/{name}/{version}", get(info::version_info))
        .route(
            "/api/v1/packages/{name}/{version}/download",
            get(download::download),
        )
        .route("/api/v1/search", get(search::search))
        .route("/api/v1/index/{name}", get(index::sparse_index))
        .route(
            "/api/v1/packages/{name}/{version}/attestation",
            get(attestation::get_attestation),
        )
        .route(
            "/api/v1/packages/{name}/{version}/proof",
            get(proof::get_proof),
        )
        .route(
            "/api/v1/transparency/checkpoint",
            get(checkpoint::get_checkpoint),
        )
        .route(
            "/api/v1/transparency/consistency",
            get(consistency::get_consistency_proof),
        )
        .route("/api/v1/audit/{name}", get(audit::get_audit))
        // Download statistics endpoints.
        .route(
            "/api/v1/packages/{name}/stats",
            get(stats::get_package_stats),
        )
        .route("/api/v1/popular", get(stats::get_popular))
        // Trusted publisher listing (public).
        .route(
            "/api/v1/packages/{name}/trusted-publishers",
            get(trusted_publishers::list_trusted_publishers),
        )
        // Organization public endpoints.
        .route("/api/v1/orgs/{name}", get(org::get_org))
        .route("/api/v1/orgs/{name}/packages", get(org::list_org_packages));

    // Authenticated routes (publish, yank, org management).
    let auth_routes = Router::new()
        .route("/api/v1/packages", post(publish::publish))
        .route("/api/v1/packages/{name}/{version}", delete(yank::yank))
        .route("/api/v1/orgs", post(org::create_org))
        .route(
            "/api/v1/orgs/{name}/members",
            get(org::list_members).post(org::invite_member),
        )
        .route(
            "/api/v1/orgs/{name}/members/{key}",
            delete(org::remove_member),
        )
        // Trusted publisher management (auth required).
        .route(
            "/api/v1/packages/{name}/trusted-publishers",
            post(trusted_publishers::add_trusted_publisher),
        )
        .route(
            "/api/v1/packages/{name}/trusted-publishers/{id}",
            delete(trusted_publishers::remove_trusted_publisher),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_publish_auth,
        ));

    Router::new()
        .merge(public_routes)
        .merge(auth_routes)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(max_upload))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::RegistryKeyManager;
    use axum::extract::{Path, Query, State};
    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use axum::Json;
    use base64::Engine as _;
    use hush_core::Keypair;

    fn test_state() -> (AppState, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = crate::config::Config {
            host: "127.0.0.1".to_string(),
            port: 0,
            data_dir: tmp.path().to_path_buf(),
            api_key: String::new(),
            allow_insecure_no_auth: false,
            max_upload_bytes: 5 * 1024 * 1024,
        };
        let state = crate::state::AppState::new(cfg).unwrap();
        (state, tmp)
    }

    fn signed_headers(kp: &Keypair, payload: &str) -> HeaderMap {
        let ts = chrono::Utc::now().to_rfc3339();
        let msg = crate::auth::caller_signature_message(payload, &ts);
        let sig = kp.sign(msg.as_bytes()).to_hex();
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Clawdstrike-Caller-Key",
            kp.public_key().to_hex().parse().unwrap(),
        );
        headers.insert("X-Clawdstrike-Caller-Sig", sig.parse().unwrap());
        headers.insert("X-Clawdstrike-Caller-Ts", ts.parse().unwrap());
        headers
    }

    fn publish_request(
        name: &str,
        version: &str,
        kp: &Keypair,
    ) -> (publish::PublishRequest, Vec<u8>) {
        let archive_bytes = build_cpkg_bytes(name, version);
        let hash = hush_core::sha256(&archive_bytes);
        let sig = kp.sign(hash.as_bytes()).to_hex();
        let manifest_toml = format!(
            "[package]\nname = \"{name}\"\nversion = \"{version}\"\npkg_type = \"guard\"\n\n[trust]\nlevel = \"trusted\"\nsandbox = \"native\"\n"
        );
        let req = publish::PublishRequest {
            archive_base64: base64::engine::general_purpose::STANDARD.encode(&archive_bytes),
            publisher_key: kp.public_key().to_hex(),
            publisher_sig: sig,
            manifest_toml,
        };
        (req, archive_bytes)
    }

    fn build_cpkg_bytes(name: &str, version: &str) -> Vec<u8> {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        let manifest_toml = format!(
            "[package]\nname = \"{name}\"\nversion = \"{version}\"\npkg_type = \"guard\"\n\n[trust]\nlevel = \"trusted\"\nsandbox = \"native\"\n"
        );
        std::fs::write(src.join("clawdstrike-pkg.toml"), manifest_toml).unwrap();
        std::fs::write(src.join("README.md"), "test package").unwrap();
        let archive = tmp.path().join("pkg.cpkg");
        clawdstrike::pkg::archive::pack(&src, &archive).unwrap();
        std::fs::read(&archive).unwrap()
    }

    async fn create_org_owned_by(state: AppState, org_name: &str, owner: &Keypair) {
        let owner_key = owner.public_key().to_hex();
        let payload = format!("org:create:{org_name}:{owner_key}:{org_name}");
        let _created = org::create_org(
            State(state),
            signed_headers(owner, &payload),
            Json(org::CreateOrgRequest {
                name: org_name.to_string(),
                display_name: Some(org_name.to_string()),
                publisher_key: owner_key,
            }),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn api_end_to_end_handlers_cover_core_paths() {
        let (state, _tmp) = test_state();
        let _router = create_router(state.clone());

        let health = health::health().await;
        assert_eq!(health.0.status, "ok");

        let owner = Keypair::from_seed(&[11u8; 32]);
        let owner_key = owner.public_key().to_hex();
        let scoped_pkg = "@acme/demo-guard";
        let version = "1.2.3";
        let create_payload = format!("org:create:acme:{}:ACME", owner_key);

        let _ = org::create_org(
            State(state.clone()),
            signed_headers(&owner, &create_payload),
            Json(org::CreateOrgRequest {
                name: "acme".to_string(),
                display_name: Some("ACME".to_string()),
                publisher_key: owner_key.clone(),
            }),
        )
        .await
        .unwrap();

        let member = Keypair::from_seed(&[12u8; 32]);
        let member_key = member.public_key().to_hex();
        let invite_payload = format!("org:invite:acme:{member_key}:member");
        let _ = org::invite_member(
            State(state.clone()),
            Path("acme".to_string()),
            signed_headers(&owner, &invite_payload),
            Json(org::InviteMemberRequest {
                publisher_key: member_key.clone(),
                role: "member".to_string(),
            }),
        )
        .await
        .unwrap();

        let remove_payload = format!("org:remove:acme:{member_key}");
        let remove_status = org::remove_member(
            State(state.clone()),
            Path(("acme".to_string(), member_key.clone())),
            signed_headers(&owner, &remove_payload),
        )
        .await
        .unwrap();
        assert_eq!(remove_status, StatusCode::NO_CONTENT);

        let (publish_req, archive_bytes) = publish_request(scoped_pkg, version, &owner);
        let publish_resp =
            publish::publish(State(state.clone()), HeaderMap::new(), Json(publish_req))
                .await
                .unwrap();
        assert_eq!(publish_resp.0.name, scoped_pkg);

        let pkg_info = info::package_info(State(state.clone()), Path(scoped_pkg.to_string()))
            .await
            .unwrap();
        assert_eq!(pkg_info.0.name, scoped_pkg);
        assert_eq!(pkg_info.0.versions.len(), 1);

        let version_info = info::version_info(
            State(state.clone()),
            Path((scoped_pkg.to_string(), version.to_string())),
        )
        .await
        .unwrap();
        assert_eq!(version_info.0.version, version);

        let search = search::search(
            State(state.clone()),
            Query(search::SearchQuery {
                q: "demo".to_string(),
                limit: 20,
                offset: 0,
            }),
        )
        .await
        .unwrap();
        assert!(search.0.total >= 1);

        let att = attestation::get_attestation(
            State(state.clone()),
            Path((scoped_pkg.to_string(), version.to_string())),
        )
        .await
        .unwrap();
        assert!(att.0.registry_key.is_some());

        let proof = proof::get_proof(
            State(state.clone()),
            Path((scoped_pkg.to_string(), version.to_string())),
        )
        .await
        .unwrap();
        assert_eq!(proof.0.tree_size, 1);
        assert!(!proof.0.root.is_empty());
        assert!(!proof.0.checkpoint_sig.is_empty());

        let download_resp = download::download(
            State(state.clone()),
            Path((scoped_pkg.to_string(), version.to_string())),
        )
        .await
        .unwrap();
        assert_eq!(download_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(download_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], &archive_bytes);

        let stats = stats::get_package_stats(State(state.clone()), Path(scoped_pkg.to_string()))
            .await
            .unwrap();
        assert_eq!(stats.0.name, scoped_pkg);
        assert!(stats.0.total_downloads >= 1);

        let popular = stats::get_popular(
            State(state.clone()),
            Query(stats::PopularQuery { limit: Some(10) }),
        )
        .await
        .unwrap();
        assert!(!popular.0.is_empty());

        let index_resp = index::sparse_index(
            State(state.clone()),
            Path(scoped_pkg.to_string()),
            HeaderMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(index_resp.status(), StatusCode::OK);
        let etag = index_resp
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();

        let mut cond_headers = HeaderMap::new();
        cond_headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&etag).unwrap());
        let not_modified = index::sparse_index(
            State(state.clone()),
            Path(scoped_pkg.to_string()),
            cond_headers,
        )
        .await
        .unwrap();
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

        let add_tp_payload = trusted_publishers::add_trusted_publisher_signed_payload(
            scoped_pkg,
            "github",
            "acme/repo",
            None,
            None,
        );
        let (created, tp) = trusted_publishers::add_trusted_publisher(
            State(state.clone()),
            Path(scoped_pkg.to_string()),
            signed_headers(&owner, &add_tp_payload),
            Json(trusted_publishers::AddTrustedPublisherRequest {
                provider: "github".to_string(),
                repository: "acme/repo".to_string(),
                workflow: None,
                environment: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(created, StatusCode::CREATED);

        let listed = trusted_publishers::list_trusted_publishers(
            State(state.clone()),
            Path(scoped_pkg.to_string()),
        )
        .await
        .unwrap();
        assert_eq!(listed.0.trusted_publishers.len(), 1);

        let del_tp_payload = format!("trusted-publisher:remove:{scoped_pkg}:{}", tp.0.id);
        let deleted = trusted_publishers::remove_trusted_publisher(
            State(state.clone()),
            Path((scoped_pkg.to_string(), tp.0.id)),
            signed_headers(&owner, &del_tp_payload),
        )
        .await
        .unwrap();
        assert_eq!(deleted, StatusCode::NO_CONTENT);

        let yanked = yank::yank(
            State(state.clone()),
            Path((scoped_pkg.to_string(), version.to_string())),
            signed_headers(&owner, &format!("yank:{scoped_pkg}:{version}")),
        )
        .await
        .unwrap();
        assert!(yanked.0.yanked);
    }

    #[tokio::test]
    async fn proof_uses_publish_time_registry_key_after_rotation() {
        let (state, _tmp) = test_state();
        let publisher = Keypair::from_seed(&[90u8; 32]);
        let package = "proof-key-test";
        let version = "1.0.0";

        let (req, _archive) = publish_request(package, version, &publisher);
        let _published = publish::publish(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .unwrap();

        let att = attestation::get_attestation(
            State(state.clone()),
            Path((package.to_string(), version.to_string())),
        )
        .await
        .unwrap();
        let publish_time_key = att.0.registry_key.clone().unwrap();

        let rotated = Keypair::from_seed(&[91u8; 32]);
        let rotated_key = rotated.public_key().to_hex();
        {
            let mut key_mgr = state.key_manager.lock().unwrap();
            key_mgr.rotate(rotated, 30).unwrap();
        }

        let proof = proof::get_proof(
            State(state.clone()),
            Path((package.to_string(), version.to_string())),
        )
        .await
        .unwrap();

        assert_ne!(publish_time_key, rotated_key);
        assert_eq!(proof.0.checkpoint_key, publish_time_key);
    }

    #[tokio::test]
    async fn proof_falls_back_to_active_key_when_historical_private_key_is_missing() {
        let (mut state, _tmp) = test_state();
        let publisher = Keypair::from_seed(&[92u8; 32]);
        let package = "proof-key-fallback-test";
        let version = "1.0.0";

        let (req, _archive) = publish_request(package, version, &publisher);
        let _published = publish::publish(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .unwrap();

        let att = attestation::get_attestation(
            State(state.clone()),
            Path((package.to_string(), version.to_string())),
        )
        .await
        .unwrap();
        let publish_time_key = att.0.registry_key.clone().unwrap();

        let rotated = Keypair::from_seed(&[93u8; 32]);
        let rotated_key = rotated.public_key().to_hex();

        {
            let mut key_mgr = state.key_manager.lock().unwrap();
            key_mgr.rotate(rotated.clone(), 30).unwrap();
        }

        // Simulate restart behavior where only the active key is restored.
        state.key_manager = std::sync::Arc::new(std::sync::Mutex::new(RegistryKeyManager::new(
            rotated.clone(),
        )));
        state.registry_keypair = std::sync::Arc::new(rotated);

        let proof = proof::get_proof(
            State(state.clone()),
            Path((package.to_string(), version.to_string())),
        )
        .await
        .unwrap();

        assert_ne!(publish_time_key, rotated_key);
        assert_eq!(proof.0.checkpoint_key, rotated_key);
    }

    #[tokio::test]
    async fn publish_rejects_manifest_mismatch_between_body_and_archive() {
        let (state, _tmp) = test_state();
        let publisher = Keypair::from_seed(&[31u8; 32]);
        let archive_bytes = build_cpkg_bytes("demo", "1.0.0");
        let hash = hush_core::sha256(&archive_bytes);
        let req = publish::PublishRequest {
            archive_base64: base64::engine::general_purpose::STANDARD.encode(&archive_bytes),
            publisher_key: publisher.public_key().to_hex(),
            publisher_sig: publisher.sign(hash.as_bytes()).to_hex(),
            manifest_toml:
                "[package]\nname = \"demo\"\nversion = \"9.9.9\"\npkg_type = \"guard\"\n"
                    .to_string(),
        };

        let err = publish::publish(State(state), HeaderMap::new(), Json(req))
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("request manifest does not match embedded archive manifest"));
    }

    #[tokio::test]
    async fn create_org_requires_signed_caller_key_match() {
        let (state, _tmp) = test_state();
        let caller = Keypair::from_seed(&[32u8; 32]);
        let other = Keypair::from_seed(&[33u8; 32]);
        let payload = format!("org:create:acme:{}:{}", other.public_key().to_hex(), "ACME");

        let err = org::create_org(
            State(state),
            signed_headers(&caller, &payload),
            Json(org::CreateOrgRequest {
                name: "acme".to_string(),
                display_name: Some("ACME".to_string()),
                publisher_key: other.public_key().to_hex(),
            }),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("must match create_org.publisher_key"));
    }

    #[tokio::test]
    async fn create_org_rejects_malformed_publisher_key_without_possession() {
        let (state, _tmp) = test_state();
        let caller = Keypair::from_seed(&[36u8; 32]);
        let malformed_key = "not-a-valid-ed25519-key";
        let payload = format!("org:create:acme:{malformed_key}:ACME");

        let err = org::create_org(
            State(state),
            signed_headers(&caller, &payload),
            Json(org::CreateOrgRequest {
                name: "acme".to_string(),
                display_name: Some("ACME".to_string()),
                publisher_key: malformed_key.to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("must match create_org.publisher_key"));
    }

    #[tokio::test]
    async fn unscoped_trusted_publisher_requires_package_publisher() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[34u8; 32]);
        let stranger = Keypair::from_seed(&[35u8; 32]);
        let package = "unscoped-guard";
        let version = "1.0.0";

        let (req, _bytes) = publish_request(package, version, &owner);
        let _published = publish::publish(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .unwrap();

        let add_payload = trusted_publishers::add_trusted_publisher_signed_payload(
            package,
            "github",
            "acme/repo",
            None,
            None,
        );
        let err = trusted_publishers::add_trusted_publisher(
            State(state.clone()),
            Path(package.to_string()),
            signed_headers(&stranger, &add_payload),
            Json(trusted_publishers::AddTrustedPublisherRequest {
                provider: "github".to_string(),
                repository: "acme/repo".to_string(),
                workflow: None,
                environment: None,
            }),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not authorized"));
    }

    #[tokio::test]
    async fn unscoped_trusted_publisher_allows_bootstrap_before_first_publish() {
        let (state, _tmp) = test_state();
        let caller = Keypair::from_seed(&[60u8; 32]);
        let package = "brand-new-unscoped";
        let add_payload = trusted_publishers::add_trusted_publisher_signed_payload(
            package,
            "github",
            "acme/repo",
            None,
            None,
        );

        let (status, created) = trusted_publishers::add_trusted_publisher(
            State(state.clone()),
            Path(package.to_string()),
            signed_headers(&caller, &add_payload),
            Json(trusted_publishers::AddTrustedPublisherRequest {
                provider: "github".to_string(),
                repository: "acme/repo".to_string(),
                workflow: None,
                environment: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created.0.package_name, package);
        assert_eq!(created.0.created_by, caller.public_key().to_hex());
    }

    #[tokio::test]
    async fn unscoped_trusted_publisher_remove_requires_package_publisher() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[37u8; 32]);
        let stranger = Keypair::from_seed(&[38u8; 32]);
        let package = "unscoped-guard";
        let version = "1.0.0";

        let (req, _bytes) = publish_request(package, version, &owner);
        let _published = publish::publish(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .unwrap();

        let add_payload = trusted_publishers::add_trusted_publisher_signed_payload(
            package,
            "github",
            "acme/repo",
            None,
            None,
        );
        let (created_status, created) = trusted_publishers::add_trusted_publisher(
            State(state.clone()),
            Path(package.to_string()),
            signed_headers(&owner, &add_payload),
            Json(trusted_publishers::AddTrustedPublisherRequest {
                provider: "github".to_string(),
                repository: "acme/repo".to_string(),
                workflow: None,
                environment: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(created_status, StatusCode::CREATED);

        let remove_payload = format!("trusted-publisher:remove:{package}:{}", created.0.id);
        let err = trusted_publishers::remove_trusted_publisher(
            State(state),
            Path((package.to_string(), created.0.id)),
            signed_headers(&stranger, &remove_payload),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not authorized"));
    }

    #[tokio::test]
    async fn yank_unscoped_requires_package_publisher() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[61u8; 32]);
        let stranger = Keypair::from_seed(&[62u8; 32]);
        let package = "yankable-unscoped";
        let version = "1.0.0";

        let (req, _bytes) = publish_request(package, version, &owner);
        let _published = publish::publish(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .unwrap();

        let payload = format!("yank:{package}:{version}");
        let err = yank::yank(
            State(state),
            Path((package.to_string(), version.to_string())),
            signed_headers(&stranger, &payload),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("not authorized"));
    }

    #[tokio::test]
    async fn create_org_rejects_empty_name() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[39u8; 32]);
        let owner_key = owner.public_key().to_hex();
        let payload = format!("org:create::{owner_key}:");

        let err = org::create_org(
            State(state),
            signed_headers(&owner, &payload),
            Json(org::CreateOrgRequest {
                name: "".to_string(),
                display_name: None,
                publisher_key: owner_key,
            }),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("organization name must match [a-z0-9]"));
    }

    #[tokio::test]
    async fn create_org_rejects_invalid_name_characters() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[40u8; 32]);
        let owner_key = owner.public_key().to_hex();
        let payload = format!("org:create:acme invalid:{owner_key}:ACME");

        let err = org::create_org(
            State(state),
            signed_headers(&owner, &payload),
            Json(org::CreateOrgRequest {
                name: "acme invalid".to_string(),
                display_name: Some("ACME".to_string()),
                publisher_key: owner_key,
            }),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("organization name must match [a-z0-9]"));
    }

    #[tokio::test]
    async fn create_org_rejects_scope_incompatible_name() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[52u8; 32]);
        let owner_key = owner.public_key().to_hex();
        let payload = format!("org:create:Acme_Team:{owner_key}:Acme Team");

        let err = org::create_org(
            State(state),
            signed_headers(&owner, &payload),
            Json(org::CreateOrgRequest {
                name: "Acme_Team".to_string(),
                display_name: Some("Acme Team".to_string()),
                publisher_key: owner_key,
            }),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("organization name must match [a-z0-9]"));
    }

    #[tokio::test]
    async fn list_members_returns_not_found_for_unknown_org() {
        let (state, _tmp) = test_state();
        let err = match org::list_members(State(state), Path("missing-org".to_string())).await {
            Ok(_) => panic!("expected missing org to return not found"),
            Err(e) => e,
        };
        assert!(err
            .to_string()
            .contains("organization 'missing-org' not found"));
    }

    #[tokio::test]
    async fn list_org_packages_returns_not_found_for_unknown_org() {
        let (state, _tmp) = test_state();
        let err = match org::list_org_packages(State(state), Path("missing-org".to_string())).await
        {
            Ok(_) => panic!("expected missing org to return not found"),
            Err(e) => e,
        };
        assert!(err
            .to_string()
            .contains("organization 'missing-org' not found"));
    }

    #[tokio::test]
    async fn invite_member_rejects_invalid_role() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[41u8; 32]);
        create_org_owned_by(state.clone(), "acme", &owner).await;

        let owner_key = owner.public_key().to_hex();
        let payload = format!("org:invite:acme:{owner_key}:admin");
        let err = org::invite_member(
            State(state),
            Path("acme".to_string()),
            signed_headers(&owner, &payload),
            Json(org::InviteMemberRequest {
                publisher_key: owner_key,
                role: "admin".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("invalid role 'admin'"));
    }

    #[tokio::test]
    async fn invite_member_requires_caller_membership() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[42u8; 32]);
        let stranger = Keypair::from_seed(&[43u8; 32]);
        let invitee = Keypair::from_seed(&[44u8; 32]);
        create_org_owned_by(state.clone(), "acme", &owner).await;

        let invitee_key = invitee.public_key().to_hex();
        let payload = format!("org:invite:acme:{invitee_key}:member");
        let err = org::invite_member(
            State(state),
            Path("acme".to_string()),
            signed_headers(&stranger, &payload),
            Json(org::InviteMemberRequest {
                publisher_key: invitee_key,
                role: "member".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("caller is not a member of @acme"));
    }

    #[tokio::test]
    async fn maintainer_cannot_remove_owner() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[45u8; 32]);
        let maintainer = Keypair::from_seed(&[46u8; 32]);
        create_org_owned_by(state.clone(), "acme", &owner).await;

        let maintainer_key = maintainer.public_key().to_hex();
        let invite_payload = format!("org:invite:acme:{maintainer_key}:maintainer");
        let created = org::invite_member(
            State(state.clone()),
            Path("acme".to_string()),
            signed_headers(&owner, &invite_payload),
            Json(org::InviteMemberRequest {
                publisher_key: maintainer_key,
                role: "maintainer".to_string(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(created.0, StatusCode::CREATED);

        let owner_key = owner.public_key().to_hex();
        let remove_payload = format!("org:remove:acme:{owner_key}");
        let err = org::remove_member(
            State(state),
            Path(("acme".to_string(), owner_key)),
            signed_headers(&maintainer, &remove_payload),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("maintainers cannot remove organization owners"));
    }

    #[tokio::test]
    async fn maintainer_cannot_invite_owner() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[53u8; 32]);
        let maintainer = Keypair::from_seed(&[54u8; 32]);
        let promoted = Keypair::from_seed(&[55u8; 32]);
        create_org_owned_by(state.clone(), "acme", &owner).await;

        let maintainer_key = maintainer.public_key().to_hex();
        let invite_maintainer_payload = format!("org:invite:acme:{maintainer_key}:maintainer");
        let _ = org::invite_member(
            State(state.clone()),
            Path("acme".to_string()),
            signed_headers(&owner, &invite_maintainer_payload),
            Json(org::InviteMemberRequest {
                publisher_key: maintainer_key,
                role: "maintainer".to_string(),
            }),
        )
        .await
        .unwrap();

        let promoted_key = promoted.public_key().to_hex();
        let promote_payload = format!("org:invite:acme:{promoted_key}:owner");
        let err = org::invite_member(
            State(state),
            Path("acme".to_string()),
            signed_headers(&maintainer, &promote_payload),
            Json(org::InviteMemberRequest {
                publisher_key: promoted_key,
                role: "owner".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("maintainers cannot promote members to owner"));
    }

    #[tokio::test]
    async fn publish_rejects_invalid_base64_archive() {
        let (state, _tmp) = test_state();
        let req = publish::PublishRequest {
            archive_base64: "not-base64!!!".to_string(),
            publisher_key: "deadbeef".to_string(),
            publisher_sig: "deadbeef".to_string(),
            manifest_toml:
                "[package]\nname = \"demo\"\nversion = \"1.0.0\"\npkg_type = \"guard\"\n"
                    .to_string(),
        };

        let err = publish::publish(State(state), HeaderMap::new(), Json(req))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid base64 archive"));
    }

    #[tokio::test]
    async fn publish_rejects_non_archive_payload_bytes() {
        let (state, _tmp) = test_state();
        let publisher = Keypair::from_seed(&[47u8; 32]);
        let archive_bytes = b"this-is-not-a-cpkg-archive".to_vec();
        let hash = hush_core::sha256(&archive_bytes);
        let req = publish::PublishRequest {
            archive_base64: base64::engine::general_purpose::STANDARD.encode(&archive_bytes),
            publisher_key: publisher.public_key().to_hex(),
            publisher_sig: publisher.sign(hash.as_bytes()).to_hex(),
            manifest_toml:
                "[package]\nname = \"demo\"\nversion = \"1.0.0\"\npkg_type = \"guard\"\n"
                    .to_string(),
        };

        let err = publish::publish(State(state), HeaderMap::new(), Json(req))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid .cpkg archive payload"));
    }

    #[tokio::test]
    async fn publish_rejects_invalid_publisher_key_hex() {
        let (state, _tmp) = test_state();
        let publisher = Keypair::from_seed(&[48u8; 32]);
        let (mut req, _bytes) = publish_request("demo", "1.0.0", &publisher);
        req.publisher_key = "not-hex".to_string();

        let err = publish::publish(State(state), HeaderMap::new(), Json(req))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid publisher key"));
    }

    #[tokio::test]
    async fn publish_rejects_invalid_publisher_signature_hex() {
        let (state, _tmp) = test_state();
        let publisher = Keypair::from_seed(&[49u8; 32]);
        let (mut req, _bytes) = publish_request("demo", "1.0.0", &publisher);
        req.publisher_sig = "not-hex".to_string();

        let err = publish::publish(State(state), HeaderMap::new(), Json(req))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid publisher signature"));
    }

    #[tokio::test]
    async fn publish_rejects_incorrect_publisher_signature() {
        let (state, _tmp) = test_state();
        let publisher = Keypair::from_seed(&[50u8; 32]);
        let (mut req, _bytes) = publish_request("demo", "1.0.0", &publisher);
        let wrong_hash = hush_core::sha256(b"not-the-archive");
        req.publisher_sig = publisher.sign(wrong_hash.as_bytes()).to_hex();

        let err = publish::publish(State(state), HeaderMap::new(), Json(req))
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("publisher signature verification failed"));
    }

    #[tokio::test]
    async fn publish_scoped_package_requires_existing_org_scope() {
        let (state, _tmp) = test_state();
        let publisher = Keypair::from_seed(&[51u8; 32]);
        let (req, _bytes) = publish_request("@missing/demo", "1.0.0", &publisher);

        let err = publish::publish(State(state), HeaderMap::new(), Json(req))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("organization 'missing' not found"));
    }

    #[tokio::test]
    async fn publish_unscoped_existing_package_requires_existing_publisher() {
        let (state, _tmp) = test_state();
        let owner = Keypair::from_seed(&[52u8; 32]);
        let attacker = Keypair::from_seed(&[53u8; 32]);

        let (first_req, _bytes) = publish_request("demo", "1.0.0", &owner);
        let first = publish::publish(State(state.clone()), HeaderMap::new(), Json(first_req))
            .await
            .unwrap();
        assert_eq!(first.0.name, "demo");
        assert_eq!(first.0.version, "1.0.0");

        let (second_req, _bytes) = publish_request("demo", "1.1.0", &attacker);
        let err = publish::publish(State(state), HeaderMap::new(), Json(second_req))
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("caller is not authorized to administer unscoped package 'demo'"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_publishes_assign_unique_leaf_indices() {
        let (state, _tmp) = test_state();
        let publisher = Keypair::from_seed(&[54u8; 32]);

        let (req_a, _bytes_a) = publish_request("pkg-a", "1.0.0", &publisher);
        let (req_b, _bytes_b) = publish_request("pkg-b", "1.0.0", &publisher);

        let task_a = {
            let state = state.clone();
            tokio::spawn(async move {
                publish::publish(State(state), HeaderMap::new(), Json(req_a)).await
            })
        };
        let task_b = {
            let state = state.clone();
            tokio::spawn(async move {
                publish::publish(State(state), HeaderMap::new(), Json(req_b)).await
            })
        };

        let res_a = task_a.await.unwrap().unwrap();
        let res_b = task_b.await.unwrap().unwrap();
        assert_eq!(res_a.0.version, "1.0.0");
        assert_eq!(res_b.0.version, "1.0.0");

        let db = state.db.lock().unwrap();
        let row_a = db.get_version("pkg-a", "1.0.0").unwrap().unwrap();
        let row_b = db.get_version("pkg-b", "1.0.0").unwrap().unwrap();
        let mut indices = vec![row_a.leaf_index.unwrap(), row_b.leaf_index.unwrap()];
        indices.sort_unstable();
        assert_eq!(indices, vec![0, 1]);
        drop(db);

        let tree_size = state.merkle_tree.lock().unwrap().tree_size();
        assert_eq!(tree_size, 2);
    }

    #[tokio::test]
    async fn search_total_reports_full_match_count_with_pagination() {
        let (state, _tmp) = test_state();
        {
            let db = state.db.lock().unwrap();
            db.upsert_package("secret-a", Some("secret scanner"), "2025-01-01T00:00:00Z")
                .unwrap();
            db.upsert_package("secret-b", Some("secret scanner"), "2025-01-02T00:00:00Z")
                .unwrap();
            db.upsert_package("secret-c", Some("secret scanner"), "2025-01-03T00:00:00Z")
                .unwrap();
        }

        let page = search::search(
            State(state),
            Query(search::SearchQuery {
                q: "secret".to_string(),
                limit: 1,
                offset: 1,
            }),
        )
        .await
        .unwrap();

        assert_eq!(page.0.packages.len(), 1);
        assert_eq!(page.0.total, 3);
    }
}
