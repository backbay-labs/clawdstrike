# Wave B Council — Reviewer 1 (hushd + control-api)

**HEAD:** 9f668a7c63aa06f93625481778c993f1dfe2a658
**Verdict:** CONCUR

## Check 1: hushd auth default = true

**Default impl evidence:** `crates/services/hushd/src/config.rs:109-111` — `fn default_auth_enabled() -> bool { true }`. The `Default` impl at line 113-120 uses `enabled: default_auth_enabled()` (line 116). The serde attribute `#[serde(default = "default_auth_enabled")]` at line 102 also flips on-load to `true` when the field is absent. Sanity-pinned by the in-crate unit test `test_auth_config_default` at line 1711: `assert!(config.auth.enabled);`.

**Middleware enforcement evidence:** `crates/services/hushd/src/auth/middleware.rs:50-58` — `require_auth` first calls `if !state.auth_enabled() { return Ok(next.run(req).await); }`. When `auth.enabled = true`, control falls through to `extract_bearer_token(&req).ok_or(StatusCode::UNAUTHORIZED)?` at line 61 (missing token => 401), then OIDC JWT validation (lines 63-77) and API-key store validation (lines 80-83) — both return `StatusCode::UNAUTHORIZED` on failure. The mirror middleware `require_auth_v1` in `crates/services/hushd/src/api/certification.rs:54-92` enforces the same path with V1 error envelopes.

**Test executed:** `auth::middleware::tests::default_auth_config_rejects_request_with_no_bearer_token` — PASS (`cargo test -p hushd default_auth_config_rejects_request_with_no_bearer_token`, 1 passed, 0 failed, 0.07s). Test constructs `Config { ..Default::default() }`, asserts `config.auth.enabled`, builds an axum `Router` wrapped in `require_auth`, sends a request with no Authorization header, and asserts response status is `UNAUTHORIZED` (lines 233-266).

**Bypass scan:** PASS — no bypass found. `grep -rn "!state.auth_enabled" crates/services/hushd/src/` returns three hits, all of the form `if !state.auth_enabled() { allow }` (middleware.rs:56, certification.rs:60, certification.rs:100). When `auth_enabled = true`, every path falls through to `extract_bearer_token` → `validate_key` (fail-closed). Session resolver at `crates/services/hushd/src/api/session.rs:134` uses pattern `None if !auth_enabled => Ok(local_service_principal(...))`; when auth is on, the `None` arm at line 135 returns `UNAUTHENTICATED`. WebSocket presence handler at `crates/services/hushd/src/api/presence.rs:515` enforces ticket-based auth when `auth_enabled` is true. No `if !enabled || some_bypass` pattern exists.

**Verdict:** PASS

## Check 2: control-api defaults

**Bind addr default evidence:** `crates/services/control-api/src/config.rs:51-53` — `listen_addr: "127.0.0.1:8080".parse().expect("static default listen addr")`. The `from_env` loader at line 108-110 also uses `"127.0.0.1:8080"` as the fallback when `LISTEN_ADDR` is unset. Parent commit (069963245^) had `0.0.0.0:8080` in both spots, confirmed by `git show 069963245^:crates/services/control-api/src/config.rs`.

**CORS default evidence:** `crates/services/control-api/src/config.rs:54` — `cors_allowed_origins: Vec::new()` in the `Default` impl. `crates/services/control-api/src/main.rs:308-327` — the new CORS builder. Lines 309-314: when allowlist empty, the layer is constructed via `AllowOrigin::list(std::iter::empty::<axum::http::HeaderValue>())` — a *zero-origin* list, NOT `CorsLayer::permissive()`. The `permissive()` call is removed and replaced with `CorsLayer::new().allow_origin(origin_layer)` at line 326. A warning is emitted on startup when the allowlist is empty (lines 310-313).

**Test executed:** `config::tests::default_config_binds_localhost_with_empty_cors_allowlist` — PASS (`cargo test -p clawdstrike-control-api default_config_binds_localhost_with_empty_cors_allowlist`, 1 passed, 0 failed). Test asserts `config.listen_addr.to_string() == "127.0.0.1:8080"` and `config.cors_allowed_origins.is_empty()` (config.rs:807-814).

**Opt-in CORS path works:** PASS — `config::tests::from_env_parses_cors_allowed_origins_csv` (config.rs:817-838) was also executed and passed (`cargo test -p clawdstrike-control-api from_env_parses_cors_allowed_origins_csv`, 1 passed, 0 failed). It sets `CORS_ALLOWED_ORIGINS=https://a.example, https://b.example`, calls `Config::from_env()`, and asserts both origins land in `config.cors_allowed_origins`. The wiring in main.rs (lines 318-324) maps non-empty/non-wildcard allowlists to `AllowOrigin::list(origins)`, and the `*` wildcard maps to `AllowOrigin::any()` at line 317 (with comment explaining the tower-http panic on `*` in `list`).

**Verdict:** PASS

## Check 3: Commit accuracy

**b6a7d3be6:** PASS — matches subject "feat(hushd): enable auth by default (security)". `git show --stat` shows 4 files: `config.rs` flips `default_auth_enabled` to return true and updates `test_auth_config_default` from `assert!(!config.auth.enabled)` to `assert!(config.auth.enabled)`; `auth/middleware.rs` adds the 35-line `default_auth_config_rejects_request_with_no_bearer_token` test; `tests/common/mod.rs` and `api/presence.rs` set `auth.enabled = false` in test scaffolding that exercises non-auth code paths (explicitly called out in the commit body). All four files match the stated intent.

**069963245:** PASS — matches subject "feat(control-api): bind localhost + named CORS allowlist by default (security)". `git show --stat` shows 3 files: `config.rs` adds `cors_allowed_origins: Vec<String>` field, the `Default` impl (101 new lines), the env parser for `CORS_ALLOWED_ORIGINS`, the two new tests (default + CSV opt-in), and flips both `Default` and `from_env` listen_addr from `0.0.0.0:8080` to `127.0.0.1:8080`; `main.rs` replaces `CorsLayer::permissive()` with the empty-by-default builder; `integration_tests.rs` adds `cors_allowed_origins: Vec::new()` to the inline `Config` literals (3 hits). All three files match the stated intent.

## DISSENT log (if any)
None.

## Final verdict
CONCUR
