# Rust Services & Bridges Audit

**Date:** 2026-05-23
**Scope:** `crates/services/` (clawdstrike-brokerd, clawdstrike-registry, control-api, eas-anchor, hush-cli, hushd, spine-cli) and `crates/bridges/` (auditd-bridge, darwin-telemetry-bridge, hubble-bridge, hush-go-native, k8s-audit-bridge, tetragon-bridge)
**Verdict:** Mixed. The bridges and broker daemon are genuinely solid. The big daemons (`hushd`, `control-api`) read like a series of sedimentary feature drops that never went back and got refactored. One service (`eas-anchor`) is a stub pretending to be a service. The CLI (`hush-cli`) is a god-binary that needs to be cracked open. A senior platform engineer would respect about half of this and be embarrassed by the other half.

## Executive Summary

There is real engineering taste in this tree — but it is not evenly applied. Hushd and Control-API show consistent use of `axum` middleware, structured tracing (`#[serde(deny_unknown_fields)]` everywhere, scope-based RBAC layering, a `TlsListener` abstraction, JWT + API-key dual auth, NATS JetStream consumers with shutdown channels). The brokerd is the cleanest single binary in the repo: constant-time auth check, explicit `ApiError` discriminated by code+status+message, fail-closed config validation that rejects empty trusted-key sets, and a 17-line `main.rs` that just builds state and serves. The bridge family (Tetragon/Hubble/auditd/k8s-audit/darwin-telemetry) all share a `bridge_runtime` crate with a shared admin server, outbox worker, and metrics — that is the right call.

What spoils this picture: `hush-cli/src/main.rs` is **3,238 lines** of declared command shapes plus a 1,500-line `run()` dispatcher. `control-api/src/main.rs` is **336 lines** that hand-roll seven independent broadcast/watch channels for shutdown coordination and spawn six `tokio::spawn` workers inline. `control-api/src/integration_tests.rs` is **11,377 lines** of test code wedged into `src/` instead of `tests/`, with manual `#[path = …]` remounts. `hushd` ships with three crypto stacks (`ring` directly + `rustls/ring` + `openssl` + `rust-xmlsec`) and rasterizes SVG certification badges in-process via `resvg`. The five bridge mains duplicate the same ~200-line clap + reconnect loop verbatim. The `eas-anchor` service's whole reason to exist (`submit_batch`/`revoke_attestation`) returns `Err(Error::Client("Chain submission not yet implemented"))`.

The most serious operational defect is the security posture of the defaults. `hushd`'s `AuthConfig.enabled` defaults to `false` via `#[serde(default)]` — meaning a vanilla config file boots the daemon with **all** API key auth bypassed. `clawdstrike-brokerd`'s admin-token check is also bypassed when `admin_token` is `None`. `control-api` defaults `LISTEN_ADDR` to `0.0.0.0:8080` and slaps `CorsLayer::permissive()` on every response. `clawdstrike-registry` defaults to `0.0.0.0:3100` with an empty `api_key` permitted. None of these are "elite Rust security tool" defaults — they are demo defaults shipped to production paths.

Persistence is also a recurring smell: `clawdstrike-brokerd::OperatorState` (capabilities, executions, revocations, freezes) lives entirely in an in-memory `RwLock<BTreeMap>`. `hushd`'s `BrokerStateStore` and `InMemoryRevocationStore` are the same story. A restart silently loses the entire capability ledger that this product is built around. Webhook delivery in `hushd::certification_webhooks` is `tokio::spawn`-and-forget with no outbox — inflight webhooks are dropped on SIGTERM. `clawdstrike-audit-monitor` (a transparency-log monitor) uses `eprintln!` everywhere, has no `tracing` setup, no signal handling, and persists state via untyped JSON file I/O.

## Service-by-service inventory

| Service                     | Role                                                              | Maturity                                  | LOC (src) |
| --------------------------- | ----------------------------------------------------------------- | ----------------------------------------- | --------- |
| `hushd`                     | Central enforcement daemon: policy, broker, RBAC, SIEM, swarm hub | **beta** — feature-rich, default-insecure | ~38,065   |
| `clawdstrike-brokerd`       | Local sidecar: capability validation, secret injection            | **production-ready** modulo persistence   | ~5,570    |
| `control-api`               | Multi-tenant control plane (Postgres + NATS)                      | **beta** — many TODOs, broad surface      | ~42,672   |
| `clawdstrike-registry`      | Package registry + transparency log                               | **beta** — sound crypto, weak operations  | ~8,815    |
| `hush-cli`                  | Primary CLI (`clawdstrike`, `hush`)                               | **beta** — god-binary, needs decomposing  | ~34,164   |
| `spine-cli`                 | Spine protocol operator CLI                                       | **beta** — clean shape, missing logging   | ~1,044    |
| `eas-anchor`                | Ethereum Attestation Service batcher                              | **experimental / stub**                   | ~1,124    |
| `tetragon-bridge`           | Tetragon gRPC → NATS Spine envelopes                              | **production-ready**                      | ~1,167    |
| `hubble-bridge`             | Cilium Hubble gRPC → NATS                                         | **production-ready**                      | ~1,163    |
| `auditd-bridge`             | Linux auditd → NATS                                               | **production-ready**                      | ~1,811    |
| `k8s-audit-bridge`          | Kubernetes audit webhook → NATS                                   | **production-ready**                      | ~1,262    |
| `darwin-telemetry-bridge`   | macOS FSEvents/unified log → NATS                                 | **production-ready**                      | ~3,205    |
| `hush-go-native`            | C ABI for Go bindings                                             | **beta**                                  | ~875      |

## Scores (1-10)

- **Service quality:**          6/10 — bridges are 8, brokerd is 8, hushd is 5, hush-cli is 4, eas-anchor is 1
- **Operational readiness:**    5/10 — graceful shutdown is inconsistent, persistence is missing where it must exist
- **API design:**               6/10 — axum router composition is good, but route-files are gigantic and there is no OpenAPI surface generation
- **Error handling:**           7/10 — `ApiError`/`thiserror` is used cleanly in brokerd and control-api; `anyhow::Result` leaks into hushd public APIs
- **Observability:**            5/10 — tracing is present but inconsistent; no request-id propagation; `eprintln!` survives in three binaries; bridges have prometheus, daemons do not
- **Security defaults:**        3/10 — auth defaults off on hushd and brokerd; CORS permissive on control-api; registry permits empty API key
- **Test coverage signal:**     6/10 — brokerd has a 3,441-line e2e harness, hushd has 7 integration files, control-api has 77 integration tests; hush-cli is good; eas-anchor and audit-monitor are barely tested

## Strengths

- **`clawdstrike-brokerd`** is the cleanest binary in the workspace. `src/main.rs` is **17 lines** that load config, build state, bind, and serve — exactly the right pattern. `api.rs::ApiError` is a discriminated `(status, code, message)` struct with `IntoResponse` that produces consistent `{"error":{"code","message"}}` JSON. The admin bearer check uses a **constant-time comparison** (`constant_time_eq` at `crates/services/clawdstrike-brokerd/src/api.rs:179-188`). `Config::from_env` validates `binding_proof_ttl_secs > 0` and rejects empty `trusted_hushd_public_keys` (`config.rs:109-119`).
- **Bridges share a runtime crate.** `tetragon-bridge`, `hubble-bridge`, `auditd-bridge`, `k8s-audit-bridge`, `darwin-telemetry-bridge` all depend on `bridge_runtime` for `wait_for_nats_startup`, `spawn_admin_server` (/healthz, /readyz, /metrics), `spawn_outbox_worker`, `BridgeMetrics`, `SqliteOutbox`. That is the right abstraction. Each bridge has bounded `max_consecutive_errors`, exponential backoff capped at 30–60s, and Prometheus metrics out of the box.
- **`hushd` `cli.rs` listen-address parsing handles IPv6** properly (`[::1]:9876`) with thorough unit tests (`crates/services/hushd/src/cli.rs:23-62, 389-407`).
- **SIGHUP for policy reload** in hushd, plus systemd notify/watchdog integration behind the `systemd` feature flag (`cli.rs:218-262`) — that is genuinely thoughtful daemon engineering.
- **Stable, documented exit codes** in `hush-cli::ExitCode` (Ok/Warn/Fail/ConfigError/RuntimeError/InvalidArgs at `crates/services/hush-cli/src/main.rs:78-99`) with explicit clap error-kind mapping (`main.rs:1352-1369`).
- **JetStream consumers in control-api** all use `tokio::sync::watch` shutdown channels rather than `JoinHandle::abort`, and emit `Acknowledge::after_processing` semantics (`crates/services/control-api/src/services/agent_heartbeat_consumer.rs`).
- **Two scope-based middleware layers** on hushd routes (`require_auth` then `scope_layer(Scope::X)`) (`crates/services/hushd/src/api/mod.rs:270-456`). Route table reads cleanly; admin/write/read are visually separated.
- **TLS abstraction** (`crates/services/hushd/src/tls.rs`) with proper `accept` error classification (skip on `ConnectionRefused/Aborted/Reset`, backoff on others).
- **`deny_unknown_fields` is pervasive** on serde structs across all services — caught at code review level.
- **Body size limit, CORS allowlist with explicit `*` handling** in `hushd::api::mod.rs:75-103` (fail-closed empty list, dedicated `AllowOrigin::any` for `*`).

## Findings

Grouped by service. ~32 findings total.

---

### hushd

#### CRITICAL — Security defaults: authentication off by default
- **Where:** `crates/services/hushd/src/config.rs:97-107`
- **What:** `AuthConfig { #[serde(default)] pub enabled: bool, .. }`. A config file that omits the `auth` block boots hushd with **all** API key middleware bypassed. `require_auth` in `crates/services/hushd/src/auth/middleware.rs:55-58` short-circuits when `!state.auth_enabled()`. `require_scope` also returns `Ok` when no `AuthenticatedActor` is in extensions (`middleware.rs:106-108`).
- **Why it matters:** Hushd binds the central policy enforcement HTTP surface for the whole product. An "out of the box" install on a developer machine is wide open; a misconfigured prod install is the same. This is the exact opposite of fail-closed.
- **Recommended action:** REWRITE config defaults. Make `enabled: bool` default to `true`. Refuse to start if `enabled = true` and `api_keys` is empty AND no identity provider is configured. Drop the `if !state.auth_enabled() { return Ok(next.run(req).await); }` shortcut entirely; replace with an `AuthMode::{Disabled, ApiKey, Oidc, Both}` enum so "off" is a deliberate, logged choice, not an omission.
- **Effort:** small (config) + medium (cascade through tests).

#### HIGH — Webhook delivery is fire-and-forget with no outbox
- **Where:** `crates/services/hushd/src/certification_webhooks.rs:68-105`
- **What:** Each certification webhook target is dispatched via `tokio::spawn(async move { … for attempt in 0..=3 { … } })`. There is no join handle, no persistent queue, no awareness on shutdown. Three attempts, then dropped on the floor.
- **Why it matters:** Certification webhooks are an integrator contract surface. SIGTERM during a delivery wave loses every inflight notification. There is no replay surface.
- **Recommended action:** REWRITE to use the same `SqliteOutbox` pattern that `bridge_runtime` already provides for the bridges. Persist on enqueue, dequeue and ack on success, retry with backoff and dead-letter on permanent failure.
- **Effort:** medium.

#### HIGH — `clawdstriked` is a vanity duplicate of `hushd`
- **Where:** `crates/services/hushd/src/bin/clawdstriked.rs` (5 lines, just `hushd::cli::run_bin("clawdstriked")`)
- **What:** Two binaries that differ only in their argv[0].
- **Why it matters:** Doubles the build output, doubles release artifacts, doubles the surface for documentation drift. Either it is a transitional rename or it should be one binary with a symlink at packaging time.
- **Recommended action:** DOCUMENT (if intentional, write it down in the package README), otherwise WIPE the `clawdstriked` binary stanza in `Cargo.toml`.
- **Effort:** trivial.

#### HIGH — Three rate limiters in one daemon
- **Where:** `crates/services/hushd/src/rate_limit.rs` (502 LOC), `v1_rate_limit.rs` (246), `identity_rate_limit.rs` (206)
- **What:** Three independent rate-limit middleware layers, each with their own state and config keys.
- **Why it matters:** Hard to reason about composite request budgets. Hard to add a fourth. Each duplicates the governor/dashmap plumbing.
- **Recommended action:** RESTRUCTURE. Build one `RateLimitRegistry` keyed by scope (`global`, `per-api-key`, `per-identity`, `per-v1`) and a single middleware that selects a key from request extensions.
- **Effort:** medium.

#### MEDIUM — Three crypto stacks in one daemon
- **Where:** `crates/services/hushd/Cargo.toml:55-72`
- **What:** Direct deps on `ring = "0.17"`, `rustls = { … features = ["ring"] }`, `openssl`, `rust-xmlsec` (which wraps libxmlsec1 which wraps OpenSSL).
- **Why it matters:** Three crypto backends triples the supply-chain attack surface, complicates FIPS posture, and inflates the binary by megabytes. `openssl`/`rust-xmlsec` are pulled in solely for SAML signature verification.
- **Recommended action:** REWRITE the SAML XML signature verifier on top of `rustls`/`ring` primitives or move SAML into an optional `saml` feature flag so the default `hushd` build does not link OpenSSL.
- **Effort:** large.

#### MEDIUM — `resvg` in a security daemon
- **Where:** `crates/services/hushd/src/api/certification.rs:971-984`
- **What:** Hushd ships a full SVG-to-PNG rasterizer (`resvg = "0.45"`, `tiny-skia`) to render certification badges as PNGs.
- **Why it matters:** That is a substantial attack surface (font parsing, vector graphics) inside the enforcement daemon. Badge rendering belongs in a static-assets generator at release time or a separate `badge-render` worker, not in the daemon that decides whether to allow file writes.
- **Recommended action:** RESTRUCTURE — pre-render badges at build time or move into a small standalone service.
- **Effort:** medium.

#### MEDIUM — `tokio::spawn` without join in `AppState::new`
- **Where:** `crates/services/hushd/src/state.rs:417-424`
- **What:** Heartbeat reaper is spawned with no `JoinHandle` retention. `shutdown_background_tasks` (called from `cli.rs:342`) does not wait on it.
- **Why it matters:** Background tasks may still be holding `state` clones during shutdown, racing with the audit ledger flush. The reaper relies on `shutdown.notified()` to exit, but if it panics, no one notices.
- **Recommended action:** REWRITE to store a `JoinSet` on `AppState` and await it during shutdown. Log on task exit.
- **Effort:** small.

#### LOW — `println!` in `hushd::cli::check_status`
- **Where:** `crates/services/hushd/src/cli.rs:373-379`
- **What:** Status subcommand emits raw `println!`.
- **Why it matters:** This is operator-facing output, so it is defensible — but lock yourself in to one style: either always go through `tracing` for daemon code paths or carve out a separate `print_status` helper that is unambiguously CLI-output.
- **Recommended action:** LEAVE (it is intentionally for human-readable CLI output) but DOCUMENT in a code comment that this branch is intentionally `println!`.
- **Effort:** trivial.

---

### clawdstrike-brokerd

#### CRITICAL — Capability/execution/revocation state is in-memory only
- **Where:** `crates/services/clawdstrike-brokerd/src/operator.rs:16-28`
- **What:** `OperatorState { inner: Arc<RwLock<OperatorStateInner>> }` with `BTreeMap`/`VecDeque` fields capped at `MAX_CAPABILITIES = 512`, `MAX_EXECUTIONS = 2048`, `MAX_TIMELINE_EVENTS = 4096`. No disk persistence, no NATS event log, nothing.
- **Why it matters:** The broker is the product feature. Restart of `clawdstrike-brokerd` silently loses the capability ledger, the revocation list, the freeze flag, and the entire timeline. An operator who freezes a provider, restarts the sidecar, and sees the freeze gone has no recourse.
- **Recommended action:** REWRITE `OperatorState` over `rusqlite` (already a workspace dep) or persist deltas onto a NATS JetStream subject (already used elsewhere). Either way, recover on boot.
- **Effort:** medium.

#### MEDIUM — Admin auth disabled when `admin_token` is None
- **Where:** `crates/services/clawdstrike-brokerd/src/api.rs:193-210`
- **What:** `require_admin_auth` returns `Ok` immediately when `state.config.admin_token` is `None`. The config loader treats this as "backward compatible".
- **Why it matters:** Anyone on the loopback (or wherever brokerd binds) can `POST /v1/admin/freeze` and `POST /v1/capabilities/{id}/revoke` if the operator forgets the env var.
- **Recommended action:** REWRITE — make the admin token mandatory unless an explicit `CLAWDSTRIKE_BROKERD_DISABLE_ADMIN_AUTH=true` is set (and log a `tracing::warn!` on every request when disabled).
- **Effort:** trivial.

#### MEDIUM — `main.rs` has no graceful shutdown
- **Where:** `crates/services/clawdstrike-brokerd/src/main.rs:1-17`
- **What:** `axum::serve(listener, create_router(state)).await?;` — no `.with_graceful_shutdown(…)`, no ctrl-c handling, no SIGTERM trap.
- **Why it matters:** Otherwise the cleanest binary in the tree. A SIGTERM during an in-flight `/v1/execute` proxy stream aborts the upstream call mid-flight without writing evidence.
- **Recommended action:** REWRITE — add `with_graceful_shutdown(shutdown_signal())` and a `tokio::select!` over ctrl-c + SIGTERM. Borrow the pattern from `hushd::cli::run_daemon`.
- **Effort:** trivial.

#### LOW — `--config` flag is missing entirely
- **Where:** `crates/services/clawdstrike-brokerd/src/main.rs`, `config.rs`
- **What:** Config is loaded purely from env vars. No file fallback, no `--config` flag, no `--show-config`.
- **Why it matters:** Operators end up writing wrapper shell scripts that `export` 11 variables before running brokerd. Inconsistent with hushd, which supports `--config` and `show-config`.
- **Recommended action:** RESTRUCTURE — add a `Cli` with `clap` deriving `Parser`, support `--config path` and `--show-config`, keep env vars as overrides.
- **Effort:** small.

---

### control-api

#### CRITICAL — Default bind is `0.0.0.0:8080` with `CorsLayer::permissive()`
- **Where:** `crates/services/control-api/src/config.rs:58-61` and `src/main.rs:310`
- **What:** `LISTEN_ADDR` default `"0.0.0.0:8080"`, plus `app.layer(CorsLayer::permissive())` unconditionally.
- **Why it matters:** Permissive CORS on a multi-tenant control plane exposes every API key in browser-driven attacks (`Authorization` plus `*`-allowed origin) when paired with the auth middleware that fishes the bearer out of `Authorization`. The 0.0.0.0 default means a Docker-Compose `up` exposes the control plane to the host network without intent.
- **Recommended action:** REWRITE — default to `127.0.0.1:8080`. Replace `CorsLayer::permissive()` with `CorsLayer::new().allow_origin(state.config.allowed_origins)` and make `allowed_origins` mandatory (no default, fail to start without it).
- **Effort:** trivial (one-line fixes) but breaks every Docker-Compose example.

#### HIGH — `main.rs` is 336 lines of inline orchestration
- **Where:** `crates/services/control-api/src/main.rs:54-336`
- **What:** `run()` hand-rolls 7 separate `tokio::sync::broadcast`/`watch` channels, manually plumbs each through 6 `tokio::spawn` blocks, and inlines `if config.X_enabled { tokio::spawn(async move { … }) }` for every background worker.
- **Why it matters:** Adding a 7th consumer adds 30+ lines of boilerplate; testing the orchestration is impossible. The current `with_graceful_shutdown` block also manually sends to each shutdown sender, which is the same boilerplate copied N times. The body of `run` repeats `tokio::spawn(async move { X_consumer::run(nats, db, &subject_filter, &stream_subjects, &stream_name, &consumer_name, shutdown_rx).await; })` near-verbatim for `audit`, `approval`, `heartbeat`, `hunt_event`.
- **Recommended action:** REWRITE. Introduce a `BackgroundService` trait with `name() -> &str`, `spawn(state, shutdown) -> JoinHandle`. Build a `ServiceSupervisor` that owns a `JoinSet`, a single `tokio::sync::watch<bool>`, and drives shutdown. `main` becomes ~50 lines.
- **Effort:** medium.

#### HIGH — `integration_tests.rs` (11,377 lines) lives in `src/`
- **Where:** `crates/services/control-api/src/integration_tests.rs`
- **What:** Massive integration test module, compiled into the library, gated by `#[cfg(test)]`, and re-mounts other modules via `#[path = "models/case_evidence.rs"] pub(crate) mod case_evidence;`.
- **Why it matters:** Slows down `cargo check` for everyone, makes the test surface invisible from outside the crate, and the `#[path]` remount pattern is a code smell — it exists because the test module pretends to be a child crate so it can access `pub(crate)` items.
- **Recommended action:** RESTRUCTURE. Move to `tests/integration/` as a proper integration test binary, expose the necessary helpers via a `pub` re-export gated behind a `testkit` feature.
- **Effort:** medium (touches many imports).

#### HIGH — Route god-files
- **Where:** `crates/services/control-api/src/routes/policies.rs` (3,153 LOC), `routes/response_actions.rs` (2,740), `routes/agents.rs` (1,745); `crates/services/hushd/src/api/broker.rs` (2,538), `api/certification.rs` (2,109), `api/swarm_hub.rs` (2,038), `api/presence.rs` (1,412)
- **What:** Single files holding 20-30 handler functions, the request/response types for all of them, validation logic, and tests.
- **Why it matters:** No one reviews a 3,000-line route file carefully. Handlers leak helper types across each other. PRs touching unrelated handlers trip on merge conflicts.
- **Recommended action:** RESTRUCTURE — `routes/policies/{mod,list,create,update,delete,validate,distribute}.rs` per domain action. Co-locate request/response types with their handler. Tests stay with the handler.
- **Effort:** medium per file, large in aggregate.

#### MEDIUM — `#[allow(dead_code)]` blanket at crate root
- **Where:** `crates/services/control-api/src/main.rs:3` (`#![allow(dead_code)]`) with the comment "Scaffold crate: many types/services are defined but not yet fully wired into routes."
- **Why it matters:** Hides genuinely dead code under a "we'll get to it" amnesty. There is no signal to clean up.
- **Recommended action:** WIPE the blanket allow. Move per-module `#[allow(dead_code)]` to the specific modules with a `// FIXME(scoping)` tag.
- **Effort:** small but will reveal real dead code.

#### MEDIUM — JetStream consumer retry uses fixed `sleep(1)`, not backoff
- **Where:** `crates/services/control-api/src/services/agent_heartbeat_consumer.rs:79`, `approval_request_consumer.rs:65`, `audit_consumer.rs:74`, `hunt_event_consumer.rs:84`
- **What:** On `consumer.fetch().messages().await` errors, sleeps a fixed 1 second and retries forever.
- **Why it matters:** A NATS server outage produces a tight 1-Hz retry storm in four consumers simultaneously. No jitter, no cap, no escalation.
- **Recommended action:** REWRITE — extract a `nats_consumer_retry` helper that does exponential backoff with jitter, capped at e.g. 30s, and emits `tracing::error!` with a counter so SREs see "consumer X has been retrying for 90 minutes".
- **Effort:** small (single helper, then four call-site swaps).

#### MEDIUM — No request-id propagation
- **Where:** `crates/services/control-api/src/main.rs:308-310` (only `TraceLayer::new_for_http()`)
- **What:** No `SetRequestIdLayer` or `PropagateRequestIdLayer`. Same in hushd.
- **Why it matters:** Cross-service tracing is impossible without correlating IDs. Every log line is a guess.
- **Recommended action:** RESTRUCTURE — add `tower_http::request_id::{SetRequestIdLayer, PropagateRequestIdLayer}` to both control-api and hushd. Bonus: emit it via `tracing::Span::record`.
- **Effort:** trivial.

---

### clawdstrike-registry

#### CRITICAL — `audit-monitor` binary uses `eprintln!` everywhere
- **Where:** `crates/services/clawdstrike-registry/src/bin/audit-monitor.rs:114-281`
- **What:** A transparency-log monitor that loops forever polling a registry, verifying consistency proofs, and emitting alerts. It uses `eprintln!("[audit-monitor] …")` for all output. No `tracing` initialization. No signal handling — `Ctrl+C` is the only way out of `loop { … sleep(interval) }`.
- **Why it matters:** A security-critical daemon (its job is to detect transparency-log tampering) with no structured logging means alerts cannot be parsed downstream and the process cannot terminate cleanly. State save on alert is also wrong: `if let Some(url) = webhook_url { send_webhook_alert(url, &msg).await; }` is best-effort with no retry.
- **Recommended action:** REWRITE — `tracing_subscriber::fmt()`, `tokio::select!` over `ctrl_c`/`SIGTERM`/`sleep(interval)`, persist state atomically (write-rename), bound the webhook with retry and deadline.
- **Effort:** small.

#### HIGH — Registry binds `0.0.0.0:3100`, allows empty `api_key`
- **Where:** `crates/services/clawdstrike-registry/src/config.rs:26, 41, 42`
- **What:** `host` defaults to `"0.0.0.0"`. `api_key = std::env::var("CLAWDSTRIKE_REGISTRY_API_KEY").unwrap_or_default()` — empty key is permitted. `allow_insecure_no_auth` defaults to `false`, which is the right default, but the loader does not enforce that an empty API key is rejected unless `allow_insecure_no_auth = true`.
- **Why it matters:** A misconfigured registry pretends auth is on while accepting any caller. The bind default exposes it on every interface.
- **Recommended action:** REWRITE — fail to start if `api_key.is_empty() && !allow_insecure_no_auth`. Default `host` to `127.0.0.1`.
- **Effort:** trivial.

#### MEDIUM — Registry has no library, no graceful shutdown
- **Where:** `crates/services/clawdstrike-registry/src/main.rs:26-50`
- **What:** Two binaries (`clawdstrike-registry`, `clawdstrike-audit-monitor`) defined in the same crate, no `lib.rs` exposed. `axum::serve(listener, app.into_make_service()).await?;` — no graceful shutdown.
- **Why it matters:** Integration tests cannot reuse the router. SIGTERM during a `POST /api/v1/packages` upload aborts mid-stream and leaves partial blobs.
- **Recommended action:** RESTRUCTURE — extract `lib.rs` with `pub fn router(state) -> Router` and `pub mod test_support`. Add ctrl-c/SIGTERM graceful shutdown.
- **Effort:** small.

---

### hush-cli

#### HIGH — `main.rs` is 3,238 lines (god-binary)
- **Where:** `crates/services/hush-cli/src/main.rs`
- **What:** A single `main.rs` that declares every `#[derive(Subcommand)]` for `Check`, `Run`, `Verify`, `Keygen`, `Policy{}`, `Guard{}`, `Origin{}`, `Pkg{}`, `Daemon{}`, `Hunt{}`, `Tui{}`, `Init{}`, `Completions{}`, `Hash{}`, `Sign{}`, `Merkle{}`, plus all of `MerkleCommands`, `PolicyCommands`, `GuardCommands`, etc., **and** a 1,500-line `async fn run()` dispatcher. Bin-level constants `CLI_JSON_VERSION`, `ExitCode`, `SandboxMode`, plus N `…JsonOutput` serde structs all live here too.
- **Why it matters:** Adding a new top-level command requires editing main.rs, the dispatcher, and the help text in the doc-comment. Discoverability is awful. Editor performance is awful.
- **Recommended action:** RESTRUCTURE. Each top-level command becomes its own module exposing `Subcommand` + `async fn execute(args, ctx) -> ExitCode`. `main.rs` becomes <200 lines: define `Cli` aggregating all sub-subcommands, parse, dispatch, print.
- **Effort:** large.

#### MEDIUM — Default signing key path is a cwd-relative file
- **Where:** `crates/services/hush-cli/src/main.rs:203, 258`
- **What:** `--signing-key` defaults to `"clawdstrike.key"` (relative to CWD). `--output` for keygen defaults to `"clawdstrike.key"`.
- **Why it matters:** Silently writes/reads private keys in whatever directory the user happens to be in. `cd /tmp && hush keygen` puts an Ed25519 seed in `/tmp/clawdstrike.key`.
- **Recommended action:** REWRITE — default to `$XDG_DATA_HOME/clawdstrike/signing.key` (use `dirs` crate) and refuse to write a key with permissive (>0600) mode.
- **Effort:** small.

#### LOW — Subcommand `Status` URL hardcoded to `http://127.0.0.1:9876`
- **Where:** `crates/services/hushd/src/cli.rs:111` (`#[arg(default_value = "http://127.0.0.1:9876")]`)
- **What:** Hard-coded URL string in clap default.
- **Why it matters:** Two places to update if the default daemon port ever changes (`config.rs::default_listen` already says `"127.0.0.1:9876"`).
- **Recommended action:** RESTRUCTURE — extract `const DEFAULT_HUSHD_URL: &str = …;` shared between `cli.rs` and `config.rs`.
- **Effort:** trivial.

---

### spine-cli

#### MEDIUM — `--verbose` flag is plumbed everywhere but `tracing` is never initialized
- **Where:** `crates/services/spine-cli/src/main.rs:27-28, 126-163`
- **What:** Every command takes `verbose: bool` as an argument, but `main()` never calls `tracing_subscriber::fmt::init()`. Subcommands receive `verbose` but appear to use it inconsistently (no `tracing::` imports in commands).
- **Why it matters:** "Verbose" is a no-op. Operators set `-v` expecting more detail and get nothing.
- **Recommended action:** REWRITE — wire `tracing_subscriber` with a level driven by `verbose`. Replace any `println!` in commands with `tracing::info!`.
- **Effort:** small.

---

### eas-anchor

#### CRITICAL — The whole service is a stub
- **Where:** `crates/services/eas-anchor/src/eas_client.rs:104-124, 127-147`
- **What:** Both `submit_batch` and `revoke_attestation` end with:
  ```rust
  Err(Error::Client(
      "Chain submission not yet implemented — use Base Sepolia testnet for integration testing"
          .into(),
  ))
  ```
  The only useful work is local ABI encoding into `_encoded_items` (note the leading underscore) which is then discarded.
- **Why it matters:** A binary called `eas-anchor` that **cannot anchor** is misleading at best. Anyone who deploys this hoping for L2 anchoring gets nothing but a NATS subscription consuming checkpoints and noisy `tracing::info!("submission pending chain integration")`.
- **Recommended action:** WIPE this from the public service list (move to `examples/`, mark `publish = false` is already true), OR REWRITE the two TODOs against `alloy` and verify against Base Sepolia. Until then, the binary should refuse to start unless `--allow-stub` is passed.
- **Effort:** large (the actual work).

---

### Bridges (cross-cutting)

#### HIGH — Five duplicate main.rs files
- **Where:** `crates/bridges/tetragon-bridge/src/main.rs:124-196`, `hubble-bridge/src/main.rs:123-195`, `auditd-bridge/src/main.rs:125-197`, `k8s-audit-bridge/src/main.rs` (similar), `darwin-telemetry-bridge/src/main.rs:138-214`
- **What:** Each `main()` is approximately:
  ```rust
  let mut backoff = Duration::from_secs(1);
  loop {
      if let Err(e) = bridge_runtime::wait_for_nats_startup(…).await {
          warn!(error = %e, "NATS startup readiness check failed, retrying");
          tokio::time::sleep(backoff).await;
          backoff = (backoff * 2).min(Duration::from_secs(60));
          continue;
      }
      match Bridge::new(config.clone()).await { Ok(bridge) => …, Err(e) => error!(…) }
      tokio::time::sleep(backoff).await;
      backoff = (backoff * 2).min(Duration::from_secs(60));
  }
  ```
  Five copies. Every change must be made five times. `diff hubble main tetragon main | wc -l = 217`.
- **Why it matters:** Bug fixes (e.g. add jitter to backoff) won't reach all bridges. New shared CLI flags (e.g. `--metrics-token`) require N copies of the same block.
- **Recommended action:** RESTRUCTURE — move the supervise loop into `bridge_runtime::run_bridge<B: Bridge>(config) -> !`. Each bridge `main` becomes ~25 lines: clap parse → call `bridge_runtime::run_bridge`.
- **Effort:** small.

#### MEDIUM — `eprintln!` for unknown-event-type warnings across all five bridges
- **Where:** `crates/bridges/tetragon-bridge/src/main.rs:117`, `hubble-bridge/src/main.rs:116`, `auditd-bridge/src/main.rs:118`, `k8s-audit-bridge/src/main.rs:116`, `darwin-telemetry-bridge/src/main.rs:131`
- **What:** All five use `eprintln!("warning: unknown event type '{other}', ignoring")` despite already having `tracing` configured.
- **Why it matters:** Inconsistent log routing. These messages won't appear in the JSON/OTEL stream that the rest of bridge logs go to.
- **Recommended action:** REWRITE — `tracing::warn!(event_type = %other, "ignoring unknown event type")`. Trivially fixed by the shared `run_bridge` refactor above.
- **Effort:** trivial.

#### MEDIUM — Admin endpoints default to `0.0.0.0:2112` with no auth
- **Where:** Every bridge: `#[arg(long, default_value = "0.0.0.0:2112", env = "ADMIN_LISTEN_ADDR")]`
- **What:** `/healthz`, `/readyz`, `/metrics` are exposed on all interfaces with no authentication.
- **Why it matters:** `/metrics` typically contains cardinality that an attacker can use for inventory (pod names, namespaces in allowlist labels). Defensible in a k8s pod with `NetworkPolicy`, indefensible on a bare VM.
- **Recommended action:** RESTRUCTURE — default to `127.0.0.1:2112` for the admin server; document the k8s deployment as "explicitly opt into 0.0.0.0 when using pod-IP scraping".
- **Effort:** trivial.

#### LOW — Outbox path defaults to `/tmp/`
- **Where:** `crates/bridges/tetragon-bridge/src/lib.rs:98` (`outbox_path: Some("/tmp/tetragon-bridge-outbox.db".to_string())`); same pattern in other bridges
- **What:** SQLite outbox defaults to `/tmp` which is often `tmpfs`/wiped at reboot.
- **Why it matters:** Defeats the durability promise of the outbox.
- **Recommended action:** REWRITE — default to `$XDG_STATE_HOME/clawdstrike/<bridge-name>/outbox.db` (or `/var/lib/clawdstrike/<bridge>/outbox.db` on Linux). Require a non-tmp location when `outbox_enabled = true`.
- **Effort:** trivial.

---

### Cross-cutting

#### MEDIUM — No OpenAPI / typed-route generation
- **Where:** All HTTP services
- **What:** Every route is hand-registered in an axum `Router` and every request/response body is a hand-rolled `serde` struct. Client SDKs in `packages/sdk/hush-ts` and friends are hand-maintained.
- **Why it matters:** Drift between server and client is silent. Manual labor.
- **Recommended action:** RESTRUCTURE — adopt `utoipa` (already in workspace?) or `aide` to derive OpenAPI from axum route declarations, generate clients from there.
- **Effort:** large but very high leverage.

#### MEDIUM — Background tasks use `tokio::spawn` instead of a tracked `JoinSet`
- **Where:** 49 `tokio::spawn` call sites in services/bridges
- **What:** Most spawns happen at handler/state-init time and the handle is dropped. There is no central registry of "live workers".
- **Why it matters:** Shutdown is best-effort; a panicked worker is silent; observability into "what workers are running" is impossible.
- **Recommended action:** RESTRUCTURE — introduce a `tokio::task::JoinSet` per service (`AppState::tasks`), `task_set.spawn(supervised(...))` everywhere, and `task_set.join_all().await` in graceful shutdown.
- **Effort:** medium.

#### LOW — `clippy::unwrap_used` / `expect_used` are bypassed via `cfg(test)`
- **Where:** Every service top-level file begins with `#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]`.
- **What:** Production unwraps remain banned (good), but tests get a free pass (acceptable). However, `#[cfg(test)]` modules that *contain* the helpers can still unwrap freely.
- **Why it matters:** Mostly fine. Note the inconsistency: brokerd's tests `#![allow(clippy::unwrap_used, clippy::expect_used)]` is set per-module rather than crate-wide, which is the more defensible style. Use one style across services.
- **Recommended action:** DOCUMENT.
- **Effort:** trivial.

---

## Action Plan

Prioritized; numbered.

1. **Flip `hushd` auth default to `enabled = true`** and refuse to start with no API keys + no IdP. (CRITICAL, small)
2. **Persist `clawdstrike-brokerd::OperatorState`** to SQLite (or NATS log). (CRITICAL, medium)
3. **Default `control-api` to `127.0.0.1:8080`** and replace `CorsLayer::permissive()`. (CRITICAL, trivial — but compose-breaking)
4. **Make `clawdstrike-brokerd` admin token mandatory** (or require an explicit opt-out env var). (HIGH, trivial)
5. **Replace `clawdstrike-audit-monitor`'s `eprintln!` with `tracing`** and add signal handling. (HIGH, small)
6. **Fail to start `clawdstrike-registry`** when `api_key.is_empty() && !allow_insecure_no_auth`; default host to `127.0.0.1`. (HIGH, trivial)
7. **Decide eas-anchor's fate** — finish the alloy implementation or hide it from public-facing service docs. (CRITICAL, large)
8. **Extract `bridge_runtime::run_bridge`** to eliminate the five duplicate main loops. (HIGH, small)
9. **Add `with_graceful_shutdown` to `clawdstrike-brokerd`**. (HIGH, trivial)
10. **Webhook outbox in `hushd::certification_webhooks`**. (HIGH, medium)
11. **Decompose `hush-cli/src/main.rs`** (and the giant route files in `hushd` and `control-api`). (HIGH, large in aggregate)
12. **Move `control-api::integration_tests`** into `tests/`. (HIGH, medium)
13. **Refactor `control-api::main::run`** into a `ServiceSupervisor`. (HIGH, medium)
14. **Consolidate the three `hushd` rate limiters** into one. (HIGH, medium)
15. **Backoff with jitter on NATS consumer retries** (one helper across four consumers). (MEDIUM, small)
16. **Remove `clawdstriked` vanity binary** or document why both exist. (HIGH, trivial)
17. **Drop `crate-level #![allow(dead_code)]`** in control-api; clean what falls out. (MEDIUM, small-medium)
18. **Add `tower_http::request_id`** to control-api + hushd. (MEDIUM, trivial)
19. **Reduce hushd crypto stacks** — gate SAML/OpenSSL behind a feature flag. (MEDIUM, large)
20. **Move `resvg` badge rendering** out of the daemon. (MEDIUM, medium)
21. **`JoinSet`-based task supervision** across services. (MEDIUM, medium)
22. **Adopt `utoipa`/`aide`** for OpenAPI generation. (MEDIUM, large)
23. **Default outbox paths** away from `/tmp`. (LOW, trivial)
24. **Default admin endpoints** on bridges to `127.0.0.1`. (LOW, trivial)
25. **`hush-cli` keygen default path** to `$XDG_DATA_HOME`. (MEDIUM, small)
26. **`spine-cli` actually wire `--verbose`** to `tracing`. (MEDIUM, small)
27. **Replace `eprintln!` warnings in five bridges** with `tracing::warn!`. (MEDIUM, trivial — fixed by item 8)
28. **Co-locate request/response types** with handlers when splitting big route files. (MEDIUM, medium)

## Top 10 Quick Wins

1. Flip `hushd::AuthConfig::enabled` default to `true`. One line, fail-closed.
2. Default `control-api` `LISTEN_ADDR` to `127.0.0.1:8080`.
3. Replace `CorsLayer::permissive()` in `control-api` with an explicit allowlist.
4. Make `clawdstrike-brokerd::admin_token` mandatory by default.
5. Add `with_graceful_shutdown(shutdown_signal())` to `clawdstrike-brokerd::main`.
6. Delete the `clawdstriked` binary entry from `hushd/Cargo.toml` (or document it).
7. Initialize `tracing_subscriber` in `spine-cli::main` so `--verbose` is not a lie.
8. Replace `eprintln!` in five bridge `parse_event_types`/`parse_verdicts` with `tracing::warn!`.
9. Default `--admin-listen-addr` in bridges to `127.0.0.1:2112`.
10. Add `tower_http::request_id::{SetRequestIdLayer, PropagateRequestIdLayer}` to both control-api and hushd; reference the same request-id header.

## Things to Leave Alone

- **`clawdstrike-brokerd::api.rs::ApiError` and `constant_time_eq`.** Discriminated error type with consistent JSON shape and a real constant-time comparator. This is the model the other services should follow.
- **`tetragon-bridge::Bridge::run` event loop** (`crates/bridges/tetragon-bridge/src/lib.rs:238-298`). Tracks `consecutive_errors`, exits when the threshold is hit, exponential backoff, `metrics.set_nats_connected` on every iteration. Solid pattern.
- **`hushd::cli::parse_listen_host_port`** with IPv6 support and explicit unit tests.
- **`hushd` systemd integration** (`#[cfg(feature = "systemd")]` block in `cli.rs:218-241`). `sd_notify::Ready` + watchdog heartbeat at half the configured `WATCHDOG_USEC` is exactly right.
- **`hushd::tls::handle_accept_error`** — skip transient client-side drops, backoff on others. Don't touch this.
- **`hush-cli::ExitCode` enum** with stable numeric exit codes and explicit clap-kind mapping in `main`. Don't change the values — they are an external contract.
- **`hushd::api::create_router` route grouping** by `public` / `read` / `check` / `admin` / `ws` / `presence_ticket`. The shape is correct even if route files are too big.
- **`#[serde(deny_unknown_fields)]` discipline.** Keep enforcing.
- **`bridge_runtime` shared crate.** The right architectural call — extend it (per Finding 8), don't undo it.
- **`clawdstrike-brokerd::Config::from_env` validation** (rejects empty trusted-key sets, zero-TTL, unsupported backend names). Mirror this in other services.

---

*Audit conducted 2026-05-23. Reviewer: GSD codebase-mapper, services & bridges focus.*
