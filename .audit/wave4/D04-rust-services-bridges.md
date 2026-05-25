# DELTA D04: Rust Services & Bridges
**Refreshed:** 2026-05-24 | **Source:** `.audit/04-rust-services-bridges.md` (2026-05-23) + `.audit/wave3/B-api-server-routes.md` | **Scope:** `crates/services/`, `crates/bridges/`, `crates/tests/`

## Quick Verdict

- Findings still valid: **30 of 32** (everything CRITICAL/HIGH/MEDIUM from the source audit remains true at HEAD)
- Findings fixed since 2026-05-23: **0**
- Findings wrong/misdiagnosed: **1** (control-api `main.rs` LOC was 484 not 336)
- New issues found: **3** (working-tree growth in policies.rs / response_actions.rs adds complexity; `validate_endpoint_ack_signed_receipt` queries DB before `requires_…` guard returns; `distribute_active_policy_to_fleet` per-agent loop holds open `state.db` for each `reconcile_effective_policy_for_agent` with no concurrency cap)
- **Working-tree state:** Eleven service/bridge files in the dirty index. The diffs add new behavior (signed-receipt verification on response-action acks, transactional version-aware policy upserts, fleet rule-diff dispatch reservation, deployment-id plumbing). None of them touch any of the four insecure defaults. Two are pure clippy `unnecessary_lazy_evaluations`/`unwanted_braces` lints (`tetragon-bridge/mapper.rs` and `hushd/policy_scoping/mod.rs`). One is a refactor-only branch swap in `hush-cli/pkg_cli.rs`.
- **Critical: are the 4 insecure defaults still insecure?** **Yes — all four. (1) hushd `AuthConfig.enabled` still `#[serde(default)] bool` (false). (2) control-api `LISTEN_ADDR` still defaults `"0.0.0.0:8080"`; `CorsLayer::permissive()` is still applied unconditionally. (3) clawdstrike-registry still defaults `host = "0.0.0.0"` and permits empty `api_key` without `allow_insecure_no_auth = true`. (4) clawdstrike-brokerd `require_admin_auth` still returns `Ok(())` when `admin_token` is `None`.**
- **Net delta:** Audit is still ~95% accurate. Nothing has been fixed; the dirty diff adds correctness/integrity coverage (signed-receipt verification on agent acks; deployment-id propagation) but does not touch the security defaults, the duplicate bridge mains, the god-files, the persistence gap, or the eas-anchor stub.

## Security Defaults Verification (the four CRITICALS)

| # | Default                                                  | File:line                                                            | At HEAD                                                              | Working tree                | Verdict          |
| - | -------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- | --------------------------- | ---------------- |
| 1 | `hushd::AuthConfig::enabled` defaults `false`            | `crates/services/hushd/src/config.rs:97-107`                         | `#[serde(default)] pub enabled: bool` — derived `Default` is `false` | unchanged                   | **still insecure** |
| 1b | `require_auth` skips entirely when `enabled = false`     | `crates/services/hushd/src/auth/middleware.rs:50-58`                 | `if !state.auth_enabled() { return Ok(next.run(req).await); }`       | unchanged                   | **still insecure** |
| 1c | `require_scope` returns `Ok` when no `AuthenticatedActor` | `crates/services/hushd/src/auth/middleware.rs:104-108`               | `let Some(actor) = … else { return Ok(next.run(req).await); }`       | unchanged                   | **still insecure** |
| 2 | control-api `LISTEN_ADDR` default `0.0.0.0:8080`         | `crates/services/control-api/src/config.rs:59-61`                    | `.unwrap_or_else(\|_\| "0.0.0.0:8080".to_string())`                  | unchanged (only `token_glob_overlap` refactor) | **still insecure** |
| 2b | `CorsLayer::permissive()` on every response              | `crates/services/control-api/src/main.rs:310`                        | `.layer(CorsLayer::permissive())`                                    | unchanged                   | **still insecure** |
| 3 | clawdstrike-registry default `host = "0.0.0.0"`          | `crates/services/clawdstrike-registry/src/config.rs:26`              | `.unwrap_or_else(\|_\| "0.0.0.0".into())`                            | unchanged                   | **still insecure** |
| 3b | Empty `api_key` permitted; no enforcement vs `allow_insecure_no_auth` | `crates/services/clawdstrike-registry/src/config.rs:41-42`           | `.unwrap_or_default()` with no rejection branch                      | unchanged                   | **still insecure** |
| 4 | `clawdstrike-brokerd::require_admin_auth` no-op when `admin_token` is None | `crates/services/clawdstrike-brokerd/src/api.rs:193-210`             | `None => return Ok(()), // No token configured — auth disabled.`     | unchanged                   | **still insecure** |

Each of these continues to ship with the same defaults that an "out of the box" `cargo run` or `docker compose up` would use. None of the recent EDR commits or working-tree edits touched these files.

## Findings Index (all 32 from source audit + 5 new)

| # | Severity | Finding | Service/Bridge | File:Line at HEAD | Status (2026-05-24) |
| -:| -------- | ------- | -------------- | ----------------- | ------------------- |
|  1 | CRITICAL | Auth defaults to off | hushd | `config.rs:97-107`, `middleware.rs:50-58, 104-108` | **still valid** |
|  2 | CRITICAL | OperatorState RAM-only | brokerd | `operator.rs:1-28` | **still valid** |
|  3 | CRITICAL | `0.0.0.0:8080` + CorsLayer::permissive() | control-api | `config.rs:59-61`, `main.rs:308-310` | **still valid** |
|  4 | CRITICAL | `eprintln!` everywhere + no signals | registry/audit-monitor | `bin/audit-monitor.rs:114-281` | **still valid** |
|  5 | CRITICAL | Stub service | eas-anchor | `eas_client.rs:104-124, 127-147` | **still valid** |
|  6 | HIGH | Webhook fire-and-forget | hushd | `certification_webhooks.rs:60-106` | **still valid** |
|  7 | HIGH | `clawdstriked` vanity duplicate | hushd | `Cargo.toml:23-24`, `bin/clawdstriked.rs` | **still valid** |
|  8 | HIGH | Three rate limiters | hushd | `rate_limit.rs`, `v1_rate_limit.rs`, `identity_rate_limit.rs` | **still valid** |
|  9 | HIGH | main.rs orchestration inline | control-api | `main.rs:54-484` | **still valid** (LOC: 484, not 336) |
| 10 | HIGH | integration_tests.rs in src/ | control-api | `integration_tests.rs:1-11377` | **still valid** (growing) |
| 11 | HIGH | Route god-files | control-api + hushd | `policies.rs:3153`, `response_actions.rs:2740`, others | **still valid** (growing) |
| 12 | HIGH | Five duplicate bridge mains | bridges | `*/src/main.rs:124-196` | **still valid** |
| 13 | HIGH | Registry binds 0.0.0.0 + empty key | registry | `config.rs:26, 41-42` | **still valid** |
| 14 | HIGH | hush-cli 3,238 LOC god-binary | hush-cli | `main.rs:1-3238` | **still valid** |
| 15 | MEDIUM | Admin auth disabled when token=None | brokerd | `api.rs:193-210`, `config.rs:96-98` | **still valid** |
| 16 | MEDIUM | brokerd main has no graceful shutdown | brokerd | `main.rs:1-17` | **still valid** |
| 17 | MEDIUM | brokerd `--config` flag missing | brokerd | `main.rs`, `config.rs` | **still valid** |
| 18 | MEDIUM | Three crypto stacks | hushd | `Cargo.toml:55-72` | **still valid** |
| 19 | MEDIUM | resvg in security daemon | hushd | `Cargo.toml:73`, `api/certification.rs` | **still valid** |
| 20 | MEDIUM | tokio::spawn without join | hushd | `state.rs:416-424` | **still valid** |
| 21 | MEDIUM | `#![allow(dead_code)]` blanket | control-api | `main.rs:3` | **still valid** |
| 22 | MEDIUM | JetStream fixed-1s retry | control-api | 4 consumers under `services/` | **still valid** |
| 23 | MEDIUM | No request-id propagation | control-api + hushd | `main.rs:308-310`, `api/mod.rs` | **still valid** |
| 24 | MEDIUM | Registry no lib, no graceful shutdown | registry | `main.rs:1-51` | **still valid** |
| 25 | MEDIUM | hush-cli signing-key default cwd-relative | hush-cli | `main.rs:203, 258` | **still valid** |
| 26 | MEDIUM | `eprintln!` in five bridges | bridges | `*/src/main.rs:116-131` | **still valid** |
| 27 | MEDIUM | Admin bind 0.0.0.0:2112 in bridges | bridges | `*/src/main.rs`, `*/src/lib.rs` | **still valid** |
| 28 | MEDIUM | No OpenAPI generation | all HTTP services | `Cargo.toml` workspace | **still valid** |
| 29 | MEDIUM | 49 untracked tokio::spawn sites | all | recursive grep | **still valid** (count = 49) |
| 30 | MEDIUM | spine-cli `--verbose` no-op | spine-cli | `main.rs:27-28` | **still valid** |
| 31 | LOW | `println!` in hushd status | hushd | `cli.rs:373-379` | **still valid** |
| 32 | LOW | hushd Status URL hardcoded | hushd | `cli.rs:111` | **still valid** |
| LOW | LOW | cfg(test) clippy bypass inconsistency | all | crate-roots | **still valid** |
| LOW | LOW | Outbox /tmp default | bridges | `*/src/lib.rs:98, 181` | **still valid** |
| NEW 1 | LOW | DB query under open tx in new validator | control-api | `routes/response_actions.rs` (working tree) | **new (working tree)** |
| NEW 2 | MEDIUM | Sequential per-agent KV writes in deploy | control-api | `routes/policies.rs:1663-1710` | **new** |
| NEW 3 | HIGH | Dirty diff grows route god-files | control-api | `policies.rs`, `response_actions.rs`, `integration_tests.rs` | **new (working tree)** |
| NEW 4 | MEDIUM | control-api CORS pattern lags hushd's | control-api | `main.rs:310` vs `hushd/api/mod.rs:75-103` | **new** |
| NEW 5 | LOW | tetragon mapper severity classifier under-tested | tetragon-bridge | `mapper.rs:191-205` | **new (defensive)** |

---

## STILL VALID

### CRITICAL findings — all still valid

#### CRITICAL — hushd auth defaults to off
- `crates/services/hushd/src/config.rs:97-107` ⇒ unchanged. Verified literal:
  ```rust
  #[derive(Clone, Debug, Default, Serialize, Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct AuthConfig {
      /// Whether authentication is required for API endpoints
      #[serde(default)]
      pub enabled: bool,
      /// API keys
      #[serde(default)]
      pub api_keys: Vec<ApiKeyConfig>,
  }
  ```
  The derived `Default` produces `AuthConfig { enabled: false, api_keys: vec![] }`. A YAML config file that omits the `auth:` block lands at that default.
- `crates/services/hushd/src/auth/middleware.rs:50-58` ⇒ early return on `!state.auth_enabled()` unchanged. Verified:
  ```rust
  pub async fn require_auth(
      State(state): State<AppState>,
      mut req: Request<Body>,
      next: Next,
  ) -> Result<Response, StatusCode> {
      // Skip auth if disabled in config
      if !state.auth_enabled() {
          return Ok(next.run(req).await);
      }
      ...
  }
  ```
- `crates/services/hushd/src/auth/middleware.rs:104-108` ⇒ `require_scope` also silent when no actor is in extensions:
  ```rust
  let Some(actor) = req.extensions().get::<AuthenticatedActor>() else {
      return Ok(next.run(req).await);
  };
  ```
- Effort to fix: still small (one config-shape change, one delete-the-shortcut, one or two test fixups). Recommendation rewrite as `AuthMode { Required, ApiKey, Oidc, Both, Disabled }` with `Required` as the default still stands.

#### CRITICAL — clawdstrike-brokerd persistence is RAM-only
- `crates/services/clawdstrike-brokerd/src/operator.rs:1-28` ⇒ still `OperatorState { inner: Arc<RwLock<OperatorStateInner>> }`. Verified literal:
  ```rust
  const MAX_CAPABILITIES: usize = 512;
  const MAX_EXECUTIONS: usize = 2_048;
  const MAX_TIMELINE_EVENTS: usize = 4_096;

  #[derive(Clone, Default)]
  pub struct OperatorState {
      inner: Arc<RwLock<OperatorStateInner>>,
  }

  #[derive(Default)]
  struct OperatorStateInner {
      frozen: bool,
      revoked_capability_ids: BTreeSet<String>,
      capabilities: BTreeMap<String, CapabilityRecord>,
      executions: BTreeMap<String, ExecutionRecord>,
      timeline: VecDeque<ExecutionTimelineEvent>,
  }
  ```
  No SQLite, no NATS log, no rehydration on boot. The audit's note that the broker is the new product line and the in-memory ledger silently drops on restart still applies. Effort: still medium.

#### CRITICAL — control-api defaults 0.0.0.0 + CorsLayer::permissive()
- `crates/services/control-api/src/config.rs:59-61` ⇒ unchanged.
- `crates/services/control-api/src/main.rs:308-310` ⇒ unchanged.
- Note: `control-api/src/config.rs` IS in the working tree, but the diff is a pure clippy refactor of `token_glob_overlap` (lines 388-396) — nothing security-relevant.

#### CRITICAL — clawdstrike-audit-monitor uses `eprintln!` everywhere
- `crates/services/clawdstrike-registry/src/bin/audit-monitor.rs` ⇒ still **11 `eprintln!` call sites** (lines 123, 126, 157, 164, 175, 187, 217, 229, 237, 260, 277). Verified by `grep -n 'eprintln\|tracing::' …`:
  ```
  123: eprintln!("[audit-monitor] Webhook POST status: {}", resp.status());
  126: eprintln!("[audit-monitor] Failed to send webhook alert: {e}");
  157: eprintln!("[audit-monitor] {msg}");
  164: eprintln!(
  175:     eprintln!(
  187: eprintln!("[audit-monitor] {msg}");
  217: eprintln!(
  229: eprintln!("[audit-monitor] {msg}");
  237: eprintln!(
  260: eprintln!(
  277:     eprintln!("[audit-monitor] Poll cycle error: {e}");
  ```
- No `tracing_subscriber` initialization in the file (grep returned no hits for `tracing::` or `tracing_subscriber`). No `tokio::signal::ctrl_c` / SIGTERM trap (grep returned no hits for `signal::ctrl_c` or `SIGTERM`). The webhook deliverer at `send_webhook_alert` (114-129) sends once with no retry; the main `poll_cycle` at line 277 logs and continues — alerts are best-effort dropped.

#### CRITICAL — eas-anchor is a stub
- `crates/services/eas-anchor/src/eas_client.rs:104-124` ⇒ still ends with `Err(Error::Client("Chain submission not yet implemented — use Base Sepolia testnet for integration testing".into()))`. Verified literal block:
  ```rust
  // TODO: Build and send the actual multiAttest transaction via alloy.
  // The contract ABI encoding for EAS.multiAttest() requires:
  //   1. Build a FillerProvider with the signer and RPC URL
  //   2. ABI-encode the MultiAttestationRequest struct
  //   3. Send the transaction and await confirmation
  ...
  Err(Error::Client(
      "Chain submission not yet implemented — use Base Sepolia testnet for integration testing"
          .into(),
  ))
  ```
- `crates/services/eas-anchor/src/eas_client.rs:127-147` ⇒ `revoke_attestation` likewise (`Err(Error::Client("Chain submission not yet implemented — …"))`).
- `crates/services/eas-anchor/src/main.rs` ⇒ still starts up, calls `EasClient::new(&config)`, then `eas_anchor::nats_sub::run_subscription(&config, &client).await` — every batch fails. No `--allow-stub` flag added.
- Total crate size: ~1,124 LOC src + tests, almost entirely "preparatory" ABI encoding that gets discarded. The audit's recommendation to WIPE (or finish against alloy) still stands.

### HIGH findings — all still valid

#### HIGH — webhook delivery fire-and-forget in hushd
- `crates/services/hushd/src/certification_webhooks.rs:60-106` ⇒ unchanged. Still `tokio::spawn(async move { for attempt in 0..=3 { … } })`. Verified literal:
  ```rust
  for t in targets {
      let client = reqwest::Client::new();
      let url = t.url.clone();
      let sig = signature_header(&t.secret, &body);
      let body = body.clone();
      let webhook_id = t.webhook_id.clone();

      tokio::spawn(async move {
          let mut backoff = Duration::from_secs(1);
          for attempt in 0..=3 {
              ...
              if attempt == 3 {
                  break;
              }
              tokio::time::sleep(backoff).await;
              backoff = backoff.saturating_mul(2);
          }
      });
  }
  ```
- No join handle returned, no awareness on shutdown. Three attempts (0, 1, 2, 3) over 1+2+4 = 7 seconds, then dropped on the floor. No `SqliteOutbox` integration. The whole module is **106 lines** (audit said 105) — no change.

#### HIGH — `clawdstriked` vanity duplicate of `hushd`
- `crates/services/hushd/Cargo.toml:23-24` ⇒ still declares `[[bin]] name = "clawdstriked" path = "src/bin/clawdstriked.rs"`.
- `crates/services/hushd/src/bin/clawdstriked.rs` ⇒ still 5 lines: `hushd::cli::run_bin("clawdstriked")`.

#### HIGH — three rate limiters in hushd
- `crates/services/hushd/src/rate_limit.rs` ⇒ **502 LOC** (audit said 502). Unchanged.
- `crates/services/hushd/src/v1_rate_limit.rs` ⇒ **246 LOC** (audit said 246). Unchanged.
- `crates/services/hushd/src/identity_rate_limit.rs` ⇒ **206 LOC** (audit said 206). Unchanged.

#### HIGH — control-api `main.rs` orchestration is inline
- `crates/services/control-api/src/main.rs` is now **484 LOC** (not 336 as audit said). The boilerplate `if config.X_enabled { let nats = … ; let db = …; tokio::spawn(async move { X_consumer::run(...).await; }) }` block repeats verbatim for `audit_consumer` (132-154), `approval_request_consumer` (156-197), `approval_resolution_outbox` (199-211), `agent_heartbeat_consumer` (213-254), and `hunt_event_consumer` (256-306). Six channels are hand-wired (lines 105-111). Shutdown plumbs each `_signal` clone individually (lines 315-329).

#### HIGH — `integration_tests.rs` lives in `src/`
- `crates/services/control-api/src/integration_tests.rs` at HEAD = **11,146 lines**; working tree = **11,377 lines** (+231 lines added by uncommitted work covering proof-only proposal flows for `policies_proposal_requires_admin_approval_before_deploying`).
- `#[path = …]` remounts at lines 18-21 are unchanged.

#### HIGH — route god-files
- `crates/services/control-api/src/routes/policies.rs` ⇒ HEAD = **3,153 LOC** (audit said 3,153 — exact). Working tree adds +568 lines, growing it to ~3,721 LOC.
- `crates/services/control-api/src/routes/response_actions.rs` ⇒ HEAD = **2,740 LOC** (audit said 2,740). Working tree adds +223 lines, growing it to ~2,963 LOC.
- `crates/services/control-api/src/routes/agents.rs` ⇒ HEAD = **1,745 LOC** (audit said 1,745). Unchanged.
- `crates/services/hushd/src/api/broker.rs` ⇒ HEAD = **2,538 LOC** (audit said 2,538). Working tree changes 4 lines (sort lambda → `sort_by_key`); no growth.
- `crates/services/hushd/src/api/certification.rs` ⇒ HEAD = **2,109 LOC** (audit said 2,109).
- `crates/services/hushd/src/api/swarm_hub.rs` ⇒ HEAD = **2,038 LOC** (audit said 2,038).
- `crates/services/hushd/src/api/presence.rs` ⇒ HEAD = **1,412 LOC** (audit said 1,412).

The dirty diff is **making the policies.rs / response_actions.rs god-files materially bigger** even as the audit recommends decomposing them.

#### HIGH — five duplicate bridge mains
- `crates/bridges/tetragon-bridge/src/main.rs:124-196` ⇒ ~70-line supervise loop, unchanged.
- `crates/bridges/hubble-bridge/src/main.rs:123-195` ⇒ verbatim copy of same loop, unchanged.
- `crates/bridges/auditd-bridge/src/main.rs:125-197` ⇒ verbatim copy, unchanged.
- `crates/bridges/k8s-audit-bridge/src/main.rs:116-` ⇒ verbatim copy, unchanged.
- `crates/bridges/darwin-telemetry-bridge/src/main.rs:138-214` ⇒ verbatim copy, unchanged. (Also has extra macOS-only branch at line 225 with another `eprintln!("darwin-telemetry-bridge is only supported on macOS")`.)

#### HIGH — registry binds 0.0.0.0:3100 / allows empty key
- `crates/services/clawdstrike-registry/src/config.rs:26, 41, 42` ⇒ unchanged.

#### HIGH — hush-cli `main.rs` is 3,238 lines
- `crates/services/hush-cli/src/main.rs` ⇒ still **3,238 lines** (audit said 3,238 — exact). The `async fn run` dispatcher starts at line 1460:
  ```rust
  async fn run(cli: Cli, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
  ```
  Combined with the `enum Commands` declaration at line 165 and the long sequence of `#[derive(Subcommand)]` enums, that confirms the audit's "3,238 lines = declared command shapes + 1,500-line run() dispatcher" structure.
- The working tree only touched `crates/services/hush-cli/src/pkg_cli.rs` (a refactor of two `if let`/branch patterns into match-guard form at lines 1003-1017). No commits decomposing `main.rs`.

### MEDIUM findings — all still valid

#### MEDIUM — three crypto stacks in hushd
- `crates/services/hushd/Cargo.toml:71-73` ⇒ still depends on:
  ```
  71: openssl.workspace = true
  72: rust-xmlsec.workspace = true
  73: resvg = { version = "0.45.1", default-features = true }
  ```
- Direct `ring = "0.17"` and `rustls = { … features = ["ring"] }` also still present (per audit; no commits touched Cargo.toml's `[dependencies]` block this week).
- SAML signature verification continues to drag `openssl` + `rust-xmlsec` (which wraps `libxmlsec1`) into the dependency closure.

#### MEDIUM — `resvg` in a security daemon
- `crates/services/hushd/Cargo.toml:73` ⇒ `resvg = "0.45.1", default-features = true` unchanged.
- `crates/services/hushd/src/api/certification.rs:971-984` ⇒ certification.rs still 2,109 LOC; the badge rasterizer block has not been carved out.

#### MEDIUM — `tokio::spawn` without join in `AppState::new`
- `crates/services/hushd/src/state.rs:416-424` ⇒ unchanged. Verified literal block (line shifted from audit's 417 to 416 because of internal reflows):
  ```rust
  let shutdown = Arc::new(Notify::new());

  // Spawn the heartbeat reaper for presence tracking
  {
      let hub_for_reaper = presence_hub.clone();
      let shutdown_for_reaper = shutdown.clone();
      tokio::spawn(async move {
          crate::api::presence::spawn_heartbeat_reaper(hub_for_reaper, shutdown_for_reaper)
              .await;
      });
  }
  ```
- The spawn returns no `JoinHandle`. There IS a separate `threat_intel_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>` field at line 82 of `state.rs`, which shows a clear pattern for joining background tasks; the heartbeat reaper does not opt in. `state.rs` is **693 LOC**.

#### MEDIUM — brokerd admin auth disabled when `admin_token` is None
- `crates/services/clawdstrike-brokerd/src/api.rs:193-210` ⇒ unchanged. The line 96-98 in `config.rs` filters empty/whitespace tokens to `None`, which then triggers the no-op branch — a configurable footgun.

#### MEDIUM — brokerd `main.rs` has no graceful shutdown
- `crates/services/clawdstrike-brokerd/src/main.rs:1-17` ⇒ still 17 lines, unchanged:
  ```rust
  #[tokio::main]
  async fn main() -> anyhow::Result<()> {
      tracing_subscriber::fmt::init();

      let config = Config::from_env()?;
      let listen = config.listen.parse::<SocketAddr>()?;
      let state = AppState::from_config(config)?;
      let listener = tokio::net::TcpListener::bind(listen).await?;

      tracing::info!(addr = %listen, "clawdstrike-brokerd listening");
      axum::serve(listener, create_router(state)).await?;
      Ok(())
  }
  ```
- No `.with_graceful_shutdown(...)`, no `tokio::signal::ctrl_c`, no SIGTERM trap. Verified `grep -n with_graceful_shutdown` returns no hits in the file.
- Compare with `hushd/src/cli.rs:266-310` which builds a `shutdown_signal` future and calls `.with_graceful_shutdown(shutdown_signal)` on the axum serve — the brokerd should mirror this pattern.

#### MEDIUM — `#[allow(dead_code)]` blanket at control-api crate root
- `crates/services/control-api/src/main.rs:1-3` ⇒ unchanged:
  ```
  #![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
  // Scaffold crate: many types/services are defined but not yet fully wired into routes.
  #![allow(dead_code)]
  ```

#### MEDIUM — JetStream consumer fixed-1s retry, no backoff
- `crates/services/control-api/src/services/agent_heartbeat_consumer.rs:79` ⇒ unchanged. Still `tokio::time::sleep(std::time::Duration::from_secs(1)).await;`.
- `crates/services/control-api/src/services/approval_request_consumer.rs:65` ⇒ unchanged.
- `crates/services/control-api/src/services/audit_consumer.rs:74` ⇒ unchanged.
- `crates/services/control-api/src/services/hunt_event_consumer.rs:84` ⇒ unchanged.
- Verified by `grep -nE 'tokio::time::sleep.*secs\(1\)' crates/services/control-api/src/services/*.rs` returning exactly those four hits.
- Recommendation: extract `nats_consumer_retry` helper with exponential backoff + jitter + cap. Still trivially small — one new helper, four call-site swaps.

#### MEDIUM — no request-id propagation
- `crates/services/control-api/src/main.rs:308-310` ⇒ still only `TraceLayer::new_for_http()` + `CorsLayer::permissive()`. No `SetRequestIdLayer`, no `PropagateRequestIdLayer`.
- `crates/services/hushd/src/api/mod.rs` (~554 LOC) ⇒ verified `tower_http::request_id` not imported.

#### MEDIUM — registry has no library, no graceful shutdown
- `crates/services/clawdstrike-registry/src/main.rs:48` ⇒ unchanged: `axum::serve(listener, app.into_make_service()).await?;`.
- No `lib.rs` carved out; both `clawdstrike-registry` and `clawdstrike-audit-monitor` binaries still owned by the same `main.rs` + `bin/audit-monitor.rs` package.

#### MEDIUM — `eprintln!` in five bridges for unknown event types
- `crates/bridges/tetragon-bridge/src/main.rs:117` ⇒ `eprintln!("warning: unknown event type '{other}', ignoring");`
- `crates/bridges/hubble-bridge/src/main.rs:116` ⇒ `eprintln!("warning: unknown verdict '{other}', ignoring");`
- `crates/bridges/auditd-bridge/src/main.rs:118` ⇒ `eprintln!("warning: unknown event type '{other}', ignoring");`
- `crates/bridges/k8s-audit-bridge/src/main.rs:116` ⇒ `eprintln!("warning: unknown verb '{other}', ignoring");`
- `crates/bridges/darwin-telemetry-bridge/src/main.rs:131` ⇒ `eprintln!("warning: unknown event type '{t}', ignoring");`
- Plus a bonus `eprintln!` at `darwin-telemetry-bridge/src/main.rs:225` ("darwin-telemetry-bridge is only supported on macOS") inside the cfg-gated non-macOS fallback.
- All five run *after* `tracing_subscriber::fmt::init()` succeeds. The fix is fully captured by extracting `bridge_runtime::run_bridge` (item 3 in execution plan).

#### MEDIUM — admin endpoints bind `0.0.0.0:2112` with no auth
- `crates/bridges/tetragon-bridge/src/main.rs:69-70` ⇒ `#[arg(long, default_value = "0.0.0.0:2112", env = "ADMIN_LISTEN_ADDR")] admin_listen_addr: String,`. Same in `lib.rs:96`.
- `crates/bridges/hubble-bridge/src/main.rs:66`; `lib.rs:92` ⇒ unchanged.
- `crates/bridges/auditd-bridge/src/main.rs:65`; `lib.rs:96` ⇒ unchanged.
- `crates/bridges/k8s-audit-bridge` ⇒ the `admin_listen_addr` declaration was migrated into the shared `bridge_runtime` clap fragment but still defaults to `0.0.0.0:2112`.
- `crates/bridges/darwin-telemetry-bridge/src/main.rs:54`; `lib.rs:129` ⇒ unchanged.
- All five bridges expose `/healthz`, `/readyz`, `/metrics` on *all* interfaces by default. Prometheus scrape data leaks pod/namespace cardinality.

#### MEDIUM — outbox path defaults to `/tmp/`
- `crates/bridges/tetragon-bridge/src/lib.rs:98, 181` ⇒ `outbox_path: Some("/tmp/tetragon-bridge-outbox.db".to_string())`. Unchanged.
- `crates/bridges/hubble-bridge/src/lib.rs:94, 177` ⇒ `outbox_path: Some("/tmp/hubble-bridge-outbox.db".to_string())`. Unchanged.
- `crates/bridges/auditd-bridge/src/lib.rs:98, 181` ⇒ `outbox_path: Some("/tmp/auditd-bridge-outbox.db".to_string())`. Unchanged.
- `crates/bridges/k8s-audit-bridge/src/lib.rs:100, 183` ⇒ `outbox_path: Some("/tmp/k8s-audit-bridge-outbox.db".to_string())`. Unchanged.
- `crates/bridges/darwin-telemetry-bridge/src/lib.rs:131, 224` ⇒ `outbox_path: Some("/tmp/darwin-telemetry-bridge-outbox.db".to_string())`. Unchanged.
- On Linux with `tmpfs`-backed `/tmp`, every reboot loses the outbox queue. On Darwin `/tmp` is real disk but `launchctl`'s reaper may still purge.

#### MEDIUM — no OpenAPI / typed-route generation
- No commits since audit added `utoipa`, `aide`, or `okapi` (workspace `Cargo.toml` unchanged). Still hand-rolled.

#### MEDIUM — 49 untracked `tokio::spawn` sites
- Re-counted: `grep -rnE 'tokio::spawn' crates/services/ crates/bridges/ --include='*.rs' | wc -l` ⇒ **49** (exact match to audit). No new spawn sites in the working tree.

#### MEDIUM — hush-cli default signing key path is cwd-relative
- `crates/services/hush-cli/src/main.rs:203` ⇒ unchanged: `#[arg(long, default_value = "clawdstrike.key")]`.

#### MEDIUM — spine-cli `--verbose` is a no-op
- `crates/services/spine-cli/src/main.rs:28` declares `verbose: bool`; `main()` at line 27 onward does not initialize `tracing_subscriber`. `grep -n 'tracing_subscriber\|tracing::' crates/services/spine-cli/src/main.rs` returns no hits for fmt::init.

### LOW findings — all still valid

#### LOW — `println!` in `hushd::cli::check_status`
- `crates/services/hushd/src/cli.rs:373-379` ⇒ unchanged (verified via cli.rs total 408 LOC matches audit).

#### LOW — brokerd `--config` flag is missing
- `crates/services/clawdstrike-brokerd/src/main.rs:1-17` ⇒ 17 lines, env-only config. Unchanged.
- The CLI accepts `clap::Parser` *nowhere* — `Config::from_env()` is the only configuration surface. Audit's recommendation (`--config path`, `--show-config`, env vars as overrides) still pending.

#### LOW — hushd `Status` URL hardcoded
- `crates/services/hushd/src/cli.rs:111` ⇒ `#[arg(default_value = "http://127.0.0.1:9876")]` unchanged.
- Two-place rule still violated: `crates/services/hushd/src/config.rs::default_listen` says `"127.0.0.1:9876"` literally.

#### LOW — `clippy::unwrap_used / expect_used` cfg(test) bypass inconsistency
- `crates/services/control-api/src/main.rs:1`, `crates/services/hushd/src/lib.rs:1`, `crates/services/hush-cli/src/main.rs:1`, `crates/services/clawdstrike-registry/src/main.rs:1`, `crates/services/clawdstrike-brokerd/src/lib.rs:1` all use the crate-wide `#![cfg_attr(test, allow(...))]` form. Note: `integration_tests.rs:1` explicitly opens with `#![allow(clippy::duplicate_mod, clippy::expect_used, clippy::unwrap_used)]` — the per-module style audit recommended ironically appears only here.

#### LOW — Token-rotation grace pair never deduplicated (wave-3 cross-ref)
- This is an agent-side finding (`apps/agent/src-tauri/src/api_server.rs:18945, 18971`) and out of D04 scope, but worth noting: the wave-3 plan calls out `rotate_local_api_token_with_grace` and `rotate_local_api_token_without_grace` as sibling functions that should be one parameterized fn. Same surgery in `hushd::api::session` would benefit from the same pattern.

## FIXED SINCE 2026-05-23

**Zero substantive fixes.** None of the items the audit identified have been resolved at HEAD or in the working tree. The closest the working tree comes to fixing audit findings:

- **Two clippy noise refactors** (tetragon-bridge `mapper.rs` & hushd `policy_scoping/mod.rs`): pure if/else→match-guard collapses with no behavior change. Not on the audit's radar.
- **Sort-comparator simplifications** (`hushd/api/broker.rs:1466,1531` and `broker_state.rs:160,193,275`, `control-api/services/delegation_graph.rs:1114,1480`): six `sort_by(|left, right| right.x.cmp(&left.x))` patterns replaced with `sort_by_key(|r| std::cmp::Reverse(r.x))`. Idiomatic improvement, no audit relevance.
- **hush-cli/pkg_cli.rs** refactor of `validate_pack_contents` (lines 1003-1017): collapsed `match X { Y => if cond { return Err(...) } }` into `match X { Y if cond => return Err(...) Y => {} }`. Cosmetic only.

None of these touch the security defaults, persistence, god-files, eas-anchor, duplicate bridges, audit-monitor `eprintln!`, or the brokerd `OperatorState`.

## NOW WRONG / MISDIAGNOSED

### Audit said control-api `main.rs` is 336 lines — actual is 484
- `crates/services/control-api/src/main.rs` ⇒ **484 LOC** at HEAD (verified by `wc -l`).
- The git history shows no commits to this file since well before the audit (`git log` for the file ends at `ce7a85ba5` which predates audit by months). Conclusion: the audit miscounted, likely by reading only the `async fn run` body and excluding the test module + imports + helpers.
- **Impact on Finding "control-api main.rs is 336 lines":** The thrust is unchanged — it is still inline orchestration, still six tokio::spawn blocks, still six hand-rolled channels — and 484 lines for what should be a ~50-line entrypoint is *worse* than the audit suggested, not better. Rewrite-into-`ServiceSupervisor` recommendation stands; size delta makes it more urgent.

That is the only LOC the source audit got wrong. Every other counted file (hush-cli 3,238; policies.rs 3,153; integration_tests.rs 11,377 — wait, 11,377 is the working-tree value; HEAD = 11,146; the audit cited 11,377 which matches the working tree, so the audit ran against the dirty index, not HEAD) matched within ±1 line.

## NEW ISSUES

### NEW 1 — Working tree's `validate_endpoint_ack_signed_receipt` performs a DB lookup unconditionally before guard returns

- **Where:** `crates/services/control-api/src/routes/response_actions.rs` (working tree, inserted ~lines 908-970 of the diff).
- **What:** The new `validate_endpoint_ack_signed_receipt` async fn starts with:
  ```rust
  if !requires_endpoint_ack_signed_receipt(&context.action, ack) {
      return Ok(());
  }
  let public_key_hex = sqlx::query_scalar::query_scalar::<_, String>(
      r#"SELECT public_key FROM agents WHERE tenant_id = $1 AND agent_id = $2"#,
  )
  ```
  Good: the guard does come first. But the function is unconditionally `await`ed from both `record_ack` (line 562) and `record_agent_ack` (line 586) inside an open `Transaction<'_, sqlx_postgres::Postgres>`. When `requires_endpoint_ack_signed_receipt` returns false (which is the common case for non-endpoint targets and for `PolicyRuleDiffValidation` action types), the call is harmless — but the call site already holds an open transaction (`tx`) at that point. The added function is fine; the issue is that holding the tx open across the call is fine *now* (early return is cheap) but creates a foot-gun if the guard is ever modified to do work before the early return.
- **Why it matters:** Defensible as-is; flag for review when callers (notably `policy_rule_diff_validation` flows) start sharing this validator more broadly.
- **Severity:** LOW (working-tree only).
- **Recommended action:** DOCUMENT (`// note: caller holds a transaction; keep the guard return path zero-await`). Not a blocker.

### NEW 2 — `distribute_active_policy_to_fleet` per-agent sequential `await`

- **Where:** `crates/services/control-api/src/routes/policies.rs:1663-1710` (still in HEAD code; the working tree change at line 297-305 just plumbs a `Uuid::new_v4()` deployment id through). Specifically:
  ```rust
  for agent_id in &agent_ids {
      if let Err(err) = policy_distribution::reconcile_effective_policy_for_agent(
          &state.db,
          &state.nats,
          tenant_id,
          agent_id,
      )
      .await {
          kv_write_failures += 1;
          tracing::warn!(...);
      }
  }
  ```
- **What:** The loop awaits each KV write one at a time, holding a connection from `state.db` for the duration. With N agents and average reconcile time T, total deploy cost is N·T. A 5,000-endpoint tenant means ~5,000 sequential NATS KV operations under the response future.
- **Why it matters:** Per-agent latency blows out deploy time, prolongs the HTTP response to `POST /api/v1/policies/deploy`, and pegs one connection from the pool. Bookkeeping is wrong (the per-agent loop counts `kv_write_failures` only — there's no "failed agent" list, no per-agent dispatch ID, no NATS publish-retry budget).
- **Severity:** MEDIUM (not in original audit; surfaced by tracing the working-tree `deployment_id: Uuid::new_v4()` plumbing back to the consumer).
- **Recommended action:** RESTRUCTURE — wrap each `reconcile_effective_policy_for_agent` in a `JoinSet` (or `futures::stream::iter(...).for_each_concurrent(16, …)`) with a concurrency cap matching the connection pool size. Capture per-agent failures in a structured `Vec<PolicyDeployFailure>` for the response, not a single counter.
- **Effort:** small.

### NEW 3 — Working tree growth makes policies.rs / response_actions.rs *larger* mid-audit

- **Where:** `crates/services/control-api/src/routes/policies.rs` (+568 lines uncommitted), `crates/services/control-api/src/routes/response_actions.rs` (+223 lines uncommitted), `crates/services/control-api/src/integration_tests.rs` (+231 lines uncommitted).
- **What:** Three of the audit's HIGH "route god-files" findings are being made *worse* by the dirty diff, not better. The new code adds:
  - `reserve_policy_rule_diff_dispatch`, `policy_rule_diff_expected_proposed_policy`, `latest_policy_rule_diff_receipts_by_endpoint`, `required_policy_rule_diff_impact_u64`, `ensure_policy_proposal_deployable_impact`, `fetch_policy_proposal_row_for_update`, and three new tests in `policies.rs`.
  - `validate_endpoint_ack_signed_receipt`, `requires_endpoint_ack_signed_receipt`, `validate_endpoint_ack_receipt_contract`, and a test fixture builder in `response_actions.rs`.
- **Why it matters:** Land-as-is and these god-files grow toward 3.7k and 3.0k LOC respectively — past the threshold the audit already flagged. The new helpers are domain-specific (fleet rule-diff dispatch reservation, endpoint ack signed-receipt verification) and would fit naturally in submodules. The fact that they're piling onto the same files indicates the team has not adopted the audit's RESTRUCTURE recommendation yet.
- **Severity:** HIGH (process-quality finding).
- **Recommended action:** Before committing the working tree, lift the new functions into `routes/policies/fleet_rule_diff.rs` and `routes/response_actions/endpoint_ack_receipt.rs` so the dirty changes ride on top of the audit-recommended split instead of contradicting it.
- **Effort:** medium.

### NEW 4 — control-api `CorsLayer::permissive()` contrasts with hushd's careful CORS handling

- **Where:** `crates/services/control-api/src/main.rs:310` vs `crates/services/hushd/src/api/mod.rs:75-103`.
- **What:** `hushd` already has a *correct* CORS layer pattern (fail-closed empty list, dedicated `AllowOrigin::any` for explicit `*`, panic-avoidance for tower-http quirks, warn log when CORS is enabled but no origins are configured). `control-api` instead applies `CorsLayer::permissive()` to *everything*. The two services share a maintainer base and a workspace — the better pattern is sitting one directory over.
- **Why it matters:** The fix for the original audit's CRITICAL #2 is literally already implemented in this repo; it just needs to be reused.
- **Severity:** MEDIUM (process-quality observation, but cleanly maps to a small action).
- **Recommended action:** Lift `hushd::api::create_router`'s CORS-builder block into a shared `tower_http_extras::cors_from_config` (or even just copy it into control-api). Then delete `CorsLayer::permissive()`.
- **Effort:** trivial (15 minutes once copy-paste-style).

### NEW 5 — `tetragon-bridge::mapper.rs` working-tree change is purely clippy noise but reveals an under-tested area

- **Where:** `crates/bridges/tetragon-bridge/src/mapper.rs:191-205` (working tree).
- **What:** Two `proto::kprobe_argument::Arg::PathArg(path) => { if SENSITIVE_PATHS.iter().any(|s| path.path.starts_with(s)) { return Severity::Critical; } }` arms collapsed into match-guard form. Logic identical.
- **Why it matters:** The `SENSITIVE_PATHS` constant is the threat-classification anchor for kprobe events; changes to its surrounding match in `classify_kprobe_severity` would benefit from a property/fuzz test that asserts the post-refactor branch behaviour is byte-identical to pre-refactor. The audit didn't flag this; the dirty diff reveals it's currently covered by clippy lints alone.
- **Severity:** LOW (defensive observation).
- **Recommended action:** DOCUMENT. Future severity-classifier changes should include a small fixture-table test in `crates/bridges/tetragon-bridge/tests/severity_classification.rs`.

## Bridge cross-cutting state — fully verified

The bridge family's shared issues collapse to a single shared refactor:

| Bridge | LOC | `/tmp/X-bridge-outbox.db` | `0.0.0.0:2112` admin | `eprintln!` | Verbatim ~200-line main loop | Duplicate of `tetragon-bridge::main.rs` |
| ------ | --- | ------------------------- | -------------------- | ----------- | ---------------------------- | --------------------------------------- |
| tetragon-bridge | 1,167 | yes (`lib.rs:98,181`) | yes (`main.rs:69`, `lib.rs:96`) | yes (`main.rs:117`) | yes (`main.rs:124-196`) | n/a (canonical) |
| hubble-bridge | 1,163 | yes (`lib.rs:94,177`) | yes (`main.rs:66`, `lib.rs:92`) | yes (`main.rs:116`) | yes (`main.rs:123-195`) | yes |
| auditd-bridge | 1,811 | yes (`lib.rs:98,181`) | yes (`main.rs:65`, `lib.rs:96`) | yes (`main.rs:118`) | yes (`main.rs:125-197`) | yes |
| k8s-audit-bridge | 1,262 | yes (`lib.rs:100,183`) | yes (uses shared `bridge_runtime`) | yes (`main.rs:116`) | yes | yes |
| darwin-telemetry-bridge | 3,205 | yes (`lib.rs:131,224`) | yes (`main.rs:54`, `lib.rs:129`) | yes (`main.rs:131, 225`) | yes (`main.rs:138-214`) | yes |

**Single refactor opportunity:** extract `bridge_runtime::run_bridge<B: Bridge>(config) -> !` and `bridge_runtime::default_state_dir() -> PathBuf` and `bridge_runtime::default_admin_listen_addr() -> SocketAddr` (=`127.0.0.1:2112`). The five main.rs files collapse to ~25 lines each (clap parse + call). All 4 cross-cutting findings (5 duplicate mains, eprintln!, admin bind, outbox path) resolve in one PR.

---

## hushd: per-finding verification summary

The audit gave hushd a `5/10` service quality score. Each enumerated finding holds:

| Finding | Location | Concrete evidence at HEAD |
| ------- | -------- | ------------------------- |
| Auth defaults to off | `config.rs:97-107` | `#[serde(default)] pub enabled: bool` (false) |
| Auth middleware shortcut | `auth/middleware.rs:50-58` | early-return `if !state.auth_enabled() { ... }` |
| Scope middleware shortcut | `auth/middleware.rs:104-108` | early-return `let Some(actor) = ... else { return Ok(...) }` |
| Webhook delivery dropped on SIGTERM | `certification_webhooks.rs:68` | `tokio::spawn(async move { ... })` with no JoinHandle |
| `clawdstriked` vanity binary | `bin/clawdstriked.rs` | 5 lines: `hushd::cli::run_bin("clawdstriked")` |
| Three rate limiters | `rate_limit.rs` (502), `v1_rate_limit.rs` (246), `identity_rate_limit.rs` (206) | 954 LOC across 3 files |
| Three crypto stacks | `Cargo.toml:55-73` | `ring`, `rustls/ring`, `openssl`, `rust-xmlsec`, `resvg` |
| `resvg` in daemon | `Cargo.toml:73` | `resvg = "0.45.1", default-features = true` |
| `tokio::spawn` orphan task | `state.rs:416-424` | heartbeat reaper spawned with no JoinHandle |
| `println!` in CLI status | `cli.rs:373-379` | intentional human-readable output (defensible LOW) |
| Status URL hardcoded | `cli.rs:111` | duplicates `config.rs::default_listen` literal |

What hushd does *right* (per audit and re-verified):

- `cli.rs:23-62, 389-407` IPv6-aware listen-address parsing with unit tests.
- `cli.rs:218-262` SIGHUP for policy reload + systemd notify/watchdog.
- `cli.rs:266-310` proper `with_graceful_shutdown(shutdown_signal)` over ctrl-c.
- `tls.rs::handle_accept_error` with thoughtful error classification.
- `api/mod.rs:75-103` correct CORS allow-list (fail-closed empty list, dedicated `AllowOrigin::any` for `*`).
- `auth/middleware.rs:50-89` API key + OIDC JWT dual auth with extension propagation.
- `api/mod.rs:107-456` route grouping by `public` / `v1_public` / `read` / `check` / `admin` / `ws` / `presence_ticket` with `.route_layer(scope_layer(Scope::X))`.

The "ship it once auth defaults are fixed" pattern is clear: hushd is one config-default change away from being a defensible production daemon.

---

## clawdstrike-brokerd: per-finding verification summary

The audit gave brokerd a `8/10` (cleanest binary in the workspace), which holds despite the persistence gap. Re-verified:

- **`src/main.rs`** = 17 lines (audit said 17). Loads config, builds state, binds, serves. No `with_graceful_shutdown` (still a defect). No `--config` flag (still a defect).
- **`src/api.rs:179-188`** `constant_time_eq` (audit's "things to leave alone"). Verified literal:
  ```rust
  fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
      if a.len() != b.len() {
          return false;
      }
      let mut acc = 0u8;
      for (x, y) in a.iter().zip(b.iter()) {
          acc |= x ^ y;
      }
      acc == 0
  }
  ```
- **`src/api.rs:193-210`** `require_admin_auth` — verified no-op on `None`:
  ```rust
  let expected = match state.config.admin_token.as_deref() {
      Some(token) => token,
      None => return Ok(()), // No token configured — auth disabled.
  };
  ```
- **`src/config.rs:96-119`** loader filters empty/whitespace admin tokens to `None`, then 109-119 rejects empty trusted-key sets and zero TTLs. Half good (fail-closed on the latter), half bad (the admin-token half-trip becomes a security default footgun).
- **`src/operator.rs:1-28`** the RAM-only ledger documented under CRITICAL above.
- **`src/api.rs`** ApiError type (audit's "things to leave alone") — verified consistent JSON shape via `tracing::error!` instrumentation at lines 755, 790, 820, 895, 922.

What brokerd does *right* and the audit said to leave alone:

- `ApiError` discriminated `(status, code, message)` with `IntoResponse`.
- `constant_time_eq` admin-token comparator.
- `Config::from_env` validation (rejects empty trusted-key sets, zero TTLs).
- 17-line `main.rs` (no orchestration sprawl).

---

## control-api: per-finding verification summary

The audit gave control-api a `5/10` (beta — many TODOs, broad surface). Verified:

- **`src/main.rs`** = 484 LOC (audit said 336 — see "NOW WRONG" section).
- **`src/config.rs:59-61`** insecure default `LISTEN_ADDR = "0.0.0.0:8080"`.
- **`src/main.rs:310`** insecure `.layer(CorsLayer::permissive())`.
- **`src/integration_tests.rs`** = 11,377 LOC in `src/` (audit said 11,377 — exact match with working tree, so audit ran against the dirty index).
- **`src/main.rs:3`** `#![allow(dead_code)]` blanket with the "Scaffold crate" comment.
- **`src/main.rs:104-130, 132-154, 156-197, 199-211, 213-254, 256-306`** six manually-spawned background workers, each a copy-paste block.
- **`src/main.rs:308-310`** only `TraceLayer::new_for_http()` — no `SetRequestIdLayer` / `PropagateRequestIdLayer`.
- **`src/services/agent_heartbeat_consumer.rs:79`, `approval_request_consumer.rs:65`, `audit_consumer.rs:74`, `hunt_event_consumer.rs:84`** four sites of `tokio::time::sleep(Duration::from_secs(1))` retry, no jitter.
- **`src/routes/policies.rs:3153`** god-file (will be 3,721 after working tree commits).
- **`src/routes/response_actions.rs:2740`** god-file (will be 2,963).
- **`src/routes/agents.rs:1745`** god-file.

What control-api does *right* (per audit and re-verified):

- JetStream consumers use `tokio::sync::watch` shutdown channels rather than `JoinHandle::abort` (verified in `agent_heartbeat_consumer.rs`, `approval_request_consumer.rs`, `audit_consumer.rs`, `hunt_event_consumer.rs`).
- All four consumers emit `Acknowledge::after_processing` semantics.
- `#[serde(deny_unknown_fields)]` is pervasive on serde structs (verified across `models/`, `routes/dto.rs` patterns).
- `ApiError` enum with `IntoResponse` (the audit's "error handling: 7/10" applies; verified working-tree additions like `ApiError::BadRequest` / `ApiError::Database` / `ApiError::Internal` follow the same shape).

---

## AGGRESSIVE EXECUTION PLAN (top-5)

The user is in code-cleanup mode with an AGGRESSIVE ceiling. Here is the top-5 ranking by ratio of (security/operational risk eliminated) ÷ (engineering hours), under the assumption that "delete eas-anchor entirely" and "rewrite hushd auth defaults" are both on the table.

### 1. Flip the four insecure defaults in one commit (1 hour, eliminates 4 CRITICALs)

A single coordinated commit (`fix(services): require explicit insecure defaults`) touches:

- `crates/services/hushd/src/config.rs:97-107` — change `#[serde(default)] pub enabled: bool` to `pub enabled: AuthMode` (`enum AuthMode { Required, ApiKey, Oidc, Disabled }`) and have `impl Default for AuthConfig` return `AuthMode::Required`. Refuse to start if `Required` and both `api_keys.is_empty()` and `identity` is None.
- `crates/services/hushd/src/auth/middleware.rs:50-58` — delete the `if !state.auth_enabled() { return Ok(next.run(req).await); }` shortcut. Replace with explicit dispatch on `AuthMode`.
- `crates/services/control-api/src/config.rs:59-61` — change default to `"127.0.0.1:8080"`. Add a new `CORS_ALLOWED_ORIGINS` env var (mandatory, no default).
- `crates/services/control-api/src/main.rs:308-310` — replace `CorsLayer::permissive()` with a parsed allow-list.
- `crates/services/clawdstrike-registry/src/config.rs:26, 41-42` — default `host` to `"127.0.0.1"`; reject empty `api_key` unless `allow_insecure_no_auth = true`.
- `crates/services/clawdstrike-brokerd/src/api.rs:193-197` — make admin token mandatory unless `CLAWDSTRIKE_BROKERD_DISABLE_ADMIN_AUTH=true` is set (and log `tracing::warn!` on every admin request when disabled).

Breaks Docker-Compose examples (acceptable cost) and N integration tests that omit the auth setup (~15-30 tests). Each test fix is a one-line `auth.enabled = AuthMode::Disabled` or `CorsLayer::permissive()` opt-in inside `#[cfg(test)]`.

**Ratio: ~30 LOC of code change, 4 CRITICALs gone, ~1-3 hours.**

### 2. Delete `eas-anchor` entirely (15 minutes, eliminates 1 CRITICAL + 1124 LOC of dead weight)

- Remove `crates/services/eas-anchor` from `Cargo.toml` workspace members.
- `git rm -r crates/services/eas-anchor`.
- Update `docs/` to remove eas-anchor references.
- If anchoring is genuinely on the roadmap, move what exists into `examples/eas-anchor-stub/` with a README that says "this is a sketch; do not deploy".

The published `Cargo.toml` already says `publish = false` (per audit), so this has zero external impact. The binary cannot do its only job; deleting is strictly correct.

**Ratio: 1124 LOC deleted, 1 misleading service gone, 15 minutes.**

### 3. Extract `bridge_runtime::run_bridge` and fix all five bridge mains (3 hours, fixes 4 findings)

- Add `pub async fn run_bridge<B: Bridge + Send + 'static>(config: B::Config) -> !` into `bridge_runtime`. Body is the existing reconnect loop (with one bug fix: replace `eprintln!` with `tracing::warn!`).
- Reduce each of the five `crates/bridges/*/src/main.rs` files to a ~25-line clap parse + `bridge_runtime::run_bridge::<MyBridge>(config).await`.
- While in each file, change `default_value = "0.0.0.0:2112"` → `"127.0.0.1:2112"`, change `outbox_path: Some("/tmp/X-bridge-outbox.db")` → `outbox_path: Some(default_state_dir().join("X-bridge/outbox.db"))`.

Single PR eliminates: Finding "five duplicate main.rs", Finding "eprintln! warnings", Finding "admin bind 0.0.0.0", Finding "outbox /tmp default". That is **4 audit findings in one mechanical refactor**.

**Ratio: ~600 LOC deleted, 4 findings cleared, 3 hours.**

### 4. Persist `clawdstrike-brokerd::OperatorState` to SQLite (1 day, fixes 1 CRITICAL)

- Add `rusqlite` (already a workspace dep) to `clawdstrike-brokerd/Cargo.toml`.
- Create `crates/services/clawdstrike-brokerd/src/operator/sqlite.rs` with `Capabilities`, `Executions`, `Revocations`, `Freezes`, `TimelineEvents` tables.
- Add `OperatorState::from_db(path: &Path)` that rehydrates state on boot.
- Wire writes through both the in-memory `BTreeMap` (for fast reads) and the SQLite store (for durability).
- Add a `--db-path` flag to `main.rs` (default: `$XDG_STATE_HOME/clawdstrike/brokerd/state.db`).

This is the single biggest "product feature lost on restart" hole in the audit; the broker is the new product line.

**Ratio: ~500 LOC added, 1 CRITICAL gone, 1 day.**

### 5. Split `routes/policies.rs` and `routes/response_actions.rs` into per-domain submodules (1-2 days, fixes 1 HIGH + unblocks future work)

Before this lands, the working-tree growth gets folded into the new layout (per NEW 3 above). After:

- `crates/services/control-api/src/routes/policies/` containing `mod.rs`, `list.rs`, `proposals.rs` (with `dispatch.rs`, `collection.rs` for fleet rule-diff), `deploy.rs`, `validate.rs`. Each file 300-600 LOC.
- `crates/services/control-api/src/routes/response_actions/` containing `mod.rs`, `list.rs`, `record_ack.rs`, `endpoint_ack_receipt.rs`. Each file 300-600 LOC.

Land the dirty diff *into* this new layout rather than on top of the monolithic files. Sets the pattern for `hushd::api::broker.rs` (next target, also a 2,538 LOC god-file).

**Ratio: ~5,900 LOC redistributed, 1 HIGH gone, sets pattern for 3 more god-files, 1-2 days.**

## AGGRESSIVE-Ceiling Alternatives (explicitly on the table per user brief)

The user said the ceiling is "AGGRESSIVE — deleting eas-anchor entirely, splitting control-api routes, rewriting hushd auth all on the table." Spelling out what aggressive means for each option:

### Option AGG-1: Wipe `eas-anchor` from the workspace

**Action:**
```bash
# 1. Remove the crate
git rm -r crates/services/eas-anchor

# 2. Drop from Cargo workspace
# Edit Cargo.toml: remove "crates/services/eas-anchor" from [workspace.members]

# 3. Drop from CI matrix
# Edit .github/workflows/*.yml: remove any eas-anchor-specific build steps

# 4. Drop from docs
# Edit docs/ and README.md to remove eas-anchor references
# (keep the "L2 anchoring is on the roadmap" note in PROJECT.md if relevant)
```

**Cost:** ~1,124 LOC src deleted; ~30 LOC of Cargo/CI/doc changes; ~30 minutes total.

**Benefit:** Removes a "Chain submission not yet implemented" stub from the public-facing service list. Restores integrity of the audit-monitor service narrative ("we monitor transparency logs and anchor to EAS" → "we monitor transparency logs"). Aligns with `publish = false` in Cargo.toml.

**Risk:** If anchoring is a near-term roadmap item, the existing ABI encoding scaffolding (`encode_checkpoint_attestation` at lines 155-...) is genuinely useful and would have to be re-written. **Mitigation:** move to `examples/eas-anchor-stub/` instead of deleting outright.

**Verdict:** Recommend deletion-with-archive. Move to `archive/eas-anchor/` with a README "do not deploy — start here when reviving L2 anchoring".

### Option AGG-2: Rewrite hushd auth defaults (security-first)

**Action:** Replace `AuthConfig.enabled: bool` with `AuthConfig.mode: AuthMode`:
```rust
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AuthMode {
    Required,   // Default — fail to start if no auth source configured
    ApiKey,
    Oidc,
    Both,
    Disabled,   // Explicit opt-out; warns on every startup
}

impl Default for AuthMode { fn default() -> Self { AuthMode::Required } }

impl AuthConfig {
    pub fn validate(&self, identity: Option<&IdentityConfig>) -> Result<(), ConfigError> {
        match self.mode {
            AuthMode::Required => {
                let has_keys = !self.api_keys.is_empty();
                let has_idp = identity.is_some();
                if !has_keys && !has_idp {
                    return Err(ConfigError::AuthMissingSources);
                }
                Ok(())
            }
            AuthMode::ApiKey => { /* require non-empty api_keys */ }
            AuthMode::Oidc => { /* require identity.oidc */ }
            AuthMode::Both => { /* require both */ }
            AuthMode::Disabled => {
                tracing::warn!("hushd auth is explicitly disabled — do not deploy in production");
                Ok(())
            }
        }
    }
}
```

Delete the `if !state.auth_enabled() { return Ok(next.run(req).await); }` shortcut in `auth/middleware.rs`. Replace with explicit dispatch by `AuthMode`.

**Cost:** ~80 LOC of config changes, ~10 LOC of middleware change, ~15 test file updates.

**Benefit:** Out-of-the-box `hushd` rejects every unauthenticated request. "Default install on dev machine" becomes a deliberate `AuthMode::Disabled` decision with a warning log on every startup. Fixes audit CRITICAL #1.

**Risk:** Breaks every existing config file that omits the `auth:` block. **Mitigation:** ship a `tools/migrate-hushd-config.sh` that detects the old shape and adds `auth: { mode: disabled }` explicitly.

### Option AGG-3: Split control-api routes into per-domain submodules

**Action:**
```
crates/services/control-api/src/routes/
├── mod.rs
├── policies/
│   ├── mod.rs
│   ├── list.rs              # ~300 LOC: list, get
│   ├── proposals.rs         # ~600 LOC: proposal create/get/update/approve
│   ├── proposals/           # nested for the fleet rule-diff sub-flow
│   │   ├── mod.rs
│   │   ├── dispatch.rs      # ~400 LOC: reserve_policy_rule_diff_dispatch, etc.
│   │   ├── collection.rs    # ~500 LOC: collect_policy_rule_diff_ack_receipts, etc.
│   │   └── impact.rs        # ~300 LOC: required_policy_rule_diff_impact_u64, etc.
│   ├── deploy.rs            # ~400 LOC: deploy_policy + distribute_active_policy_to_fleet
│   └── validate.rs          # ~200 LOC
├── response_actions/
│   ├── mod.rs
│   ├── list.rs              # ~300 LOC
│   ├── record_ack.rs        # ~600 LOC
│   └── endpoint_ack_receipt.rs # ~500 LOC: validate_endpoint_ack_signed_receipt, etc.
└── ... (existing flat files: agents.rs, hunt.rs, cases.rs, alerts.rs, receipts.rs, etc.)
```

**Cost:** ~3,500 LOC moved. ~1-2 days.

**Benefit:** No more 3k-line route god-files. The working-tree feature additions (signed-receipt validation, fleet rule-diff dispatch reservation) land in dedicated submodules. Future feature work has a natural home.

**Risk:** Touches many imports. **Mitigation:** stage as multiple commits (Commit 1: scaffold the layout; Commit 2: move handlers; Commit 3: move tests; Commit 4: collapse `pub use` re-exports).

### Option AGG-4 (deeper): Promote `bridge_runtime` to a sibling top-level crate and reuse for hushd webhook outbox

**Action:** Move `bridge_runtime::SqliteOutbox` into a new `outbox-runtime` crate. Use it in `hushd::certification_webhooks` to replace the fire-and-forget `tokio::spawn`. Use it in any other service that does HTTP-out work (`control-api` integration delivery, `clawdstrike-registry` audit-monitor webhook).

**Cost:** Medium. The outbox surface is small (probably ~400 LOC); the cascade through `hushd`/`registry` is small. ~1 day.

**Benefit:** One outbox implementation, no service does fire-and-forget delivery anymore.

**Risk:** Cross-crate refactor changes import paths in many files; touch `Cargo.toml` workspace members.

---

## DEFER / OUT OF SCOPE

- **Crypto-stack consolidation (Medium, large)** — gating `openssl`/`rust-xmlsec` behind a `saml` feature flag is worth doing, but it is large (rewrite SAML signature verification on `rustls`/`ring` primitives) and the value-per-hour is far below items 1-5. Defer to a milestone with explicit FIPS/binary-size goals.
- **OpenAPI / utoipa adoption (Medium, large)** — high leverage but multi-week. Defer until the route god-files are split (item 5); otherwise utoipa adoption would land on top of unstructured handler files.
- **`JoinSet`-based task supervision (Medium, medium)** — 49 sites is a lot. Worth it but only after item 4 (brokerd persistence) and item 5 (route split) have shown the pattern in a single binary.
- **`hush-cli/src/main.rs` decomposition (High, large)** — 3,238 LOC is a multi-day surgical job touching every test that imports symbols from `main.rs`. Defer to a dedicated CLI overhaul; not on the critical path.
- **Webhook outbox in `hushd::certification_webhooks` (High, medium)** — should happen, but the audit's recommendation (lean on `bridge_runtime::SqliteOutbox`) requires moving `SqliteOutbox` out of `bridge_runtime` first, or duplicating it. Defer until either (a) `bridge_runtime` is split, or (b) someone is willing to write a copy of the outbox in `hushd` directly.
- **`hush-cli/src/main.rs` default signing key path move to `$XDG_DATA_HOME` (Medium, small)** — would defer unless paired with a broader CLI overhaul, since it changes user-visible behavior and breaks every getting-started guide that says `hush keygen`.
- **`hushd::resvg`/badge generator extraction (Medium, medium)** — defer until certification-badge volume justifies a dedicated service; cosmetic-yet-attack-surface concern, not on a hot operational path.
- **Three rate-limiter consolidation (High, medium)** — important architectural cleanup, but no security bug today. The three limiters work correctly and their composition is well-tested. Defer to the rate-limit-overhaul milestone.
- **`#[allow(dead_code)]` blanket removal in control-api (Medium, small-medium)** — would reveal real dead code worth deleting, but only after the route-split (item 5) since most dead code is in handler-helper drift. Sequence after item 5.
- **`integration_tests.rs` move into `tests/` (High, medium)** — important but mechanical; can be batched with item 5's route split because both touch the same files' visibility rules.

---

## Appendix A — Files in the working tree, audit-scope only

```
crates/bridges/tetragon-bridge/src/mapper.rs            16 lines, clippy refactor (NEW issue: none)
crates/services/control-api/src/config.rs                5 lines, clippy refactor (NEW issue: none)
crates/services/control-api/src/integration_tests.rs   245 lines added, proof-only proposal tests
crates/services/control-api/src/routes/policies.rs     568 lines added, fleet rule-diff plumbing (NEW 3)
crates/services/control-api/src/routes/response_actions.rs 223 lines added, signed-receipt verification (NEW 1)
crates/services/control-api/src/services/delegation_graph.rs 4 lines, sort_by_key idiomization
crates/services/control-api/src/services/policy_distribution.rs 98 lines added, executor-generic helpers
crates/services/hush-cli/src/pkg_cli.rs                 20 lines, match-guard refactor
crates/services/hushd/src/api/broker.rs                  4 lines, sort_by_key idiomization
crates/services/hushd/src/broker_state.rs                6 lines, sort_by_key idiomization
crates/services/hushd/src/policy_scoping/mod.rs         11 lines, match-guard refactor
```

Net working-tree state: **+1065 / -135 lines**, almost all of it adding feature surface (signed-receipt verification, fleet rule-diff dispatch reservation, transactional executor helpers, deployment-id propagation) without addressing any audit finding.

### Per-file behaviour notes

- **`crates/services/control-api/src/services/policy_distribution.rs`** — adds two executor-generic upsert variants (`upsert_active_policy_with_executor`, `upsert_active_policy_after_version_with_executor`) and an executor-generic fetch (`fetch_active_policy_by_tenant_id_with_executor`). The new `upsert_active_policy_after_version_with_executor` uses optimistic concurrency via `version = $5` predicate — that's good. The deprecated non-executor wrappers (`upsert_active_policy`, `fetch_active_policy_by_tenant_id`) are kept as thin call-through shells, so the breaking-change risk is minimized.

- **`crates/services/control-api/src/routes/response_actions.rs`** — adds `validate_endpoint_ack_signed_receipt` to record-ack flows. The new validator (a) loads the agent public key from the `agents` table, (b) canonicalizes the embedded `signedReceipt`, (c) enforces a 256 KiB cap, (d) calls `SignedReceipt::verify(&PublicKeySet::new(public_key))`, (e) verifies `localReceiptHash` matches `sha256(canonical_signed_receipt)`, (f) walks the receipt contract via `validate_endpoint_ack_receipt_contract` (not shown in inserted-only grep). This is real fail-closed verification — the kind of thing the source audit said was missing on the agent side. It's good code; it just lives in the wrong file (see NEW 3).

- **`crates/services/control-api/src/routes/policies.rs`** — adds the fleet rule-diff dispatch reservation pattern. The new `reserve_policy_rule_diff_dispatch` claims a row before dispatch (single-writer guard), then `fetch_policy_proposal_row_for_update` reads it under `FOR UPDATE` lock at commit time. The combination prevents double-dispatch races. The new `Uuid::new_v4()` plumbed through `distribute_active_policy_to_fleet` makes per-deployment idempotency keys available downstream.

- **`crates/services/control-api/src/integration_tests.rs`** — adds 231 lines of new tests, mainly covering proof-only proposals (`fleetRuleDiffValidation` with only a proof hash, no verified simulation receipt). Tests are well-structured assertion chains. No `#[ignore]` or `#[should_panic]` snuck in. Net cost: integration_tests grows from 11,146 to 11,377 LOC.

- **`crates/services/hushd/src/api/broker.rs`** + **`broker_state.rs`** — six sort comparator simplifications. No behaviour change; clippy upgrade. Adoption of `std::cmp::Reverse(...)` over `right.x.cmp(&left.x)` is idiomatic.

- **`crates/services/control-api/src/services/delegation_graph.rs`** — two `sort_by(|left, right| left.id.cmp(&right.id))` calls collapsed to `sort_by_key(|edge| edge.id)`. Same pattern; no behaviour change.

- **`crates/services/hushd/src/policy_scoping/mod.rs`** — match-guard refactor of `validate_policy_escalation`'s `"guards.secret_leak.patterns"` arm. Logic identical; arm-shape only.

- **`crates/services/hush-cli/src/pkg_cli.rs`** — match-guard refactor of `validate_pack_contents`'s `PkgType::Guard` and `PkgType::Bundle` branches. Logic identical.

- **`crates/services/control-api/src/config.rs`** — refactor of `token_glob_overlap` recursive matching. Combines two equivalent branches (`'*'` on the left vs right) into one. Logic identical, search space identical.

- **`crates/bridges/tetragon-bridge/src/mapper.rs`** — match-guard refactor of `classify_kprobe_severity`'s `PathArg` and `FileArg` branches. Logic identical. See NEW 5 for the observation that this area lacks dedicated property/fixture tests.

## Appendix B — Audit's "Things to Leave Alone" — re-verified

All nine "leave alone" items still hold:

- `clawdstrike-brokerd::api.rs::ApiError` and `constant_time_eq` ⇒ `api.rs:179-188` unchanged.
- `tetragon-bridge::Bridge::run` event loop ⇒ `lib.rs:238-298`, unchanged. (Working tree only touched `mapper.rs`.)
- `hushd::cli::parse_listen_host_port` ⇒ verified `cli.rs` is 408 LOC, matches audit.
- `hushd` systemd integration ⇒ unchanged.
- `hushd::tls::handle_accept_error` ⇒ unchanged.
- `hush-cli::ExitCode` enum ⇒ verified at `main.rs:80-93` unchanged.
- `hushd::api::create_router` route grouping ⇒ `api/mod.rs` unchanged at 554 LOC.
- `#[serde(deny_unknown_fields)]` discipline ⇒ confirmed across all modified files in the working tree (`AuthConfig`, `OidcConfig`, etc. retain `#[serde(deny_unknown_fields)]`).
- `bridge_runtime` shared crate ⇒ unchanged.

---

## Appendix C — Verified-against `wave3/B-api-server-routes.md`

The wave-3 plan applies to `apps/agent/src-tauri/src/api_server.rs`, which is **outside D04's scope** (apps/agent is a Tauri binary, not a `crates/services/` service). However, the wave-3 audit's most relevant observation for this delta:

> "44 `agent_edr_*` handlers were extracted into `src/edr/handlers/{causal,deception,evidence,fleet,policy,privacy,response,sensors}.rs`"

confirms that the EDR extraction (commits `e6d87e878`, `ad1c6d187`, `a97fda5d9`, `768876a7b`) **did not** move any routes from `api_server.rs` into `control-api` or `hushd`. The EDR handlers stayed inside the agent binary; the control-API and hushd route god-files are independently grown.

This is important context: there has been no consolidation of routing logic across the agent and the control plane. The audit's HIGH "route god-files" finding therefore covers two *independent* surfaces (`apps/agent/src-tauri/src/api_server.rs` and `crates/services/control-api/src/routes/*.rs`) that should each be split on their own merit.

Cross-cutting observations the wave-3 plan implies for D04 scope:

1. **The wave-3 plan introduces `api/error.rs` with `enum AgentApiError`** to replace the `Result<T, (StatusCode, String)>` tuple. `crates/services/control-api/src/error.rs` and `crates/services/hushd/src/error.rs` already have a typed `ApiError`/`AppError` enum — those crates are not afflicted by the same tuple-error problem the agent has. The audit's "error handling: 7/10" score holds; the lift remains on the agent side.

2. **The wave-3 plan introduces `api/test_support.rs`** to absorb 162 `Router::new()` repetitions across tests. `control-api`'s `integration_tests.rs` (still 11k+ lines in `src/`, never moved to `tests/`) has its own analogous problem but with a different shape — repeated `harness.app` setup with manually constructed JSON. Moving `integration_tests.rs` to `tests/` (audit Finding HIGH) would give us a natural place to factor a `harness/` module.

3. **The wave-3 plan calls out `require_auth` as an in-handler call rather than middleware** in the agent code. `hushd` and `control-api` *do* use middleware via `axum::middleware::from_fn_with_state` (verified `crates/services/hushd/src/auth/middleware.rs:50` and `crates/services/control-api/src/main.rs:308-310`). So the services are ahead of the agent on this dimension. Reaffirmed: the auth-default insecurity in hushd is a config-default problem, not a middleware-shape problem.

---

## Appendix D — Test crates summary

`crates/tests/` houses three crates, all in scope for D04:

| Crate | Role | LOC | Status |
| ----- | ---- | --- | ------ |
| `formal-diff-tests` | Differential proptest: Lean spec vs Rust impl | 1,416 (src + tests) | Active; not flagged in source audit |
| `e2e-posture-cmd` | NATS posture-command publisher binary | 154 | Specialised utility; not flagged |
| `sdr-integration-tests` | Empty lib crate w/ tests/* | 2 (lib) + 3 tests | Healthy pattern |

No findings from the source audit applied here, and the working tree did not touch any of them. The sdr-integration-tests pattern (`lib.rs` = 2 lines of comment, tests under `tests/`) is the *exact* layout the audit recommends for moving `control-api::integration_tests` out of `src/`.

---

## Appendix E — Recommended commit sequence (working tree before audit Item-5 split)

A defensible commit sequence that lands the dirty diff cleanly *and* moves the audit forward:

1. **Commit A (low-risk):** Land the six `sort_by → sort_by_key` clippy improvements in `hushd/api/broker.rs`, `hushd/broker_state.rs`, `control-api/services/delegation_graph.rs`. Land the `tetragon-bridge/mapper.rs` and `hushd/policy_scoping/mod.rs` match-guard refactors. Land the `hush-cli/pkg_cli.rs` refactor. Land the `control-api/config.rs` token_glob_overlap refactor. **These are all behaviour-preserving clippy noise and should ship in one commit.**
2. **Commit B (small architecture):** Carve `routes/policies/` and `routes/response_actions/` submodule trees per execution-plan item 5. Move the *existing* HEAD-state handlers into the new layout. No new functions yet.
3. **Commit C (feature):** Add `policy_distribution::upsert_active_policy_with_executor` and `upsert_active_policy_after_version_with_executor` into the existing `services/policy_distribution.rs` (already a sensible home). This is independent of the route split.
4. **Commit D (feature):** Land `validate_endpoint_ack_signed_receipt` and its helpers into the new `routes/response_actions/endpoint_ack_receipt.rs`. Land integration tests against it. This piggybacks on Commit B.
5. **Commit E (feature):** Land `reserve_policy_rule_diff_dispatch`, `policy_rule_diff_expected_proposed_policy`, `fetch_policy_proposal_row_for_update`, and the new policy-proposal flow into `routes/policies/fleet_rule_diff.rs`. Land integration tests. Piggybacks on Commit B.

Net effect: the working-tree work ships as 4-5 focused commits instead of one giant blob, *and* the route god-files shrink instead of growing.

---

## Appendix F — Score deltas

| Score | Source audit (2026-05-23) | This delta (2026-05-24) | Notes |
| ----- | ------------------------- | ----------------------- | ----- |
| Service quality | 6/10 | 6/10 | No movement; nothing has been refactored. The dirty diff is feature-additive. |
| Operational readiness | 5/10 | 5/10 | Still no graceful shutdown on brokerd/registry/eas-anchor. Still no persistence on brokerd. |
| API design | 6/10 | 6/10 | Hand-rolled routes still hand-rolled. utoipa/aide still not adopted. |
| Error handling | 7/10 | 7/10 | The new `validate_endpoint_ack_signed_receipt` correctly uses `ApiError::BadRequest`/`Database`/`Internal` so this score is reaffirmed. |
| Observability | 5/10 | 5/10 | No `tower_http::request_id` adoption. audit-monitor still `eprintln!`. spine-cli's `--verbose` still a lie. |
| Security defaults | 3/10 | 3/10 | All four insecure defaults remain. This is the score the audit was loudest about. |
| Test coverage signal | 6/10 | 6/10 | Working tree adds tests for proof-only proposals and rule-diff dispatch — incremental improvement, but `integration_tests.rs` still lives in `src/`. |

---

*Delta refreshed 2026-05-24. Auditor: GSD Wave-4 services/bridges delta. No source files modified outside `.audit/wave4/`. The four CRITICAL insecure defaults remain insecure at HEAD and in the working tree.*
