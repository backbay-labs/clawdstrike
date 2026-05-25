# Wave B — Reviewer 2 Verdict

**Reviewer:** Agent #2
**Branch:** cleanup/waves-abce
**HEAD:** 9f668a7c63aa06f93625481778c993f1dfe2a658
**Verdict:** CONCUR

## Item-by-item check

### Check 1 — clawdstrike-registry refuses empty API key by default

**Evidence — `allow_insecure_no_auth` field:** `crates/services/clawdstrike-registry/src/config.rs:18` declares `pub allow_insecure_no_auth: bool`. `Default` at line 30 sets it to `false`. The field is `#[derive(Clone, Debug)]` member of `Config`.

**Evidence — startup-validation function:** `Config::validate()` at lines 39-47 bails out with the message `"CLAWDSTRIKE_REGISTRY_API_KEY is unset; refuse to start. Set the API key, or set CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH=true to opt in."` when `self.api_key.trim().is_empty() && !self.allow_insecure_no_auth`. `from_env` (line 50) invokes `config.validate()?` at line 82 before returning, so startup actually fails. `main.rs:36` calls `Config::from_env()?`, so the gate is wired into the daemon startup path.

**Evidence — empty-string vs None:** the field is typed `String`, not `Option<String>`, so the "None" case is realised by the empty-string default. `from_env` (line 66) reads `std::env::var(...).unwrap_or_default()` which yields `""` when the env var is unset, and `validate()` uses `trim().is_empty()` which catches `""`, `"   "`, and any whitespace-only input. The spec's "`None`/empty" requirement is satisfied semantically.

**Evidence — runtime middleware path:** `crates/services/clawdstrike-registry/src/auth.rs:170-181` also consults `allow_insecure_no_auth` at request time. With insecure-on it logs a warn and continues; with insecure-off it returns 503. This is defense in depth on top of the startup gate.

**Tests:** `cargo test -p clawdstrike-registry` → `test result: ok. 181 passed; 0 failed`. Relevant config-test names:
- `config::tests::validate_rejects_empty_api_key_without_insecure_opt_in ... ok`
- `config::tests::validate_allows_empty_api_key_when_insecure_opt_in_set ... ok`
- `config::tests::validate_accepts_non_empty_api_key ... ok`
- `config::tests::default_config_paths ... ok`
- `config::tests::parse_bool_env_defaults_to_false_when_missing ... ok`

**Critical sub-checks:**
- Empty string + `allow_insecure_no_auth=false` errors: covered by `validate_rejects_empty_api_key_without_insecure_opt_in` (line 141-147) using `api_key: String::new()`. PASS.
- `allow_insecure_no_auth=true` allows empty key: covered by `validate_allows_empty_api_key_when_insecure_opt_in_set` (line 149-157). PASS.

**Verdict:** PASS.

### Check 2 — clawdstrike-brokerd requires admin token for mutations by default

**Evidence — `require_admin_auth` returns 401 by default:** `crates/services/clawdstrike-brokerd/src/api.rs:193-223`. When `admin_token` is `None`, the code at line 196-209 returns `Err(ApiError::unauthorized("BROKER_AUTH_REQUIRED", ...))` unless `allow_insecure_no_admin_token == true`, in which case it logs a warn and returns `Ok(())`. When `admin_token` is `Some(...)`, it requires a `Bearer ...` header with a constant-time match against the configured token.

**Evidence — `allow_insecure_no_admin_token` config flag:** `crates/services/clawdstrike-brokerd/src/config.rs:38` declares `pub allow_insecure_no_admin_token: bool`. The doc comment (lines 36-37) labels it "Explicit insecure override that allows mutation endpoints to accept requests without an admin token. Defaults to false." `from_env` (line 103-104) reads the boolean from `CLAWDSTRIKE_BROKERD_ALLOW_INSECURE_NO_ADMIN_TOKEN`, and `env_bool` (lines 41-46) returns `false` when the env var is absent.

**Evidence — GET endpoints remain open:** Router at `api.rs:160-173`:
- GET: `/health`, `/v1/providers`, `/v1/capabilities`, `/v1/executions` — none call `require_admin_auth` (handlers at lines 225, 232, 238, 247).
- POST mutations: `/v1/capabilities/{id}/revoke`, `/v1/admin/freeze`, `/v1/execute`, `/v1/execute/stream`. All four handlers call `require_admin_auth(&headers, &state)?` as the first line: `revoke_capability` (line 261), `set_freeze` (line 632), `execute` (line 725), `execute_stream` (line 855). No mutation handler bypasses auth.

**Tests — named auth tests:** `cargo test -p clawdstrike-brokerd` →
- `api::tests::auth_rejects_missing_token_by_default ... ok` (lines 1242-1249)
- `api::tests::auth_skipped_when_insecure_opt_in_set ... ok` (lines 1251-1256)
- Bonus router-level tests also PASS: `mutation_endpoint_returns_401_when_no_token_and_no_insecure_opt_in` (line 1314-1331) and `mutation_endpoint_open_when_insecure_opt_in_set` (line 1333-1350) exercise the full axum stack on `/v1/admin/freeze`.

**Tests — full brokerd suite:** `cargo test -p clawdstrike-brokerd` →
- Unit tests: `117 passed; 0 failed`.
- e2e: `19 passed; 0 failed`.
- Doc-tests: `0 passed; 0 failed`.
- No failures, no ignored.

**Verdict:** PASS.

### Check 3 — Pre-existing brokerd tests updated correctly

**Evidence — diff:** `git diff fix/macos-es-ne-hardening..HEAD -- crates/services/clawdstrike-brokerd/tests/e2e.rs` shows exactly 19 added lines `+        allow_insecure_no_admin_token: true,`, each appearing immediately after a pre-existing `admin_token: None,` line in a `Config { ... }` literal. Zero deletions, zero removed `admin_token` lines. Each addition matches a separate Config struct literal in a separate test function — the executor's count of 19 is exact.

**Evidence — these tests do not exercise the auth path:** `grep -E "401|UNAUTHORIZED|BROKER_AUTH_REQUIRED" crates/services/clawdstrike-brokerd/tests/e2e.rs` returns zero matches. The e2e tests are concerned with capability validation, freeze/revoke business logic, stream behaviour, evidence persistence, secret-backend resolution, and provider behaviour — not with auth gating. Setting `allow_insecure_no_admin_token: true` correctly opts these tests out of the auth wall so they continue to exercise their intended subject matter. Auth itself is covered by the new `api.rs` unit tests (Check 2).

**Cross-check for accidental bypass-with-asserted-success:** The 19 changed tests all hit mutation endpoints (`revoke`, `set_freeze`, `execute`, `execute_stream`) via the router, but never assert against a 401 outcome that the bypass would now mask. They assert on capability resolution, evidence shape, frozen state, etc. The behaviour under test is orthogonal to auth.

**Verdict:** PASS.

### Check 4 — Commit accuracy

**`e893defcd`** — `feat(registry): refuse empty api_key unless allow_insecure_no_auth (security)`.
- `git show --stat` reports `crates/services/clawdstrike-registry/src/config.rs | 59 +++++++++++++++++++++- 1 file changed, 57 insertions(+), 2 deletions(-)`.
- Body cites D04 V-03 (delayed-failure pattern) and explains that the auth middleware fallback existed but no startup gate did. The single-file diff matches the subject: only `config.rs` is changed.
- **Verdict:** PASS — single-file, scope matches subject, message references the right audit finding.

**`70b0fa547`** — `feat(brokerd): require admin token for mutations by default (security)`.
- `git show --stat` reports changes across 7 files: `Cargo.lock | 1 +`, `clawdstrike-brokerd/Cargo.toml | 1 +`, `api.rs | 82 ++++++++++++++++++++--`, `capability.rs | 1 +`, `config.rs | 9 ++-`, `lease.rs | 1 +`, `tests/e2e.rs | 19 +++++`. Total `106 insertions(+), 8 deletions(-)`.
- Body cites D04 V-04 (fail-open default). The +82 LOC in `api.rs` is the auth gate plus the new test cases. `config.rs` (+9) adds the new field and env-var read. `e2e.rs` (+19) is the test-only Config literal updates verified in Check 3. The `Cargo.lock`/`Cargo.toml`/`capability.rs`/`lease.rs` single-line touches are likely a `tower` (or similar) dev-dep addition needed for the new oneshot router tests; the body does not call them out, but they are mechanical and consistent with adding `ServiceExt` based test wiring.
- **Verdict:** PASS — multi-file scope is consistent with the subject; small ancillary touches are mechanical and do not change product behaviour.

## DISSENT log

(none)

## Concur log

- The implementation went beyond minimum: the brokerd `require_admin_auth` already uses a constant-time byte comparison (`constant_time_eq` at line 179-188), so the new path is not just fail-closed by default but also timing-side-channel hardened against guess-and-check token enumeration. Combined with the explicit `tracing::warn!` log when the insecure bypass is active (`api.rs:198-201`), operators get visibility into the unsafe mode without having to grep for config.
- Registry validation lives in both startup (`from_env` → `validate`) and the request middleware (`auth.rs:170-181`). Either layer rejects an empty key alone; together they make insecure no-auth deployments visible at both boot time (anyhow error) and request time (503 with structured log). Defense in depth is appropriate for a registry that persists publisher keys.
- Test coverage for the brokerd auth gate exercises both the function in isolation (`auth_rejects_missing_token_by_default`, `auth_skipped_when_insecure_opt_in_set`, `auth_passes_with_correct_bearer_token`, `auth_rejects_wrong_token`, `auth_rejects_missing_header`, `auth_rejects_non_bearer_scheme`, `auth_rejects_empty_bearer_value`) AND the full router stack via `oneshot` (`mutation_endpoint_returns_401_when_no_token_and_no_insecure_opt_in`, `mutation_endpoint_open_when_insecure_opt_in_set`). Both end-to-end and unit-level confidence.

## Final verdict
CONCUR
