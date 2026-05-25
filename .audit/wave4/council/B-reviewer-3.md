# Wave B Council — Reviewer 3 (stronghold + cross-cutting)

**HEAD:** 9f668a7c63aa06f93625481778c993f1dfe2a658
**Branch:** cleanup/waves-abce (3 commits ahead of fix/macos-es-ne-hardening from Wave A; 5 new commits in Wave B)
**Verdict:** DISSENT

---

## Check 1: stronghold getrandom fail-loud

### Old behavior present in 9f668a7c6?

No. The silent fallback is gone. Pre-Wave-B (verified via `git show 9f668a7c6 --` and the diff against HEAD~1's parent):

```rust
// OLD — what D07 N-07 flagged
fn generate_and_write_machine_secret(key_file: &Path, out: &mut [u8; 32]) {
    getrandom::getrandom(out).unwrap_or_else(|_| {
        // Absolute last resort — should never happen on supported platforms.
        eprintln!("[stronghold] WARNING: getrandom failed, using fallback");
    });
    ...
}
```

That code is no longer present at HEAD.

### New behavior evidence

`apps/workbench/src-tauri/src/commands/stronghold.rs:65,93,102-108`:

```rust
pub fn derive_machine_password(data_dir: &Path) -> Result<Zeroizing<Vec<u8>>, String> {   // :65
    ...
    Ok(Zeroizing::new(hasher.finalize().to_vec()))                                         // :93
}

fn generate_and_write_machine_secret(key_file: &Path, out: &mut [u8; 32]) -> Result<(), String> {
    getrandom::getrandom(out).map_err(|e| {                                                // :103
        eprintln!("[stronghold] getrandom failed: {e}");
        format!(
            "OS CSPRNG (getrandom) failed: {e}. Refusing to open vault with a weak key."
        )
    })?;                                                                                   // :108
    ...
}
```

The function signature now returns `Result`. `getrandom` failure converts to a `String` error and bubbles up. The SAFETY comment at `:97-101` explicitly documents why: "Any CSPRNG failure here must propagate so the vault refuses to open rather than silently fall back to a predictable, machine-public key."

### Caller handles new error

`apps/workbench/src-tauri/src/main.rs:32-36`:

```rust
// SAFETY: a getrandom failure must propagate; refuse to derive a
// weak fallback password (see stronghold::generate_and_write_machine_secret).
let password = stronghold_cmds::derive_machine_password(&data_dir)
    .expect("derive vault password requires working OS CSPRNG");
```

The caller is the Tauri plugin builder closure for `tauri_plugin_stronghold::Builder::new`. `.expect()` with an unambiguous message is correct for this context: this runs inside the Tauri `Builder::plugin(...)` chain before window setup, so panicking on init is reasonable and visible. Alternative shapes (`Builder::default().run()` returning Err, structured return) would require a more invasive refactor; the panic produces a hard "vault refuses to open" failure mode that is exactly what the audit asked for. The internal test still calls `.expect("derive first")` at `:562-563` — fine for tests.

`cargo check` from `apps/workbench/src-tauri`: `Finished `dev` profile [unoptimized + debuginfo] target(s) in 9.43s` — clean, no errors, no warnings.

**Verdict: PASS** — silent fallback removed, error propagates, caller fails loud via panic at init time.

---

## Check 2: Compile + clippy

### cargo check --workspace --all-targets

Background command completed in 59.34s, exit code 0. Final line: `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 59.34s`. Zero `error[E…]` lines.

Total warnings: 42 (lib) + 44 (lib test, 39 dup) = ~47 unique, **all** located in `crates/libs/clawdstrike-policy-event/src/edr/*` (`mod.rs`, `receipt/mod.rs`, `causal/recorder.rs`, `deception.rs`, `detection/supply_chain.rs`, `flight_recorder/mod.rs`, `response.rs`). These are the pre-existing C-4 dead-code issue (Wave A Reviewer 2 confirmed the same 42 warnings at `555f2f33b`). Wave B did not touch `crates/libs/clawdstrike-policy-event` at all (`git log --oneline 555f2f33b..HEAD -- crates/libs/clawdstrike-policy-event/src/edr/` returns empty).

### cargo clippy on the 4 service crates

**hushd / clawdstrike-registry / clawdstrike-brokerd** — `cargo clippy -p hushd -p clawdstrike-registry -p clawdstrike-brokerd` finishes clean: `Finished \`dev\` profile [unoptimized + debuginfo] target(s) in 21.57s`. Only the pre-existing 43 `clawdstrike-policy-event` warnings surface as dependency-tree warnings; **zero clippy errors against the three service crates themselves**.

**clawdstrike-control-api — FAILS.** `cargo clippy -p clawdstrike-control-api` (no `-D warnings`, default lint levels) returns:

```
error: used `expect()` on a `Result` value
  --> crates/services/control-api/src/config.rs:51:26
   |
51 |               listen_addr: "127.0.0.1:8080"
52 | |                 .parse()
53 | |                 .expect("static default listen addr"),
   = note: requested on the command line with `-D clippy::expect-used`
error: could not compile `clawdstrike-control-api` (bin "clawdstrike-control-api") due to 1 previous error; 1 warning emitted
```

This is enforced by `Cargo.toml:191-193 [workspace.lints.clippy] expect_used = "deny"` (workspace root). Wave B commit `069963245` (V-02) added a new `Default for Config` impl that calls `.parse().expect("static default listen addr")` at `config.rs:51-53`. The crate ships workspace-level `[lints] workspace = true`, so this is a hard error, not a warning. **This is a fresh regression introduced by Wave B.**

A correct shape would have been `SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)` (no parse needed, no `.expect`) or a `const fn` builder; either is mechanical and 1-4 LOC.

### New warnings introduced by Wave B

- **1 clippy error**, blocking compile under workspace lints: `crates/services/control-api/src/config.rs:51` (`.expect()` in `Default for Config` introduced by 069963245).

All 42-43 `clawdstrike-policy-event` warnings pre-date Wave B (verified Wave A Reviewer 2's identical count + Wave A's HEAD `555f2f33b`).

The `policies.rs:2380` "too many arguments (9/7)" lint pre-existed: `git log --oneline 555f2f33b..HEAD -- crates/services/control-api/src/routes/policies.rs` returns empty (Wave B didn't touch policies.rs), and the function shape at `555f2f33b` already had 9 args (verified via `git show 555f2f33b:crates/services/control-api/src/routes/policies.rs`).

**Verdict: FAIL** — Wave B's V-02 commit introduces a hard clippy regression in control-api by using `.expect()` in code subject to `expect_used = "deny"`. Until this is fixed, `cargo clippy -p clawdstrike-control-api` fails. This is mechanical to fix but blocks any CI step that runs `cargo clippy -D warnings` or `cargo clippy -- -D clippy::expect-used` (which the workspace already does via `expect_used = "deny"`).

---

## Check 3: New attack surface

### allow_insecure_no_auth (registry)

- **NOT new in Wave B** — the field already existed at `555f2f33b` in `clawdstrike-registry/src/config.rs` (verified via `git show 555f2f33b:crates/services/clawdstrike-registry/src/config.rs`). Wave B's e893defcd added a *startup gate* (`validate()` called from `from_env`) plus a `Default for Config` impl, not the flag itself.
- Default value: `false` (config.rs:30 inside the new `Default` impl).
- Requires explicit set: yes — `CLAWDSTRIKE_REGISTRY_ALLOW_INSECURE_NO_AUTH=true` (or 1/yes/on), parsed via `parse_bool_env` which returns `Ok(false)` when the env var is unset (`config.rs:103-118`).
- Documented: yes — doc comment at `config.rs:16-17` ("Explicit insecure override to allow unauthenticated access when `api_key` is empty. Defaults to false.") and a second doc comment on `validate()` at `:37-38`.
- Overlap: none. `auth.rs:170-176` only activates the bypass when both (a) `api_key.is_empty()` and (b) `allow_insecure_no_auth == true`. OIDC pre-validation at `auth.rs:155-167` runs first and is unaffected.

### allow_insecure_no_admin_token (brokerd)

- **NEW in Wave B** (commit 70b0fa547). Did not exist at `555f2f33b` (verified via `git show 555f2f33b:crates/services/clawdstrike-brokerd/src/config.rs` — no such field).
- Default value: `false` — `env_bool("CLAWDSTRIKE_BROKERD_ALLOW_INSECURE_NO_ADMIN_TOKEN")` defaults to `false` when unset (config.rs:42-46).
- Requires explicit set: yes — `CLAWDSTRIKE_BROKERD_ALLOW_INSECURE_NO_ADMIN_TOKEN=1` (or `true`/`TRUE`/`yes`/`YES`).
- Documented: yes — doc comments at `config.rs:32-34` (cross-references the new flag from `admin_token` field) and `:36-38` ("Explicit insecure override that allows mutation endpoints to accept requests without an admin token. Defaults to false.").
- Overlap: none. `api.rs:193-210` only opens the bypass when `admin_token.is_none() && allow_insecure_no_admin_token == true`. The flag does NOT also skip Ed25519 signature verification on capabilities (`capability.rs` paths are unaffected), nor does it bypass DPoP / DNS pinning. The check is called from exactly 4 mutation routes (api.rs:261, 632, 725, 855); GET routes (`/healthz`) intentionally remain open (the docstring at `:191-192` documents this).

### Other opt-in-to-insecure flags

- `nats_allow_insecure_mock_provisioner` (control-api): pre-existed at `555f2f33b` (commit eb5a75552). Not introduced by Wave B.
- `allow_insecure_http_for_loopback` (clawdstrike async_guards): library-side, unrelated to Wave B services.

**No other new attack-surface flags were introduced by Wave B.**

**Verdict: PASS** — both flags default to false, require explicit opt-in via env, are documented, and have surgical (no-cascade) scope.

---

## Check 4: Coverage of D04 V-01..V-04

### V-01 (hushd) — commit b6a7d3be6 — PASS

- `crates/services/hushd/src/config.rs:97-124`: `AuthConfig` no longer derives `Default`; explicit impl returns `enabled: true` via `default_auth_enabled()` helper. `#[serde(default = "default_auth_enabled")]` ensures YAML configs that omit the `auth.enabled` key still get `true`.
- Existing test at `config.rs:1709` flipped from `assert!(!config.auth.enabled)` to `assert!(config.auth.enabled)`.
- New test `default_auth_config_rejects_request_with_no_bearer_token` at `middleware.rs:232-263` builds the default-config router, fires a no-auth request at `/protected`, asserts `StatusCode::UNAUTHORIZED`.
- middleware.rs:50-58 untouched (`require_auth` still early-returns on `!state.auth_enabled()`), but now `auth_enabled()` defaults to true. Both `require_auth` and `require_scope` early-return arms are now dead-by-default unless the operator flips the flag. This is the right shape.

### V-02 (control-api) — commit 069963245 — PARTIAL PASS

- LISTEN_ADDR default flipped to `127.0.0.1:8080` (`config.rs:51-53, 109`).
- `cors_allowed_origins: Vec<String>` field added with default `Vec::new()` (config.rs:9, :54), parsed from `CORS_ALLOWED_ORIGINS` env var as comma-separated list (`:112-121`).
- `CorsLayer::permissive()` removed; `main.rs:308-327` now builds a CORS layer with:
  - empty allowlist → `AllowOrigin::list(std::iter::empty())` (fail-closed) with a warn log,
  - `"*"` → `AllowOrigin::any()`,
  - otherwise → parsed `HeaderValue` list.
- **PROBLEM**: the new `Default for Config` impl introduces a workspace-level clippy `expect_used = "deny"` violation at `config.rs:51-53`. This blocks `cargo clippy -p clawdstrike-control-api`. See Check 2 for full citation.
- Functionally the fix is right; mechanically it's broken under clippy.

### V-03 (registry) — commit e893defcd — PARTIAL PASS

The D04 audit identified **two** registry defaults as insecure (table rows 3 + 3b):
- Row 3: `host = "0.0.0.0"` at `config.rs:26`.
- Row 3b: empty `api_key` permitted without `allow_insecure_no_auth = true` at `config.rs:41-42`.

D04 also recommends in "Mitigations" (`config.rs:599`): **"default `host` to `"127.0.0.1"`; reject empty `api_key` unless `allow_insecure_no_auth = true`"**.

Wave B's commit e893defcd only addressed row 3b (the api_key gate via `validate()`). **The `host` default is unchanged at HEAD**: `config.rs:26` and `:51` both still produce `"0.0.0.0"`:

```rust
// config.rs:23-34 (HEAD)
impl Default for Config {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),     // ← still 0.0.0.0
            ...
        }
    }
}

// config.rs:51 (HEAD, in from_env)
let host = std::env::var("CLAWDSTRIKE_REGISTRY_HOST").unwrap_or_else(|_| "0.0.0.0".into());
```

The doc comment at `config.rs:8` still reads "Listen host (default: 0.0.0.0)".

Wave B's plan summary (C-3) says "refuse empty API key unless explicit `allow_insecure_no_auth: true`" but references file:lines `config.rs:26,41-42` (`:26` is the host default line). The audit explicitly asked for both. Only one half landed. This is a documented insecure default still shipping at HEAD.

### V-04 (brokerd) — commit 70b0fa547 — PASS

- `require_admin_auth` (api.rs:193-210) no longer returns `Ok(())` when `admin_token.is_none()`. Instead:
  - if `allow_insecure_no_admin_token` is true: warn-log and `return Ok(())`,
  - else: `return Err(ApiError::unauthorized("BROKER_AUTH_REQUIRED", ...))`.
- Two new tokio tests at `api.rs:1314-1349`:
  - `mutation_endpoint_returns_401_when_no_token_and_no_insecure_opt_in` builds the full router, POSTs to `/v1/admin/freeze`, asserts 401.
  - `mutation_endpoint_open_when_insecure_opt_in_set` does the same with the flag on, asserts 200.
- Existing tests `auth_skipped_when_no_token_configured` renamed to `auth_rejects_missing_token_by_default` and updated to expect 401.
- `config.rs:36-38` adds the new `allow_insecure_no_admin_token: bool` field with default false via `env_bool` at `:103-104`.
- 4 internal tests that exercised the prior "no token = no auth" path were updated to set `allow_insecure_no_admin_token: true` (api.rs:1384, 1495, 1600; capability.rs:357; lease.rs:681; tests/e2e.rs:144, 335, 484). Those updates are correct: they were testing pre-revocation/lease behavior, not the auth-bypass behavior, and they now explicitly opt in to the insecure mode they were implicitly relying on.

**Overall Verdict: FAIL.** V-01 and V-04 are clean. V-02 is functionally clean but introduces a NEW clippy regression (see Check 2). V-03 is half-fixed — the `host = "0.0.0.0"` half of the audit's row 3 is unaddressed. The audit's stated goal was "Flip all four insecure defaults"; what shipped is "flip three of the four, plus one of two registry defaults, plus a clippy regression in control-api".

---

## Check 5: Pre-existing flakes

The executor reported two flakes that pre-date Wave B:
1. `crates/libs/clawdstrike-policy-event/src/edr/...::tests::endpoint_response_rollback_receipt_binds_restore_effect`
2. `crates/libs/clawdstrike/tests/abuse_harness.rs` (the spec's path)

Path correction first: the *actual* paths to those tests at HEAD:
- Flake 1 lives in `crates/libs/clawdstrike-policy-event/src/edr/mod.rs:8293` (one big `mod.rs`, not a separate `tests.rs`).
- Flake 2 lives in `crates/services/hush-cli/tests/abuse_harness.rs` (not `crates/libs/clawdstrike/tests/abuse_harness.rs` — that file does not exist; the spec used a wrong directory).

With paths corrected:

```
$ git log --oneline 555f2f33b..HEAD -- \
    crates/services/hush-cli/tests/abuse_harness.rs \
    crates/libs/clawdstrike-policy-event/src/edr/mod.rs
(no output)
```

Neither file was touched between Wave A's HEAD (`555f2f33b`) and Wave B's HEAD (`9f668a7c6`). The full Wave B diff stat (`git diff --stat 555f2f33b..HEAD`) shows only:

```
apps/workbench/src-tauri/src/commands/stronghold.rs
apps/workbench/src-tauri/src/main.rs
crates/services/clawdstrike-brokerd/{Cargo.toml,src/api.rs,src/capability.rs,src/config.rs,src/lease.rs,tests/e2e.rs}
crates/services/clawdstrike-registry/src/config.rs
crates/services/control-api/{src/config.rs,src/integration_tests.rs,src/main.rs}
crates/services/hushd/{src/api/presence.rs,src/auth/middleware.rs,src/config.rs,tests/common/mod.rs}
Cargo.lock
```

`crates/libs/clawdstrike-policy-event/src/edr/mod.rs` and `crates/services/hush-cli/tests/abuse_harness.rs` are not in that list. **Wave B did not modify the files holding the two reported flakes**, so any failure of those two tests at HEAD pre-dates Wave B by construction.

**Verdict: PASS** — both reported flakes pre-date Wave B (Wave B's diff does not include their source files).

---

## DISSENT log

1. **NEW clippy regression in control-api** (introduced by V-02 commit 069963245). `crates/services/control-api/src/config.rs:51-53` uses `.expect("static default listen addr")` inside the new `Default for Config` impl. The workspace-level `[workspace.lints.clippy] expect_used = "deny"` (Cargo.toml:191-193) escalates this to a hard error. `cargo clippy -p clawdstrike-control-api` exits with: `error: could not compile clawdstrike-control-api ... due to 1 previous error`. This is a Wave-B-introduced regression: pre-Wave-B (`git show 555f2f33b:crates/services/control-api/src/config.rs`) had no `Default` impl, hence no `.expect()`.
   - Recommended fix (mechanical, ~3 LOC): replace `"127.0.0.1:8080".parse().expect("...")` with `SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)` — no `parse`, no `.expect`. Or, less invasively, replace `.expect("static default listen addr")` with `.unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))`. Either avoids the clippy lint without changing semantics.
   - Severity: this blocks any CI step that runs `cargo clippy --workspace` (or `cargo clippy -p clawdstrike-control-api`). The work that V-02 was supposed to do is correct; the implementation broke the existing lint contract.

2. **V-03 only half-fixed** — `clawdstrike-registry` still defaults `host = "0.0.0.0"` in two places (`config.rs:26` in the new `Default` impl, `config.rs:51` in `from_env`). The D04 audit (row 3 of the "four CRITICALS" table) flagged this independently from row 3b (the api_key gate). The mitigation block in D04 explicitly recommends `host = "127.0.0.1"`. The delta summary's C-3 bullet uses imprecise wording ("refuse empty API key…") that elides this half, but its line reference (`config.rs:26,41-42`) includes line 26 (the host default).
   - Recommended fix (~2 LOC): change `host: "0.0.0.0".to_string()` to `host: "127.0.0.1".to_string()` at config.rs:26 and the matching `.unwrap_or_else` at config.rs:51. The doc comment at `:8` should also flip.
   - Severity: this is the same severity as V-02's CORS/listen fix — it's a "fail-closed default for a deployable service surface". A registry that defaults to 0.0.0.0 binds publicly on every Docker host.

3. **`derive_machine_password` is now used from a panic context**. Wave B fixed the actual security issue (no more silent fallback), but the workbench's `main.rs:34` now panics on a getrandom failure. For a desktop Tauri shell this is the correct call (and matches what the audit asked for — "vault refuses to open"), but it would be nicer to surface the error to the user via a Tauri dialog rather than a hard panic before the window exists. This is a polish gap, not a regression — marking as a CONCUR note rather than a DISSENT item.

## CONCUR log

- Stronghold fix is correct and surgical: the function signature change (`-> Zeroizing<Vec<u8>>` to `-> Result<Zeroizing<Vec<u8>>, String>`) cleanly forces all four call sites in `stronghold.rs` and the one call site in `main.rs` to confront the failure mode, and the SAFETY comment at `:97-101` is the right kind of comment to keep next to a credential-vault primitive.
- V-01 (hushd auth) is the most thorough of the four: it includes a regression test that builds the default-config router and asserts 401, which is exactly the kind of test that protects against a future revert.
- V-04 (brokerd) properly enumerates the four mutation routes that need the bypass-gate update, surface area is correctly bounded (GETs deliberately exempt), and the test pair (`mutation_endpoint_returns_401_…` / `mutation_endpoint_open_when_insecure_opt_in_set`) covers both arms.
- Both new opt-in-insecure flags (`allow_insecure_no_admin_token`, the strengthened `allow_insecure_no_auth` gate) are documented, default false, single-purpose, and do not cascade. The naming is honest (the word "insecure" is in the flag name).
- Wave B's commits do not touch the two pre-existing flake files (`crates/libs/clawdstrike-policy-event/src/edr/mod.rs`, `crates/services/hush-cli/tests/abuse_harness.rs`), so those flakes cannot be regressions Wave B caused.

## Final verdict

**DISSENT.** Two blocking items:

1. `cargo clippy -p clawdstrike-control-api` is broken at HEAD by Wave B's V-02 commit (`.expect` in `Default for Config` violates workspace `expect_used = "deny"`). Mechanical to fix (~3 LOC). Until then, any CI clippy step on control-api will fail.
2. V-03 is half-fixed: registry `host = "0.0.0.0"` default remains insecure at `config.rs:26, 51`. The audit explicitly flagged this as a separate "still insecure" row. ~2 LOC to fix.

V-01, V-04, and the stronghold fix (N-07) are clean. The cross-cutting compile is green, no new opt-in-insecure flags overlap dangerously, and the pre-existing flakes are confirmed pre-Wave-B.

If the two DISSENT items above land in a follow-up Wave-B touch (single 5-LOC commit), this reviewer flips to CONCUR.
