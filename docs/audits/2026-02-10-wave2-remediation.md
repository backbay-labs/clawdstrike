# Rust Security + Correctness Audit — Wave 2 Remediation (2026-02-10)

This document records remediation for CS-AUDIT2-001 through CS-AUDIT2-007.
Remediation branch: `audit-fix/2026-02-10-remediation`
HEAD: `bb66f02bc3d2bb097c3a34c3b2d5777f38f35dd1`
Merged as: `N/A (not merged yet)`

## CS-AUDIT2-001 — CONNECT policy target != dial target (SNI vs CONNECT host)

### What was wrong
CONNECT requests targeting an IP could be policy-checked against extracted SNI instead of the dial target, enabling policy bypass when SNI was allowlisted but CONNECT IP was blocked.

### Fix strategy
- Enforced policy check on the actual CONNECT target (`connect_host:connect_port`) before sending tunnel success and before any upstream dial.
- For IP CONNECT targets, added SNI consistency enforcement:
  - Evaluate SNI host separately.
  - Require SNI host DNS resolution to include the same CONNECT IP.
  - Reject on mismatch before upstream connection.
- Kept event emission and outcome tracking for both connect target and SNI checks.

### Code pointers
- `crates/services/hush-cli/src/hush_run.rs`
- Functions: `handle_connect_proxy_client`, `sni_host_matches_connect_ip`

### Tests added
- `connect_proxy_rejects_ip_target_with_allowlisted_sni_mismatch`
  - Asserts blocked IP CONNECT target is rejected even when SNI payload contains allowlisted host.
  - Asserts no upstream TCP accept occurs.

### Proof commands
- `cargo test -p hush-cli connect_proxy_rejects_ip_target_with_allowlisted_sni_mismatch -- --nocapture`
- Observed: `test result: ok. 1 passed; 0 failed; ...`

## CS-AUDIT2-002 — hush run resource bounds (slowloris + unbounded events + forward timeout)

### What was wrong
Proxy and event-forwarding paths had bounded pieces but lacked complete protection against slow header reads and potentially stalled forwarding operations.

### Fix strategy
- Added CONNECT header read timeout (slowloris mitigation) with 408 response on timeout.
- Kept and exercised in-flight proxy connection cap behavior.
- Added explicit forwarding timeout for hushd event forwarding HTTP requests.
- Verified bounded event queue drop behavior under stalled forwarding pressure.

### Code pointers
- `crates/services/hush-cli/src/hush_run.rs`
- Functions: `start_connect_proxy`, `handle_connect_proxy_client`, `HushdForwarder::new`, `HushdForwarder::forward_event`

### Tests added
- `proxy_slowloris_does_not_exceed_connection_cap`
  - Simulates partial/slow header sender.
  - Asserts cap enforcement (`503`) and post-timeout responsiveness (`501`).
- `event_forwarding_backpressure_keeps_memory_bounded`
  - Simulates stalled forward target.
  - Asserts queue saturation triggers drops (`dropped_count > 0`).

### Proof commands
- `cargo test -p hush-cli proxy_slowloris_does_not_exceed_connection_cap -- --nocapture`
- `cargo test -p hush-cli event_forwarding_backpressure_keeps_memory_bounded -- --nocapture`
- Observed: `test result: ok. 1 passed; 0 failed; ...` (for each command)

## CS-AUDIT2-003 — IRM filesystem traversal bypass via normalization

### What was wrong
Filesystem IRM normalization collapsed `..` segments, potentially converting traversal intent into apparently safe paths and bypassing boundary checks.

### Fix strategy
- Stopped sanitizing away parent traversal during normalization.
- Added explicit fail-closed traversal detection for `..` segments (including mixed forms).
- Broadened path extraction to catch relative traversal path inputs.

### Code pointers
- `crates/libs/clawdstrike/src/irm/fs.rs`
- Functions: `normalize_path`, `extract_path`, `has_parent_traversal`, `evaluate`

### Tests added
- `filesystem_irm_denies_parent_traversal_relative_paths`
  - Covers string and object path forms.
  - Includes relative traversal examples.

### Proof commands
- `cargo test -p clawdstrike filesystem_irm_denies_parent_traversal_relative_paths -- --nocapture`
- Observed: `test result: ok. 1 passed; 0 failed; ...`

## CS-AUDIT2-004 — IRM URL host parsing spoof (userinfo ambiguity)

### What was wrong
Network IRM host extraction used string splitting, allowing spoofing via userinfo forms like `api.openai.com@evil.example`.

### Fix strategy
- Replaced split-based extraction with strict URL parsing (`reqwest::Url`, backed by `url::Url` semantics).
- Normalized parsed host for comparisons (lowercase + trailing-dot trim).
- Ensured policy decisions use parsed authority host.

### Code pointers
- `crates/libs/clawdstrike/src/irm/net.rs`
- Functions: `extract_host_from_url`, `extract_host`, `normalize_host`

### Tests added
- `test_userinfo_spoof_url_uses_actual_host_and_is_denied`
  - Verifies spoof URL resolves to `evil.example` semantics and is denied when only `api.openai.com` is allowlisted.

### Proof commands
- `cargo test -p clawdstrike test_userinfo_spoof_url_uses_actual_host_and_is_denied -- --nocapture`
- Observed: `test result: ok. 1 passed; 0 failed; ...`

## CS-AUDIT2-005 — git commit/ref option injection hardening

### What was wrong
`git+...@COMMIT:PATH` commit/ref token lacked strict validation; dash-prefixed values could be interpreted as git options.

### Fix strategy
- Added strict commit/ref validation:
  - Rejects dash-prefixed tokens.
  - Allows only short/full OID or strict refname grammar.
- Applied validation in both absolute and relative git extends resolution flows.
- Hardened `git fetch` invocation with `--` separator before user-controlled ref token.
  - `--` is inserted immediately before the user-controlled ref token to prevent option parsing as flags.
  - Verified behavior with `git fetch --depth 1 origin -- main` in a local temporary repo (exit `0`).

### Code pointers
- `crates/services/hush-cli/src/remote_extends.rs`
- `crates/services/hushd/src/remote_extends.rs`
- Functions: `validate_git_commit_ref`, `is_hex_oid`, `is_valid_git_refname`, `resolve_git_absolute`, `resolve_git_relative`, `git_show_file`

### Tests added
- `remote_extends_rejects_dash_prefixed_commit_ref` (hush-cli)
- `remote_extends_rejects_dash_prefixed_commit_ref` (hushd)
  - Both assert deterministic config error before git fetch execution path.

### Proof commands
- `cargo test -p hush-cli remote_extends_rejects_dash_prefixed_commit_ref -- --nocapture`
- `cargo test -p hushd remote_extends_rejects_dash_prefixed_commit_ref -- --nocapture`
- Observed: `test result: ok. 1 passed; 0 failed; ...` (for each command)

## CS-AUDIT2-006 — policy extends recursion depth DoS

### What was wrong
Extends resolution was recursively unbounded, enabling deep-chain resource exhaustion.

### Fix strategy
- Added explicit max extends depth guard (`MAX_POLICY_EXTENDS_DEPTH`).
  - Default limit: `32`.
  - Rationale: prevents runaway recursion / resource exhaustion in deep `extends` chains.
- Threaded depth counter through recursive resolution calls.
- Added deterministic user-facing error: `Policy extends depth exceeded (limit: N)`.

### Code pointers
- `crates/libs/clawdstrike/src/policy.rs`
- Function: `from_yaml_with_extends_internal_resolver`

### Tests added
- `policy_extends_depth_limit_enforced`
  - Constructs chain longer than limit and asserts depth-exceeded failure.

### Proof commands
- `cargo test -p clawdstrike policy_extends_depth_limit_enforced -- --nocapture`
- Observed: `test result: ok. 1 passed; 0 failed; ...`

## CS-AUDIT2-007 — async guards background mode unbounded inflight

### What was wrong
Background async guard execution detached tasks without bounded in-flight control, permitting burst-driven task growth.

### Fix strategy
- Added bounded background in-flight semaphore to runtime.
- Implemented saturation behavior: drop scheduling when full.
- Added runtime counters for dropped and in-flight/peak visibility.
- Caller behavior on saturation: `evaluate_async_guards` returns immediately with a warning result (`background: dropped`) and increments drop counters.
- Returned explicit warning details when background scheduling is dropped.

### Code pointers
- `crates/libs/clawdstrike/src/async_guards/runtime.rs`
- `crates/libs/clawdstrike/tests/async_guard_runtime.rs`
- Functions: `with_background_in_flight_limit`, `spawn_background`, `background_*` accessors

### Tests added
- `async_background_guards_enforce_inflight_limit`
  - Applies burst load with background mode.
  - Asserts in-flight peak never exceeds cap and drops occur under saturation.

### Proof commands
- `cargo test -p clawdstrike async_background_guards_enforce_inflight_limit -- --nocapture`
- Observed: `test result: ok. 1 passed; 0 failed; ...`

## Required validation gates

### Commands
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --workspace`
- `cargo test -p clawdstrike irm::`
- `cargo test -p clawdstrike policy::`
- `cargo test -p hush-cli`
- `cargo test -p hushd`

### PASS evidence summary
- All required commands completed successfully with no failing tests and no clippy/fmt violations.

## Regression matrix

- `CS-AUDIT2-001` -> `connect_proxy_rejects_ip_target_with_allowlisted_sni_mismatch`
- `CS-AUDIT2-002` -> `proxy_slowloris_does_not_exceed_connection_cap`, `event_forwarding_backpressure_keeps_memory_bounded`
- `CS-AUDIT2-003` -> `filesystem_irm_denies_parent_traversal_relative_paths`
- `CS-AUDIT2-004` -> `test_userinfo_spoof_url_uses_actual_host_and_is_denied`
- `CS-AUDIT2-005` -> `remote_extends_rejects_dash_prefixed_commit_ref` (hush-cli, hushd)
- `CS-AUDIT2-006` -> `policy_extends_depth_limit_enforced`
- `CS-AUDIT2-007` -> `async_background_guards_enforce_inflight_limit`
