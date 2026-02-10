# Clawdstrike Audit Remediation (2026-02-10)

## Tracking Checklist
- [x] CS-AUDIT-001 (High) git remote host allowlist bypass for non-HTTP remotes (SCP/ssh/git)
- [x] CS-AUDIT-002 (Medium) allow_private_ips=false inconsistent for git remote extends
- [x] CS-AUDIT-003 (High) path guards bypassable via symlink traversal (lexical-only normalization)
- [x] CS-AUDIT-004 (Medium) hush run unbounded channel + task fanout causes unbounded memory growth
- [x] CS-AUDIT-005 (Medium) hushd session lock DashMap grows unbounded (no pruning)
- [x] CS-AUDIT-006 (Low) threat_intel_guards test harness unwrap() panics on loopback bind denial

## A) Summary
On 2026-02-10, the Rust security/correctness audit findings CS-AUDIT-001 through CS-AUDIT-006 were remediated across `clawdstrike`, `hush-cli`, and `hushd`. The fixes enforce host/IP policy invariants for git remote extends, close symlink-based path guard bypasses, bound the hush event/proxy pipeline under load, add lock lifecycle pruning in session management, and harden threat-intel tests to avoid panic in restricted loopback environments.

## B) Per-issue closure evidence

### CS-AUDIT-001 — git remote host allowlist bypass for non-HTTP remotes
Bug/invariant: git remote extends must enforce host allowlist for URL-style (`ssh://`, `git://`) and SCP-style (`git@host:path`) remotes before any fetch operation.

Fix approach:
- Added git remote host parsing for URL and SCP forms.
- Enforced allowlist checks on parsed git hosts in resolver path before `git fetch`.
- Rejected unsupported git remote schemes (e.g., `file://`) explicitly.

Code pointers:
- `crates/services/hush-cli/src/remote_extends.rs:356` (`resolve_git_absolute` pre-fetch host validation)
- `crates/services/hush-cli/src/remote_extends.rs:581` (`parse_git_remote_host`)
- `crates/services/hush-cli/src/remote_extends.rs:611` (`parse_scp_like_git_host`)
- `crates/services/hushd/src/remote_extends.rs:326` (`resolve_git_absolute` parity)
- `crates/services/hushd/src/remote_extends.rs:551` (`parse_git_remote_host`)

New/updated tests:
- `remote_extends_git_scp_host_must_be_allowlisted` denies SCP host outside allowlist.
- `remote_extends_git_file_scheme_is_rejected` rejects `git+file://...`.
- `scp_style_git_remote_must_be_allowlisted` verifies daemon resolver parity.
- `parse_git_remote_host_rejects_unsupported_scheme` verifies unsupported scheme rejection.

Proof commands:
```bash
cargo test -p hush-cli remote_extends_contract::remote_extends_git_scp_host_must_be_allowlisted -- --nocapture
cargo test -p hush-cli remote_extends_contract::remote_extends_git_file_scheme_is_rejected -- --nocapture
cargo test -p hushd remote_extends::tests::scp_style_git_remote_must_be_allowlisted -- --nocapture
cargo test -p hushd remote_extends::tests::parse_git_remote_host_rejects_unsupported_scheme -- --nocapture
```
Expected output: each command reports `test result: ok` with `1 passed; 0 failed` for the selected test.

### CS-AUDIT-002 — allow_private_ips=false inconsistent for git remote extends
Bug/invariant: `allow_private_ips=false` must block private/loopback/link-local targets for git remote extends with the same behavior as HTTP extends.

Fix approach:
- Added git host resolution path (`resolve_host_addrs`) and non-public IP rejection check (`ensure_git_host_ip_policy`) for git remotes.
- Applied policy in both CLI and daemon remote resolvers.
- Preserved `https_only` behavior for URL-style git remotes where applicable.

Code pointers:
- `crates/services/hush-cli/src/remote_extends.rs:133` (`ensure_git_host_ip_policy`)
- `crates/services/hush-cli/src/remote_extends.rs:629` (`resolve_host_addrs`)
- `crates/services/hushd/src/remote_extends.rs:103` (`ensure_git_host_ip_policy`)
- `crates/services/hushd/src/remote_extends.rs:598` (`resolve_host_addrs`)

New/updated tests:
- `remote_extends_git_private_ip_blocked_when_disallowed` (CLI) rejects `ssh://127.0.0.1/...` git remote.
- `private_ip_git_remote_is_blocked_by_default` (daemon) rejects private git remote with default policy.

Proof commands:
```bash
cargo test -p hush-cli remote_extends_contract::remote_extends_git_private_ip_blocked_when_disallowed -- --nocapture
cargo test -p hushd remote_extends::tests::private_ip_git_remote_is_blocked_by_default -- --nocapture
```
Expected output: both commands report `test result: ok` and no fetch attempt succeeds for private targets.

### CS-AUDIT-003 — path guards bypassable via symlink traversal
Bug/invariant: path allowlist and forbidden-path decisions must evaluate effective filesystem target (resolved path), not only lexical path.

Fix approach:
- Added filesystem-aware normalization: canonicalize existing paths; for non-existing write targets canonicalize parent and rejoin filename.
- Path allowlist guard now matches against filesystem-aware normalized path.
- Forbidden path guard now evaluates both lexical and resolved paths; exceptions are resolved-target aware when canonicalization changes the target.

Code pointers:
- `crates/libs/clawdstrike/src/guards/path_normalization.rs:56` (`normalize_path_for_policy_with_fs`)
- `crates/libs/clawdstrike/src/guards/path_allowlist.rs:98` (`is_file_access_allowed`, `is_file_write_allowed`, `is_patch_allowed`)
- `crates/libs/clawdstrike/src/guards/forbidden_path.rs:191` (`is_forbidden` uses lexical + resolved checks)

New/updated tests:
- `symlink_escape_outside_allowlist_is_denied` ensures allowlisted symlink escaping outside scope is blocked.
- `symlink_target_matching_forbidden_pattern_is_forbidden` ensures forbidden target reached via symlink is still blocked.
- `fs_aware_normalization_uses_canonical_parent_for_new_file` covers non-existing write-target normalization.

Proof commands:
```bash
cargo test -p clawdstrike symlink_escape_outside_allowlist_is_denied --lib -- --nocapture
cargo test -p clawdstrike symlink_target_matching_forbidden_pattern_is_forbidden --lib -- --nocapture
cargo test -p clawdstrike fs_aware_normalization_uses_canonical_parent_for_new_file --lib -- --nocapture
```
Expected output: all tests pass and confirm symlink-based bypass cases are denied.

Remaining TOCTOU limitation and mitigation:
- A post-check symlink swap is still theoretically possible in any path-check-then-open model.
- Mitigation here is to canonicalize at guard evaluation time and require resolved-target matching for exceptions, reducing lexical-only bypasses without widening allow rules.

### CS-AUDIT-004 — hush run unbounded channel + task fanout memory growth
Bug/invariant: telemetry/event and proxy handling must remain bounded under adversarial flood; no unbounded queue growth.

Fix approach:
- Replaced unbounded event channel with bounded `tokio::mpsc::channel`.
- Added `EventEmitter` drop-on-full behavior using `try_send` and atomic dropped-event counter.
- Added proxy in-flight semaphore cap; saturated connections receive `503` and increment rejection counter.
- Exposed counters in run-end metadata and warning logs.

Code pointers:
- `crates/services/hush-cli/src/hush_run.rs:28` (`EVENT_QUEUE_CAPACITY`, `PROXY_MAX_IN_FLIGHT_CONNECTIONS`)
- `crates/services/hush-cli/src/hush_run.rs:124` (`EventEmitter` bounded emission/drop counter)
- `crates/services/hush-cli/src/hush_run.rs:232` (bounded channel creation)
- `crates/services/hush-cli/src/hush_run.rs:350` (`droppedEventCount` / `proxyRejectedConnections` metadata)
- `crates/services/hush-cli/src/hush_run.rs:731` (`start_connect_proxy` in-flight semaphore and 503 behavior)

New/updated tests:
- `event_emitter_drops_events_when_queue_is_full` verifies bounded queue and drop counting.
- `proxy_rejects_connections_when_in_flight_limit_is_reached` verifies saturated proxy returns 503 and increments rejection counter.

Proof commands:
```bash
cargo test -p hush-cli event_emitter_drops_events_when_queue_is_full -- --nocapture
cargo test -p hush-cli proxy_rejects_connections_when_in_flight_limit_is_reached -- --nocapture
```
Expected output: both tests pass; queue occupancy remains bounded and proxy saturation is observable.

### CS-AUDIT-005 — hushd session lock DashMap grows unbounded
Bug/invariant: per-session lock table must not grow monotonically after session termination/churn.

Fix approach:
- Added idle lock removal function based on `Arc` strong count.
- Added pruning method across lock-table keys.
- Invoked lock cleanup on `terminate_session` and prune pass after `terminate_sessions_for_user`.

Code pointers:
- `crates/services/hushd/src/session/mod.rs:412` (`remove_session_lock_if_idle`)
- `crates/services/hushd/src/session/mod.rs:421` (`prune_idle_session_locks`)
- `crates/services/hushd/src/session/mod.rs:643` (`terminate_session` cleanup hook)
- `crates/services/hushd/src/session/mod.rs:659` (`terminate_sessions_for_user` prune hook)

New/updated tests:
- `terminate_session_removes_idle_lock_entry` verifies lock entry cleanup on termination.
- `lock_table_does_not_grow_under_session_churn` verifies map does not grow under repeated create/lock/terminate cycles.

Proof commands:
```bash
cargo test -p hushd session::tests::terminate_session_removes_idle_lock_entry -- --nocapture
cargo test -p hushd session::tests::lock_table_does_not_grow_under_session_churn -- --nocapture
```
Expected output: both tests pass and final lock-table length is zero in churn test.

### CS-AUDIT-006 — threat_intel_guards unwrap panic on loopback bind denial
Bug/invariant: threat-intel integration tests must not panic due to loopback bind denial in restricted CI/sandbox environments.

Fix approach:
- Changed test server helper to return `std::io::Result<String>` instead of unwrapping bind/start failures.
- Added graceful per-test handling: skip on `PermissionDenied`, panic only for unexpected errors.
- Removed panic-on-spawn behavior in server task path.

Code pointers:
- `crates/libs/clawdstrike/tests/threat_intel_guards.rs:14` (`serve` now returns `Result`)
- `crates/libs/clawdstrike/tests/threat_intel_guards.rs:62` (skip handling in VT test)
- `crates/libs/clawdstrike/tests/threat_intel_guards.rs:125` (skip handling in GSB test)
- `crates/libs/clawdstrike/tests/threat_intel_guards.rs:189` (skip handling in Snyk test)

New/updated tests:
- Existing tests (`virustotal_file_hash_denies_and_caches`, `safe_browsing_denies_on_match`, `snyk_denies_on_upgradable_vulns`) now degrade gracefully instead of panicking when loopback bind is denied.

Proof commands:
```bash
cargo test -p clawdstrike --test threat_intel_guards -- --nocapture
```
Expected output: suite reports `ok`; in restricted environments, individual tests print explicit skip reason instead of panicking.

## C) Full gate run evidence
Commands executed:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

Results summary:
- `cargo fmt --all -- --check`: pass.
- `cargo clippy --all-targets --all-features -- -D warnings`: pass.
- `cargo test --workspace`: pass (all unit/integration/doc tests across workspace passed; no failing tests).

Skipped gates:
- None.
