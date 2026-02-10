# Clawdstrike Audit Remediation (2026-02-10)

## Remediation Metadata
- Audit report date: 2026-02-10
- Audit report: `docs/audits/2026-02-rust-security-correctness-audit.md`
- Remediation branch: `audit-fix/2026-02-10-remediation`
- Primary remediation commit: `b14547ee` (`fix(audit): remediate CS-AUDIT-001..006`)

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
- Explicitly rejected unsupported git remote schemes (`file://`, and other non `http/https/ssh/git`).

Code pointers:
- `crates/services/hush-cli/src/remote_extends.rs:356`
- `crates/services/hush-cli/src/remote_extends.rs:581`
- `crates/services/hush-cli/src/remote_extends.rs:611`
- `crates/services/hushd/src/remote_extends.rs:326`
- `crates/services/hushd/src/remote_extends.rs:551`

New/updated tests:
- `remote_extends_git_scp_host_must_be_allowlisted`
- `remote_extends_git_file_scheme_is_rejected`
- `scp_style_git_remote_must_be_allowlisted`
- `parse_git_remote_host_rejects_unsupported_scheme`

Proof commands:
```bash
cargo test -p hush-cli remote_extends_contract::remote_extends_git_scp_host_must_be_allowlisted -- --nocapture
cargo test -p hush-cli remote_extends_contract::remote_extends_git_file_scheme_is_rejected -- --nocapture
cargo test -p hushd remote_extends::tests::scp_style_git_remote_must_be_allowlisted -- --nocapture
cargo test -p hushd remote_extends::tests::parse_git_remote_host_rejects_unsupported_scheme -- --nocapture
```
Observed output snippet:
```text
test tests::remote_extends_contract::remote_extends_git_scp_host_must_be_allowlisted ... ok
test tests::remote_extends_contract::remote_extends_git_file_scheme_is_rejected ... ok
test remote_extends::tests::scp_style_git_remote_must_be_allowlisted ... ok
test remote_extends::tests::parse_git_remote_host_rejects_unsupported_scheme ... ok
```
Observed/guaranteed rejection strings (asserted by tests):
- `Remote extends host not allowlisted:`
- `Unsupported git remote scheme for remote extends:`

### CS-AUDIT-002 — allow_private_ips=false inconsistent for git remote extends
Bug/invariant: `allow_private_ips=false` must block private/loopback/link-local targets for git remote extends with the same behavior as HTTP extends.

Fix approach:
- Added git host resolution path (`resolve_host_addrs`) and non-public IP rejection check (`ensure_git_host_ip_policy`) for git remotes.
- Applied policy in both CLI and daemon remote resolvers.
- Resolution semantics are fail-closed over the full resolved address set: if any resolved address is non-public, resolution is rejected (not "first address wins").
- IPv6 policy blocks loopback/link-local/private ranges (`::1`, `fe80::/10`, `fc00::/7`, `ff00::/8`); IPv4-mapped IPv6 addresses (for example `::ffff:127.0.0.1`) are treated by their embedded IPv4 publicness and are rejected when private.

Code pointers:
- `crates/services/hush-cli/src/remote_extends.rs:133`
- `crates/services/hush-cli/src/remote_extends.rs:629`
- `crates/services/hush-cli/src/remote_extends.rs:744`
- `crates/services/hush-cli/src/remote_extends.rs:816`
- `crates/services/hushd/src/remote_extends.rs:103`
- `crates/services/hushd/src/remote_extends.rs:598`
- `crates/services/hushd/src/remote_extends.rs:713`
- `crates/services/hushd/src/remote_extends.rs:785`

New/updated tests:
- `remote_extends_git_private_ip_blocked_when_disallowed` (CLI)
- `remote_extends_git_ipv4_mapped_ipv6_private_ip_blocked_when_disallowed` (CLI)
- `private_ip_git_remote_is_blocked_by_default` (daemon)
- `ipv4_mapped_ipv6_addresses_inherit_v4_publicness` (daemon)

Proof commands:
```bash
cargo test -p hush-cli remote_extends_contract::remote_extends_git_private_ip_blocked_when_disallowed -- --nocapture
cargo test -p hush-cli remote_extends_contract::remote_extends_git_ipv4_mapped_ipv6_private_ip_blocked_when_disallowed -- --nocapture
cargo test -p hushd remote_extends::tests::private_ip_git_remote_is_blocked_by_default -- --nocapture
cargo test -p hushd remote_extends::tests::ipv4_mapped_ipv6_addresses_inherit_v4_publicness -- --nocapture
```
Observed output snippet:
```text
test tests::remote_extends_contract::remote_extends_git_private_ip_blocked_when_disallowed ... ok
test tests::remote_extends_contract::remote_extends_git_ipv4_mapped_ipv6_private_ip_blocked_when_disallowed ... ok
test remote_extends::tests::private_ip_git_remote_is_blocked_by_default ... ok
test remote_extends::tests::ipv4_mapped_ipv6_addresses_inherit_v4_publicness ... ok
```
Observed/guaranteed rejection string (asserted by tests):
- `Remote extends host resolved to non-public IPs (blocked):`

### CS-AUDIT-003 — path guards bypassable via symlink traversal
Bug/invariant: path allowlist and forbidden-path decisions must evaluate effective filesystem target (resolved path), not only lexical path.

Fix approach:
- Added filesystem-aware normalization for policy checks.
- Existing paths: canonicalize symlink-resolved target before matching.
- Non-existing write/patch targets: canonicalize parent directory and rejoin filename before matching.
- Path allowlist now checks the filesystem-aware normalized path.
- Forbidden-path checks both lexical and resolved paths; exceptions are resolved-target aware when canonicalization changes the path.

Code pointers:
- `crates/libs/clawdstrike/src/guards/path_normalization.rs:56`
- `crates/libs/clawdstrike/src/guards/path_allowlist.rs:98`
- `crates/libs/clawdstrike/src/guards/forbidden_path.rs:191`

New/updated tests:
- `symlink_escape_outside_allowlist_is_denied`
- `symlink_target_matching_forbidden_pattern_is_forbidden`
- `fs_aware_normalization_uses_canonical_parent_for_new_file`

Proof commands:
```bash
cargo test -p clawdstrike symlink_escape_outside_allowlist_is_denied --lib -- --nocapture
cargo test -p clawdstrike symlink_target_matching_forbidden_pattern_is_forbidden --lib -- --nocapture
cargo test -p clawdstrike fs_aware_normalization_uses_canonical_parent_for_new_file --lib -- --nocapture
```
Observed output snippet:
```text
test guards::path_allowlist::tests::symlink_escape_outside_allowlist_is_denied ... ok
test guards::forbidden_path::tests::symlink_target_matching_forbidden_pattern_is_forbidden ... ok
test guards::path_normalization::tests::fs_aware_normalization_uses_canonical_parent_for_new_file ... ok
```
Remaining TOCTOU limitation and mitigation:
- A post-check symlink swap remains theoretically possible in any check-then-open model.
- Mitigation here is canonicalization at guard-evaluation time plus resolved-target exception matching, which removes lexical-only bypasses and keeps policy fail-closed.
- Performance note: canonicalization is only done at guard evaluation time (per tool action), not as a background scan loop.

### CS-AUDIT-004 — hush run unbounded channel + task fanout memory growth
Bug/invariant: telemetry/event and proxy handling must remain bounded under adversarial flood; no unbounded queue growth.

Fix approach:
- Replaced unbounded event channel with bounded `tokio::mpsc::channel`.
- Queue-full behavior is explicit: `try_send` drops the newest event being emitted when the queue is full, increments `droppedEventCount`, and continues without back-pressuring callers.
- Logging behavior is coalesced: one end-of-run warning reports total dropped events (no per-event flood logs).
- Added proxy in-flight semaphore cap; saturated connections receive `503 Service Unavailable` and increment `proxyRejectedConnections`.

Code pointers:
- `crates/services/hush-cli/src/hush_run.rs:28`
- `crates/services/hush-cli/src/hush_run.rs:124`
- `crates/services/hush-cli/src/hush_run.rs:232`
- `crates/services/hush-cli/src/hush_run.rs:350`
- `crates/services/hush-cli/src/hush_run.rs:731`

New/updated tests:
- `event_emitter_drops_events_when_queue_is_full`
- `proxy_rejects_connections_when_in_flight_limit_is_reached`

Proof commands:
```bash
cargo test -p hush-cli event_emitter_drops_events_when_queue_is_full -- --nocapture
cargo test -p hush-cli proxy_rejects_connections_when_in_flight_limit_is_reached -- --nocapture
```
Observed output snippet:
```text
test hush_run::tests::event_emitter_drops_events_when_queue_is_full ... ok
test hush_run::tests::proxy_rejects_connections_when_in_flight_limit_is_reached ... ok
```

### CS-AUDIT-005 — hushd session lock DashMap grows unbounded
Bug/invariant: per-session lock table must not grow monotonically after session termination/churn.

Fix approach:
- Added idle lock removal and explicit lock-table pruning functions.
- Correctness constraint: lock entries are removed only when no other holders/waiters exist (`Arc::strong_count == 1`).
- `terminate_session` now removes idle lock entries.
- `terminate_sessions_for_user` performs a prune pass after bulk termination.

Code pointers:
- `crates/services/hushd/src/session/mod.rs:412`
- `crates/services/hushd/src/session/mod.rs:421`
- `crates/services/hushd/src/session/mod.rs:643`
- `crates/services/hushd/src/session/mod.rs:659`

New/updated tests:
- `terminate_session_removes_idle_lock_entry`
- `lock_table_does_not_grow_under_session_churn`

Proof commands:
```bash
cargo test -p hushd session::tests::terminate_session_removes_idle_lock_entry -- --nocapture
cargo test -p hushd session::tests::lock_table_does_not_grow_under_session_churn -- --nocapture
```
Observed output snippet:
```text
test session::tests::terminate_session_removes_idle_lock_entry ... ok
test session::tests::lock_table_does_not_grow_under_session_churn ... ok
```

### CS-AUDIT-006 — threat_intel_guards unwrap panic on loopback bind denial
Bug/invariant: threat-intel integration tests must not panic due to loopback bind denial in restricted CI/sandbox environments.

Fix approach:
- Test server helper returns `std::io::Result<String>` instead of unwrapping bind/start failures.
- Each test now skips on `PermissionDenied` with explicit `SKIPPED:` message.
- Unexpected bind errors still fail the test with panic.

Code pointers:
- `crates/libs/clawdstrike/tests/threat_intel_guards.rs:14`
- `crates/libs/clawdstrike/tests/threat_intel_guards.rs:62`
- `crates/libs/clawdstrike/tests/threat_intel_guards.rs:125`
- `crates/libs/clawdstrike/tests/threat_intel_guards.rs:189`

New/updated tests:
- Existing threat-intel tests now degrade gracefully with explicit skip semantics in restricted environments.

Proof commands:
```bash
cargo test -p clawdstrike --test threat_intel_guards -- --nocapture
```
Observed output snippet:
```text
test virustotal_file_hash_denies_and_caches ... ok
test safe_browsing_denies_on_match ... ok
test snyk_denies_on_upgradable_vulns ... ok
```
Observed skip string contract (on restricted environments):
- `SKIPPED: <test_name>: loopback bind denied (...)`

## C) Full gate run evidence
Commands executed:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

Observed output snippets:
```text
Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.54s
Finished `test` profile [unoptimized + debuginfo] target(s) in 0.76s

test result: ok. 226 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
...
test result: ok. 130 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
...
Doc-tests clawdstrike
...
test result: ok. 3 passed; 0 failed
```

Results summary:
- `cargo fmt --all -- --check`: pass.
- `cargo clippy --all-targets --all-features -- -D warnings`: pass.
- `cargo test --workspace`: pass (all unit/integration/doc tests across workspace passed; no failing tests).

Skipped gates:
- None.

## D) Regression Matrix
- SCP/git-remote allowlist bypass prevented:
  - `remote_extends_git_scp_host_must_be_allowlisted`
  - `scp_style_git_remote_must_be_allowlisted`
- Unsupported `file://` git remotes prevented:
  - `remote_extends_git_file_scheme_is_rejected`
  - `parse_git_remote_host_rejects_unsupported_scheme`
- Private/loopback/link-local git targets prevented:
  - `remote_extends_git_private_ip_blocked_when_disallowed`
  - `remote_extends_git_ipv4_mapped_ipv6_private_ip_blocked_when_disallowed`
  - `private_ip_git_remote_is_blocked_by_default`
  - `ipv4_mapped_ipv6_addresses_inherit_v4_publicness`
- Symlink traversal bypasses prevented:
  - `symlink_escape_outside_allowlist_is_denied`
  - `symlink_target_matching_forbidden_pattern_is_forbidden`
- Event flood / unbounded memory growth bounded:
  - `event_emitter_drops_events_when_queue_is_full`
  - `proxy_rejects_connections_when_in_flight_limit_is_reached`
- Session lock-table monotonic growth prevented:
  - `terminate_session_removes_idle_lock_entry`
  - `lock_table_does_not_grow_under_session_churn`
- Loopback bind panic in tests prevented:
  - `threat_intel_guards` suite now emits explicit `SKIPPED:` when loopback bind is denied.
