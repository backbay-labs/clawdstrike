# Rust Security + Correctness Audit — Wave 3 Remediation (2026-02-10)

This document records remediation for CS-AUDIT3-001 through CS-AUDIT3-003.
Remediation branch: `audit-fix/2026-02-10-wave3-remediation`
Start HEAD: `b739d96e4c1a1ca3e0b2aa7589f6baa44af63dc0`
Merged as: `N/A (not merged yet)`

## Tracking checklist

- [x] CS-AUDIT3-001 (High) CONNECT hostname target is not IP-pinned; private/non-public IP gate missing for hostname CONNECT
- [x] CS-AUDIT3-002 (Medium) IRM fs object-path extraction misses non-first arg object path; “no path found -> Allow” bypass
- [x] CS-AUDIT3-003 (Low) cargo audit warnings: unsound/unmaintained advisories triage + policy gate with documented exceptions

## CS-AUDIT3-001 — CONNECT hostname target pinning + non-public IP enforcement

### What was wrong
CONNECT requests using hostnames were policy-checked by host, but the dial path could re-resolve DNS later and connect to a different IP. This left a gap where the dial target was not pinned to the policy-evaluated resolution and non-public IPs were not explicitly gated for hostname CONNECT targets.

### Fix strategy
- Added single-pass CONNECT hostname resolution before upstream dial.
- Added explicit resolution-time policy gate for `allow_private_ips`:
  - If `allow_private_ips=false`, the proxy selects only public resolved addresses.
  - If all resolved addresses are non-public, request is denied.
- Pinned a concrete `SocketAddr` for dial and switched dial path to that pinned address.
- Kept SNI consistency behavior for IP CONNECT targets unchanged.
- Added observability event details with host, port, resolved IP list, selected pinned IP, and allow/deny reason.
- Added CLI control for this behavior: `--proxy-allow-private-ips`.

### Code pointers
- `crates/services/hush-cli/src/hush_run.rs`
  - `handle_connect_proxy_client`
  - `resolve_connect_hostname_target`
  - `resolve_connect_hostname_target_with_resolver`
  - `connect_resolution_block_result`
- `crates/services/hush-cli/src/main.rs`
  - run command args (`proxy_allow_private_ips`)
- `crates/services/hush-cli/src/policy_observe.rs`
  - run args wiring for `proxy_allow_private_ips`

### Tests added
- `connect_proxy_hostname_target_is_ip_pinned_after_policy_check`
  - Uses injectable resolver hook returning different addresses across calls.
  - Asserts resolver is used once and selected dial target stays pinned to first (policy-check) resolution.
- `connect_proxy_hostname_target_rejects_non_public_resolution_when_private_disallowed`
  - Asserts hostname CONNECT resolution to loopback is denied when private IPs are disallowed.

### Proof commands
- `cargo test -p hush-cli connect_proxy_hostname_target_is_ip_pinned_after_policy_check -- --nocapture`
- Observed: `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 136 filtered out; finished in 0.01s`

## CS-AUDIT3-002 — IRM filesystem arg scanning + fail-closed on missing path

### What was wrong
Filesystem IRM extraction only checked object-form paths on the first argument. A path in later object args could be missed, causing `no path found` to default to allow.

### Fix strategy
- Expanded object-form path extraction to scan all args, not only `args.first()`.
- Added support for known object keys across args: `path`, `file_path`, `target_path`.
- Changed filesystem evaluation behavior to fail closed when no path can be extracted for filesystem calls.
- Kept traversal detection checks intact so extracted relative traversal forms remain denied.

### Code pointers
- `crates/libs/clawdstrike/src/irm/fs.rs`
  - `extract_path`
  - `evaluate`

### Tests added
- `filesystem_irm_denies_traversal_when_path_is_in_nonfirst_object_arg`
  - First arg is a non-path object; second arg carries traversal path.
  - Asserts deny with traversal-related reason.
- `filesystem_irm_denies_when_no_path_can_be_extracted`
  - Asserts fail-closed deny when a filesystem event has no extractable path.

### Proof commands
- `cargo test -p clawdstrike irm::fs::tests::filesystem_irm_denies_traversal_when_path_is_in_nonfirst_object_arg -- --exact`
- Observed: `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 223 filtered out; finished in 0.01s`

## CS-AUDIT3-003 — Dependency advisory governance policy

### What was wrong
RustSec unsound/unmaintained advisories were present in dependency graph and required explicit governance with auditable ownership, expiration, and CI policy enforcement.

### Fix strategy
- Added explicit advisory governance documentation with owner/expiry and tracking notes.
- Updated `deny.toml` advisory exceptions with owner and expiry metadata.
- Updated CI `security-audit` step to run `cargo audit --deny warnings` with explicit advisory IDs for accepted temporary exceptions.
- Retained `cargo deny check` in CI so advisory policy remains reviewable in version-controlled config.

### Code pointers
- `deny.toml`
- `.github/workflows/ci.yml`
- `docs/security/dependency-advisories.md`

### Advisory disposition
- `RUSTSEC-2024-0375` (`atty` unmaintained): temporary exception
- `RUSTSEC-2021-0145` (`atty` unsound): temporary exception
- `RUSTSEC-2025-0141` (`bincode` unmaintained): temporary exception
- `RUSTSEC-2024-0388` (`derivative` unmaintained): temporary exception
- `RUSTSEC-2024-0436` (`paste` unmaintained): temporary exception
- `RUSTSEC-2025-0134` (`rustls-pemfile` unmaintained): temporary exception

### Proof commands
- `cargo audit --deny warnings --ignore RUSTSEC-2024-0375 --ignore RUSTSEC-2025-0141 --ignore RUSTSEC-2024-0388 --ignore RUSTSEC-2024-0436 --ignore RUSTSEC-2025-0134 --ignore RUSTSEC-2021-0145`
- Observed: `Scanning Cargo.lock for vulnerabilities (783 crate dependencies)` (exit code `0`)
- `cargo deny check`
- Observed: `advisories ok, bans ok, licenses ok, sources ok`

## Validation gates

### Commands
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --workspace`

### Observed output summary
- `cargo fmt --all -- --check`: exit code `0`
- `cargo clippy --all-targets --all-features -- -D warnings`: `Finished 'dev' profile ...`
- `cargo test --workspace`: repeated crate/test summaries with final per-suite `test result: ok ...` and no failures

## Regression matrix

- `CS-AUDIT3-001` -> `connect_proxy_hostname_target_is_ip_pinned_after_policy_check`, `connect_proxy_hostname_target_rejects_non_public_resolution_when_private_disallowed`
- `CS-AUDIT3-002` -> `filesystem_irm_denies_traversal_when_path_is_in_nonfirst_object_arg`, `filesystem_irm_denies_when_no_path_can_be_extracted`
- `CS-AUDIT3-003` -> `cargo audit --deny warnings ...` policy gate + `cargo deny check`
