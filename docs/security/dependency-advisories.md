# Dependency Advisory Triage (reviewed 2026-08-24)

This document tracks explicitly accepted RustSec advisories for Clawdstrike.

Policy gates:
- CI `security-audit` job runs `cargo audit --deny warnings` with explicit `--ignore` exceptions.
- CI `license-check` job runs `cargo deny check` using `deny.toml`.

| Advisory ID | Crate | Disposition | Owner | Expiry | Tracking |
|---|---|---|---|---|---|
| RUSTSEC-2024-0375 | `atty` (unmaintained) | Temporary exception (transitive via `rust-xmlsec`) | `@security-team` | 2026-12-31 | Upstream SAML stack migration away from `atty` |
| RUSTSEC-2021-0145 | `atty` (unsound) | Temporary exception (same transitive path as above) | `@security-team` | 2026-12-31 | Remove once `atty` is fully eliminated |
| RUSTSEC-2025-0141 | `bincode` (unmaintained) | Temporary exception (transitive via `regorus`) | `@policy-runtime` | 2026-12-31 | Track `regorus` migration away from `bincode` 2.x |
| RUSTSEC-2024-0388 | `derivative` (unmaintained) | Temporary exception (transitive via Alloy/EAS stack) | `@deps-maintainers` | 2026-12-31 | Track upstream Alloy dependency updates |
| RUSTSEC-2024-0411 | `gdkwayland-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0412 | `gdk` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0413 | `atk` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0414 | `gdkx11-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0415 | `gtk` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0416 | `atk-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0417 | `gdkx11` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0418 | `gdk-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0419 | `gtk3-macros` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0420 | `gtk-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0429 | `glib` (unsound iterator impls) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0436 | `paste` (unmaintained) | Temporary exception (transitive via Alloy stack) | `@deps-maintainers` | 2026-12-31 | Track upstream replacement/removal |
| RUSTSEC-2025-0057 | `fxhash` (unmaintained) | Temporary exception (transitive via `kuchikiki` in Tauri stacks) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY/tauri-utils drops `kuchikiki` or replaces `fxhash` |
| RUSTSEC-2024-0370 | `proc-macro-error` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-12-31 | Remove once GTK3 macro stack is removed from the Linux desktop dependency graph |
| RUSTSEC-2025-0134 | `rustls-pemfile` (unmaintained) | Temporary exception (transitive via `async-nats` 0.40) | `@messaging-platform` | 2026-12-31 | Track `async-nats` 0.50+ migration to `rustls-pki-types` APIs |
| RUSTSEC-2025-0075 | `unic-char-range` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-12-31 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0080 | `unic-common` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-12-31 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0081 | `unic-char-property` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-12-31 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0098 | `unic-ucd-version` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-12-31 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0100 | `unic-ucd-ident` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-12-31 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0119 | `number_prefix` (unmaintained) | Temporary exception (transitive via `indicatif` 0.17) | `@deps-maintainers` | 2026-12-31 | Track `indicatif` update to drop `number_prefix` |
| RUSTSEC-2026-0173 | `proc-macro-error2` (unmaintained) | Temporary exception (transitive via `alloy-sol-macro`) | `@deps-maintainers` | 2026-12-31 | Track Alloy dropping `proc-macro-error2` |
| RUSTSEC-2026-0049 | `rustls-webpki` 0.102.8 (CRL DP matching) | Temporary exception (transitive via `async-nats` 0.40) | `@messaging-platform` | 2026-12-31 | Upgrade `async-nats` to 0.50+ (`rustls-webpki` ^0.103) |
| RUSTSEC-2026-0098 | `rustls-webpki` 0.102.8 (URI name constraints) | Temporary exception (same transitive path as RUSTSEC-2026-0049) | `@messaging-platform` | 2026-12-31 | Upgrade `async-nats` to 0.50+ (`rustls-webpki` ^0.103) |
| RUSTSEC-2026-0099 | `rustls-webpki` 0.102.8 (wildcard name constraints) | Temporary exception (same transitive path as RUSTSEC-2026-0049) | `@messaging-platform` | 2026-12-31 | Upgrade `async-nats` to 0.50+ (`rustls-webpki` ^0.103) |
| RUSTSEC-2026-0104 | `rustls-webpki` 0.102.8 (CRL parse panic) | Temporary exception (same transitive path as RUSTSEC-2026-0049) | `@messaging-platform` | 2026-12-31 | Upgrade `async-nats` to 0.50+ (`rustls-webpki` ^0.103) |
| RUSTSEC-2026-0222 | `wasmtime` 44.0.3 (engine/store type-index mix-up) | Temporary exception (patched 46+ needs Rust 1.94; MSRV is 1.93) | `@policy-runtime` | 2026-12-31 | Take wasmtime 46.0.3+ when workspace MSRV moves to 1.94 |
| RUSTSEC-2026-0194 | `quick-xml` (duplicate-attribute quadratic) | Temporary exception (Tauri/WRY pin 0.37–0.39; patched >=0.41.0) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY pulls `quick-xml` >=0.41.0 |
| RUSTSEC-2026-0195 | `quick-xml` (NsReader namespace DoS) | Temporary exception (Tauri/WRY pin 0.37–0.39; patched >=0.41.0) | `@desktop-platform` | 2026-12-31 | Remove once Tauri/WRY pulls `quick-xml` >=0.41.0 |
| RUSTSEC-2026-0253 | `lru` 0.16.4 (pop panic-safety UAF) | Temporary exception (alloy-provider pins 0.16; patched >=0.18.2) | `@deps-maintainers` | 2026-12-31 | Track Alloy bump of `lru` to >=0.18.2 |
| RUSTSEC-2026-0097 | `rand` 0.7.3 (unsound custom logger) | Temporary exception (transitive via older Tauri/app stacks) | `@desktop-platform` | 2026-12-31 | Remove once app lockfiles drop `rand` 0.7.3 |
| RUSTSEC-2026-0105 | `core2` (unmaintained; yanked) | Temporary exception (workbench libp2p/Stronghold transitive) | `@desktop-platform` | 2026-12-31 | Remove once Stronghold/libp2p drop yanked `core2` |
| RUSTSEC-2017-0008 | `serial` (unmaintained) | Temporary exception (transitive via `portable-pty` in workbench PTY service; mitigated by strict shell/env allowlists plus backend-minted capability tokens and trusted-window guards) | `@desktop-platform` | 2026-12-31 | Ticket `SEC-PTY-001`: remove ignore immediately after upstream `portable-pty` drops `serial` |

Review notes (2026-08-24):
- Removed expired `aws-lc-rs` / `aws-lc-sys` exceptions (RUSTSEC-2026-0044..0048, 0067, 0068): workspace now uses `aws-lc-sys` 0.39.0.
- Removed `rustybuzz` / `ttf-parser` exceptions by upgrading `resvg` 0.45.1 → 0.48.1 (skrifa + harfrust).
- Removed stale pending-triage IDs that no lockfile still reports (RUSTSEC-2026-0118, 0119).
- `RUSTSEC-2026-0049` is `rustls-webpki`, not `aws-lc-rs` (doc correction).

Review rules:
- No advisory exception may be extended without a new review date and rationale.
- Expired entries must be removed or renewed in the same change that updates CI policy.
