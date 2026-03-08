# Dependency Advisory Triage (2026-02-10)

This document tracks explicitly accepted RustSec advisories for Clawdstrike.

Policy gates:
- CI `security-audit` job runs `cargo audit --deny warnings` with explicit `--ignore` exceptions.
- CI `license-check` job runs `cargo deny check` using `deny.toml`.

| Advisory ID | Crate | Disposition | Owner | Expiry | Tracking |
|---|---|---|---|---|---|
| RUSTSEC-2024-0375 | `atty` (unmaintained) | Temporary exception (transitive via `rust-xmlsec`) | `@security-team` | 2026-06-30 | Upstream dependency migration in SAML stack |
| RUSTSEC-2021-0145 | `atty` (unsound) | Temporary exception (same transitive path as above) | `@security-team` | 2026-06-30 | Remove once `atty` is fully eliminated |
| RUSTSEC-2025-0141 | `bincode` (unmaintained) | Temporary exception (transitive via `regorus`) | `@policy-runtime` | 2026-06-30 | Track `regorus` migration away from `bincode` 2.x |
| RUSTSEC-2024-0388 | `derivative` (unmaintained) | Temporary exception (transitive via Alloy/EAS stack) | `@deps-maintainers` | 2026-06-30 | Track upstream Alloy dependency updates |
| RUSTSEC-2024-0411 | `gdkwayland-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0412 | `gdk` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0413 | `atk` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0414 | `gdkx11-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0415 | `gtk` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0416 | `atk-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0417 | `gdkx11` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0418 | `gdk-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0419 | `gtk3-macros` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0420 | `gtk-sys` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0429 | `glib` (unsound iterator impls) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY Linux backend no longer depends on GTK3 crates |
| RUSTSEC-2024-0436 | `paste` (unmaintained) | Temporary exception (transitive via Alloy stack) | `@deps-maintainers` | 2026-06-30 | Track upstream replacement/removal |
| RUSTSEC-2025-0057 | `fxhash` (unmaintained) | Temporary exception (transitive via `kuchikiki` in desktop Tauri stack) | `@desktop-platform` | 2026-06-30 | Remove once Tauri/WRY/tauri-utils drops `kuchikiki` or replaces `fxhash` |
| RUSTSEC-2024-0370 | `proc-macro-error` (unmaintained) | Temporary exception (transitive via Linux Tauri/WRY GTK3 stack) | `@desktop-platform` | 2026-06-30 | Remove once GTK3 macro stack is removed from the Linux desktop dependency graph |
| RUSTSEC-2025-0134 | `rustls-pemfile` (unmaintained) | Temporary exception (transitive via `async-nats`) | `@messaging-platform` | 2026-06-30 | Track migration to `rustls-pki-types` APIs |
| RUSTSEC-2025-0075 | `unic-char-range` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-06-30 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0080 | `unic-common` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-06-30 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0081 | `unic-char-property` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-06-30 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0098 | `unic-ucd-version` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-06-30 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0100 | `unic-ucd-ident` (unmaintained) | Temporary exception (transitive via `urlpattern` in `tauri-utils`) | `@desktop-platform` | 2026-06-30 | Remove once `tauri-utils` no longer depends on `urlpattern`/`unic-*` |
| RUSTSEC-2025-0119 | `number_prefix` (unmaintained) | Temporary exception (transitive via `indicatif`) | `@deps-maintainers` | 2026-06-30 | Track `indicatif` update to drop `number_prefix` |

Review rules:
- No advisory exception may be extended without a new review date and rationale.
- Expired entries must be removed or renewed in the same change that updates CI policy.
