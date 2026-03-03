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
| RUSTSEC-2024-0436 | `paste` (unmaintained) | Temporary exception (transitive via Alloy stack) | `@deps-maintainers` | 2026-06-30 | Track upstream replacement/removal |
| RUSTSEC-2025-0134 | `rustls-pemfile` (unmaintained) | Temporary exception (transitive via `async-nats`) | `@messaging-platform` | 2026-06-30 | Track migration to `rustls-pki-types` APIs |
| RUSTSEC-2025-0119 | `number_prefix` (unmaintained) | Temporary exception (transitive via `indicatif`) | `@deps-maintainers` | 2026-06-30 | Track `indicatif` update to drop `number_prefix` |

Review rules:
- No advisory exception may be extended without a new review date and rationale.
- Expired entries must be removed or renewed in the same change that updates CI policy.
