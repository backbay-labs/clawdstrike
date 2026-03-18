# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- No unreleased changes yet.

## [0.2.7] - 2026-03-18

### Added

- Added formal verification across the policy toolchain with Lean 4 proofs, solver-backed Z3 checks, Aeneas regeneration coverage, CLI attestation reporting, and CI verification lanes (#202).

### Changed

- Normalized `0.2.7` release metadata across the Rust workspace, npm workspace, Python SDK, docker workspace manifests, OpenClaw plugin manifest, and packaging assets, and hardened the release scripts/preflight to cover those surfaces in future cuts.

### Fixed

- Fixed the OpenClaw `tool_result_persist` hook so synchronous post-result enforcement, redaction, and async scanner follow-up now run on real tool traffic instead of being silently dropped (#205).
- Hardened policy verification and extends loading semantics so strict inheritance checks, backend attestation levels, and formal verification CI behave consistently across CLI, library, and workbench flows (#202).

## [0.2.6] - 2026-03-16

### Added

- Added HushSpec support across the policy toolchain with dual-format auto-loading, bidirectional compilation, CLI migration, vendored spec sources, and fixture-backed conformance coverage (#197).
- Added the Detection Engineering IDE in Workbench with multi-format editing, visual panels, ATT&CK coverage, evidence packs, validation lab flows, and publish-time provenance controls (#196).
- Added secret-broker trust-plane work, origin-aware policy enforcement, Python and Go origin transport parity, and inbound OpenClaw message hooks across the SDK and adapter surface (#191, #181, #177, #174).
- Added the fleet security control plane plus the next wave of workbench policy-builder, origin profile, simulator, and hunt lab flows (#176, #184, #185, #186, #187, #190, #193).

### Changed

- Integrated nono kernel-level sandboxing and hardened the operator cockpit, agent/runtime handoff, and related CI flows for release readiness (#178, #175).
- Aligned release metadata to `0.2.6` across Rust, npm, Python, agent, docker workspace, and packaging manifests, and now keep internal npm package dependency ranges in sync during version bumps.

### Fixed

- HushSpec decompile now fails closed on lossy egress and severity translations, and the CLI migration path now surfaces those failures cleanly instead of silently downgrading policy intent (#197).
- Hardened CI and repo validation for the vendored `vendor/hushspec` tree, offline test disk pressure, and release-time moved-path checks (#197).
- Fixed auth, registry, remote tempdir, and FFI cache hardening issues, and removed namespace-wide Cilium L7 DNS proxy rules that were breaking DNS resolution (#188, #183).

## [0.1.2] - 2026-02-26

### Added

- **CUA Gateway** — `ComputerUseGuard`, `ShellCommandGuard`, `PathAllowlistGuard`, `RemoteDesktopSideChannelGuard`, `InputInjectionCapabilityGuard` guards; 3 remote-desktop rulesets and `ai-agent-posture` ruleset (#88)
- **Desktop Agent Overhaul** — OTA updates, session/agent tracing, Open Web UI integration, local dashboard MVP (#86)
- **Enterprise Desktop Agent** — hardened agent deployment with productionized OpenClaw ownership (#80)
- **FFI** — `hush-ffi` C ABI crate with C# SDK and Go SDK bindings (#83)
- **OpenClaw Launch Readiness** — security fixes, adapter-core alignment, PR review resolutions (#101)
- **Agent fail-closed POC** — smoke test suite for fail-closed enforcement (#63)
- **Helm confidence pipeline** — EKS smoke/resilience workflows (#65)
- **Policy Workbench** — river-based policy workbench with hushd eval hardening (#64)

### Changed

- Guard count expanded from 7 to 12 with CUA Gateway guards
- `@clawdstrike/` npm scope finalized for all public packages
- Ruleset count expanded from 5 to 9 (added `ai-agent-posture`, `remote-desktop`, `remote-desktop-permissive`, `remote-desktop-strict`)

### Fixed

- `hushd`: replace `expect(format!)` with `unwrap_or_else(panic!)` (#98)
- SDK: `host:port` network parsing and docs refresh (#81)
- SDK: resolve 44 review findings across all packages (#67)
- Helm: all-on profile with bridge/ingress contract fixes (#66)
- CI: Artifact Hub ORAS media type and badge alignment (#73, #74, #75, #78)

### Security

- Removed 22 unused Python imports flagged by CodeQL (#97)
- Updated lockfiles and acknowledged remaining advisories (#96)
- Dependency bumps: minimatch, Cargo workspace, Rust minor (#72, #85, #89, #90)

## [0.1.1] - 2026-02-10

### Added

- **npm scope migration** — packages published under `@clawdstrike/` scope (#59)
- **Helm chart** — Artifact Hub integration, chart icon, ORAS publishing
- **Argo CD** — dev deploy verification workflow (#68)
- **CI** — tag-driven publishing pipeline for Rust and npm

### Fixed

- Release pipeline: protoc installation, npm publish race conditions, crate ordering
- Adapters: bump `adapter-core` minimum to `^0.1.1` and sync lock files

[Unreleased]: https://github.com/backbay-labs/clawdstrike/compare/v0.2.7...HEAD
[0.2.7]: https://github.com/backbay-labs/clawdstrike/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/backbay-labs/clawdstrike/compare/v0.2.5...v0.2.6
[0.1.2]: https://github.com/backbay-labs/clawdstrike/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/backbay-labs/clawdstrike/compare/v0.1.0...v0.1.1
