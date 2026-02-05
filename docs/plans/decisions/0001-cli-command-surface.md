# ADR 0001: CLI command surface (`hush` vs `clawdstrike`)

Status: **SUPERSEDED**
Date: 2026-02-03
Superseded: 2026-02-04 (API redesign unified on `clawdstrike` as the primary CLI name)

## Context

The repo historically exposed two user-visible CLIs:

- Rust: `hush` (in `crates/hush-cli`)
- TypeScript/OpenClaw: `clawdstrike` (in `packages/clawdstrike-openclaw`)

## Original Decision (now superseded)

For M0, the original decision standardized on `hush` as the canonical CLI name, with `clawdstrike` as a compatibility wrapper.

## Current State

As of the SDK/API redesign (PR #30, #32), the project has unified on `clawdstrike` as the primary CLI name:

- **Primary CLI binary:** `clawdstrike` (commands: `clawdstrike check`, `clawdstrike policy`, etc.)
- **Legacy alias:** `hush` (still available for backwards compatibility)
- **Daemon:** `clawdstriked` (previously `hushd`)
- **Environment variables:** `CLAWDSTRIKE_*` prefix (previously `HUSHD_*`)

The crate names remain unchanged (`hush-cli`, `hush-core`, `hushd`) as internal implementation details.

## See Also

- PR #30: SDK/API Redesign - Hard cutover
- PR #32: Documentation updates for new naming
