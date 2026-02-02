# Rust-killa Status

This file tracks the “docs/plans/rust-killa” execution backlog as applied to this repository checkout.

## Completed (this repo)

- PR-001: Rust example `examples/rust/basic-verification` updated to current `SignedReceipt` model.
- PR-002: Rulesets made single-source-of-truth via embedded `rulesets/*.yaml` and `RuleSet::list()`/`RuleSet::by_name()`.
- PR-003: Policy validation now fails closed on invalid glob/regex patterns (aggregated errors).
- PR-004: Typed config actions (`default_action` enums) for egress + MCP tool config.
- PR-005: Engine semantics preserve warnings and expose per-guard evidence via `GuardReport`.
- PR-006: mdBook docs rewritten to match the current Rust implementation (no phantom CLI/schema).
- PR-007: CLI exit codes + `--json` output for `hush check` and `hush verify` (versioned JSON + tests).
- PR-008: Canonical JSON golden vectors + deterministic float formatting (ryu-based) for `hush-core`.
- PR-009: Receipt schema drift prevention (strict schema version validation + deny-unknown-fields + fixtures/tests).
- PR-010: Full domain glob semantics via `globset` (case-insensitive; validated at policy load).
- PR-011: Parser hardening: fuzz/property tests for DNS/SNI parsing.
- PR-012: API safety: `#[must_use]` on guard results + reduced public surface area + `#[non_exhaustive]` errors.
- PR-013: Performance micro-optimizations (removed avoidable allocations in hashing + guard evaluation hot paths).
- PR-014: Dependency hygiene (removed unused deps; manifests match actual usage).
- PR-015: CI gates for fmt/clippy/test (plus docs validation and offline vendoring job).
- PR-016: Offline builds via vendored Rust deps (`vendor/` + `.cargo/config.toml`).
- PR-017: Docs code blocks validated (bash/sh syntax checked in CI; no execution).
- PR-018: Threat model clarified (enforced vs attested; explicit limitations).
- EXTRA: Prompt-injection hygiene utilities + `PromptInjectionGuard` for `untrusted_text`, including fingerprint-based dedupe helper.

## In progress / next

- (none)

## Validation commands

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## 3-hour cadence script

To run continuous checks for ~3 hours and write logs under `target/rust-killa/`:

```bash
bash scripts/rust-killa-cadence.sh
```
