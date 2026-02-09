# Crates

Rust workspace crates grouped by operational role.

Layout:

1. `crates/libs/` - reusable Rust libraries.
2. `crates/services/` - deployable services and CLI binaries.
3. `crates/bridges/` - bridge binaries for event ingestion/integration.
4. `crates/tests/` - cross-crate integration test crates.

Ownership and maturity:

1. Owners are defined in `.github/CODEOWNERS`.
2. Maturity levels are defined in `docs/REPO_MAP.md`.
