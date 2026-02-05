# Repository Guidelines

## Project Structure & Module Organization

- `crates/`: Rust workspace crates (core engine, guards, CLI, daemon, WASM bindings)
- `packages/`: TypeScript SDK + framework adapters, plus Python SDK in `packages/hush-py/`
- `apps/desktop/`: Tauri + Vite desktop app
- `rulesets/`: pre-configured YAML policies used by examples and tooling
- `docs/`: mdBook source (`docs/src/**`)
- `examples/`, `fixtures/`, `scripts/`, `tools/`, `fuzz/`
- `vendor/`: vendored Rust dependencies for offline builds (avoid hand-editing)

## Build, Test, and Development Commands

Toolchains are pinned in `mise.toml` (Rust `1.93`, Node `24`, Python `3.12`).

- Rust workspace: `cargo build`, `cargo test --workspace`
- Format/lint: `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings`
- Rust “local CI”: `mise run ci`
- Full platform check (Rust + TS + Python + docs): `bash scripts/test-platform.sh`
- Offline (vendored) Rust tests: `CARGO_NET_OFFLINE=true scripts/cargo-offline.sh test --workspace --all-targets`

TypeScript packages are built/tested per-package (no root JS workspace):
- Example: `npm --prefix packages/hush-ts ci && npm --prefix packages/hush-ts test`
- Desktop: `npm --prefix apps/desktop ci && npm --prefix apps/desktop run tauri:dev`

Docs:
- `mdbook build docs` / `mdbook test docs`

## Coding Style & Naming Conventions

- Rust: `rustfmt` is authoritative. Clippy denies `unwrap()`/`expect()` at the workspace level—prefer `?` + typed errors.
- TypeScript: 2-space indentation, ESM modules. Keep public exports stable; run `npm run typecheck` in touched packages.
- Python (`packages/hush-py`): 4-space indentation, `ruff` (line length 100) + `mypy --strict`.

## Testing Guidelines

- Rust: `cargo test -p <crate>`; add unit/integration tests for guard/policy changes (property tests may use `proptest`).
- TypeScript: `vitest` with `*.test.ts` / `*.e2e.test.ts` naming; run `npm test` in affected packages.
- Python: `pytest` under `packages/hush-py/tests/` (`test_*.py`).

## Commit & Pull Request Guidelines

- Commits follow Conventional Commits (seen in history): `feat:`, `fix:`, `docs:`, `chore(deps):`, with optional scopes (e.g. `feat(desktop): …`) and `!` for breaking changes.
- Branches typically use `feature/<name>` or `fix/<name>`.
- PRs: keep scope tight, link issues (“Closes #123”), update docs for public API changes, and include screenshots for `apps/desktop` UI changes.
- Security reports: follow `SECURITY.md` (no public issues for vulnerabilities).
