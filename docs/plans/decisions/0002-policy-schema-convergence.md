# ADR 0002: Policy schema convergence (Rust `1.1.0` vs OpenClaw `clawdstrike-v1.0`)

Status: **ACCEPTED**  
Date: 2026-02-03

## Context

There are (at least) two incompatible policy schemas in active use:

- **Rust policy schema** (`crates/clawdstrike`): `version: "1.1.0"` with a guard-centric shape under `guards.*` (plus `settings.*`). Parsing is strict (`deny_unknown_fields`) and should fail closed.
- **TS/OpenClaw policy schema** (`@clawdstrike/openclaw`): `version: "clawdstrike-v1.0"` with an action-category shape (`egress`, `filesystem`, `execution`, `tools`, `limits`, `on_violation`, …).

Docs/plans assume the guard-centric schema for P0/P1 work (custom guards, compositions), but many integration docs/examples show the OpenClaw schema.

## Decision

Define a clear canonical schema, plus an explicit compatibility story:

1. **Canonical policy schema for “Hushclaw v1”:** the Rust guard-centric schema (`version: "1.1.0"`, top-level `guards`, `settings`, `extends`, `merge_strategy`, …).
2. **Compatibility stance (M0):**
   - **Portable policies MUST be written in the canonical schema.**
   - OpenClaw `clawdstrike-v1.0` is treated as **legacy/compat**, supported via a translation layer in the TS runtime (and eventually via `hush policy migrate` tooling).
   - Rust continues to **fail closed** on unknown/legacy schema versions (no silent acceptance).
3. **Deprecation timeline for legacy OpenClaw schema (`clawdstrike-v1.0`):**
   - **M0 (now):** docs/plans + fixtures standardize on canonical schema; legacy remains supported only where it already exists.
   - **M1:** ship migration tooling (`hush policy migrate`) and a TS translation layer; emit warnings when legacy is loaded.
   - **M2:** legacy schema requires explicit opt-in (e.g., `--accept-legacy` or a `compat:` block); default behavior is fail-closed.
   - **Next major:** remove legacy-by-default; keep only as a migration input if still needed.

## Consequences

- Workstreams can proceed in parallel: Rust keeps its strict schema; TS can implement a shim without blocking Rust.
- Docs/plans can converge on a single schema without pretending the code already does.
- “Same policy file behaves the same” becomes testable (once parity fixtures + harness exist).

## Confirmed by Connor (2026-02-03)

- Canonical v1 schema: Rust guard-centric (`version: "1.1.0"`, `guards.*`) *(ADR 0005 bumped the schema from `1.0.0` → `1.1.0` to add `custom_guards`.)*
- OpenClaw schema: legacy input with explicit deprecation timeline

## Open item (still TBD)

- Key-casing for canonical on-disk YAML (snake_case vs camelCase) and whether we commit to accepting both.
