# ADR 0001: CLI command surface (`hush` vs `clawdstrike`)

Status: **ACCEPTED**  
Date: 2026-02-03

## Context

The repo currently exposes two user-visible CLIs:

- Rust: `hush` (in `crates/hush-cli`) with subcommands like `hush check` and `hush policy ...`.
- TypeScript/OpenClaw: `clawdstrike` (in `packages/clawdstrike-openclaw`) with `clawdstrike policy ...` and `clawdstrike audit ...`.

The docs/plans currently mix these names, which blocks parallel work (people can’t tell which commands are canonical vs implementation-specific).

## Decision

For M0, standardize documentation conventions without forcing an immediate runtime rename:

1. **Canonical CLI name for this repo’s docs/plans:** use **`hush`** for the “product CLI” and for any commands intended to exist across runtimes long-term (policy-as-code, receipts, audit).
2. **OpenClaw/Node CLI stays `clawdstrike` for now:** use **`clawdstrike`** only when the workflow is explicitly OpenClaw/TypeScript-specific (e.g., OpenClaw plugin setup, `@clawdstrike/openclaw` examples).
3. **When both exist, show both with labels:**
   - `hush ...` *(Rust / canonical)*  
   - `clawdstrike ...` *(TS/OpenClaw / compatibility surface)*
4. **Do not invent third names** (e.g. `claw`, `hushclaw`) for end-user commands in docs.
5. **Ship an alias/wrapper in this direction:** `clawdstrike` → `hush` (same verbs/flags).

## Consequences

- Docs become unambiguous while Rust and TS worktrees evolve independently.
- CLI work can implement the wrapper/alias without rewriting the plan docs again.

## Confirmed by Connor (2026-02-03)

- Canonical CLI name: `hush`
- Compatibility wrapper: `clawdstrike` forwards to `hush`
- `clawdstrike` is documented as OpenClaw/TS-specific unless explicitly stated otherwise
