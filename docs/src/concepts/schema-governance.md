# Schema Governance

Clawdstrike is a multi-language repo (Rust crates + TypeScript/Python SDKs + an OpenClaw plugin). To avoid “looks right but silently ignored” security failures, we treat **schemas as compatibility boundaries**:

- **Unknown fields are rejected** (fail-closed) where parsing is security-critical.
- **Versions are validated** and unsupported versions are rejected.
- Cross-language drift is prevented with **golden vectors** committed under `fixtures/`.

## What schemas exist?

| Schema | Used by | Version field | File format | Notes |
|---|---|---|---|---|
| Rust **policy** schema | `clawdstrike` engine + `clawdstrike` CLI + `clawdstriked` | `policy.version` (`"1.1.0"`) | YAML | Parsed with strict semver + unknown-field rejection. |
| OpenClaw **policy** schema | `@clawdstrike/openclaw` | `policy.version` (`"clawdstrike-v1.0"`) | YAML | **Not** the same as Rust policy schema; smaller surface and OpenClaw-shaped. Strict validation + unknown-field rejection. |
| **Receipt** schema | `hush-core` + SDKs | `receipt.version` (`"1.0.0"`) | JSON | Signed receipts use canonical JSON (RFC 8785 / JCS). |

## Rust vs OpenClaw policy compatibility (important)

The Rust policy schema and the OpenClaw plugin policy schema are **not wire-compatible**.

- Rust policies live under `guards.*` and are designed for the Rust `HushEngine`/`clawdstriked` stack.
- OpenClaw policies live under top-level sections like `egress`, `filesystem`, `execution`, and are designed for OpenClaw hooks + the `policy_check` tool.

If you copy a Rust policy YAML into OpenClaw (or vice-versa), the correct behavior is: **reject it**, not “best effort”.

## Migration policy

We use version bumps as a hard gate:

- If a change is backwards-incompatible (renames, semantic changes), bump the schema version and keep parsers strict.
- If a change is backwards-compatible (additive only), we still prefer a version bump if it changes security semantics.

### When you change a schema, also update:

- `fixtures/` vectors used by Rust/TS/Py tests (receipt/JCS drift prevention).
- Docs pages that show sample YAML/JSON.
- CI gates so drift can’t merge (fmt/clippy/test + SDK tests + docs validation + fuzz schedule).
