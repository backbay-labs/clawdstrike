# Core Rust Libraries Audit

Scope: every directory under `crates/libs/`. No services, no bridges, no vendored code.

## Executive Summary

The core libraries are a study in contrasts. There is a small, beautifully-crafted nucleus — `hush-core`, `hush-proxy`, `clawdstrike-guard-sdk`, and (most of) `clawdstrike-broker-protocol` — that any principal Rust engineer would be happy to ship. `hush-core` in particular nails the basics: `thiserror`-based errors, RFC 8785 canonical JSON with a hand-written shortest-repr float canonicalizer, clean `Result` propagation, zero `.unwrap()` outside doctests, sensible module boundaries (the largest file is 718 lines), and a documented quick-start that compiles. That crate alone could be extracted, published to crates.io, and used as a recruiting artifact.

Then you scroll one directory over and find `crates/libs/clawdstrike-policy-event/src/edr/mod.rs` — a single file with **9,836 lines**, **160+ functions**, **`#![allow(dead_code, unused_imports)]`** at the top, all wildcard-re-exported through `pub use causal::*; pub use deception::*; pub use detection::*; …`. Right next to it, `edr/receipt/mod.rs` is **6,402 lines**. These are not files, they are spillover from cut-and-paste authoring. The crate uses `anyhow::Result` in 100+ public function signatures — a death sentence for any consumer trying to handle errors structurally — and `unwrap_or_default()` on every `serde_json::to_value` to hide failures. A principal would take one look at the `tree` output and close the tab.

The middle tier is uneven. `clawdstrike` itself (the marquee crate) has good bones — `Guard` and `AsyncGuard` traits are clean, `Error` enum is well-factored, `Policy` is `deny_unknown_fields` everywhere, the workspace clippy config sets `unwrap_used = "deny"` / `expect_used = "deny"`. But the engine's API surface bloats with four near-identical `add_extra_guard{,_box}/with_extra_guard{,_box}` methods, `engine.rs` and `policy.rs` are each ~4500 lines mixing production and tests, and `lib.rs` is a 64-line `cfg(feature = "full")` minefield where `full` actually enables 13 of the 15 features by default. `spine` ships three CLI binaries (3,480 lines) from a *library* crate. `bridge-runtime` is 911 lines of unsegmented `lib.rs` that returns `Result<_, String>` from every public function despite having a `PublishError` enum defined right above. `hush-wasm` checks **generated WASM JS/TypeScript artifacts into git** (`hush_wasm.js`, `hush_wasm.d.ts`, `hush_wasm_bg.wasm.d.ts`).

The verification stack (`logos-ffi`, `logos-z3`, `clawdstrike-logos`) has the worst form of half-built feature: it advertises capabilities it doesn't have. `logos-ffi` claims "FFI bindings to Logos (LEAN 4) proof system" — the actual implementation is `// TODO: Call LEAN 4 runtime via FFI` followed by `Ok(ProofResult::Unknown { reason: "LEAN FFI not yet implemented" })`. `logos-z3` honestly stubs out Layer-1 (explanatory) and Layer-2 (epistemic) checking with `"not yet implemented"`. `clawdstrike-logos/src/verifier.rs` is 3,875 lines in one file. None of this is wrong to *have*, but shipping it as `description = "FFI bindings to Logos…"` instead of `description = "Type definitions for a future LEAN integration"` is the kind of polish you'd never let through a code review at a serious shop.

Verdict: there is a real Rust engineer here. There is also a coding-agent ghost that wrote ~30,000 lines of receipt boilerplate while no one was looking, and the two have not been reconciled. With a focused two-week cleanup — splitting the two giant files, killing `bridge-runtime`'s String errors, deleting checked-in WASM artifacts, demoting `logos-*` to honest names, and moving `spine`'s binaries to `crates/services/` — this becomes a portfolio-grade workspace. Without that, the elite-engineer pitch dies the first time a reviewer types `cloc crates/libs/`.

## Crate-by-crate Inventory

| Crate | LOC | Files | Public Surface | Status |
|---|---|---|---|---|
| `hush-core` | 2,999 | 15 | crypto primitives, JCS, Merkle, Ed25519, receipts, TPM | **solid** |
| `hush-proxy` | 736 | 6 | DNS / SNI / domain policy types | **solid** |
| `clawdstrike-guard-sdk` | 469 | 5 | guest-side WASM guard trait + types | **solid** |
| `clawdstrike-guard-sdk-macros` | 131 | 1 | `#[clawdstrike_guard]` proc macro | **solid** |
| `clawdstrike-broker-protocol` | 712 | 1 | 31 wire types, capability signing | **solid but monolithic** |
| `clawdstrike-ocsf` | 5,853 | 31 | OCSF 1.4 types + converters | **solid (size justified by spec)** |
| `hush-certification` | 2,772 | 7 | audit ledger, badges, evidence bundles | **shaky (sqlite-bound, publish=false)** |
| `hush-multi-agent` | 2,131 | 9 | delegation, revocation, identity | **shaky (in-memory only)** |
| `spine` (`hush-spine`) | 7,626 | 20 | envelopes, checkpoints, NATS — plus 3 CLIs | **shaky (binaries in lib crate)** |
| `clawdstrike` | 55,037 | 109 | policy engine, 15 guards, packaging, sandbox | **shaky at the edges, solid at the core** |
| `hush-wasm` | 1,459 | 5 | wasm-bindgen wrappers + checked-in artifacts | **shaky (build outputs committed)** |
| `hush-ffi` | 2,803 | 12 | C ABI for FFI consumers | **solid** |
| `clawdstrike-policy-event` | 28,753 | 54 | PolicyEvent + EDR receipt zoo | **abandoned-feeling sprawl** |
| `bridge-runtime` | 911 | 1 | NATS outbox + axum + sqlite, all in one file | **shaky (no module split, String errors)** |
| `clawdstrike-logos` | 5,707 | 18 | policy → modal-temporal formulas | **experimental (and labeled honestly)** |
| `logos-ffi` | 1,760 | 5 | "LEAN 4 FFI" — actually zero FFI | **half-built (false advertising)** |
| `logos-z3` | 1,842 | 3 | Z3 SMT integration | **experimental (L1/L2 stubbed)** |
| `hunt-scan` | 6,267 | 12 | MCP discovery + scanning | **shaky (outside audit scope-ish; product code in libs/)** |
| `hunt-query` | 4,471 | 11 | timeline / replay / NL query | **shaky (no-op `ocsf` feature shim)** |
| `hunt-correlate` | 5,788 | 9 | correlation rules, watch mode | **shaky (NATS-heavy for a library)** |

Total: ~138K LOC across 20 crates.

## Scores

- **Rust idiomaticity:** 6/10 — `hush-core` is a 9; `clawdstrike-policy-event` and `bridge-runtime` drag it down.
- **API quality:** 5/10 — the core traits (`Guard`, `Signer`, `RevocationStore`) are clean; the periphery is god-structs (`BrokerCapabilityStatus` with 22 fields, almost all optional) and wildcard re-exports.
- **Error handling:** 5/10 — `thiserror` is standard, but `anyhow::Result` infects `policy-event`, `String` errors infect `bridge-runtime`, and `Error::SpineError(String)` collapses a perfectly good error enum into a string.
- **Documentation:** 5/10 — `hush-core`, `clawdstrike`, `hush-ffi`, and `logos-z3` have crate-level docs with examples; `clawdstrike-policy-event`, `bridge-runtime`, `hunt-correlate`, `clawdstrike-broker-protocol`, `hush-multi-agent`, `hush-certification`, `clawdstrike-ocsf`, and the giant `edr/mod.rs` either have stub docs or none. No README in 15/20 crates. Workspace README is three lines.
- **Test coverage signal:** 7/10 — tests exist for almost every public surface; ~7,000 lines in `crates/libs/clawdstrike/tests/`; proptest used throughout `hush-core` and `clawdstrike`; doctests compile and run. But ~2,400 lines of tests are buried inside `edr/mod.rs`'s 9,836 lines.
- **Architecture / separation of concerns:** 4/10 — `clawdstrike-policy-event` mashes types, conversion, simulation, OCSF, EDR receipts, deception, flight recorder, and causal graphs into one crate with two ten-thousand-line files. `spine` ships binaries. `bridge-runtime` puts SQLite outbox, NATS publisher, and an axum health server in a single `lib.rs`.
- **Cargo hygiene:** 6/10 — workspace versioning works, license is consistent, `deny.toml` exists. But `default = ["full"]` in `clawdstrike` enables 13 of 15 features by default (defeating the point), `hunt-query` has a no-op compatibility feature still hanging around, `logos-z3` skips `version.workspace = true` and pins `0.2.7` by hand.

## Strengths

Specific files and crates that look excellent and should not be touched:

- **`crates/libs/hush-core/src/canonical.rs`** — 358 lines. A hand-written shortest-repr float canonicalizer that matches `JSON.stringify()` semantics for cross-language byte-identical hashing, with five JCS conformance vectors as tests and proper proptest neighbors. The kind of code you point at in an interview.
- **`crates/libs/hush-core/src/lib.rs`** — 76 lines, clean module re-exports, a `prelude` module, doctest examples that actually compile, `#[cfg(not(target_arch = "wasm32"))]` gating TPM correctly.
- **`crates/libs/hush-core/src/error.rs`** (65 lines), **`signing.rs`** (336 lines), **`hashing.rs`** (231 lines) — all under the 500-line bar, all with `#[non_exhaustive]` errors and `thiserror` `#[from]` conversions.
- **`crates/libs/clawdstrike-guard-sdk/`** + **`clawdstrike-guard-sdk-macros/`** — five small files, one tiny proc macro, a clear `prelude`, an actually-useful trait. This is what a plugin SDK should look like.
- **`crates/libs/hush-proxy/src/lib.rs`** — 13 lines. Four modules, four `pub use` re-exports, done. The crate description matches what's inside.
- **`crates/libs/clawdstrike/src/guards/mod.rs`** lines 67-308 — `Severity`, `GuardResult`, `GuardContext`, `GuardAction`, `Guard` trait. Concise, `#[must_use]` where appropriate, doctests on the trait, `#[serde(alias = "low"|"medium"|"high")]` for backward compat.
- **`crates/libs/clawdstrike/src/error.rs`** — 118 lines. `#[non_exhaustive]` enum, `PolicyFieldError` + `PolicyValidationError` separated cleanly, `From` impls for `serde_json`, `serde_yaml`, `regex`, `hush_core`, plus a feature-gated `From<spine::Error>`.
- **`crates/libs/hush-ffi/src/lib.rs`** + `error.rs` — proper FFI hygiene with `with_ffi_guard`, thread-local last-error, `#[unsafe(no_mangle)]` on Rust 2024 edition, `string_to_c` helper that surfaces NUL errors rather than panicking.
- **`crates/libs/clawdstrike-broker-protocol/src/lib.rs`** lines 1-300 — `BrokerProvider`, `HttpMethod`, `UrlScheme`, `CredentialRef`, `ProofBinding` are well-designed value types with `deny_unknown_fields` and `#[serde(skip_serializing_if = ...)]` everywhere.
- **`crates/libs/hush-multi-agent/src/lib.rs`** — 31 lines, modules are private (`mod token;`), only carefully chosen items re-exported, sqlite gated behind a feature.
- **Workspace `[workspace.lints.clippy]` block** — `unwrap_used = "deny"`, `expect_used = "deny"`. This is real, and it's working: of the ~1,900 `.unwrap()` calls in the workspace, every single one I sampled is in `#[cfg(test)]`, doctests, or behind `#![cfg_attr(test, allow(...))]`.

## Findings

### CRITICAL — Architecture: `edr/mod.rs` is a 9,836-line monolith with `#![allow(dead_code, unused_imports)]`

- **Where**: `crates/libs/clawdstrike-policy-event/src/edr/mod.rs:1-9836`
- **What**: A single file contains 73 free functions, 88 methods, ~7,400 lines of production code, ~2,400 lines of tests, starts with `#![allow(dead_code, unused_imports)]`, and wildcard-re-exports every sibling module: `pub use action::*; pub use actor::*; pub use causal::*; pub use deception::*; pub use detection::*; pub use event::*; pub use flight_recorder::*; pub use ids::*; pub use privacy::*; pub use process::*; pub use receipt::*; pub use response::*; pub use sensor_state::*; pub use simulation::*;`. No public type lives here — it's all free helpers that serve as glue between submodules.
- **Why it matters**: Nobody can navigate this. `cargo doc` for this module is unreadable. Adding a field anywhere triggers a recompile of the entire blob. The `#![allow(dead_code)]` permanently hides dead code growth. The wildcard re-exports mean a typo in any submodule silently shadows an unrelated type at the crate boundary.
- **Recommended action**: RESTRUCTURE — split into `edr/conversion.rs`, `edr/metadata.rs`, `edr/process.rs` (already a file? merge), `edr/detection_helpers.rs`. Replace wildcard re-exports with explicit `pub use`. Move tests to `tests/edr_*.rs`. Delete the file-level `allow`s and fix what they were hiding.
- **Effort**: large (1-2 weeks)

### CRITICAL — Architecture: `edr/receipt/mod.rs` is 6,402 lines of receipt-builder boilerplate

- **Where**: `crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs:1-6402`
- **What**: 139 type definitions, dozens of `EndpointDecisionReceipt::for_*` constructors (each 50-100 lines of `EndpointReceiptEvidence::hashed("key", value)` calls), and 100+ `anyhow::Result` returns. Every receipt family has its own constructor in the same file.
- **Why it matters**: This file alone is larger than half of `hush-core`. The pattern (`for_sensor_state`, `for_telemetry_privacy`, `for_detection`, `for_response_execution`, …) screams for a `ReceiptBuilder` trait + a single `impl Family for SensorState` per family in its own file.
- **Recommended action**: REWRITE — introduce `pub trait ReceiptFamily { fn build(&self, ctx: ReceiptContext) -> EndpointDecisionReceipt; }`. Move each `for_*` into a file named after the family. Stop putting `anyhow::Result` on infallible builders.
- **Effort**: large

### CRITICAL — Cargo hygiene: `hush-wasm` checks generated WASM/JS artifacts into git

- **Where**: `crates/libs/hush-wasm/hush_wasm.js`, `hush_wasm.d.ts`, `hush_wasm_bg.wasm.d.ts`, `hush_wasm.d.ts.template`, `pkg/` (the actual 2.4 MB `hush_wasm_bg.wasm` is in `.gitignore` but the typing files derived from it are tracked)
- **What**: `git ls-files crates/libs/hush-wasm/` shows `hush_wasm.js` (44 KB) and the generated `.d.ts` files committed. The local `.gitignore` excludes only `pkg/` and `*.wasm`.
- **Why it matters**: These are build outputs. Every WASM rebuild dirties the working tree. They drift. Code review sees giant diffs in machine-generated files. Anyone publishing this crate's source distribution gets 50 KB of dead JS for free.
- **Recommended action**: WIPE — delete `hush_wasm.js`, `hush_wasm.d.ts`, `hush_wasm_bg.wasm.d.ts`, `hush_wasm.d.ts.template`, `package.json`, and `pkg/` from the tracked tree; extend `.gitignore`; have `build.sh` emit them into `target/` or `dist/` instead.
- **Effort**: trivial (15 min)

### HIGH — Half-built feature: `logos-ffi` advertises LEAN 4 FFI it does not implement

- **Where**: `crates/libs/logos-ffi/Cargo.toml:5` (description), `crates/libs/logos-ffi/src/lib.rs:99-131`
- **What**: Crate description: `"FFI bindings to Logos (LEAN 4) proof system for formal reasoning"`. Actual implementation:
  ```rust
  // TODO: Call LEAN 4 runtime via FFI
  // For now, return unknown
  Ok(ProofResult::Unknown {
      reason: "LEAN FFI not yet implemented".to_string(),
  })
  ```
  The `lean-runtime` feature flag flips a boolean and changes literally nothing else in the codebase — there is no `extern "C"` block, no `[build-dependencies]` for LEAN, no `lean.h` include.
- **Why it matters**: A reviewer reads the crate name + description and assumes formal proofs are wired up. They are not. The crate is currently a 1,760-line type library masquerading as an FFI shim. This is the worst form of demo-driven engineering.
- **Recommended action**: RESTRUCTURE — rename the crate `logos-types` (or fold it into `clawdstrike-logos`), rewrite the description to `"Type definitions and formula AST for the planned Logos verifier"`, delete the `lean-runtime` feature, delete the `lean_available` field and method.
- **Effort**: small (an afternoon)

### HIGH — Half-built feature: `logos-z3` stubs Layer 1 and Layer 2 with `"not yet implemented"`

- **Where**: `crates/libs/logos-z3/src/lib.rs:231-243`
- **What**:
  ```rust
  fn check_explanatory(&self, _formula: &Formula) -> Result<ProofResult> {
      Ok(ProofResult::Unknown {
          reason: "Explanatory (counterfactual) checking not yet implemented".to_string(),
      })
  }
  fn check_epistemic(&self, _formula: &Formula) -> Result<ProofResult> {
      Ok(ProofResult::Unknown {
          reason: "Epistemic checking not yet implemented".to_string(),
      })
  }
  ```
  Two of the three claimed verification layers are stubs that return `Unknown`.
- **Why it matters**: A consumer who routes a formula through `check_explanatory` gets a no-op success that looks like a verification result. Honesty-wise, this should either be implemented or explicitly fail.
- **Recommended action**: REWRITE — return `Err(Z3Error::UnsupportedFormula("explanatory layer (L1) is not implemented"))` until the implementation lands. Document the gap in the crate-level docs (currently the docs imply full support).
- **Effort**: trivial (30 min)

### HIGH — Cargo hygiene: `version = "0.2.7"` hard-pinned in `logos-z3`

- **Where**: `crates/libs/logos-z3/Cargo.toml:2-9`
- **What**: Every other library crate in the workspace uses `version.workspace = true`. `logos-z3` instead has:
  ```toml
  version = "0.2.7"
  edition = "2021"
  rust-version = "1.93"
  license = "Apache-2.0"
  repository = "..."
  ```
  None of these inherit from the workspace.
- **Why it matters**: When the workspace version bumps to 0.3.0, this crate silently stays at 0.2.7 and goes out of sync. Same risk for MSRV, license, repo URL.
- **Recommended action**: RESTRUCTURE — replace all five lines with `*.workspace = true`. Trivial PR.
- **Effort**: trivial

### HIGH — Architecture: `bridge-runtime` is 911 lines in one `lib.rs` with `Result<_, String>` everywhere

- **Where**: `crates/libs/bridge-runtime/src/lib.rs:89, 117, 166, 182, 262, 275, 539, 558, 822`
- **What**: Every public function returns `Result<_, String>` even though a `PublishError` enum is defined at line 60. The file mixes a SQLite outbox, an async NATS publisher, axum health/metrics handlers, and chain-state management with zero module structure.
- **Why it matters**: String errors lose type information and `?`-chain ergonomics. The 911-line single-file layout is the same anti-pattern as the EDR module on a smaller scale. The crate's job description ("shared reliability and observability runtime") is already three concerns.
- **Recommended action**: RESTRUCTURE — split into `outbox.rs`, `publisher.rs`, `chain.rs`, `health.rs`; make every function return `Result<_, PublishError>` (or split the error type per-module); remove `tokio = { features = ["full"] }` (a library should pick its features).
- **Effort**: medium (1-2 days)

### HIGH — Architecture: `spine` library crate ships three binaries totaling 3,480 lines

- **Where**: `crates/libs/spine/src/bin/checkpointer.rs` (1,938 lines), `proofs_api.rs` (1,426), `witness.rs` (116); `crates/libs/spine/Cargo.toml:43-56`
- **What**: A library crate (`crates/libs/spine`) contains three CLI binaries — gated behind a `bins` feature, but still living in the library tree. `checkpointer.rs` alone is larger than any production source file in the actual library.
- **Why it matters**: Libraries should not ship binaries; binaries belong under `crates/services/` or `crates/bins/`. The "bins feature" pattern leaks 7 optional dependencies (clap, axum, tower-http, tracing-subscriber, futures, uuid, anyhow) into the library's dependency surface, even if disabled by default.
- **Recommended action**: RESTRUCTURE — move all three binaries to `crates/services/spine-{checkpointer,proofs-api,witness}/`. Delete the `bins` feature and the seven optional deps from `crates/libs/spine/Cargo.toml`.
- **Effort**: small

### HIGH — Code smell: `clawdstrike-policy-event` uses `anyhow::Result` across 100+ public signatures

- **Where**: `crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs` (106 occurrences), `facade.rs` (13), `event.rs` (4), `stream.rs` (4), `ocsf.rs` (1), `simulate.rs` (1)
- **What**: A library crate exposes `anyhow::Result<T>` as its public return type instead of a typed error. Example: `pub fn read_events_from_str(jsonl: &str) -> anyhow::Result<Vec<PolicyEvent>>`.
- **Why it matters**: `anyhow::Error` is for application binaries, not libraries. Consumers cannot pattern-match on errors, cannot map specific failure modes to HTTP statuses, cannot decide what is retriable. `anyhow` in a library's public API is a recruiting red flag — every Rust style guide says so.
- **Recommended action**: REWRITE — define `PolicyEventError`, `EdrReceiptError`, `FacadeError` enums via `thiserror`. Convert all public signatures. Keep `anyhow` only in test code or `#[cfg(feature = "...")]` ergonomic wrappers if needed.
- **Effort**: medium

### HIGH — API design: `Error::SpineError(String)` collapses a perfectly good error enum

- **Where**: `crates/libs/clawdstrike/src/error.rs:96-97, 109-114`
- **What**:
  ```rust
  #[error("Spine error: {0}")]
  SpineError(String),
  ...
  impl From<spine::Error> for Error {
      fn from(e: spine::Error) -> Self {
          Error::SpineError(e.to_string())
      }
  }
  ```
  `spine::Error` is presumably a structured enum, but it's stringified into a leaf variant.
- **Why it matters**: Loses every bit of structural information. Same complaint as anyhow, smaller scope. Other `From` impls in the same file correctly use `#[from]` (`std::io::Error`, `serde_json::Error`, `serde_yaml::Error`, `regex::Error`, `hush_core::Error`).
- **Recommended action**: REWRITE — `Spine(#[from] spine::Error)`. Two lines.
- **Effort**: trivial

### HIGH — API design: `BrokerCapabilityStatus` is a 22-field god struct, most fields `Option`

- **Where**: `crates/libs/clawdstrike-broker-protocol/src/lib.rs:405-447`
- **What**: A wire type with 22 fields, 15 of which are `Option<T>` or `BTreeMap` defaults. The struct mixes capability identity, lifecycle, execution stats, intent preview, minted identity, and delegation lineage.
- **Why it matters**: Optional-soup makes the type's actual invariants impossible to read. What's required at issue time vs. after first execution vs. after revocation? Nobody can tell from the type.
- **Recommended action**: REWRITE — split into `BrokerCapability` (issue-time, immutable), `BrokerCapabilityRuntime` (execution counters), and `BrokerCapabilityProof` (lineage + minted identity). Use enum states for lifecycle (`Active { execution_count: u64 }`, `Revoked { revoked_at: DateTime<Utc>, reason: String }`).
- **Effort**: medium

### HIGH — Half-built feature: `WasmPolicyLab` holds an `inner` that no method uses

- **Where**: `crates/libs/hush-wasm/src/policy_lab.rs:22-37`
- **What**:
  ```rust
  #[wasm_bindgen]
  pub struct WasmPolicyLab {
      #[allow(dead_code)]
      inner: PolicyLabHandle,
  }
  #[wasm_bindgen]
  impl WasmPolicyLab {
      #[wasm_bindgen(constructor)]
      pub fn new(policy_yaml: &str) -> Result<WasmPolicyLab, JsError> { ... }
  }
  ```
  The constructor parses YAML and stores a `PolicyLabHandle`. There are zero methods that use `self.inner`. The `#[allow(dead_code)]` is the smoking gun.
- **Why it matters**: This is a placeholder for an API that doesn't exist yet, shipped as if it does. The constructor performs validation and throws on bad YAML — fine — but the type is otherwise inert.
- **Recommended action**: REWRITE — either implement the obvious methods (`synth`, `simulate`, etc.) as `impl` blocks using `self.inner`, or delete the struct and keep the free functions only.
- **Effort**: small

### HIGH — API bloat: `HushEngine` has four near-identical "add extra guard" methods

- **Where**: `crates/libs/clawdstrike/src/engine.rs:241-277`
- **What**:
  ```rust
  pub fn with_extra_guard<G: Guard + 'static>(mut self, guard: G) -> Self
  pub fn with_extra_guard_box(mut self, guard: Box<dyn Guard>) -> Self
  pub fn add_extra_guard<G: Guard + 'static>(&mut self, guard: G) -> &mut Self
  pub fn add_extra_guard_box(&mut self, guard: Box<dyn Guard>) -> &mut Self
  ```
  Plus a separate `HushEngineBuilder` with its own `with_keypair` / `with_generated_keypair` that duplicate the inherent methods.
- **Why it matters**: Four methods that do the same thing (push into `Vec<Box<dyn Guard>>`) is the textbook example of API bloat. The `_box` variants exist because someone hit "I have a `Box<dyn Guard>` and the generic version won't take it" — that's solvable with `impl Into<Box<dyn Guard>>`.
- **Recommended action**: REWRITE — keep `add_extra_guard<G: Into<Box<dyn Guard>>>(&mut self, guard: G)` and `with_extra_guard<G: Into<Box<dyn Guard>>>(mut self, guard: G) -> Self`. Delete the two `_box` variants. Choose one of builder vs. inherent and stop duplicating.
- **Effort**: small

### MEDIUM — Cargo hygiene: `clawdstrike` `default = ["full"]` defeats feature-gating

- **Where**: `crates/libs/clawdstrike/Cargo.toml:77-108`
- **What**: 15 features defined, `default = ["full"]`, `full = ["policy-event", "spine", "dep:tokio", "dep:dirs", "dep:nono", "dep:dashmap", "dep:futures", "dep:uuid", "dep:reqwest", "dep:sha2", "dep:semver", "dep:pubgrub", "dep:tar", "dep:zstd"]`. So the default build pulls 12 optional dependencies including `reqwest` (with `blocking`), `pubgrub`, `tar`, `zstd`, `wasmtime` (when `wasm-plugin-runtime` is on).
- **Why it matters**: The whole point of feature-gating optional deps is to let downstream consumers opt out. A `default = ["full"]` where `full` enables everything is identical to no feature gating at all, except now you have to remember to pass `--no-default-features` and hand-curate. Build times suffer; the WASM-compatible detection surface is hidden behind a feature that consumers must explicitly disable.
- **Recommended action**: RESTRUCTURE — `default = []` or `default = ["policy-event"]`. Document that `full` is opt-in. Add a `cargo check --no-default-features` to CI to lock the minimal surface.
- **Effort**: small (but breaking)

### MEDIUM — Architecture: `clawdstrike/src/policy.rs` is 4,156 lines with ~1,700 lines of tests

- **Where**: `crates/libs/clawdstrike/src/policy.rs:1-2380` (production), `2381-4156` (tests)
- **What**: A single file with the entire policy schema, validation, resolver, custom guards, and 1,700 lines of `#[cfg(test)] mod tests`. The policy module is the API contract of the entire engine.
- **Why it matters**: This file is impossible to skim. The schema's invariants are buried 1,500 lines down. Move tests to `tests/policy_*.rs` integration tests — they'll catch the same things and the source file becomes navigable.
- **Recommended action**: RESTRUCTURE — split `policy.rs` into `policy/mod.rs` (public types), `policy/resolver.rs`, `policy/validation.rs`, `policy/custom_guards.rs`. Hoist tests into `tests/policy_*.rs`.
- **Effort**: medium

### MEDIUM — Architecture: `clawdstrike/src/engine.rs` is 4,599 lines

- **Where**: `crates/libs/clawdstrike/src/engine.rs:1-1796` (production), `1797-4599` (tests)
- **What**: Engine struct (140 lines), 5 wrapper types (`PostureAwareReport`, `GuardEvaluationMetadata`, etc.), 2,800 lines of tests, plus a `HushEngineBuilder` at the bottom that duplicates the inherent constructor methods.
- **Why it matters**: Same problem as `policy.rs`. The test bloat is the bigger sin.
- **Recommended action**: RESTRUCTURE — move tests to `tests/engine_*.rs`; lift the builder to its own file.
- **Effort**: medium

### MEDIUM — Code smell: `unwrap_or` on `serde_json::to_value` hides failures

- **Where**: `crates/libs/clawdstrike-policy-event/src/edr/mod.rs:78-80` (and many more)
- **What**:
  ```rust
  let value = serde_json::to_value(sensor_state).unwrap_or(serde_json::Value::Null);
  let canonical = canonicalize_json(&value).unwrap_or_else(|_| "null".to_string());
  sha256(canonical.as_bytes()).to_hex_prefixed()
  ```
  If serialization fails, the content hash is just `sha256("null")` — a single magic value that collides across every receipt for every type. Silent corruption.
- **Why it matters**: This is a fail-closed system. Silent fallback to a deterministic-but-wrong hash is the opposite of fail-closed. Find every `.unwrap_or` on `to_value`/`canonicalize_json` and replace with `Result` propagation.
- **Recommended action**: REWRITE — change the helper signature to `Result<String, _>`; callers either propagate or use a sentinel that is distinguishable from real content.
- **Effort**: medium

### MEDIUM — Docs: `crates/libs/README.md` is three lines

- **Where**: `crates/libs/README.md`
- **What**: Full content:
  ```
  # Library Crates

  Reusable Rust libraries live here.
  ```
- **Why it matters**: A reviewer landing here needs a map. What's the layering? Which crates are public? Which are internal (`publish = false`)? What's the deprecation policy? What's the MSRV? With 20 crates this is the front door of the library tier.
- **Recommended action**: DOCUMENT — write a 100-200 line README with a dependency graph (use mermaid), per-crate one-liner, publish status, and a "Which crate should I depend on?" decision table.
- **Effort**: small

### MEDIUM — Docs: 15 of 20 crates have no `README.md`

- **Where**: missing for `spine`, `hush-multi-agent`, `hush-certification`, `hush-proxy`, `hush-ffi`, `clawdstrike-broker-protocol`, `clawdstrike-ocsf`, `clawdstrike-policy-event`, `clawdstrike-logos`, `logos-ffi`, `logos-z3`, `bridge-runtime`, `hunt-*`, `clawdstrike-guard-sdk*`
- **What**: Only `hush-core`, `hush-wasm`, and `clawdstrike` have crate-level READMEs.
- **Why it matters**: `cargo publish` and crates.io show the README. Without one, the crate page is a Cargo.toml dump. Internal devs also need quick onboarding.
- **Recommended action**: DOCUMENT — even a 30-line README per crate is enough. Auto-generate from `//!` doc comments where they exist.
- **Effort**: medium (~3-4 hours of mechanical work)

### MEDIUM — API surface: `clawdstrike::core` is an empty re-export trick

- **Where**: `crates/libs/clawdstrike/src/lib.rs:219-225`
- **What**:
  ```rust
  pub mod crypto {
      pub use hush_core::*;
  }

  /// Preserves the historical `hush_core::*` re-export while adding the
  /// pure decision core (`CoreSeverity`, `CoreVerdict`, etc.).
  pub mod core;
  ```
  The `crypto` module is a wildcard pass-through. The `core` module is declared but its definition (`src/core.rs`?) and the relationship to `crypto` is unclear from the lib root.
- **Why it matters**: A consumer asking "where do I get `Hash` from?" sees `clawdstrike::crypto::Hash`, `clawdstrike::core::Hash`, and `hush_core::Hash` — three paths to the same type. Wildcard re-exports of an entire crate break semver-on-additions in `hush_core`.
- **Recommended action**: RESTRUCTURE — replace `pub mod crypto { pub use hush_core::*; }` with explicit re-exports of the 6-8 actually-used types. Decide whether `clawdstrike::core` or `clawdstrike::crypto` is the canonical name and deprecate the other.
- **Effort**: small

### MEDIUM — Code smell: `Result<Self, String>` in `bridge-runtime::SqliteOutbox::open`

- **Where**: `crates/libs/bridge-runtime/src/lib.rs:89-105`
- **What**: An async constructor returns `Result<Self, String>`, doing `.map_err(|e| format!("failed to create outbox directory: {e}"))` for I/O errors and `.map_err(|e| format!("failed to open outbox sqlite db: {e}"))` for rusqlite errors. `PublishError` is defined in the same file with `Outbox(String)` and the right variants for both cases.
- **Why it matters**: Already covered in the bridge-runtime finding; flagging this specific function because it's the most obvious case — the error type literally exists 30 lines above.
- **Recommended action**: REWRITE — return `Result<Self, PublishError>`. Use `#[from]` on `std::io::Error` and `rusqlite::Error`.
- **Effort**: trivial

### MEDIUM — Cargo hygiene: `hunt-query` has a no-op `ocsf` feature shim

- **Where**: `crates/libs/hunt-query/Cargo.toml` (features block) + `crates/libs/hunt-query/src/lib.rs:5-7`
- **What**:
  ```toml
  [features]
  ocsf = []
  ```
  ```rust
  //! OCSF projection is part of the crate's baseline surface. The legacy `ocsf`
  //! cargo feature remains as a no-op compatibility shim for downstream manifests
  //! that still enable it.
  ```
- **Why it matters**: Dead feature flag. The "compatibility shim" comment implies external pinning, but the workspace controls all consumers — `grep -r 'hunt-query/ocsf'` should find every reference and they can all be updated.
- **Recommended action**: WIPE — delete the feature, grep the workspace, remove from any `features = [...]` lists.
- **Effort**: trivial

### MEDIUM — Code smell: `hush-multi-agent::token` uses `Result<_, String>` in trait surface

- **Where**: `crates/libs/clawdstrike/src/jailbreak.rs:26-37`
- **What**:
  ```rust
  #[async_trait]
  pub trait LlmJudge: Send + Sync {
      async fn score(&self, input: &str) -> Result<f32, String>;
  }
  #[async_trait]
  pub trait SessionStore: Send + Sync {
      async fn load(&self, session_id: &str) -> Result<Option<SessionAggPersisted>, String>;
      async fn save(&self, session_id: &str, state: SessionAggPersisted) -> Result<(), String>;
  }
  ```
  Two public traits return `Result<_, String>`. These will be implemented by external integrations (a real LLM provider, a real session store).
- **Why it matters**: External impls can't surface typed errors (rate-limit, auth failure, transient network) through a `String`. This is a trait-design footgun on the way out the door.
- **Recommended action**: REWRITE — define `LlmJudgeError` and `SessionStoreError` enums. Even a one-variant `enum LlmJudgeError { #[error("LLM judge error: {0}")] Other(String) }` is strictly better and lets future variants be added without a breaking change to impls.
- **Effort**: small

### MEDIUM — Architecture: `clawdstrike-logos/src/verifier.rs` is 3,875 lines

- **Where**: `crates/libs/clawdstrike-logos/src/verifier.rs`
- **What**: Single file holds `VerificationBackend`, `AttestationLevel`, verification options, formula inspection, Z3 integration, guard-specific inheritance checks, and `#[cfg(test)]` blocks.
- **Why it matters**: Same monolith problem at smaller scale. Split by backend and by guard family.
- **Recommended action**: RESTRUCTURE — `verifier/mod.rs`, `verifier/formula_inspection.rs`, `verifier/z3.rs`, `verifier/guards/{egress,path,mcp,shell}.rs`.
- **Effort**: medium

### MEDIUM — Code smell: `#[allow(unused_mut)]` in `clawdstrike-logos/src/verifier.rs:430, 541`

- **Where**: `crates/libs/clawdstrike-logos/src/verifier.rs:430,541`
- **What**: Two `#[allow(unused_mut)]` annotations.
- **Why it matters**: `unused_mut` means a `let mut x` where `x` is never mutated. Usually a leftover from a previous refactor. Cheap to fix.
- **Recommended action**: WIPE — drop the `mut`. Two-line cleanup.
- **Effort**: trivial

### MEDIUM — API design: TPM types unconditionally re-exported, breaking WASM-target consumers

- **Where**: `crates/libs/hush-core/src/lib.rs:64-65, 74-75`
- **What**: TPM module and re-exports are gated correctly with `#[cfg(not(target_arch = "wasm32"))]`. (This is actually correct.) Flag retracted, but I checked.
- **Why it matters**: N/A — this is well-done. Leaving the entry as a positive checkpoint.
- **Recommended action**: LEAVE
- **Effort**: zero

### MEDIUM — Cargo hygiene: `publish = false` scatter

- **Where**: `clawdstrike-broker-protocol/Cargo.toml`, `hush-certification/Cargo.toml`, `hush-multi-agent/Cargo.toml`
- **What**: Three crates marked `publish = false` while the rest are publishable. No `[workspace.metadata]` documenting why or what the publication tier strategy is.
- **Why it matters**: New crates don't know which bucket they belong in. Reviewer asking "is this OSS?" has to grep three `Cargo.toml` files.
- **Recommended action**: DOCUMENT — add a comment to each `publish = false` explaining the reason ("internal protocol; not yet stable", "depends on sqlite-bound storage"), or hoist to `crates/libs/internal/` if the boundary is permanent.
- **Effort**: trivial

### LOW — Code smell: `clawdstrike-policy-event/src/ocsf.rs:423` calls a variable `stub`

- **Where**: `crates/libs/clawdstrike-policy-event/src/ocsf.rs:423-432`
- **What**:
  ```rust
  let stub = PolicyEvent { ... };
  classify_event(&stub)
  ```
  A local variable named `stub` because it's being used as a placeholder to feed into a classifier.
- **Why it matters**: The name communicates "this is hacky". `synthetic_event` or `classification_input` would do.
- **Recommended action**: REWRITE — rename. Take the opportunity to ensure the synthetic event is built via a typed constructor instead of struct literal where some fields might be wrong.
- **Effort**: trivial

### LOW — Code smell: `clawdstrike/src/plugins/loader.rs:410` writes magic bytes for a "wasm stub"

- **Where**: `crates/libs/clawdstrike/src/plugins/loader.rs:410`
- **What**: `std::fs::write(dir.path().join("guard.wasm"), b"\0asm").expect("write wasm stub");`
- **Why it matters**: This is in a test (presumably), but writing four bytes and calling it a WASM module is fragile. If WASM validation gets stricter, this test silently breaks. Use `wat` to compile a real one-instruction module — already a dev-dependency (`wat = "1.245.1"`).
- **Recommended action**: REWRITE — use `wat::parse_str("(module)")` to produce a valid empty module.
- **Effort**: trivial

### LOW — Code smell: `#[allow(dead_code)]` on three `MCP*` fields

- **Where**: `crates/libs/hunt-scan/src/mcp_client.rs:67, 69, 103`
- **What**: Three fields marked dead. (Out-of-scope crate; flagging for completeness — `hunt-scan` is a library under `crates/libs/`.)
- **Why it matters**: Same pattern as the `WasmPolicyLab.inner` smoking gun — dead fields signal half-finished features.
- **Recommended action**: RESTRUCTURE or REWRITE — either wire up the fields or delete them.
- **Effort**: small

### LOW — Documentation: doctests use `unwrap()` instead of `?`

- **Where**: `crates/libs/clawdstrike/src/lib.rs:42`, `crates/libs/hush-core/src/lib.rs:40, 43`, `crates/libs/hush-core/src/merkle.rs:66, 161-162`
- **What**:
  ```rust
  //! let policy = Policy::from_yaml(yaml).unwrap();
  //! let tree = MerkleTree::from_leaves(&leaves).unwrap();
  ```
  Public-facing doctest examples model `.unwrap()` to users.
- **Why it matters**: Users copy from docs. Modeling unwrap teaches bad habits. The Rust API Guidelines explicitly suggest `# fn main() -> Result<(), Box<dyn std::error::Error>> { ... ? ... Ok(()) }`.
- **Recommended action**: REWRITE — convert doctests to `?`-based with hidden `main` wrappers.
- **Effort**: small

### LOW — API surface: `Severity::Info` is "logged but allowed" — name is misleading

- **Where**: `crates/libs/clawdstrike/src/guards/mod.rs:67-82`
- **What**: `Severity::Info` is documented as "Informational, logged but allowed" — but other variants `Warning` / `Error` / `Critical` are *outcomes*, not just severities. A guard that returns `allowed: true, severity: Critical` is semantically weird.
- **Why it matters**: Conflates severity (informational/warning/error/critical) with disposition (allow/block). Two orthogonal axes.
- **Recommended action**: DOCUMENT (now) / REWRITE (later) — for now, doc-comment the orthogonality explicitly. For a future 0.3.0, split into `enum Outcome { Allow, Block, Quarantine }` + `enum Severity { Info, Low, Medium, High, Critical }`.
- **Effort**: small (doc only)

### LOW — Cargo hygiene: `hush-multi-agent` and `hush-certification` use `tempfile = "3"` while workspace pins `tempfile = "3.25"`

- **Where**: `crates/libs/hush-multi-agent/Cargo.toml`, `crates/libs/hush-certification/Cargo.toml`
- **What**: Loose version strings in dev-dependencies vs the workspace's explicit pin.
- **Why it matters**: `cargo deny` warns on multiple-version graphs. Two `tempfile` major-3 minors at once is a smell.
- **Recommended action**: WIPE — use `tempfile.workspace = true` consistently. Same applies to `proptest = "1"` vs the workspace's `proptest = "1.10"`.
- **Effort**: trivial

## Action Plan

Numbered, prioritized. Each step is independent unless noted.

1. **Delete checked-in WASM artifacts.** `git rm crates/libs/hush-wasm/{hush_wasm.js,hush_wasm.d.ts,hush_wasm_bg.wasm.d.ts,hush_wasm.d.ts.template,package.json}` + extend `.gitignore`. (CRITICAL #3, trivial, no risk.)
2. **Rename or absorb `logos-ffi`.** Update description, remove dead `lean-runtime` feature, delete `lean_available` boolean. Either rename to `logos-types` or fold into `clawdstrike-logos`. (HIGH #4.)
3. **Stop lying in `logos-z3`.** Return `Err(Z3Error::UnsupportedFormula(...))` from `check_explanatory` and `check_epistemic` until implemented. Update crate docs. (HIGH #5.)
4. **Fix `logos-z3` workspace inheritance.** Replace hand-pinned `version = "0.2.7"`, `edition`, `license`, `rust-version`, `repository` with `*.workspace = true`. (HIGH #6.)
5. **Fix `Error::SpineError(String)` and `bridge-runtime` String errors.** Two structural error-handling fixes. (HIGH #9, HIGH #7.)
6. **Move `spine` binaries to `crates/services/`.** Drop the `bins` feature and seven optional deps. (HIGH #8.)
7. **Modularize `crates/libs/clawdstrike-policy-event/src/edr/mod.rs`.** Split the 9,836-line file. Drop the `#![allow(dead_code, unused_imports)]`. Replace wildcard re-exports. (CRITICAL #1, large.)
8. **Modularize `crates/libs/clawdstrike-policy-event/src/edr/receipt/mod.rs`.** Introduce a `ReceiptFamily` trait, one file per family. (CRITICAL #2, large.)
9. **Replace `anyhow::Result` in `clawdstrike-policy-event` public API.** Introduce `PolicyEventError`, `EdrReceiptError`. (HIGH #10.)
10. **Modularize `clawdstrike/src/{engine,policy}.rs`.** Hoist tests out of source files into `tests/`. (MEDIUM #14, #15.)
11. **Modularize `clawdstrike-logos/src/verifier.rs` (3,875 lines).** (MEDIUM #22.)
12. **Modularize `bridge-runtime/src/lib.rs`.** Already covered by #5; the split into `outbox/publisher/chain/health` files is the second half. (HIGH #7.)
13. **Fix `clawdstrike` `default = ["full"]`.** Change to `default = []` (breaking) or `default = ["policy-event"]`. Add `cargo check --no-default-features` to CI. (MEDIUM #13.)
14. **Replace `Result<_, String>` in `LlmJudge` and `SessionStore` traits.** (MEDIUM #21.)
15. **Stop silent fallback on `serde_json::to_value`.** Audit every `.unwrap_or(serde_json::Value::Null)` and `.unwrap_or_else(|_| "null".to_string())` — these are hash-collision generators in a fail-closed system. (MEDIUM #16.)
16. **Write 20 crate READMEs and rewrite `crates/libs/README.md`.** (MEDIUM #17, #18.)
17. **Resolve `clawdstrike::crypto` vs `clawdstrike::core` ambiguity.** (MEDIUM #19.)
18. **Implement or delete `WasmPolicyLab`.** (HIGH #11.)
19. **Collapse the four `add_extra_guard*` variants on `HushEngine`.** (HIGH #12.)
20. **Split `BrokerCapabilityStatus`.** (HIGH #11 — wait, that's WasmPolicyLab; this is its own. Long-term: replace optional soup with state-typed variants.)
21. **Convert doctest `.unwrap()`s to `?`.** (LOW.)
22. **Delete the `hunt-query/ocsf` no-op feature shim.** (MEDIUM #20.)

## Top 10 Quick Wins (<30 min each)

1. `git rm` the 5 checked-in WASM JS/TS artifacts in `crates/libs/hush-wasm/`. Update `.gitignore`. (5 min)
2. `Error::SpineError(String)` → `Spine(#[from] spine::Error)` in `crates/libs/clawdstrike/src/error.rs:96-114`. (2 min)
3. Replace `logos-z3/Cargo.toml`'s hand-pinned `version`, `edition`, `license`, `rust-version`, `repository` with `*.workspace = true`. (3 min)
4. Delete the two `#[allow(unused_mut)]` in `crates/libs/clawdstrike-logos/src/verifier.rs:430,541` and drop the corresponding `mut`. (5 min)
5. Delete `[features] ocsf = []` from `crates/libs/hunt-query/Cargo.toml` plus any `hunt-query/ocsf` references. (10 min)
6. Make `check_explanatory` and `check_epistemic` in `crates/libs/logos-z3/src/lib.rs:231-243` return an honest `Err`. (5 min)
7. Replace `b"\0asm"` magic bytes in `crates/libs/clawdstrike/src/plugins/loader.rs:410` with `wat::parse_str("(module)").unwrap()`. (10 min)
8. Replace `Result<_, String>` in `bridge-runtime/src/lib.rs:89,117,166,182,262,275` with `Result<_, PublishError>` using the already-defined enum and `#[from]`. (25 min)
9. Rewrite `crates/libs/README.md` from three lines to a real index with a dependency table. (20 min)
10. Either implement `WasmPolicyLab.simulate/synth/etc.` or delete the struct in `crates/libs/hush-wasm/src/policy_lab.rs:22-37` — remove the `#[allow(dead_code)]` and resolve. (15 min for deletion path)

## Things to Leave Alone

These are well-built. Don't refactor for refactoring's sake.

- **`crates/libs/hush-core/`** — every file. The crate is the workspace's crown jewel: clean error enum, working doctests, RFC 8785 canonical JSON with conformance tests, sensible Merkle implementation, proper WASM gating, `Signer` trait abstraction. Future changes should preserve its current shape.
- **`crates/libs/hush-proxy/`** — small, focused, no dependencies on the engine. Let it stay tiny.
- **`crates/libs/clawdstrike-guard-sdk/`** + `clawdstrike-guard-sdk-macros/` — the plugin SDK. Five files, one proc macro, a clear contract. Shipping shape.
- **`crates/libs/hush-ffi/`** — `with_ffi_guard` + thread-local last-error is the right pattern. The C ABI hygiene is correct.
- **`crates/libs/clawdstrike/src/error.rs`** — already structured properly. Just fix the `SpineError(String)` line.
- **`crates/libs/clawdstrike/src/guards/mod.rs`** — the `Guard` trait, `GuardAction` enum, `Severity`/`GuardResult` types. The core API.
- **`crates/libs/clawdstrike-broker-protocol/src/lib.rs:1-300`** — the small value types (`BrokerProvider`, `HttpMethod`, `UrlScheme`, `CredentialRef`, `ProofBinding`). The god struct further down is the part to fix.
- **`crates/libs/clawdstrike-ocsf/`** — size is justified by the OCSF v1.4 spec surface. The structure (one file per class, one per object, separate convert/) is correct.
- **Workspace `[workspace.lints.clippy]` `unwrap_used = "deny"` / `expect_used = "deny"`** — this is doing real work, do not relax it. The `#![cfg_attr(test, allow(...))]` per-file pattern is the right escape hatch.
- **`hush-multi-agent::token::DelegationClaims`** — clean JWT-like delegation type, `deny_unknown_fields`, redelegate/ceiling pattern is well-thought-out.
- **`hush-multi-agent::lib.rs`** — 31 lines, private modules, selective re-exports. Model of a good library root.

---

Final word: the spine of this workspace is good. The flab is bad. A focused pass through the action plan above removes the embarrassments without rewriting anything that's actually working.
