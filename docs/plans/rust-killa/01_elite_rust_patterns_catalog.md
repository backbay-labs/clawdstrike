# Elite Rust Patterns Catalog (v3)

This is the patterns doc that should guide the “de-ai-slopify” pass. It is tailored to hushclaw and focuses on patterns
that prevent drift, enforce security boundaries, and keep APIs clean.

Constraint note: no outbound network access here, so this doc is based on stable Rust community practice and the code in this repo.

## How to use
- Pick 1-3 patterns per PR.
- Apply them mechanically and add tests.
- Update docs/examples as part of the same PR to prevent drift.

## Index

- API Safety: 4 patterns
- Async & Concurrency: 3 patterns
- Config & Serde: 7 patterns
- Docs & Maintenance: 2 patterns
- Errors: 5 patterns
- Performance: 2 patterns
- Security: 4 patterns
- Testing: 3 patterns
- Types & API: 9 patterns

## API Safety

### `#[must_use]` on security decisions
- Why it matters: A security engine that can be ignored accidentally is a foot-gun.
- What it looks like:
  ```rust
  #[must_use]
  pub struct GuardResult { /* ... */ }
  ```
- When to use:
  - Any return value representing allow/block/warn decisions.
- Pitfalls:
  - Overusing `#[must_use]` on trivial values.
- Apply to hushclaw:
  - Mark `GuardResult` and any future `GuardReport` as must-use.

### Expose evidence, not just a summary
- Why it matters: Returning only “allowed/blocked” loses debugging information and hides warnings.
- What it looks like:
  ```rust
  pub struct GuardReport {
    pub overall: GuardResult,
    pub per_guard: Vec<GuardResult>,
  }
  ```
- When to use:
  - Multi-check engines where explainability matters.
- Pitfalls:
  - Making evidence too big for hot path; consider optional detail modes.
- Apply to hushclaw:
  - Engine aggregation currently can lose warnings; evidence type fixes that.

### Minimize public surface area; re-export intentionally
- Why it matters: Public APIs become contracts; minimize what you must maintain.
- Apply to hushclaw:
  Audit `pub` items and convert internals to pub(crate).

### Use `#[non_exhaustive]` for public enums that will evolve
- Why it matters: Allows adding variants without breaking downstream matches.
- Apply to hushclaw:
  Consider for error enums and policy action enums.

## Async & Concurrency

### Avoid holding locks across `.await`
- Why it matters: Holding locks across await is a common source of deadlocks and latency spikes.
- What it looks like:
  - Acquire lock, copy needed state, drop lock, then await.
- When to use:
  - Any async code with shared state.
- Pitfalls:
  - Accidentally extending lock lifetime via references.
- Apply to hushclaw:
  - Engine state is behind `RwLock`; keep lock scopes minimal as features grow.

### Use atomics for hot counters
- Why it matters: Atomics reduce lock contention for simple counters in high-throughput scenarios.
- What it looks like:
  ```rust
  use std::sync::atomic::{AtomicU64, Ordering};
  ```
- When to use:
  - For `action_count`/`violation_count` if check rate becomes high.
- Pitfalls:
  - Over-optimizing; use only if metrics show contention.
- Apply to hushclaw:
  - `EngineState` uses `RwLock`; consider atomics later if needed.

### Prefer channels over shared mutable state for event streams
- Why it matters: Channels make backpressure and ownership explicit.
- Apply to hushclaw:
  If you add audit logging streams, use bounded channels.

## Config & Serde

### Typed enums instead of stringly config
- Why it matters: Typos in config should be rejected. Enums validate at the boundary and force exhaustive handling.
- What it looks like:
  ```rust
  #[derive(Deserialize, Serialize)]
  #[serde(rename_all = "lowercase")]
  pub enum DefaultAction { Allow, Block, Log }
  ```
- When to use:
  - Any finite config decision set.
- Pitfalls:
  - Renaming enum variants without migration strategy.
- Apply to hushclaw:
  - `EgressAllowlistConfig.default_action` and `McpToolConfig.default_action`.

### Fail-fast validation at config boundaries
- Why it matters: Security controls must fail closed: invalid patterns must not be silently dropped.
- What it looks like:
  ```rust
  pub fn validate(&self) -> Result<(), PolicyValidationError> {
    // compile patterns; collect errors
  }
  ```
- When to use:
  - Policy parsing, ruleset loading, pattern compilation.
- Pitfalls:
  - Returning early and hiding multiple errors.
- Apply to hushclaw:
  - Replace guard `filter_map(...ok())` pattern compilation with explicit validation.

### Strict mode: `deny_unknown_fields` (when schema is stable)
- Why it matters: Unknown YAML keys are usually typos. In security policy, typos should be errors.
- What it looks like:
  ```rust
  #[derive(Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct Policy { /* ... */ }
  ```
- When to use:
  - When the schema is stable enough to enforce strictly.
- Pitfalls:
  - Breaking forward compatibility; consider offering both strict and permissive parse paths.
- Apply to hushclaw:
  - Add a strict parse entrypoint or CLI flag; keep permissive parse for upgrades if needed.

### Default functions instead of implicit defaults
- Why it matters: Explicit default functions document behavior and avoid surprising serde defaults.
- What it looks like:
  ```rust
  fn default_timeout() -> u64 { 3600 }
  ```
- When to use:
  - Any field with a meaningful default that affects behavior/security.
- Pitfalls:
  - Changing defaults silently; treat it as behavior change.
- Apply to hushclaw:
  - PolicySettings already uses default functions; continue this style for other defaults.

### Version serialized formats intentionally
- Why it matters: Policies and receipts are long-lived artifacts; versioning prevents silent drift.
- What it looks like:
  ```rust
  pub const POLICY_SCHEMA: &str = "hushclaw-v1";
  ```
- When to use:
  - Any schema you expect external tools to consume.
- Pitfalls:
  - “Version” field exists but is unused/unchecked.
- Apply to hushclaw:
  - Decide what `Policy.version` and `Receipt.version` mean and validate them.

### Avoid `serde_json::Value` for core config unless truly needed
- Why it matters: Untyped JSON spreads ambiguity into the system. Prefer typed structs/enums.
- Apply to hushclaw:
  Policy and guard configs are typed today; keep it that way.

### Use `skip_serializing_if` to keep artifacts stable and compact
- Why it matters: Stable JSON/YAML output matters for signatures and diffs.
- Apply to hushclaw:
  Receipt already uses skip_serializing_if; apply to policy output if needed.

## Docs & Maintenance

### Docs are contract or roadmap, never ambiguous
- Why it matters: In security tooling, ambiguous docs are dangerous because users rely on them for safety.
- What it looks like:
  - “Not implemented yet” banners for roadmap docs.
  - Contract docs tested against implementation.
- When to use:
  - Always.
- Pitfalls:
  - Shipping docs that describe commands/schemas that don’t exist.
- Apply to hushclaw:
  - mdBook policy schema and CLI docs do not match current Rust code; pick a stance and align.

### Compile docs/examples in CI
- Why it matters: Prevents drift and keeps docs honest.
- Apply to hushclaw:
  Add CI jobs for mdBook build and example compilation (in a networked environment).

## Errors

### Structured errors with stable variants
- Why it matters: Elite Rust treats error enums as public API: predictable, matchable, forward-compatible.
- What it looks like:
  ```rust
  #[derive(thiserror::Error, Debug)]
  #[non_exhaustive]
  pub enum Error {
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
  }
  ```
- When to use:
  - In library crates used by others.
- Pitfalls:
  - Converting everything to `String` and losing structure.
- Apply to hushclaw:
  - Consider `#[non_exhaustive]` on `hush-core::Error` and `hushclaw::Error`.
  - Add a structured validation error type instead of `ConfigError(String)` for pattern failures.

### Use `anyhow` only at app boundaries
- Why it matters: Elite Rust keeps library errors typed; `anyhow` is best for binaries where you want context chaining quickly.
- What it looks like:
  ```rust
  fn main() -> anyhow::Result<()> { /* ... */ }
  ```
- When to use:
  - In `hush-cli` and `hushd`, not in `hush-core`.
- Pitfalls:
  - Letting `anyhow::Error` leak into library APIs.
- Apply to hushclaw:
  - Current split is decent: `anyhow` in binaries, `thiserror` in libs; keep it.

### Avoid boolean-only verification APIs
- Why it matters: Booleans hide why verification failed. Elite APIs offer detailed errors.
- What it looks like:
  ```rust
  pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), VerifyError>;
  ```
- When to use:
  - Signature verification, proof verification, policy validation.
- Pitfalls:
  - Returning Result but still losing error causes via strings.
- Apply to hushclaw:
  - `PublicKey::verify` returns bool; consider adding a fallible verify method for diagnostics.

### Prefer error enums with structured fields over formatted strings
- Why it matters: Structured fields support programmatic handling and better diagnostics.
- Apply to hushclaw:
  Replace `ConfigError(String)` in hushclaw with structured variants where possible.

### Add context at boundaries, not everywhere
- Why it matters: Too much context becomes noise; put context where user needs it (CLI/policy load).
- Apply to hushclaw:
  Keep hush-core errors precise; add context in hush-cli via anyhow.

## Performance

### Avoid allocations in hot paths
- Why it matters: Elite Rust code avoids allocating in tight loops (hashing, repeated checks).
- What it looks like:
  - Use fixed-size arrays for fixed-size concatenations.
  - Avoid `to_string()` just to compute size.
- When to use:
  - Hash concatenation, argument size limits, repeated engine checks.
- Pitfalls:
  - Premature optimization; measure first.
- Apply to hushclaw:
  - `concat_hashes` and `McpToolGuard` args sizing allocate; candidates for improvement.

### Avoid repeated allocations in per-action guard iteration
- Why it matters: Repeated Vec allocation per check is noise; keep a fixed slice of guards.
- Apply to hushclaw:
  `check_action` builds a Vec of guard refs each time; can be pre-built.

## Security

### Treat canonicalization as a security boundary
- Why it matters: If canonicalization differs across languages or versions, signatures can fail or be forged by ambiguity.
- What it looks like:
  - Golden vectors and cross-language fixtures.
  - Explicit versioning of receipt schema + canonicalization rules.
- When to use:
  - Any signing/verifying of JSON artifacts.
- Pitfalls:
  - Under-testing float edge cases.
- Apply to hushclaw:
  - Expand RFC 8785 vector coverage and consider `ryu` for float formatting stability.

### Never log secrets; redact early
- Why it matters: Logs are data exfiltration paths. Redact at detection time.
- What it looks like:
  - Store only redacted matches in details.
  - Avoid printing tool args verbatim.
- When to use:
  - Any structured logging or error output that might include user content.
- Pitfalls:
  - Logging entire JSON args structures for debug.
- Apply to hushclaw:
  - SecretLeakGuard redacts matches; apply similar discipline across other guards.

### Normalize domains consistently (lowercase, strip trailing dot)
- Why it matters: Inconsistent normalization creates bypass risk.
- Apply to hushclaw:
  Define a single normalization function in hush-proxy and use it everywhere.

### Document parser limitations explicitly
- Why it matters: If DNS compression pointers or TLS fragmentation are unsupported, say so to avoid false assumptions.
- Apply to hushclaw:
  Document in hush-proxy docs and in error messages.

## Testing

### Golden vectors for spec/crypto code
- Why it matters: Spec code needs exact outputs defended by known-good vectors; property tests alone are not enough.
- What it looks like:
  - Store vectors in files; assert exact outputs.
- When to use:
  - Canonical JSON, Merkle proofs, receipt signing.
- Pitfalls:
  - Only testing happy paths.
- Apply to hushclaw:
  - Add RFC 8785 canonicalization vectors and Merkle vectors.

### Examples are tests
- Why it matters: Broken examples destroy trust. Elite repos compile examples in CI.
- What it looks like:
  - CI step building examples.
- When to use:
  - Always for published crates and security tools.
- Pitfalls:
  - Examples that drift from API changes.
- Apply to hushclaw:
  - Fix/remove the outdated Rust verification example.

### Use property/fuzz tests for byte parsers
- Why it matters: Parsers are fragile; fuzzing catches panics and OOB logic errors.
- Apply to hushclaw:
  DNS/SNI parsers should never panic on random input.

## Types & API

### Newtype for semantic clarity
- Why it matters: Prevents primitive obsession (e.g., `String` everywhere) and makes invariants explicit.
- What it looks like:
  ```rust
  pub struct Domain(String);
  pub struct PolicyId(String);
  ```
- When to use:
  - When a value has domain meaning beyond its primitive representation.
  - When you want to enforce parsing/normalization at construction.
- Pitfalls:
  - Creating wrappers without conversion traits (`Display`, `FromStr`, `AsRef`).
  - Making fields public and leaking invariants.
- Apply to hushclaw:
  - Model egress domains as validated types if you expand semantics.
  - Replace stringly-typed `default_action` with enums/newtypes in guards.

### Prefer borrowed inputs (`&str`, `&[u8]`) in library APIs
- Why it matters: Borrowed inputs make ownership intent explicit and avoid forcing callers to allocate.
- What it looks like:
  ```rust
  pub fn from_hex(hex: &str) -> Result<Self> { /* ... */ }
  pub fn sign(&self, message: &[u8]) -> Signature { /* ... */ }
  ```
- When to use:
  - When you only need to read data, not store it.
  - Parsing, hashing, verification, path checks.
- Pitfalls:
  - Returning references to temporary data.
  - Overusing lifetimes in public APIs when a `Cow` would be cleaner.
- Apply to hushclaw:
  - Most hush-core APIs already accept borrowed bytes/strings; keep that discipline as you expand.

### Use `Path`/`PathBuf` for filesystem boundaries
- Why it matters: String paths are platform-footguns. `Path` preserves OS semantics and reduces normalization bugs.
- What it looks like:
  ```rust
  pub fn is_forbidden(&self, path: &Path) -> bool { /* ... */ }
  ```
- When to use:
  - Whenever you interact with actual OS paths (writes, reads, patch targets).
- Pitfalls:
  - Glob libraries often want strings; define a clear conversion boundary and normalize once.
- Apply to hushclaw:
  - ForbiddenPathGuard currently normalizes `\` to `/` manually; consider Path-based normalization + explicit glob semantics.

### Prefer enums to `bool` parameters
- Why it matters: Boolean parameters are ambiguous at call sites and invite misuse.
- What it looks like:
  ```rust
  pub enum Mode { Strict, Permissive }
  ```
- When to use:
  - When a function has multiple behavioral modes (strict vs permissive parse).
- Pitfalls:
  - Overengineering: keep enums small and meaningful.
- Apply to hushclaw:
  - If you add strict vs permissive policy parsing, use an enum or separate methods.

### Expose fallible constructors for validated types
- Why it matters: If a type has invariants, construction should enforce them at the boundary.
- What it looks like:
  ```rust
  impl Domain {
    pub fn parse(s: &str) -> Result<Self> { /* normalize + validate */ }
  }
  ```
- When to use:
  - Domains, CIDRs, policy IDs, tool names with restrictions.
- Pitfalls:
  - Having multiple constructors with unclear invariants.
- Apply to hushclaw:
  - Domain matching semantics are currently limited; if you expand them, add validated constructors.

### Builder pattern for complex configuration
- Why it matters: Builders prevent huge constructors and make defaults discoverable and extendable.
- What it looks like:
  ```rust
  pub struct PolicyBuilder { /* ... */ }
  ```
- When to use:
  - When configuration has many optional fields or grows over time.
- Pitfalls:
  - Builders that allow invalid states without a validate() step.
- Apply to hushclaw:
  - Policy is serde-first; consider builders for programmatic construction or for engine options.

### Use `#[repr(transparent)]` + `serde(transparent)` for newtypes
- Why it matters: Keeps ABI/serde behavior predictable for wrapper types.
- Apply to hushclaw:
  Hash and key types already use serde(transparent); keep that consistency for future newtypes.

### Implement `FromStr` for parseable domain types
- Why it matters: Makes parsing idiomatic (`"...".parse()?`) and integrates with clap.
- Apply to hushclaw:
  If you add `Domain`/`ToolName` types, implement FromStr and Display.

### Use `Cow` when inputs are usually borrowed
- Why it matters: Avoids allocation in common case but allows owned fallback when normalization needed.
- Apply to hushclaw:
  If you normalize domains or paths, `Cow` can keep APIs ergonomic.

## Anti-slop heuristics (what to delete/avoid)
- “Stringly typed policies”: security decisions represented as arbitrary strings.
- Silent failure: invalid patterns dropped, errors swallowed, or defaults silently used.
- Boolean-only verification: no diagnostics, no auditability.
- “Just clone it”: pervasive clones instead of deliberate ownership design.
- Docs as fiction: examples and docs that do not compile or do not match reality.

## Bibliography
- Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Rustdoc Book: https://doc.rust-lang.org/stable/rustdoc/
- Clippy Book: https://doc.rust-lang.org/stable/clippy/
- Rust Style Guide (RFC 2436): https://rust-lang.github.io/rfcs/2436-style-guide.html

## Appendix: Additional high-signal patterns (repo-specific)

### Define and document wildcard semantics explicitly
- Category: Security
- Why it matters: Wildcard semantics are part of the security contract. If users assume globbing but you implement only `*.` prefix, policies will be wrong.
- Apply:
  - Decide if you support only `*.` subdomain wildcard or full glob patterns.
  - Test semantics in unit tests and document them in ruleset docs.
  - Align mdBook examples with actual behavior.

### Treat “docs drift” as a failing test
- Category: Docs & Maintenance
- Why it matters: If docs describe commands/schemas that do not exist, users will run unsafe workflows based on false assumptions.
- Apply:
  - Add CI checks: build mdBook, compile examples, and (optionally) validate CLI help output.
  - Mark aspirational docs as roadmap with links to issues.
  - Keep a single source of truth for rulesets (YAML vs hard-coded).

### Introduce a small “schema fixtures” directory
- Category: Testing
- Why it matters: Golden fixtures for policy YAML and receipt JSON prevent accidental schema drift and help cross-language consumers.
- Apply:
  - Add `fixtures/policy/*.yaml` and `fixtures/receipts/*.json`.
  - Tests load and validate all fixtures.
  - When changing schema, update fixtures deliberately with migration notes.

### Prefer deterministic ordering in serialized outputs
- Category: Config & Serde
- Why it matters: Deterministic output reduces diff noise and makes signatures stable (for canonical JSON it is mandatory).
- Apply:
  - Ensure map keys are sorted in canonical JSON (already done).
  - For YAML “show policy” output, consider stable ordering where possible.
  - For CLI list outputs, sort consistently.

### Model severity ordering in the type system
- Category: API Safety
- Why it matters: If severity is ordered (info < warning < error < critical), encode it to avoid ad-hoc helper functions.
- Apply:
  - Implement `Ord`/`PartialOrd` for `Severity` if that matches the semantics.
  - Or add a method `Severity::rank() -> u8` and use it consistently.
  - Ensure aggregation logic considers warnings, not only blocks.

### Separate “policy model” from “compiled policy”
- Category: Design & Architecture
- Why it matters: Elite systems parse config into a model, then compile/validate into an executable form (compiled regexes, globsets).
- Apply:
  - Keep `Policy` as serde model.
  - Create `CompiledPolicy` that holds compiled patterns and typed actions.
  - This avoids recompiling patterns repeatedly and makes validation explicit.

### Prefer explicit port/protocol matching in egress policies when threat model requires it
- Category: Security
- Why it matters: Allowlisting only by domain can still allow exfiltration over unusual ports or protocols.
- Apply:
  - If needed, extend `GuardAction::NetworkEgress` evaluation to include port rules.
  - Model ports as sets/ranges with tests.
  - Keep defaults conservative.

### Make receipt signing keys explicit and managed
- Category: Security
- Why it matters: Ephemeral keys make receipts non-verifiable across restarts; explicit key management is part of the product contract.
- Apply:
  - `hushd` currently generates ephemeral keys by default; document this clearly.
  - Provide a key loading path and consider key rotation strategy if this becomes production.
  - Consider preventing accidental logging/printing of private keys.

### Define “what is enforced” vs “what is attested”
- Category: Design & Architecture
- Why it matters: If enforcement is at the agent tool layer (not OS syscall layer), document that explicitly to avoid false security assumptions.
- Apply:
  - Update README/mdBook architecture docs with enforcement boundaries.
  - Define threat model and limitations.
  - Align guard actions with actual intercept points (MCP/tool calls, patch application).

