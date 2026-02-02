# Elite Rust Codebase Case Studies (v3)

Goal: describe what “elite Rust” looks like in practice by studying patterns commonly used in top-tier Rust projects,
then translate those patterns into concrete guidance for hushclaw.

Important constraint:
- This environment has no outbound network access, so I cannot fetch and quote actual Tokio/Serde/ripgrep source files here.
- The case studies below focus on durable, widely-known design patterns those projects embody, plus actionable mappings.

## Table of contents
- 1. Tokio: async runtime, cancellation, and boundaries
- 2. Serde: schema evolution and trait design
- 3. ripgrep: CLI contract and performance engineering
- 4. rustc/stdlib: stability, layering, and internal APIs
- 5. Applied case studies for hushclaw (design exercises)
- 6. Pattern-to-hushclaw mapping (priority list)
- Bibliography

## 1. Tokio: async runtime, cancellation, and boundaries

Tokio is a reference point for real-world async Rust where correctness and predictability matter more than cleverness.
When people say “elite Rust”, they often mean “Tokio-grade boundaries”: explicit runtime ownership, explicit scheduling,
and explicit backpressure/cancellation.

### 1.1 Boundary discipline
The core discipline you see in elite async code:
- Libraries avoid surprising global side effects (like creating background runtimes implicitly).
- Blocking work is explicitly segregated from async work.
- Cancellation is treated as a normal outcome and documented in APIs.

### 1.2 Concrete patterns to emulate (for hushclaw)
- Builder objects to keep configuration extensible and discoverable.
- Explicit resource limits (concurrency, queue sizes, timeouts).
- Explicit “lifecycle” semantics for long-running services (start/reload/shutdown).

### 1.3 Error surfaces in async systems
Elite async systems separate:
- user-facing “operation failed” errors (typed), from
- internal task failures (join errors, cancellation), from
- programmer errors (panics).

In hushclaw terms:
- A policy violation is not a crash; it is an expected outcome.
- A parse error is a configuration bug; it should be surfaced clearly.
- A panic is a bug; treat it as a high-severity internal failure.

### 1.4 Tokio-style “don’t hold locks across await”
This is the #1 rule you should adopt for any future async expansion (daemon, audit streams, hot reload):
- Acquire lock, copy what you need, release lock, then `.await`.
- For counters, prefer atomics; for queues, prefer channels.

### 1.5 Tokio-style builder (pseudo-code)
```rust
pub struct EngineBuilder {
  policy: Policy,
  fail_fast: bool,
  verbose_logging: bool,
  max_violations: usize,
}

impl EngineBuilder {
  pub fn new(policy: Policy) -> Self { /* defaults */ }
  pub fn fail_fast(mut self, v: bool) -> Self { self.fail_fast = v; self }
  pub fn build(self) -> HushEngine { /* ... */ }
}
```

### 1.6 How this maps to hushclaw code today
- `HushEngine` already exists and is async-friendly, but:
  - state tracking uses an `RwLock` (fine), but as features grow you should consider atomics for counters.
  - guard aggregation currently can lose warnings; a Tokio-grade system would keep per-check evidence.

### 1.7 Tokio-inspired checklist you can apply immediately
- Document which APIs are async-safe and which perform blocking work (even if none do today).
- Define timeouts for any future IO-bound guard (e.g., calling out to external scanners).
- If you build `hushd`, define concurrency limits and backpressure behavior from day 1.
- Use `tracing` spans: one span per action check, with fields: session_id, guard_name, action_kind.
- Treat cancellation (Ctrl-C, client disconnect) as a supported path in daemon mode.

## 2. Serde: schema evolution and trait design

Serde is the canonical example of elite Rust interface design: a minimal trait boundary + derive-based ergonomics + strict schema thinking.

### 2.1 Schema discipline as a security feature
In security tools, schema discipline is not “nice to have”. It is a security boundary:
- A policy typo must not silently weaken enforcement.
- A receipt schema drift must not cause false verification success/failure.

### 2.2 Strict vs permissive parsing
Elite systems often provide both:
- permissive parse (forward compatibility), and
- strict parse (fail on unknown fields / invalid patterns).

Hushclaw should likely default to strict parse for *policies*, because they represent intent and security posture.

### 2.3 Versioning strategies
Common strategies (choose one intentionally):
- Semantic version string (e.g., `1.0.0`) with semver rules.
- Schema ID string (e.g., `hushclaw-v1.0`) with explicit compatibility tables.
- Integer schema version (e.g., `1`) with a migration chain.

### 2.4 Apply to hushclaw: you currently have two policy schemas
- Implemented schema: `Policy { version, name, description, guards, settings }`.
- Documented schema: `version, extends, egress/filesystem/execution/tools, limits, on_violation`.

Pick one as the contract.

### 2.5 How to do inheritance (extends) without making a mess
If you implement `extends`, define merge semantics explicitly:
- Scalars: does child override or merge?
- Lists: append, override, or set-union?
- Maps: recursive merge or override?
- Validation: do you validate base first, then merged, or merged only?

Elite approach: write tests for merge semantics before implementing them.

### 2.6 Apply to hushclaw code today
- Your `Policy` model is already strongly typed and serde-friendly.
- Next step is to add validation (compile patterns) and choose strictness defaults.

### 2.7 Serde-inspired checklist you can apply immediately
- Add golden YAML fixtures for every shipped ruleset (`rulesets/*.yaml`) and test they parse + validate.
- Add golden JSON fixtures for receipts and test canonicalization is stable.
- Provide a strict validation path (`Policy::validate`) and expose it via CLI.
- Keep untyped JSON (`serde_json::Value`) contained and documented (e.g., `scores`, `metadata`).

## 3. ripgrep: CLI contract and performance engineering

ripgrep is the archetype of “Rust as a product”: fast, stable, predictable. The biggest lesson is that it treats its CLI surface
as a contract. For security tooling, that mindset is essential.

### 3.1 CLI contract principles
- Stable subcommands and flags.
- Stable exit codes.
- Stable output formats (especially machine-readable formats).

### 3.2 Apply to hushclaw: current contract breaches
- mdBook documents CLI commands that do not exist in `crates/hush-cli`.
- Examples reference rulesets (`ai-agent-minimal`, `cicd`) not supported by runtime `RuleSet::by_name`.

### 3.3 Design a “contract test suite” for hush-cli
Elite CLI projects treat this as normal:
- Integration tests that run the binary and assert output/exit codes.
- Golden output snapshots for `--help` and key commands.

### 3.4 Apply to hushclaw code today
- Add tests that invoke `hush policy list` and ensure it matches whatever the engine can load.
- If you implement `hush run`, define semantics and then add tests that cover common denial cases (reading ~/.ssh).

### 3.5 ripgrep-inspired checklist you can apply immediately
- Define exit codes for allow/block/warn/error and document them.
- Keep CLI output deterministic and grep-friendly.
- Provide `--json` output for machine use (policy validate, check results).
- Ensure all README and mdBook examples are executable tests or compile-time checked.

## 4. rustc/stdlib: stability, layering, and internal APIs

The Rust stdlib and compiler are the extreme example of layered design:
- Public API is stable and curated.
- Internals are aggressively encapsulated.
- Diagnostics are treated as UX.

### 4.1 Apply to hushclaw
- Use `pub(crate)` by default; re-export intentionally from `lib.rs`.
- Add `#[non_exhaustive]` to public error enums if you expect evolution.
- Treat policy errors as diagnostics: show which field/pattern is wrong.

## 5. Applied case studies for hushclaw (design exercises)

This section is intentionally concrete: it uses the above “elite patterns” as design constraints for features
that the docs *claim* exist but the code does not implement yet.

### 5.1 Case study: implementing `hush run` (daemonless wrapper)

Problem statement:
- mdBook describes `hush run --policy policy.yaml -- command args`.
- Current Rust CLI has no `run` command and no interception layer for subprocess IO.

Elite design constraints (Tokio + ripgrep style):
- Do not invent a giant framework; start with a minimal wrapper that adds value.
- Keep output contract stable; never hide stdout/stderr without explaining it.
- Make policy validation fail-fast before executing anything.

Minimal viable implementation sketch:
- Parse policy (YAML) -> validate -> instantiate engine.
- Spawn subprocess with captured stdout/stderr (or pass-through with tee).
- Intercept file accesses/egress? (Hard without OS hooks.)

Reality check:
- Without OS-level sandboxing (ptrace/seccomp/macOS sandbox), you cannot truly enforce file and network access for an arbitrary process.
- Therefore, a “hush run” MVP should likely focus on:
  - policy validation
  - patch integrity checks (if applying patches)
  - tool invocation restrictions (if integrating with an agent runtime)
  - receipt signing for declared actions (attestation model)

If you want real enforcement for arbitrary commands, the architecture becomes:
- intercept at the agent tool layer (MCP/agent runtime), not at OS syscall level.

### 5.2 Case study: implementing policy inheritance (`extends`)

Problem statement:
- mdBook policy schema relies on `extends` and remote policy sources (file/https/git).
- Current Rust `Policy` has no `extends` field and no merge semantics.

Elite design constraints (Serde style):
- Define merge semantics explicitly and test them before implementing.
- Treat the effective policy as a derived artifact you can print and hash.
- Make resolution sources explicit and safe (avoid silent network fetches in libraries).

Implementation sketch:
- Add `extends: Option<String>` to the schema (if you adopt mdBook schema), or keep it separate in a “policy loader” layer.
- Implement a resolver interface that can load base policies from:
  - built-in registry (e.g., hushclaw:default)
  - local file (file://)
  - (optionally) remote sources (https://, git://) but only in the CLI binary, not in library code.
- Merge base and child into an “effective policy” and then validate.

### 5.3 Case study: warning aggregation semantics

Problem statement:
- Guards can emit warnings (allowed + severity warning), but the engine may drop them in the returned result.

Elite design constraints:
- Warnings must be observable by default (at least in report form).
- The engine should provide an “explain” output showing which guard said what.

Implementation sketch:
- Introduce `GuardReport { overall, per_guard, stats }`.
- Define `overall` as:
  - blocked if any blocked
  - warned if none blocked but any warned
  - allowed otherwise

## 6. Pattern-to-hushclaw mapping (priority list)

### P0 (must fix to restore trust)
- Docs/README/examples must match code or be labeled as roadmap.
- Remove silent config weakening (invalid patterns must error).
- Fix ruleset loading drift and example drift.

### P1 (quality and ergonomics)
- Typed config enums, strict parse mode, and policy validation reports.
- Engine report type with per-guard evidence.
- Integration tests for CLI contract and rulesets.

### P2 (product roadmap)
- Decide and implement: `hush run` and/or `hushd` server API.
- Align mdBook policy schema with implementation.

## Bibliography
- Tokio: https://tokio.rs/
- Serde: https://serde.rs/
- ripgrep: https://github.com/BurntSushi/ripgrep
- Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Rustdoc Book: https://doc.rust-lang.org/stable/rustdoc/
- Clippy Book: https://doc.rust-lang.org/stable/clippy/

## Appendix A: Applied design sketches (what “elite patterns” look like when building hushclaw features)

These sketches are intentionally concrete and use the same design constraints you see in elite Rust projects:
- explicit boundaries
- typed decisions
- validation at the boundary
- small, composable modules
- tests as contracts

### A.1 Sketch: `RuleSetRegistry` (unify YAML rulesets + CLI + engine)

Problem:
- You have YAML rulesets in `rulesets/`, but runtime ruleset selection is hard-coded (`RuleSet::by_name`).

Elite design goal:
- A single authoritative registry that both engine and CLI use.

Design options:
- Runtime file-driven:
  - Registry loads `rulesets/*.yaml` at startup.
  - Pros: easy to add rulesets without code changes.
  - Cons: runtime file dependency; must define search paths.
- Compile-time embedded:
  - Use `include_str!()` to embed shipped YAML into the binary.
  - Pros: deterministic; no file dependency.
  - Cons: adding rulesets requires a code change.

API shape (pseudo-code):
```rust
pub struct RuleSetRegistry {
  by_id: BTreeMap<String, RuleSet>,
}

impl RuleSetRegistry {
  pub fn load_embedded() -> Result<Self> { /* ... */ }
  pub fn load_dir(path: &Path) -> Result<Self> { /* ... */ }
  pub fn get(&self, id: &str) -> Option<&RuleSet> { /* ... */ }
  pub fn list_ids(&self) -> impl Iterator<Item=&str> { /* ... */ }
}
```

Key “elite” details:
- Use deterministic ordering (BTreeMap) so outputs are stable.
- Validate policies on load; do not accept partially-parsed rulesets.
- Treat invalid YAML as a failure in CI.

### A.2 Sketch: `Policy::validate()` + compiled policy (Serde discipline)

Problem:
- Guard configs compile patterns with `filter_map(...ok())`, silently dropping invalid patterns.

Elite design goal:
- Separate “parsed policy” from “compiled policy”.

API shape (pseudo-code):
```rust
pub struct CompiledPolicy {
  forbidden_paths: ForbiddenPathGuard,
  egress: EgressAllowlistGuard,
  secrets: SecretLeakGuard,
  patch: PatchIntegrityGuard,
  mcp: McpToolGuard,
}

impl Policy {
  pub fn validate(&self) -> Result<(), PolicyValidationError> { /* ... */ }
  pub fn compile(&self) -> Result<CompiledPolicy, PolicyValidationError> { /* compile + return */ }
}
```

Key “elite” details:
- `validate()` aggregates errors and reports all invalid patterns at once.
- `compile()` is the only path that constructs compiled regexes/globs.
- The engine uses `CompiledPolicy` rather than re-compiling patterns per request.

### A.3 Sketch: warning aggregation contract + evidence (Tokio-grade explicitness)

Problem:
- Warnings can be lost because the engine only compares severity for blocking results.

Elite design goal:
- Make warnings observable and reportable without turning everything into logs.

API shape (pseudo-code):
```rust
pub enum OverallDecision { Allowed, AllowedWithWarnings, Blocked }

pub struct GuardReport {
  pub overall: OverallDecision,
  pub per_guard: Vec<GuardResult>,
}
```

Key “elite” details:
- The overall decision is computed deterministically from per-guard results.
- CLI and receipts can reuse the same decision semantics.
- Tests define the contract (allow+warn -> AllowedWithWarnings).

### A.4 Sketch: “docs-as-contract” enforcement via tests (ripgrep discipline)

Problem:
- mdBook currently describes commands (`hush run`, `policy lint`) and a policy schema that do not exist.

Elite design goal:
- Drift must be caught mechanically (CI).

Tactics:
- Compile examples in CI (Rust examples, maybe TS examples).
- Add integration tests that run `hush --help` and key subcommands and compare against snapshots.
- Build mdBook in CI and fail on warnings.

Key “elite” detail:
- Treat docs failures as real failures; don’t let them slide “because docs”.

### A.5 Sketch: implementing `hush run` honestly (enforcement vs attestation)

Problem:
- `hush run` implies enforcement, but OS-level enforcement is not implemented.

Elite design goal:
- Be explicit about what is enforced and what is merely attested.

Two viable product shapes:
- Shape 1: Agent-tool enforcement
  - hushclaw sits inside the agent runtime (MCP/tools) and checks actions as they happen.
  - Receipts attest to checked actions.
- Shape 2: OS-level enforcement (harder)
  - You need sandboxing (seccomp, sandbox-exec, containers) or syscall interception.
  - This is a major engineering and platform surface area decision.

If you ship `hush run` soon, shape 1 is the honest MVP.

## Appendix B: How to read “elite Rust” code (practical method)

If you later do a real code-reading pass of Tokio/Serde/ripgrep, this is how to extract patterns quickly:
- Start at `lib.rs`: what is re-exported? what is hidden? (public surface curation).
- Look at error modules: are errors typed and structured? do they preserve sources?
- Look at config/builder modules: how are defaults expressed? how is validation performed?
- Look at tests: are there golden vectors? property tests? integration tests?
- Look at feature flags: what heavy deps are gated? what is in default features?
- Look at docs: do examples compile? is there a doc-test harness?

Then translate those observations into your repo as “constraints” and “mechanical refactors”.

## Appendix C: Reading list (stable sources)

- Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Rustdoc Book: https://doc.rust-lang.org/stable/rustdoc/
- Cargo features: https://doc.rust-lang.org/cargo/reference/features.html
- Clippy Book: https://doc.rust-lang.org/stable/clippy/

## Appendix D: In-repo multi-language drift case study (Python vs Rust)

This repo already contains a concrete example of why “elite Rust” projects obsess over schema/version discipline:
- There is a Python package (`packages/hush-py`) that implements canonical JSON, Merkle, guards, and receipts.
- Its receipt schema and canonicalization approach do not match the Rust `hush-core` implementation.

This is not a moral failing; it is what happens when schemas are not treated as contracts and are not defended by fixtures/tests.

### D.1 Python canonicalization vs Rust canonicalization
- Python `hush.canonical.canonicalize` delegates to `json.dumps(... sort_keys=True, ensure_ascii=False, allow_nan=False)`.
- Rust `crates/hush-core/src/canonical.rs` implements its own RFC 8785/JCS serializer and explicitly tries to align with ECMAScript `JSON.stringify()` number/escape semantics.

Potential mismatch risks:
- Key ordering: RFC 8785 sorts by UTF-16 code units; Python sorts by Unicode code points (usually same for ASCII, differs for some edge cases).
- Float formatting: Python’s `json.dumps` formatting rules differ from Rust’s JCS logic and from JS `JSON.stringify` in edge cases.
- Escaping: Python and JS differ for some unicode escaping behavior; Rust currently implements explicit escaping rules.

Elite mitigation strategy:
- Pick *one* canonicalization contract and implement it identically across languages.
- Add golden canonicalization vectors stored as fixtures and run them in Rust and Python tests.

### D.2 Python receipt schema vs Rust receipt schema
- Python `packages/hush-py/src/hush/receipt.py` defines Receipt fields: `id`, `artifact_root`, `event_count`, `metadata`.
- Rust `crates/hush-core/src/receipt.rs` defines Receipt fields: `version`, `receipt_id`, `timestamp`, `content_hash`, `verdict`, `provenance`, `metadata`.

Elite mitigation strategy:
- Decide whether these are two different product layers (and rename packages accordingly), or whether they are intended to be the same artifact type.
- If they are intended to be the same, introduce explicit schema versioning and migration.
- Add cross-language fixtures: one canonical receipt JSON that both Rust and Python can parse and verify.

### D.3 Why this matters for “elite Rust style”
Elite Rust codebases avoid this kind of drift by:
- Treating serialized artifacts (configs, receipts) as first-class contracts.
- Adding fixtures and compatibility tests early.
- Keeping docs honest (contract vs roadmap).

### D.4 Concrete next steps for hushclaw (if multi-language is real)

- Introduce `fixtures/canonical/*.json` containing canonicalization vectors and expected canonical strings.
- Add Rust tests that canonicalize each fixture and compare to expected outputs.
- Add Python tests that canonicalize the same fixtures and compare to the same expected outputs.
- Unify receipt schema or add versioned receipt formats and document them.

## Appendix E: In-repo integration drift case study (OpenClaw plugin policies)

The mdBook policy schema is not “just docs”: it is used by other parts of this repo.

Evidence:
- `packages/hushclaw-openclaw/examples/hello-secure-agent/policy.yaml` uses the mdBook schema:
  - `version: "hushclaw-v1.0"`
  - `egress: { mode, allowed_domains, denied_domains }`
  - `filesystem: { allowed_write_roots, forbidden_paths }`
  - `on_violation: cancel`

This means the repo currently contains at least two “live” policy schemas:
- Schema S1 (mdBook/OpenClaw): `egress/filesystem/execution/tools/...` + `extends` + `on_violation`.
- Schema S2 (Rust crates/hushclaw): `guards.*` + `settings`.

Why this matters:
- If the OpenClaw plugin is part of the product, S1 is not optional.
- If Rust is intended to be the core enforcement engine, Rust must either implement S1 or there must be a translation layer.

Elite mitigation strategy:
- Decide on a canonical schema and enforce it with fixtures/tests across Rust + plugin + Python.
- If you keep both schemas, explicitly version them and implement a translation layer with tests (treat translation as a security boundary).

## Appendix F: Decision matrix (unify policy schema vs translation layer)

Given that mdBook/OpenClaw policy schema appears to be used in-repo, you have three realistic options:

### Option 1: Unify on mdBook/OpenClaw schema (S1) and implement it in Rust
- Pros:
  - One schema across the product.
  - Docs become accurate by implementing what they describe.
  - OpenClaw examples keep working.
- Cons:
  - Larger Rust implementation effort (inheritance, tools/execution sections, on_violation semantics).

### Option 2: Unify on current Rust schema (S2) and rewrite plugin + docs
- Pros:
  - Rust stays simpler and matches current implementation.
  - Faster to ship a consistent Rust story.
- Cons:
  - Breaks plugin examples and requires migrating OpenClaw integration.
  - Docs need major rewrite.

### Option 3: Keep both schemas and add a translation layer (S1 -> S2)
- Pros:
  - Preserves compatibility while allowing Rust internals to remain stable.
  - Enables gradual migration.
- Cons:
  - Translation becomes a security boundary; must be tested heavily.
  - Risk of semantic mismatch (“what does on_violation mean in S2?”).
