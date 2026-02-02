# Execution Plan / PR Backlog (v3)

This backlog is intentionally specific and reviewable: each PR has goals, files, steps, acceptance criteria, and tests.
It is biased toward restoring trust first (docs/examples/config correctness), then improving ergonomics and features.

Constraints:
- Rust builds/tests cannot run here due to no crates.io access; validate these changes in a networked CI runner.

## Workstreams
- Workstream A: Trust & contract alignment (docs/examples/rulesets)
- Workstream B: Policy correctness (typed config + validation)
- Workstream C: Engine semantics (warnings + evidence)
- Workstream D: Spec hardening (canonical JSON + receipts)
- Workstream E: Tooling (CI, offline builds, dependency hygiene)

## PR backlog

## PR-001: Restore trust: fix broken Rust example or remove it
- Goal: Ensure shipped examples compile and match the current receipt model.
- Files:
  - examples/rust/basic-verification/src/main.rs
  - examples/rust/basic-verification/README.md
  - crates/hush-core/src/receipt.rs
- Steps:
  - Decide whether the example should verify `SignedReceipt` (current) or a legacy receipt schema (not currently present).
  - If current: rewrite the example to parse `SignedReceipt` JSON and verify via `hush_core::receipt::PublicKeySet` + `SignedReceipt::verify`.
  - Update the example README and its sample JSON accordingly.
  - Optional: add a `Makefile` target or CI step to build examples so drift is caught early.
- Acceptance criteria:
  - The example compiles against the workspace crates.
  - The example’s README no longer references removed symbols/fields.
- Tests:
  - Add a CI step to compile examples (once builds are possible in CI).
- Risk:
  - Low; mechanical update with a clear contract.

## PR-002: Rulesets: pick a single source of truth and enforce it
- Goal: Eliminate drift between YAML rulesets, engine `RuleSet::by_name`, CLI listing, and docs.
- Files:
  - crates/clawdstrike/src/policy.rs
  - crates/hush-cli/src/main.rs
  - rulesets/*.yaml
  - README.md
  - docs/src/reference/rulesets/*
- Steps:
  - Pick one: (A) runtime file-driven rulesets, (B) compile-time embedded YAML rulesets, or (C) hard-coded rulesets only.
  - Update `RuleSet::by_name` and CLI to match the chosen mechanism.
  - Ensure `hush policy list` and `hush policy show` operate over the same registry.
  - Update README and mdBook ruleset docs to match.
- Acceptance criteria:
  - CLI list/show matches engine behavior exactly.
  - No orphaned YAML rulesets that the engine cannot load.
- Tests:
  - Add a test that enumerates all shipped rulesets and validates they parse + validate.
- Risk:
  - Medium; user-visible behavior change.

## PR-003: Policy validation: fail closed on invalid regex/glob patterns
- Goal: Remove silent weakening due to invalid patterns being dropped.
- Files:
  - crates/clawdstrike/src/policy.rs
  - crates/clawdstrike/src/error.rs
  - crates/clawdstrike/src/guards/forbidden_path.rs
  - crates/clawdstrike/src/guards/secret_leak.rs
  - crates/clawdstrike/src/guards/patch_integrity.rs
- Steps:
  - Introduce `PolicyValidationError` with a list of field errors (guard name, field path, pattern, compile error).
  - Implement `Policy::validate()` and call it in policy load paths (CLI, daemon).
  - Remove `filter_map(...ok())` silent drops; either validate before creating guard or make guard constructor fallible.
- Acceptance criteria:
  - Invalid patterns cause validation failure with actionable diagnostics.
  - Policies cannot silently lose protections due to typos.
- Tests:
  - Unit tests with invalid glob and invalid regex ensuring validation fails.
- Risk:
  - Medium; stricter behavior can break existing configs (desired for security).

## PR-004: Typed config actions: replace `default_action: String` with enums
- Goal: Make policy semantics unambiguous and typo-proof.
- Files:
  - crates/clawdstrike/src/guards/egress_allowlist.rs
  - crates/clawdstrike/src/guards/mcp_tool.rs
  - rulesets/*.yaml
- Steps:
  - Introduce enums for default actions with serde rename_all=lowercase.
  - Update guards to match exhaustively.
  - Update all shipped YAML rulesets and docs to use the enum values.
- Acceptance criteria:
  - Invalid `default_action` values are rejected at parse/validate time.
- Tests:
  - Parse tests: valid values accepted, invalid rejected with clear messages.
- Risk:
  - Medium; config compatibility changes.

## PR-005: Engine semantics: preserve warnings and per-guard evidence
- Goal: Make warning results visible and explainable.
- Files:
  - crates/clawdstrike/src/engine.rs
  - crates/clawdstrike/src/guards/mod.rs
  - crates/hush-cli/src/main.rs
- Steps:
  - Introduce a `GuardReport` containing per-guard results plus an overall verdict.
  - Update engine to aggregate severity across allowed+warn+block results (not only blocks).
  - Update CLI output to show warning-only outcomes distinctly (and optionally print per-guard evidence when `-vv`).
- Acceptance criteria:
  - If any guard warns and none block, overall result is “warn” (or equivalent) and visible in CLI.
  - Per-guard evidence is returned programmatically.
- Tests:
  - Unit test: allow + warn => overall warn.
  - Unit test: warn + block => overall block.
- Risk:
  - Medium; API/behavior change. Consider adding new API rather than replacing existing one if needed.

## PR-006: Docs alignment: mark mdBook content as roadmap or rewrite to match implementation
- Goal: Stop docs from describing nonexistent CLI and policy schema.
- Files:
  - docs/src/README.md
  - docs/src/reference/policy-schema.md
  - docs/src/reference/api/cli.md
  - docs/src/getting-started/*
- Steps:
  - Pick “roadmap” vs “contract” stance for mdBook.
  - If roadmap: add banners and link to tracking plan/issues.
  - If contract: rewrite docs to reflect `Policy` struct and actual CLI commands.
- Acceptance criteria:
  - New users can follow docs successfully or are explicitly warned about unimplemented features.
- Tests:
  - Optional: mdBook CI build; optional: “doctest” harness for code blocks where feasible.
- Risk:
  - Low-to-medium depending on how much rewriting you choose.

## PR-007: CLI contract: define exit codes and add a JSON output mode
- Goal: Make hush-cli scriptable and stable (ripgrep-grade contract).
- Files:
  - crates/hush-cli/src/main.rs
  - README.md
  - docs/src/reference/api/cli.md
- Steps:
  - Define exit code semantics for allowed/blocked/warn/error.
  - Add `--json` output for `check` and `verify` commands that prints structured results.
  - Update docs and README examples accordingly.
- Acceptance criteria:
  - Exit codes are deterministic and documented.
  - JSON schema is stable and versioned (even if just a top-level version field).
- Tests:
  - Integration tests that run CLI and assert exit code + JSON fields.
- Risk:
  - Medium; user-facing contract changes.

## PR-008: Spec hardening: canonical JSON vectors
- Goal: Defend canonicalization against spec drift and edge cases.
- Files:
  - crates/hush-core/src/canonical.rs
  - crates/hush-core/src/error.rs
- Steps:
  - Add a golden vector file (JSON inputs + expected canonical outputs).
  - Expand tests for floats, unicode, control characters, exponent formatting.
  - Consider switching float formatting strategy to a proven shortest-repr algorithm.
- Acceptance criteria:
  - Canonicalization outputs match vector expectations exactly.
- Tests:
  - Unit tests that iterate vector fixtures.
- Risk:
  - Low; mostly tests, but may reveal behavior that needs change.

## PR-009: Spec hardening: receipt schema drift prevention
- Goal: Prevent receipts and verifiers from drifting silently across versions.
- Files:
  - crates/hush-core/src/receipt.rs
  - examples/*
- Steps:
  - Define receipt schema version semantics (schema ID vs semver).
  - Add parsing/validation rules for receipt version.
  - Add fixtures and tests for version acceptance/rejection.
- Acceptance criteria:
  - Receipt verification clearly reports version mismatches.
- Tests:
  - Unit tests for version validation.
- Risk:
  - Low-to-medium; could affect external consumers.

## PR-010: Domain matching semantics: either document limitations or implement full wildcard support
- Goal: Avoid policy bypass assumptions and align docs with behavior.
- Files:
  - crates/hush-proxy/src/dns.rs
  - crates/hush-proxy/src/policy.rs
  - docs/src/reference/policy-schema.md
  - docs/src/reference/rulesets/*
- Steps:
  - Decide whether you want only `*.` wildcard semantics or full glob semantics.
  - If full glob: implement via `globset` (already in workspace deps) and add exhaustive tests.
  - If limited: document the limitation in docs and rule descriptions.
- Acceptance criteria:
  - Docs and behavior match; tests cover wildcard cases.
- Tests:
  - Unit tests for domain matching semantics (exact, wildcard, edge cases).
- Risk:
  - Medium; behavior change if you expand semantics.

## PR-011: Parser hardening: fuzz/property tests for DNS/SNI parsing
- Goal: Treat parsers as security boundaries and defend against malformed inputs.
- Files:
  - crates/hush-proxy/src/dns.rs
  - crates/hush-proxy/src/sni.rs
- Steps:
  - Add fuzz targets or property tests for malformed packets.
  - Document explicitly what is unsupported (DNS compression pointers, fragmented TLS records).
- Acceptance criteria:
  - Parsers do not panic on random input; they return errors or None safely.
- Tests:
  - Fuzz tests (if adopted) or property tests with generated byte arrays.
- Risk:
  - Low; mostly tests, might reveal parsing bugs.

## PR-012: API safety: add `#[must_use]` and tighten visibility
- Goal: Prevent ignored security decisions and reduce public surface area.
- Files:
  - crates/clawdstrike/src/guards/mod.rs
  - crates/clawdstrike/src/engine.rs
  - crates/hush-core/src/*
- Steps:
  - Mark `GuardResult` (and report type, if added) as `#[must_use]`.
  - Audit `pub` items; convert internal-only symbols to `pub(crate)`.
  - Add `#[non_exhaustive]` to public error enums if appropriate.
- Acceptance criteria:
  - Ignoring guard results produces compiler warnings.
  - Public API surface is smaller and intentional.
- Tests:
  - N/A (compile-time), plus ensure downstream crates still compile if any exist.
- Risk:
  - Medium; API surface changes could affect downstream users.

## PR-013: Performance micro-optimizations (only if needed): avoid allocations in hot paths
- Goal: Remove avoidable allocations in hashing and guard evaluation.
- Files:
  - crates/hush-core/src/hashing.rs
  - crates/clawdstrike/src/guards/mcp_tool.rs
  - crates/clawdstrike/src/engine.rs
- Steps:
  - Replace `concat_hashes` Vec allocation with a fixed `[u8; 64]` buffer.
  - Replace args size calculation with `serde_json::to_vec` (byte-accurate) or a size-tracking serializer.
  - Avoid allocating guard list per call in `check_action` (store slice of guards).
- Acceptance criteria:
  - No functional changes; lower allocation counts in benchmarks (if you add them).
- Tests:
  - Existing tests should pass; consider adding micro-benchmarks if this becomes hot.
- Risk:
  - Low; but avoid doing this before correctness fixes unless perf is urgent.

## PR-014: Dependency hygiene: remove or justify unused deps
- Goal: Keep dependency surface minimal and intentional.
- Files:
  - crates/hush-core/Cargo.toml
  - crates/clawdstrike/Cargo.toml
  - crates/hush-proxy/Cargo.toml
- Steps:
  - Confirm unused deps (`uuid`, `ipnet`, `globset`, `tokio` in hush-proxy).
  - Remove them or implement the intended features (CIDR egress, richer wildcard support, async IO).
- Acceptance criteria:
  - Cargo manifests reflect actual usage.
- Tests:
  - Build/test in a networked environment.
- Risk:
  - Low-to-medium; depends if you actually need those deps for planned features.

## PR-015: CI: add fmt/clippy/test gates (networked CI runner)
- Goal: Make style and correctness non-negotiable and prevent drift.
- Files:
  - .github/workflows/ci.yml (new or updated)
- Steps:
  - Add jobs for `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test --workspace`.
  - If offline builds matter, consider adding a job that uses vendored deps.
- Acceptance criteria:
  - CI fails on formatting, clippy warnings, or failing tests.
- Tests:
  - CI itself.
- Risk:
  - Low; but will surface existing issues that must be fixed.

## PR-016: Offline builds: vendor dependencies (optional but recommended)
- Goal: Enable builds/tests in restricted environments.
- Files:
  - .cargo/config.toml (new)
  - vendor/ (new, generated)
  - README.md
- Steps:
  - Run `cargo vendor` in a networked environment.
  - Check in vendor directory or provide a script to regenerate (org preference).
  - Document offline build steps in README.
- Acceptance criteria:
  - Project builds with `CARGO_NET_OFFLINE=true` when vendor is present.
- Tests:
  - CI job that runs offline (if feasible).
- Risk:
  - Medium; increases repo size and requires process discipline.

## PR-017: Docs code blocks as tests (optional): prevent future drift
- Goal: Make doc examples mechanically checked rather than aspirational.
- Files:
  - docs/src/**/*
  - tools/scripts/validate-docs (new, optional)
- Steps:
  - Add a lightweight script that extracts fenced code blocks marked as bash and runs syntax checks or dry-runs (where safe).
  - For Rust snippets, prefer rustdoc tests in crate docs.
- Acceptance criteria:
  - Common doc commands are validated or flagged when stale.
- Tests:
  - CI job runs the doc validation script.
- Risk:
  - Medium; doc test harness can be brittle if not scoped carefully.

## PR-018: Clarify threat model: what is enforced vs what is attested
- Goal: Make it explicit whether clawdstrike enforces OS-level restrictions or agent-tool-level restrictions.
- Files:
  - README.md
  - docs/src/concepts/architecture.md
- Steps:
  - Write a short threat model: attacker, assets, enforcement points.
  - Clarify limitations (e.g., no syscall interception).
  - Align marketing claims (“protects from data exfiltration”) with actual enforcement surface.
- Acceptance criteria:
  - Docs clearly state enforcement boundaries and limitations.
- Tests:
  - N/A.
- Risk:
  - Low; mostly documentation but important for trust.

## Sequencing recommendation (minimize risk)
- Start: PR-001, PR-002, PR-006, PR-018 (restore trust and contract clarity).
- Next: PR-003, PR-004 (security boundary correctness).
- Next: PR-005, PR-007 (engine/CLI semantics).
- Next: PR-008, PR-009 (spec hardening).
- Then: PR-010, PR-011 (policy semantics and parser hardening).
- Finally: PR-014, PR-015, PR-016, PR-017 (hygiene and tooling).

## Exit criteria for “de-ai-slopified v1”
- No broken examples, and examples are compiled in CI.
- Docs either match implementation or are clearly labeled as roadmap with tracking issues.
- Policy validation fails closed on invalid patterns and invalid enum values.
- Warnings are observable and evidence is available (per guard).
- Canonical JSON and receipt signing are defended by golden vectors.
- CLI has stable exit code contract and optional machine-readable output.


## Appendix A: Acceptance test matrix (what to run before merging)

These are the tests/commands that should gate PRs once you have a networked CI runner (or vendored deps).

### A.1 Formatting and linting
- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`

### A.2 Unit tests
- `cargo test --workspace --all-targets`

### A.3 Example compilation
- Build examples explicitly (or include them in workspace test matrix).

### A.4 Schema fixtures
- Parse and validate all `rulesets/*.yaml`.
- Parse and validate any `fixtures/policy/*.yaml` and `fixtures/receipts/*.json` you add.

### A.5 CLI integration tests
- Run `hush --help` and snapshot expected output.
- Run `hush policy list` and assert it matches shipped rulesets.
- Run `hush check` in allow and block scenarios and assert exit codes.

## Appendix B: Risk register (things likely to surprise you)

- Risk: policy schema unification is bigger than it looks because other packages (OpenClaw, Python) already depend on the mdBook schema.
- Risk: strict validation will break existing policies that relied on permissive parsing or typos; provide migration notes.
- Risk: canonical JSON cross-language compatibility is hard; commit to fixtures early.
- Risk: “hush run” implies OS enforcement; be explicit about enforcement boundaries to avoid false security assumptions.
- Risk: offline builds are currently impossible; decide if vendoring is required for your environments.

## Appendix C: Migration notes template (use when changing schemas)

When a PR changes policy schema or receipt schema, include a MIGRATION section in the PR description:
- Old field(s) -> new field(s) mapping
- Default behavior changes
- Example before/after YAML or JSON
- Compatibility guarantees (what is supported, what is not)
- Required actions for users (update rulesets, update plugin, update python)

## Appendix D: Workstream task breakdown (more granular than PRs)


### D.1 Workstream A (Trust & contract alignment)

- Inventory all docs that reference missing CLI commands (hush run, policy lint) and decide rewrite vs roadmap banners.
- Inventory all policy schema examples in docs and in OpenClaw plugin; categorize by schema version.
- Decide the canonical schema contract (S1 vs S2) and document the decision in README.
- Add a “status” section to docs listing what is implemented today.
- Update or remove broken examples (Rust verification example).
- Ensure ruleset docs match ruleset implementation.

### D.2 Workstream B (Policy correctness)

- Implement `Policy::validate()` and ensure it is called on load paths.
- Add aggregated validation errors with clear field paths.
- Replace stringly-typed default actions with enums.
- Decide strict vs permissive parsing and expose explicit APIs or flags.
- Add tests that parse every shipped YAML ruleset and validate it.
- Add fixtures for policy YAML and validate them.

### D.3 Workstream C (Engine semantics)

- Define warning aggregation semantics and encode them in tests.
- Implement `GuardReport` and decide whether to make it additive or replace existing return types.
- Update CLI output to reflect warnings distinctly.
- Optionally: attach per-guard evidence to receipts as provenance detail (threat-model dependent).

### D.4 Workstream D (Spec hardening)

- Add canonical JSON golden vectors and ensure they match across Rust/Python if multi-language is real.
- Add receipt schema fixtures and version validation.
- Add Merkle vectors for odd sizes and inclusion proofs.
- Add fuzz/property tests for DNS/SNI parsing (security boundary).

### D.5 Workstream E (Tooling)

- Add CI fmt/clippy/test gates in a networked runner.
- Decide whether offline builds are required; if yes, vendor deps and add offline CI gate.
- Remove unused dependencies or implement the features they were intended for.
- Add integration tests for CLI contract.

## Appendix E: Dependency graph (sequencing rationale)

Some PRs logically depend on others. Use this to avoid rework:

- PR-018 (threat model clarity) should come early because it informs schema/CLI decisions.
- PR-002 (ruleset source of truth) should come before CLI JSON output or CLI contract tests.
- PR-003 (policy validation) should come before PR-004 (typed actions), because validation will need to validate action values too.
- PR-003 and PR-004 should come before PR-005 (GuardReport), because the report likely wants validated/typed configs.
- PR-008/PR-009 (spec hardening) should come after schema decisions if schema fields change canonicalization inputs.
- PR-010 (domain wildcard semantics) should come after deciding whether globset is used and after docs/schema alignment.
- PR-015 (CI) can be introduced early but expect it to fail until foundational fixes are merged.
- PR-016 (offline vendor) depends on a networked environment at least once to generate vendor tree.

A pragmatic ordering:
1) PR-018, PR-006, PR-001
2) PR-002
3) PR-003, PR-004
4) PR-005, PR-007
5) PR-008, PR-009, PR-010, PR-011
6) PR-014, PR-015, PR-016, PR-017, PR-013

## Appendix F: Additional PR ideas (if multi-language + OpenClaw integration is core)

These are not in the main PR sequence because they depend on the schema decision, but they are likely necessary if the product
really includes the Python SDK and OpenClaw plugin.

### PR-019: Implement schema translation layer (S1 -> S2) with fixtures
- Goal: allow OpenClaw/mdBook policies (S1) to be consumed by Rust engine (S2) via explicit translation.
- Files:
  - `crates/clawdstrike/src/policy.rs` (or new `policy_loader.rs`)
  - `rulesets/` and `packages/clawdstrike-openclaw/examples/*` (fixtures)
- Steps:
  - Define S1 structs (serde) and translation into S2 Policy/Guard configs.
  - Define translation semantics explicitly and test with fixtures.
- Risk: high; translation becomes a security boundary and must be heavily tested.

### PR-020: Cross-language canonicalization and receipt fixtures (Rust <-> Python)
- Goal: prevent drift between Rust and Python canonical JSON + receipt schemas.
- Files:
  - `crates/hush-core/src/canonical.rs`
  - `packages/hush-py/src/hush/canonical.py`
  - `fixtures/canonical/*` (new)
  - `fixtures/receipts/*` (new)
- Steps:
  - Decide a single canonicalization contract and implement it in both languages.
  - Add shared fixtures and make both test suites consume them.
- Risk: high if you change canonicalization; may invalidate existing signatures.

### PR-021: OpenClaw plugin alignment with Rust engine
- Goal: ensure OpenClaw plugin policies and guard semantics match Rust guard behavior.
- Files:
  - `packages/clawdstrike-openclaw/src/*`
  - `packages/clawdstrike-openclaw/examples/*`
- Steps:
  - Decide whether plugin uses S1 schema directly or through translation into S2.
  - Add integration tests that feed example policies into Rust validator/translator (if available).
- Risk: medium; integration work but prevents product fragmentation.

## Appendix G: Release checklist (practical)

- All CI gates green (fmt/clippy/tests/examples).
- Rulesets parse + validate in CI.
- Docs are built (mdBook) and do not reference missing commands (or are clearly labeled roadmap).
- Canonicalization vectors pass; receipt fixtures pass.
- CLI exit codes documented and verified by integration tests.
- Threat model / enforcement boundaries updated in README.
- Version bump applied consistently across crates (workspace versioning).
- Changelog/release notes include schema changes and migration notes.
- If schema changed: provide before/after examples and update OpenClaw/Python if needed.
- If key handling changed: document verification requirements (public keys, rotation).
- Confirm unused dependencies are removed (or justified) before release.
- Confirm policy validation errors are actionable and stable (no confusing messages).
- Confirm warnings are not silently dropped (engine report semantics tested).
- Confirm OpenClaw example policies still work (or provide migration notes).
