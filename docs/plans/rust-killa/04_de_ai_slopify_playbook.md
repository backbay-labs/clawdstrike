# De-AI-Slopify Playbook for Hushclaw (v3)

This playbook is a *process document*: how to turn this repo into something that feels “Tokio/Serde-grade” in discipline,
without turning it into a complicated framework.

The key correction from earlier attempts: we optimize for *signal*, not line count. Every checklist item below is tied to
this repo’s actual code and drift issues.

Constraints:
- No outbound network access here -> cannot run `cargo test` because dependencies cannot be fetched.
- Treat the repo as “offline-first”; if that is a requirement in your environment, add vendoring support.

## 0) North Star: what “elite Rust” means here
- Security boundaries are explicit (canonical JSON, policy parsing, pattern matching semantics).
- Misconfiguration fails closed (invalid regex/glob is an error, not silently ignored).
- Public APIs are small, typed, and documented with compilable examples.
- Tests include golden vectors for spec code and regressions for every bug found.
- Docs are either contract (accurate) or explicitly labeled roadmap (inaccurate-but-intentional).

## 1) Phase 0: Decide “contract vs roadmap” and stop doc drift

### 1.1 Identify the competing contracts
- Contract A (current code): policy schema in `crates/hushclaw/src/policy.rs` and rulesets in `rulesets/*.yaml`.
- Contract B (docs): mdBook schema in `docs/src/reference/policy-schema.md` with `extends`, `egress/filesystem/execution/tools`, `on_violation`.

You cannot have both be true at the same time. Pick one.

### 1.2 Two viable strategies
- Strategy 1 (docs-as-contract): rewrite mdBook to match current Rust code. Remove/replace any commands and schemas that do not exist.
- Strategy 2 (docs-as-roadmap): keep mdBook as the intended future, but add clear banners: “Not implemented yet”, and link to tracking issues.

### 1.3 Concrete doc drift fixes (minimum viable trust restore)
- Add a banner to `docs/src/README.md` and `docs/src/reference/policy-schema.md` indicating the implementation status.
- Update CLI docs: `docs/src/reference/api/cli.md` should reflect *actual* `hush` commands in `crates/hush-cli/src/main.rs`.
- Align ruleset docs with `rulesets/*.yaml` or with `RuleSet::by_name` behavior (choose one).

## 2) Phase 1: Stop shipping broken examples and mismatched artifacts

### 2.1 Examples are tests
- Broken example: `examples/rust/basic-verification` does not match current `hush-core` receipt type.
- Fix: either update it to verify the current `SignedReceipt`, or delete/move it to a legacy folder with explicit versioning.

### 2.2 Rulesets are tests
- If you ship `rulesets/*.yaml`, add a unit test that loads and validates every YAML file.
- If you do not actually support YAML rulesets at runtime, remove them and update docs.

## 3) Phase 2: Eliminate silent weakening (config validation is a security boundary)

### 3.1 Prohibit silent pattern drops
Current code drops invalid patterns in several guards (glob/regex compile failures). Elite fix:
- Collect *all* invalid patterns and surface them in a structured error.
- Refuse to create a guard/policy if critical patterns fail to compile.

### 3.2 Add a first-class validation API
Introduce:
- `Policy::validate() -> Result<(), PolicyValidationError>`
- `RuleSet::validate()` if rulesets become file-driven
- CLI: `hush policy validate <file>` that prints errors with context

### 3.3 Make config decisions typed
Replace string fields like `default_action: String` with enums:
- `allow|block|log` for egress
- `allow|block` for MCP tool default

## 4) Phase 3: Fix engine semantics (warnings + evidence)

### 4.1 Decide what warnings mean
Right now warnings can be lost. Elite design requires an explicit contract:
- If any guard blocks -> overall blocked.
- Else if any guard warns -> overall allowed-with-warnings.
- Else -> allowed.

### 4.2 Add an “evidence report” type
Introduce `GuardReport`:
```rust
pub struct GuardReport {
  pub overall: GuardResult,
  pub per_guard: Vec<GuardResult>,
}
```

Why it matters:
- Debugging becomes possible without adding logs everywhere.
- You can attach evidence to receipts later.
- Warnings become visible and testable.

### 4.3 Test the semantics
- Add a test where one guard returns allow and another returns warn; assert the overall verdict is warn (if that is the contract).
- Add tests for multiple blocks and severity ordering.

## 5) Phase 4: Harden cryptographic/spec boundaries (hush-core)

This is where “elite Rust” matters most: spec correctness is security correctness.

### 5.1 Canonical JSON
- Treat canonicalization as the signing contract.
- Expand tests to cover RFC 8785 vectors and edge float cases.
- Consider using a proven float-to-shortest algorithm (`ryu`) rather than relying on debug formatting for stability.

### 5.2 Receipt schema versioning
- Right now receipts have `version: "1.0.0"` as a string.
- Decide if this is a schema version (compat table) or a semantic version (semver rules).
- Add explicit version validation to receipt parsing if receipts will be exchanged externally.

### 5.3 Key material hygiene
- Decide threat model: if in-scope, consider `zeroize` for private key material or avoid `Clone` on secret-bearing structs.

## 6) Phase 5: Guard-specific de-slopify checklists (hushclaw)

### 6.1 ForbiddenPathGuard
- Make glob compilation errors visible (validation report).
- Consider whether path matching should be Path-based (platform correct) or string/glob based (portable).
- Document normalization semantics (slashes, home dirs, env vars) if you add them.

### 6.2 EgressAllowlistGuard / DomainPolicy
- Document domain matching semantics clearly (only `*.` wildcard today).
- If you want full glob semantics, implement it intentionally (globset) and test it.
- Consider normalizing domains (lowercase, strip trailing dot) and document it.

### 6.3 SecretLeakGuard
- Treat regex compilation as validation boundary.
- Add explicit allow/ignore patterns for false positives (if desired).
- Ensure guard details never include the raw secret (already mostly true).

### 6.4 PatchIntegrityGuard
- Consider scanning both additions and deletions depending on threat model.
- If diff parsing becomes complex, consider using a unified diff parser rather than line heuristics.
- Make pattern compilation errors visible.

### 6.5 McpToolGuard
- Replace `default_action: String` with enum.
- Replace args size calculation that allocates (`args.to_string().len()`) with a byte-accurate method.
- Consider wildcard matching or namespaces for tool names if your tool ecosystem grows.

## 7) CLI de-slopify checklist (hush-cli)

### 7.1 Contract tests
- Add tests that run `hush` subcommands and assert exit codes + key output strings.
- Ensure `hush policy list` matches actual available rulesets (YAML or hard-coded, whichever you choose).

### 7.2 Output formats
- Decide: human output vs JSON output.
- If you add JSON output, stabilize the schema and version it.

## 8) Daemon de-slopify checklist (hushd)

### 8.1 Be honest about what it enforces
- Without OS sandbox hooks, you cannot fully enforce file/network for arbitrary processes.
- Therefore `hushd` should likely enforce at the agent-tool layer (MCP/tool calls) rather than raw syscalls.

### 8.2 If you add an HTTP server
- Define request schema and version it.
- Add authentication story if used beyond localhost.
- Add resource limits and backpressure.

## Appendix A: Mechanical refactor recipes (step-by-step)

### Recipe A: Convert string config to enum safely
1) Introduce enum in the same module as the config type.
2) Add serde rename_all = lowercase.
3) Update YAML rulesets and docs.
4) Add tests: parse valid values; reject invalid values.

### Recipe B: Add aggregated validation errors
1) Define error types:
   - `PolicyValidationError { errors: Vec<PolicyFieldError> }`
   - `PolicyFieldError { path: String, message: String }`
2) Implement `Policy::validate()` that collects errors.
3) Wire validation into `from_yaml_file` in CLI.
4) Add a CLI command to print errors in a stable format.

### Recipe C: Add GuardReport and keep per-guard evidence
1) Add new type `GuardReport` in `crates/hushclaw/src/guards/mod.rs` or `engine.rs`.
2) Update engine to collect per-guard results.
3) Define overall semantics (blocked/warn/allow).
4) Update CLI to display report when verbose.
5) Add tests for warn aggregation.

## Bibliography
- Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Rustdoc Book: https://doc.rust-lang.org/stable/rustdoc/
- Clippy Book: https://doc.rust-lang.org/stable/clippy/
- RFC 8785 (JCS): https://www.rfc-editor.org/rfc/rfc8785

## Appendix B: Per-crate de-slopify checklists (repo-specific)

### B.1 `crates/hush-core` (crypto + receipts)

- Treat `canonical.rs` as a spec boundary:
  - add golden vectors (RFC 8785) and test exact output strings
  - add cross-language fixtures if Python/TS are in scope
  - decide float formatting strategy (avoid debug formatting surprises)
- Treat `receipt.rs` as a schema contract:
  - decide what `version` means (schema ID vs semver)
  - add explicit version validation
  - add fixtures and tests to prevent drift
- Add a fallible verification API where booleans are currently used (optional but useful):
  - `PublicKey::verify` currently returns bool; consider `verify_strict -> Result`
- Review key material handling:
  - decide whether `Keypair` should be Clone
  - consider `zeroize` depending on threat model
- Add doc examples in rustdoc for core public APIs:
  - `Receipt::new`, `SignedReceipt::sign`, `SignedReceipt::verify`

### B.2 `crates/hush-proxy` (parsers + domain policy)

- DNS parsing (`dns.rs`):
  - document unsupported compression pointers
  - add property/fuzz tests for malformed packets
- TLS SNI parsing (`sni.rs`):
  - document limitations (fragmentation, partial reads)
  - add malformed input tests (must not panic)
- Domain matching semantics:
  - decide `*.` only vs globset
  - align docs and rule examples to actual semantics
  - normalize domains consistently (lowercase, strip trailing dot) and test it

### B.3 `crates/hushclaw` (policy + engine + guards)

- Fix policy schema confusion:
  - current Rust Policy (guards/settings) does not match mdBook/OpenClaw policy schema
  - decide unify vs translation layer
- Add `Policy::validate()`:
  - compile glob/regex patterns
  - reject invalid patterns with actionable diagnostics
- Replace stringly-typed config actions with enums:
  - `default_action: String` -> enum
- Engine semantics:
  - implement a `GuardReport` so warnings are not lost
  - make severity ordering explicit and tested
- Guard-specific improvements:
  - ForbiddenPathGuard: consider Path-based normalization rules
  - SecretLeakGuard: consider allow/ignore patterns to reduce false positives
  - PatchIntegrityGuard: consider scanning deletions too (threat-model dependent)
  - McpToolGuard: avoid allocations when measuring args size; consider namespaces/wildcards

### B.4 `crates/hush-cli` (contract + UX)

- Align CLI docs to actual commands (or implement missing ones).
- Define and document exit code semantics (allowed/blocked/warn/error).
- Consider adding `--json` output mode for automation (CI/CD).
- Add integration tests that run the CLI and assert output/exit codes.

### B.5 `crates/hushd` (daemon honesty)

- Decide enforcement boundary:
  - agent-tool enforcement (MCP/tool layer) vs OS-level enforcement (sandboxing)
- Document the current state clearly: server not implemented, key persistence semantics.
- If you add a server:
  - define request/response schemas and version them
  - add authentication story if not purely localhost
  - add backpressure and resource limits

## Appendix C: Multi-language alignment plan (Python + OpenClaw + Rust)

Your repo contains multiple implementations/schemas:
- Rust receipt schema (hush-core)
- Python receipt schema (packages/hush-py)
- OpenClaw policy schema (packages/hushclaw-openclaw)
- mdBook policy schema (docs)

De-slopify goal:
- Either unify schemas, or explicitly version and translate between them with fixtures/tests.

Concrete steps:
- Create `fixtures/` that includes:
  - policy YAML examples for each supported schema version
  - canonical JSON vectors
  - receipt JSON fixtures
- Add a test harness in each language that loads the same fixtures and asserts identical results where required.

If you do not actually want multi-language compatibility:
- Rename packages or add strong documentation boundaries so users do not assume compatibility.

## Appendix D: Review template (use in PRs)

When reviewing a PR, require the author to answer:
- What invariants are introduced or changed?
- Are invalid configs rejected early and loudly?
- Are new public APIs minimal and documented?
- Are there new allocations in hot paths? If yes, why is it acceptable?
- Are there new drift risks (docs/examples/rulesets) and how are they prevented?
- What tests were added? Do they cover edge cases and regressions?
- If schema changes occurred, where is the migration plan?

## Appendix E: Schema translation mapping (mdBook/OpenClaw schema -> current Rust schema)

If you choose “Option 3” from the decision matrix (keep both schemas and translate), you need an explicit mapping.
Treat this mapping as a security boundary: it must be tested with fixtures.

Terminology:
- S1 = mdBook/OpenClaw schema (egress/filesystem/execution/tools/... + on_violation + extends)
- S2 = Rust `Policy` schema implemented in `crates/hushclaw/src/policy.rs` (guards + settings)

### E.1 High-level mapping
- `egress.allowed_domains` -> `guards.egress_allowlist.allow`
- `egress.denied_domains` -> `guards.egress_allowlist.block`
- `egress.mode` -> `guards.egress_allowlist.default_action` + allow/block interpretation
- `filesystem.forbidden_paths` -> `guards.forbidden_path.patterns`
- `tools.allowed/denied` -> `guards.mcp_tool.allow/block`
- `secrets.additional_patterns` -> `guards.secret_leak.patterns` (append)
- `on_violation` -> S2 does not currently model this (gap)
- `limits.*` -> S2 does not currently model this (gap)
- `execution.*` -> S2 does not currently model this (gap)

### E.2 Detailed mapping table

| S1 field | Meaning | S2 target | Notes/gaps |
|---|---|---|---|
| `version` | schema id (e.g., hushclaw-v1.0) | `Policy.version` | S2 currently uses semantic-looking version; decide meaning. |
| `extends` | base policy id or URI | (new loader layer) | S2 has no extends; translation requires a loader/merge stage. |
| `egress.mode` | allowlist/denylist/open | `EgressAllowlistConfig.default_action` | S2 only has allow/block default; may need richer enum. |
| `egress.allowed_domains` | allowed host patterns | `EgressAllowlistConfig.allow` | Ensure wildcard semantics match. |
| `egress.denied_domains` | denied host patterns | `EgressAllowlistConfig.block` | Ensure precedence semantics match. |
| `egress.allowed_cidrs` | allowed IP ranges | (new feature) | S2 has unused `ipnet`; likely intended for this. |
| `filesystem.allowed_write_roots` | write allow roots | (new guard) | S2 has no write-root enforcement guard. |
| `filesystem.forbidden_paths` | blocked paths | `ForbiddenPathConfig.patterns` | Needs normalization rules and glob semantics. |
| `execution.mode` | allowlist/denylist | (new guard) | S2 has no command execution policy. |
| `execution.allowed_commands` | allowlist commands | (new guard) | Probably belongs in a ShellCommandGuard. |
| `execution.denied_patterns` | regex blocklist | (new guard) | Similar to PatchIntegrityGuard patterns but for commands. |
| `tools.mode` | allowlist/denylist | `McpToolConfig.allow/block/default_action` | S2 has allow/block/confirm sets; formalize mode. |
| `tools.allowed` | allow list | `McpToolConfig.allow` | If mode is allowlist, block everything else. |
| `tools.denied` | deny list | `McpToolConfig.block` | Deny takes precedence. |
| `tools.policies.*` | per-tool limits | (new feature) | S2 has only global max args size. |
| `secrets.additional_patterns` | extra regexes | `SecretLeakConfig.patterns` | Compile failures must be surfaced (validation). |
| `secrets.ignored_patterns` | false-positive suppression | (new feature) | Add ignore list and test semantics. |
| `guards.<name>` | enable/disable guard | (new feature) | S2 implies enable by config presence; might need explicit toggles. |
| `limits.*` | resource limits | (new feature) | Only meaningful if you have enforcement hooks. |
| `on_violation` | cancel/warn/isolate/escalate | (engine-level semantics) | S2 has fail_fast + logging; not the same. |

### E.3 Key engineering warnings
- Do not attempt to “kind of support” S1 by partial translation without labeling it; partial security policy support is worse than none.
- If you cannot enforce OS-level limits, do not pretend limits are enforced; treat them as advisory only and label them.
- Translation logic must be deterministic and tested with fixtures, or it becomes a hidden policy bypass bug.

## Appendix F: CI + offline build playbook (so quality gates are real)

If this repo is meant to be usable in restricted environments (no internet), you need to treat offline builds as a first-class constraint.

### F.1 Minimal CI gates (networked runner)
- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`
- Build examples (Rust examples) to prevent drift.

### F.2 Offline CI gate (optional, but valuable)
- Vendor dependencies via `cargo vendor` and configure `.cargo/config.toml` to use vendored sources.
- Run `CARGO_NET_OFFLINE=true cargo test --workspace` in CI.

### F.3 Why this is part of “de-ai-slopify”
- If your quality gates cannot run, drift is inevitable (docs drift, example drift, schema drift).
- Elite engineering is as much about process as code: you need gates that actually execute.

## Appendix G: Worked refactor examples (high-signal, mechanical)


### G.1 Worked example: implement `PolicyValidationError` (aggregate invalid patterns)

Goal:
- Replace silent pattern drops with actionable errors that list *all* invalid patterns at once.

Suggested types (pseudo-code):
```rust
#[derive(Debug, thiserror::Error)]
#[error("policy validation failed ({0} errors)")]
pub struct PolicyValidationError(pub Vec<PolicyFieldError>);

#[derive(Debug)]
pub struct PolicyFieldError {
  pub path: String,
  pub message: String,
}
```

Implementation steps:
1) Add these types in `crates/hushclaw/src/error.rs` (or a new `validation.rs`).
2) Implement `Policy::validate()` in `crates/hushclaw/src/policy.rs`:
   - for each guard config present, compile patterns
   - on error, push a `PolicyFieldError` with a path like `guards.secret_leak.patterns[3].pattern`
3) Return `Err(PolicyValidationError(errors))` if any errors exist.
4) Wire validation into CLI `policy validate` and into ruleset loading.

Tests to add:
- Invalid glob string in forbidden paths => validation fails and includes the path + error message.
- Invalid regex string in secret patterns => validation fails and includes the path + error message.
- Multiple invalid patterns => validation returns multiple errors (no early exit).

### G.2 Worked example: convert `default_action` strings to enums

Goal:
- Prevent typos from weakening policy behavior.

Suggested enum:
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction { Allow, Block }
```

Implementation steps:
1) Define enum in the guard config module (`egress_allowlist.rs` / `mcp_tool.rs`).
2) Replace `default_action: String` with `default_action: DefaultAction`.
3) Update defaults accordingly.
4) Update logic that currently checks `== "allow"` to match on enum.
5) Update YAML rulesets and any docs/examples that refer to string actions.

Tests to add:
- Parse valid YAML values: allow/block.
- Parse invalid YAML value: should fail with serde error (or validation error).

### G.3 Worked example: implement `GuardReport` (preserve warnings)

Goal:
- Make warnings observable and explainable; avoid the current “warning dropped” behavior.

Suggested types:
```rust
#[derive(Clone, Debug)]
pub enum OverallDecision { Allowed, AllowedWithWarnings, Blocked }

#[derive(Clone, Debug)]
pub struct GuardReport {
  pub overall: OverallDecision,
  pub per_guard: Vec<GuardResult>,
}
```

Aggregation rules (must be tested):
- If any `GuardResult.allowed == false` -> `Blocked`.
- Else if any `GuardResult.severity == Warning` -> `AllowedWithWarnings`.
- Else -> `Allowed`.

Implementation steps:
1) Update engine to collect per-guard results in a Vec.
2) Compute overall decision via the rules above.
3) Return `GuardReport` (either replace return type or add a new method `check_action_report`).
4) Update CLI output: if `AllowedWithWarnings`, print warnings and optionally list per-guard results.

Tests to add:
- allow-only => Allowed
- allow + warn => AllowedWithWarnings
- warn + block => Blocked

## Appendix H: “Elite PR size” guidance (how to keep this reviewable)

- Avoid “mega PRs” that touch everything at once.
- Prefer PRs that change one contract boundary at a time:
  - ruleset loading
  - policy validation
  - engine report semantics
  - canonicalization vectors
- Keep diffs small and add tests in the same PR.

## Appendix I: Final de-slopify checklist (use before release)

- Docs: README reflects actual CLI commands and policy schema.
- Docs: mdBook policy schema is either implemented or clearly labeled as roadmap.
- Docs: OpenClaw example policies are compatible with the chosen schema strategy.
- Examples: all examples compile (and are compiled in CI).
- Rulesets: CLI list matches engine loadable rulesets.
- Rulesets: every shipped ruleset YAML parses and validates in tests.
- Policy: invalid regex patterns fail validation with actionable errors.
- Policy: invalid glob patterns fail validation with actionable errors.
- Policy: unknown fields are handled intentionally (strict mode or permissive mode documented).
- Policy: stringly-typed actions replaced with enums where finite.
- Policy: domain wildcard semantics documented and tested.
- Engine: warnings are preserved and observable (no silent drop).
- Engine: per-guard evidence is available (report type) or logs are sufficient and documented.
- Engine: receipts include enough provenance to be meaningful (policy hash, ruleset id).
- Engine: policy hash is stable and deterministic.
- hush-core: canonical JSON outputs defended by golden vectors.
- hush-core: canonical JSON behavior aligned with other language implementations (if multi-language is real).
- hush-core: Merkle logic defended by vectors across sizes (odd/even).
- hush-core: signature verification has diagnostic mode (optional).
- hush-proxy: DNS parser does not panic on malformed input.
- hush-proxy: SNI parser does not panic on malformed input.
- hush-proxy: parser limitations documented (compression pointers, fragmentation).
- Guards: forbidden path patterns compile; invalid patterns are errors.
- Guards: secret leak patterns compile; invalid patterns are errors.
- Guards: patch integrity patterns compile; invalid patterns are errors.
- Guards: MCP tool config is typed (no arbitrary string modes).
- Guards: egress policy semantics tested (allow, block precedence).
- CLI: exit code semantics defined and documented.
- CLI: machine-readable output available for automation (optional but recommended).
- CLI: no commands documented that do not exist.
- Daemon: documentation matches implementation status (server TODO clearly stated).
- Daemon: receipt key management semantics documented (ephemeral vs persisted).
- Security: no logs include raw secrets or tokens.
- Security: guard details redact sensitive matches (no raw secrets).
- Security: enforcement boundary documented (agent-tool vs OS-level).
- Dependencies: unused deps removed or justified by implemented features.
- Dependencies: feature flags used for optional heavy deps (if added).
- Tooling: rustfmt enforced in CI.
- Tooling: clippy enforced in CI (deny warnings) with explicit allowlist if needed.
- Tooling: tests run in CI.
- Tooling: offline build strategy documented if required (vendor).
- API: public items are intentional; `pub(crate)` by default.
- API: error enums are forward-compatible (`#[non_exhaustive]` where appropriate).
- API: critical return values are `#[must_use]` (guard results).
- Performance: avoid avoidable allocations in per-action hot paths (measured if needed).
- Performance: lock contention is acceptable or optimized (based on metrics).
- Testing: integration tests exist for CLI contract (help output, key commands).
- Testing: regression tests exist for all previously found bugs (example drift, ruleset drift, warning drop).
- Release: versioning policy documented (MSRV, semver strategy).
- Release: changelog or release notes process exists.
