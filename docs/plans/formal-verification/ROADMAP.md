# Formal Verification Roadmap

**Author**: Principal Engineering
**Date**: 2026-03-16
**Status**: Active
**Predecessor**: [Landscape Survey](./landscape-survey.md)
**Last reviewed**: 2026-03-16

---

## Executive Summary

Six phases, ~28 weeks, three complementary paths:

1. **Logos/Z3** (shortest): SMT-based policy consistency/completeness checking. Requires building Z3 FFI from scratch (Layer 0 is currently enumeration-only) and a policy-to-formula bridge crate.
2. **Aeneas/Lean 4** (deepest): Translate the pure Rust core to Lean 4, prove properties about the actual implementation.
3. **Leanstral** (experimental): Mistral's Lean 4 proof agent for proof maintenance. Near-zero success on software verification benchmarks -- treat as evaluation only.

Target: ~500-800 lines of pure decision-making code. Cedar achieved comparable coverage with ~5 engineers over 2+ years; we scope aggressively to the decision-making core.

---

## MVP Definition and Cut Lines

If the project must be cut early, each phase boundary represents a coherent stopping point with standalone value.

| Cut Point | Calendar | Deliverable | Value |
|-----------|----------|-------------|-------|
| **End of Phase 0** (Week 2) | Minimal | `clawdstrike::core` module extracted, Aeneas feasibility confirmed | Architectural improvement (pure core); go/no-go data for continuing |
| **End of Phase 1** (Week 8) | **MVP** | `clawdstrike check --verify-policy` ships; Z3 consistency/completeness/inheritance checks on all built-in rulesets; enriched receipts | User-facing policy verification; CI-integrated; differentiator vs. every competitor |
| **End of Phase 2** (Week 14) | Strong | Lean 4 reference spec with 6 proved properties + 1M differential tests | Machine-checked spec; high-volume agreement testing; Attestation Level 2 |
| **End of Phase 3** (Week 22) | Full | Aeneas proofs of actual Rust implementation | Implementation-level verification; Attestation Level 3 |

**The MVP is Phase 0 + Phase 1.** If the project is resource-constrained, ship Z3 policy verification and stop. It delivers the most user-visible value per engineering-dollar: every policy author gets automated consistency and completeness checking, and every receipt can carry Z3 verification metadata. Phases 2-5 are incremental assurance deepening.

---

## Verification Targets

The 500-800 lines of pure decision-making logic targeted for verification. See [Verification Targets](./verification-targets.md) for full analysis of all 12 candidates with scoring.

| Function / Module | File | Lines | Verification Path | Priority Score |
|-------------------|------|-------|-------------------|---------------|
| `aggregate_overall()` | `engine.rs:1785` | ~35 | Aeneas + Z3 | 25 |
| `severity_ord()` | `engine.rs:1699` | 7 | Aeneas | 25 (bundled) |
| `MerkleTree::from_leaves()` / `audit_path()` / `verify_audit_path()` | `hush-core/src/merkle.rs` | ~110 | Aeneas | 20 |
| `from_yaml_with_extends_internal_resolver()` (cycle detection) | `policy.rs:1420` | ~45 | Aeneas | 20 |
| `canonicalize()` (RFC 8785 JCS) | `hush-core/src/canonical.rs` | ~358 | Aeneas + differential testing | 20 |
| `GuardConfigs::merge_with()` | `policy.rs:280` | ~80 | Aeneas + Z3 | 15 |
| `Policy::merge()` | `policy.rs:1295` | ~90 | Aeneas + Z3 | 15 |
| `merge_custom_guards()` | `policy.rs:1574` | ~20 | Aeneas | 15 (bundled) |
| `leaf_hash()` / `node_hash()` | `hush-core/src/merkle.rs:27,39` | ~20 | Aeneas | 20 (bundled) |

**Not in scope for Aeneas** (from verification-targets Tier 3): async guard runtime, serde deserialization, WASM bindings, origin/enclave resolution, shell command regex matching. These are addressed through testing and code review.

---

## Properties to Prove

Eight core properties, ranked by security impact. Numbering is consistent with the [Policy Specification](./policy-specification.md) document.

| ID | Property | Informal Statement | Formal Shape | Phase |
|----|----------|-------------------|--------------|-------|
| **P1** | Deny monotonicity | If any guard returns `allowed: false`, `aggregate_overall` returns `allowed: false` | `exists i. !results[i].allowed => !aggregate_overall(results).allowed` | 1, 2, 3 |
| **P2** | Fail-closed on config error | If `config_error` is `Some`, every `check_action` returns `Err` | `config_error.is_some() => forall action. check_action(action).is_err()` | 2 |
| **P3** | Severity total order | `severity_ord` defines a consistent total order: `Info < Warning < Error < Critical` | Reflexive, antisymmetric, transitive, total | 2, 3 |
| **P4** | Merge monotonicity | `merge_with` never removes a forbidden path from the base policy (unless explicitly in `remove_patterns`) | `forall p in base.forbidden_paths, p not in child.remove_patterns => p in merge_with(base, child).forbidden_paths` | 1, 2, 3 |
| **P5** | Cycle detection soundness | Cyclic `extends` references always return `Err` | `has_cycle(extends_graph) => from_yaml_with_extends(yaml).is_err()` | 2, 3 |
| **P6** | Depth bound termination | Extends resolution terminates within `MAX_POLICY_EXTENDS_DEPTH` (32) levels | `depth > 32 => Err(...)`, no infinite recursion | 2, 3 |
| **P7** | Merkle inclusion completeness | Every leaf in a `MerkleTree` has a valid audit path that verifies | `forall i < leaf_count. verify_audit_path(root, leaf[i], audit_path(i))` | 3 |
| **P8** | Canonical JSON determinism | `canonicalize(v) = canonicalize(v)` and key ordering follows RFC 8785 | Determinism + key ordering by UTF-16 code unit comparison | 3 |

**Not listed but tracked in INDEX.md**: Origin default-deny (P9, deferred until Origin Enclaves stabilize -- the `origin.rs` code is not yet in its final form and uses async/Arc<RwLock> which are Aeneas-incompatible).

---

## Phase 0: Foundation (Weeks 1-3)

**Goal**: Establish the verification infrastructure and extract a verifiable core. This phase is the go/no-go gate for the entire initiative.

**Extended to 3 weeks** from the original 2 to account for realistic Aeneas troubleshooting time. The aeneas-pipeline doc (Risk #1) rates Aeneas pattern rejection at Medium likelihood, and the core module extraction involves 13 guard config fields with per-type merge logic that may need rewriting.

### Tasks

- [ ] **Extract `clawdstrike::core` module**
  - New module `crates/libs/clawdstrike/src/core/mod.rs` with sub-modules:
    - `core::verdict` -- `Verdict` enum, `Severity` enum, `severity_ord()`, `GuardResult` (no serde)
    - `core::aggregate` -- `aggregate_overall()` (pure function, no async)
    - `core::merge` -- `GuardConfigs::merge_with()`, `Policy::merge()`, `merge_custom_guards()`
    - `core::cycle` -- Cycle detection logic extracted from `from_yaml_with_extends_internal_resolver()`
  - Constraints: no `async`, no `serde` derives (pure Rust types), no `dyn Trait`, no I/O
  - The existing code in `engine.rs` and `policy.rs` re-exports from `core::` and delegates
  - All existing tests continue to pass (refactor, not rewrite)

- [ ] **Create `clawdstrike-logos` bridge crate**
  - New crate at `crates/libs/clawdstrike-logos/`
  - Dependencies: `clawdstrike` (policy types), `logos-ffi` (formula AST)
  - Cargo workspace member in root `Cargo.toml`
  - Expose a `PolicyCompiler` trait:
    ```rust
    pub trait PolicyCompiler {
        fn compile_guards(&self, guards: &GuardConfigs) -> Vec<Formula>;
        fn compile_policy(&self, policy: &Policy) -> Vec<Formula>;
    }
    ```

- [ ] **Define policy-to-formula translation trait**
  - Each guard config maps to normative formulas:
    - `ForbiddenPathConfig` -> `Vec<Prohibition>`
    - `PathAllowlistConfig` -> `Vec<Permission>`
    - `EgressAllowlistConfig` -> `Vec<Permission>` + `Vec<Prohibition>`
    - `ShellCommandConfig` -> `Vec<Prohibition>`
    - `McpToolConfig` -> `Vec<Permission>`
  - Implement `GuardFormulas` trait for each config type
  - Formula atoms use structured names: `access("/etc/shadow")`, `egress("api.openai.com")`, `shell("rm -rf")`

- [ ] **Aeneas smoke test**
  - Install Aeneas toolchain (`charon` + `aeneas` binaries)
  - Pin specific git commits for both (Aeneas is pre-1.0; see Risk table)
  - Run `charon` on the extracted `core` module to produce LLBC
  - Run `aeneas` to generate Lean 4 output
  - Verify the generated Lean 4 type-checks (may require `#[cfg(not(aeneas))]` annotations on unsupported patterns)
  - Document any Rust patterns that need refactoring for Aeneas compatibility
  - **Go/no-go decision**: If `aggregate_overall` and `severity_ord` fail to extract after 3 days of troubleshooting, escalate. If `merge_with` fails, continue with the simpler targets and revisit merge in Phase 3.

- [ ] **Set up Lean 4 project structure**
  - New directory: `formal/lean4/ClawdStrike/`
  - `lakefile.lean` with Aeneas standard library dependency (`aeneas-lean4`)
  - Directory structure:
    ```
    formal/lean4/ClawdStrike/
      lakefile.lean
      lean-toolchain
      ClawdStrike/
        Core/
          Verdict.lean       -- Aeneas output
          Aggregate.lean     -- Aeneas output
          Merge.lean         -- Aeneas output
          Cycle.lean         -- Aeneas output
        Spec/
          Properties.lean    -- Theorem statements
        Proofs/
          DenyMonotonicity.lean
          CycleTermination.lean
          MergeMonotonicity.lean
    ```

### Deliverables

| Deliverable | Acceptance Criteria |
|-------------|-------------------|
| `clawdstrike::core` module | All existing tests pass, module has zero async/serde/IO dependencies |
| `clawdstrike-logos` crate skeleton | Compiles, `PolicyCompiler` trait defined, unit tests for formula generation of 1 guard type |
| Aeneas smoke test | `charon` produces LLBC for `core::aggregate`, `aeneas` produces `.lean` file that type-checks |
| Lean 4 project | `lake build` succeeds with Aeneas standard library |
| Go/no-go report | Written assessment of Aeneas compatibility for all Tier 1 targets |

### Risks

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Extracting pure core breaks existing API surface | Low | Use `pub use core::*` re-exports; no downstream changes |
| Aeneas rejects patterns in `merge_with` (e.g., `Option::or_else`, `Vec::retain`, `HashSet`) | Medium | Rewrite to explicit `match` arms; test Charon within first 3 days; fall back to verifying only aggregate/severity/cycle if merge is intractable |
| Lean 4 toolchain installation issues in CI | Low | Pin exact Lean version in `lean-toolchain`; cache `~/.elan/` in CI |
| Aeneas version instability (pre-1.0) | High | Pin Charon and Aeneas to specific git commits; commit generated Lean code to version control for diffing; regenerate only on planned updates |

---

## Phase 1: Z3 Policy Verification (Weeks 4-8)

**Goal**: Verify policy consistency and completeness via SMT, using the Logos normative logic stack.

### Prerequisite: Logos Z3 Current State (Honest Assessment)

The `logos-z3` crate (`crates/libs/logos-z3/`) now uses the `z3` crate FFI for satisfiability/validity checks and for the policy-verification integration in `clawdstrike-logos`. The implementation status:

- **Layer 0 (propositional)**: Implemented with hybrid enumeration for small formulas and direct Z3 checks for larger formulas.
- **Layer 1 (explanatory)**: Returns `Unknown` (still stubbed).
- **Layer 2 (epistemic)**: Returns `Unknown` (still stubbed).
- **Layer 3 (normative)**: Partially implemented for policy consistency, completeness, and inheritance checks used by ClawdStrike verification.
- `checker.rs` and `translation.rs` are populated and exercised by the Z3-backed test suite.

**Implication for Phase 1**: We are extending a working Z3 integration, not wiring it from scratch. The remaining work is about broadening and hardening the normative encoding rather than first-use FFI bring-up.

### Tasks

- [x] **Wire up actual Z3 FFI in `logos-z3`**
  - `translation.rs`: Logos `Formula` -> Z3 AST conversion
  - `checker.rs`: Z3 context management, solver lifecycle, model extraction
  - Hybrid Layer 0 path: exhaustive enumeration for small formulas, Z3 solver for larger formulas
  - Validation against the existing Layer 0 tests and the `clawdstrike-logos` Z3 verification path

- [ ] **Implement Logos Layer 3 (normative) Z3 encoding**
  - Extend `check_normative()` (currently returns `Unknown` at `lib.rs:220`)
  - Encoding strategy: standard deontic possible-worlds semantics
    - For each agent `a`, introduce Boolean sort `permitted_a(action)` and `forbidden_a(action)`
    - Deontic axioms as Z3 assertions:
      - `P(a) <=> NOT F(a)` -- permission is dual of prohibition
      - `O(a) => P(a)` -- obligation implies permission
      - `F(a) AND P(a) => false` -- contradiction (policy inconsistency)
    - Policy composition rules:
      - `forbidden(child) = forbidden(child_own) UNION forbidden(parent)` -- prohibitions accumulate
      - `permitted(child) = permitted(child_own) INTERSECT permitted(parent)` -- permissions narrow
  - Finite-domain optimization: enumerate action atoms from the policy (typically <50) rather than universal quantification over strings

- [ ] **Implement policy-to-formula translator for each guard type**
  - In `clawdstrike-logos`:
  - `ForbiddenPathGuard`:
    ```
    For each pattern p in forbidden_path.patterns:
      F_agent(access(p))
    For each pattern p in forbidden_path.additional_patterns:
      F_agent(access(p))
    ```
  - `PathAllowlistGuard`:
    ```
    For each allowed path p in path_allowlist.allowed_paths:
      P_agent(access(p))
    Default: F_agent(access(x)) for all x not matching an allowed path
    ```
  - `EgressAllowlistGuard`:
    ```
    For each domain d in egress_allowlist.allowed_domains:
      P_agent(egress(d))
    Default: F_agent(egress(x)) for all x not in allowed_domains
    ```
  - `ShellCommandGuard`:
    ```
    For each blocked cmd c in shell_command.blocked:
      F_agent(shell(c))
    ```
  - `McpToolGuard`:
    ```
    For each tool t in mcp_tool.allowed_tools:
      P_agent(mcp(t))
    If default_action == "deny":
      F_agent(mcp(x)) for all x not in allowed_tools
    ```
  - Implementation: ~500 lines across 5 guard translators

- [ ] **Z3 verification properties**
  - **Consistency check**: For a compiled policy, assert all formulas simultaneously. If Z3 returns `unsat`, the policy contains a contradiction (some action is both permitted and forbidden). Return counterexample showing the conflicting action.
    ```
    check(AND(all_permissions, all_prohibitions)) != unsat
    ```
  - **Completeness check**: For each action type (file, egress, shell, mcp), verify that at least one guard covers it. Encode as: `NOT (exists x. covered(x))` and check for `unsat`.
  - **Inheritance soundness**: Given base policy `B` and child policy `C`, verify:
    ```
    check(NOT (forall a. F_B(a) => F_merge(B,C)(a))) == unsat
    ```
    i.e., every prohibition in the base is preserved in the merged policy.
  - Each check runs in <100ms for typical policies (<50 atoms)

- [ ] **Integrate Z3 results into ClawdStrike receipt metadata**
  - Extend `Receipt` metadata (via `merge_metadata()`) with:
    ```json
    {
      "verification": {
        "z3_verified": true,
        "z3_consistency": "pass",
        "z3_completeness": "pass",
        "z3_inheritance_sound": "pass",
        "verification_time_ms": 42,
        "z3_proof_hash": "sha256:abcd1234...",
        "verification_properties": ["P1", "P4"]
      }
    }
    ```
  - Proof hash: SHA-256 of the canonical JSON of the Z3 query + result

- [ ] **Add `clawdstrike check --verify-policy` CLI command**
  - New subcommand in `hush-cli` (at `crates/services/hush-cli/`)
  - Input: policy YAML file path
  - Output: verification report (JSON or human-readable)
  - Exit code: 0 if all checks pass, 1 if any fail
  - Example:
    ```
    $ clawdstrike check --verify-policy policy.yaml
    Consistency:  PASS (12 formulas, 0 conflicts)
    Completeness: PASS (4/4 action types covered)
    Inheritance:  PASS (extends "strict", 0 weakened prohibitions)
    Time: 38ms
    ```

### Deliverables

| Deliverable | Acceptance Criteria |
|-------------|-------------------|
| Z3 FFI integration | `logos-z3` calls the Z3 solver for propositional checks and ClawdStrike policy verification; existing tests pass |
| Normative Z3 encoding | `check_normative()` returns `Valid`/`Invalid` for test formulas; deontic axioms validated against known theorems |
| Guard translators | All 5 guard types produce correct formulas; round-trip tests against known policies |
| Consistency checker | Detects intentionally contradictory policies; passes on all built-in rulesets (`permissive`, `default`, `strict`, `ai-agent`, `cicd`) |
| Completeness checker | Detects missing guard coverage; passes on `strict` and `ai-agent` rulesets |
| Inheritance checker | Detects intentional weakening; passes on all `extends` chains in `rulesets/` |
| Enriched receipts | `z3_verified` field present in receipts when verification is enabled |
| CLI command | `clawdstrike check --verify-policy` works end-to-end |

### Acceptance Tests

```bash
# All built-in rulesets pass consistency
for f in rulesets/*.yaml; do
  clawdstrike check --verify-policy "$f" || exit 1
done

# Intentionally broken policy detected
echo 'guards:
  forbidden_path:
    patterns: ["/app/data"]
  path_allowlist:
    allowed_paths: ["/app/data"]' > /tmp/contradictory.yaml
clawdstrike check --verify-policy /tmp/contradictory.yaml && exit 1
```

### Risks

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Z3 FFI integration takes longer than expected (no existing code to extend) | Medium | Budget 1.5 weeks for Z3 wiring; the `z3` crate has good Rust bindings; propositional layer is well-understood |
| Z3 timeout on complex policies (>50 atoms, nested inheritance) | Low | Finite-domain optimization limits atom count to policy contents; configurable timeout (default 5s); tier system (Quick/Standard/Full) |
| Glob patterns are not first-class in Z3 (path matching is approximate) | Medium | Over-approximate: if Z3 says "consistent," it is. If "inconsistent," flag for manual review of glob-related false positives |
| Translation bugs (policy semantics != formula semantics) | Medium | Differential testing: generate random policies, evaluate via both Rust engine and Z3 formula, assert agreement on concrete inputs |

---

## Phase 2: Lean 4 Reference Specification (Weeks 9-14)

**Goal**: Write a formal specification of the policy evaluator as total functions in Lean 4, and prove core properties about the specification.

**Extended to 6 weeks** from the original 4 to account for: (a) realistic Lean 4 ramp-up time for the team, (b) the policy-specification doc defining a much richer spec than what the original 4-week window assumed, (c) the differential test harness requiring both Rust and Lean executable integration.

### Prerequisite: Lean 4 Expertise

Requires at least one engineer with working Lean 4 experience (High severity / High likelihood risk). Mitigations:
1. Budget 2 weeks of ramp-up (types + simple proofs while learning).
2. Contract proof engineer ($250-400/hr, 15-20 hrs/week, 6-8 weeks = $22,500-$48,000) for hard proofs.
3. **Fallback**: If unavailable by Week 9, defer Phase 2 and ship Z3-only.

### Tasks

- [ ] **Define algebraic data types in Lean 4**
  - These are manually written (not Aeneas-generated), representing the *specification*, not the implementation. See [Policy Specification](./policy-specification.md) for the complete type definitions:
    ```lean
    inductive Severity where
      | info | warning | error | critical
    deriving DecidableEq, Repr

    structure GuardResult where
      allowed : Bool
      guard : String
      severity : Severity

    inductive MergeStrategy where
      | replace | merge | deepMerge

    structure ForbiddenPathConfig where
      patterns : List String
      additionalPatterns : List String

    structure GuardConfigs where
      forbiddenPath : Option ForbiddenPathConfig
      pathAllowlist : Option PathAllowlistConfig
      egressAllowlist : Option EgressAllowlistConfig
      -- ... (all 13 guard configs)

    structure Policy where
      name : String
      extends : Option String
      mergeStrategy : MergeStrategy
      guards : GuardConfigs
    ```

- [ ] **Define evaluation semantics as total functions**
  - `severityOrd : Severity -> Nat` -- total order mapping
  - `worseResult : GuardResult -> GuardResult -> GuardResult` -- pairwise comparison
  - `aggregate : List GuardResult -> GuardResult` -- verdict aggregation (recursive fold using `worseResult`)
  - `mergeGuardConfigs : GuardConfigs -> GuardConfigs -> GuardConfigs` -- guard-level merge
  - `mergePolicy : Policy -> Policy -> Policy` -- policy-level merge
  - `hasConfigError : Policy -> Bool` -- config error detection
  - `evalPolicy : Policy -> Action -> Context -> Except String GuardResult` -- full evaluation
  - All functions must be total (Lean enforces termination)

- [ ] **Prove core properties in Lean 4**
  - **P1: Deny monotonicity** -- The key security theorem.
    ```lean
    theorem deny_wins (rs : List GuardResult) (v : GuardResult)
      (hMem : v in rs) (hDeny : v.allowed = false) :
      (aggregate rs).allowed = false
    ```
  - **P2: Fail-closed on config error** -- Any config error prevents all actions.
    ```lean
    theorem fail_closed (policy : Policy) (action : Action) (ctx : Context)
      (h : hasConfigError policy = true) :
      exists msg, evalPolicy policy action ctx = .error msg
    ```
  - **P3: Severity total order** -- Reflexive, antisymmetric, transitive, total.
    ```lean
    theorem severity_ord_total_order :
      forall (a b : Severity),
        severityOrd a <= severityOrd b \/ severityOrd b <= severityOrd a
    ```
  - **P4: Forbidden path soundness** -- A forbidden path in the config means denial.
    ```lean
    theorem forbidden_path_sound (cfg : ForbiddenPathConfig) (path : String)
      (h : path in cfg.effectivePatterns) :
      !(evalForbiddenPath cfg path).allowed
    ```
  - **P5: Inheritance monotonicity** -- Child merge never removes base prohibitions (unless explicitly removed).
    ```lean
    theorem merge_preserves_forbidden (base child : GuardConfigs)
      (p : String) (h : p in (base.forbiddenPath.getD default).effectivePatterns) :
      p in ((mergeGuardConfigs base child).forbiddenPath.getD default).effectivePatterns
    ```
  - **P6: Merge idempotence on normalized policies** -- Once `extends` and additive/removal helper fields have been resolved, self-merge yields the same evaluation result.
    ```lean
    theorem merge_policy_idempotent
      (p : Policy) (action : Action) (ctx : Context)
      (h_norm : Policy.Normalized p) :
      evalPolicy (mergePolicy p p) action ctx = evalPolicy p action ctx
    ```
  - Determinism (trivial for total functions; `rfl` proof)

- [ ] **Set up differential testing framework**
  - Generate random policies + actions via `proptest` (Rust side):
    - Random `GuardConfigs` with 0-5 guards enabled, random patterns
    - Random `GuardResult` lists with 1-20 entries, random allowed/severity values
    - Random merge scenarios (base + child with various `MergeStrategy`)
    - Custom `proptest::Arbitrary` impls that respect schema constraints (see Open Question #2)
  - Compile Lean spec to native executable via `lake exe`
  - Differential test harness:
    1. Generate input (Rust `proptest`)
    2. Serialize to JSON
    3. Evaluate in Lean spec (via compiled executable reading JSON)
    4. Evaluate in Rust impl
    5. Assert agreement
  - Targets:
    - Week 14: 1M tests passing
    - Week 28+ (Phase 5): 100M nightly in CI (Cedar's benchmark)
  - Harness lives in `crates/tests/formal-diff-tests/`

### Deliverables

| Deliverable | Acceptance Criteria |
|-------------|-------------------|
| Lean 4 algebraic types | All ClawdStrike core types represented; `lake build` succeeds |
| Evaluation functions | `aggregate`, `mergeGuardConfigs`, `mergePolicy`, `severityOrd`, `evalPolicy` defined as total functions |
| P1 proof (deny monotonicity) | `#check` succeeds in Lean |
| P2 proof (fail-closed) | `#check` succeeds in Lean |
| P3 proof (severity total order) | `#check` succeeds in Lean |
| P5 proof (inheritance monotonicity) | `#check` succeeds in Lean |
| P6 proof (merge idempotence) | `#check` succeeds in Lean |
| Differential test harness | 1M random tests pass (Lean spec agrees with Rust impl) |

---

## Phase 3: Aeneas Verification (Weeks 15-22)

**Goal**: Formally verify the *actual Rust implementation* (not just a separate spec) by translating it to Lean 4 via Aeneas and proving properties about the translated code.

**Extended to 8 weeks** from the original 6. The effort table below totals ~7 weeks without buffer; the original 6-week allocation was a schedule overrun baked into the plan. With realistic troubleshooting and Aeneas breakage, 8 weeks is defensible.

### Tasks

- [ ] **Aeneas translation of `clawdstrike::core`**
  - Translate each sub-module separately to manage complexity:
    - `core::aggregate` -> `ClawdStrike/Impl/Aggregate.lean` (estimated: 2-3 days)
    - `core::verdict` -> `ClawdStrike/Impl/Verdict.lean` (estimated: 1 day)
    - `core::cycle` -> `ClawdStrike/Impl/Cycle.lean` (estimated: 3-5 days)
    - `core::merge` -> `ClawdStrike/Impl/Merge.lean` (estimated: 1-2 weeks)
  - Merge is the hardest: 13 `Option` fields with per-type merge logic, nested pattern matching
  - Expected Aeneas issues and workarounds:
    - `Option::or_else` closures: rewrite to explicit `match`
    - `Vec::contains`: provide Aeneas-compatible wrapper
    - `Vec::retain`: rewrite as explicit loop or `filter`
    - `String` operations: may need to abstract to opaque type
    - `HashSet` (cycle detection): verify Charon support; fallback to sorted Vec

- [ ] **Prove `aggregate_overall` monotonicity against actual Rust implementation**
  - The Aeneas output is a Lean function that *is* the Rust implementation (translated)
  - Prove: `deny_wins_impl` -- same theorem as P1 but about the Aeneas-generated function
  - This proves the *Rust code*, not a hand-written spec
  - Cross-reference with Phase 2 spec: prove `aggregate_spec = aggregate_impl` (implementation matches specification)

- [ ] **Prove cycle detection termination**
  - Depth bound: `depth > MAX_POLICY_EXTENDS_DEPTH => Err`
  - Visited set completeness: every resolved key is added to `visited` before recursion
  - Combined: `from_yaml_with_extends_internal` terminates for all inputs
  - Lean 4 termination proof via well-founded recursion on `MAX_POLICY_EXTENDS_DEPTH - depth`

- [ ] **Aeneas translation of `hush-core::merkle`**
  - Target functions: `leaf_hash`, `node_hash`, `MerkleTree::from_leaves`, `audit_path`, `verify_audit_path`
  - SHA-256 is axiomatized (we do not verify the hash function itself, only its usage)
  - Properties to prove:
    - **RFC 6962 leaf/node hashing correctness**: `leaf_hash` prepends `0x00`, `node_hash` prepends `0x01` (structural correctness)
    - **Inclusion proof completeness**: `forall i < leaf_count. audit_path(i).is_ok()`
    - **Proof verification roundtrip**: `verify_audit_path(root, leaf_hash(leaf[i]), audit_path(i)) = true`
  - Estimated: 1-2 weeks for translation + proofs

- [ ] **Axiomatize Ed25519 in Lean 4, prove receipt signing properties**
  - Do NOT verify Ed25519 implementation (use axioms from `ed25519-dalek`)
  - Axioms:
    ```lean
    axiom ed25519_sign_verify (sk : SecretKey) (pk : PublicKey) (msg : ByteArray)
      (h : pk = sk.publicKey) :
      ed25519_verify pk msg (ed25519_sign sk msg) = true

    axiom ed25519_sign_deterministic (sk : SecretKey) (msg : ByteArray) :
      ed25519_sign sk msg = ed25519_sign sk msg
    ```
  - Prove: signature covers canonical JSON content (the message signed is `canonicalize(receipt_json)`)
  - Prove: verification roundtrip (sign then verify succeeds)

### Deliverables

| Deliverable | Acceptance Criteria |
|-------------|-------------------|
| Aeneas translation of `core::aggregate` | Generated Lean 4 type-checks |
| Aeneas translation of `core::merge` | Generated Lean 4 type-checks |
| Aeneas translation of `core::cycle` | Generated Lean 4 type-checks |
| `deny_wins_impl` proof | Machine-checked proof that Rust `aggregate_overall` satisfies deny monotonicity |
| `aggregate_spec_eq_impl` proof | Machine-checked proof that Aeneas translation agrees with Phase 2 reference spec |
| Cycle termination proof | Machine-checked proof of termination within depth bound |
| Merkle inclusion completeness proof | Machine-checked proof that every leaf has a valid audit path |
| Receipt signing correctness | Machine-checked proof of sign/verify roundtrip (modulo Ed25519 axioms) |

### Estimated Effort

| Component | Translation | Proofs | Total |
|-----------|-------------|--------|-------|
| `core::aggregate` + `core::verdict` | 2 days | 3 days | 1 week |
| `core::cycle` | 3 days | 5 days | ~1.5 weeks |
| `core::merge` | 5 days | 8 days | ~2.5 weeks |
| `hush-core::merkle` | 3 days | 5 days | ~1.5 weeks |
| Ed25519 axiomatization + receipt proofs | 1 day | 2 days | 3 days |
| **Total** | | | **~7 weeks** (1 week buffer in 8-week phase) |

### Risks

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Aeneas version breaks generated code between phases | High (Aeneas is pre-1.0) | Pin to specific git commit; commit generated Lean to version control; only upgrade on planned cycles |
| `merge_with` is too complex for Aeneas | Medium | Verify simpler targets first (aggregate, cycle). If merge fails, prove it against the reference spec only (Phase 2 level). |
| Proofs take longer than estimated | Medium | The merge monotonicity proof is the riskiest (2.5 weeks estimated). If it stalls at week 20, defer to Phase 6 and ship the simpler proofs. |

---

## Phase 4: Leanstral Evaluation (Weeks 19-22)

**Goal**: Evaluate AI-assisted proof generation and establish a workflow for ongoing proof maintenance.

This phase is an evaluation, not a deployment. Leanstral's pass@16 rate is 32% on research math; software verification (miniCodeProps) is near-zero for all current LLM provers.

### Tasks

- [ ] **Deploy Leanstral**
  - Option A: 4x A100 80GB on RunPod (~$8-12/hr on-demand, ~$200-500/mo reserved)
  - Option B: Mistral API (if available for Leanstral by this phase)
  - Set up `lean-lsp-mcp` MCP server connecting Leanstral to the Lean 4 project
  - Validate basic operation: Leanstral can read our `lakefile.lean`, understand the project structure, and generate valid tactics

- [ ] **Benchmark against Phase 2 and Phase 3 proofs**
  - Take 10+ theorem statements from Phase 2 and Phase 3
  - For each, measure:
    - Can Leanstral complete the proof autonomously (pass@1, pass@8)?
    - Time to proof (or timeout at 30 minutes)?
    - Proof quality (tactic count, use of `sorry`, readability)?
    - Cost per proof attempt?
  - **Expected success rates** (from landscape survey):
    - Trivial lemmas (`simp`/`omega`): ~60-80%
    - Easy structural induction: ~20-40%
    - Medium lemmas (deny monotonicity): ~5-15%
    - Hard lemmas (merge, cycle termination): ~0-5%
    - Our proofs use Aeneas-generated code with non-standard types, likely unseen in training.
  - Document results in `formal/lean4/ClawdStrike/evaluation/leanstral-benchmark.md`

- [ ] **Set up lean-lsp-mcp for interactive proof development**
  - Configure as MCP tool server accessible from Claude Code
  - Workflow: human writes `theorem` statement with `sorry` body, Leanstral fills in proof
  - Integrate with Lean 4 infoview for step-by-step tactic validation

- [ ] **Develop proof automation workflow**
  - Standard operating procedure:
    1. Human writes theorem statement and any necessary helper lemmas
    2. Leanstral attempts proof via MCP agent loop (budget: 16 attempts, 30 min timeout)
    3. If successful: human reviews generated proof for correctness and style
    4. If failed: human writes proof manually, using Leanstral for sub-goals
  - Track metrics: % of proofs automated, time saved vs. manual, cost per proof

- [ ] **Assessment report**
  - Can Leanstral prove P1 from scratch? Can it repair a broken proof when code changes?
  - Expected answer: **No, not yet.** The evaluation gives data for future re-assessment.

### Deliverables

| Deliverable | Acceptance Criteria |
|-------------|-------------------|
| Leanstral deployment | Model responds to Lean 4 proof queries via MCP |
| Benchmark report | 10+ theorems evaluated, success rates and costs documented |
| MCP proof workflow | `lean-lsp-mcp` integrated with development environment |
| Automation SOP | Written procedure for human+Leanstral proof development |
| Cost/benefit analysis | $ per proof vs. hours of manual proof engineering |
| Assessment verdict | Written recommendation on whether to invest further in Leanstral |

---

## Phase 5: Production Integration (Weeks 23-28)

**Goal**: Ship formal verification as a user-facing feature with tiered attestation levels.

**Extended to 6 weeks** from the original 4. The original plan had Phase 5 at weeks 21-24 with Phase 3 ending at week 16, but Phase 3 now ends at week 22 and Phase 5 has additional production hardening tasks.

### Tasks

- [ ] **`clawdstrike verify` CLI command**
  - New top-level command in `hush-cli`:
    ```
    clawdstrike verify [OPTIONS] <policy.yaml>

    Options:
      --z3          Run Z3 consistency/completeness/inheritance checks
      --diff-test   Run differential tests against Lean spec (requires compiled spec)
      --full        Run all verification passes
      --json        Output results as JSON
      --strict      Fail on any verification warning (not just errors)
    ```
  - Exit codes: 0 = all pass, 1 = verification failure, 2 = verification error (tool failure)
  - JSON output schema for CI integration:
    ```json
    {
      "policy": "policy.yaml",
      "attestation_level": 1,
      "checks": [
        {"name": "z3_consistency", "result": "pass", "time_ms": 38},
        {"name": "z3_completeness", "result": "pass", "time_ms": 12},
        {"name": "z3_inheritance", "result": "pass", "time_ms": 24}
      ],
      "properties_verified": ["P1", "P4"],
      "timestamp": "2026-09-15T10:30:00Z"
    }
    ```

- [ ] **Policy load-time verification (optional, configurable)**
  - New `settings` field in policy YAML:
    ```yaml
    settings:
      verification:
        enabled: true           # default: false
        mode: warn              # warn | strict (strict blocks unverified policies)
        checks: [consistency, completeness, inheritance]
        cache: true             # cache results by policy content hash
    ```
  - Implementation:
    - On `Policy::from_yaml_with_extends`, if `settings.verification.enabled`:
      1. Compute SHA-256 of policy YAML content
      2. Check verification cache (`~/.clawdstrike/verification-cache/`)
      3. If cache miss: run Z3 checks, store result
      4. If check fails and `mode == strict`: return `Err`
      5. If check fails and `mode == warn`: log warning, continue
  - Performance target: <100ms including cache lookup for typical policies
  - Cache invalidation: content-addressed (hash of normalized YAML)

- [ ] **Receipt attestation levels**
  - Four-tier system reflecting verification depth:

  | Level | Name | Meaning | How Achieved |
  |-------|------|---------|-------------|
  | 0 | Heuristic | Guards evaluated, no formal verification | Current behavior (default) |
  | 1 | Z3-Verified | Policy passed Z3 consistency/completeness checks | Phase 1 Z3 checks pass |
  | 2 | Spec-Proved | Policy properties proved in Lean 4 reference spec | Phase 2 proofs + differential tests pass |
  | 3 | Impl-Verified | Rust implementation verified via Aeneas translation | Phase 3 Aeneas proofs cover the evaluated code path |

  - Receipt metadata includes `attestation_level` field
  - Level is the *minimum* of all applicable verification results
  - `SignedReceipt` includes the attestation level in the signed content (cannot be upgraded after signing)

- [ ] **Scale differential testing to 100M nightly**
  - Optimize the Lean spec executable for throughput
  - Set up nightly CI runner with 8+ cores
  - Dashboard for tracking disagreement rate over time

- [ ] **Documentation**
  - mdBook chapter: `docs/src/verification.md`
    - What is formally verified (and what is not)
    - How to run `clawdstrike verify`
    - How to enable load-time verification
    - Understanding attestation levels
    - Architecture: Logos/Z3, Aeneas/Lean 4, differential testing
  - API documentation for `clawdstrike-logos` crate

### Deliverables

| Deliverable | Acceptance Criteria |
|-------------|-------------------|
| `clawdstrike verify` CLI | End-to-end execution with JSON output on all built-in rulesets |
| Load-time verification | Configurable via policy YAML; <100ms with cache; strict mode blocks unverified |
| Attestation levels in receipts | `attestation_level` field in signed receipts; Level 1 achievable for all standard rulesets |
| 100M nightly differential tests | CI pipeline running, zero disagreements |
| mdBook chapter | Rendered in `docs/book/` with working examples |

---

## Phase 6: Advanced (Ongoing, Post-Week 28)

**Goal**: Extend verification to harder targets and establish continuous verification in CI.

### Tasks (Prioritized)

- [ ] **Continuous verification in CI** (High priority)
  - On every PR that touches `crates/libs/clawdstrike/src/core/`:
    1. Re-run `charon` + `aeneas` to regenerate Lean 4 translation
    2. Re-check all Lean proofs (`lake build`)
    3. Run 1M differential tests
    4. Block merge if any proof breaks
  - Estimated CI time: ~5 min per PR (Lean checking)

- [ ] **Canonical JSON verification** (High priority)
  - Aeneas translation of `hush-core/src/canonical.rs`
  - Prove P8: determinism and RFC 8785 key ordering
  - Cross-language differential tests (Rust vs TS vs Python) for the JCS test vectors

- [ ] **Posture state machine verification** (Medium priority)
  - Use TLA+ or Logos temporal operators to verify:
    - All posture transitions are reachable from the initial state
    - No deadlock states (every state has at least one outbound transition)
    - Budget counters never underflow
    - Capability sets are monotonically non-increasing along enforcement paths
  - Target: `crates/libs/clawdstrike/src/posture.rs`

- [ ] **Policy merge associativity proofs** (Medium priority)
  - `merge(merge(A, B), C) = merge(A, merge(B, C))` -- associativity
  - Note: merge is not commutative by design (child overrides parent)

- [ ] **ForbiddenPath symlink safety proof** (Medium priority)
  - Prove that `normalize_path_for_policy` correctly resolves symlinks such that no symlink can bypass a forbidden path
  - Requires modeling the filesystem as a partial function `Path -> Option<Path>`

- [ ] **Egress allowlist intersection correctness** (Low priority)
  - Prove that `EgressAllowlistConfig::merge_with` correctly computes the intersection of domain allowlists
  - i.e., after merge, only domains allowed by BOTH base and child are permitted

- [ ] **Lean FFI in logos-ffi** (Low priority)
  - Connect the stubbed `LogosContext` in `logos-ffi` to actual Lean 4 proof checking
  - Allow Logos to verify formulas by delegating to the Lean kernel

- [ ] **Explore Verus for direct Rust annotation-based verification** (Exploratory)
  - If Aeneas translation maintenance becomes burdensome, evaluate Verus as an alternative
  - Trade-off: verification lives in-source (easier maintenance) but requires rewriting target functions

---

## Dependency Graph

```
Phase 0 (Foundation, Weeks 1-3)
  |
  +--------> Phase 1 (Z3 Policy Verification, Weeks 4-8)
  |            |
  |            +--------+
  |                     |
  +--------> Phase 2 (Lean Spec, Weeks 9-14)
  |            |                     |
  |            +--------> Phase 3 (Aeneas, Weeks 15-22)
  |            |                     |
  |            +--------> Phase 4 (Leanstral Eval, Weeks 19-22)
  |                                  |
  |                                  v
  +----------------------------> Phase 5 (Production, Weeks 23-28)
                                     |
                                     v
                                 Phase 6 (Advanced, Ongoing)
```

**Critical path (Z3 MVP)**: Phase 0 -> Phase 1 (Z3 in production by Week 8)
**Deep verification path**: Phase 0 -> Phase 2 -> Phase 3 -> Phase 5 (Aeneas in production by Week 28)
**Automation evaluation path**: Phase 0 -> Phase 2 -> Phase 4 (Leanstral assessment by Week 22)

### Parallelism

Phases 1 (Z3, Rust engineer) and 2 (Lean, proof engineer/contractor) run in parallel after Phase 0. Phase 3 depends on Phase 2; Phase 4 overlaps Phase 3 (weeks 19-22). Phase 5 can ship Level 1 attestation with Phase 1 alone.

---

## Timeline

```
Week  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28
      [  Phase 0    ]
               [   Phase 1: Z3 Policy Verification  ]
                              [    Phase 2: Lean 4 Reference Spec          ]
                                                        [ Phase 3: Aeneas Verification               ]
                                                                    [Phase 4: Leanstral]
                                                                                    [  Phase 5: Production    ]
                                                                                                        Phase 6 ->
```

### Milestones

| Week | Milestone | Gate |
|------|-----------|------|
| 3 | `clawdstrike::core` module extracted, Aeneas smoke test passing, go/no-go report | Phase 0 complete |
| 5 | Z3 FFI wired up, normative encoding working, first guard translator complete | Phase 1 midpoint |
| 8 | `clawdstrike check --verify-policy` works on all built-in rulesets | **Phase 1 complete (MVP)** |
| 11 | Lean 4 types defined, `aggregate` specified as total function | Phase 2 midpoint |
| 14 | 6 properties proved in Lean 4, 1M differential tests passing | Phase 2 complete |
| 18 | Aeneas translation of `core::aggregate` and `core::cycle` complete | Phase 3 midpoint |
| 22 | All Aeneas proofs complete (aggregate, cycle, merge, Merkle); Leanstral benchmark complete | Phase 3 + 4 complete |
| 28 | `clawdstrike verify` shipped, attestation levels in receipts, 100M nightly diff tests | Phase 5 complete |

---

## Cost Estimates

| Item | One-Time | Monthly Recurring | Notes |
|------|----------|-------------------|-------|
| Proof engineer (contract, Phases 2-3) | $22,500 - $48,000 | -- | 6-8 weeks at ~15-20 hrs/week at $250-400/hr; pairs with internal engineer |
| Internal engineer time (Phases 0-5) | Opportunity cost | -- | ~1 FTE for 7 months; not a cash outlay but the largest real cost |
| Leanstral compute (Phase 4) | -- | $200 - $500 | 4x A100 80GB on RunPod; only during 4-week evaluation window |
| Differential testing CI (nightly) | -- | ~$50 | 100M tests on 8-core runner, ~2 hours |
| Z3 in CI (per PR) | -- | ~$0 | Z3 checks run in <10s; negligible cost |
| Lean 4 toolchain in CI | -- | ~$20 | elan install + lake build; cached between runs |
| **Total (cash, Year 1)** | **$22,500 - $48,000** | **$270 - $570/mo** | |

### Cost-Benefit Comparison

| Approach | Cash Cost | Time to First Verified Property | Assurance Level |
|----------|-----------|-------------------------------|-----------------|
| Phase 0 + 1 only (Z3 MVP) | ~$0 (internal) | 8 weeks | Policy-level consistency (spec, not impl); Attestation Level 1 |
| Phases 0-2 (Z3 + Lean spec) | ~$22-48k | 14 weeks | Spec-level properties + differential testing; Attestation Level 2 |
| Phases 0-3 (full) | ~$22-48k + FTE time | 22 weeks | Implementation-level verification; Attestation Level 3 |
| Cedar's approach (reference) | ~$500k+ (5 engineers, 2+ years) | 12+ months | Production-grade, comprehensive |

**Note:** The $22.5-48k assumes part-time (15-20 hrs/week). Full-time senior Lean 4 + Rust verification engineers command $300-500/hr and are scarce. If an internal engineer ramps up during Phase 2, the contractor engagement can be shortened to 4 weeks.

---

## Success Metrics

| Metric | Target | Measurement | Achievable By |
|--------|--------|-------------|---------------|
| Z3 verification of built-in rulesets | 100% pass rate | All `rulesets/*.yaml` pass consistency + completeness + inheritance | Phase 1 (Week 8) |
| False negatives in Z3-verified policies | 0 | Consistency check catches all planted contradictions in test suite | Phase 1 (Week 8) |
| Z3 policy-load-time verification overhead | <100ms | Benchmark on representative policies with cache cold | Phase 1 (Week 8) |
| Core properties formally proved (spec level) | 6 (P1-P6) | Lean 4 `#check` succeeds for all theorem statements | Phase 2 (Week 14) |
| Differential tests passing | 1M | CI dashboard; zero disagreements between Lean spec and Rust impl | Phase 2 (Week 14) |
| Core properties proved (implementation level) | P1, P5, P7 minimum | Lean 4 `#check` on Aeneas-generated functions | Phase 3 (Week 22) |
| Differential tests passing (nightly) | 100M+ | CI dashboard; zero disagreements | Phase 5 (Week 28) |
| Receipt attestation level for standard rulesets | Level 1 minimum, Level 2 for P1-P6 targets | `clawdstrike verify --full` output | Phase 5 (Week 28) |
| Aeneas translation coverage | `aggregate_overall`, cycle detection, Merkle tree minimum | All targeted functions successfully translated and proved | Phase 3 (Week 22) |

**Note**: `merge_with` Aeneas translation is a stretch goal for Phase 3 due to its complexity. If it fails to translate, it remains at spec-level (Phase 2) verification only. This is an explicit scope management decision, not a failure.

---

## Competitive Positioning

See [Landscape Survey, Section 5](./landscape-survey.md) for full analysis. No competitor in AI agent security has formal verification. OPA/Rego is Turing-complete (unfriendly to verification). Cedar verified authorization, not runtime security.

---

## Risk Register

| # | Risk | Severity | Likelihood | Phase | Mitigation |
|---|------|----------|------------|-------|------------|
| R1 | **No Lean 4 expertise on team** | High | High | 2, 3 | Contract proof engineer ($22-48k); budget 2 weeks ramp-up; fallback to Z3-only if no hire by Week 9 |
| R2 | **Aeneas rejects `merge_with` patterns** | High | Medium | 0, 3 | Phase 0 smoke test answers this by Week 3; prove merge only at spec level (Phase 2) if Aeneas fails |
| R3 | **Aeneas version instability** | Medium | High | 3, 6 | Pin to specific git commits; commit generated Lean to VCS; regenerate only on planned upgrade cycles |
| R4 | **Z3 FFI integration takes longer than expected** (no existing code to extend) | Medium | Medium | 1 | Budget 1.5 weeks for Z3 wiring; the z3 Rust crate has good bindings |
| R5 | **logos-z3 normative encoding is unsound** | Medium | Low | 1 | Validate against known deontic logic results; cross-check with Lean proofs in Phase 2 |
| R6 | **Leanstral cannot handle software verification** | Low (expected) | High (expected) | 4 | Do not depend on Leanstral for any deliverable; treat Phase 4 as evaluation only |
| R7 | **Verification effort delays feature work** | Medium | Medium | All | Phase 0+1 is ~1 engineer for 8 weeks; Phases 2-3 use a contractor; feature team is not blocked |
| R8 | **Verified core diverges from actual code** | Medium | Medium | 2, 5 | Differential testing (Cedar's approach); CI enforcement; Aeneas re-translation on every PR touching `core/` |
| R9 | **Translation bugs in policy-to-formula compiler** | Medium | Medium | 1 | Differential tests comparing Z3 results with Rust evaluation on the same concrete inputs |
| R10 | **Proof engineer cost exceeds budget** | Medium | Medium | 2, 3 | Part-time engagement (15-20 hrs/week) caps cost; internal engineer handles types/spec; contractor handles hard proofs only |
| R11 | **Z3 timeout on complex policies with temporal operators (posture)** | Low | Low | 6 | Defer posture BMC to Phase 6; core policy checks (Phase 1) have <50 atoms and are fast |
| R12 | **Glob patterns not first-class in Z3** | Low | Medium | 1 | Over-approximate: Z3 "consistent" is definitive; "inconsistent" flagged for manual review |

---

## Decision Log

| # | Decision | Rationale | Alternatives Considered | Date |
|---|----------|-----------|----------------------|------|
| D1 | Z3 first, Lean second | Z3 delivers verified policies in weeks; Lean takes months. Ship value incrementally. Phase 0+1 is the MVP. | Lean-only (too slow for first deliverable), Verus-only (smaller ecosystem) | 2026-03-16 |
| D2 | Reference spec + differential testing (Cedar's approach) for Phase 2 | 90% of value at 10% of cost vs. full end-to-end Rust verification. Proven approach. | End-to-end Aeneas only (too expensive and risky for v1) | 2026-03-16 |
| D3 | Aeneas over Verus for Rust verification | Larger ecosystem (Lean 4 + Mathlib + potential Leanstral). Industrial precedent (SymCrypt ML-KEM). Aeneas verifies existing code; Verus requires rewriting. | Verus (kept as Phase 6 fallback if Aeneas maintenance is too burdensome) | 2026-03-16 |
| D4 | Axiomatize Ed25519, do not verify it | `ed25519-dalek` is a well-audited library; re-verifying it is out of scope and infeasible (contains `unsafe`). | Verify from scratch (not feasible) | 2026-03-16 |
| D5 | Separate `clawdstrike::core` module | Aeneas requires pure, safe, no-async Rust; clean separation benefits testing too. Module has zero dependencies beyond std. | Annotate in-place with `#[cfg(aeneas)]` (fragile, hard to maintain) | 2026-03-16 |
| D6 | Attestation levels in receipts (4-tier) | Gives users a clear, auditable signal of verification depth. Levels correspond to phases. | Binary "verified" flag (less informative); no attestation metadata (missed opportunity) | 2026-03-16 |
| D7 | Treat Leanstral as evaluation, not dependency | Published benchmarks show near-zero success on software verification (miniCodeProps). No deliverable depends on Leanstral succeeding. | Depend on Leanstral for proof maintenance (too risky) | 2026-03-16 |
| D8 | 28-week timeline (from original 24) | Original plan had Phase 3 effort (~7 weeks) squeezed into 6-week phase, no buffer for Aeneas troubleshooting, and assumed existing Z3 FFI. Honest accounting adds 4 weeks. | Keep 24-week aspirational target (dishonest planning) | 2026-03-16 |
| D9 | Part-time contractor over full-time hire for Lean proofs | Lean 4 + Rust verification is a niche skill; full-time hire is hard and expensive. Part-time engagement (15-20 hrs/week) gives expert input while internal engineer ramps up. | Full-time hire ($250-400k/yr for this profile); fully outsource (loses knowledge transfer) | 2026-03-16 |
| D10 | `merge_with` Aeneas translation is a stretch goal | 13 Option fields with per-type merge logic is the hardest Aeneas target. Spec-level proof (Phase 2) is sufficient if Aeneas translation fails. | Require full Aeneas coverage (creates schedule risk for Phase 3) | 2026-03-16 |

---

## Open Questions

1. **Aeneas compatibility**: Will `GuardConfigs::merge_with()` with 13 `Option` fields and per-type merge logic translate cleanly? Phase 0 smoke test will answer this. **Decision point: Week 3.**

2. **Differential test oracle**: How do we generate random policies that are both valid (pass schema validation) and interesting (exercise non-trivial merge/aggregation behavior)? Likely answer: custom `proptest::Arbitrary` impl that respects schema constraints. Should be prototyped during Phase 2.

3. **Lean 4 in CI**: Do we need the Lean toolchain in CI, or can we check in proof artifacts? Checking in artifacts is fragile; CI verification is correct. Use `elan` in CI with cached toolchain. **Decision: CI verification.**

4. **Z3 static linking**: `logos-z3/Cargo.toml` has a `z3-static` feature for static linking. Should we default to static or dynamic? Static is simpler for distribution but increases build time (~5-10 min for Z3 from source). **Decision: static for release builds, dynamic for development.**

5. **Policy-to-formula soundness**: The Z3 path verifies properties of the *formula translation*, not the Rust code. How do we ensure the translator itself is correct? Answer: (a) extensive unit tests with known-correct translations, (b) differential tests comparing Z3 results with Rust evaluation on the same inputs, (c) Phase 3 Aeneas proofs verify the implementation directly.

6. **Leanstral availability**: Will Leanstral be available as an API service by Week 19, or will we need to self-host? Plan for self-hosting; switch to API if available.

7. **Nightly Rust for Charon**: Charon requires a specific nightly Rust toolchain. How does this interact with ClawdStrike's MSRV (1.93)? Answer: Charon runs as a separate extraction step, not as part of the normal build. The nightly requirement applies only to the CI verification job, not to the production build.

8. **Origin default-deny (P9 from INDEX.md)**: Should this property be added to the verification targets once Origin Enclaves stabilize? Deferred until the origin.rs code reaches its final form. The code currently uses async/Arc<RwLock> which are Aeneas-incompatible.

---

## References

- [Aeneas: Rust verification by functional translation](https://github.com/AeneasVerif/aeneas) (Inria/Microsoft Research, ICFP 2022 + 2024)
- [Amazon Cedar: Lean 4 formalization](https://github.com/cedar-policy/cedar-spec) (Amazon, 2023-present)
- [Leanstral: Lean 4 proof agent](https://mistral.ai/news/leanstral) (Mistral AI, 2026)
- [Verus: Verified Rust via SMT](https://github.com/verus-lang/verus) (Microsoft Research / CMU)
- [lean-lsp-mcp](https://github.com/leanprover/lean-lsp-mcp) -- MCP server for Lean Language Server
- [SymCrypt ML-KEM verification via Aeneas](https://www.microsoft.com/en-us/research/publication/a-verified-implementation-of-ml-kem/) (Microsoft, 2025)
- Logos stack: `crates/libs/logos-ffi/`, `crates/libs/logos-z3/`, `logos-goap`
- ClawdStrike policy engine: `crates/libs/clawdstrike/src/engine.rs`, `crates/libs/clawdstrike/src/policy.rs`
- ClawdStrike Merkle tree: `crates/libs/hush-core/src/merkle.rs`
- ClawdStrike canonical JSON: `crates/libs/hush-core/src/canonical.rs`
