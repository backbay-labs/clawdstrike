# Formal Verification Landscape Survey

**Author**: Principal Engineering
**Date**: 2026-03-16
**Status**: Complete

---

## 1. Problem Statement

ClawdStrike enforces security at the AI agent tool boundary using 13 built-in guards, a policy inheritance system with deep-merge semantics, and a verdict aggregation pipeline. The system is fail-closed by design: `#[must_use]` on all result types, `deny_unknown_fields` on all serde structs, config errors bubble up as sticky denials.

But "by design" is not "by proof." The core invariants are enforced by convention and testing:

- **Deny-wins**: `aggregate_overall()` (`engine.rs:1785`) selects the most severe blocking result. A single logic error (e.g., wrong comparison direction in severity ordering) silently permits dangerous actions.
- **Fail-closed**: `config_error: Option<String>` gates every `check_action_report()` call (`engine.rs:440`). If a code path bypasses this check, the engine runs with a broken policy and allows everything.
- **Merge monotonicity**: `GuardConfigs::merge_with()` (`policy.rs:280`) implements per-guard merge logic across 13 guard config fields plus custom guards. A bug in any branch can cause a child policy to silently drop a parent's restrictions.
- **Cycle detection**: `from_yaml_with_extends_internal_resolver` (`policy.rs:1420`) uses a `HashSet<String>` visited set bounded by `MAX_POLICY_EXTENDS_DEPTH = 32` (`policy.rs:32`). An off-by-one or key collision silently permits infinite recursion or rejects valid chains.

Formal verification provides mathematical proof that these invariants hold for all inputs, not just the inputs covered by tests. For a security system, this is the difference between "tested" and "proved."

### What We Are NOT Verifying

Full end-to-end verification of the entire `clawdstrike` crate (async runtime, serde, regex, I/O) is neither feasible nor necessary. The target is the **pure decision-making core**: verdict aggregation, policy merge, severity ordering, cycle detection, and the mapping from policy configuration to guard instantiation. This is approximately 400-800 lines of pure logic embedded in ~10,000+ lines of production code (see [Verification Targets](./verification-targets.md) for the exact inventory and [Aeneas Pipeline](./aeneas-pipeline.md) Appendix A for per-file LOC).

---

## 2. Prior Art: Amazon Cedar

Cedar is the closest existing precedent for formally verified policy enforcement. Understanding what they did -- and what they chose not to do -- is critical for scoping our own effort.

### What Cedar Verified

| Property | Technique | Scope |
|----------|-----------|-------|
| "Forbid overrides permit" | Lean 4 proof | Authorization semantics |
| "Explicit permit required" | Lean 4 proof | Default-deny correctness |
| Validator soundness | Dafny proof | Type checking rejects ill-formed policies |
| Implementation correctness | Differential testing | Lean spec vs. Rust impl, 100M+ nightly |

### Key Architecture Decisions

1. **Reference specification, not end-to-end Rust verification.** Cedar wrote a complete Lean 4 specification of the authorization semantics and proved properties about the spec. They did NOT verify the Rust implementation directly. Instead, they run differential tests: the Lean spec and the Rust impl must agree on 100M+ randomly generated inputs every night.

2. **Small, decidable language.** Cedar's policy language is intentionally not Turing-complete. Policies are first-order expressions over entity hierarchies. This makes the semantics amenable to SMT-based automated verification.

3. **Dual-prover approach.** Lean 4 for the deep semantic properties (human-guided), Dafny for the validator (more automated via SMT). Different tools for different proof shapes.

### Lessons for ClawdStrike

- ClawdStrike's policy evaluation is also not Turing-complete. Policies are YAML configurations interpreted by a fixed set of guards. There are no loops, no recursion in evaluation (only in `extends` resolution, which is bounded at depth 32). This means the core semantics are a decision procedure, and many properties are amenable to fully automated SMT verification.
- A reference spec + differential testing (Cedar's approach) delivers most of the practical value at a fraction of the cost of end-to-end Rust verification. We should plan for this as the primary strategy, with direct implementation verification (via Aeneas) as a complementary second path.
- Cedar had a team of ~5 verification engineers working for 2+ years. We need to scope aggressively: verify the pure decision-making core, not the entire crate.

---

## 3. Tool Landscape

### 3.1 Aeneas (Rust to Lean 4)

**Source**: [github.com/AeneasVerif/aeneas](https://github.com/AeneasVerif/aeneas)
**Origin**: Inria / Microsoft Research
**Papers**: ICFP 2022 ("Aeneas: Rust verification by functional translation"), ICFP 2024 (extended)
**Maturity**: Research-grade, ~4900 commits, active development

#### How It Works

Aeneas takes safe Rust code (via LLBC, the Low-Level Borrow Calculus extracted from the Rust compiler) and translates it to pure functional Lean 4 code using a "backward functions" technique. Mutable borrows become pairs of (value, continuation), so `&mut T` in Rust maps to `(T, T -> Result)` in Lean.

#### What It Supports

| Feature | Support | Notes |
|---------|---------|-------|
| Structs, enums | Yes | Direct translation to Lean inductive types |
| Generics | Yes | Lean polymorphism |
| Traits | Yes | Lean typeclasses |
| Closures | Yes | Defunctionalization |
| Iterators | Partial | Simple patterns via loop translation |
| `Vec<T>`, `HashMap` | Yes | Via Aeneas standard library |
| Pattern matching | Yes | |
| `Option`, `Result` | Yes | Monadic encoding |

#### What It Does NOT Support

| Feature | Status | Impact on ClawdStrike |
|---------|--------|----------------------|
| `unsafe` | No | Not used in policy/engine core |
| `async`/`await` | No | Guards are async -- cannot verify guard execution directly |
| `Cell`/`RefCell`/`RwLock` | No | `HushEngine` uses `Arc<RwLock>` for `EngineState` -- must abstract away |
| `Arc`, `Mutex` | No | Shared-state concurrency primitives excluded |
| I/O, filesystem, network | No | Policy loading (serde/fs) excluded |
| `dyn Trait` | No | `Box<dyn Guard>` dispatch excluded |
| FFI | No | |
| Macros (proc or declarative) | Partial | Expanded by rustc before Charon extraction |
| Serde derives | No | Must work on already-deserialized types |

#### Industrial Precedent

Microsoft used Aeneas (with hax) to verify SymCrypt's ML-KEM (post-quantum cryptography) implementation -- pure algorithmic logic extracted from a larger system, the same pattern we follow.

---

### 3.2 Leanstral (AI-Assisted Proof Automation)

**Source**: [mistral.ai/news/leanstral](https://mistral.ai/news/leanstral)
**Model**: MoE 119B total / 6.5B active parameters, fine-tuned for Lean 4
**License**: Apache 2.0
**Tooling**: `lean-lsp-mcp` MCP server wrapping Lean's Language Server Protocol

#### Capabilities

Leanstral is an agentic Lean 4 prover. It reads a Lean project, understands the type signatures and theorem statements, and generates proof terms using a type-checker-in-the-loop workflow (each candidate tactic is validated by Lean's kernel before proceeding).

#### Benchmarks

| Benchmark | Leanstral | Claude Sonnet | Claude Opus | Notes |
|-----------|-----------|---------------|-------------|-------|
| FLTEval (pass@2) | 26.3% ($36) | 23.7% ($549) | 39.6% ($1650) | Research math |
| FLTEval (pass@16) | 32.0% | -- | -- | Still 68% failure |
| miniCodeProps | Not benchmarked | Near-zero on medium/hard | Near-zero on medium/hard | Software verification |

#### Assessment

Leanstral can automate routine lemmas (case splits, `simp`/`omega` chains, structural induction with clear structure). It cannot discover deep properties or handle creative proof design.

Key weaknesses:

1. **No software verification benchmarks.** All published results are on mathematical theorems. miniCodeProps (which tests code property proofs) shows all current LLM provers fail on nearly all medium and hard problems.
2. **Requires existing Lean context.** The formalization (types, definitions, theorem statements) must exist before Leanstral can help fill in proof bodies.
3. **68% failure rate at pass@16** on research math. Software verification should expect higher failure rates.

**Role in our pipeline: proof assistant, not proof engineer.** The human designs the formalization, states theorems, and handles hard cases. See [Aeneas Pipeline, Section 4](./aeneas-pipeline.md#step-4-leanstral-assisted-proof-automation-future) for success rate estimates by proof category.

---

### 3.3 Logos Stack (Existing, In-Repository)

**Location**: `crates/libs/logos-ffi`, `crates/libs/logos-z3`, `logos-goap`

The Logos stack exists in the monorepo, implements a 4-layer modal-temporal logic, and has operators that map directly to policy semantics.

#### Current State

| Component | Status | What It Does |
|-----------|--------|-------------|
| `logos-ffi` | Complete | Formula AST for all 4 layers, axiom schemas (S5 modal + linear temporal), proof receipts with Ed25519 signing |
| `logos-z3` | Layer 0 complete, policy-focused Layer 3 partial, Layers 1-2 stubbed | Hybrid enumeration/Z3 satisfiability plus policy-verification checks and counterexample generation |
| `logos-goap` | Complete | Verified planning with proof receipts |

#### Layer 3 Normative Operators (Directly Relevant)

The `Formula` enum in `logos-ffi/src/formula.rs` already has:

```
Obligation(AgentId, Box<Formula>)   -- O_a(phi): agent a must ensure phi
Permission(AgentId, Box<Formula>)   -- P_a(phi): agent a may do phi
Prohibition(AgentId, Box<Formula>)  -- F_a(phi): agent a must not do phi
Preference(Box<Formula>, Box<Formula>) -- phi < psi: psi preferred over phi
```

And the derived operator:

```
permission_via_obligation: P_a(phi) = NOT O_a(NOT phi)
```

This is exactly the vocabulary needed to express ClawdStrike policy semantics formally.

#### What Needs to Be Built

1. **Normative Z3 encoding.** `logos-z3/src/lib.rs`: `check_normative()` currently returns `Unknown`. We need to implement deontic logic semantics in the Z3 encoding -- Standard Deontic Logic (SDL) axioms where permission is the dual of prohibition, obligation implies permission, and the two are mutually exclusive. See [Logos Integration, Section 4](./logos-integration.md#4-z3-layer-3-encoding-design) for the full axiom set.

2. **Policy-to-formula compiler.** A function that takes a `Policy` struct and produces a set of `Formula` values representing its normative content. For example, a `ForbiddenPathConfig` with patterns `["/etc/shadow", "~/.ssh/*"]` compiles to `F_agent(access("/etc/shadow")) AND F_agent(access("~/.ssh/*"))`. See [Logos Integration, Section 2](./logos-integration.md#2-policy-to-formula-translation) for per-guard translation rules.

3. **Property checker.** A function that takes two policies (base and merged) and checks that every prohibition in the base is preserved in the merge. This is a validity check: `F_base(phi) => F_merged(phi)` should hold for all `phi` (no counterexample). When the check fails, Z3 produces a satisfying assignment showing the specific action whose prohibition was lost.

#### Why This Is the Shortest Path

- No new dependencies (Logos is already in the workspace)
- No Lean toolchain setup
- Z3 is mature, battle-tested, and handles propositional + first-order logic efficiently
- Proof receipts already implemented (Ed25519 signed, formula hashed)
- We can have a working prototype checking merge monotonicity within days, not months

---

### 3.4 Verus (Verified Rust via SMT)

**Source**: [github.com/verus-lang/verus](https://github.com/verus-lang/verus)
**Origin**: Microsoft Research / CMU
**Approach**: Hoare-style annotations in Rust source, verified by Z3

Verus lets you annotate Rust functions with preconditions (`requires`), postconditions (`ensures`), and loop invariants, then verifies them via Z3 SMT solving. Unlike Aeneas, you write specifications inline with the Rust code -- no separate theorem prover project.

#### Advantages Over Aeneas

- No separate Lean project to maintain -- specifications live alongside the code
- Verification stays in sync with the implementation by construction
- Handles some patterns Aeneas cannot (bounded loops, some interior mutability)
- Richer specification of loop invariants

#### Disadvantages

- Requires writing annotated versions of functions in Verus's restricted Rust dialect (cannot verify arbitrary existing code directly)
- Verification annotations can be 2-5x the size of the verified code
- Less compositional than Lean proofs -- harder to build libraries of reusable lemmas
- Smaller community, fewer examples of real-world use
- Cannot verify async code (same limitation as Aeneas)

#### Role in Our Plan

Verus is a viable alternative to Aeneas for Path 2, but we prefer the Lean ecosystem (Aeneas + Leanstral + Mathlib) for three reasons: (1) the Lean community is larger and more active, (2) Leanstral provides an automation path that has no Verus equivalent, and (3) Cedar's precedent with Lean 4 means more reference material. We keep Verus as a fallback if Aeneas translation hits unsupported Rust patterns in our codebase.

---

### 3.5 Other Tools Considered

| Tool | What It Does | Potential Use | Assessment |
|------|-------------|---------------|------------|
| **TLA+** | Model check state machines | Posture system state transitions, budget counter overflow, delegation token lifecycle | **Best fit for posture verification.** See [Verification Targets, Target 10](./verification-targets.md). |
| **Kani** | Bounded model checking for Rust via CBMC | Finding bugs in bounded scenarios; complement to formal proofs | Useful for exhaustive testing of `aggregate_overall` up to input size N. Does not provide full proofs. |
| **Alloy** | Lightweight design checking via SAT | Quick exploration of policy merge properties before committing to full verification | Good for prototyping, but does not scale to production verification. |
| **K Framework** | Define language semantics once, derive interpreter + model checker + deductive verifier | Could define ClawdStrike policy semantics as a K definition | High setup cost, small community. Not recommended unless team has K expertise. |
| **Creusot** | Rust verification via Why3 | Similar niche to Verus; less mature | No meaningful advantage over Verus for our use case. |
| **Prusti** | Rust verification via Viper | Research-grade, handles some ownership patterns | Least mature of the Rust verification tools. Not recommended. |

---

## 4. The Three Paths

### Path 1: Logos/Z3 -- Shortest Path to Verified Policy Properties

**Timeline**: 2-4 weeks to prototype, 2-3 months to production
**Effort**: 1 engineer
**Delivers**: SMT-verified policy merge monotonicity, deny-wins aggregation, forbid-overrides-permit

**Approach**:
1. Implement `check_normative()` in `logos-z3` using standard deontic possible-worlds semantics
2. Write a `PolicyCompiler` that translates `Policy` -> `Vec<Formula>` (normative content)
3. For each property (deny-wins, merge monotonicity, etc.), encode as a validity query and check with Z3
4. Emit signed `ProofReceipt` for verified properties
5. Integrate into CI: policies that fail verification are rejected

**Strengths**:
- Builds on existing code
- Fully automated (no human proof effort beyond encoding)
- Fast feedback loop (Z3 returns in milliseconds)
- Produces counterexamples when properties fail

**Limitations**:
- Verifies the *specification* (formula translation), not the *implementation* (Rust code)
- Requires trusting that the policy-to-formula compiler is correct
- Cannot verify properties about Rust code paths (fail-closed, etc.)

---

### Path 2: Aeneas/Lean 4 -- Deepest Verification of Core Logic

**Timeline**: 3-6 months to first proofs, 6-12 months to comprehensive coverage
**Effort**: 1-2 engineers with Lean experience
**Delivers**: Machine-checked proofs that the Rust implementation of aggregation, merge, and cycle detection is correct

**Approach**:
1. Extract `aggregate_overall`, `severity_ord`, `GuardConfigs::merge_with`, and cycle detection into a standalone `clawdstrike-core-pure` crate with no async, no serde, no I/O
2. Run Aeneas to translate to Lean 4
3. State theorems about the translated functions (deny-wins, monotonicity, termination)
4. Prove theorems in Lean 4 (using Leanstral for routine sub-goals)
5. Run differential tests: the Lean functions and the Rust functions must agree on randomized inputs

**Strengths**:
- Verifies the actual Rust code (via translation), not just a separate spec
- Proofs are machine-checked by Lean's kernel (highest assurance level)
- Differential testing catches translation bugs

**Limitations**:
- Requires extracting pure logic into a separate crate (refactoring effort)
- Aeneas is research-grade; may hit unsupported patterns
- Lean proofs require significant expertise
- Only covers the extracted pure core, not the full pipeline

---

### Path 3: Leanstral Automation -- Aspirational

**Timeline**: Depends on LLM prover maturity (12-24 months to be practical)
**Effort**: Minimal ongoing (after setup)
**Delivers**: Automated proof generation and maintenance as the codebase evolves

**Approach**:
1. Complete Path 2 (Aeneas/Lean setup with human-written proofs)
2. Set up Leanstral via `lean-lsp-mcp` as a CI step
3. When code changes break proofs, Leanstral attempts to repair them automatically
4. Human reviews and accepts/rejects repairs

**Strengths**:
- Reduces ongoing maintenance cost of formal proofs
- Scales proof effort as codebase grows

**Limitations**:
- Current LLM provers fail on most non-trivial software verification problems
- Requires Path 2 as prerequisite
- Risk of accepting incorrect proof repairs if review is lax

---

### Recommended Sequencing

```
Weeks 1-6:    Path 1 (Logos/Z3)   -- quick wins, CI-integrated policy verification
Weeks 7-16:   Path 2 (Aeneas)     -- deep verification of pure core
Weeks 17+:    Path 3 (Leanstral)  -- automation layer on top of Path 2
```

See [ROADMAP](./ROADMAP.md) for the detailed week-by-week plan.

Path 1 and Path 2 are **complementary**: Path 1 verifies _policy-level_ properties (formula translation), Path 2 verifies _implementation-level_ properties (actual Rust code via Lean 4). Together they cover the full stack.

---

## 5. Competitive Positioning

### Current Landscape

| System | Domain | Formal Verification | Technique |
|--------|--------|-------------------|-----------|
| **Amazon Cedar** | Authorization (RBAC/ABAC) | Yes -- Lean 4 + Dafny + differential testing | Reference spec + implementation testing |
| **OPA / Rego** | General policy | None | No formal semantics; Rego is Turing-complete |
| **Sentinel (HashiCorp)** | Infrastructure policy | None | Custom language, no formal semantics |
| **Casbin** | Access control | None | Model-based but not formally verified |
| **ClawdStrike** | AI agent runtime security | **Planned** | Logos/Z3 + Aeneas/Lean 4 |

### Why This Matters

1. **Cedar proved it is achievable.** The techniques are known; the tools exist. The question is execution.

2. **AI agent security demands higher assurance.** Authorization policies gate human-initiated requests. ClawdStrike gates autonomous agent actions -- an agent with a silently weakened policy can exfiltrate data or execute arbitrary code without a human in the loop. The blast radius of a policy engine bug is categorically larger.

3. **No competitor has formal verification.** OPA/Rego has no formal semantics. Rego is Turing-complete, making verification fundamentally harder. ClawdStrike's bounded evaluation is an architectural advantage.

4. **The Logos stack reduces integration cost.** Connecting Logos Layer 3 to policy semantics is a bridge crate, not a multi-year framework build.

---

## 6. Risk Assessment

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| Aeneas cannot handle our Rust patterns | Medium | Medium | Extract pure core into minimal crate (see [Aeneas Pipeline, Section 3](./aeneas-pipeline.md#3-architectural-refactoring-required)); fallback to Verus |
| Logos Z3 normative encoding is unsound | Medium | Low | Validate against known SDL theorems; cross-check with Lean proofs from Path 2 |
| Leanstral cannot handle our proof obligations | High | High | Do not depend on Path 3 for any milestone; treat as cost reduction, not capability |
| Verification effort delays feature work | Medium | Medium | Path 1 requires < 1 FTE-month; defer Path 2 if resource-constrained |
| Verified core diverges from production code | High | Medium | Differential testing (Cedar's approach); CI enforcement; core module delegates to production code |
| Z3 timeout on complex policies | Low | Low | Policy evaluation is bounded; typical queries have < 50 atoms; finite-domain optimization (see [Logos Integration, Section 4.5](./logos-integration.md)) |
| Team lacks Lean 4 expertise | High | High | Start with Leanstral-assisted proofs for simple cases; budget for ramp-up; consider contracting a proof engineer |
| Policy-to-formula translator has bugs | Medium | Medium | Differential testing: evaluate policies through both Rust engine and Z3, assert agreement on verdicts |

---

## 7. Open Questions

1. **Granularity of Aeneas extraction**: Should we extract individual functions (`aggregate_overall`, `merge_with`) or create a `core/` module with all pure logic? **Current plan**: `core/` module approach (see [Aeneas Pipeline, Section 3](./aeneas-pipeline.md#3-architectural-refactoring-required)). Phase 0 smoke test will validate.
2. **Differential test oracle**: How do we generate random policies that are both valid YAML and exercise interesting merge/aggregation behavior? **Likely answer**: Custom `proptest::Arbitrary` impl that respects schema constraints (see [ROADMAP, Phase 2](./ROADMAP.md#phase-2-lean-4-reference-specification-weeks-7-10)).
3. **Logos Z3 integration point**: Should the policy-to-formula compiler live in `clawdstrike` or in a new crate? **Decision**: New `clawdstrike-logos` bridge crate to keep Z3 dependency optional (see [Logos Integration, Section 6.2](./logos-integration.md#62-crate-structure)).
4. **CI performance budget**: How much verification time per PR is acceptable? Z3 queries should be < 1s; Lean checking could be 30s-5min. See [ROADMAP, Phase 6](./ROADMAP.md#phase-6-advanced-ongoing-post-week-24) for CI time estimates.
5. **Lean 4 toolchain in CI**: Do we need Lean in our CI image, or can we check in generated proof artifacts? **Decision**: Use `elan` in CI with cached toolchain. Checking in artifacts is fragile (see [ROADMAP, Open Question 3](./ROADMAP.md#open-questions)).
