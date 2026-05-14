# Formal Verification Initiative -- Documentation Index

## Vision

Machine-checked proofs that "deny means deny," fail-closed means fail-closed, and inheritance never silently weakens security.

Two assets make this tractable: (1) the Logos modal-temporal logic stack in `platform/crates/`, whose normative operators map directly to policy semantics, and (2) a policy evaluation model that is bounded and non-Turing-complete.

## Document Map

| Document | Description | Status |
|----------|-------------|--------|
| [Landscape Survey](./landscape-survey.md) | Survey of tools, techniques, prior art, and the three verification paths | Complete (reviewed) |
| [Verification Targets](./verification-targets.md) | Prioritized analysis of what to verify, with effort estimates and recommended tools | Complete (reviewed) |
| [Logos Integration](./logos-integration.md) | Connecting Logos Layer 3 normative operators to ClawdStrike policy semantics (Z3 path) | Implemented (Phase 1 complete) |
| [Aeneas Pipeline](./aeneas-pipeline.md) | Rust-to-Lean 4 verification pipeline for pure decision-making logic | In Progress (Phase 3) |
| [Policy Specification](./policy-specification.md) | Formal spec of the policy evaluator as a total decision procedure (Lean 4 reference) | Implemented (Phase 2 complete) |
| [ROADMAP](./ROADMAP.md) | Phased implementation roadmap (Logos/Z3 first, Aeneas second, Leanstral third) | Active (Phases 0-2 complete, Phase 3 in progress, Phase 5 CI integrated) |
| [Phase 0: Aeneas Feasibility](./phase0-aeneas-feasibility.md) | Feasibility assessment of Aeneas extraction for ClawdStrike's pure functions | Complete |
| [Phase 3: Merkle Report](./phase3-merkle-report.md) | Aeneas extraction results for hush-core Merkle tree module (partial -- types only) | Complete |

## Architecture Context

The policy engine lives in `crates/libs/clawdstrike/src/`. The verifiable target is the **pure decision-making core**: ~400-800 lines of logic embedded in ~10K+ lines of production code. See [Verification Targets](./verification-targets.md) for the exact function inventory.

| Module | LOC | Verification relevance |
|--------|-----|----------------------|
| `engine.rs` | 4623 | **Critical** -- deny-wins (`aggregate_overall` at line 1785), fail-closed |
| `policy.rs` | 3735 | **High** -- merge semantics, monotonicity, cycle detection |
| `guards/mod.rs` | -- | **High** -- result lattice, severity total order |
| `pipeline.rs` | -- | Medium -- ordering invariants |
| `posture.rs` | -- | Medium -- state machine safety |
| `origin.rs` + `enclave.rs` | -- | Medium -- default-deny on unknown origin |

## Core Properties to Verify

1. **Deny-wins aggregation**: If any guard returns `allowed: false`, `aggregate_overall()` returns a result with `allowed: false`. (See `engine.rs:1785`.)
2. **Fail-closed on config error**: If `config_error` is `Some`, every `check_action_report()` returns `Err`. (See `engine.rs:440`.)
3. **Severity total order**: `severity_ord` defines a consistent total order: `Info(0) < Warning(1) < Error(2) < Critical(3)`. (See `engine.rs:1699`.)
4. **Merge monotonicity**: Extending a policy with a child never removes a forbidden path unless the child explicitly includes that path in `remove_patterns`. (See `policy.rs:280`, `guards/forbidden_path.rs:139`.)
5. **Cycle detection soundness**: `from_yaml_with_extends_internal_resolver` with a cyclic reference always returns `Err`. (See `policy.rs:1420`.)
6. **Depth bound**: Extends resolution terminates within `MAX_POLICY_EXTENDS_DEPTH` (32) levels. (See `policy.rs:32`.)
7. **Origin default-deny**: When `origins` is configured and no origin matches, behavior matches `effective_default_behavior()`.

## CI Status (Phase 5)

Formal verification runs automatically on every push and PR that touches the policy engine, rulesets, or formal spec. The CI workflow lives at `.github/workflows/formal-verification.yml`.

| Check | What it does | Target time |
|-------|-------------|-------------|
| **Policy Verification (Z3)** | Runs `clawdstrike policy verify` on all 11 built-in rulesets, checking consistency, completeness, and inheritance soundness via the Logos/Z3 integration | < 10s |
| **Differential Tests** | Runs `formal-diff-tests` (proptest-based) comparing the Lean 4 reference spec against the production Rust implementation for aggregate, merge, and cycle logic | Configurable via `PROPTEST_CASES` (default: 1M in CI, 10K locally) |
| **Lean 4 Spec Build** | Builds the Lean 4 project at `formal/lean4/ClawdStrike/` via `lake build`, confirming all type definitions, evaluation functions, and proved theorems compile cleanly | ~2 min with cache |

**Verification summary (as of 2026-03-17):**

- Lean 4 theorems: 155 (across Core, Spec, and Proofs modules)
- Properties with complete proofs (no sorry): P1 (deny monotonicity), P3 (severity order), P5 (cycle termination), P6 (depth bound)
- Properties with partial proofs (some sorry): P4 (merge monotonicity), P7 (Merkle inclusion), P8 (canonical JSON)
- `Spec/Properties.lean` is fully proved, including forbidden-path policy soundness, forbidden-path merge additions, and normalized-policy merge idempotence
- Remaining editable `sorry` goals live in `Spec/MerkleProperties.lean`, `Proofs/MergeMonotonicity.lean`, and `Proofs/Impl/*`
- Differential test coverage: aggregate, merge, and cycle logic (3 test suites)

**Local verification** (via mise):

```bash
mise run verify-policies   # Z3 policy checks (~5s)
mise run diff-test          # Differential tests (10K cases default, override with PROPTEST_CASES)
mise run verify-lean        # Lean 4 build (~2 min first run, seconds with cache)
mise run verify-all         # All of the above
```

**Path triggers:** CI only fires when files in the verification-relevant paths change:
`crates/libs/clawdstrike/src/core/**`, `policy.rs`, `engine.rs`, `hush-core/src/merkle.rs`, `hush-core/src/canonical.rs`, `crates/tests/formal-diff-tests/**`, `formal/**`, `rulesets/**`.

## Key References

- [Aeneas](https://github.com/AeneasVerif/aeneas) -- Rust-to-Lean 4 translator (Inria/Microsoft Research, ICFP 2022 + 2024)
- [Leanstral](https://mistral.ai/news/leanstral) -- Mistral's Lean 4 proof agent (MoE 119B, Apache 2.0)
- [Amazon Cedar](https://www.cedarpolicy.com/) -- Formally verified authorization policy language (Lean 4 + Dafny)
- [Verus](https://github.com/verus-lang/verus) -- Verified Rust via SMT (Microsoft Research / CMU)
- [IMP Formalization](https://www.cs.princeton.edu/courses/archive/fall10/cos441/sf/Imp.html) -- Software Foundations Ch. 8 (inspiration for [Policy Specification](./policy-specification.md))
- Logos Stack: `crates/libs/logos-ffi` (formula AST, axiom schemas), `crates/libs/logos-z3` (SMT-backed checker), `logos-goap` (verified planning)

## Relationship to Logos

ClawdStrike's policy semantics map to Logos Layer 3 normative operators:

| ClawdStrike concept | Logos formula |
|---------------------|-------------|
| Forbidden path `/etc/shadow` | `F_agent(access("/etc/shadow"))` (Prohibition) |
| Allowed egress to `api.openai.com` | `P_agent(egress("api.openai.com"))` (Permission) |
| Required secret scan on write | `O_agent(scan_before_write)` (Obligation) |
| Merge monotonicity | `F_base(phi) => F_merge(base, child)(phi)` |
| Deny-wins aggregation | `F_agent(phi) AND P_agent(phi) => F_agent(phi)` |

See [Logos Integration](./logos-integration.md) for the full design.
