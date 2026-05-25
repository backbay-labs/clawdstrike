# Aeneas Pipeline: Rust-to-Lean 4 Verification for ClawdStrike

**Status**: Design
**Author**: Verification Engineering
**Date**: 2026-03-16
**Prerequisite**: [Landscape Survey](./landscape-survey.md), [Verification Targets](./verification-targets.md)

---

## 1. Aeneas Overview

[Aeneas](https://github.com/AeneasVerif/aeneas) translates safe Rust into theorem prover code via Charon (LLBC extraction from rustc) followed by codegen to Lean 4 / HOL4 / Coq / F*. Developed by Inria and Microsoft Research (ICFP 2022, 2024).

```
rustc -> Charon (~60-120s) -> LLBC -> Aeneas (~2-5s) -> Lean 4
```

**Key technique:** Mutable borrows become backward functions (`&mut T` -> `(T, T -> Result)`), eliminating the need for separation logic. Proofs use standard functional reasoning.

**Support and limitations** are detailed in the [Landscape Survey](./landscape-survey.md). In summary: Aeneas handles structs, enums, generics, traits, closures, `Vec`, `Option`, `Result`, pattern matching, and loops. It does NOT handle `unsafe`, `async`, interior mutability, `dyn Trait`, FFI, I/O, `Arc`/`Mutex`, serde derives, or complex iterator chains.

**Industrial precedent:** Microsoft SymCrypt ML-KEM (2024-2025), Amazon Cedar (same Lean 4 ecosystem), Eurydice (C extraction for HACL*).

---

## 2. ClawdStrike Verification Surface

The following targets are ranked by the intersection of security value and Aeneas feasibility. Rankings are based on actual codebase analysis of the files listed.

### Tier 1: HIGH VALUE + EXCELLENT Aeneas Fit

These are pure or near-pure functions with no async, no serde, no I/O, operating on owned/borrowed data with simple types.

| # | Target | File(s) | LOC | Properties to Prove | Estimated Effort |
|---|--------|---------|-----|---------------------|-----------------|
| 1 | Guard aggregation (`aggregate_overall`) | `crates/libs/clawdstrike/src/engine.rs:1785-1818` | ~34 | Deny monotonicity: if any `GuardResult` has `allowed: false`, output has `allowed: false`. Severity ordering preserved. Sanitize precedence among non-blocking ties. | 2-3 days |
| 2 | Severity ordering (`severity_ord`) | `crates/libs/clawdstrike/src/engine.rs:1699-1706` | ~8 | Total order: antisymmetric, transitive, total. `Info < Warning < Error < Critical`. | 1 day |
| 3 | Merkle tree construction + inclusion proofs | `crates/libs/hush-core/src/merkle.rs` | 360 | (a) `inclusion_proof(i).verify(leaf_i, root) = true` for all valid `i`. (b) RFC 6962 domain separation: `leaf_hash` uses `0x00` prefix, `node_hash` uses `0x01` prefix. (c) Tree height = `ceil(log2(n))`. (d) Root is deterministic given leaves. | 1-2 weeks |
| 4 | Canonical JSON (`canonicalize`) | `crates/libs/hush-core/src/canonical.rs` | 358 | (a) Determinism: `canonicalize(v) = canonicalize(v)`. (b) Key ordering: RFC 8785 UTF-16 code unit sort. (c) Idempotence: `parse(canonicalize(v))` round-trips. (d) Number normalization: `-0 -> 0`, scientific notation thresholds. | 1-2 weeks |
| 5 | Policy cycle detection | `crates/libs/clawdstrike/src/policy.rs:1420-1465` | ~45 | (a) Cyclic extends always returns `Err`. (b) Depth > 32 always returns `Err`. (c) Visited set grows monotonically. (d) Function terminates. | 3-5 days |

### Tier 2: HIGH VALUE + GOOD Aeneas Fit (Requires Extraction)

These functions are embeddable in pure code but currently interleaved with serde types, Option chains, and Vec operations that need minor restructuring.

| # | Target | File(s) | LOC | Properties to Prove | Estimated Effort |
|---|--------|---------|-----|---------------------|-----------------|
| 6 | GuardConfigs::merge_with | `crates/libs/clawdstrike/src/policy.rs:280-368` | ~90 | (a) Child `forbidden_path.additional_patterns` always appear in output. (b) Child `forbidden_path.remove_patterns` never appear in output. (c) Merge is deterministic. | 2-3 weeks |
| 7 | ForbiddenPathConfig::merge_with | `crates/libs/clawdstrike/src/guards/forbidden_path.rs:139-181` | ~43 | (a) Monotonicity: base patterns survive unless explicitly removed. (b) `remove_patterns` applied after `additional_patterns`. (c) Exception union: child exceptions always added. | 1-2 weeks |
| 8 | EgressAllowlistConfig::intersect_with | `crates/libs/clawdstrike/src/guards/egress_allowlist.rs:128-168` | ~41 | (a) Blocklists union: `output.block` is superset of both inputs. (b) Allowlists intersect: every domain in `output.allow` is in both inputs. (c) Stricter default wins: `Block > Log > Allow`. (d) Disabled side is identity. Also covers `merge_with` at lines 78-119 (~42 LOC) which handles additive/subtractive domain changes. | 2 weeks |
| 9 | Ed25519 signing interface contracts | `crates/libs/hush-core/src/signing.rs` | 336 | (a) Keypair::from_seed determinism. (b) PublicKey round-trip: `from_bytes(pk.as_bytes()) = Ok(pk)`. (c) Signature round-trip: `from_hex(sig.to_hex()) = Ok(sig)`. (d) Sign-verify round-trip: `pk.verify(msg, &kp.sign(msg)) = true` (axiomatic on ed25519-dalek). Note: `Keypair::sign` returns `Signature` directly (infallible), while `Signer::sign` returns `Result<Signature>`. | 1 week |
| 10 | Receipt signing coverage | `crates/libs/hush-core/src/receipt.rs:298-315` | ~18 | (a) `SignedReceipt::sign_with` calls `receipt.to_canonical_json()` then `signer.sign(canonical.as_bytes())`. (b) Verification succeeds iff the receipt content is unchanged. (c) Any field mutation invalidates the signature. The entry point `sign()` delegates to `sign_with()` at line 299. | 1 week |

### Tier 3: OUT OF SCOPE for Aeneas

These components cannot be translated by Aeneas due to fundamental feature blockers.

| Target | File | Blocker |
|--------|------|---------|
| `Guard` trait dispatch | `guards/mod.rs` | `#[async_trait]`, `dyn Trait` dispatch. The core module operates on `GuardResult` values (post-dispatch), not `Guard` trait objects. |
| Async guard runtime (cache, circuit breaker, retry) | `async_guards/*.rs` | `tokio`, `async_trait`, `Arc<Mutex>` |
| Engine check_action orchestration | `engine.rs:381-453` (check_action at 381, check_action_report at 435) | `async`, `Arc<RwLock<EngineState>>` |
| Crypto internals (ed25519-dalek, sha2, sha3) | External crates | `unsafe` blocks, assembly |
| Serde deserialization of Policy YAML | `policy.rs` | Serde macros, visitor pattern |
| WASM bindings | `hush-wasm/src/*.rs` | wasm-bindgen FFI |
| Origin context preparation | `engine.rs:455+` | `Arc<RwLock>`, async, complex state machine |
| Posture runtime evaluation | `engine.rs:1042+` | Mutable state, timestamps, budgets |
| Shell command regex matching | `guards/shell_command.rs` | `regex` crate internals, heuristic extraction |
| DomainPolicy evaluation | `hush-proxy/src/policy.rs` | Glob matching via external crate |

---

## 3. Architectural Refactoring Required

To make the verifiable core extractable by Charon/Aeneas, we need a clean separation between pure decision logic and the effectful runtime. The goal is a `core` module that Aeneas can consume without modification.

### Proposed Module Structure

```
crates/libs/clawdstrike/src/
├── core/                    <-- NEW: Aeneas-compatible pure module
│   ├── mod.rs                   Module root, re-exports
│   ├── verdict.rs               GuardResult, Severity, severity_ord (pure copies)
│   ├── aggregate.rs             aggregate_overall (pure, no async)
│   ├── merge.rs                 GuardConfigs merge logic (extracted from policy.rs)
│   ├── forbidden_path_merge.rs  ForbiddenPathConfig merge (extracted)
│   ├── egress_merge.rs          EgressAllowlistConfig merge + intersect (extracted)
│   └── cycle.rs                 Cycle detection logic (extracted from policy.rs)
├── guards/                  (existing, uses core::verdict)
├── engine.rs                (existing, calls core::aggregate)
├── policy.rs                (existing, delegates to core::merge, core::cycle)
└── ...
```

### Extraction Constraints

The `core/` module must satisfy ALL of the following invariants:

1. **No `async`**: No `async fn`, no `tokio`, no `Future`.
2. **No `serde`**: No `#[derive(Serialize, Deserialize)]`. Conversion between serde types and core types happens outside the module.
3. **No `Arc`, `Mutex`, `RwLock`**: No shared-state concurrency primitives.
4. **No `dyn Trait`**: Use enums or monomorphized generics. The current `Guard` trait is `dyn`-dispatched; the core module operates on `GuardResult` values, not `Guard` trait objects.
   - **Caveat**: `aggregate_overall` calls `r.is_sanitized()`, which inspects a `serde_json::Value` field (`details`). For the core module, replace this with a `bool` field `sanitized` on the core `GuardResult` type, with the conversion layer populating it from the serde value.
5. **No external crates with `unsafe`**: The module can depend on `std` (safe parts) but not on `regex`, `glob`, `serde_json`, `sha2`, etc. Any hashing is passed in as a function parameter or type parameter.
6. **No I/O**: No file reads, no network, no stdout. Pure transformations only.
7. **No `#[cfg(feature = ...)]`**: The core module compiles identically under all feature flags.

### Bridging Pattern

```rust
// In engine.rs (NOT verified):
use crate::core::aggregate::aggregate_overall as core_aggregate;

fn aggregate_overall(results: &[GuardResult]) -> GuardResult {
    // Convert runtime GuardResult -> core::GuardResult if types differ,
    // or use the same type if core re-exports it.
    core_aggregate(results)
}
```

```rust
// In core/aggregate.rs (VERIFIED via Aeneas):
use super::verdict::{GuardResult, Severity};

/// Aggregate guard results. Deny wins over allow.
/// The highest-severity blocking result is selected.
/// Among non-blocking results of equal severity, sanitize wins over plain warning.
pub fn aggregate_overall(results: &[GuardResult]) -> GuardResult {
    // ... pure implementation identical to current engine.rs:1785-1818
}
```

### Migration Strategy

1. **Phase 1**: Create `core/` module with copies of the pure functions. Both the original and the copy exist; the original delegates to the copy. All existing tests pass.
2. **Phase 2**: Run Charon on `core/` module. Fix any extraction failures by adjusting types (e.g., replacing `String` with `&str` where Aeneas prefers it).
3. **Phase 3**: Write Lean 4 theorems against the generated code. Proofs reference the extracted functions directly.
4. **Phase 4**: CI integration -- Charon extraction + Lean 4 proof checking runs on every PR that touches `core/`.

---

## 4. The Pipeline in Detail

### Step 1: Charon Extraction

```bash
# Install Charon (requires nightly Rust matching Charon's pinned toolchain)
cargo +nightly install --git https://github.com/AeneasVerif/charon charon

# Extract the core module to LLBC
# --preset=aeneas applies Aeneas-compatible lowering passes
cargo +nightly charon \
  --preset=aeneas \
  -p clawdstrike \
  --include clawdstrike::core \
  --dest formal/llbc/

# Output: formal/llbc/clawdstrike.llbc
```

**Expected issues and fixes:**

| Issue | Symptom | Fix |
|-------|---------|-----|
| `serde` in scope | Charon errors on derive macros | Ensure `core/` has no serde derives |
| `String::contains` | May not be in Aeneas primitives | Replace with manual char iteration or add to primitives |
| `Vec::retain` | Higher-order closure extraction | May need to rewrite as explicit loop |
| `HashSet` (cycle detection) | Aeneas HashMap/HashSet support is partial; `contains` + `insert` likely work but verify | Test early; fallback to sorted `Vec` + linear search |
| `div_ceil` | Stabilized in Rust 1.73 but Charon may not model it | Inline: `(n + d - 1) / d` (in merkle.rs, divisor is always 2: `(n + 1) / 2`) |
| `usize::is_multiple_of` | Used in merkle.rs; nightly/recent stabilization | Replace with `idx % 2 == 0` |

### Step 2: Aeneas Code Generation

```bash
# Install Aeneas
opam install aeneas  # or build from source

# Generate Lean 4 code
aeneas \
  --backend lean \
  --dest formal/lean4/ClawdStrike/ \
  formal/llbc/clawdstrike.llbc

# Output structure:
# formal/lean4/ClawdStrike/
#   Core/Verdict.lean
#   Core/Aggregate.lean
#   Core/Merge.lean
#   Core/Cycle.lean
#   ...
```

### Step 3: Lean 4 Proof Development

The generated Lean 4 code provides function definitions. Proofs are written in companion files.

**Example: Deny Monotonicity**

```lean
-- File: formal/lean4/ClawdStrike/Proofs/AggregateProps.lean

import ClawdStrike.Core.Aggregate
import ClawdStrike.Core.Verdict

open ClawdStrike.Core

/-- If any guard result in the input list has `allowed = false`,
    then the aggregated result also has `allowed = false`. -/
theorem deny_monotonicity
    (results : List GuardResult)
    (h_nonempty : results ≠ [])
    (h_exists_deny : ∃ r ∈ results, r.allowed = false) :
    (aggregate_overall results).allowed = false := by
  -- Proof by induction on the list, using the definition of
  -- aggregate_overall which iterates and selects blocking results.
  sorry -- placeholder: actual proof TBD

/-- Severity ordering is a total order. -/
theorem severity_ord_total_order :
    ∀ (a b : Severity),
      severity_ord a ≤ severity_ord b ∨ severity_ord b ≤ severity_ord a := by
  intro a b
  cases a <;> cases b <;> simp [severity_ord]

/-- severity_ord is injective (distinct constructors have distinct ordinals). -/
theorem severity_ord_injective :
    ∀ (a b : Severity), severity_ord a = severity_ord b → a = b := by
  intro a b
  cases a <;> cases b <;> simp [severity_ord]
```

**Example: Merkle Inclusion Proof Soundness**

```lean
-- File: formal/lean4/ClawdStrike/Proofs/MerkleProps.lean

import ClawdStrike.Core.Merkle

open ClawdStrike.Core.Merkle

/-- For a well-formed tree, the inclusion proof for index i
    verifies against the tree's root when given the original leaf. -/
theorem inclusion_proof_complete
    (leaves : List (List UInt8))
    (h_nonempty : leaves ≠ [])
    (tree : MerkleTree)
    (h_tree : tree = MerkleTree.from_leaves leaves)
    (i : Nat)
    (h_bound : i < leaves.length)
    (proof : MerkleProof)
    (h_proof : proof = tree.inclusion_proof i) :
    proof.verify (leaves.get ⟨i, h_bound⟩) tree.root = true := by
  sorry -- structural induction on tree levels

/-- RFC 6962 domain separation: leaf and node hashes use distinct prefixes,
    so no leaf hash can collide with a node hash (up to collision resistance). -/
theorem domain_separation
    (data : List UInt8) (left right : Hash) :
    leaf_hash data ≠ node_hash left right := by
  -- The first byte of the SHA-256 input differs (0x00 vs 0x01).
  -- Under collision resistance (axiomatized), distinct inputs ≠ equal outputs.
  sorry -- requires collision resistance axiom
```

**Example: Cycle Detection Termination**

```lean
/-- Cycle detection terminates: the visited set grows strictly on each recursive
    call, and the depth counter decreases to zero. -/
theorem cycle_detection_terminates
    (yaml : String) (resolver : PolicyResolver)
    (visited : HashSet String) (depth : Nat)
    (h_depth : depth ≤ 32) :
    from_yaml_with_extends_internal_resolver yaml resolver visited depth
      terminates := by
  -- Well-founded recursion on (32 - depth) with visited set as auxiliary measure.
  sorry

/-- If the extends chain contains a cycle, resolution returns Err. -/
theorem cycle_returns_err
    (yaml_chain : List (String × String))  -- (key, yaml) pairs
    (h_cycle : ∃ i j, i < j ∧ yaml_chain[i].1 = yaml_chain[j].1) :
    resolve_chain yaml_chain = Err "Circular policy extension detected" := by
  sorry
```

### Step 4: Leanstral-Assisted Proof Automation (Future)

Once the proof obligations are established, Leanstral can assist with discharging simpler proofs.

```
┌─────────────────────────────────────┐
│  lean-lsp-mcp agent loop            │
│                                     │
│  1. Read .lean file                 │
│  2. Identify `sorry` placeholders   │
│  3. Query Lean LSP for goal state   │
│  4. Propose tactic sequence         │
│  5. Check via Lean LSP diagnostics  │
│  6. If error: backtrack, retry      │
│  7. If success: write proof, next   │
└─────────────────────────────────────┘
```

**Realistic expectations for Leanstral:**

| Proof Category | Leanstral Success Rate | Notes |
|---------------|----------------------|-------|
| Simple case analysis (`cases a <;> simp`) | ~90% | Standard tactic patterns |
| List induction with library lemmas | ~70% | Needs access to Mathlib/Aeneas primitives |
| Numeric bounds (depth < 32) | ~60% | omega tactic usually works |
| Collision resistance arguments | ~10% | Requires domain-specific axioms |
| Complex merge invariants | ~20% | Multi-step induction with nested structures |

**Cost model:**

| Backend | Specification | Cost per Proof Attempt |
|---------|--------------|----------------------|
| RunPod (4x A100 80GB) | Self-hosted Leanstral | ~$4.76/hr, ~$0.08/attempt |
| Mistral API (pass@2) | Hosted | ~$18/attempt (128K context) |
| Human proof engineer | Manual | ~$200-400/hr |

Best strategy: Leanstral handles the simple proofs (severity ordering, case splits, basic induction). Human engineers handle merge invariants and crypto axioms.

---

## 5. Handling Crypto Axiomatically

The ed25519-dalek, sha2, and sha3 crates contain `unsafe` code and cannot be translated by Aeneas. We axiomatize their behavior at the boundary.

### Axiom Set

```lean
-- File: formal/lean4/ClawdStrike/Axioms/Crypto.lean

/-- SHA-256 is a deterministic function from byte sequences to 32-byte hashes. -/
axiom sha256_deterministic :
  ∀ (data : List UInt8), sha256 data = sha256 data

/-- SHA-256 is collision-resistant (computational assumption).
    We model this as: distinct inputs produce distinct outputs.
    This is an idealization; in practice, collision resistance is
    a computational hardness assumption, not an information-theoretic guarantee. -/
axiom sha256_collision_resistant :
  ∀ (a b : List UInt8), a ≠ b → sha256 a ≠ sha256 b

/-- Ed25519 sign-then-verify roundtrip. -/
axiom ed25519_verify_roundtrip :
  ∀ (key : Keypair) (msg : List UInt8),
    PublicKey.verify key.public_key msg (Keypair.sign key msg) = true

/-- Ed25519 signing is deterministic (Ed25519 is a deterministic scheme). -/
axiom ed25519_sign_deterministic :
  ∀ (key : Keypair) (msg : List UInt8),
    Keypair.sign key msg = Keypair.sign key msg

/-- Ed25519 unforgeability (computational assumption).
    Without the private key, no signature verifies. -/
axiom ed25519_unforgeable :
  ∀ (pk : PublicKey) (msg : List UInt8) (sig : Signature),
    PublicKey.verify pk msg sig = true →
    ∃ (key : Keypair), key.public_key = pk ∧ Keypair.sign key msg = sig
```

### What We Prove ABOUT Signing (Not OF Signing)

With these axioms, we can prove properties of ClawdStrike's signing layer without verifying ed25519-dalek itself:

```lean
/-- Receipt signature covers the canonical JSON content.
    If the receipt content changes, the signature no longer verifies. -/
theorem receipt_signature_covers_content :
  ∀ (receipt : Receipt) (key : Keypair),
    let signed := SignedReceipt.sign receipt key
    let canonical := Receipt.to_canonical_json receipt
    PublicKey.verify key.public_key canonical.toUTF8 signed.signatures.signer = true := by
  intro receipt key
  -- Follows directly from the definition of SignedReceipt.sign
  -- which calls to_canonical_json then Keypair.sign
  simp [SignedReceipt.sign, ed25519_verify_roundtrip]

/-- Mutation detection: changing any field of the receipt
    invalidates the signature (under collision resistance). -/
theorem mutation_detection :
  ∀ (r1 r2 : Receipt) (key : Keypair),
    r1 ≠ r2 →
    Receipt.to_canonical_json r1 ≠ Receipt.to_canonical_json r2 →
    let signed := SignedReceipt.sign r1 key
    PublicKey.verify key.public_key
      (Receipt.to_canonical_json r2).toUTF8
      signed.signatures.signer = false := by
  sorry -- requires canonicalize injectivity + collision resistance
```

### Axiom Soundness

These axioms are sound under standard cryptographic assumptions:

| Axiom | Underlying Assumption | Strength |
|-------|----------------------|----------|
| `sha256_deterministic` | Deterministic algorithm | Unconditional |
| `sha256_collision_resistant` | 2^128 work to find collision | Computational |
| `ed25519_verify_roundtrip` | Correctness of Ed25519 spec | Unconditional (given correct impl) |
| `ed25519_sign_deterministic` | RFC 8032 deterministic nonce | Unconditional |
| `ed25519_unforgeable` | Discrete log hardness on Curve25519 | Computational |

The collision resistance axiom is the strongest assumption. ClawdStrike's security already depends on SHA-256 collision resistance, so this does not expand the trust boundary.

---

## 6. Leanstral Integration

### Architecture

```
┌─────────────────────┐     ┌──────────────────────┐
│ Aeneas-generated    │     │ Human-written         │
│ Lean 4 definitions  │◄────│ proof obligations     │
│ (Core/*.lean)       │     │ (Proofs/*.lean)       │
└────────┬────────────┘     └──────────┬────────────┘
         │                             │
         v                             v
┌──────────────────────────────────────────────────┐
│ Lean 4 LSP Server                                │
│  - Type-checks definitions                       │
│  - Reports `sorry` goals                         │
│  - Validates tactic sequences                    │
└────────┬─────────────────────────────────────────┘
         │
         v
┌──────────────────────────────────────────────────┐
│ lean-lsp-mcp (MCP server)                        │
│  - Exposes Lean LSP as MCP tools                 │
│  - getGoalState, applyTactic, checkFile          │
└────────┬─────────────────────────────────────────┘
         │
         v
┌──────────────────────────────────────────────────┐
│ Leanstral Agent (or Claude with lean-lsp-mcp)    │
│  - Reads proof file                              │
│  - Identifies sorry placeholders                 │
│  - Iteratively proposes tactics                  │
│  - Checks diagnostics                            │
│  - Commits successful proofs                     │
└──────────────────────────────────────────────────┘
```

### MCP Agent Loop (Detailed)

```
for each sorry_location in proof_file:
    goal_state = lean_lsp.get_goal_state(sorry_location)

    for attempt in 1..max_attempts:
        tactics = leanstral.propose_tactics(goal_state, context)

        for tactic in tactics:
            result = lean_lsp.apply_tactic(sorry_location, tactic)

            if result.success:
                if result.remaining_goals == 0:
                    commit(tactic)
                    break
                else:
                    goal_state = result.new_goals
                    continue  # recurse on subgoals
            else:
                backtrack()

        if all_goals_discharged:
            break

    if not all_goals_discharged:
        mark_for_human_review(sorry_location, goal_state)
```

### Integration with CI

```yaml
# .github/workflows/verify.yml
name: Formal Verification
on:
  pull_request:
    paths: ['crates/libs/clawdstrike/src/core/**']

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust nightly + Charon
        run: |
          rustup install nightly-2026-03-01
          cargo +nightly-2026-03-01 install --git https://github.com/AeneasVerif/charon charon

      - name: Extract LLBC
        run: cargo +nightly-2026-03-01 charon --preset=aeneas -p clawdstrike --include clawdstrike::core

      - name: Install Aeneas + Lean 4
        run: |
          elan install leanprover/lean4:stable  # pin to specific version in lean-toolchain
          # Install aeneas binary

      - name: Generate Lean 4
        run: aeneas --backend lean --dest formal/lean4/ClawdStrike/ clawdstrike.llbc

      - name: Check proofs
        run: cd formal/lean4 && lake build
```

---

## 7. Risks and Mitigations

| # | Risk | Severity | Likelihood | Mitigation |
|---|------|----------|------------|------------|
| 1 | **Aeneas cannot handle ClawdStrike's Rust idioms** (e.g., `Vec::retain`, `HashSet`, `div_ceil`) | High | Medium | Extract pure core module early (Phase 1). Run Charon on it within the first week. Rewrite unsupported patterns before committing to proofs. |
| 2 | **Proof effort exceeds security value** | Medium | Medium | Start with `aggregate_overall` (2-3 days). If the full proof takes >1 week for this trivial function, re-evaluate the entire initiative. Set a 4-week timebox for Tier 1 targets. |
| 3 | **Aeneas breaking changes across versions** | Medium | High (Aeneas is pre-1.0) | Pin Charon and Aeneas to specific git commits. Regenerate Lean code on stable releases only. Keep generated code in version control for diffing. |
| 4 | **Generated Lean 4 code is unreadable** | Low | Low | Aeneas output is generally clean. Use `#[aeneas::rename]` annotations for custom names. Write a thin renaming script if needed. |
| 5 | **Lean 4 ecosystem version churn** | Medium | Medium | Pin `lean-toolchain` and `lakefile.lean`. Use `lake` package manager for reproducible builds. |
| 6 | **Core module extraction introduces bugs** | Medium | Low | Phase 1 requires all existing tests to pass through the delegating wrappers. Property tests (`proptest`) serve as additional safety net. Diff the extracted functions line-by-line against originals. |
| 7 | **Team lacks Lean 4 expertise** | High | High | Start with Leanstral/Claude-assisted proofs for simple cases. Budget for 2-4 weeks of Lean 4 ramp-up. Consider contracting a proof engineer for the first milestone. |
| 8 | **Axiomatized crypto is unsound** | Low | Very Low | Axioms mirror standard cryptographic assumptions (collision resistance, EUF-CMA). Clearly document axiom set. Review with cryptographer. |

---

## 8. Phased Execution Plan

### Phase 0: Feasibility Spike (1 week)

**Goal**: Confirm Aeneas can extract `aggregate_overall` and `severity_ord`.

1. Create `crates/libs/clawdstrike/src/core/` with `verdict.rs` and `aggregate.rs`.
2. Run Charon. Fix extraction errors.
3. Run Aeneas. Inspect generated Lean 4.
4. Write and prove `severity_ord_total_order` (should be trivial).
5. **Go/no-go decision** based on extraction quality and proof difficulty.

### Phase 1: Core Extraction + Tier 1 Proofs (4 weeks)

1. Extract all Tier 1 targets into `core/`.
2. Prove deny monotonicity, severity ordering, cycle detection termination.
3. Prove Merkle inclusion proof soundness.
4. Prove canonical JSON determinism and key ordering.
5. Set up CI pipeline.

### Phase 2: Tier 2 Proofs + Leanstral (6 weeks)

1. Extract merge logic into `core/`.
2. Prove merge monotonicity (forbidden path, egress).
3. Prove signing interface contracts (axiomatic).
4. Integrate Leanstral for automated proof attempts.
5. Document axiom set and proof assumptions.

### Phase 3: Continuous Verification (Ongoing)

1. Every PR touching `core/` triggers Charon + Lean 4 proof check.
2. New properties added as new guards are implemented.
3. Cross-language differential testing (Rust canonical JSON vs TS vs Python) complements formal proofs.

---

## 9. Relationship to Other Verification Paths

This document focuses on Aeneas (Rust -> Lean 4). See [Logos Integration](./logos-integration.md) for the complementary Z3 policy-level verification path and [Verification Targets](./verification-targets.md) for the master list of what to verify with which tool.

---

## Appendix A: File Inventory for Verification

| Source File | LOC | Aeneas Target | Status |
|------------|-----|---------------|--------|
| `crates/libs/clawdstrike/src/engine.rs` | 4623 | `aggregate_overall` (34 LOC, lines 1785-1818), `severity_ord` (8 LOC, lines 1699-1706) | Extract to `core/` |
| `crates/libs/clawdstrike/src/policy.rs` | 3735 | Cycle detection (45 LOC, lines 1420-1465), `GuardConfigs::merge_with` (89 LOC, lines 280-368) | Extract to `core/` |
| `crates/libs/clawdstrike/src/guards/forbidden_path.rs` | 547 | `ForbiddenPathConfig::merge_with` (43 LOC, lines 139-181) | Extract to `core/` |
| `crates/libs/clawdstrike/src/guards/egress_allowlist.rs` | 647 | `merge_with` (42 LOC, lines 78-119), `intersect_with` (41 LOC, lines 128-168) | Extract to `core/` |
| `crates/libs/hush-core/src/merkle.rs` | 360 (incl. ~108 LOC tests) | Non-test production code (~252 LOC, pure, no async) | Direct extraction |
| `crates/libs/hush-core/src/canonical.rs` | 358 | Entire file (pure, no async) | Direct extraction |
| `crates/libs/hush-core/src/signing.rs` | 336 | Interface contracts only (axiomatize crypto) | Partial extraction |
| `crates/libs/hush-core/src/receipt.rs` | 718 | `SignedReceipt::sign_with` (lines 303-315), `Receipt::to_canonical_json` (line 228) | Partial extraction |
| `crates/libs/hush-core/src/hashing.rs` | 231 | `Hash` type (axiomatize sha256/keccak256) | Type extraction only |

**Total verifiable LOC (Tier 1+2)**: ~620 LOC of pure logic, extracted from ~11,555 LOC of production code. Breakdown: ~302 LOC from clawdstrike decision logic (aggregate 35, severity_ord 8, cycle detection 45, GuardConfigs merge 89, ForbiddenPath merge 43, egress merge 42, egress intersect 41), ~250 LOC from hush-core merkle (non-test), ~50 LOC from canonical.rs core path, ~18 LOC from receipt signing path.
