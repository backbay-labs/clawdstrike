# Codex Handoff: Prove Remaining Sorry Stubs in ClawdStrike Lean 4 Spec

## Context

Lean 4 formal spec of ClawdStrike's policy engine. 39+ theorems proved; `Spec/Properties.lean` is complete. **20 remaining `sorry` goals** across 5 proof files, plus Aeneas-generated stubs under `Impl/` (do not edit). Builds cleanly with `lake build` (Lean 4.28.0-rc1 + Aeneas stdlib).

## Repository

```
/formal/lean4/ClawdStrike/
├── ClawdStrike/
│   ├── Core/           # Hand-written spec (types + functions)
│   │   ├── Verdict.lean    # Severity, GuardResult, Action, GuardConfigs, Policy
│   │   ├── Aggregate.lean  # worseResult, defaultResult, aggregateOverall (List.foldl)
│   │   ├── Merge.lean      # ForbiddenPathConfig.mergeWith, GuardConfigs.mergeWith, Policy.mergeWith
│   │   ├── Cycle.lean      # checkExtendsCycle, resolveChain (fuel-bounded)
│   │   ├── Eval.lean       # evalForbiddenPath, evalGuards (filterMap over 13 Option fields), evalPolicy
│   │   ├── Crypto.lean     # Ed25519 axioms
│   │   └── Receipt.lean    # SignedReceipt.sign, SignedReceipt.verify
│   ├── Impl/           # Aeneas-generated Lean from actual Rust (DO NOT EDIT)
│   │   ├── Types.lean
│   │   ├── Funs.lean       # severity_ord, aggregate_index, aggregate_overall, check_extends_cycle, etc.
│   │   ├── FunsExternal.lean
│   │   └── TypesExternal.lean
│   ├── Spec/
│   │   └── Properties.lean # DONE (0 sorry)
│   └── Proofs/
│       ├── DenyMonotonicity.lean     # DONE (0 sorry)
│       ├── SeverityOrder.lean        # DONE (0 sorry)
│       ├── AggregateProperties.lean  # DONE (0 sorry)
│       ├── CycleTermination.lean     # DONE (0 sorry)
│       ├── MergeMonotonicity.lean    # 1 sorry
│       ├── ReceiptSigning.lean       # DONE (0 sorry)
│       └── Impl/
│           ├── DenyMonotonicity_Impl.lean  # 4 sorry
│           ├── SpecImplEquiv.lean          # 6 sorry
│           └── CycleTermination_Impl.lean  # 2 sorry (but less important)
├── lakefile.lean   # Aeneas dependency from git
└── lean-toolchain  # leanprover/lean4:v4.16.0 (lake upgrades to 4.28.0-rc1)
```

## Status (2026-03-17)

`Spec/Properties.lean` complete. Three previously top-priority stubs resolved:

1. `forbidden_path_policy_soundness`
   - Proved by showing the denying forbidden-path result survives `evalGuards`' `filterMap`, then applying deny monotonicity in both fail-fast and non-fail-fast branches.
2. `forbidden_path_merge_includes_additions`
   - Proved by splitting on whether the added pattern was already present in the base effective patterns before the merge.
3. `merge_policy_idempotent`
   - Proved in a narrowed form over `Policy.Normalized`, with helper lemmas showing self-merge is identity for each normalized deep-merge guard config.

### Why P6 was narrowed instead of changing runtime semantics

The unrestricted theorem

```lean
theorem merge_policy_idempotent (policy : Policy) (action : Action) (ctx : Context) :
    evalPolicy (Policy.mergeWith policy policy) action ctx =
    evalPolicy policy action ctx := by
  ...
```

is false for the current spec and runtime semantics. A concrete counterexample is an `egressAllowlist` policy with `allow = []`, `defaultAction = some .block`, and `additionalAllow = ["good.com"]`: the standalone policy blocks `networkEgress "good.com" 443`, but self-merge materializes `additionalAllow` into `allow`, so the merged policy allows it.

The better ClawdStrike-aligned fix is to state idempotence on the normalized / resolved subset:

- `extends_ = none`
- deep-merge helper fields such as `additional_*` / `remove_*` have already been materialized into the explicit lists used at evaluation time

That matches the formal spec's intended "fully resolved policy" domain and avoids a behavior-changing runtime spec rewrite.

## Remaining Highest-Value Targets

- `ClawdStrike/Proofs/MergeMonotonicity.lean`: 1 remaining forbidden-path list-membership proof
- `ClawdStrike/Spec/MerkleProperties.lean`: 7 Merkle-tree spec proofs
- `ClawdStrike/Proofs/Impl/SpecImplEquiv.lean`: 6 spec/implementation bridge proofs
- `ClawdStrike/Proofs/Impl/DenyMonotonicity_Impl.lean`: 4 implementation deny-monotonicity proofs
- `ClawdStrike/Proofs/Impl/CycleTermination_Impl.lean`: 2 implementation cycle proofs

## The 12 Impl Bridge Sorry Stubs (Secondary Priority)

In `Proofs/Impl/`, bridging the spec to Aeneas-generated Rust translation. Blocked on axiomatized iterator/collection semantics in the Aeneas stdlib.

### SpecImplEquiv.lean (6 sorry)

The key theorem is `aggregate_overall_equiv`:
```lean
theorem aggregate_overall_equiv
    (results : Slice core.verdict.CoreVerdict)
    (impl_result : core.verdict.CoreVerdict)
    (h_ok : core.aggregate.aggregate_overall results = ok impl_result)
    (spec_results : List GuardResult)
    (h_corr : spec_results = results.val.map implVerdictToSpec) :
    impl_result.allowed = (aggregateOverall spec_results).allowed := by
  sorry
```

The Aeneas `aggregate_overall` (in `Impl/Funs.lean`) works by:
1. Calling `core.iter.IntoIterator` on the slice
2. Mapping each element to `(allowed, severity_ord, sanitized)` tuples
3. Running `aggregate_index_loop` which iterates and tracks the "worst" index
4. Returning the element at the winning index via `core.ops.index.Index`

The spec `aggregateOverall` is `List.foldl worseResult defaultResult`.

To prove equivalence, you need axioms about:
- `Slice.iter` producing the same elements as `.val`
- `.map` + `.collect` materializing correctly
- `aggregate_index_loop` selecting the same element as `foldl worseResult`

### DenyMonotonicity_Impl.lean (4 sorry)

Key theorem: if any input verdict has `allowed = false`, the Aeneas `aggregate_overall` output has `allowed = false`. Depends on `aggregate_overall_equiv` above.

### CycleTermination_Impl.lean (2 sorry)

Cycle detection correspondence between spec and impl. Less critical.

## Verified Proof Techniques That Work

From the completed proof files, these patterns succeed in this codebase:

```lean
-- Enum case analysis
cases a <;> cases b <;> simp [Severity.toNat]

-- List induction with foldl
induction results with
| nil => simp [aggregateOverall, defaultResult]
| cons x xs ih => simp [aggregateOverall, List.foldl]; exact ...

-- Unfolding + simp
unfold evalForbiddenPath
simp [h_enabled, h_match, h_no_exception, GuardResult.block]

-- Bool case split (Lean 4.28 compatible)
cases h : a.allowed <;> simp [h, worseResult]

-- Foldl accumulator propagation (key lemma pattern)
lemma foldl_preserves_property (acc : T) (xs : List T) (h : P acc) :
    P (xs.foldl f acc) := by
  induction xs generalizing acc with
  | nil => exact h
  | cons x xs ih => exact ih (step_preserves_P h)

-- List membership via filterMap
apply List.mem_filterMap.mpr
exact ⟨some result, ⟨List.mem_cons_self .., rfl⟩⟩
```

## Build & Verify

```bash
cd formal/lean4/ClawdStrike
lake build                                    # Full build (should succeed with sorry warnings)
lake env lean ClawdStrike/Spec/Properties.lean  # Check specific file
grep -rn "sorry" ClawdStrike/ --include="*.lean" | grep -v ".lake/" | grep -v "comment"
```

## Success Criteria

1. **Minimum:** Prove P4a (`forbidden_path_policy_soundness`). This is the most impactful — it connects guard-level soundness to end-to-end policy evaluation.
2. **Stretch:** Prove P5b and/or reduce Impl bridge sorry count.
3. **Don't break:** `lake build` must still succeed. Don't introduce new sorry or errors.
4. **Don't edit:** Files in `ClawdStrike/Impl/` (Aeneas-generated — must not be hand-modified).
