/-
  Merge monotonicity and idempotence proofs (P5, P6).
  Mirrors: core/merge.rs, guards/*.rs merge_with()
-/

import ClawdStrike.Core.Verdict
import ClawdStrike.Core.Merge
import ClawdStrike.Core.Eval
import ClawdStrike.Spec.Properties

set_option autoImplicit false

namespace ClawdStrike.Proofs

open ClawdStrike.Core

-- P5

theorem deepMerge_monotone (base child : PolicyRestriction) :
    PolicyRestriction.atLeastAsRestrictive
      (PolicyRestriction.deepMerge base child) base := by
  unfold PolicyRestriction.atLeastAsRestrictive
  unfold PolicyRestriction.deepMerge
  simp

theorem deepMerge_monotone_child (base child : PolicyRestriction) :
    PolicyRestriction.atLeastAsRestrictive
      (PolicyRestriction.deepMerge base child) child := by
  unfold PolicyRestriction.atLeastAsRestrictive
  unfold PolicyRestriction.deepMerge
  simp

theorem replace_not_monotone :
    ∃ (base child : PolicyRestriction),
      ¬ PolicyRestriction.atLeastAsRestrictive
          (PolicyRestriction.replaceMerge base child) base := by
  refine ⟨⟨10, false⟩, ⟨0, false⟩, ?_⟩
  unfold PolicyRestriction.atLeastAsRestrictive
  unfold PolicyRestriction.replaceMerge
  simp

theorem deepMerge_assoc_forbidden (a b c : PolicyRestriction) :
    (PolicyRestriction.deepMerge (PolicyRestriction.deepMerge a b) c).forbiddenCount =
    (PolicyRestriction.deepMerge a (PolicyRestriction.deepMerge b c)).forbiddenCount := by
  unfold PolicyRestriction.deepMerge
  simp
  omega

theorem deepMerge_comm_forbidden (a b : PolicyRestriction) :
    (PolicyRestriction.deepMerge a b).forbiddenCount =
    (PolicyRestriction.deepMerge b a).forbiddenCount := by
  unfold PolicyRestriction.deepMerge
  simp
  omega

theorem deepMerge_zero_child (base : PolicyRestriction) :
    (PolicyRestriction.deepMerge base ⟨0, false⟩).forbiddenCount =
    base.forbiddenCount := by
  unfold PolicyRestriction.deepMerge
  simp

theorem deepMerge_failFast_mono_left (base child : PolicyRestriction)
    (h : base.failFast = true) :
    (PolicyRestriction.deepMerge base child).failFast = true := by
  unfold PolicyRestriction.deepMerge
  simp [h]

theorem deepMerge_failFast_mono_right (base child : PolicyRestriction)
    (h : child.failFast = true) :
    (PolicyRestriction.deepMerge base child).failFast = true := by
  unfold PolicyRestriction.deepMerge
  simp [h]

-- P6

theorem childOverrides_idempotent {α : Type} (x : Option α) :
    childOverrides x x = x := by
  unfold childOverrides
  cases x with
  | none => rfl
  | some _ => rfl

theorem childOverrides_some {α : Type} (base : Option α) (c : α) :
    childOverrides base (some c) = some c := by
  unfold childOverrides
  rfl

theorem childOverrides_none {α : Type} (base : Option α) :
    childOverrides base none = base := by
  unfold childOverrides
  rfl

theorem childOverridesStr_nonempty (base child : String) (h : ¬child.isEmpty) :
    childOverridesStr base child = child := by
  unfold childOverridesStr
  simp [h]

theorem childOverridesStr_empty (base : String) :
    childOverridesStr base "" = base := by
  unfold childOverridesStr
  simp [String.isEmpty]

-- P5a

theorem merged_effective_patterns_eq (cfg : ForbiddenPathConfig)
    (ps : List GlobPattern)
    (h_patterns : cfg.patterns = some ps)
    (h_no_additional : cfg.additionalPatterns = [])
    (h_no_remove : cfg.removePatterns = []) :
    cfg.effectivePatterns = ps := by
  unfold ForbiddenPathConfig.effectivePatterns
  simp [h_patterns, h_no_additional, h_no_remove]

theorem forbidden_path_merge_preserves_base (base child : ForbiddenPathConfig)
    (p : GlobPattern)
    (h_in_base : p ∈ base.effectivePatterns)
    (h_not_removed : ¬(p ∈ child.removePatterns)) :
    p ∈ (ForbiddenPathConfig.mergeWith base child).effectivePatterns := by
  unfold ForbiddenPathConfig.mergeWith
  unfold ForbiddenPathConfig.effectivePatterns
  simp
  sorry  -- requires detailed list membership reasoning through filter/append

-- P5b

theorem forbidden_path_merge_includes_additions (base child : ForbiddenPathConfig)
    (p : GlobPattern)
    (h_in_additional : p ∈ child.additionalPatterns)
    (h_not_removed : ¬(p ∈ child.removePatterns))
    (h_child_no_explicit : child.patterns = none) :
    p ∈ (ForbiddenPathConfig.mergeWith base child).effectivePatterns := by
  unfold ForbiddenPathConfig.mergeWith
  unfold ForbiddenPathConfig.effectivePatterns
  simp [h_child_no_explicit]
  by_cases hp : p ∈ (match base.patterns with | some ps => ps | none => defaultForbiddenPatterns)
  · by_cases hr : p ∈ base.removePatterns
    · right; right
      exact ⟨h_in_additional, h_not_removed, Or.inr hr, Or.inr (Or.inl hr)⟩
    · left
      exact ⟨hp, h_not_removed, hr⟩
  · by_cases ha : p ∈ base.additionalPatterns
    · by_cases hr : p ∈ base.removePatterns
      · right; right
        exact ⟨h_in_additional, h_not_removed, Or.inl hp, Or.inr (Or.inl hr)⟩
      · right; left
        exact ⟨ha, h_not_removed, hr, hp⟩
    · right; right
      exact ⟨h_in_additional, h_not_removed, Or.inl hp, Or.inl ha⟩

-- GuardConfigs merge preserves existing guards

theorem guardConfigs_merge_preserves_forbidden_path (base child : GuardConfigs)
    (cfg : ForbiddenPathConfig)
    (h_base : base.forbiddenPath = some cfg)
    (h_child_none : child.forbiddenPath = none) :
    (GuardConfigs.mergeWith base child).forbiddenPath = some cfg := by
  unfold GuardConfigs.mergeWith
  simp [h_base, h_child_none]

theorem guardConfigs_merge_preserves_egress (base child : GuardConfigs)
    (cfg : EgressAllowlistConfig)
    (h_base : base.egressAllowlist = some cfg)
    (h_child_none : child.egressAllowlist = none) :
    (GuardConfigs.mergeWith base child).egressAllowlist = some cfg := by
  unfold GuardConfigs.mergeWith
  simp [h_base, h_child_none]

theorem guardConfigs_merge_childOverrides_preserves (base child : GuardConfigs)
    (h : child.patchIntegrity = none) :
    (GuardConfigs.mergeWith base child).patchIntegrity = base.patchIntegrity := by
  unfold GuardConfigs.mergeWith
  simp [childOverrides_none, h]

end ClawdStrike.Proofs
