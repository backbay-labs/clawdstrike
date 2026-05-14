/-
  Core property statements P1-P13.
  Property numbering follows docs/plans/clawdstrike/formal-verification/policy-specification.md.
-/

import ClawdStrike.Core.Verdict
import ClawdStrike.Core.Aggregate
import ClawdStrike.Core.Merge
import ClawdStrike.Core.Cycle
import ClawdStrike.Core.Eval

set_option autoImplicit false

namespace ClawdStrike.Spec

open ClawdStrike.Core

-- Helper lemmas (needed locally since we don't import Proofs/)

private theorem foldl_worseResult_deny (acc : GuardResult) (xs : List GuardResult)
    (h : acc.allowed = false) :
    (xs.foldl worseResult acc).allowed = false := by
  induction xs generalizing acc with
  | nil => exact h
  | cons x xs ih =>
    simp only [List.foldl]
    apply ih
    unfold worseResult
    simp only [h]
    cases hc : x.allowed
    · simp; split <;> simp_all
    · simp; exact h

private theorem worseResult_preserves_deny_right' (a b : GuardResult)
    (h : b.allowed = false) :
    (worseResult a b).allowed = false := by
  unfold worseResult
  simp only [h]
  cases hb : a.allowed
  · simp; split <;> simp_all
  · simp; exact h

private theorem foldl_worseResult_deny_mem (acc : GuardResult) (xs : List GuardResult)
    (r : GuardResult) (h_mem : r ∈ xs) (h_deny : r.allowed = false) :
    (xs.foldl worseResult acc).allowed = false := by
  induction xs generalizing acc with
  | nil => simp at h_mem
  | cons _ ys ih =>
    simp only [List.foldl]
    cases h_mem with
    | head =>
      exact foldl_worseResult_deny _ ys
        (worseResult_preserves_deny_right' acc _ h_deny)
    | tail _ h_tail =>
      exact ih _ h_tail

/-- P1: Deny Monotonicity -/
theorem deny_monotonicity (results : List GuardResult) (r : GuardResult)
    (h_mem : r ∈ results) (h_deny : r.allowed = false) :
    (aggregateOverall results).allowed = false := by
  unfold aggregateOverall
  exact foldl_worseResult_deny_mem defaultResult results r h_mem h_deny

/-- P1a: worseResult preserves denial from the left. -/
theorem worseResult_preserves_deny_left (a b : GuardResult)
    (h : a.allowed = false) :
    (worseResult a b).allowed = false := by
  unfold worseResult
  simp only [h]
  cases hc : b.allowed
  · simp; split <;> simp_all
  · simp; exact h

/-- P1b: worseResult preserves denial from the right. -/
theorem worseResult_preserves_deny_right (a b : GuardResult)
    (h : b.allowed = false) :
    (worseResult a b).allowed = false := by
  unfold worseResult
  simp only [h]
  cases hb : a.allowed
  · simp; split <;> simp_all
  · simp; exact h

/-- P1c: worseResult preserves denial from either side. -/
theorem worseResult_preserves_deny (a b : GuardResult)
    (h : a.allowed = false ∨ b.allowed = false) :
    (worseResult a b).allowed = false := by
  cases h with
  | inl ha => exact worseResult_preserves_deny_left a b ha
  | inr hb => exact worseResult_preserves_deny_right a b hb

/-- P2: Allow Requires Unanimity (contrapositive of P1). -/
theorem allow_requires_unanimity (results : List GuardResult)
    (h_allow : (aggregateOverall results).allowed = true)
    (r : GuardResult) (h_mem : r ∈ results) :
    r.allowed = true := by
  cases hr : r.allowed with
  | false =>
    have h_agg_deny := deny_monotonicity results r h_mem hr
    simp [h_agg_deny] at h_allow
  | true => rfl

/-- P3: Severity Total Order -/
theorem severity_total_order (a b : Severity) :
    a ≤ b ∨ b ≤ a := by
  show a.toNat ≤ b.toNat ∨ b.toNat ≤ a.toNat
  exact Nat.le_total a.toNat b.toNat

/-- P3a: Transitivity. -/
theorem severity_le_trans (a b c : Severity)
    (h1 : a ≤ b) (h2 : b ≤ c) : a ≤ c := by
  show a.toNat ≤ c.toNat
  exact Nat.le_trans h1 h2

/-- P3b: Antisymmetry. -/
theorem severity_le_antisymm (a b : Severity)
    (h1 : a ≤ b) (h2 : b ≤ a) : a = b := by
  have h_eq : a.toNat = b.toNat := Nat.le_antisymm h1 h2
  exact Severity.toNat_injective a b h_eq

/-- P3c: toNat is injective. -/
theorem severity_toNat_injective (a b : Severity)
    (h : a.toNat = b.toNat) : a = b := by
  cases a <;> cases b <;> simp [Severity.toNat] at h <;> rfl

/-- P4: Forbidden Path Soundness -/
theorem forbidden_path_guard_soundness (cfg : ForbiddenPathConfig) (path : Path)
    (ctx : Context)
    (h_enabled : cfg.enabled = true)
    (h_match : matchesAny cfg.effectivePatterns path = true)
    (h_no_exception : matchesAny cfg.exceptions path = false) :
    (evalForbiddenPath cfg (.fileAccess path) ctx).allowed = false := by
  unfold evalForbiddenPath
  simp [h_enabled, h_match, h_no_exception, GuardResult.block]

/-- P4a: Forbidden Path Soundness (end-to-end via policy evaluation). -/
theorem forbidden_path_policy_soundness (policy : Policy) (path : Path)
    (ctx : Context) (cfg : ForbiddenPathConfig)
    (h_guard : policy.guards.forbiddenPath = some cfg)
    (h_enabled : cfg.enabled = true)
    (h_match : matchesAny cfg.effectivePatterns path = true)
    (h_no_exception : matchesAny cfg.exceptions path = false)
    (h_no_error : hasConfigError policy = false) :
    ∃ (result : GuardResult),
      evalPolicy policy (.fileAccess path) ctx = .ok result ∧
      result.allowed = false := by
  have h_guard_deny :
      (evalForbiddenPath cfg (.fileAccess path) ctx).allowed = false :=
    forbidden_path_guard_soundness cfg path ctx h_enabled h_match h_no_exception
  have h_mem_guard :
      evalForbiddenPath cfg (.fileAccess path) ctx ∈
        evalGuards policy.guards (.fileAccess path) ctx := by
    unfold evalGuards
    apply List.mem_filterMap.mpr
    refine ⟨some (evalForbiddenPath cfg (.fileAccess path) ctx), ?_⟩
    refine ⟨?_, rfl⟩
    simp [h_guard]
  have h_find_isSome :
      ((evalGuards policy.guards (.fileAccess path) ctx).find? (fun r => !r.allowed)).isSome := by
    apply List.find?_isSome.2
    refine ⟨evalForbiddenPath cfg (.fileAccess path) ctx, h_mem_guard, ?_⟩
    simp [h_guard_deny]
  let firstDeny :=
    ((evalGuards policy.guards (.fileAccess path) ctx).find? (fun r => !r.allowed)).get
      h_find_isSome
  have h_find :
      (evalGuards policy.guards (.fileAccess path) ctx).find? (fun r => !r.allowed) =
        some firstDeny := by
    rw [Option.eq_some_iff_get_eq]
    exact ⟨h_find_isSome, rfl⟩
  have h_first_deny : firstDeny.allowed = false := by
    have h := List.find?_some h_find
    simpa [firstDeny] using h
  by_cases h_fail_fast : policy.settings.effectiveFailFast
  · refine ⟨aggregateOverall [firstDeny], ?_, ?_⟩
    · unfold evalPolicy
      simp [h_no_error, h_fail_fast, h_find]
    · exact deny_monotonicity [firstDeny] firstDeny (by simp) h_first_deny
  · refine ⟨aggregateOverall (evalGuards policy.guards (.fileAccess path) ctx), ?_, ?_⟩
    · unfold evalPolicy
      simp [h_no_error, h_fail_fast]
    · exact deny_monotonicity _ _ h_mem_guard h_guard_deny

/-- P5: Inheritance Restrictiveness (abstract model). -/
theorem deepMerge_monotone (base child : PolicyRestriction) :
    PolicyRestriction.atLeastAsRestrictive
      (PolicyRestriction.deepMerge base child) base := by
  unfold PolicyRestriction.atLeastAsRestrictive PolicyRestriction.deepMerge
  simp

private noncomputable def cleanFPConfig (en : Bool) (ps : List GlobPattern) (exns : List GlobPattern) : ForbiddenPathConfig :=
  { enabled := en, patterns := some ps, exceptions := exns,
    additionalPatterns := [], removePatterns := [] }

private theorem effectivePatterns_clean (en : Bool) (ps : List GlobPattern) (exns : List GlobPattern) :
    (cleanFPConfig en ps exns).effectivePatterns = ps := by
  unfold cleanFPConfig ForbiddenPathConfig.effectivePatterns
  simp only [List.filter_nil, List.append_nil]
  induction ps with
  | nil => rfl
  | cons x xs ih =>
    simp only [List.filter, List.contains]
    exact congrArg (x :: ·) ih

private noncomputable def mergedFinalPatterns (base child : ForbiddenPathConfig) : List GlobPattern :=
  let startPatterns := base.effectivePatterns
  let withAdditions := startPatterns ++ child.additionalPatterns.filter
    (fun p => !startPatterns.contains p)
  withAdditions.filter (fun p => !child.removePatterns.contains p)

private theorem mergeWith_clean (base child : ForbiddenPathConfig)
    (h : child.patterns = none) :
    ForbiddenPathConfig.mergeWith base child =
    cleanFPConfig child.enabled (mergedFinalPatterns base child)
      (base.exceptions ++ child.exceptions.filter (fun e => !base.exceptions.contains e)) := by
  unfold ForbiddenPathConfig.mergeWith mergedFinalPatterns cleanFPConfig
  simp [h]

private theorem not_mem_contains_false (xs : List String) (p : String) (h : ¬(p ∈ xs)) :
    xs.contains p = false := by
  cases hc : xs.contains p
  · rfl
  · exact absurd (List.contains_iff_mem.mp hc) h

/-- P5a: ForbiddenPath merge preserves base patterns (when child.patterns = none). -/
theorem forbidden_path_merge_preserves_base (base child : ForbiddenPathConfig)
    (p : GlobPattern)
    (h_in_base : p ∈ base.effectivePatterns)
    (h_not_removed : ¬ (p ∈ child.removePatterns))
    (h_child_no_explicit : child.patterns = none) :
    p ∈ (ForbiddenPathConfig.mergeWith base child).effectivePatterns := by
  rw [mergeWith_clean base child h_child_no_explicit]
  rw [effectivePatterns_clean]
  unfold mergedFinalPatterns
  apply List.mem_filter.mpr
  refine ⟨List.mem_append_left _ h_in_base, ?_⟩
  rw [Bool.not_eq_true', not_mem_contains_false child.removePatterns p h_not_removed]

/-- P5b: ForbiddenPath merge includes child additions. -/
theorem forbidden_path_merge_includes_additions (base child : ForbiddenPathConfig)
    (p : GlobPattern)
    (h_in_additional : p ∈ child.additionalPatterns)
    (h_not_removed : ¬ (p ∈ child.removePatterns))
    (h_child_no_explicit : child.patterns = none) :
    p ∈ (ForbiddenPathConfig.mergeWith base child).effectivePatterns := by
  rw [mergeWith_clean base child h_child_no_explicit]
  rw [effectivePatterns_clean]
  unfold mergedFinalPatterns
  by_cases h_in_base : p ∈ base.effectivePatterns
  · apply List.mem_filter.mpr
    refine ⟨List.mem_append.mpr (Or.inl h_in_base), ?_⟩
    rw [Bool.not_eq_true', not_mem_contains_false child.removePatterns p h_not_removed]
  · apply List.mem_filter.mpr
    refine ⟨List.mem_append.mpr (Or.inr ?_), ?_⟩
    · apply List.mem_filter.mpr
      refine ⟨h_in_additional, ?_⟩
      rw [Bool.not_eq_true', not_mem_contains_false base.effectivePatterns p h_in_base]
    · rw [Bool.not_eq_true', not_mem_contains_false child.removePatterns p h_not_removed]

-- Normalization invariants for merge idempotence

/-- Additive/removal helpers materialized into explicit patterns. -/
def ForbiddenPathConfig.Normalized (cfg : ForbiddenPathConfig) : Prop :=
  ∃ ps, cfg.patterns = some ps ∧ cfg.additionalPatterns = [] ∧ cfg.removePatterns = []

def EgressAllowlistConfig.Normalized (cfg : EgressAllowlistConfig) : Prop :=
  cfg.additionalAllow = [] ∧
  cfg.removeAllow = [] ∧
  cfg.additionalBlock = [] ∧
  cfg.removeBlock = []

def SecretLeakConfig.Normalized (cfg : SecretLeakConfig) : Prop :=
  cfg.additionalPatterns = [] ∧ cfg.removePatterns = []

def McpToolConfig.Normalized (cfg : McpToolConfig) : Prop :=
  cfg.additionalAllow = [] ∧
  cfg.removeAllow = [] ∧
  cfg.additionalBlock = [] ∧
  cfg.removeBlock = []

def GuardConfigs.Normalized (cfg : GuardConfigs) : Prop :=
  (∀ fp, cfg.forbiddenPath = some fp → ForbiddenPathConfig.Normalized fp) ∧
  (∀ eg, cfg.egressAllowlist = some eg → EgressAllowlistConfig.Normalized eg) ∧
  (∀ sl, cfg.secretLeak = some sl → SecretLeakConfig.Normalized sl) ∧
  (∀ mcp, cfg.mcpTool = some mcp → McpToolConfig.Normalized mcp)

def Policy.Normalized (policy : Policy) : Prop :=
  policy.extends_ = none ∧ GuardConfigs.Normalized policy.guards

private theorem filter_not_mem_self (xs : List String) :
    xs.filter (fun x => !decide (x ∈ xs)) = [] := by
  apply List.eq_nil_iff_forall_not_mem.mpr
  intro y hy
  rcases List.mem_filter.mp hy with ⟨hy_xs, h_keep⟩
  simp [hy_xs] at h_keep

private theorem forbidden_path_mergeWith_self_of_normalized (cfg : ForbiddenPathConfig)
    (h_norm : ForbiddenPathConfig.Normalized cfg) :
    ForbiddenPathConfig.mergeWith cfg cfg = cfg := by
  rcases h_norm with ⟨ps, h_patterns, h_additional, h_remove⟩
  cases cfg with
  | mk enabled patterns exceptions additionalPatterns removePatterns =>
    have h_patterns' : patterns = some ps := by simpa using h_patterns
    have h_additional' : additionalPatterns = [] := by simpa using h_additional
    have h_remove' : removePatterns = [] := by simpa using h_remove
    unfold ForbiddenPathConfig.mergeWith
    simp [h_patterns', h_additional', h_remove', filter_not_mem_self]

private theorem path_allowlist_mergeWith_self (cfg : PathAllowlistConfig) :
    PathAllowlistConfig.mergeWith cfg cfg = cfg := by
  unfold PathAllowlistConfig.mergeWith
  simp

private theorem egress_allowlist_mergeWith_self_of_normalized (cfg : EgressAllowlistConfig)
    (h_norm : EgressAllowlistConfig.Normalized cfg) :
    EgressAllowlistConfig.mergeWith cfg cfg = cfg := by
  rcases h_norm with ⟨h_additional_allow, h_remove_allow, h_additional_block, h_remove_block⟩
  cases cfg with
  | mk enabled allow block defaultAction additionalAllow removeAllow additionalBlock removeBlock =>
    simp at h_additional_allow h_remove_allow h_additional_block h_remove_block
    unfold EgressAllowlistConfig.mergeWith
    cases defaultAction <;>
      simp [h_additional_allow, h_remove_allow, h_additional_block, h_remove_block]

private theorem secret_leak_mergeWith_self_of_normalized (cfg : SecretLeakConfig)
    (h_norm : SecretLeakConfig.Normalized cfg) :
    SecretLeakConfig.mergeWith cfg cfg = cfg := by
  rcases h_norm with ⟨h_additional, h_remove⟩
  cases cfg
  rename_i enabled patterns additionalPatterns removePatterns skipPaths
  simp at h_additional h_remove
  unfold SecretLeakConfig.mergeWith
  simp [h_additional, h_remove]

private theorem mcp_tool_mergeWith_self_of_normalized (cfg : McpToolConfig)
    (h_norm : McpToolConfig.Normalized cfg) :
    McpToolConfig.mergeWith cfg cfg = cfg := by
  rcases h_norm with ⟨h_additional_allow, h_remove_allow, h_additional_block, h_remove_block⟩
  cases cfg with
  | mk enabled allow block requireConfirmation defaultAction maxArgsSize
      additionalAllow removeAllow additionalBlock removeBlock =>
    simp at h_additional_allow h_remove_allow h_additional_block h_remove_block
    unfold McpToolConfig.mergeWith
    cases defaultAction <;> cases maxArgsSize <;>
      simp [h_additional_allow, h_remove_allow, h_additional_block, h_remove_block]

private theorem forbidden_path_field_mergeWith_self_of_normalized (cfg : GuardConfigs)
    (h_norm : GuardConfigs.Normalized cfg) :
    (match cfg.forbiddenPath with
     | some fp => some (ForbiddenPathConfig.mergeWith fp fp)
     | none => none) = cfg.forbiddenPath := by
  cases h_fp : cfg.forbiddenPath with
  | none =>
    simp
  | some fp =>
    have h_fp_norm : ForbiddenPathConfig.Normalized fp := h_norm.1 fp h_fp
    simp [forbidden_path_mergeWith_self_of_normalized fp h_fp_norm]

private theorem egress_allowlist_field_mergeWith_self_of_normalized (cfg : GuardConfigs)
    (h_norm : GuardConfigs.Normalized cfg) :
    (match cfg.egressAllowlist with
     | some eg => some (EgressAllowlistConfig.mergeWith eg eg)
     | none => none) = cfg.egressAllowlist := by
  cases h_eg : cfg.egressAllowlist with
  | none =>
    simp
  | some eg =>
    have h_eg_norm : EgressAllowlistConfig.Normalized eg := h_norm.2.1 eg h_eg
    simp [egress_allowlist_mergeWith_self_of_normalized eg h_eg_norm]

private theorem secret_leak_field_mergeWith_self_of_normalized (cfg : GuardConfigs)
    (h_norm : GuardConfigs.Normalized cfg) :
    (match cfg.secretLeak with
     | some sl => some (SecretLeakConfig.mergeWith sl sl)
     | none => none) = cfg.secretLeak := by
  cases h_sl : cfg.secretLeak with
  | none =>
    simp
  | some sl =>
    have h_sl_norm : SecretLeakConfig.Normalized sl := h_norm.2.2.1 sl h_sl
    simp [secret_leak_mergeWith_self_of_normalized sl h_sl_norm]

private theorem mcp_tool_field_mergeWith_self_of_normalized (cfg : GuardConfigs)
    (h_norm : GuardConfigs.Normalized cfg) :
    (match cfg.mcpTool with
     | some mcp => some (McpToolConfig.mergeWith mcp mcp)
     | none => none) = cfg.mcpTool := by
  cases h_mcp : cfg.mcpTool with
  | none =>
    simp
  | some mcp =>
    have h_mcp_norm : McpToolConfig.Normalized mcp := h_norm.2.2.2 mcp h_mcp
    simp [mcp_tool_mergeWith_self_of_normalized mcp h_mcp_norm]

private theorem guardConfigs_eq_of_fields (a b : GuardConfigs)
    (h_forbiddenPath : a.forbiddenPath = b.forbiddenPath)
    (h_pathAllowlist : a.pathAllowlist = b.pathAllowlist)
    (h_egressAllowlist : a.egressAllowlist = b.egressAllowlist)
    (h_secretLeak : a.secretLeak = b.secretLeak)
    (h_patchIntegrity : a.patchIntegrity = b.patchIntegrity)
    (h_shellCommand : a.shellCommand = b.shellCommand)
    (h_mcpTool : a.mcpTool = b.mcpTool)
    (h_promptInjection : a.promptInjection = b.promptInjection)
    (h_jailbreak : a.jailbreak = b.jailbreak)
    (h_computerUse : a.computerUse = b.computerUse)
    (h_remoteDesktop : a.remoteDesktopSideChannel = b.remoteDesktopSideChannel)
    (h_inputInjection : a.inputInjectionCapability = b.inputInjectionCapability)
    (h_spiderSense : a.spiderSense = b.spiderSense) :
    a = b := by
  cases a <;> cases b <;> simp_all

private theorem guardConfigs_mergeWith_self_of_normalized (cfg : GuardConfigs)
    (h_norm : GuardConfigs.Normalized cfg) :
    GuardConfigs.mergeWith cfg cfg = cfg := by
  apply guardConfigs_eq_of_fields
  · cases h_fp : cfg.forbiddenPath with
    | none =>
      simp [GuardConfigs.mergeWith, h_fp]
    | some fp =>
      have h_fp_norm : ForbiddenPathConfig.Normalized fp := h_norm.1 fp h_fp
      simp [GuardConfigs.mergeWith, h_fp, forbidden_path_mergeWith_self_of_normalized fp h_fp_norm]
  · cases h_path : cfg.pathAllowlist <;> simp [GuardConfigs.mergeWith, PathAllowlistConfig.mergeWith, h_path]
  · cases h_eg : cfg.egressAllowlist with
    | none =>
      simp [GuardConfigs.mergeWith, h_eg]
    | some eg =>
      have h_eg_norm : EgressAllowlistConfig.Normalized eg := h_norm.2.1 eg h_eg
      simp [GuardConfigs.mergeWith, h_eg, egress_allowlist_mergeWith_self_of_normalized eg h_eg_norm]
  · cases h_sl : cfg.secretLeak with
    | none =>
      simp [GuardConfigs.mergeWith, h_sl]
    | some sl =>
      have h_sl_norm : SecretLeakConfig.Normalized sl := h_norm.2.2.1 sl h_sl
      simp [GuardConfigs.mergeWith, h_sl, secret_leak_mergeWith_self_of_normalized sl h_sl_norm]
  · cases h_patch : cfg.patchIntegrity <;> simp [GuardConfigs.mergeWith, childOverrides, h_patch]
  · cases h_shell : cfg.shellCommand <;> simp [GuardConfigs.mergeWith, childOverrides, h_shell]
  · cases h_mcp : cfg.mcpTool with
    | none =>
      simp [GuardConfigs.mergeWith, h_mcp]
    | some mcp =>
      have h_mcp_norm : McpToolConfig.Normalized mcp := h_norm.2.2.2 mcp h_mcp
      simp [GuardConfigs.mergeWith, h_mcp, mcp_tool_mergeWith_self_of_normalized mcp h_mcp_norm]
  · cases h_prompt : cfg.promptInjection <;> simp [GuardConfigs.mergeWith, childOverrides, h_prompt]
  · cases h_jb : cfg.jailbreak <;> simp [GuardConfigs.mergeWith, childOverrides, h_jb]
  · cases h_cu : cfg.computerUse <;> simp [GuardConfigs.mergeWith, childOverrides, h_cu]
  · cases h_rd : cfg.remoteDesktopSideChannel <;> simp [GuardConfigs.mergeWith, childOverrides, h_rd]
  · cases h_ii : cfg.inputInjectionCapability <;> simp [GuardConfigs.mergeWith, childOverrides, h_ii]
  · cases h_ss : cfg.spiderSense <;> simp [GuardConfigs.mergeWith, childOverrides, h_ss]

private theorem policy_mergeWith_self_of_normalized (policy : Policy)
    (h_norm : Policy.Normalized policy) :
    Policy.mergeWith policy policy = policy := by
  cases policy with
  | mk version name description extends_ mergeStrategy guards settings =>
    have h_extends : extends_ = none := h_norm.1
    have h_guards : GuardConfigs.mergeWith guards guards = guards :=
      guardConfigs_mergeWith_self_of_normalized guards h_norm.2
    cases h_extends
    simp [Policy.mergeWith, h_guards]

/-- P6: Merge Idempotence (childOverrides). -/
theorem childOverrides_idempotent {α : Type} (x : Option α) :
    childOverrides x x = x := by
  unfold childOverrides
  cases x <;> rfl

/-- P6a: Merge Idempotence (full policy, requires normalization). -/
theorem merge_policy_idempotent (policy : Policy) (action : Action) (ctx : Context)
    (h_norm : Policy.Normalized policy) :
    evalPolicy (Policy.mergeWith policy policy) action ctx =
    evalPolicy policy action ctx := by
  rw [policy_mergeWith_self_of_normalized policy h_norm]

/-- P7: Aggregate determinism (trivial for pure functions). -/
theorem aggregate_deterministic (results : List GuardResult) :
    aggregateOverall results = aggregateOverall results := by
  rfl

/-- P7a: worseResult is idempotent on allowed status. -/
theorem worseResult_idempotent_allowed (a : GuardResult) :
    (worseResult a a).allowed = a.allowed := by
  unfold worseResult
  cases ha : a.allowed <;> simp [ha]

/-- P7b: worseResult is at least as restrictive as either input. -/
theorem worseResult_at_least_as_restrictive (a b : GuardResult) :
    (worseResult a b).allowed = false ∨
    (a.allowed = true ∧ b.allowed = true) := by
  cases ha : a.allowed <;> cases hb : b.allowed
  · left; exact worseResult_preserves_deny_left a b ha
  · left; exact worseResult_preserves_deny_left a b ha
  · left; exact worseResult_preserves_deny_right a b hb
  · right; constructor <;> rfl

private theorem worseResult_default_decision_fields (r : GuardResult) :
    (worseResult defaultResult r).allowed = r.allowed ∧
    (worseResult defaultResult r).severity = r.severity ∧
    (worseResult defaultResult r).sanitized = r.sanitized := by
  unfold worseResult defaultResult
  cases hr : r.allowed <;> cases hs : r.severity <;> cases hsan : r.sanitized <;>
    simp_all [Severity.toNat]

private theorem worseResult_congr_decision (a b c : GuardResult)
    (ha : a.allowed = b.allowed) (hs : a.severity = b.severity)
    (hsan : a.sanitized = b.sanitized) :
    (worseResult a c).allowed = (worseResult b c).allowed ∧
    (worseResult a c).severity = (worseResult b c).severity ∧
    (worseResult a c).sanitized = (worseResult b c).sanitized := by
  unfold worseResult
  simp only [ha, hs, hsan]
  split <;> simp_all
  split <;> simp_all
  split <;> simp_all

private theorem foldl_worseResult_congr_decision (a b : GuardResult) (xs : List GuardResult)
    (ha : a.allowed = b.allowed) (hs : a.severity = b.severity)
    (hsan : a.sanitized = b.sanitized) :
    (xs.foldl worseResult a).allowed = (xs.foldl worseResult b).allowed ∧
    (xs.foldl worseResult a).severity = (xs.foldl worseResult b).severity ∧
    (xs.foldl worseResult a).sanitized = (xs.foldl worseResult b).sanitized := by
  induction xs generalizing a b with
  | nil => exact ⟨ha, hs, hsan⟩
  | cons x xs ih =>
    simp only [List.foldl]
    have h := worseResult_congr_decision a b x ha hs hsan
    exact ih _ _ h.1 h.2.1 h.2.2

/-- P7c: aggregateOverall and aggregateSpec agree on allowed and severity.
    They may differ on guardName/message (cosmetic). -/
theorem aggregate_forms_equivalent (results : List GuardResult) :
    (aggregateOverall results).allowed = (aggregateSpec results).allowed ∧
    (aggregateOverall results).severity = (aggregateSpec results).severity := by
  unfold aggregateOverall aggregateSpec
  cases results with
  | nil => simp [List.foldl, defaultResult, GuardResult.allow]
  | cons r rs =>
    simp only [List.foldl]
    have h := worseResult_default_decision_fields r
    have h' := foldl_worseResult_congr_decision _ _ rs h.1 h.2.1 h.2.2
    exact ⟨h'.1, h'.2.1⟩

-- P8: Severity Monotonicity in Aggregate
private theorem worseResult_severity_mono_left (a b : GuardResult)
    (h_deny : a.allowed = false) :
    a.severity.toNat ≤ (worseResult a b).severity.toNat := by
  unfold worseResult
  simp [h_deny]
  cases hb : b.allowed <;> simp
  · split
    · omega
    · omega

private theorem worseResult_severity_mono_right (a b : GuardResult)
    (h_deny : b.allowed = false) :
    b.severity.toNat ≤ (worseResult a b).severity.toNat := by
  unfold worseResult
  simp [h_deny]
  cases ha : a.allowed <;> simp
  · split
    · exact Nat.le_refl _
    · omega

private theorem foldl_worseResult_severity (acc : GuardResult) (xs : List GuardResult)
    (h_deny : acc.allowed = false) :
    acc.severity.toNat ≤ (xs.foldl worseResult acc).severity.toNat := by
  induction xs generalizing acc with
  | nil => exact Nat.le_refl acc.severity.toNat
  | cons x xs ih =>
    simp only [List.foldl]
    have h_step := worseResult_severity_mono_left acc x h_deny
    have h_deny' := worseResult_preserves_deny_left acc x h_deny
    exact Nat.le_trans h_step (ih (worseResult acc x) h_deny')

private theorem foldl_worseResult_severity_mem (acc : GuardResult) (xs : List GuardResult)
    (r : GuardResult) (h_mem : r ∈ xs) (h_deny : r.allowed = false) :
    r.severity.toNat ≤ (xs.foldl worseResult acc).severity.toNat := by
  induction xs generalizing acc with
  | nil => simp at h_mem
  | cons x xs ih =>
    simp only [List.foldl]
    cases h_mem with
    | head =>
      have h_step := worseResult_severity_mono_right acc r h_deny
      have h_deny' := worseResult_preserves_deny_right acc r h_deny
      exact Nat.le_trans h_step (foldl_worseResult_severity (worseResult acc r) xs h_deny')
    | tail _ h_tail =>
      exact ih (worseResult acc x) h_tail

/-- P8: Aggregate severity >= any blocking result's severity. -/
theorem aggregate_severity_monotone (results : List GuardResult)
    (r : GuardResult) (h_mem : r ∈ results) (h_deny : r.allowed = false) :
    r.severity.toNat ≤ (aggregateOverall results).severity.toNat := by
  unfold aggregateOverall
  exact foldl_worseResult_severity_mem defaultResult results r h_mem h_deny

/-- P9: Fail-closed on config error. -/
theorem fail_closed_config (policy : Policy) (action : Action) (ctx : Context)
    (h_error : hasConfigError policy = true) :
    ∃ (msg : String), evalPolicy policy action ctx = .error msg := by
  unfold evalPolicy
  simp [h_error]

/-- P10: Cycle detection. -/
theorem cycle_detected_if_visited (key : String) (visited : Visited) (depth : Nat)
    (h_visited : visited.contains key = true)
    (h_depth : depth ≤ maxExtendsDepth) :
    checkExtendsCycle key visited depth = .cycleDetected key := by
  unfold checkExtendsCycle
  simp [Nat.not_lt.mpr h_depth, h_visited]

/-- P10a: resolveChain detects visited keys. -/
theorem resolveChain_cycle_detected (lookup : String → Option PolicyNode)
    (key : String) (visited : Visited) (fuel : Nat)
    (h_visited : visited.contains key = true)
    (h_fuel : fuel > 0) :
    ∃ k, resolveChain lookup key visited fuel = .cycleDetected k := by
  match fuel, h_fuel with
  | n + 1, _ =>
    exists key
    unfold resolveChain
    simp [h_visited]

/-- P10b: Zero fuel terminates with depthExceeded. -/
theorem zero_fuel_terminates (lookup : String → Option PolicyNode)
    (key : String) (visited : Visited) :
    ∃ n, resolveChain lookup key visited 0 = .depthExceeded n := by
  exact ⟨visited.length, rfl⟩

/-- P10c: Depth limit exceeded is detected. -/
theorem depth_exceeded_detected (key : String) (visited : Visited) (depth : Nat)
    (h_deep : depth > maxExtendsDepth) :
    checkExtendsCycle key visited depth = .depthExceeded depth maxExtendsDepth := by
  unfold checkExtendsCycle
  simp [h_deep]

/-- P11: Empty list produces an allow verdict. -/
theorem empty_results_allow :
    (aggregateOverall []).allowed = true := by
  unfold aggregateOverall
  simp [List.foldl, defaultResult]

/-- P11a: No guards configured produces allow (assuming valid version). -/
theorem no_guards_allow (action : Action) (ctx : Context) :
    evalPolicy { guards := {} } action ctx = .ok (defaultResult) := by
  unfold evalPolicy
  have h_no_err : hasConfigError { guards := ({} : GuardConfigs) } = false := by native_decide
  simp [h_no_err]
  unfold evalGuards
  simp [List.filterMap]
  unfold aggregateOverall
  simp [List.foldl]

/-- P12: Disabled guards always allow. -/
theorem disabled_forbidden_path_allows (cfg : ForbiddenPathConfig)
    (action : Action) (ctx : Context)
    (h_disabled : cfg.enabled = false) :
    (evalForbiddenPath cfg action ctx).allowed = true := by
  unfold evalForbiddenPath
  simp [h_disabled, GuardResult.allow]

theorem disabled_egress_allows (cfg : EgressAllowlistConfig)
    (action : Action) (ctx : Context)
    (h_disabled : cfg.enabled = false) :
    (evalEgressAllowlist cfg action ctx).allowed = true := by
  unfold evalEgressAllowlist
  simp [h_disabled, GuardResult.allow]

theorem disabled_shell_command_allows (cfg : ShellCommandConfig)
    (action : Action) (ctx : Context)
    (h_disabled : cfg.enabled = false) :
    (evalShellCommand cfg action ctx).allowed = true := by
  unfold evalShellCommand
  simp [h_disabled, GuardResult.allow]

theorem disabled_mcp_tool_allows (cfg : McpToolConfig)
    (action : Action) (ctx : Context)
    (h_disabled : cfg.enabled = false) :
    (evalMcpTool cfg action ctx).allowed = true := by
  unfold evalMcpTool
  simp [h_disabled, GuardResult.allow]

/-- P13: Guards are irrelevant for non-matching action types. -/
theorem forbidden_path_irrelevant_for_shell (cfg : ForbiddenPathConfig)
    (cmd : Command) (ctx : Context) :
    (evalForbiddenPath cfg (.shellCommand cmd) ctx).allowed = true := by
  unfold evalForbiddenPath
  cases h : cfg.enabled <;> simp [GuardResult.allow]

theorem egress_irrelevant_for_file (cfg : EgressAllowlistConfig)
    (path : Path) (ctx : Context) :
    (evalEgressAllowlist cfg (.fileAccess path) ctx).allowed = true := by
  unfold evalEgressAllowlist
  cases h : cfg.enabled <;> simp [GuardResult.allow]

theorem shell_irrelevant_for_file (cfg : ShellCommandConfig)
    (path : Path) (ctx : Context) :
    (evalShellCommand cfg (.fileAccess path) ctx).allowed = true := by
  unfold evalShellCommand
  cases h : cfg.enabled <;> simp [GuardResult.allow]

theorem mcp_irrelevant_for_file (cfg : McpToolConfig)
    (path : Path) (ctx : Context) :
    (evalMcpTool cfg (.fileAccess path) ctx).allowed = true := by
  unfold evalMcpTool
  cases h : cfg.enabled <;> simp [GuardResult.allow]

end ClawdStrike.Spec
