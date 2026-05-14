/-
  Aggregate and evaluation proofs (P4, P7, P8, P9, P11, P12, P13).
  Mirrors: core/aggregate.rs, guards/*.rs
-/

import ClawdStrike.Core.Verdict
import ClawdStrike.Core.Aggregate
import ClawdStrike.Core.Eval
import ClawdStrike.Spec.Properties
import ClawdStrike.Proofs.DenyMonotonicity

set_option autoImplicit false

namespace ClawdStrike.Proofs

open ClawdStrike.Core

-- P11

theorem empty_results_allow :
    (aggregateOverall []).allowed = true := by
  unfold aggregateOverall
  simp [List.foldl, defaultResult]

theorem defaultResult_allowed : defaultResult.allowed = true := by
  unfold defaultResult; rfl

theorem aggregate_singleton_allow (r : GuardResult) (h : r.allowed = true) :
    (aggregateOverall [r]).allowed = true := by
  unfold aggregateOverall
  simp [List.foldl]
  unfold worseResult defaultResult
  simp [h]
  split
  · exact h
  · split
    · exact h
    · rfl

theorem aggregate_singleton_deny (r : GuardResult) (h : r.allowed = false) :
    (aggregateOverall [r]).allowed = false := by
  exact deny_monotonicity [r] r (List.mem_cons_self ..) h

-- P7a

theorem worseResult_idempotent_allowed (a : GuardResult) :
    (worseResult a a).allowed = a.allowed := by
  unfold worseResult
  cases ha : a.allowed <;> simp [ha]

-- P7b

theorem worseResult_at_least_as_restrictive (a b : GuardResult) :
    (worseResult a b).allowed = false ∨
    (a.allowed = true ∧ b.allowed = true) := by
  cases ha : a.allowed <;> cases hb : b.allowed
  · left; exact worseResult_preserves_deny_left a b ha
  · left; exact worseResult_preserves_deny_left a b ha
  · left; exact worseResult_preserves_deny_right a b hb
  · right; constructor <;> rfl

-- P7

theorem aggregate_deterministic (results : List GuardResult) :
    aggregateOverall results = aggregateOverall results := rfl

theorem worseResult_returns_input (a b : GuardResult) :
    worseResult a b = a ∨ worseResult a b = b := by
  unfold worseResult
  simp only
  split
  · exact Or.inr rfl
  · split
    · exact Or.inr rfl
    · split
      · exact Or.inr rfl
      · exact Or.inl rfl

-- P8

theorem worseResult_severity_mono_left (a b : GuardResult)
    (h_deny : a.allowed = false) :
    a.severity.toNat ≤ (worseResult a b).severity.toNat := by
  unfold worseResult
  simp [h_deny]
  cases hb : b.allowed <;> simp
  · split
    · omega
    · omega

theorem worseResult_severity_mono_right (a b : GuardResult)
    (h_deny : b.allowed = false) :
    b.severity.toNat ≤ (worseResult a b).severity.toNat := by
  unfold worseResult
  simp [h_deny]
  cases ha : a.allowed <;> simp
  · split
    · exact Nat.le_refl _
    · omega

theorem foldl_worseResult_severity (acc : GuardResult) (xs : List GuardResult)
    (h_deny : acc.allowed = false) :
    acc.severity.toNat ≤ (xs.foldl worseResult acc).severity.toNat := by
  induction xs generalizing acc with
  | nil => exact Nat.le_refl acc.severity.toNat
  | cons x xs ih =>
    simp only [List.foldl]
    have h_step := worseResult_severity_mono_left acc x h_deny
    have h_deny' := worseResult_preserves_deny_left acc x h_deny
    exact Nat.le_trans h_step (ih (worseResult acc x) h_deny')

theorem foldl_worseResult_severity_mem (acc : GuardResult) (xs : List GuardResult)
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

theorem aggregate_severity_monotone (results : List GuardResult)
    (r : GuardResult) (h_mem : r ∈ results) (h_deny : r.allowed = false) :
    r.severity.toNat ≤ (aggregateOverall results).severity.toNat := by
  unfold aggregateOverall
  exact foldl_worseResult_severity_mem defaultResult results r h_mem h_deny

-- P9

theorem fail_closed_config (policy : Policy) (action : Action) (ctx : Context)
    (h_error : hasConfigError policy = true) :
    ∃ (msg : String), evalPolicy policy action ctx = .error msg := by
  unfold evalPolicy
  simp [h_error]

-- P12

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

-- P13

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

-- P4

theorem forbidden_path_guard_soundness (cfg : ForbiddenPathConfig) (path : Path)
    (ctx : Context)
    (h_enabled : cfg.enabled = true)
    (h_match : matchesAny cfg.effectivePatterns path = true)
    (h_no_exception : matchesAny cfg.exceptions path = false) :
    (evalForbiddenPath cfg (.fileAccess path) ctx).allowed = false := by
  unfold evalForbiddenPath
  simp [h_enabled, h_match, h_no_exception, GuardResult.block]

theorem aggregate_two (a b : GuardResult) :
    aggregateOverall [a, b] = worseResult (worseResult defaultResult a) b := by
  unfold aggregateOverall
  simp [List.foldl]

-- P1c

theorem worseResult_preserves_deny (a b : GuardResult)
    (h : a.allowed = false ∨ b.allowed = false) :
    (worseResult a b).allowed = false := by
  cases h with
  | inl ha => exact worseResult_preserves_deny_left a b ha
  | inr hb => exact worseResult_preserves_deny_right a b hb

end ClawdStrike.Proofs
