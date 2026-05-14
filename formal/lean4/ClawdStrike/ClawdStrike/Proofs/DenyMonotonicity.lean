/-
  Deny monotonicity proofs (P1, P1a, P1b, P2).
-/

import ClawdStrike.Core.Verdict
import ClawdStrike.Core.Aggregate
import ClawdStrike.Spec.Properties

set_option autoImplicit false

namespace ClawdStrike.Proofs

open ClawdStrike.Core

-- P1a
theorem worseResult_preserves_deny_left (best candidate : GuardResult)
    (h : best.allowed = false) :
    (worseResult best candidate).allowed = false := by
  unfold worseResult
  simp only [h]
  cases hc : candidate.allowed
  · simp; split <;> simp_all
  · simp; exact h

-- P1b
theorem worseResult_preserves_deny_right (best candidate : GuardResult)
    (h : candidate.allowed = false) :
    (worseResult best candidate).allowed = false := by
  unfold worseResult
  simp only [h]
  cases hb : best.allowed
  · simp; split <;> simp_all
  · simp; exact h

theorem foldl_worseResult_deny (acc : GuardResult) (xs : List GuardResult)
    (h : acc.allowed = false) :
    (xs.foldl worseResult acc).allowed = false := by
  induction xs generalizing acc with
  | nil => exact h
  | cons x xs ih =>
    simp only [List.foldl]
    exact ih (worseResult acc x) (worseResult_preserves_deny_left acc x h)

theorem foldl_worseResult_deny_mem (acc : GuardResult) (xs : List GuardResult)
    (r : GuardResult) (h_mem : r ∈ xs) (h_deny : r.allowed = false) :
    (xs.foldl worseResult acc).allowed = false := by
  induction xs generalizing acc with
  | nil => simp at h_mem
  | cons _ ys ih =>
    simp only [List.foldl]
    cases h_mem with
    | head =>
      exact foldl_worseResult_deny _ ys
        (worseResult_preserves_deny_right acc _ h_deny)
    | tail _ h_tail =>
      exact ih _ h_tail

-- P1
theorem deny_monotonicity (results : List GuardResult) (r : GuardResult)
    (h_mem : r ∈ results) (h_deny : r.allowed = false) :
    (aggregateOverall results).allowed = false := by
  unfold aggregateOverall
  exact foldl_worseResult_deny_mem defaultResult results r h_mem h_deny

-- P2
theorem allow_requires_unanimity (results : List GuardResult)
    (h_allow : (aggregateOverall results).allowed = true)
    (r : GuardResult) (h_mem : r ∈ results) :
    r.allowed = true := by
  cases hr : r.allowed with
  | false =>
    have h_agg_deny := deny_monotonicity results r h_mem hr
    simp [h_agg_deny] at h_allow
  | true => rfl

end ClawdStrike.Proofs
