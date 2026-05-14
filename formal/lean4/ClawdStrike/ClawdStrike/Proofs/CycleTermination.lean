/-
  Cycle termination proofs (P10, P10a, P10b, P10c).
  Mirrors: check_extends_cycle in core/cycle.rs
-/

import ClawdStrike.Core.Cycle
import ClawdStrike.Spec.Properties

set_option autoImplicit false

namespace ClawdStrike.Proofs

open ClawdStrike.Core

theorem depth_exceeded_detected (key : String) (visited : Visited) (depth : Nat)
    (h_deep : depth > maxExtendsDepth) :
    checkExtendsCycle key visited depth = .depthExceeded depth maxExtendsDepth := by
  unfold checkExtendsCycle
  simp [h_deep]

theorem cycle_detected_if_visited_check (key : String) (visited : Visited) (depth : Nat)
    (h_visited : visited.contains key = true)
    (h_depth : depth ≤ maxExtendsDepth) :
    checkExtendsCycle key visited depth = .cycleDetected key := by
  unfold checkExtendsCycle
  have h_not_deep : ¬(depth > maxExtendsDepth) := Nat.not_lt_of_le h_depth
  simp [Nat.not_lt.mpr h_depth, h_visited]

theorem check_extends_ok (key : String) (visited : Visited) (depth : Nat)
    (h_not_deep : depth ≤ maxExtendsDepth)
    (h_not_visited : visited.contains key = false) :
    checkExtendsCycle key visited depth = .ok := by
  unfold checkExtendsCycle
  simp [Nat.not_lt.mpr h_not_deep, h_not_visited]

theorem zero_fuel_terminates (lookup : String → Option PolicyNode)
    (key : String) (visited : Visited) :
    ∃ n, resolveChain lookup key visited 0 = .depthExceeded n := by
  exact ⟨visited.length, rfl⟩

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

theorem resolve_terminates_on_visited (lookup : String → Option PolicyNode)
    (key : String) (visited : Visited) (fuel : Nat)
    (h_visited : visited.contains key = true) :
    (∃ k, resolveChain lookup key visited fuel = .cycleDetected k) ∨
    (∃ n, resolveChain lookup key visited fuel = .depthExceeded n) := by
  cases fuel with
  | zero =>
    right
    exact zero_fuel_terminates lookup key visited
  | succ n =>
    left
    exact resolveChain_cycle_detected lookup key visited (n + 1) h_visited (Nat.succ_pos n)

theorem resolve_ok_extends_visited (lookup : String → Option PolicyNode)
    (key : String) (visited : Visited) (fuel : Nat) (chain : List String)
    (h_ok : resolveChain lookup key visited fuel = .ok chain)
    (k : String) (h_in : k ∈ visited) :
    k ∈ chain := by
  induction fuel generalizing key visited with
  | zero =>
    unfold resolveChain at h_ok
    simp at h_ok
  | succ n ih =>
    unfold resolveChain at h_ok
    split at h_ok
    · simp at h_ok
    · split at h_ok
      · simp [ResolveResult.ok.injEq] at h_ok
        rw [← h_ok]
        exact List.mem_cons_of_mem key h_in
      · split at h_ok
        · simp [ResolveResult.ok.injEq] at h_ok
          rw [← h_ok]
          exact List.mem_cons_of_mem key h_in
        · rename_i _ _ heq
          have h_mem : k ∈ key :: visited := List.mem_cons_of_mem key h_in
          exact ih _ (key :: visited) h_ok h_mem

theorem resolve_ok_contains_key (lookup : String → Option PolicyNode)
    (key : String) (visited : Visited) (fuel : Nat) (chain : List String)
    (h_ok : resolveChain lookup key visited fuel = .ok chain) :
    key ∈ chain := by
  induction fuel generalizing key visited with
  | zero =>
    unfold resolveChain at h_ok
    simp at h_ok
  | succ n ih =>
    unfold resolveChain at h_ok
    split at h_ok
    · simp at h_ok
    · split at h_ok
      · simp [ResolveResult.ok.injEq] at h_ok
        rw [← h_ok]
        exact List.mem_cons_self ..
      · split at h_ok
        · simp [ResolveResult.ok.injEq] at h_ok
          rw [← h_ok]
          exact List.mem_cons_self ..
        · exact resolve_ok_extends_visited lookup _ (key :: visited) n chain h_ok
            key (List.mem_cons_self ..)

theorem resolve_fuel_mono (lookup : String → Option PolicyNode)
    (key : String) (visited : Visited) (n : Nat) (chain : List String)
    (h_ok : resolveChain lookup key visited n = .ok chain) :
    resolveChain lookup key visited (n + 1) = .ok chain := by
  induction n generalizing key visited with
  | zero =>
    unfold resolveChain at h_ok
    simp at h_ok
  | succ m ih =>
    unfold resolveChain at h_ok ⊢
    cases h_vis : Visited.contains visited key
    · simp [h_vis] at h_ok ⊢
      cases h_look : lookup key
      · simp [h_look] at h_ok ⊢
        exact h_ok
      · simp [h_look] at h_ok ⊢
        rename_i node
        cases h_ext : node.extends_
        · simp [h_ext] at h_ok ⊢
          exact h_ok
        · simp [h_ext] at h_ok ⊢
          exact ih _ (key :: visited) h_ok
    · simp [h_vis] at h_ok

end ClawdStrike.Proofs
