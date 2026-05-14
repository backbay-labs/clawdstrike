/-
  Severity total order proofs (P3, P3a, P3b, P3c).
  Mirrors: severity_ord in core/verdict.rs
-/

import ClawdStrike.Core.Verdict
import ClawdStrike.Spec.Properties

set_option autoImplicit false

namespace ClawdStrike.Proofs

open ClawdStrike.Core

theorem severity_le_refl (a : Severity) : a ≤ a := by
  show a.toNat ≤ a.toNat
  exact Nat.le_refl a.toNat

theorem severity_le_trans (a b c : Severity)
    (h1 : a ≤ b) (h2 : b ≤ c) : a ≤ c := by
  show a.toNat ≤ c.toNat
  exact Nat.le_trans h1 h2

theorem severity_le_antisymm (a b : Severity)
    (h1 : a ≤ b) (h2 : b ≤ a) : a = b := by
  have h_eq : a.toNat = b.toNat := Nat.le_antisymm h1 h2
  exact Severity.toNat_injective a b h_eq

theorem severity_total_order (a b : Severity) :
    a ≤ b ∨ b ≤ a := by
  show a.toNat ≤ b.toNat ∨ b.toNat ≤ a.toNat
  exact Nat.le_total a.toNat b.toNat

theorem severity_toNat_injective (a b : Severity)
    (h : a.toNat = b.toNat) : a = b := by
  cases a <;> cases b <;> simp [Severity.toNat] at h <;> rfl

theorem severity_lt_iff_toNat_lt (a b : Severity) :
    a < b ↔ a.toNat < b.toNat :=
  Iff.rfl

theorem info_le_warning : Severity.info ≤ Severity.warning := by
  show (0 : Nat) ≤ 1; omega

theorem warning_le_error : Severity.warning ≤ Severity.error := by
  show (1 : Nat) ≤ 2; omega

theorem error_le_critical : Severity.error ≤ Severity.critical := by
  show (2 : Nat) ≤ 3; omega

theorem info_le_critical : Severity.info ≤ Severity.critical := by
  show (0 : Nat) ≤ 3; omega

theorem info_lt_warning : Severity.info < Severity.warning := by
  show (0 : Nat) < 1; omega

theorem warning_lt_error : Severity.warning < Severity.error := by
  show (1 : Nat) < 2; omega

theorem error_lt_critical : Severity.error < Severity.critical := by
  show (2 : Nat) < 3; omega

theorem severity_ne_of_lt (a b : Severity) (h : a < b) : a ≠ b := by
  intro h_eq
  subst h_eq
  exact Nat.lt_irrefl a.toNat h

theorem info_is_minimum (s : Severity) : Severity.info ≤ s := by
  show (0 : Nat) ≤ s.toNat
  exact Nat.zero_le s.toNat

theorem critical_is_maximum (s : Severity) : s ≤ Severity.critical := by
  show s.toNat ≤ 3
  cases s <;> simp [Severity.toNat] <;> omega

theorem severity_le_iff_toNat_le (a b : Severity) :
    a ≤ b ↔ a.toNat ≤ b.toNat :=
  Iff.rfl

def severity_le_decidable (a b : Severity) : Decidable (a ≤ b) :=
  inferInstanceAs (Decidable (a.toNat ≤ b.toNat))

def severity_lt_decidable (a b : Severity) : Decidable (a < b) :=
  inferInstanceAs (Decidable (a.toNat < b.toNat))

end ClawdStrike.Proofs
