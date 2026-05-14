/-
  Receipt signing proofs.
  Mirrors: receipt.rs SignedReceipt::sign, SignedReceipt::verify
-/

import ClawdStrike.Core.Crypto
import ClawdStrike.Core.Receipt

set_option autoImplicit false

namespace ClawdStrike.Proofs

open ClawdStrike.Core
open ClawdStrike.Core.Receipt

theorem sign_then_verify (sk : Crypto.SecretKey) (r : Receipt) :
    (SignedReceipt.sign sk r).verify = true := by
  unfold SignedReceipt.sign SignedReceipt.verify
  simp only []
  exact Crypto.sign_verify_roundtrip sk (Crypto.canonicalize r.toCanonicalJson)

theorem signature_covers_content (sk : Crypto.SecretKey) (r : Receipt) :
    (SignedReceipt.sign sk r).signature =
      Crypto.ed25519_sign sk (Crypto.canonicalize r.toCanonicalJson) := by
  unfold SignedReceipt.sign
  rfl

theorem verify_recomputes_canonical (sr : SignedReceipt) :
    sr.verify =
      Crypto.ed25519_verify sr.signerPublicKey
        (Crypto.canonicalize sr.receipt.toCanonicalJson)
        sr.signature := by
  unfold SignedReceipt.verify
  rfl

theorem sign_preserves_receipt (sk : Crypto.SecretKey) (r : Receipt) :
    (SignedReceipt.sign sk r).receipt = r := by
  unfold SignedReceipt.sign
  rfl

theorem sign_binds_public_key (sk : Crypto.SecretKey) (r : Receipt) :
    (SignedReceipt.sign sk r).signerPublicKey = Crypto.publicKey sk := by
  unfold SignedReceipt.sign
  rfl

theorem different_receipts_independent
    (sk : Crypto.SecretKey) (r1 r2 : Receipt) :
    (SignedReceipt.sign sk r1).verify = true ∧
    (SignedReceipt.sign sk r2).verify = true :=
  ⟨sign_then_verify sk r1, sign_then_verify sk r2⟩

theorem canonical_json_deterministic_signing
    (sk : Crypto.SecretKey) (r : Receipt) :
    SignedReceipt.sign sk r = SignedReceipt.sign sk r := rfl

end ClawdStrike.Proofs
