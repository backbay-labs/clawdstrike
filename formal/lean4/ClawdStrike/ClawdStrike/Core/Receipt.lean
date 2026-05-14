/-
  Receipt data type and sign/verify operations (simplified).
  Mirrors: hush-core/src/receipt.rs
-/

import ClawdStrike.Core.Crypto

set_option autoImplicit false

namespace ClawdStrike.Core.Receipt

open ClawdStrike.Core.Crypto

/-- Mirrors: Receipt in receipt.rs (simplified). -/
structure Receipt where
  version : String
  timestamp : String
  action : String
  verdict : String
  guardResults : List String
  metadata : String
  deriving Repr, BEq

/-- Simplified canonical JSON serialization (deterministic field ordering). -/
def Receipt.toCanonicalJson (r : Receipt) : String :=
  "{\"action\":" ++ "\"" ++ r.action ++ "\""
  ++ ",\"guardResults\":" ++ toString r.guardResults
  ++ ",\"metadata\":" ++ "\"" ++ r.metadata ++ "\""
  ++ ",\"timestamp\":" ++ "\"" ++ r.timestamp ++ "\""
  ++ ",\"verdict\":" ++ "\"" ++ r.verdict ++ "\""
  ++ ",\"version\":" ++ "\"" ++ r.version ++ "\""
  ++ "}"

/-- Mirrors: SignedReceipt in receipt.rs (primary signer only, no co-signer). -/
structure SignedReceipt where
  receipt : Receipt
  signature : Crypto.Signature
  signerPublicKey : Crypto.PublicKey

/-- Mirrors: SignedReceipt::sign in receipt.rs (happy path). -/
noncomputable def SignedReceipt.sign (sk : Crypto.SecretKey) (r : Receipt) : SignedReceipt :=
  let canonical := Crypto.canonicalize r.toCanonicalJson
  { receipt := r
  , signature := Crypto.ed25519_sign sk canonical
  , signerPublicKey := Crypto.publicKey sk }

/-- Mirrors: SignedReceipt::verify in receipt.rs (core signature check). -/
noncomputable def SignedReceipt.verify (sr : SignedReceipt) : Bool :=
  let canonical := Crypto.canonicalize sr.receipt.toCanonicalJson
  Crypto.ed25519_verify sr.signerPublicKey canonical sr.signature

end ClawdStrike.Core.Receipt
