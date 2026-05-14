/-
  Axiomatized Ed25519 and canonical JSON (RFC 8785).
  Mirrors: hush-core/src/signing.rs, hush-core/src/receipt.rs, hush-core/src/canonical.rs
-/

set_option autoImplicit false

namespace ClawdStrike.Core.Crypto

-- Opaque types

axiom SecretKey : Type
axiom PublicKey : Type
axiom Signature : Type
axiom ByteArray : Type

-- Operations

axiom publicKey : SecretKey → PublicKey
axiom ed25519_sign : SecretKey → ByteArray → Signature
axiom ed25519_verify : PublicKey → ByteArray → Signature → Bool

-- Axioms

/-- Sign-verify roundtrip (RFC 8032 Section 5.1.7).
    Sound because ed25519-dalek is a well-audited RFC 8032 implementation. -/
axiom sign_verify_roundtrip (sk : SecretKey) (msg : ByteArray) :
    ed25519_verify (publicKey sk) msg (ed25519_sign sk msg) = true

/-- Trivially true for pure functions; documents Rust deterministic nonce generation. -/
theorem sign_deterministic (sk : SecretKey) (msg : ByteArray) :
    ed25519_sign sk msg = ed25519_sign sk msg := rfl

/-- Mirrors: crate::canonical::canonicalize (RFC 8785 JCS). -/
axiom canonicalize : String → ByteArray

/-- Trivially true for pure functions; documents RFC 8785 determinism. -/
theorem canonicalize_deterministic (s : String) :
    canonicalize s = canonicalize s := rfl

end ClawdStrike.Core.Crypto
