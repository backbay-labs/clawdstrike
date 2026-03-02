package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Signer is the signing interface used by hush-go (e.g., receipts).
type Signer interface {
	PublicKey() PublicKey
	Sign(message []byte) (Signature, error)
}

// Keypair wraps an Ed25519 private key.
type Keypair struct {
	privateKey ed25519.PrivateKey
}

// GenerateKeypair creates a new random Ed25519 keypair.
func GenerateKeypair() (*Keypair, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	return &Keypair{privateKey: priv}, nil
}

// KeypairFromSeed creates a keypair from a 32-byte seed.
func KeypairFromSeed(seed [32]byte) *Keypair {
	priv := ed25519.NewKeyFromSeed(seed[:])
	return &Keypair{privateKey: priv}
}

// KeypairFromHex creates a keypair from a hex-encoded 32-byte seed.
func KeypairFromHex(hexSeed string) (*Keypair, error) {
	hexSeed = strings.TrimPrefix(hexSeed, "0x")
	b, err := hex.DecodeString(hexSeed)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 32 {
		return nil, errors.New("seed must be 32 bytes")
	}
	var seed [32]byte
	copy(seed[:], b)
	return KeypairFromSeed(seed), nil
}

// PublicKey returns the public key for this keypair.
func (kp *Keypair) PublicKey() PublicKey {
	pub := kp.privateKey.Public().(ed25519.PublicKey)
	var pk PublicKey
	copy(pk[:], pub)
	return pk
}

// Sign signs a message and returns the signature.
func (kp *Keypair) Sign(message []byte) (Signature, error) {
	sig := ed25519.Sign(kp.privateKey, message)
	var s Signature
	copy(s[:], sig)
	return s, nil
}

// Hex returns the seed as a hex string.
func (kp *Keypair) Hex() string {
	return hex.EncodeToString(kp.privateKey.Seed())
}

// PublicKey is a 32-byte Ed25519 public key.
type PublicKey [32]byte

// PublicKeyFromHex parses a hex string into a PublicKey.
func PublicKeyFromHex(s string) (PublicKey, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return PublicKey{}, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 32 {
		return PublicKey{}, fmt.Errorf("public key must be 32 bytes, got %d", len(b))
	}
	var pk PublicKey
	copy(pk[:], b)
	return pk, nil
}

// PublicKeyFromBytes creates a PublicKey from a byte slice.
func PublicKeyFromBytes(b []byte) (PublicKey, error) {
	if len(b) != 32 {
		return PublicKey{}, fmt.Errorf("public key must be 32 bytes, got %d", len(b))
	}
	var pk PublicKey
	copy(pk[:], b)
	return pk, nil
}

// Verify checks an Ed25519 signature against this public key.
func (pk PublicKey) Verify(message []byte, sig *Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(pk[:]), message, sig[:])
}

// Hex returns the public key as a lowercase hex string.
func (pk PublicKey) Hex() string {
	return hex.EncodeToString(pk[:])
}

// HexPrefixed returns the public key as a "0x"-prefixed hex string.
func (pk PublicKey) HexPrefixed() string {
	return "0x" + pk.Hex()
}

// Bytes returns the raw 32-byte array.
func (pk PublicKey) Bytes() [32]byte {
	return [32]byte(pk)
}

// MarshalJSON serializes as a hex string.
func (pk PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(pk.Hex())
}

// UnmarshalJSON deserializes from a hex string.
func (pk *PublicKey) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := PublicKeyFromHex(s)
	if err != nil {
		return err
	}
	*pk = parsed
	return nil
}

// Signature is a 64-byte Ed25519 signature.
type Signature [64]byte

// SignatureFromHex parses a hex string into a Signature.
func SignatureFromHex(s string) (Signature, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return Signature{}, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 64 {
		return Signature{}, fmt.Errorf("signature must be 64 bytes, got %d", len(b))
	}
	var sig Signature
	copy(sig[:], b)
	return sig, nil
}

// Hex returns the signature as a lowercase hex string.
func (s Signature) Hex() string {
	return hex.EncodeToString(s[:])
}

// HexPrefixed returns the signature as a "0x"-prefixed hex string.
func (s Signature) HexPrefixed() string {
	return "0x" + s.Hex()
}

// Bytes returns the raw 64-byte array.
func (s Signature) Bytes() [64]byte {
	return [64]byte(s)
}

// MarshalJSON serializes as a hex string.
func (s Signature) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Hex())
}

// UnmarshalJSON deserializes from a hex string.
func (s *Signature) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed, err := SignatureFromHex(str)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// VerifySignature is a convenience function that verifies a signature.
func VerifySignature(pk PublicKey, message []byte, sig *Signature) bool {
	return pk.Verify(message, sig)
}
