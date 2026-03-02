// Package crypto provides cryptographic primitives for hush-go:
// SHA-256, Keccak-256 hashing and Ed25519 signing.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Hash is a 32-byte hash value. It serializes to JSON as "0x<hex>".
type Hash [32]byte

func SHA256(data []byte) Hash {
	return Hash(sha256.Sum256(data))
}

// Keccak256 computes the Keccak-256 hash (Ethereum-compatible, NOT SHA3-256).
func Keccak256(data []byte) Hash {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

func HashFromHex(s string) (Hash, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return Hash{}, fmt.Errorf("invalid hex: %w", err)
	}
	if len(b) != 32 {
		return Hash{}, fmt.Errorf("hash must be 32 bytes, got %d", len(b))
	}
	var h Hash
	copy(h[:], b)
	return h, nil
}

func (h Hash) Hex() string {
	return hex.EncodeToString(h[:])
}

func (h Hash) HexPrefixed() string {
	return "0x" + h.Hex()
}

func (h Hash) Bytes() [32]byte {
	return [32]byte(h)
}

func (h Hash) IsZero() bool {
	return h == Hash{}
}

func (h Hash) String() string {
	return h.HexPrefixed()
}

func (h Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.HexPrefixed())
}

func (h *Hash) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := HashFromHex(s)
	if err != nil {
		return err
	}
	*h = parsed
	return nil
}

var errHashLength = errors.New("hash must be 32 bytes")

func HashFromBytes(b []byte) (Hash, error) {
	if len(b) != 32 {
		return Hash{}, errHashLength
	}
	var h Hash
	copy(h[:], b)
	return h, nil
}
