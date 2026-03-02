package crypto

import (
	"encoding/json"
	"testing"
)

func TestSHA256(t *testing.T) {
	hash := SHA256([]byte("hello"))
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash.Hex() != expected {
		t.Errorf("SHA256(hello) = %s, want %s", hash.Hex(), expected)
	}
}

func TestKeccak256(t *testing.T) {
	hash := Keccak256([]byte("hello"))
	expected := "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
	if hash.Hex() != expected {
		t.Errorf("Keccak256(hello) = %s, want %s", hash.Hex(), expected)
	}
}

func TestHashFromHex(t *testing.T) {
	original := SHA256([]byte("test"))

	fromHex, err := HashFromHex(original.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if fromHex != original {
		t.Error("HashFromHex roundtrip without prefix failed")
	}

	fromPrefixed, err := HashFromHex(original.HexPrefixed())
	if err != nil {
		t.Fatal(err)
	}
	if fromPrefixed != original {
		t.Error("HashFromHex roundtrip with prefix failed")
	}
}

func TestHashFromHexErrors(t *testing.T) {
	if _, err := HashFromHex("not-hex"); err == nil {
		t.Error("expected error for invalid hex")
	}
	if _, err := HashFromHex("abcd"); err == nil {
		t.Error("expected error for wrong length")
	}
}

func TestHashJSON(t *testing.T) {
	hash := SHA256([]byte("test"))
	data, err := json.Marshal(hash)
	if err != nil {
		t.Fatal(err)
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	if s[:2] != "0x" {
		t.Errorf("JSON should be 0x-prefixed, got %s", s)
	}

	var restored Hash
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored != hash {
		t.Error("JSON roundtrip failed")
	}
}

func TestHashIsZero(t *testing.T) {
	var zero Hash
	if !zero.IsZero() {
		t.Error("zero hash should be zero")
	}
	h := SHA256([]byte("x"))
	if h.IsZero() {
		t.Error("non-zero hash should not be zero")
	}
}

func TestSignVerify(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("Hello, Clawdstrike!")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !kp.PublicKey().Verify(msg, &sig) {
		t.Error("valid signature rejected")
	}
	if kp.PublicKey().Verify([]byte("wrong"), &sig) {
		t.Error("invalid signature accepted")
	}
}

func TestKeypairFromSeed(t *testing.T) {
	seed := [32]byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
		42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}
	kp1 := KeypairFromSeed(seed)
	kp2 := KeypairFromSeed(seed)
	if kp1.PublicKey().Hex() != kp2.PublicKey().Hex() {
		t.Error("same seed should produce same public key")
	}
}

func TestKeypairFromHex(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	hexSeed := kp.Hex()

	restored, err := KeypairFromHex(hexSeed)
	if err != nil {
		t.Fatal(err)
	}
	if kp.PublicKey().Hex() != restored.PublicKey().Hex() {
		t.Error("hex roundtrip failed")
	}
}

func TestPublicKeyHexRoundtrip(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pk := kp.PublicKey()
	restored, err := PublicKeyFromHex(pk.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if pk != restored {
		t.Error("public key hex roundtrip failed")
	}
}

func TestSignatureHexRoundtrip(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := kp.Sign([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := SignatureFromHex(sig.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if sig != restored {
		t.Error("signature hex roundtrip failed")
	}
}

func TestPublicKeyJSON(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pk := kp.PublicKey()
	data, err := json.Marshal(pk)
	if err != nil {
		t.Fatal(err)
	}
	var restored PublicKey
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if pk != restored {
		t.Error("public key JSON roundtrip failed")
	}
}

func TestSignatureJSON(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := kp.Sign([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	var restored Signature
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if sig != restored {
		t.Error("signature JSON roundtrip failed")
	}
}

func TestVerifySignature(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test")
	sig, err := kp.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySignature(kp.PublicKey(), msg, &sig) {
		t.Error("VerifySignature rejected valid signature")
	}
}
