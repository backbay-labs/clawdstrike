package receipt

import (
	"testing"

	"github.com/backbay/clawdstrike-go/crypto"
)

func makeTestReceipt() Receipt {
	return Receipt{
		Version:     SchemaVersion,
		ReceiptID:   "test-receipt-001",
		Timestamp:   "2026-01-01T00:00:00Z",
		ContentHash: crypto.Hash{},
		Verdict:     PassWithGate("test-gate"),
		Provenance: &Provenance{
			ClawdstrikeVersion: "0.1.0",
			Provider:           "local",
			PolicyHash:         &crypto.Hash{},
			Ruleset:            "default",
		},
	}
}

func TestSignAndVerify(t *testing.T) {
	receipt := makeTestReceipt()
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := Sign(receipt, kp)
	if err != nil {
		t.Fatal(err)
	}

	keys := NewPublicKeySet(kp.PublicKey())
	result := signed.Verify(keys)

	if !result.Valid {
		t.Errorf("expected valid, errors: %v", result.Errors)
	}
	if !result.SignerValid {
		t.Error("expected signer valid")
	}
}

func TestSignWithCosigner(t *testing.T) {
	receipt := makeTestReceipt()
	signerKP, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cosignerKP, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := Sign(receipt, signerKP)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.AddCosigner(cosignerKP); err != nil {
		t.Fatal(err)
	}

	keys := NewPublicKeySet(signerKP.PublicKey()).WithCosigner(cosignerKP.PublicKey())
	result := signed.Verify(keys)

	if !result.Valid {
		t.Errorf("expected valid, errors: %v", result.Errors)
	}
	if !result.SignerValid {
		t.Error("expected signer valid")
	}
	if result.CosignerValid == nil || !*result.CosignerValid {
		t.Error("expected cosigner valid")
	}
}

func TestWrongKeyFails(t *testing.T) {
	receipt := makeTestReceipt()
	signerKP, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wrongKP, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := Sign(receipt, signerKP)
	if err != nil {
		t.Fatal(err)
	}

	keys := NewPublicKeySet(wrongKP.PublicKey())
	result := signed.Verify(keys)

	if result.Valid {
		t.Error("expected invalid with wrong key")
	}
	if result.SignerValid {
		t.Error("signer should be invalid with wrong key")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors")
	}
}

func TestSignRejectsUnsupportedVersion(t *testing.T) {
	receipt := makeTestReceipt()
	receipt.Version = "2.0.0"
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Sign(receipt, kp)
	if err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestVerifyFailsClosedOnUnsupportedVersion(t *testing.T) {
	receipt := makeTestReceipt()
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := Sign(receipt, kp)
	if err != nil {
		t.Fatal(err)
	}
	signed.Receipt.Version = "2.0.0"

	keys := NewPublicKeySet(kp.PublicKey())
	result := signed.Verify(keys)

	if result.Valid {
		t.Error("expected invalid for unsupported version")
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestCanonicalJSONDeterministic(t *testing.T) {
	receipt := makeTestReceipt()
	json1, err := receipt.ToCanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	json2, err := receipt.ToCanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if json1 != json2 {
		t.Error("canonical JSON should be deterministic")
	}
}

func TestCanonicalJSONSorted(t *testing.T) {
	receipt := makeTestReceipt()
	j, err := receipt.ToCanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}

	// "content_hash" should come before "verdict"
	contentPos := indexOf(j, `"content_hash"`)
	verdictPos := indexOf(j, `"verdict"`)
	if contentPos >= verdictPos {
		t.Error("content_hash should come before verdict in canonical JSON")
	}
}

func TestSerializationRoundtrip(t *testing.T) {
	receipt := makeTestReceipt()
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := Sign(receipt, kp)
	if err != nil {
		t.Fatal(err)
	}

	jsonStr, err := signed.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := SignedReceiptFromJSON(jsonStr)
	if err != nil {
		t.Fatal(err)
	}

	keys := NewPublicKeySet(kp.PublicKey())
	result := restored.Verify(keys)
	if !result.Valid {
		t.Errorf("restored receipt verification failed: %v", result.Errors)
	}
}

func TestVerdictConstructors(t *testing.T) {
	p := Pass()
	if !p.Passed {
		t.Error("Pass should be passed")
	}
	f := Fail()
	if f.Passed {
		t.Error("Fail should not be passed")
	}
	pg := PassWithGate("my-gate")
	if !pg.Passed || pg.GateID != "my-gate" {
		t.Error("PassWithGate wrong")
	}
	fg := FailWithGate("my-gate")
	if fg.Passed || fg.GateID != "my-gate" {
		t.Error("FailWithGate wrong")
	}
}

func TestReceiptBuilder(t *testing.T) {
	receipt := NewReceipt(crypto.Hash{}, Pass()).
		WithID("my-receipt").
		WithProvenance(Provenance{})

	if receipt.ReceiptID != "my-receipt" {
		t.Error("ID not set")
	}
	if receipt.Provenance == nil {
		t.Error("provenance not set")
	}
}

func TestValidateVersion(t *testing.T) {
	tests := []struct {
		version string
		wantErr bool
	}{
		{"1.0.0", false},
		{"2.0.0", true},
		{"1.1.0", true},
		{"abc", true},
		{"1.0", true},
		{"01.0.0", true},
		{"1.0.0.0", true},
		{"", true},
	}
	for _, tt := range tests {
		err := ValidateVersion(tt.version)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateVersion(%q) = %v, wantErr %v", tt.version, err, tt.wantErr)
		}
	}
}

func TestSignedReceiptFromJSONRejectsUnknownFields(t *testing.T) {
	// Create a valid signed receipt first
	receipt := makeTestReceipt()
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(receipt, kp)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr, err := signed.ToJSON()
	if err != nil {
		t.Fatal(err)
	}

	// Inject an unknown field at the top level
	injected := `{"unknown_field":"bad",` + jsonStr[1:]
	_, err = SignedReceiptFromJSON(injected)
	if err == nil {
		t.Error("expected error for unknown field in signed receipt JSON")
	}
}

func TestCosignerSigWithoutKeyFailsVerification(t *testing.T) {
	receipt := makeTestReceipt()
	signerKP, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cosignerKP, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	signed, err := Sign(receipt, signerKP)
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.AddCosigner(cosignerKP); err != nil {
		t.Fatal(err)
	}

	// Verify with only the signer key, no cosigner key
	keys := NewPublicKeySet(signerKP.PublicKey())
	result := signed.Verify(keys)

	if result.Valid {
		t.Error("expected invalid when cosigner signature present but no cosigner key provided")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors")
	}
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
