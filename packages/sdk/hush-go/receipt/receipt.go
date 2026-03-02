// Package receipt implements signed attestation receipts for Clawdstrike.
package receipt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/backbay/clawdstrike-go/canonical"
	"github.com/backbay/clawdstrike-go/crypto"
)

// SchemaVersion is the current receipt schema version.
const SchemaVersion = "1.0.0"

// ValidateVersion checks that a receipt version is supported. Fail-closed.
func ValidateVersion(version string) error {
	if !isValidSemver(version) {
		return fmt.Errorf("invalid receipt version format: %q", version)
	}
	if version != SchemaVersion {
		return fmt.Errorf("unsupported receipt version: %q (supported: %q)", version, SchemaVersion)
	}
	return nil
}

func isValidSemver(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		if len(p) > 1 && p[0] == '0' {
			return false
		}
		if _, err := strconv.ParseUint(p, 10, 64); err != nil {
			return false
		}
	}
	return true
}

// Verdict is the result from quality gates or guards.
type Verdict struct {
	Passed  bool             `json:"passed"`
	GateID  string           `json:"gate_id,omitempty"`
	Scores  *json.RawMessage `json:"scores,omitempty"`
	Threshold *float64       `json:"threshold,omitempty"`
}

// Pass creates a passing verdict.
func Pass() Verdict {
	return Verdict{Passed: true}
}

// Fail creates a failing verdict.
func Fail() Verdict {
	return Verdict{Passed: false}
}

// PassWithGate creates a passing verdict with a gate ID.
func PassWithGate(gateID string) Verdict {
	return Verdict{Passed: true, GateID: gateID}
}

// FailWithGate creates a failing verdict with a gate ID.
func FailWithGate(gateID string) Verdict {
	return Verdict{Passed: false, GateID: gateID}
}

// ViolationRef is a reference to a guard violation.
type ViolationRef struct {
	Guard    string `json:"guard"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Action   string `json:"action,omitempty"`
}

// Provenance contains execution environment information.
type Provenance struct {
	ClawdstrikeVersion string         `json:"clawdstrike_version,omitempty"`
	Provider           string         `json:"provider,omitempty"`
	PolicyHash         *crypto.Hash   `json:"policy_hash,omitempty"`
	Ruleset            string         `json:"ruleset,omitempty"`
	Violations         []ViolationRef `json:"violations,omitempty"`
}

// Receipt is an unsigned attestation of an execution.
type Receipt struct {
	Version     string           `json:"version"`
	ReceiptID   string           `json:"receipt_id,omitempty"`
	Timestamp   string           `json:"timestamp"`
	ContentHash crypto.Hash      `json:"content_hash"`
	Verdict     Verdict          `json:"verdict"`
	Provenance  *Provenance      `json:"provenance,omitempty"`
	Metadata    *json.RawMessage `json:"metadata,omitempty"`
}

// NewReceipt creates a new receipt with the current schema version and timestamp.
func NewReceipt(contentHash crypto.Hash, verdict Verdict) Receipt {
	return Receipt{
		Version:     SchemaVersion,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		ContentHash: contentHash,
		Verdict:     verdict,
	}
}

// WithID sets the receipt ID.
func (r Receipt) WithID(id string) Receipt {
	r.ReceiptID = id
	return r
}

// WithProvenance sets the provenance.
func (r Receipt) WithProvenance(p Provenance) Receipt {
	r.Provenance = &p
	return r
}

// WithMetadata sets the metadata from raw JSON.
func (r Receipt) WithMetadata(m json.RawMessage) Receipt {
	r.Metadata = &m
	return r
}

// ValidateVersion checks the receipt's schema version.
func (r *Receipt) ValidateVersion() error {
	return ValidateVersion(r.Version)
}

// ToCanonicalJSON serializes the receipt to canonical JSON. Validates version first.
func (r *Receipt) ToCanonicalJSON() (string, error) {
	if err := r.ValidateVersion(); err != nil {
		return "", err
	}
	return canonical.Canonicalize(r)
}

// HashSHA256 returns the SHA-256 of the canonical JSON.
func (r *Receipt) HashSHA256() (crypto.Hash, error) {
	s, err := r.ToCanonicalJSON()
	if err != nil {
		return crypto.Hash{}, err
	}
	return crypto.SHA256([]byte(s)), nil
}

// HashKeccak256 returns the Keccak-256 of the canonical JSON.
func (r *Receipt) HashKeccak256() (crypto.Hash, error) {
	s, err := r.ToCanonicalJSON()
	if err != nil {
		return crypto.Hash{}, err
	}
	return crypto.Keccak256([]byte(s)), nil
}

// Signatures on a receipt.
type Signatures struct {
	Signer   crypto.Signature  `json:"signer"`
	Cosigner *crypto.Signature `json:"cosigner,omitempty"`
}

// SignedReceipt is a receipt with cryptographic signatures.
type SignedReceipt struct {
	Receipt    Receipt    `json:"receipt"`
	Signatures Signatures `json:"signatures"`
}

// Sign creates a signed receipt.
func Sign(receipt Receipt, signer crypto.Signer) (*SignedReceipt, error) {
	if err := receipt.ValidateVersion(); err != nil {
		return nil, err
	}
	canonicalJSON, err := receipt.ToCanonicalJSON()
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}
	sig, err := signer.Sign([]byte(canonicalJSON))
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &SignedReceipt{
		Receipt:    receipt,
		Signatures: Signatures{Signer: sig},
	}, nil
}

// AddCosigner adds a co-signer signature.
func (sr *SignedReceipt) AddCosigner(signer crypto.Signer) error {
	if err := sr.Receipt.ValidateVersion(); err != nil {
		return err
	}
	canonicalJSON, err := sr.Receipt.ToCanonicalJSON()
	if err != nil {
		return fmt.Errorf("canonical JSON: %w", err)
	}
	sig, err := signer.Sign([]byte(canonicalJSON))
	if err != nil {
		return fmt.Errorf("cosign: %w", err)
	}
	sr.Signatures.Cosigner = &sig
	return nil
}

// PublicKeySet holds keys for verification.
type PublicKeySet struct {
	Signer   crypto.PublicKey
	Cosigner *crypto.PublicKey
}

// NewPublicKeySet creates a set with just the primary signer.
func NewPublicKeySet(signer crypto.PublicKey) PublicKeySet {
	return PublicKeySet{Signer: signer}
}

// WithCosigner adds a co-signer public key.
func (pks PublicKeySet) WithCosigner(cosigner crypto.PublicKey) PublicKeySet {
	pks.Cosigner = &cosigner
	return pks
}

// VerificationResult holds the outcome of receipt verification.
type VerificationResult struct {
	Valid          bool     `json:"valid"`
	SignerValid    bool     `json:"signer_valid"`
	CosignerValid *bool    `json:"cosigner_valid,omitempty"`
	Errors         []string `json:"errors,omitempty"`
}

// Verify checks all signatures on the receipt.
func (sr *SignedReceipt) Verify(keys PublicKeySet) VerificationResult {
	if err := sr.Receipt.ValidateVersion(); err != nil {
		return VerificationResult{
			Valid:  false,
			Errors: []string{err.Error()},
		}
	}

	canonicalJSON, err := sr.Receipt.ToCanonicalJSON()
	if err != nil {
		return VerificationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("failed to serialize receipt: %v", err)},
		}
	}
	message := []byte(canonicalJSON)

	result := VerificationResult{Valid: true}

	// Verify primary signature
	result.SignerValid = keys.Signer.Verify(message, &sr.Signatures.Signer)
	if !result.SignerValid {
		result.Valid = false
		result.Errors = append(result.Errors, "Invalid signer signature")
	}

	// Verify co-signer (optional)
	if sr.Signatures.Cosigner != nil && keys.Cosigner != nil {
		valid := keys.Cosigner.Verify(message, sr.Signatures.Cosigner)
		result.CosignerValid = &valid
		if !valid {
			result.Valid = false
			result.Errors = append(result.Errors, "Invalid cosigner signature")
		}
	}

	return result
}

// ToJSON serializes the signed receipt to pretty-printed JSON.
func (sr *SignedReceipt) ToJSON() (string, error) {
	data, err := json.MarshalIndent(sr, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SignedReceiptFromJSON parses a signed receipt from JSON.
func SignedReceiptFromJSON(data string) (*SignedReceipt, error) {
	var sr SignedReceipt
	if err := json.Unmarshal([]byte(data), &sr); err != nil {
		return nil, err
	}
	return &sr, nil
}

var (
	ErrUnsupportedVersion = errors.New("unsupported receipt version")
	ErrInvalidVersion     = errors.New("invalid receipt version")
)
