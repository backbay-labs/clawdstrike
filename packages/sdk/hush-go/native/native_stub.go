//go:build !cgo

// Package native provides CGo bindings to the Rust hush-go-native library.
//
// This file is the fallback when CGO is disabled. All functions return
// ErrNativeUnavailable. The pure-Go implementations in the crypto, canonical,
// and merkle packages should be used instead.
package native

import "errors"

// ErrNativeUnavailable is returned when CGo is not available.
var ErrNativeUnavailable = errors.New("native: CGo not available, build with CGO_ENABLED=1")

// ErrNativeError is returned when a native function returns null (error).
// Defined here to keep the API surface identical across build tags.
var ErrNativeError = errors.New("native: operation failed")

// IsAvailable returns false when CGo is disabled.
func IsAvailable() bool { return false }

// SHA256 is not available without CGo.
func SHA256(data []byte) (string, error) { return "", ErrNativeUnavailable }

// Keccak256 is not available without CGo.
func Keccak256(data []byte) (string, error) { return "", ErrNativeUnavailable }

// VerifyEd25519 is not available without CGo.
func VerifyEd25519(msg []byte, sigHex, pkHex string) bool { return false }

// Canonicalize is not available without CGo.
func Canonicalize(jsonStr string) (string, error) { return "", ErrNativeUnavailable }

// MerkleRoot is not available without CGo.
func MerkleRoot(leafHexes []string) (string, error) { return "", ErrNativeUnavailable }

// GenerateMerkleProof is not available without CGo.
func GenerateMerkleProof(leafHexes []string, index int) (string, error) {
	return "", ErrNativeUnavailable
}

// VerifyReceipt is not available without CGo.
func VerifyReceipt(receiptJSON, sigHex, pkHex string) bool { return false }

// DetectJailbreak is not available without CGo.
func DetectJailbreak(text, sessionID, configJSON string) (string, error) {
	return "", ErrNativeUnavailable
}

// SanitizeOutput is not available without CGo.
func SanitizeOutput(text, configJSON string) (string, error) { return "", ErrNativeUnavailable }

// WatermarkPublicKey is not available without CGo.
func WatermarkPublicKey(configJSON string) (string, error) { return "", ErrNativeUnavailable }

// WatermarkPrompt is not available without CGo.
func WatermarkPrompt(prompt, configJSON, appID, sessionID string) (string, error) {
	return "", ErrNativeUnavailable
}

// ExtractWatermark is not available without CGo.
func ExtractWatermark(text, configJSON string) (string, error) { return "", ErrNativeUnavailable }
