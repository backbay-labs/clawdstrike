//go:build cgo

// Package native provides CGo bindings to the Rust hush-go-native library.
//
// When built with CGO_ENABLED=1 and the static library present in native/lib/,
// all functions delegate to the Rust implementation for performance and
// cross-language determinism. When CGO is disabled, the stub file provides
// fallbacks that return ErrNativeUnavailable.
package native

/*
#cgo LDFLAGS: -L${SRCDIR}/lib -lhush_go_native -ldl -lm -lpthread
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#include "include/hush_go_native.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"errors"
	"unsafe"
)

// ErrNativeError is returned when a native function returns null (error).
var ErrNativeError = errors.New("native: operation failed")

// IsAvailable returns true when the native Rust library is linked.
func IsAvailable() bool {
	return bool(C.hush_is_available())
}

// SHA256 computes SHA-256 of data via the Rust implementation.
// Returns a 0x-prefixed hex string.
func SHA256(data []byte) (string, error) {
	var cResult *C.char
	if len(data) == 0 {
		cResult = C.hush_sha256(nil, 0)
	} else {
		cResult = C.hush_sha256((*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	}
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}

// Keccak256 computes Keccak-256 of data via the Rust implementation.
// Returns a 0x-prefixed hex string.
func Keccak256(data []byte) (string, error) {
	var cResult *C.char
	if len(data) == 0 {
		cResult = C.hush_keccak256(nil, 0)
	} else {
		cResult = C.hush_keccak256((*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	}
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}

// VerifyEd25519 verifies an Ed25519 signature using the Rust implementation.
// sigHex and pkHex are hex-encoded (with or without 0x prefix).
func VerifyEd25519(msg []byte, sigHex, pkHex string) bool {
	cSig := C.CString(sigHex)
	defer C.free(unsafe.Pointer(cSig))
	cPk := C.CString(pkHex)
	defer C.free(unsafe.Pointer(cPk))

	var result C.bool
	if len(msg) == 0 {
		result = C.hush_verify_ed25519(nil, 0, cSig, cPk)
	} else {
		result = C.hush_verify_ed25519(
			(*C.uchar)(unsafe.Pointer(&msg[0])),
			C.size_t(len(msg)),
			cSig,
			cPk,
		)
	}
	return bool(result)
}

// Canonicalize performs RFC 8785 canonical JSON via the Rust implementation.
func Canonicalize(jsonStr string) (string, error) {
	cJSON := C.CString(jsonStr)
	defer C.free(unsafe.Pointer(cJSON))

	cResult := C.hush_canonicalize(cJSON)
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}

// MerkleRoot computes a Merkle root from a list of hex-encoded leaf hashes.
// Returns a 0x-prefixed hex string.
func MerkleRoot(leafHexes []string) (string, error) {
	jsonBytes, err := json.Marshal(leafHexes)
	if err != nil {
		return "", err
	}

	cJSON := C.CString(string(jsonBytes))
	defer C.free(unsafe.Pointer(cJSON))

	cResult := C.hush_merkle_root(cJSON)
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}

// GenerateMerkleProof generates a Merkle inclusion proof for a leaf at the given index.
// Returns a JSON string of the proof.
func GenerateMerkleProof(leafHexes []string, index int) (string, error) {
	jsonBytes, err := json.Marshal(leafHexes)
	if err != nil {
		return "", err
	}

	cJSON := C.CString(string(jsonBytes))
	defer C.free(unsafe.Pointer(cJSON))

	cResult := C.hush_generate_merkle_proof(cJSON, C.size_t(index))
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}

// VerifyReceipt verifies a receipt signature.
// receiptJSON is the canonical JSON of the receipt body.
// sigHex and pkHex are hex-encoded Ed25519 signature and public key.
func VerifyReceipt(receiptJSON, sigHex, pkHex string) bool {
	cReceipt := C.CString(receiptJSON)
	defer C.free(unsafe.Pointer(cReceipt))
	cSig := C.CString(sigHex)
	defer C.free(unsafe.Pointer(cSig))
	cPk := C.CString(pkHex)
	defer C.free(unsafe.Pointer(cPk))

	return bool(C.hush_verify_receipt(cReceipt, cSig, cPk))
}

// DetectJailbreak runs jailbreak detection on the given text.
// sessionID may be empty. configJSON may be empty for defaults.
// Returns the raw JSON result string.
func DetectJailbreak(text, sessionID, configJSON string) (string, error) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	var cSession *C.char
	if sessionID != "" {
		cSession = C.CString(sessionID)
		defer C.free(unsafe.Pointer(cSession))
	}

	var cConfig *C.char
	if configJSON != "" {
		cConfig = C.CString(configJSON)
		defer C.free(unsafe.Pointer(cConfig))
	}

	cResult := C.hush_detect_jailbreak(cText, cSession, cConfig)
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}

// SanitizeOutput runs output sanitization on the given text.
// configJSON may be empty for defaults.
// Returns the raw JSON result string.
func SanitizeOutput(text, configJSON string) (string, error) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	var cConfig *C.char
	if configJSON != "" {
		cConfig = C.CString(configJSON)
		defer C.free(unsafe.Pointer(cConfig))
	}

	cResult := C.hush_sanitize_output(cText, cConfig)
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}

// WatermarkPublicKey returns the watermark public key (stub).
func WatermarkPublicKey(configJSON string) (string, error) {
	var cConfig *C.char
	if configJSON != "" {
		cConfig = C.CString(configJSON)
		defer C.free(unsafe.Pointer(cConfig))
	}

	cResult := C.hush_watermark_public_key(cConfig)
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}

// WatermarkPrompt watermarks a prompt (stub).
func WatermarkPrompt(prompt, configJSON, appID, sessionID string) (string, error) {
	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))

	var cConfig *C.char
	if configJSON != "" {
		cConfig = C.CString(configJSON)
		defer C.free(unsafe.Pointer(cConfig))
	}

	cAppID := C.CString(appID)
	defer C.free(unsafe.Pointer(cAppID))
	cSessionID := C.CString(sessionID)
	defer C.free(unsafe.Pointer(cSessionID))

	cResult := C.hush_watermark_prompt(cPrompt, cConfig, cAppID, cSessionID)
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}

// ExtractWatermark extracts a watermark from text (stub).
func ExtractWatermark(text, configJSON string) (string, error) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	var cConfig *C.char
	if configJSON != "" {
		cConfig = C.CString(configJSON)
		defer C.free(unsafe.Pointer(cConfig))
	}

	cResult := C.hush_extract_watermark(cText, cConfig)
	if cResult == nil {
		return "", ErrNativeError
	}
	defer C.hush_free_string(cResult)
	return C.GoString(cResult), nil
}
