package hush

/*
#cgo LDFLAGS: -lhush_ffi
#include <stdlib.h>
#include <stdint.h>

// Infra
extern const char* hush_last_error(void);
extern void hush_free_string(char* ptr);
extern const char* hush_version(void);

// Hashing
extern int32_t hush_sha256(const uint8_t* data, uintptr_t len, uint8_t* out_32);
extern char* hush_sha256_hex(const uint8_t* data, uintptr_t len);
extern int32_t hush_keccak256(const uint8_t* data, uintptr_t len, uint8_t* out_32);
extern char* hush_keccak256_hex(const uint8_t* data, uintptr_t len);
extern char* hush_canonicalize_json(const char* json);

// Keypair
extern void* hush_keypair_generate(void);
extern void* hush_keypair_from_seed(const uint8_t* seed_32);
extern void* hush_keypair_from_hex(const char* hex);
extern char* hush_keypair_public_key_hex(const void* kp);
extern int32_t hush_keypair_public_key_bytes(const void* kp, uint8_t* out_32);
extern char* hush_keypair_sign_hex(const void* kp, const uint8_t* msg, uintptr_t len);
extern int32_t hush_keypair_sign(const void* kp, const uint8_t* msg, uintptr_t len, uint8_t* out_64);
extern char* hush_keypair_to_hex(const void* kp);
extern void hush_keypair_destroy(void* kp);

// Verify
extern int32_t hush_verify_ed25519(const char* pk_hex, const uint8_t* msg, uintptr_t msg_len, const char* sig_hex);
extern int32_t hush_verify_ed25519_bytes(const uint8_t* pk_32, const uint8_t* msg, uintptr_t msg_len, const uint8_t* sig_64);

// Receipt
extern char* hush_verify_receipt(const char* receipt_json, const char* signer_hex, const char* cosigner_hex);
extern char* hush_sign_receipt(const char* receipt_json, const void* kp);
extern char* hush_hash_receipt(const char* receipt_json, const char* algorithm);
extern char* hush_receipt_canonical_json(const char* receipt_json);

// Merkle
extern char* hush_merkle_root(const char* leaf_hashes_json);
extern char* hush_merkle_proof(const char* leaf_hashes_json, uintptr_t index);
extern int32_t hush_verify_merkle_proof(const char* leaf_hex, const char* proof_json, const char* root_hex);

// Security
extern char* hush_detect_jailbreak(const char* text, const char* session_id, const char* config_json);
extern char* hush_sanitize_output(const char* text, const char* config_json);

// Watermark
extern char* hush_watermark_public_key(const char* config_json);
extern char* hush_watermark_prompt(const char* prompt, const char* config_json, const char* app_id, const char* session_id);
extern char* hush_extract_watermark(const char* text, const char* config_json);
*/
import "C"
import (
	"strings"
	"unsafe"
)

// ---------------------------------------------------------------------------
// C string helpers -- only file with import "C"
// ---------------------------------------------------------------------------

// allocCString allocates a C string from a Go string. Caller must free with freeCString.
func allocCString(s string) (unsafe.Pointer, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return nil, ErrCStringContainsNUL
	}
	return unsafe.Pointer(C.CString(s)), nil
}

// allocCStringOpt allocates a C string from a Go *string. nil input -> nil pointer.
// Caller must free non-nil results with freeCString.
func allocCStringOpt(s *string) (unsafe.Pointer, error) {
	if s == nil {
		return nil, nil
	}
	return allocCString(*s)
}

// freeCString frees a C string allocated by allocCString. Safe to call with nil.
func freeCString(p unsafe.Pointer) {
	if p != nil {
		C.free(p)
	}
}

// goStringFromC converts a C char* to Go string without freeing.
func goStringFromC(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	return C.GoString((*C.char)(p))
}

// goStringFromCFree converts a callee-allocated C char* to Go string and frees it
// via hush_free_string.
func goStringFromCFree(p unsafe.Pointer) string {
	if p == nil {
		return ""
	}
	s := C.GoString((*C.char)(p))
	C.hush_free_string((*C.char)(p))
	return s
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

// cBytesPtr returns an unsafe.Pointer to the first element of a byte slice,
// or nil if the slice is empty.
func cBytesPtr(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}

// ---------------------------------------------------------------------------
// Bridge functions -- thin wrappers so other .go files never touch C.xxx
// ---------------------------------------------------------------------------

// Infra
func ffiVersion() unsafe.Pointer   { return unsafe.Pointer(C.hush_version()) }
func ffiLastError() unsafe.Pointer { return unsafe.Pointer(C.hush_last_error()) }

// Hashing
func ffiSha256(data unsafe.Pointer, dlen int, out unsafe.Pointer) int32 {
	return int32(C.hush_sha256((*C.uint8_t)(data), C.uintptr_t(dlen), (*C.uint8_t)(out)))
}
func ffiSha256Hex(data unsafe.Pointer, dlen int) unsafe.Pointer {
	return unsafe.Pointer(C.hush_sha256_hex((*C.uint8_t)(data), C.uintptr_t(dlen)))
}
func ffiKeccak256(data unsafe.Pointer, dlen int, out unsafe.Pointer) int32 {
	return int32(C.hush_keccak256((*C.uint8_t)(data), C.uintptr_t(dlen), (*C.uint8_t)(out)))
}
func ffiKeccak256Hex(data unsafe.Pointer, dlen int) unsafe.Pointer {
	return unsafe.Pointer(C.hush_keccak256_hex((*C.uint8_t)(data), C.uintptr_t(dlen)))
}
func ffiCanonicalizeJSON(json unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_canonicalize_json((*C.char)(json)))
}

// Keypair
func ffiKeypairGenerate() unsafe.Pointer {
	return C.hush_keypair_generate()
}
func ffiKeypairFromSeed(seed unsafe.Pointer) unsafe.Pointer {
	return C.hush_keypair_from_seed((*C.uint8_t)(seed))
}
func ffiKeypairFromHex(hex unsafe.Pointer) unsafe.Pointer {
	return C.hush_keypair_from_hex((*C.char)(hex))
}
func ffiKeypairPublicKeyHex(kp unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_keypair_public_key_hex(kp))
}
func ffiKeypairPublicKeyBytes(kp unsafe.Pointer, out unsafe.Pointer) int32 {
	return int32(C.hush_keypair_public_key_bytes(kp, (*C.uint8_t)(out)))
}
func ffiKeypairSignHex(kp unsafe.Pointer, msg unsafe.Pointer, mlen int) unsafe.Pointer {
	return unsafe.Pointer(C.hush_keypair_sign_hex(kp, (*C.uint8_t)(msg), C.uintptr_t(mlen)))
}
func ffiKeypairSign(kp unsafe.Pointer, msg unsafe.Pointer, mlen int, out unsafe.Pointer) int32 {
	return int32(C.hush_keypair_sign(kp, (*C.uint8_t)(msg), C.uintptr_t(mlen), (*C.uint8_t)(out)))
}
func ffiKeypairToHex(kp unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_keypair_to_hex(kp))
}
func ffiKeypairDestroy(kp unsafe.Pointer) {
	C.hush_keypair_destroy(kp)
}

// Verify
func ffiVerifyEd25519(pkHex unsafe.Pointer, msg unsafe.Pointer, msgLen int, sigHex unsafe.Pointer) int32 {
	return int32(C.hush_verify_ed25519((*C.char)(pkHex), (*C.uint8_t)(msg), C.uintptr_t(msgLen), (*C.char)(sigHex)))
}
func ffiVerifyEd25519Bytes(pk unsafe.Pointer, msg unsafe.Pointer, msgLen int, sig unsafe.Pointer) int32 {
	return int32(C.hush_verify_ed25519_bytes((*C.uint8_t)(pk), (*C.uint8_t)(msg), C.uintptr_t(msgLen), (*C.uint8_t)(sig)))
}

// Receipt
func ffiVerifyReceipt(receiptJSON, signerHex, cosignerHex unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_verify_receipt((*C.char)(receiptJSON), (*C.char)(signerHex), (*C.char)(cosignerHex)))
}
func ffiSignReceipt(receiptJSON unsafe.Pointer, kp unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_sign_receipt((*C.char)(receiptJSON), kp))
}
func ffiHashReceipt(receiptJSON, algorithm unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_hash_receipt((*C.char)(receiptJSON), (*C.char)(algorithm)))
}
func ffiReceiptCanonicalJSON(receiptJSON unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_receipt_canonical_json((*C.char)(receiptJSON)))
}

// Merkle
func ffiMerkleRoot(leafHashesJSON unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_merkle_root((*C.char)(leafHashesJSON)))
}
func ffiMerkleProof(leafHashesJSON unsafe.Pointer, index int) unsafe.Pointer {
	return unsafe.Pointer(C.hush_merkle_proof((*C.char)(leafHashesJSON), C.uintptr_t(index)))
}
func ffiVerifyMerkleProof(leafHex, proofJSON, rootHex unsafe.Pointer) int32 {
	return int32(C.hush_verify_merkle_proof((*C.char)(leafHex), (*C.char)(proofJSON), (*C.char)(rootHex)))
}

// Security
func ffiDetectJailbreak(text, sessionID, configJSON unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_detect_jailbreak((*C.char)(text), (*C.char)(sessionID), (*C.char)(configJSON)))
}
func ffiSanitizeOutput(text, configJSON unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_sanitize_output((*C.char)(text), (*C.char)(configJSON)))
}

// Watermark
func ffiWatermarkPublicKey(configJSON unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_watermark_public_key((*C.char)(configJSON)))
}
func ffiWatermarkPrompt(prompt, configJSON, appID, sessionID unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_watermark_prompt((*C.char)(prompt), (*C.char)(configJSON), (*C.char)(appID), (*C.char)(sessionID)))
}
func ffiExtractWatermark(text, configJSON unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(C.hush_extract_watermark((*C.char)(text), (*C.char)(configJSON)))
}
