package hush

import (
	"runtime"
	"sync"
	"unsafe"
)

// Sha256 computes the SHA-256 hash of data, returning 32 bytes.
func Sha256(data []byte) ([32]byte, error) {
	// Ensure any follow-up hush_last_error() call happens on the same OS thread
	// as the failing FFI call (native errors are thread-local).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var out [32]byte
	rc := ffiSha256(cBytesPtr(data), len(data), unsafe.Pointer(&out[0]))
	if rc != 0 {
		return out, lastError()
	}
	return out, nil
}

// Sha256Hex computes the SHA-256 hash of data and returns the hex string.
func Sha256Hex(data []byte) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	p := ffiSha256Hex(cBytesPtr(data), len(data))
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// Keccak256 computes the Keccak-256 hash of data, returning 32 bytes.
func Keccak256(data []byte) ([32]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var out [32]byte
	rc := ffiKeccak256(cBytesPtr(data), len(data), unsafe.Pointer(&out[0]))
	if rc != 0 {
		return out, lastError()
	}
	return out, nil
}

// Keccak256Hex computes the Keccak-256 hash of data and returns the hex string.
func Keccak256Hex(data []byte) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	p := ffiKeccak256Hex(cBytesPtr(data), len(data))
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// CanonicalizeJSON canonicalizes a JSON string per RFC 8785 (JCS).
func CanonicalizeJSON(json string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cj, err := allocCString(json)
	if err != nil {
		return "", err
	}
	defer freeCString(cj)
	p := ffiCanonicalizeJSON(cj)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// Keypair wraps an opaque hush-ffi Ed25519 keypair handle.
// Call Close() to explicitly destroy the keypair and zero key material.
// The finalizer will also destroy it on GC if Close() was not called.
type Keypair struct {
	mu  sync.RWMutex
	ptr unsafe.Pointer
}

func (kp *Keypair) rlockPtrOrErr() (unsafe.Pointer, func(), error) {
	if kp == nil {
		return nil, func() {}, ErrKeypairNil
	}

	kp.mu.RLock()
	if kp.ptr == nil {
		kp.mu.RUnlock()
		return nil, func() {}, ErrKeypairClosed
	}
	return kp.ptr, kp.mu.RUnlock, nil
}

func newKeypair(ptr unsafe.Pointer) *Keypair {
	kp := &Keypair{ptr: ptr}
	runtime.SetFinalizer(kp, (*Keypair).Close)
	return kp
}

// GenerateKeypair creates a new random Ed25519 keypair.
func GenerateKeypair() (*Keypair, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptr := ffiKeypairGenerate()
	if err := checkPtr(ptr); err != nil {
		return nil, err
	}
	return newKeypair(ptr), nil
}

// KeypairFromSeed creates a keypair from a 32-byte seed.
func KeypairFromSeed(seed [32]byte) (*Keypair, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ptr := ffiKeypairFromSeed(unsafe.Pointer(&seed[0]))
	if err := checkPtr(ptr); err != nil {
		return nil, err
	}
	return newKeypair(ptr), nil
}

// KeypairFromHex creates a keypair from a hex-encoded seed string.
func KeypairFromHex(hex string) (*Keypair, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ch, err := allocCString(hex)
	if err != nil {
		return nil, err
	}
	defer freeCString(ch)
	ptr := ffiKeypairFromHex(ch)
	if err := checkPtr(ptr); err != nil {
		return nil, err
	}
	return newKeypair(ptr), nil
}

// PublicKeyHex returns the public key as a hex-encoded string.
func (kp *Keypair) PublicKeyHex() (string, error) {
	ptr, unlock, err := kp.rlockPtrOrErr()
	if err != nil {
		return "", err
	}
	defer unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	p := ffiKeypairPublicKeyHex(ptr)
	runtime.KeepAlive(kp)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// PublicKeyBytes returns the 32-byte public key.
func (kp *Keypair) PublicKeyBytes() ([32]byte, error) {
	var out [32]byte
	ptr, unlock, err := kp.rlockPtrOrErr()
	if err != nil {
		return out, err
	}
	defer unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rc := ffiKeypairPublicKeyBytes(ptr, unsafe.Pointer(&out[0]))
	runtime.KeepAlive(kp)
	if rc != 0 {
		return out, lastError()
	}
	return out, nil
}

// SignHex signs a message and returns the hex-encoded signature.
func (kp *Keypair) SignHex(msg []byte) (string, error) {
	ptr, unlock, err := kp.rlockPtrOrErr()
	if err != nil {
		return "", err
	}
	defer unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	p := ffiKeypairSignHex(ptr, cBytesPtr(msg), len(msg))
	runtime.KeepAlive(kp)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// Sign signs a message and returns the 64-byte signature.
func (kp *Keypair) Sign(msg []byte) ([64]byte, error) {
	var out [64]byte
	ptr, unlock, err := kp.rlockPtrOrErr()
	if err != nil {
		return out, err
	}
	defer unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rc := ffiKeypairSign(ptr, cBytesPtr(msg), len(msg), unsafe.Pointer(&out[0]))
	runtime.KeepAlive(kp)
	if rc != 0 {
		return out, lastError()
	}
	return out, nil
}

// ToHex exports the keypair seed as a hex-encoded string.
func (kp *Keypair) ToHex() (string, error) {
	ptr, unlock, err := kp.rlockPtrOrErr()
	if err != nil {
		return "", err
	}
	defer unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	p := ffiKeypairToHex(ptr)
	runtime.KeepAlive(kp)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// Close explicitly destroys the keypair, zeroing key material.
// Safe to call multiple times.
func (kp *Keypair) Close() {
	if kp == nil {
		return
	}

	kp.mu.Lock()
	defer kp.mu.Unlock()

	if kp.ptr != nil {
		// Keep hush_last_error thread-local semantics consistent across all FFI calls.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ffiKeypairDestroy(kp.ptr)
		kp.ptr = nil
		runtime.SetFinalizer(kp, nil)
	}
}

// VerifyEd25519 verifies an Ed25519 signature using hex-encoded inputs.
// Returns true if the signature is valid.
func VerifyEd25519(pubkeyHex string, msg []byte, sigHex string) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cpk, err := allocCString(pubkeyHex)
	if err != nil {
		return false, err
	}
	defer freeCString(cpk)
	csig, err := allocCString(sigHex)
	if err != nil {
		return false, err
	}
	defer freeCString(csig)
	rc := ffiVerifyEd25519(cpk, cBytesPtr(msg), len(msg), csig)
	switch rc {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, lastError()
	}
}

// VerifyEd25519Bytes verifies an Ed25519 signature using raw byte inputs.
// Returns true if the signature is valid.
func VerifyEd25519Bytes(pubkey [32]byte, msg []byte, sig [64]byte) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rc := ffiVerifyEd25519Bytes(
		unsafe.Pointer(&pubkey[0]),
		cBytesPtr(msg),
		len(msg),
		unsafe.Pointer(&sig[0]),
	)
	switch rc {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, lastError()
	}
}
