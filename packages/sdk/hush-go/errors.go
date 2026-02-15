package hush

import (
	"errors"
	"unsafe"
)

var (
	// ErrKeypairNil is returned when a nil *Keypair is passed or used.
	ErrKeypairNil = errors.New("hush: keypair is nil")
	// ErrKeypairClosed is returned when a Keypair has been closed (its native handle is nil).
	ErrKeypairClosed = errors.New("hush: keypair is closed")
	// ErrCStringContainsNUL is returned when a string contains an interior NUL byte and cannot be
	// safely passed to C as a NUL-terminated string.
	ErrCStringContainsNUL = errors.New("hush: string contains NUL byte")
)

// HushError represents an error from the native hush-ffi library.
type HushError struct {
	Message string
}

func (e *HushError) Error() string { return e.Message }

// lastError retrieves the last error message from the native library.
// Returns a generic error if no message is available.
func lastError() error {
	msg := goStringFromC(ffiLastError())
	if msg == "" {
		msg = "hush-ffi: unknown error"
	}
	return &HushError{Message: msg}
}

// checkPtr checks if a C pointer is nil. If nil, it returns lastError.
func checkPtr(ptr unsafe.Pointer) error {
	if ptr == nil {
		return lastError()
	}
	return nil
}
