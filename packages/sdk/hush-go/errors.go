package hush

import "unsafe"

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
