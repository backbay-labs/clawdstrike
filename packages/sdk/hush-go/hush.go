package hush

import "runtime"

// Version returns the hush-ffi library version string.
func Version() string {
	// Ensure hush_last_error thread-local semantics are not disrupted by callers.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return goStringFromC(ffiVersion())
}

// IsAvailable returns true if the native library is loaded and functional.
func IsAvailable() (available bool) {
	defer func() {
		if r := recover(); r != nil {
			available = false
		}
	}()
	v := Version()
	return v != ""
}
