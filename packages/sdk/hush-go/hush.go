package hush

// Version returns the hush-ffi library version string.
func Version() string {
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
