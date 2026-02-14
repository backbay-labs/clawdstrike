package hush

import "runtime"

// DetectJailbreak analyzes text for jailbreak attempts.
// sessionID and configJSON are optional (pass nil to use defaults).
// Returns the detection result as a JSON string.
func DetectJailbreak(text string, sessionID, configJSON *string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ct := allocCString(text)
	defer freeCString(ct)
	cs := allocCStringOpt(sessionID)
	defer freeCString(cs)
	cc := allocCStringOpt(configJSON)
	defer freeCString(cc)

	p := ffiDetectJailbreak(ct, cs, cc)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// SanitizeOutput sanitizes model output for sensitive data.
// configJSON is optional (pass nil for defaults).
// Returns the sanitized text as a JSON string.
func SanitizeOutput(text string, configJSON *string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ct := allocCString(text)
	defer freeCString(ct)
	cc := allocCStringOpt(configJSON)
	defer freeCString(cc)

	p := ffiSanitizeOutput(ct, cc)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}
