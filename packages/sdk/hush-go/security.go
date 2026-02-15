package hush

import "runtime"

// DetectJailbreak analyzes text for jailbreak attempts.
// sessionID and configJSON are optional (pass nil to use defaults).
// Returns the detection result as a JSON string.
func DetectJailbreak(text string, sessionID, configJSON *string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ct, err := allocCString(text)
	if err != nil {
		return "", err
	}
	defer freeCString(ct)
	cs, err := allocCStringOpt(sessionID)
	if err != nil {
		return "", err
	}
	defer freeCString(cs)
	cc, err := allocCStringOpt(configJSON)
	if err != nil {
		return "", err
	}
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

	ct, err := allocCString(text)
	if err != nil {
		return "", err
	}
	defer freeCString(ct)
	cc, err := allocCStringOpt(configJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cc)

	p := ffiSanitizeOutput(ct, cc)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}
