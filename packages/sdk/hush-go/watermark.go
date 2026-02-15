package hush

import "runtime"

// WatermarkPublicKey returns the public key hex for a watermark configuration.
func WatermarkPublicKey(configJSON string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cc, err := allocCString(configJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cc)

	p := ffiWatermarkPublicKey(cc)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// WatermarkPrompt watermarks a prompt with the given configuration.
// appID and sessionID are optional (pass nil for "unknown").
func WatermarkPrompt(prompt, configJSON string, appID, sessionID *string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cp, err := allocCString(prompt)
	if err != nil {
		return "", err
	}
	defer freeCString(cp)
	cc, err := allocCString(configJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cc)
	ca, err := allocCStringOpt(appID)
	if err != nil {
		return "", err
	}
	defer freeCString(ca)
	cs, err := allocCStringOpt(sessionID)
	if err != nil {
		return "", err
	}
	defer freeCString(cs)

	p := ffiWatermarkPrompt(cp, cc, ca, cs)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}

// ExtractWatermark extracts and verifies a watermark from text.
// Returns the watermark data as a JSON string.
func ExtractWatermark(text, configJSON string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ct, err := allocCString(text)
	if err != nil {
		return "", err
	}
	defer freeCString(ct)
	cc, err := allocCString(configJSON)
	if err != nil {
		return "", err
	}
	defer freeCString(cc)

	p := ffiExtractWatermark(ct, cc)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}
