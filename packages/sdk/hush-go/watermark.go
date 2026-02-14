package hush

// WatermarkPublicKey returns the public key hex for a watermark configuration.
func WatermarkPublicKey(configJSON string) (string, error) {
	cc := allocCString(configJSON)
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
	cp := allocCString(prompt)
	defer freeCString(cp)
	cc := allocCString(configJSON)
	defer freeCString(cc)
	ca := allocCStringOpt(appID)
	defer freeCString(ca)
	cs := allocCStringOpt(sessionID)
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
	ct := allocCString(text)
	defer freeCString(ct)
	cc := allocCString(configJSON)
	defer freeCString(cc)

	p := ffiExtractWatermark(ct, cc)
	if p == nil {
		return "", lastError()
	}
	return goStringFromCFree(p), nil
}
