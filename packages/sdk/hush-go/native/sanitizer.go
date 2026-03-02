package native

import "encoding/json"

// SanitizationResult holds the parsed result from output sanitization.
type SanitizationResult struct {
	Sanitized   string          `json:"sanitized"`
	WasRedacted bool            `json:"was_redacted"`
	Findings    json.RawMessage `json:"findings"`
	Redactions  json.RawMessage `json:"redactions"`
	Stats       json.RawMessage `json:"stats"`
}

// OutputSanitizer wraps the native output sanitization.
type OutputSanitizer struct {
	configJSON string
}

// NewOutputSanitizer creates a new OutputSanitizer with default config.
func NewOutputSanitizer() *OutputSanitizer {
	return &OutputSanitizer{}
}

// NewOutputSanitizerWithConfig creates an OutputSanitizer with a JSON config.
func NewOutputSanitizerWithConfig(configJSON string) *OutputSanitizer {
	return &OutputSanitizer{configJSON: configJSON}
}

// Sanitize runs output sanitization on the given text.
func (s *OutputSanitizer) Sanitize(text string) (*SanitizationResult, error) {
	raw, err := SanitizeOutput(text, s.configJSON)
	if err != nil {
		return nil, err
	}

	var result SanitizationResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return &result, nil
}
