package native

import "encoding/json"

// WatermarkResult holds the parsed result from watermark extraction.
type WatermarkResult struct {
	Detected   bool            `json:"detected"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Confidence float64         `json:"confidence"`
}

// Watermarker wraps the native watermarking functions.
type Watermarker struct {
	configJSON string
}

// NewWatermarker creates a new Watermarker with default config.
func NewWatermarker() *Watermarker {
	return &Watermarker{}
}

// NewWatermarkerWithConfig creates a Watermarker with a JSON config.
func NewWatermarkerWithConfig(configJSON string) *Watermarker {
	return &Watermarker{configJSON: configJSON}
}

// PublicKey returns the watermark public key.
func (w *Watermarker) PublicKey() (string, error) {
	return WatermarkPublicKey(w.configJSON)
}

// WatermarkPromptText watermarks a prompt with the given identifiers.
func (w *Watermarker) WatermarkPromptText(prompt, appID, sessionID string) (string, error) {
	return WatermarkPrompt(prompt, w.configJSON, appID, sessionID)
}

// Extract extracts a watermark from the given text.
func (w *Watermarker) Extract(text string) (*WatermarkResult, error) {
	raw, err := ExtractWatermark(text, w.configJSON)
	if err != nil {
		return nil, err
	}

	var result WatermarkResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return &result, nil
}
