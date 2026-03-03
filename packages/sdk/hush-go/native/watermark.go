package native

import "encoding/json"

// EncodedWatermark mirrors the Rust/TS/Python watermark payload envelope.
type EncodedWatermark struct {
	Payload              json.RawMessage `json:"payload"`
	Encoding             string          `json:"encoding"`
	EncodedDataBase64URL string          `json:"encodedDataBase64Url"`
	Signature            string          `json:"signature"`
	PublicKey            string          `json:"publicKey"`
	Fingerprint          string          `json:"fingerprint"`
}

// WatermarkedPrompt is the result returned by native watermarking.
type WatermarkedPrompt struct {
	Original    string           `json:"original"`
	Watermarked string           `json:"watermarked"`
	Watermark   EncodedWatermark `json:"watermark"`
}

// WatermarkResult is the parsed result from watermark extraction and verification.
type WatermarkResult struct {
	Found     bool              `json:"found"`
	Verified  bool              `json:"verified"`
	Errors    []string          `json:"errors"`
	Watermark *EncodedWatermark `json:"watermark,omitempty"`
}

// Watermarker wraps the native watermarking functions.
type Watermarker struct {
	configJSON string
}

// PromptWatermarker is a naming alias that matches TS/Python SDK ergonomics.
type PromptWatermarker = Watermarker

// NewWatermarker creates a new Watermarker with default config.
func NewWatermarker() *Watermarker {
	return &Watermarker{}
}

// NewPromptWatermarker creates a new PromptWatermarker with default config.
func NewPromptWatermarker() *PromptWatermarker {
	return &PromptWatermarker{}
}

// NewWatermarkerWithConfig creates a Watermarker with a JSON config.
func NewWatermarkerWithConfig(configJSON string) *Watermarker {
	return &Watermarker{configJSON: configJSON}
}

// NewPromptWatermarkerWithConfig creates a PromptWatermarker with a JSON config.
func NewPromptWatermarkerWithConfig(configJSON string) *PromptWatermarker {
	return &PromptWatermarker{configJSON: configJSON}
}

// PublicKey returns the watermark public key.
func (w *Watermarker) PublicKey() (string, error) {
	return WatermarkPublicKey(w.configJSON)
}

// WatermarkPromptText watermarks a prompt with the given identifiers and returns raw JSON.
func (w *Watermarker) WatermarkPromptText(prompt, appID, sessionID string) (string, error) {
	return WatermarkPrompt(prompt, w.configJSON, appID, sessionID)
}

// Watermark applies watermarking and returns a parsed result.
func (w *Watermarker) Watermark(prompt, appID, sessionID string) (*WatermarkedPrompt, error) {
	raw, err := w.WatermarkPromptText(prompt, appID, sessionID)
	if err != nil {
		return nil, err
	}

	var result WatermarkedPrompt
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExtractRaw extracts and verifies a watermark, returning the raw JSON response.
func (w *Watermarker) ExtractRaw(text string) (string, error) {
	return ExtractWatermark(text, w.configJSON)
}

// Extract extracts and verifies a watermark from the given text.
func (w *Watermarker) Extract(text string) (*WatermarkResult, error) {
	raw, err := w.ExtractRaw(text)
	if err != nil {
		return nil, err
	}

	var result WatermarkResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// WatermarkExtractor extracts and verifies watermarks.
type WatermarkExtractor struct {
	configJSON string
}

// NewWatermarkExtractor creates an extractor with default verification config.
func NewWatermarkExtractor() *WatermarkExtractor {
	return &WatermarkExtractor{}
}

// NewWatermarkExtractorWithConfig creates an extractor with JSON verifier config.
func NewWatermarkExtractorWithConfig(configJSON string) *WatermarkExtractor {
	return &WatermarkExtractor{configJSON: configJSON}
}

// Extract parses and verifies a watermark from text.
func (e *WatermarkExtractor) Extract(text string) (*WatermarkResult, error) {
	raw, err := ExtractWatermark(text, e.configJSON)
	if err != nil {
		return nil, err
	}

	var result WatermarkResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return &result, nil
}
