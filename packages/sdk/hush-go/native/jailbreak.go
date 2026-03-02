package native

import "encoding/json"

// JailbreakResult holds the parsed result from jailbreak detection.
type JailbreakResult struct {
	Severity        string          `json:"severity"`
	Confidence      float64         `json:"confidence"`
	RiskScore       int             `json:"risk_score"`
	Blocked         bool            `json:"blocked"`
	Signals         json.RawMessage `json:"signals"`
	LayerResults    json.RawMessage `json:"layer_results"`
	Fingerprint     string          `json:"fingerprint"`
	Canonicalization json.RawMessage `json:"canonicalization"`
	Session         json.RawMessage `json:"session,omitempty"`
	LatencyMs       float64         `json:"latency_ms"`
}

// JailbreakDetector wraps the native jailbreak detection.
type JailbreakDetector struct {
	configJSON string
}

// NewJailbreakDetector creates a new JailbreakDetector with default config.
func NewJailbreakDetector() *JailbreakDetector {
	return &JailbreakDetector{}
}

// NewJailbreakDetectorWithConfig creates a JailbreakDetector with a JSON config.
func NewJailbreakDetectorWithConfig(configJSON string) *JailbreakDetector {
	return &JailbreakDetector{configJSON: configJSON}
}

// Detect runs jailbreak detection on the given text.
func (d *JailbreakDetector) Detect(text string) (*JailbreakResult, error) {
	return d.DetectWithSession(text, "")
}

// DetectWithSession runs jailbreak detection with a session ID for aggregation.
func (d *JailbreakDetector) DetectWithSession(text, sessionID string) (*JailbreakResult, error) {
	raw, err := DetectJailbreak(text, sessionID, d.configJSON)
	if err != nil {
		return nil, err
	}

	var result JailbreakResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return &result, nil
}
