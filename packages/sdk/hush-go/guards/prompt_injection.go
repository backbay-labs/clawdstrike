package guards

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/backbay/clawdstrike-go/policy"
)

// Default prompt injection thresholds.
const (
	DefaultWarnThreshold  = 0.5
	DefaultBlockThreshold = 0.8
	DefaultMaxScanBytes   = 200 * 1024 // 200KB
)

// InjectionSeverity classifies the severity of a prompt injection attempt.
type InjectionSeverity int

const (
	InjectionSafe       InjectionSeverity = iota
	InjectionSuspicious
	InjectionHigh
	InjectionCritical
)

func (s InjectionSeverity) String() string {
	switch s {
	case InjectionSafe:
		return "safe"
	case InjectionSuspicious:
		return "suspicious"
	case InjectionHigh:
		return "high"
	case InjectionCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Suspicious keywords and patterns for heuristic detection.
var suspiciousPatterns = []string{
	"ignore previous",
	"ignore all previous",
	"ignore the above",
	"disregard previous",
	"disregard all previous",
	"disregard the above",
	"forget previous",
	"forget all previous",
	"new instructions",
	"new instruction",
	"override instructions",
	"system prompt",
	"you are now",
	"act as",
	"pretend to be",
	"jailbreak",
	"ignore safety",
	"ignore guidelines",
	"bypass restrictions",
	"bypass safety",
	"do not refuse",
	"do anything",
	"no restrictions",
	"developer mode",
	"dan mode",
}

// PromptInjectionGuard detects prompt injection in untrusted text.
type PromptInjectionGuard struct {
	warnThreshold  float64 // 0 means "use default" per Go zero-value convention
	blockThreshold float64 // 0 means "use default" per Go zero-value convention
	maxScanBytes   int     // 0 means "use default" per Go zero-value convention
}

// NewPromptInjectionGuard creates a guard with the given config. Nil config uses defaults.
func NewPromptInjectionGuard(cfg *policy.PromptInjectionConfig) *PromptInjectionGuard {
	g := &PromptInjectionGuard{
		warnThreshold:  DefaultWarnThreshold,
		blockThreshold: DefaultBlockThreshold,
		maxScanBytes:   DefaultMaxScanBytes,
	}
	if cfg != nil {
		if cfg.WarnThreshold > 0 {
			g.warnThreshold = cfg.WarnThreshold
		}
		if cfg.BlockThreshold > 0 {
			g.blockThreshold = cfg.BlockThreshold
		}
		if cfg.MaxScanBytes > 0 {
			g.maxScanBytes = cfg.MaxScanBytes
		}
	}
	return g
}

func (g *PromptInjectionGuard) Name() string { return "prompt_injection" }

func (g *PromptInjectionGuard) Handles(action GuardAction) bool {
	return action.Type == "custom" && action.CustomType == "untrusted_text"
}

func (g *PromptInjectionGuard) Check(action GuardAction, ctx *GuardContext) GuardResult {
	text, ok := action.CustomData.(string)
	if !ok {
		// Not a string — can't scan. Fail-closed: block.
		return Block(g.Name(), Error, "untrusted_text data is not a string")
	}

	// Truncate to max scan bytes
	if len(text) > g.maxScanBytes {
		text = text[:g.maxScanBytes]
	}

	// Compute fingerprint
	hash := sha256.Sum256([]byte(text))
	fingerprint := hex.EncodeToString(hash[:])

	// Heuristic scoring
	score := heuristicScore(text)
	severity := scoreToSeverity(score)

	details := map[string]interface{}{
		"score":       score,
		"severity":    severity.String(),
		"fingerprint": fingerprint,
	}

	if score >= g.blockThreshold {
		return Block(g.Name(), Critical,
			fmt.Sprintf("prompt injection detected (score=%.2f)", score)).
			WithDetails(details)
	}

	if score >= g.warnThreshold {
		return Warn(g.Name(),
			fmt.Sprintf("suspicious text detected (score=%.2f)", score)).
			WithDetails(details)
	}

	return Allow(g.Name()).WithDetails(details)
}

// heuristicScore calculates a 0.0–1.0 score based on suspicious pattern matches.
func heuristicScore(text string) float64 {
	lower := strings.ToLower(text)
	matches := 0
	for _, pat := range suspiciousPatterns {
		if strings.Contains(lower, pat) {
			matches++
		}
	}
	if matches == 0 {
		return 0.0
	}
	// Normalize: 3+ matches → 1.0
	score := float64(matches) / 3.0
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func scoreToSeverity(score float64) InjectionSeverity {
	switch {
	case score >= 0.8:
		return InjectionCritical
	case score >= 0.5:
		return InjectionHigh
	case score > 0.0:
		return InjectionSuspicious
	default:
		return InjectionSafe
	}
}
