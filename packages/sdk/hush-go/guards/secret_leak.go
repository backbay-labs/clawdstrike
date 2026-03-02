package guards

import (
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/backbay/clawdstrike-go/internal"
	"github.com/backbay/clawdstrike-go/policy"
)

// DefaultSecretPatterns are the default secret detection patterns.
var DefaultSecretPatterns = []policy.SecretLeakPatternConfig{
	{Name: "aws_access_key", Pattern: `AKIA[0-9A-Z]{16}`, Severity: "critical"},
	{Name: "github_token", Pattern: `gh[ps]_[A-Za-z0-9]{36}`, Severity: "critical"},
	{Name: "openai_key", Pattern: `sk-[A-Za-z0-9]{48}`, Severity: "critical"},
	{Name: "private_key", Pattern: `-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`, Severity: "critical"},
}

type compiledPattern struct {
	name     string
	re       *regexp.Regexp
	severity Severity
}

// SecretLeakGuard detects secrets in file writes.
type SecretLeakGuard struct {
	patterns  []compiledPattern
	skipPaths []string
}

// NewSecretLeakGuard creates a guard with the given config. Nil config uses defaults.
// Patterns are compiled at construction time; invalid patterns cause an error.
func NewSecretLeakGuard(cfg *policy.SecretLeakConfig) (*SecretLeakGuard, error) {
	rawPatterns := DefaultSecretPatterns
	var skipPaths []string

	if cfg != nil {
		if len(cfg.Patterns) > 0 {
			rawPatterns = cfg.Patterns
		}
		skipPaths = cfg.SkipPaths
	}

	compiled := make([]compiledPattern, 0, len(rawPatterns))
	for _, rp := range rawPatterns {
		re, err := regexp.Compile(rp.Pattern)
		if err != nil {
			return nil, fmt.Errorf("secret_leak: invalid pattern %q (%s): %w", rp.Name, rp.Pattern, err)
		}
		sev, _ := ParseSeverity(rp.Severity)
		compiled = append(compiled, compiledPattern{
			name:     rp.Name,
			re:       re,
			severity: sev,
		})
	}

	return &SecretLeakGuard{
		patterns:  compiled,
		skipPaths: skipPaths,
	}, nil
}

func (g *SecretLeakGuard) Name() string { return "secret_leak" }

func (g *SecretLeakGuard) Handles(action GuardAction) bool {
	return action.Type == "file_write" || action.Type == "patch"
}

func (g *SecretLeakGuard) Check(action GuardAction, ctx *GuardContext) GuardResult {
	// Normalize path before skip_paths check
	normalizedPath := filepath.Clean(action.Path)

	// Check skip_paths
	for _, skip := range g.skipPaths {
		if internal.DoubleStarMatch(skip, normalizedPath) {
			return Allow(g.Name())
		}
	}

	// For patch actions, scan the diff instead of content
	var content string
	if action.Type == "patch" {
		content = action.Diff
	} else {
		content = string(action.Content)
	}

	for _, pat := range g.patterns {
		match := pat.re.FindString(content)
		if match != "" {
			redacted := redact(match)
			return Block(g.Name(), pat.severity,
				fmt.Sprintf("potential secret detected (%s): %s", pat.name, redacted)).
				WithDetails(map[string]interface{}{
					"pattern": pat.name,
					"match":   redacted,
				})
		}
	}

	return Allow(g.Name())
}

// redact shows first 4 + "..." + last 4 characters.
func redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
