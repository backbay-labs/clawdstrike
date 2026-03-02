package guards

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/backbay/clawdstrike-go/policy"
)

// Default patch integrity limits from the default ruleset.
const (
	DefaultMaxAdditions      = 1000
	DefaultMaxDeletions      = 500
	DefaultMaxImbalanceRatio = 10.0
)

// DefaultForbiddenPatchPatterns are the default forbidden patterns.
var DefaultForbiddenPatchPatterns = []string{
	`(?i)disable[\s_\-]?(security|auth|ssl|tls)`,
	`(?i)skip[\s_\-]?(verify|validation|check)`,
	`(?i)rm\s+-rf\s+/`,
	`(?i)chmod\s+777`,
}

type compiledForbidden struct {
	pattern string
	re      *regexp.Regexp
}

// PatchIntegrityGuard validates patch safety.
type PatchIntegrityGuard struct {
	maxAdditions      int
	maxDeletions      int
	requireBalance    bool
	maxImbalanceRatio float64
	forbidden         []compiledForbidden
}

// NewPatchIntegrityGuard creates a guard with the given config. Nil config uses defaults.
func NewPatchIntegrityGuard(cfg *policy.PatchIntegrityConfig) (*PatchIntegrityGuard, error) {
	g := &PatchIntegrityGuard{
		maxAdditions:      DefaultMaxAdditions,
		maxDeletions:      DefaultMaxDeletions,
		maxImbalanceRatio: DefaultMaxImbalanceRatio,
	}

	rawPatterns := DefaultForbiddenPatchPatterns

	if cfg != nil {
		if cfg.MaxAdditions > 0 {
			g.maxAdditions = cfg.MaxAdditions
		}
		if cfg.MaxDeletions > 0 {
			g.maxDeletions = cfg.MaxDeletions
		}
		g.requireBalance = cfg.RequireBalance
		if cfg.MaxImbalanceRatio > 0 {
			g.maxImbalanceRatio = cfg.MaxImbalanceRatio
		}
		if len(cfg.ForbiddenPatterns) > 0 {
			rawPatterns = cfg.ForbiddenPatterns
		}
	}

	forbidden := make([]compiledForbidden, 0, len(rawPatterns))
	for _, pat := range rawPatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("patch_integrity: invalid forbidden pattern %q: %w", pat, err)
		}
		forbidden = append(forbidden, compiledForbidden{pattern: pat, re: re})
	}
	g.forbidden = forbidden

	return g, nil
}

func (g *PatchIntegrityGuard) Name() string { return "patch_integrity" }

func (g *PatchIntegrityGuard) Handles(action GuardAction) bool {
	return action.Type == "patch"
}

func (g *PatchIntegrityGuard) Check(action GuardAction, ctx *GuardContext) GuardResult {
	diff := action.Diff

	// Check for forbidden patterns (critical severity)
	for _, f := range g.forbidden {
		if f.re.MatchString(diff) {
			return Block(g.Name(), Critical,
				fmt.Sprintf("forbidden pattern detected in patch: %s", f.pattern))
		}
	}

	// Parse unified diff for addition/deletion counts
	additions, deletions := parseDiffStats(diff)

	if additions > g.maxAdditions {
		return Block(g.Name(), Error,
			fmt.Sprintf("patch has %d additions (max %d)", additions, g.maxAdditions))
	}

	if deletions > g.maxDeletions {
		return Block(g.Name(), Error,
			fmt.Sprintf("patch has %d deletions (max %d)", deletions, g.maxDeletions))
	}

	if g.requireBalance && g.maxImbalanceRatio > 0 {
		if deletions > 0 {
			ratio := float64(additions) / float64(deletions)
			if ratio > g.maxImbalanceRatio {
				return Block(g.Name(), Error,
					fmt.Sprintf("patch imbalance ratio %.1f exceeds max %.1f", ratio, g.maxImbalanceRatio))
			}
		} else if additions > 0 {
			// All additions, no deletions — check if we require balance
			return Block(g.Name(), Error,
				fmt.Sprintf("patch has %d additions with 0 deletions (balance required)", additions))
		}
	}

	return Allow(g.Name())
}

// parseDiffStats counts + and - lines in a unified diff.
func parseDiffStats(diff string) (additions, deletions int) {
	lines := strings.Split(diff, "\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		// Skip diff headers
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") ||
			strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "diff ") ||
			strings.HasPrefix(line, "index ") {
			continue
		}
		if line[0] == '+' {
			additions++
		} else if line[0] == '-' {
			deletions++
		}
	}
	return
}
