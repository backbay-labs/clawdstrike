package guards

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/backbay/clawdstrike-go/internal"
	"github.com/backbay/clawdstrike-go/policy"
)

// DefaultForbiddenPatterns are the default patterns from the default ruleset.
var DefaultForbiddenPatterns = []string{
	"**/.ssh/**",
	"**/id_rsa*",
	"**/id_ed25519*",
	"**/id_ecdsa*",
	"**/.aws/**",
	"**/.env",
	"**/.env.*",
	"**/.git-credentials",
	"**/.gitconfig",
	"**/.gnupg/**",
	"**/.kube/**",
	"**/.docker/**",
	"**/.npmrc",
	"**/.password-store/**",
	"**/pass/**",
	"**/.1password/**",
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
}

// ForbiddenPathGuard blocks access to sensitive filesystem paths.
type ForbiddenPathGuard struct {
	patterns   []string
	exceptions []string
}

// NewForbiddenPathGuard creates a guard with the given config. Nil config uses defaults.
func NewForbiddenPathGuard(cfg *policy.ForbiddenPathConfig) *ForbiddenPathGuard {
	g := &ForbiddenPathGuard{}
	if cfg != nil {
		g.patterns = cfg.Patterns
		g.exceptions = cfg.Exceptions
	}
	if len(g.patterns) == 0 {
		g.patterns = DefaultForbiddenPatterns
	}
	return g
}

func (g *ForbiddenPathGuard) Name() string { return "forbidden_path" }

func (g *ForbiddenPathGuard) Handles(action GuardAction) bool {
	return action.Type == "file_access" || action.Type == "file_write"
}

func (g *ForbiddenPathGuard) Check(action GuardAction, ctx *GuardContext) GuardResult {
	path := normalizePath(action.Path)

	// Check exceptions first
	for _, exc := range g.exceptions {
		if internal.DoubleStarMatch(exc, path) {
			return Allow(g.Name())
		}
	}

	// Check forbidden patterns
	for _, pat := range g.patterns {
		if internal.DoubleStarMatch(pat, path) {
			return Block(g.Name(), Critical,
				fmt.Sprintf("access to %q blocked by pattern %q", action.Path, pat))
		}
	}

	return Allow(g.Name())
}

// normalizePath cleans a path and attempts to resolve symlinks (best effort).
func normalizePath(path string) string {
	cleaned := filepath.Clean(path)
	// Try to resolve symlinks; fall back to cleaned path on error.
	resolved, err := os.Readlink(cleaned)
	if err == nil {
		if filepath.IsAbs(resolved) {
			return filepath.Clean(resolved)
		}
		return filepath.Clean(filepath.Join(filepath.Dir(cleaned), resolved))
	}
	return cleaned
}
