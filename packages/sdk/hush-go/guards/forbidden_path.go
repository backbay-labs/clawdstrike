package guards

import (
	"fmt"
	"path/filepath"

	"github.com/backbay-labs/clawdstrike-go/internal"
	"github.com/backbay-labs/clawdstrike-go/policy"
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
	return action.Type == "file_access" || action.Type == "file_write" || action.Type == "patch"
}

func (g *ForbiddenPathGuard) Check(action GuardAction, ctx *GuardContext) GuardResult {
	path := action.Path

	// Resolve relative paths using ctx.Cwd
	if !filepath.IsAbs(path) && ctx != nil && ctx.Cwd != "" {
		path = filepath.Join(ctx.Cwd, path)
	}

	cleaned := filepath.Clean(path)
	resolved := normalizePath(path)

	// Evaluate the resolved path before the lexical path so symlink exceptions
	// cannot bypass forbidden resolved targets.
	if result, matched := g.evaluatePath(action.Path, resolved); matched {
		return result
	}
	if cleaned != resolved {
		if result, matched := g.evaluatePath(action.Path, cleaned); matched {
			return result
		}
	}

	return Allow(g.Name())
}

func (g *ForbiddenPathGuard) evaluatePath(originalPath, candidate string) (GuardResult, bool) {
	for _, pat := range g.patterns {
		if !internal.DoubleStarMatch(pat, candidate) {
			continue
		}
		if matchesAnyPathPattern(g.exceptions, candidate) {
			return Allow(g.Name()), true
		}
		return Block(g.Name(), Critical,
			fmt.Sprintf("access to %q blocked by pattern %q", originalPath, pat)), true
	}
	return GuardResult{}, false
}

func matchesAnyPathPattern(patterns []string, value string) bool {
	for _, pat := range patterns {
		if internal.DoubleStarMatch(pat, value) {
			return true
		}
	}
	return false
}

// normalizePath cleans a path and attempts to resolve full symlink chains (best effort).
func normalizePath(path string) string {
	cleaned := filepath.Clean(path)
	// Try to resolve full symlink chain; fall back to cleaned path on error.
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err == nil {
		return resolved
	}
	return cleaned
}
