package guards

import (
	"fmt"
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

	// Collect all paths to check (cleaned + resolved, deduplicated)
	pathsToCheck := []string{cleaned}
	if resolved != cleaned {
		pathsToCheck = append(pathsToCheck, resolved)
	}

	// Check exceptions first — if any path matches an exception, allow
	for _, exc := range g.exceptions {
		for _, p := range pathsToCheck {
			if internal.DoubleStarMatch(exc, p) {
				return Allow(g.Name())
			}
		}
	}

	// Check forbidden patterns — if any path matches, block
	for _, pat := range g.patterns {
		for _, p := range pathsToCheck {
			if internal.DoubleStarMatch(pat, p) {
				return Block(g.Name(), Critical,
					fmt.Sprintf("access to %q blocked by pattern %q", action.Path, pat))
			}
		}
	}

	return Allow(g.Name())
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
