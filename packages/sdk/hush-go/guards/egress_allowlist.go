package guards

import (
	"fmt"
	"strings"

	"github.com/backbay-labs/clawdstrike-go/policy"
)

// DefaultAllowedDomains are the default egress allowlist from the default ruleset.
var DefaultAllowedDomains = []string{
	"*.openai.com",
	"*.anthropic.com",
	"api.github.com",
	"github.com",
	"*.githubusercontent.com",
	"*.npmjs.org",
	"registry.npmjs.org",
	"pypi.org",
	"files.pythonhosted.org",
	"crates.io",
	"static.crates.io",
}

// EgressAllowlistGuard controls network egress by domain.
type EgressAllowlistGuard struct {
	allow         []string
	block         []string
	defaultAction string
}

func NewEgressAllowlistGuard(cfg *policy.EgressAllowlistConfig) *EgressAllowlistGuard {
	g := &EgressAllowlistGuard{
		defaultAction: "block",
	}
	if cfg != nil {
		g.allow = cfg.Allow
		g.block = cfg.Block
		if cfg.DefaultAction != "" {
			g.defaultAction = cfg.DefaultAction
		}
	}
	if len(g.allow) == 0 && len(g.block) == 0 {
		g.allow = DefaultAllowedDomains
	}
	return g
}

func (g *EgressAllowlistGuard) Name() string { return "egress_allowlist" }

func (g *EgressAllowlistGuard) Handles(action GuardAction) bool {
	return action.Type == "network_egress"
}

func (g *EgressAllowlistGuard) Check(action GuardAction, ctx *GuardContext) GuardResult {
	host := strings.ToLower(action.Host)

	// Block list takes precedence
	for _, pattern := range g.block {
		if matchDomain(pattern, host) {
			return Block(g.Name(), Error,
				fmt.Sprintf("egress to %q blocked by block rule %q", host, pattern))
		}
	}

	// Check allow list
	for _, pattern := range g.allow {
		if matchDomain(pattern, host) {
			return Allow(g.Name())
		}
	}

	// Apply default action
	if g.defaultAction == "allow" {
		return Allow(g.Name())
	}
	return Block(g.Name(), Error,
		fmt.Sprintf("egress to %q blocked (not in allowlist)", host))
}

// matchDomain matches a host against a domain pattern.
// Supports wildcards: "*.domain.com" matches "sub.domain.com".
func matchDomain(pattern, host string) bool {
	pattern = strings.ToLower(pattern)

	if pattern == "*" {
		return true
	}

	if pattern == host {
		return true
	}

	// Wildcard prefix: "*.domain.com"
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".domain.com"
		return strings.HasSuffix(host, suffix)
	}

	return false
}
