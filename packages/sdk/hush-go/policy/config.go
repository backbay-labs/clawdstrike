// Package policy implements Clawdstrike policy loading, validation, and resolution.
package policy

// ForbiddenPathConfig configures the forbidden path guard.
type ForbiddenPathConfig struct {
	Enabled    *bool    `yaml:"enabled,omitempty"`
	Patterns   []string `yaml:"patterns"`
	Exceptions []string `yaml:"exceptions"`
}

// EgressAllowlistConfig configures the egress allowlist guard.
type EgressAllowlistConfig struct {
	Enabled       *bool    `yaml:"enabled,omitempty"`
	Allow         []string `yaml:"allow"`
	Block         []string `yaml:"block"`
	DefaultAction string   `yaml:"default_action"`
}

// SecretLeakPatternConfig defines a single secret detection pattern.
type SecretLeakPatternConfig struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Severity string `yaml:"severity"`
}

// SecretLeakConfig configures the secret leak guard.
type SecretLeakConfig struct {
	Enabled   *bool                     `yaml:"enabled,omitempty"`
	Patterns  []SecretLeakPatternConfig `yaml:"patterns"`
	SkipPaths []string                  `yaml:"skip_paths"`
}

// PatchIntegrityConfig configures the patch integrity guard.
type PatchIntegrityConfig struct {
	Enabled           *bool    `yaml:"enabled,omitempty"`
	MaxAdditions      int      `yaml:"max_additions"`
	MaxDeletions      int      `yaml:"max_deletions"`
	RequireBalance    *bool    `yaml:"require_balance,omitempty"`
	MaxImbalanceRatio float64  `yaml:"max_imbalance_ratio"`
	ForbiddenPatterns []string `yaml:"forbidden_patterns"`
}

// McpToolConfig configures the MCP tool guard.
type McpToolConfig struct {
	Enabled             *bool    `yaml:"enabled,omitempty"`
	Allow               []string `yaml:"allow"`
	Block               []string `yaml:"block"`
	RequireConfirmation []string `yaml:"require_confirmation"`
	DefaultAction       string   `yaml:"default_action"`
	MaxArgsSize         int      `yaml:"max_args_size"`
}

// PromptInjectionConfig configures the prompt injection guard.
type PromptInjectionConfig struct {
	Enabled        *bool   `yaml:"enabled,omitempty"`
	WarnThreshold  float64 `yaml:"warn_threshold"`
	BlockThreshold float64 `yaml:"block_threshold"`
	MaxScanBytes   int     `yaml:"max_scan_bytes"`
}

// JailbreakConfig configures the jailbreak guard.
// Currently a placeholder for native delegation.
type JailbreakConfig struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

// GuardEnabled returns whether a guard is enabled based on its Enabled field.
// If the field is nil (not set), the guard is considered enabled by default.
func GuardEnabled(enabled *bool) bool {
	return enabled == nil || *enabled
}
