// Package policy implements Clawdstrike policy loading, validation, and resolution.
package policy

// PatternEntryConfig is a policy-level pattern entry for inline pattern databases.
type PatternEntryConfig struct {
	ID        string    `yaml:"id" json:"id"`
	Category  string    `yaml:"category" json:"category"`
	Stage     string    `yaml:"stage" json:"stage"`
	Label     string    `yaml:"label" json:"label"`
	Embedding []float32 `yaml:"embedding" json:"embedding"`
}

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

// SpiderSenseTrustedKeyConfig represents a trusted signing key entry for
// pattern DB signature verification.
type SpiderSenseTrustedKeyConfig struct {
	KeyID     string `yaml:"key_id,omitempty" json:"key_id,omitempty"`
	PublicKey string `yaml:"public_key" json:"public_key"`
	NotBefore string `yaml:"not_before,omitempty" json:"not_before,omitempty"`
	NotAfter  string `yaml:"not_after,omitempty" json:"not_after,omitempty"`
	Status    string `yaml:"status,omitempty" json:"status,omitempty"`
}

// SpiderSenseConfig configures the spider_sense guard for embedding-based
// threat detection via cosine similarity against a pattern database.
// Pointer types are used for numeric fields so that an explicit zero value
// (valid in Rust) is distinguishable from "not set" (use default).
type SpiderSenseConfig struct {
	Enabled             *bool                `yaml:"enabled,omitempty"`
	SimilarityThreshold *float64             `yaml:"similarity_threshold,omitempty"`
	AmbiguityBand       *float64             `yaml:"ambiguity_band,omitempty"`
	TopK                *int                 `yaml:"top_k,omitempty"`
	Patterns            []PatternEntryConfig `yaml:"patterns,omitempty" json:"patterns,omitempty"`

	// Canonical (Rust-compatible) fields accepted for policy parsing parity.
	EmbeddingAPIURL                 string                        `yaml:"embedding_api_url,omitempty"`
	EmbeddingAPIKey                 string                        `yaml:"embedding_api_key,omitempty"`
	EmbeddingModel                  string                        `yaml:"embedding_model,omitempty"`
	PatternDBPath                   string                        `yaml:"pattern_db_path,omitempty"`
	PatternDBVersion                string                        `yaml:"pattern_db_version,omitempty"`
	PatternDBChecksum               string                        `yaml:"pattern_db_checksum,omitempty"`
	PatternDBSignature              string                        `yaml:"pattern_db_signature,omitempty"`
	PatternDBSignatureKeyID         string                        `yaml:"pattern_db_signature_key_id,omitempty"`
	PatternDBPublicKey              string                        `yaml:"pattern_db_public_key,omitempty"`
	PatternDBTrustStorePath         string                        `yaml:"pattern_db_trust_store_path,omitempty"`
	PatternDBTrustedKeys            []SpiderSenseTrustedKeyConfig `yaml:"pattern_db_trusted_keys,omitempty" json:"pattern_db_trusted_keys,omitempty"`
	PatternDBManifestPath           string                        `yaml:"pattern_db_manifest_path,omitempty"`
	PatternDBManifestTrustStorePath string                        `yaml:"pattern_db_manifest_trust_store_path,omitempty"`
	PatternDBManifestTrustedKeys    []SpiderSenseTrustedKeyConfig `yaml:"pattern_db_manifest_trusted_keys,omitempty" json:"pattern_db_manifest_trusted_keys,omitempty"`
	LlmAPIURL                       string                        `yaml:"llm_api_url,omitempty"`
	LlmAPIKey                       string                        `yaml:"llm_api_key,omitempty"`
	LlmModel                        string                        `yaml:"llm_model,omitempty"`
	LlmPromptTemplateID             string                        `yaml:"llm_prompt_template_id,omitempty"`
	LlmPromptTemplateVersion        string                        `yaml:"llm_prompt_template_version,omitempty"`
	LlmTimeoutMs                    *int                          `yaml:"llm_timeout_ms,omitempty"`
	LlmFailMode                     string                        `yaml:"llm_fail_mode,omitempty"`
	Async                           map[string]interface{}        `yaml:"async,omitempty"`
}

// GuardEnabled returns whether a guard is enabled based on its Enabled field.
// If the field is nil (not set), the guard is considered enabled by default.
func GuardEnabled(enabled *bool) bool {
	return enabled == nil || *enabled
}
