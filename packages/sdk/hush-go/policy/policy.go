package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Supported schema versions.
var supportedVersions = map[string]bool{
	"1.1.0": true,
	"1.2.0": true,
}

// MergeStrategy controls how policies are combined via extends.
type MergeStrategy string

const (
	MergeReplace MergeStrategy = "replace"
	MergeMerge   MergeStrategy = "merge"
	MergeDeep    MergeStrategy = "deep_merge"
)

// GuardConfigs holds optional configuration for each guard.
type GuardConfigs struct {
	ForbiddenPath   *ForbiddenPathConfig   `yaml:"forbidden_path,omitempty"`
	EgressAllowlist *EgressAllowlistConfig `yaml:"egress_allowlist,omitempty"`
	SecretLeak      *SecretLeakConfig      `yaml:"secret_leak,omitempty"`
	PatchIntegrity  *PatchIntegrityConfig  `yaml:"patch_integrity,omitempty"`
	McpTool         *McpToolConfig         `yaml:"mcp_tool,omitempty"`
	PromptInjection *PromptInjectionConfig `yaml:"prompt_injection,omitempty"`
	Jailbreak       *JailbreakConfig       `yaml:"jailbreak,omitempty"`
}

// PolicySettings holds global policy settings.
type PolicySettings struct {
	FailFast           bool `yaml:"fail_fast"`
	VerboseLogging     bool `yaml:"verbose_logging"`
	SessionTimeoutSecs int  `yaml:"session_timeout_secs"`
}

// Policy represents a Clawdstrike security policy.
type Policy struct {
	Version       string         `yaml:"version"`
	Name          string         `yaml:"name"`
	Description   string         `yaml:"description,omitempty"`
	Extends       []string       `yaml:"extends,omitempty"`
	MergeStrategy MergeStrategy  `yaml:"merge_strategy,omitempty"`
	Guards        GuardConfigs   `yaml:"guards"`
	Settings      PolicySettings `yaml:"settings"`
	settingsSet   bool           `yaml:"-"`
}

type extendsField []string

func (e *extendsField) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		value := strings.TrimSpace(node.Value)
		if value == "" {
			*e = nil
			return nil
		}
		*e = []string{value}
		return nil
	case yaml.SequenceNode:
		values := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				return fmt.Errorf("policy: extends entries must be strings")
			}
			values = append(values, strings.TrimSpace(item.Value))
		}
		*e = values
		return nil
	default:
		return fmt.Errorf("policy: extends must be a string or list of strings")
	}
}

type decodedPolicy struct {
	Version       string          `yaml:"version"`
	Name          string          `yaml:"name"`
	Description   string          `yaml:"description,omitempty"`
	Extends       extendsField    `yaml:"extends,omitempty"`
	MergeStrategy MergeStrategy   `yaml:"merge_strategy,omitempty"`
	Guards        GuardConfigs    `yaml:"guards"`
	Settings      *PolicySettings `yaml:"settings,omitempty"`
}

var placeholderRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// substituteString replaces ${VAR} placeholders with os.Getenv(VAR) in a string value.
func substituteString(s string) string {
	return placeholderRe.ReplaceAllStringFunc(s, func(match string) string {
		name := match[2 : len(match)-1]
		return os.Getenv(name)
	})
}

// substitutePolicy performs environment variable substitution on string fields
// of a parsed policy. This runs AFTER YAML parsing so that substitution cannot
// alter YAML structure or inject additional YAML keys.
func substitutePolicy(p *Policy) {
	p.Version = substituteString(p.Version)
	p.Name = substituteString(p.Name)
	p.Description = substituteString(p.Description)
}

// FromYAML parses a policy from YAML bytes. Unknown fields are rejected.
// Environment variable substitution (${VAR}) is applied to string fields
// after parsing, so it cannot alter YAML structure.
func FromYAML(data []byte) (*Policy, error) {
	var decoded decodedPolicy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("policy: parse YAML: %w", err)
	}

	p := Policy{
		Version:       decoded.Version,
		Name:          decoded.Name,
		Description:   decoded.Description,
		Extends:       append([]string(nil), decoded.Extends...),
		MergeStrategy: decoded.MergeStrategy,
		Guards:        decoded.Guards,
	}
	if decoded.Settings != nil {
		p.Settings = *decoded.Settings
		p.settingsSet = true
	}

	substitutePolicy(&p)
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// FromYAMLFile loads a policy from a YAML file.
func FromYAMLFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read file %q: %w", path, err)
	}
	return FromYAML(data)
}

// Validate checks that the policy is well-formed. Fail-closed: invalid policies are rejected.
func (p *Policy) Validate() error {
	if p.Version == "" {
		return fmt.Errorf("policy: missing version")
	}
	if !supportedVersions[p.Version] {
		supported := make([]string, 0, len(supportedVersions))
		for v := range supportedVersions {
			supported = append(supported, v)
		}
		return fmt.Errorf("policy: unsupported version %q (supported: %v)", p.Version, supported)
	}
	if p.Name == "" {
		return fmt.Errorf("policy: missing name")
	}
	return nil
}

// ToYAML serializes the policy to YAML.
func (p *Policy) ToYAML() ([]byte, error) {
	data, err := yaml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal YAML: %w", err)
	}
	return data, nil
}
