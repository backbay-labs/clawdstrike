package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func TestLoadAllBuiltinRulesets(t *testing.T) {
	names := BuiltinNames()
	if len(names) != 6 {
		t.Fatalf("expected 6 builtin rulesets, got %d", len(names))
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			p, err := ByName(name)
			if err != nil {
				t.Fatalf("ByName(%q) error: %v", name, err)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("Validate() error: %v", err)
			}
			if p.Name == "" {
				t.Error("expected non-empty Name")
			}
			if p.Version == "" {
				t.Error("expected non-empty Version")
			}
		})
	}
}

func TestSpiderSenseCanonicalConfigParses(t *testing.T) {
	yamlData := []byte(`
version: "1.3.0"
name: SpiderSenseParse
guards:
  spider_sense:
    enabled: true
    embedding_api_url: "${SPIDER_SENSE_EMBEDDING_URL}"
    embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.85
    ambiguity_band: 0.10
    top_k: 5
    pattern_db_path: "builtin:s2bench-v1"
    pattern_db_version: "s2bench-v1"
    pattern_db_checksum: "8943003a9de9619d2f8f0bf133c9c7690ab3a582cbcbe4cb9692d44ee9643a73"
    llm_api_url: "https://example.invalid/v1/messages"
    llm_api_key: "llm-key"
    llm_model: "gpt-4.1-mini"
    llm_prompt_template_id: "spider_sense.deep_path.json_classifier"
    llm_prompt_template_version: "1.0.0"
    pattern_db_manifest_path: "/tmp/spider/manifest.json"
    pattern_db_manifest_trust_store_path: "/tmp/spider/manifest-roots.json"
    async:
      timeout_ms: 5000
      on_timeout: warn
`)

	p, err := FromYAML(yamlData)
	if err != nil {
		t.Fatalf("FromYAML: %v", err)
	}
	if p.Guards.SpiderSense == nil {
		t.Fatal("expected guards.spider_sense to parse")
	}
	if p.Guards.SpiderSense.PatternDBPath != "builtin:s2bench-v1" {
		t.Fatalf("unexpected pattern_db_path: %q", p.Guards.SpiderSense.PatternDBPath)
	}
	if p.Guards.SpiderSense.EmbeddingModel != "text-embedding-3-small" {
		t.Fatalf("unexpected embedding_model: %q", p.Guards.SpiderSense.EmbeddingModel)
	}
	if p.Guards.SpiderSense.PatternDBVersion != "s2bench-v1" {
		t.Fatalf("unexpected pattern_db_version: %q", p.Guards.SpiderSense.PatternDBVersion)
	}
	if p.Guards.SpiderSense.PatternDBChecksum == "" {
		t.Fatal("expected non-empty pattern_db_checksum")
	}
	if p.Guards.SpiderSense.Async == nil {
		t.Fatal("expected guards.spider_sense.async to parse")
	}
	if p.Guards.SpiderSense.LlmPromptTemplateID != "spider_sense.deep_path.json_classifier" {
		t.Fatalf("unexpected llm_prompt_template_id: %q", p.Guards.SpiderSense.LlmPromptTemplateID)
	}
	if p.Guards.SpiderSense.PatternDBManifestPath != "/tmp/spider/manifest.json" {
		t.Fatalf("unexpected pattern_db_manifest_path: %q", p.Guards.SpiderSense.PatternDBManifestPath)
	}
}

func TestSpiderSenseBuiltinRulesetParses(t *testing.T) {
	p, err := ByName("spider-sense")
	if err != nil {
		t.Fatalf("ByName(spider-sense): %v", err)
	}
	if p.Guards.SpiderSense == nil {
		t.Fatal("expected spider_sense guard config in built-in ruleset")
	}
	if p.Guards.SpiderSense.PatternDBPath != "builtin:s2bench-v1" {
		t.Fatalf("unexpected pattern_db_path: %q", p.Guards.SpiderSense.PatternDBPath)
	}
	if p.Guards.SpiderSense.PatternDBVersion != "s2bench-v1" {
		t.Fatalf("unexpected pattern_db_version: %q", p.Guards.SpiderSense.PatternDBVersion)
	}
	if p.Guards.SpiderSense.PatternDBChecksum == "" {
		t.Fatal("expected pattern_db_checksum in built-in ruleset")
	}
}

func TestYAMLRoundtrip(t *testing.T) {
	original, err := ByName("default")
	if err != nil {
		t.Fatalf("ByName(default): %v", err)
	}

	data, err := original.ToYAML()
	if err != nil {
		t.Fatalf("ToYAML: %v", err)
	}

	roundtripped, err := FromYAML(data)
	if err != nil {
		t.Fatalf("FromYAML: %v", err)
	}

	if roundtripped.Name != original.Name {
		t.Errorf("Name mismatch: %q vs %q", roundtripped.Name, original.Name)
	}
	if roundtripped.Version != original.Version {
		t.Errorf("Version mismatch: %q vs %q", roundtripped.Version, original.Version)
	}
	if roundtripped.Guards.ForbiddenPath == nil {
		t.Error("expected ForbiddenPath config after roundtrip")
	}
}

func TestUnknownFieldRejection(t *testing.T) {
	yamlData := []byte(`
version: "1.1.0"
name: Test
bogus_field: true
`)
	_, err := FromYAML(yamlData)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

func TestUnsupportedVersion(t *testing.T) {
	yamlData := []byte(`
version: "2.0.0"
name: Test
`)
	_, err := FromYAML(yamlData)
	if err == nil {
		t.Fatal("expected error for unsupported version, got nil")
	}
}

func TestMissingVersion(t *testing.T) {
	yamlData := []byte(`
name: Test
`)
	_, err := FromYAML(yamlData)
	if err == nil {
		t.Fatal("expected error for missing version, got nil")
	}
}

func TestMissingName(t *testing.T) {
	yamlData := []byte(`
version: "1.1.0"
`)
	_, err := FromYAML(yamlData)
	if err == nil {
		t.Fatal("expected error for missing name, got nil")
	}
}

func TestPlaceholderSubstitution(t *testing.T) {
	t.Setenv("CLAWDSTRIKE_TEST_NAME", "SubstitutedPolicy")
	yamlData := []byte(`
version: "1.1.0"
name: "${CLAWDSTRIKE_TEST_NAME}"
`)
	p, err := FromYAML(yamlData)
	if err != nil {
		t.Fatalf("FromYAML: %v", err)
	}
	if p.Name != "SubstitutedPolicy" {
		t.Errorf("expected Name=SubstitutedPolicy, got %q", p.Name)
	}
}

func TestPlaceholderMissingEnvReplacesEmpty(t *testing.T) {
	os.Unsetenv("CLAWDSTRIKE_NONEXISTENT_VAR")
	yamlData := []byte(`
version: "1.1.0"
name: "prefix_${CLAWDSTRIKE_NONEXISTENT_VAR}_suffix"
`)
	p, err := FromYAML(yamlData)
	if err != nil {
		t.Fatalf("FromYAML: %v", err)
	}
	if p.Name != "prefix__suffix" {
		t.Errorf("expected Name=prefix__suffix, got %q", p.Name)
	}
}

func TestFromYAMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	data := []byte(`
version: "1.1.0"
name: FileTest
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	p, err := FromYAMLFile(path)
	if err != nil {
		t.Fatalf("FromYAMLFile: %v", err)
	}
	if p.Name != "FileTest" {
		t.Errorf("expected Name=FileTest, got %q", p.Name)
	}
}

func TestFromYAMLAcceptsScalarExtends(t *testing.T) {
	yamlData := []byte(`
version: "1.1.0"
name: ScalarExtends
extends: strict
`)
	p, err := FromYAML(yamlData)
	if err != nil {
		t.Fatalf("FromYAML: %v", err)
	}
	if len(p.Extends) != 1 || p.Extends[0] != "strict" {
		t.Fatalf("expected extends [strict], got %v", p.Extends)
	}
}

func TestResolveBuiltin(t *testing.T) {
	p, err := Resolve("default")
	if err != nil {
		t.Fatalf("Resolve(default): %v", err)
	}
	if p.Name != "Default" {
		t.Errorf("expected Name=Default, got %q", p.Name)
	}
}

func TestResolveWithExtends(t *testing.T) {
	dir := t.TempDir()

	// Write a child that extends a built-in
	childPath := filepath.Join(dir, "child.yaml")
	childYAML := []byte(`
version: "1.1.0"
name: ChildPolicy
extends:
  - permissive
guards:
  egress_allowlist:
    allow:
      - "custom.example.com"
    block: []
    default_action: block
`)
	if err := os.WriteFile(childPath, childYAML, 0644); err != nil {
		t.Fatalf("write child: %v", err)
	}

	p, err := Resolve(childPath)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Name != "ChildPolicy" {
		t.Errorf("expected Name=ChildPolicy, got %q", p.Name)
	}
	// Child egress should override parent
	if p.Guards.EgressAllowlist == nil {
		t.Fatal("expected EgressAllowlist from child")
	}
	if len(p.Guards.EgressAllowlist.Allow) != 1 || p.Guards.EgressAllowlist.Allow[0] != "custom.example.com" {
		t.Errorf("expected child egress allow, got %v", p.Guards.EgressAllowlist.Allow)
	}
	// Parent's patch_integrity should carry through
	if p.Guards.PatchIntegrity == nil {
		t.Fatal("expected PatchIntegrity inherited from permissive")
	}
}

func TestResolveWithNamespacedBuiltinExtends(t *testing.T) {
	dir := t.TempDir()
	childPath := filepath.Join(dir, "child.yaml")

	childYAML := []byte(`
version: "1.1.0"
name: ChildPolicy
extends: clawdstrike:permissive
`)
	if err := os.WriteFile(childPath, childYAML, 0o644); err != nil {
		t.Fatalf("write child: %v", err)
	}

	p, err := Resolve(childPath)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if p.Name != "ChildPolicy" {
		t.Fatalf("expected child name override, got %q", p.Name)
	}
	if p.Guards.PatchIntegrity == nil {
		t.Fatal("expected guard config inherited from namespaced builtin extends")
	}
}

func TestDefaultPolicyHasAllGuards(t *testing.T) {
	p, err := ByName("default")
	if err != nil {
		t.Fatalf("ByName(default): %v", err)
	}
	if p.Guards.ForbiddenPath == nil {
		t.Error("missing ForbiddenPath")
	}
	if p.Guards.EgressAllowlist == nil {
		t.Error("missing EgressAllowlist")
	}
	if p.Guards.SecretLeak == nil {
		t.Error("missing SecretLeak")
	}
	if p.Guards.PatchIntegrity == nil {
		t.Error("missing PatchIntegrity")
	}
	if p.Guards.McpTool == nil {
		t.Error("missing McpTool")
	}
}

func TestVersion120Accepted(t *testing.T) {
	yamlData := []byte(`
version: "1.2.0"
name: NewVersionTest
`)
	p, err := FromYAML(yamlData)
	if err != nil {
		t.Fatalf("FromYAML with 1.2.0: %v", err)
	}
	if p.Version != "1.2.0" {
		t.Errorf("expected version 1.2.0, got %q", p.Version)
	}
}

func TestCycleDetection(t *testing.T) {
	dir := t.TempDir()

	// A extends B, B extends A → cycle
	aPath := filepath.Join(dir, "a.yaml")
	bPath := filepath.Join(dir, "b.yaml")

	aYAML := []byte("version: \"1.1.0\"\nname: A\nextends:\n  - " + bPath + "\n")
	bYAML := []byte("version: \"1.1.0\"\nname: B\nextends:\n  - " + aPath + "\n")

	if err := os.WriteFile(aPath, aYAML, 0644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(bPath, bYAML, 0644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	_, err := Resolve(aPath)
	if err == nil {
		t.Fatal("expected cycle detection error, got nil")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected error to mention cycle, got: %v", err)
	}
}

func TestResolveAllowsSharedAncestorDAG(t *testing.T) {
	dir := t.TempDir()

	commonPath := filepath.Join(dir, "common.yaml")
	aPath := filepath.Join(dir, "a.yaml")
	bPath := filepath.Join(dir, "b.yaml")
	rootPath := filepath.Join(dir, "root.yaml")

	if err := os.WriteFile(commonPath, []byte(`
version: "1.1.0"
name: Common
guards:
  forbidden_path:
    patterns: ["**/.env"]
`), 0o644); err != nil {
		t.Fatalf("write common: %v", err)
	}

	if err := os.WriteFile(aPath, []byte(`
version: "1.1.0"
name: A
extends:
  - `+commonPath+`
`), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}

	if err := os.WriteFile(bPath, []byte(`
version: "1.1.0"
name: B
extends:
  - `+commonPath+`
`), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	if err := os.WriteFile(rootPath, []byte(`
version: "1.1.0"
name: Root
extends:
  - `+aPath+`
  - `+bPath+`
`), 0o644); err != nil {
		t.Fatalf("write root: %v", err)
	}

	p, err := Resolve(rootPath)
	if err != nil {
		t.Fatalf("expected DAG extends resolution to succeed, got: %v", err)
	}
	if p.Name != "Root" {
		t.Errorf("expected resolved policy name Root, got %q", p.Name)
	}
}

func TestDeepMerge(t *testing.T) {
	base := &Policy{
		Version: "1.1.0",
		Name:    "Base",
		Guards: GuardConfigs{
			ForbiddenPath: &ForbiddenPathConfig{
				Patterns:   []string{"a", "b"},
				Exceptions: []string{"exc1"},
			},
			EgressAllowlist: &EgressAllowlistConfig{
				Allow:         []string{"base.com"},
				DefaultAction: "block",
			},
		},
	}
	child := &Policy{
		Version:       "1.1.0",
		Name:          "Child",
		MergeStrategy: MergeDeep,
		Guards: GuardConfigs{
			ForbiddenPath: &ForbiddenPathConfig{
				Patterns: []string{"c"},
				// Exceptions not set → should inherit from parent
			},
			// EgressAllowlist not set at all → should inherit from parent entirely
		},
	}
	result := Merge(base, child)

	// ForbiddenPath: patterns overridden, exceptions inherited
	if result.Guards.ForbiddenPath == nil {
		t.Fatal("expected ForbiddenPath")
	}
	if len(result.Guards.ForbiddenPath.Patterns) != 1 || result.Guards.ForbiddenPath.Patterns[0] != "c" {
		t.Errorf("expected child patterns [c], got %v", result.Guards.ForbiddenPath.Patterns)
	}
	if len(result.Guards.ForbiddenPath.Exceptions) != 1 || result.Guards.ForbiddenPath.Exceptions[0] != "exc1" {
		t.Errorf("expected inherited exceptions [exc1], got %v", result.Guards.ForbiddenPath.Exceptions)
	}

	// EgressAllowlist: fully inherited from parent
	if result.Guards.EgressAllowlist == nil {
		t.Fatal("expected EgressAllowlist inherited from parent")
	}
	if len(result.Guards.EgressAllowlist.Allow) != 1 || result.Guards.EgressAllowlist.Allow[0] != "base.com" {
		t.Errorf("expected inherited allow [base.com], got %v", result.Guards.EgressAllowlist.Allow)
	}
}

func TestMergeReplace(t *testing.T) {
	base := &Policy{
		Version: "1.1.0",
		Name:    "Base",
		Guards: GuardConfigs{
			ForbiddenPath: &ForbiddenPathConfig{Patterns: []string{"a", "b"}},
			McpTool:       &McpToolConfig{Block: []string{"x"}},
		},
	}
	child := &Policy{
		Version:       "1.1.0",
		Name:          "Child",
		MergeStrategy: MergeReplace,
		Guards: GuardConfigs{
			ForbiddenPath: &ForbiddenPathConfig{Patterns: []string{"c"}},
		},
	}
	result := Merge(base, child)
	if result.Guards.McpTool != nil {
		t.Error("expected McpTool to be nil after replace merge")
	}
	if len(result.Guards.ForbiddenPath.Patterns) != 1 || result.Guards.ForbiddenPath.Patterns[0] != "c" {
		t.Errorf("expected child patterns only, got %v", result.Guards.ForbiddenPath.Patterns)
	}
}

func TestDeepMergeEnabledAndRequireBalanceOverride(t *testing.T) {
	base := &Policy{
		Version: "1.1.0",
		Name:    "Base",
		Guards: GuardConfigs{
			ForbiddenPath: &ForbiddenPathConfig{
				Enabled:  boolPtr(true),
				Patterns: []string{"**/.env"},
			},
			PatchIntegrity: &PatchIntegrityConfig{
				Enabled:        boolPtr(true),
				RequireBalance: boolPtr(true),
				MaxAdditions:   100,
			},
		},
	}
	child := &Policy{
		Version:       "1.1.0",
		Name:          "Child",
		MergeStrategy: MergeDeep,
		Guards: GuardConfigs{
			ForbiddenPath: &ForbiddenPathConfig{
				Enabled: boolPtr(false),
			},
			PatchIntegrity: &PatchIntegrityConfig{
				Enabled:        boolPtr(false),
				RequireBalance: boolPtr(false),
			},
		},
	}

	result := Merge(base, child)
	if result.Guards.ForbiddenPath == nil || result.Guards.ForbiddenPath.Enabled == nil {
		t.Fatal("expected forbidden_path enabled to be present")
	}
	if *result.Guards.ForbiddenPath.Enabled {
		t.Error("expected forbidden_path enabled override to false")
	}

	if result.Guards.PatchIntegrity == nil || result.Guards.PatchIntegrity.RequireBalance == nil {
		t.Fatal("expected patch_integrity require_balance to be present")
	}
	if *result.Guards.PatchIntegrity.RequireBalance {
		t.Error("expected require_balance override to false")
	}
	if result.Guards.PatchIntegrity.Enabled == nil || *result.Guards.PatchIntegrity.Enabled {
		t.Error("expected patch_integrity enabled override to false")
	}
}

func TestMergeInheritsBaseSettingsWhenChildOmitsSettings(t *testing.T) {
	base := &Policy{
		Version: "1.1.0",
		Name:    "Base",
		Settings: PolicySettings{
			FailFast:           true,
			VerboseLogging:     true,
			SessionTimeoutSecs: 90,
		},
		settingsSet: true,
	}
	child := &Policy{
		Version: "1.1.0",
		Name:    "Child",
	}

	result := Merge(base, child)
	if !result.Settings.FailFast || !result.Settings.VerboseLogging || result.Settings.SessionTimeoutSecs != 90 {
		t.Fatalf("expected inherited settings, got %+v", result.Settings)
	}
}

func TestMergeUsesChildSettingsWhenExplicitlySet(t *testing.T) {
	base := &Policy{
		Version: "1.1.0",
		Name:    "Base",
		Settings: PolicySettings{
			FailFast:           true,
			VerboseLogging:     true,
			SessionTimeoutSecs: 90,
		},
		settingsSet: true,
	}
	child := &Policy{
		Version: "1.1.0",
		Name:    "Child",
		Settings: PolicySettings{
			FailFast:           false,
			VerboseLogging:     false,
			SessionTimeoutSecs: 0,
		},
		settingsSet: true,
	}

	result := Merge(base, child)
	if result.Settings.FailFast || result.Settings.VerboseLogging || result.Settings.SessionTimeoutSecs != 0 {
		t.Fatalf("expected explicit child settings to override base, got %+v", result.Settings)
	}
}
