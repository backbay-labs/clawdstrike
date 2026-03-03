package policy

import (
	"embed"
	"fmt"
)

//go:embed rulesets/*.yaml
var rulesetFS embed.FS

// Known built-in ruleset names.
var builtinNames = map[string]string{
	"permissive": "rulesets/permissive.yaml",
	"default":    "rulesets/default.yaml",
	"strict":     "rulesets/strict.yaml",
	"ai-agent":   "rulesets/ai-agent.yaml",
	"cicd":       "rulesets/cicd.yaml",
}

// BuiltinNames returns the list of available built-in ruleset names.
func BuiltinNames() []string {
	names := make([]string, 0, len(builtinNames))
	for n := range builtinNames {
		names = append(names, n)
	}
	return names
}

// IsBuiltin reports whether name is a built-in ruleset.
func IsBuiltin(name string) bool {
	_, ok := builtinNames[name]
	return ok
}

// ByName loads a built-in ruleset by name.
func ByName(name string) (*Policy, error) {
	path, ok := builtinNames[name]
	if !ok {
		return nil, fmt.Errorf("policy: unknown built-in ruleset %q", name)
	}
	data, err := rulesetFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read embedded ruleset %q: %w", name, err)
	}
	return FromYAML(data)
}
