package policy

import (
	"fmt"
)

// MaxExtendsDepth is the maximum recursion depth for policy resolution.
const MaxExtendsDepth = 32

// Resolve loads a policy spec (built-in name or file path) and resolves its extends chain.
func Resolve(spec string) (*Policy, error) {
	return resolveAt(spec, 0)
}

func resolveAt(spec string, depth int) (*Policy, error) {
	if depth > MaxExtendsDepth {
		return nil, fmt.Errorf("policy: extends depth exceeds %d", MaxExtendsDepth)
	}

	p, err := load(spec)
	if err != nil {
		return nil, err
	}

	if len(p.Extends) == 0 {
		return p, nil
	}

	// Resolve base policies left-to-right, then merge child on top.
	var base *Policy
	for _, ext := range p.Extends {
		resolved, err := resolveAt(ext, depth+1)
		if err != nil {
			return nil, fmt.Errorf("policy: resolving extends %q: %w", ext, err)
		}
		if base == nil {
			base = resolved
		} else {
			base = Merge(base, resolved)
		}
	}

	// Merge the child policy onto the resolved base.
	result := Merge(base, p)
	// Clear extends so it doesn't re-resolve.
	result.Extends = nil
	return result, nil
}

// load tries built-in name first, then falls back to file path.
func load(spec string) (*Policy, error) {
	if IsBuiltin(spec) {
		return ByName(spec)
	}
	return FromYAMLFile(spec)
}

// Merge combines base and child policies. The child overrides fields present
// in both, controlled by the child's MergeStrategy.
func Merge(base, child *Policy) *Policy {
	result := &Policy{
		Version:       child.Version,
		Name:          child.Name,
		Description:   child.Description,
		MergeStrategy: child.MergeStrategy,
		Settings:      child.Settings,
	}

	if result.Version == "" {
		result.Version = base.Version
	}
	if result.Name == "" {
		result.Name = base.Name
	}
	if result.Description == "" {
		result.Description = base.Description
	}

	strategy := child.MergeStrategy
	if strategy == "" {
		strategy = MergeMerge
	}

	switch strategy {
	case MergeReplace:
		result.Guards = child.Guards
	default: // merge / deep_merge — replace each guard config if present in child
		result.Guards = base.Guards
		if child.Guards.ForbiddenPath != nil {
			result.Guards.ForbiddenPath = child.Guards.ForbiddenPath
		}
		if child.Guards.EgressAllowlist != nil {
			result.Guards.EgressAllowlist = child.Guards.EgressAllowlist
		}
		if child.Guards.SecretLeak != nil {
			result.Guards.SecretLeak = child.Guards.SecretLeak
		}
		if child.Guards.PatchIntegrity != nil {
			result.Guards.PatchIntegrity = child.Guards.PatchIntegrity
		}
		if child.Guards.McpTool != nil {
			result.Guards.McpTool = child.Guards.McpTool
		}
		if child.Guards.PromptInjection != nil {
			result.Guards.PromptInjection = child.Guards.PromptInjection
		}
		if child.Guards.Jailbreak != nil {
			result.Guards.Jailbreak = child.Guards.Jailbreak
		}
	}

	return result
}
