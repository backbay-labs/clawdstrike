package policy

import (
	"fmt"
)

// MaxExtendsDepth is the maximum recursion depth for policy resolution.
const MaxExtendsDepth = 32

// Resolve loads a policy spec (built-in name or file path) and resolves its extends chain.
func Resolve(spec string) (*Policy, error) {
	visited := make(map[string]bool)
	return resolveAt(spec, 0, visited)
}

func resolveAt(spec string, depth int, visited map[string]bool) (*Policy, error) {
	if depth > MaxExtendsDepth {
		return nil, fmt.Errorf("policy: extends depth exceeds %d", MaxExtendsDepth)
	}

	if visited[spec] {
		return nil, fmt.Errorf("policy: cycle detected in extends chain: %q", spec)
	}
	visited[spec] = true

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
		resolved, err := resolveAt(ext, depth+1, visited)
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
	case MergeDeep:
		result.Guards = deepMergeGuards(base.Guards, child.Guards)
	default: // merge — replace each guard config if present in child
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

// deepMergeGuards performs field-by-field merge of guard configs.
// Child values override parent; unset child fields inherit from parent.
func deepMergeGuards(base, child GuardConfigs) GuardConfigs {
	result := base

	if child.ForbiddenPath != nil {
		if base.ForbiddenPath != nil {
			merged := *base.ForbiddenPath
			if len(child.ForbiddenPath.Patterns) > 0 {
				merged.Patterns = child.ForbiddenPath.Patterns
			}
			if len(child.ForbiddenPath.Exceptions) > 0 {
				merged.Exceptions = child.ForbiddenPath.Exceptions
			}
			result.ForbiddenPath = &merged
		} else {
			result.ForbiddenPath = child.ForbiddenPath
		}
	}

	if child.EgressAllowlist != nil {
		if base.EgressAllowlist != nil {
			merged := *base.EgressAllowlist
			if len(child.EgressAllowlist.Allow) > 0 {
				merged.Allow = child.EgressAllowlist.Allow
			}
			if len(child.EgressAllowlist.Block) > 0 {
				merged.Block = child.EgressAllowlist.Block
			}
			if child.EgressAllowlist.DefaultAction != "" {
				merged.DefaultAction = child.EgressAllowlist.DefaultAction
			}
			result.EgressAllowlist = &merged
		} else {
			result.EgressAllowlist = child.EgressAllowlist
		}
	}

	if child.SecretLeak != nil {
		if base.SecretLeak != nil {
			merged := *base.SecretLeak
			if len(child.SecretLeak.Patterns) > 0 {
				merged.Patterns = child.SecretLeak.Patterns
			}
			if len(child.SecretLeak.SkipPaths) > 0 {
				merged.SkipPaths = child.SecretLeak.SkipPaths
			}
			result.SecretLeak = &merged
		} else {
			result.SecretLeak = child.SecretLeak
		}
	}

	if child.PatchIntegrity != nil {
		if base.PatchIntegrity != nil {
			merged := *base.PatchIntegrity
			if child.PatchIntegrity.MaxAdditions > 0 {
				merged.MaxAdditions = child.PatchIntegrity.MaxAdditions
			}
			if child.PatchIntegrity.MaxDeletions > 0 {
				merged.MaxDeletions = child.PatchIntegrity.MaxDeletions
			}
			if child.PatchIntegrity.RequireBalance {
				merged.RequireBalance = true
			}
			if child.PatchIntegrity.MaxImbalanceRatio > 0 {
				merged.MaxImbalanceRatio = child.PatchIntegrity.MaxImbalanceRatio
			}
			if len(child.PatchIntegrity.ForbiddenPatterns) > 0 {
				merged.ForbiddenPatterns = child.PatchIntegrity.ForbiddenPatterns
			}
			result.PatchIntegrity = &merged
		} else {
			result.PatchIntegrity = child.PatchIntegrity
		}
	}

	if child.McpTool != nil {
		if base.McpTool != nil {
			merged := *base.McpTool
			if len(child.McpTool.Allow) > 0 {
				merged.Allow = child.McpTool.Allow
			}
			if len(child.McpTool.Block) > 0 {
				merged.Block = child.McpTool.Block
			}
			if len(child.McpTool.RequireConfirmation) > 0 {
				merged.RequireConfirmation = child.McpTool.RequireConfirmation
			}
			if child.McpTool.DefaultAction != "" {
				merged.DefaultAction = child.McpTool.DefaultAction
			}
			if child.McpTool.MaxArgsSize > 0 {
				merged.MaxArgsSize = child.McpTool.MaxArgsSize
			}
			result.McpTool = &merged
		} else {
			result.McpTool = child.McpTool
		}
	}

	if child.PromptInjection != nil {
		if base.PromptInjection != nil {
			merged := *base.PromptInjection
			if child.PromptInjection.WarnThreshold > 0 {
				merged.WarnThreshold = child.PromptInjection.WarnThreshold
			}
			if child.PromptInjection.BlockThreshold > 0 {
				merged.BlockThreshold = child.PromptInjection.BlockThreshold
			}
			if child.PromptInjection.MaxScanBytes > 0 {
				merged.MaxScanBytes = child.PromptInjection.MaxScanBytes
			}
			result.PromptInjection = &merged
		} else {
			result.PromptInjection = child.PromptInjection
		}
	}

	if child.Jailbreak != nil {
		result.Jailbreak = child.Jailbreak
	}

	return result
}
