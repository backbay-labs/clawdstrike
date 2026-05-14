# Adopting HushSpec

HushSpec is a portable, open specification for AI agent security rules. Clawdstrike fully supports HushSpec documents alongside its native policy format.

## Why HushSpec?

- **Portable**: HushSpec documents work across any engine that implements the spec
- **Simpler**: No engine-specific merge helpers, async config, or runtime settings
- **Open**: Neutral spec not tied to any vendor

## Format Detection

Clawdstrike auto-detects the format based on the top-level key:

```yaml
# HushSpec format
hushspec: "0.1.0"
name: my-policy
rules:
  egress:
    allow: ["api.openai.com"]
    default: block
```

```yaml
# Clawdstrike-native format
version: "1.5.0"
name: my-policy
guards:
  egress_allowlist:
    allow: ["api.openai.com"]
    default_action: block
```

## Converting Existing Policies

Use the CLI to convert between formats:

```bash
# Clawdstrike → HushSpec
hush policy migrate my-policy.yaml --to hushspec --output my-policy.hushspec.yaml

# HushSpec → Clawdstrike
hush policy migrate my-policy.hushspec.yaml --to 1.5.0 --output my-policy.yaml
```

## Key Differences

| Concept | HushSpec | Clawdstrike |
|---------|----------|-------------|
| Top-level key | `hushspec: "0.1.0"` | `version: "1.5.0"` |
| Rules container | `rules:` | `guards:` |
| Tool access | `rules.tool_access` | `guards.mcp_tool` |
| Egress | `rules.egress` | `guards.egress_allowlist` |
| Secret detection | `rules.secret_patterns` | `guards.secret_leak` |
| Default action field | `default:` | `default_action:` |
| Path allowlist read | `read:` | `file_access_allow:` |
| Merge helpers | Not supported | `additional_*`, `remove_*` |
| Settings | Not supported | `settings:` block |
| Broker | Not supported | `broker:` block |
| Custom guards | Not supported | `custom_guards:`, `guards.custom[]` |

## What Stays in Clawdstrike Format

Some features only exist in Clawdstrike-native format:
- **Settings**: `fail_fast`, `verbose_logging`, `session_timeout_secs`
- **Broker config**: Secret brokering with capability authority
- **Custom guard plugins**: Package-based guard extensions
- **Async guard config**: Timeout, cache, circuit breaker, retry
- **Merge helpers**: `additional_patterns`, `remove_patterns` for fine-grained inheritance

These are engine-specific concerns and are injected as defaults when compiling HushSpec.

## HushSpec Extensions

HushSpec supports optional extensions for advanced features:

```yaml
hushspec: "0.1.0"
rules:
  egress:
    allow: ["api.openai.com"]
    default: block
extensions:
  posture:
    initial: standard
    states:
      standard:
        capabilities: [file_access, egress]
      restricted:
        capabilities: [file_access]
    transitions:
      - from: "*"
        to: restricted
        on: critical_violation
  detection:
    prompt_injection:
      block_at_or_above: high
    jailbreak:
      block_threshold: 40
```

## Programmatic Usage

### Rust

```rust
use clawdstrike::Policy;

// Auto-detect format
let policy = Policy::from_yaml_auto(yaml_str)?;

// Or use the compiler directly
use clawdstrike::hushspec_compiler;
let spec = hushspec::HushSpec::parse(yaml_str)?;
let policy = hushspec_compiler::compile(&spec)?;
```

### TypeScript

```typescript
import { parse, validate } from '@hushspec/core';

const result = parse(yamlString);
if (result.ok) {
  const validation = validate(result.value);
  console.log(validation.valid);
}
```

## Recommendation

- **New projects**: Start with HushSpec format
- **Existing projects**: Continue using Clawdstrike format; migrate incrementally
- **Shared policies**: Use HushSpec for policies shared across teams/engines
