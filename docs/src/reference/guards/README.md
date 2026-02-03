# Guards Reference

Clawdstrike ships with nine built-in guards plus utilities for output sanitization and watermarking. Guards evaluate a `GuardAction` plus `GuardContext` and return a `GuardResult`.

## Built-in Guards

| Guard | Purpose | Config key |
|-------|---------|------------|
| [ForbiddenPathGuard](./forbidden-path.md) | Block access to sensitive paths | `guards.forbidden_path` |
| [EgressAllowlistGuard](./egress.md) | Control network egress | `guards.egress_allowlist` |
| [SecretLeakGuard](./secret-leak.md) | Detect secrets in writes/patches | `guards.secret_leak` |
| [PatchIntegrityGuard](./patch-integrity.md) | Block dangerous patches | `guards.patch_integrity` |
| [McpToolGuard](./mcp-tool.md) | Restrict MCP tool usage | `guards.mcp_tool` |
| [PromptInjectionGuard](./prompt-injection.md) | Detect prompt-injection in untrusted text | `guards.prompt_injection` |
| [JailbreakGuard](./jailbreak.md) | Detect jailbreak attempts with 4-layer analysis | `guards.jailbreak` |

## Output Processing

| Component | Purpose | Config key |
|-----------|---------|------------|
| [Output Sanitizer](./output-sanitizer.md) | Redact secrets/PII from LLM output | `guards.output_sanitizer` |
| [Watermarking](./watermarking.md) | Embed provenance markers in prompts | `guards.watermarking` |

## Action Coverage

| Guard | FileAccess | FileWrite | Patch | NetworkEgress | McpTool | Custom |
|-------|------------|-----------|-------|---------------|---------|--------|
| ForbiddenPath | ✓ | ✓ | ✓ | | | |
| EgressAllowlist | | | | ✓ | | |
| SecretLeak | | ✓ | ✓ | | | |
| PatchIntegrity | | | ✓ | | | |
| McpTool | | | | | ✓ | |
| PromptInjection | | | | | | ✓ (`untrusted_text`) |
| Jailbreak | | | | | | ✓ (`user_input`) |

## Evaluation Order and Fail-Fast

`HushEngine` evaluates applicable guards in this order:

1. `forbidden_path`
2. `egress_allowlist`
3. `secret_leak`
4. `patch_integrity`
5. `mcp_tool`
6. `prompt_injection` (only for `Custom("untrusted_text", ...)`)
7. `jailbreak` (only for `Custom("user_input", ...)`)
8. Custom/extra guards (if registered)

If `settings.fail_fast: true`, evaluation stops on the first blocked result. Otherwise, all applicable guards run and the final verdict is the highest severity across results (block > warn > allow).

## Defaults and "Disabling" a Guard

If a guard config is omitted from the policy, the guard runs with its default configuration.

There is no `enabled: false` toggle in the current policy schema. To effectively disable a guard, configure it to allow everything:

```yaml
# "Disable" ForbiddenPathGuard by having no patterns
guards:
  forbidden_path:
    patterns: []

# "Disable" EgressAllowlist by allowing all
guards:
  egress_allowlist:
    default_action: allow
```

## Custom Guards

You can extend `HushEngine` with custom guards:

```rust
use clawdstrike::{Guard, GuardAction, GuardContext, GuardResult};

struct MyCustomGuard;

#[async_trait::async_trait]
impl Guard for MyCustomGuard {
    fn name(&self) -> &str {
        "my_custom_guard"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::Custom(kind, _) if *kind == "my_action")
    }

    async fn check(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
    ) -> GuardResult {
        // Your logic here
        GuardResult::allow()
    }
}

// Register with engine
let engine = HushEngine::new().with_extra_guard(Box::new(MyCustomGuard));
```

See [Custom Guards Guide](../../guides/custom-guards.md) for more details.

## Guard Categories

### Access Control Guards

Control what resources can be accessed:

- **ForbiddenPathGuard** — Filesystem paths
- **EgressAllowlistGuard** — Network destinations
- **McpToolGuard** — Tool invocations

### Content Analysis Guards

Analyze content for security issues:

- **SecretLeakGuard** — Detect secrets in output
- **PatchIntegrityGuard** — Validate patch safety
- **PromptInjectionGuard** — Detect instruction hijacking
- **JailbreakGuard** — Detect safety bypass attempts

### Output Processing

Process LLM output before delivery:

- **Output Sanitizer** — Redact sensitive data
- **Watermarking** — Add provenance tracking
