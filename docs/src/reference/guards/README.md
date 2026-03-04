# Guards Reference

Clawdstrike ships with 13 built-in guards. Guards evaluate a `GuardAction` plus `GuardContext` and return a `GuardResult`.

## Built-in Guards

| Guard | Purpose | Config key |
|-------|---------|------------|
| [ForbiddenPathGuard](./forbidden-path.md) | Block access to sensitive paths | `guards.forbidden_path` |
| [PathAllowlistGuard](./path-allowlist.md) | Deny-by-default path allowlisting | `guards.path_allowlist` |
| [EgressAllowlistGuard](./egress.md) | Control network egress | `guards.egress_allowlist` |
| [SecretLeakGuard](./secret-leak.md) | Detect secrets in writes/patches | `guards.secret_leak` |
| [PatchIntegrityGuard](./patch-integrity.md) | Block dangerous patches | `guards.patch_integrity` |
| [ShellCommandGuard](./shell-command.md) | Validate shell commands against forbidden patterns | `guards.shell_command` |
| [McpToolGuard](./mcp-tool.md) | Restrict MCP tool usage | `guards.mcp_tool` |
| [PromptInjectionGuard](./prompt-injection.md) | Detect prompt-injection in untrusted text | `guards.prompt_injection` |
| [JailbreakGuard](./jailbreak.md) | Detect jailbreak attempts with 4-layer analysis | `guards.jailbreak` |
| [ComputerUseGuard](./computer-use.md) | CUA gateway with configurable enforcement modes | `guards.computer_use` |
| [RemoteDesktopSideChannelGuard](./remote-desktop-side-channel.md) | Control remote desktop channels | `guards.remote_desktop_side_channel` |
| [InputInjectionCapabilityGuard](./input-injection-capability.md) | Control input injection types and probes | `guards.input_injection_capability` |
| [SpiderSenseGuard](./spider-sense.md) | Embedding-based threat screening with optional deep-path escalation | `guards.spider_sense` |

## Prompt-security utilities (not policy guards)

Some prompt-security features are implemented as standalone utilities and are wired into integrations (for example, `@clawdstrike/vercel-ai`):

- [Output Sanitizer](./output-sanitizer.md) — redact secrets/PII from model output (including streaming)
- [Watermarking](./watermarking.md) — embed signed provenance markers in prompts

## Action Coverage

| Guard | FileAccess | FileWrite | Patch | NetworkEgress | ShellCommand | McpTool | Custom |
|-------|------------|-----------|-------|---------------|--------------|---------|--------|
| ForbiddenPath | ✓ | ✓ | ✓ | | | | |
| PathAllowlist | ✓ | ✓ | ✓ | | | | |
| EgressAllowlist | | | | ✓ | | | |
| SecretLeak | | ✓ | ✓ | | | | |
| PatchIntegrity | | | ✓ | | | | |
| ShellCommand | | | | | ✓ | | |
| McpTool | | | | | | ✓ | |
| PromptInjection | | | | | | | ✓ (`untrusted_text`) |
| Jailbreak | | | | | | | ✓ (`user_input`) |
| ComputerUse | | | | | | | ✓ (`remote.*`, `input.*`) |
| RemoteDesktopSideChannel | | | | | | | ✓ (`remote.*` side channels) |
| InputInjectionCapability | | | | | | | ✓ (`input.inject`) |
| SpiderSense | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

## Evaluation Order and Fail-Fast

`HushEngine` evaluates applicable guards in this order:

1. `forbidden_path`
2. `path_allowlist`
3. `egress_allowlist`
4. `secret_leak`
5. `patch_integrity`
6. `shell_command`
7. `mcp_tool`
8. `prompt_injection` (only for `Custom("untrusted_text", ...)`)
9. `jailbreak` (only for `Custom("user_input", ...)`)
10. `computer_use` (only for `Custom("remote.*"|"input.*", ...)`)
11. `remote_desktop_side_channel` (only for `Custom("remote.*", ...)` side channels)
12. `input_injection_capability` (only for `Custom("input.inject", ...)`)
13. Custom/extra guards (if registered)

Async guards (including Spider-Sense when configured via `guards.spider_sense`) run in the deep stage after fast/std guards, and only when earlier stages did not deny.

If `settings.fail_fast: true`, evaluation stops on the first blocked result. Otherwise, all applicable guards run and the final verdict is the highest severity across results (block > warn > allow).

## Defaults and Disabling a Guard

If a guard config is omitted from the policy, the guard runs with its default configuration.

Every guard config supports an `enabled` field. Set `enabled: false` to disable a guard:

```yaml
guards:
  forbidden_path:
    enabled: false

  egress_allowlist:
    enabled: false
```

## Custom Guards

You can extend `HushEngine` with custom guards:

```rust,ignore
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
        GuardResult::allow(self.name())
    }
}

// Register with engine
let engine = HushEngine::new().with_extra_guard(Box::new(MyCustomGuard));
```

See [Custom Guards Guide](../../guides/custom-guards.md) for more details.

## Guard Categories

### Access Control Guards

Control what resources can be accessed:

- **ForbiddenPathGuard** — Block sensitive filesystem paths
- **PathAllowlistGuard** — Deny-by-default path allowlisting
- **EgressAllowlistGuard** — Network destinations
- **ShellCommandGuard** — Shell command validation
- **McpToolGuard** — Tool invocations

### Content Analysis Guards

Analyze content for security issues:

- **SecretLeakGuard** — Detect secrets in output
- **PatchIntegrityGuard** — Validate patch safety
- **PromptInjectionGuard** — Detect instruction hijacking
- **JailbreakGuard** — Detect safety bypass attempts
- **SpiderSenseGuard** — Embedding similarity screening with optional deep-path escalation

### Computer Use (CUA) Guards

Control AI agent interactions with remote desktops:

- **ComputerUseGuard** — CUA gateway with enforcement modes
- **RemoteDesktopSideChannelGuard** — Channel-level control (clipboard, file transfer, etc.)
- **InputInjectionCapabilityGuard** — Input type validation and postcondition probes

### Output Processing

Process LLM output before delivery:

- **Output Sanitizer** — Redact sensitive data
- **Watermarking** — Add provenance tracking
