# Guards Reference

Hushclaw ships with five built-in guards. Guards evaluate a `GuardAction` plus `GuardContext` and return a `GuardResult`.

## Built-in guards

| Guard | Purpose | Config key |
|------|---------|------------|
| [ForbiddenPathGuard](./forbidden-path.md) | Block access to sensitive paths | `guards.forbidden_path` |
| [EgressAllowlistGuard](./egress.md) | Control network egress | `guards.egress_allowlist` |
| [SecretLeakGuard](./secret-leak.md) | Detect secrets in writes/patches | `guards.secret_leak` |
| [PatchIntegrityGuard](./patch-integrity.md) | Block dangerous patches | `guards.patch_integrity` |
| [McpToolGuard](./mcp-tool.md) | Restrict MCP tool usage | `guards.mcp_tool` |
| [PromptInjectionGuard](./prompt-injection.md) | Detect prompt-injection in untrusted text | `guards.prompt_injection` |

## Action coverage

| Guard | FileAccess | FileWrite | Patch | NetworkEgress | McpTool |
|------|------------|-----------|-------|---------------|---------|
| ForbiddenPath | ✓ | ✓ | ✓ | | |
| EgressAllowlist | | | | ✓ | |
| SecretLeak | | ✓ | ✓ | | |
| PatchIntegrity | | | ✓ | | |
| McpTool | | | | | ✓ |

PromptInjectionGuard handles only `GuardAction::Custom("untrusted_text", ...)`.

## Evaluation order and fail-fast

`HushEngine` evaluates applicable guards in this order:

1. `forbidden_path`
2. `egress_allowlist`
3. `secret_leak`
4. `patch_integrity`
5. `mcp_tool`
6. `prompt_injection` (only for `Custom("untrusted_text", ...)`)

If `settings.fail_fast: true`, evaluation stops on the first blocked result. Otherwise, all applicable guards run and the final verdict is the highest severity across results (block > warn > allow).

## Defaults and “disabling” a guard

If a guard config is omitted from the policy, the guard runs with its default configuration.
There is no `enabled: false` toggle in the current policy schema; to effectively disable a guard you must configure it to allow everything (e.g. empty forbidden path patterns, `default_action: allow`, etc.).
