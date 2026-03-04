# Guards

Guards are small, focused checks that evaluate a single action against policy/config and return a `GuardResult`.

## The Guard trait

In Rust:

```rust,ignore
#[async_trait]
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    fn handles(&self, action: &GuardAction<'_>) -> bool;
    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult;
}
```

## Action types

Guards operate on `GuardAction`:

- `FileAccess(path)`
- `FileWrite(path, bytes)`
- `Patch(path, diff)`
- `NetworkEgress(host, port)`
- `ShellCommand(command)`
- `McpTool(tool_name, args_json)`
- `Custom(kind, payload_json)` (used for things like `untrusted_text` scanning)

## Built-in guards

Clawdstrike ships with 13 built-in guards:

- `ForbiddenPathGuard`
- `PathAllowlistGuard`
- `EgressAllowlistGuard`
- `SecretLeakGuard`
- `PatchIntegrityGuard`
- `ShellCommandGuard`
- `McpToolGuard`
- `PromptInjectionGuard`
- `JailbreakGuard`
- `ComputerUseGuard`
- `RemoteDesktopSideChannelGuard`
- `InputInjectionCapabilityGuard`
- `SpiderSenseGuard`

See the [Guards reference](../reference/guards/README.md) for configs and details.
