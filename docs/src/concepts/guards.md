# Guards

Guards are small, focused checks that evaluate a single action against policy/config and return a `GuardResult`.

## The Guard trait

In Rust:

```rust
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
- `McpTool(tool_name, args_json)`

## Built-in guards

Hushclaw ships with:

- `ForbiddenPathGuard`
- `EgressAllowlistGuard`
- `SecretLeakGuard`
- `PatchIntegrityGuard`
- `McpToolGuard`

See the [Guards reference](../reference/guards/README.md) for configs and details.
