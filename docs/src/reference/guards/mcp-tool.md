# McpToolGuard

Restricts MCP tool invocations by name and argument size.

## Actions

- `GuardAction::McpTool(tool_name, args_json)`

## Configuration

```yaml
guards:
  mcp_tool:
    allow: []                  # empty => allow all except `block`
    block:
      - "shell_exec"
      - "run_command"
    require_confirmation:
      - "git_push"
    default_action: allow      # allow|block
    max_args_size: 1048576     # bytes
    additional_allow: []
    remove_allow: []
    additional_block: []
    remove_block: []
```

## Behavior

- `block` takes precedence over `require_confirmation`.
- If `allow` is non-empty, the guard operates in allowlist mode (everything else is blocked).
- `require_confirmation` returns a warning result (allowed but flagged).
- Argument size is computed from JSON-serialized bytes (`serde_json::to_vec(args)`).
