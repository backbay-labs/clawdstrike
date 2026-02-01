# McpToolGuard

Controls which MCP tools can be invoked by agents.

## Overview

The McpToolGuard manages access to MCP (Model Context Protocol) tools, allowing you to create allowlists or denylists for specific tools.

## Configuration

### Deny specific tools

```yaml
tools:
  denied:
    - "shell_exec_raw"
    - "network_fetch_any"
    - "file_delete"
```

### Allow only specific tools

```yaml
tools:
  mode: allowlist
  allowed:
    - "read_file"
    - "write_file"
    - "list_directory"
    - "run_command"
```

### Default (all allowed except denied)

```yaml
tools:
  allowed: []  # Empty = all allowed
  denied:
    - "dangerous_tool"
```

## Example Violations

```
Event: ToolCall { tool_name: "shell_exec_raw", params: {...} }
Decision: Deny
Guard: McpToolGuard
Severity: Medium
Reason: Tool 'shell_exec_raw' is in deny list
```

```
Event: ToolCall { tool_name: "unknown_tool", params: {...} }
Decision: Deny
Guard: McpToolGuard
Severity: Low
Reason: Tool 'unknown_tool' not in allow list
```

## Tool Policies

Set per-tool limits:

```yaml
tools:
  policies:
    write_file:
      max_size_bytes: 1048576    # 1MB limit
      require_diff: true          # Must show diff first

    run_command:
      timeout_seconds: 60
      max_output_lines: 1000

    read_file:
      max_size_bytes: 5242880    # 5MB limit
```

## Common Tool Categories

### Safe for most use cases
```yaml
tools:
  allowed:
    - "read_file"
    - "write_file"
    - "list_directory"
    - "search_files"
```

### Potentially dangerous
```yaml
tools:
  denied:
    - "shell_exec_raw"      # Unbounded shell access
    - "network_fetch_any"   # Unbounded network
    - "file_delete"         # Destructive
    - "system_info"         # Information disclosure
```

### Require confirmation
```yaml
tools:
  require_confirmation:
    - "run_command"
    - "write_file"
    - "delete_file"
```

## Wildcard Matching

Match tool name patterns:

```yaml
tools:
  denied:
    - "shell_*"       # All shell tools
    - "*_dangerous"   # Anything ending in _dangerous
    - "debug_*"       # All debug tools
```

## Testing

```bash
# Test tool access
echo '{"event_type":"tool_call","data":{"tool_name":"shell_exec_raw"}}' | \
  hush policy test - --policy policy.yaml

# Expected: DENIED
```

## Integration with OpenClaw

When using the OpenClaw plugin, tool calls are automatically intercepted:

```typescript
// This is checked against policy
const result = await agent.invoke_tool("write_file", {
  path: "./output.txt",
  content: "Hello"
});
```

## Related

- [OpenClaw Integration](../../guides/openclaw-integration.md) - Plugin setup
- [Policies](../../concepts/policies.md) - Configure tool access
