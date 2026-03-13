---
description: "Import and analyze agent activity logs to synthesize security policies"
---

# Observe & Analyze

## Observe-Synth-Tighten Workflow

```
OBSERVE  -->  SYNTH  -->  TIGHTEN
  |             |            |
  v             v            v
Collect     Generate     Harden
events      candidate    iteratively
            policy
```

### Phase 1: Observe

Collect agent activity events in JSONL format. Each event should have:

```jsonl
{"action_type": "file_access", "target": "/workspace/src/app.ts"}
{"action_type": "network_egress", "target": "api.openai.com"}
{"action_type": "shell_command", "target": "npm install express"}
{"action_type": "mcp_tool_call", "target": "read_file"}
{"action_type": "file_write", "target": "/workspace/src/utils.ts", "content": "export function add(a, b) { return a + b; }"}
```

#### Supported Action Types

| action_type | target field | content field |
|-------------|-------------|---------------|
| `file_access` | File path | - |
| `file_write` | File path | File content |
| `network_egress` / `network` | Domain or URL | - |
| `shell_command` / `shell` | Command string | - |
| `mcp_tool_call` / `mcp_tool` | Tool name | - |
| `patch_apply` / `patch` | File path | Patch content |
| `user_input` | - | User text |

### Phase 2: Analyze

After collecting events, analyze patterns:

1. **Action distribution** — What types of actions does the agent perform most?
2. **Network footprint** — Which domains does the agent contact? Are any unexpected?
3. **File access patterns** — What paths does the agent read/write? Any sensitive directories?
4. **Tool usage** — Which MCP tools and shell commands are used?
5. **Anomalies** — Any actions that look suspicious or out of pattern?

### Phase 3: Synthesize

Call `workbench_synth_policy` with the JSONL events to generate a candidate policy. The synthesizer:

- Builds egress allowlists from observed domains
- Creates MCP tool allow/block lists from observed tool usage
- Sets forbidden path patterns based on standard sensitive paths
- Configures path allowlists from observed file access patterns
- Enables shell command guard if shell actions are observed

### Phase 4: Validate & Test

1. Call `workbench_validate_policy` on the synthesized policy.
2. Call `workbench_suggest_scenarios` to generate test cases.
3. Call `workbench_run_all_scenarios` to verify the policy works correctly.

### Phase 5: Tighten

Review the synthesized policy and tighten it:

- **Remove over-permissions** — Are there domains in the allowlist the agent shouldn't contact?
- **Add missing guards** — Enable detection guards (prompt injection, jailbreak) if user-facing.
- **Tighten thresholds** — Reduce patch size limits, lower detection thresholds.
- **Check compliance** — Use `workbench_compliance_check` and close gaps.

## Event Analysis Tips

### Red Flags in Events

Watch for these patterns that suggest the policy should be extra strict:

| Pattern | Risk | Action |
|---------|------|--------|
| Agent accesses `.env` or `.ssh` paths | Credential theft | Block with forbidden_path |
| Network calls to unknown/unusual domains | Data exfiltration | Restrict with egress_allowlist |
| Shell commands with pipes or redirections | Command injection | Enable shell_command guard |
| Many different MCP tools used | Over-privilege | Restrict with mcp_tool block |
| Large file writes | Data manipulation | Enable patch_integrity limits |
| User inputs with instruction keywords | Prompt injection | Enable prompt_injection guard |

### Baseline Comparison

After synthesizing, compare the result against the `strict` ruleset using `workbench_diff_policies` to identify areas where the synthesized policy is weaker.

## Instructions

- Help format raw logs into proper JSONL if needed
- Summarize event patterns before synthesizing
- Validate the synthesized policy immediately with `workbench_validate_policy`
- Run test scenarios to verify before recommending
- Highlight suspicious patterns in the events
- Provide the final policy as clean YAML
- Use `workbench_diff_policies` for before/after comparison
