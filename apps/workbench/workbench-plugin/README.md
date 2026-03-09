# ClawdStrike Workbench Plugin for Claude Code

Claude Code plugin for the ClawdStrike Policy Workbench. Provides MCP tools for scenario testing, policy validation, compliance scoring, and policy synthesis.

## Installation

### Prerequisites

- [Claude Code](https://claude.ai/code) installed
- [Bun](https://bun.sh/) runtime (for the MCP server)

### Setup

```bash
# Install MCP server dependencies
cd apps/workbench/mcp-server
bun install

# Install the plugin
claude plugin add ./workbench-plugin
```

### Manual MCP Setup

To configure the MCP server without the plugin, add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "clawdstrike-workbench": {
      "command": "bun",
      "args": ["run", "/path/to/apps/workbench/mcp-server/index.ts"]
    }
  }
}
```

## Skills

### /workbench:build-scenario

Create test scenarios with proper payloads, expected verdicts, and guard targeting.

```
/workbench:build-scenario Test that reading SSH private keys is blocked
```

### /workbench:tighten-policy

Analyze a policy and apply specific tightening actions based on guard coverage, compliance gaps, and test results.

```
/workbench:tighten-policy Block all egress except api.openai.com and registry.npmjs.org
```

### /workbench:security-audit

Run a 6-stage audit: validate, check compliance (HIPAA/SOC2/PCI-DSS), generate and run scenarios, report findings.

```
/workbench:security-audit Audit my current policy
```

### /workbench:observe-analyze

Import agent activity logs (JSONL), analyze patterns, and synthesize a policy using the observe-synth-tighten workflow.

```
/workbench:observe-analyze Import and analyze these agent logs to build a policy
```

## MCP Tools

| Tool | Purpose |
|------|---------|
| `workbench_create_scenario` | Create a test scenario with action type, payload, expected verdict |
| `workbench_run_scenario` | Run a single scenario against a policy YAML |
| `workbench_run_all_scenarios` | Batch-run scenarios with summary report |
| `workbench_validate_policy` | Validate policy YAML for schema errors and warnings |
| `workbench_synth_policy` | Synthesize a policy from JSONL agent events |
| `workbench_compliance_check` | Score against HIPAA, SOC2, PCI-DSS |
| `workbench_list_guards` | List all 13 guards with config schemas |
| `workbench_suggest_scenarios` | Generate test scenarios for a policy's guards |
| `workbench_diff_policies` | Semantic diff of two policies |
| `workbench_export_policy` | Convert policy to JSON or TOML |

## MCP Resources

| Resource | URI |
|----------|-----|
| Built-in scenarios | `workbench://scenarios/builtin` |
| Guard registry | `workbench://guards/registry` |
| Built-in rulesets | `workbench://rulesets/builtin` |

## License

Apache-2.0
