# AI Agent

**Ruleset ID:** `ai-agent` (also accepted as `clawdstrike:ai-agent`)

**Source:** `rulesets/ai-agent.yaml`

Policy tuned for AI coding assistants (expanded egress allowlist + slightly higher patch limits).

## What it does (high level)

- Blocks common credential/secret paths; allows `.env.example`/`.env.template` as documentation exceptions
- Allows egress to common AI APIs, code hosts, registries, and docs; blocks everything else by default
- Includes secret leak patterns and skips common test/fixture paths
- Relaxes patch size limits vs `default`
- Blocks a smaller set of MCP tools by default and requires confirmation for deployment/publish-like tools

## View the exact policy

```bash
clawdstrike policy show ai-agent
```
