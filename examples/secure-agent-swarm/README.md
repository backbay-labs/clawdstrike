# Secure Agent Swarm Example

A 3-agent swarm where each agent has different security policies enforced through Clawdstrike adapters and hushd attribution.

## Architecture

```
┌─────────────┐  ClaudeAdapter     ┌────────┐
│   Planner   │───────────────────▶│        │
│  (ai-agent) │                    │        │
├─────────────┤  VercelAIAdapter   │ hushd  │
│    Coder    │───────────────────▶│/check  │
│   (strict)  │                    │/audit  │
├─────────────┤  ToolBoundary      │/events │
│  Reviewer   │───────────────────▶│        │
│ (read-only) │                    └────────┘
└─────────────┘
```

## Agents

| Agent    | Adapter              | Policy    | Capabilities                         |
|----------|----------------------|-----------|--------------------------------------|
| Planner  | `ClaudeAdapter`      | ai-agent  | read_file, list_directory, create_plan |
| Coder    | `VercelAIAdapter`    | strict    | write_file, apply_patch              |
| Reviewer | `FrameworkToolBoundary` | read-only | read_file, search, grep             |

## Prerequisites

```bash
# Start hushd with strict ruleset
cargo run -p hushd -- --ruleset strict
```

## Run

```bash
npm install
npx tsx index.ts
```

## Expected Output

- Planner: all actions allowed (read-only + planning)
- Coder: `write_file src/feature.ts` allowed, `write_file ~/.ssh/config` blocked, `shell_exec` blocked
- Reviewer: read actions allowed, `write_file` blocked
- Audit queries show per-agent attribution
- SSE events stream in real-time with agent_id
