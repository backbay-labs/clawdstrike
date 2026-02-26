# AI Agent Posture

**Ruleset ID:** `ai-agent-posture` (also accepted as `clawdstrike:ai-agent-posture`)

**Source:** `rulesets/ai-agent-posture.yaml`

Posture-aware security policy for AI coding assistants with progressive capability grants. Extends the `ai-agent` ruleset.

## What it does (high level)

- Inherits all guards from the `ai-agent` ruleset (`extends: clawdstrike:ai-agent`)
- Defines three posture states with progressive capabilities:
  - **restricted** (initial): read-only mode with `file_access` only, no budgets
  - **standard**: adds `file_write` and `egress` capabilities with budgets (50 file writes, 20 egress calls)
  - **elevated**: full capabilities (`file_access`, `file_write`, `egress`, `mcp_tool`, `patch`, `shell`) with a 200 file writes budget
- Defines posture transitions:
  - `restricted` -> `standard`: on `user_approval`
  - `standard` -> `elevated`: on `user_approval`
  - any state -> `restricted`: on `critical_violation`
  - `elevated` -> `standard`: on `timeout` (after 1 hour)
  - `standard` -> `restricted`: on `budget_exhausted`

## When to use

Use this ruleset when you want agents to start in a minimal-privilege state and progressively gain capabilities with explicit user approval. This is useful for environments where you want defense-in-depth: even if the base guards allow an action, the posture system can restrict it based on the current session state.

## Posture states

| State | Capabilities | Budgets |
|-------|-------------|---------|
| `restricted` | `file_access` | none |
| `standard` | `file_access`, `file_write`, `egress` | 50 file writes, 20 egress calls |
| `elevated` | `file_access`, `file_write`, `egress`, `mcp_tool`, `patch`, `shell` | 200 file writes |

## View the exact policy

```bash
clawdstrike policy show ai-agent-posture
```
