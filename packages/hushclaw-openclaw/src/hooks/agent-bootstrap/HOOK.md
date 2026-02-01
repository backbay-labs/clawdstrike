---
name: hushclaw-bootstrap
description: Inject security context into agent workspace
metadata: {"openclaw":{"emoji":"lock","events":["agent:bootstrap"]}}
---

# Hushclaw Bootstrap Hook

Injects SECURITY.md into the agent workspace during bootstrap.
This file informs the agent about security constraints and available tools.

## Behavior

1. Loads policy from config
2. Generates security prompt using `generateSecurityPrompt()`
3. Adds SECURITY.md to bootstrap files

## Configuration

The hook reads policy from:
- `event.context.cfg.hushclaw.policy` - Policy file path
- Inline policy config in `event.context.cfg.hushclaw`
