---
name: hushclaw-agent-bootstrap
description: "Inject security context into agent prompts"
metadata: {"openclaw":{"emoji":"🛡️","events":["agent:bootstrap"]}}
---

# HushClaw Agent Bootstrap Hook

This hook runs during agent initialization to inject security context
into the agent's workspace. This helps the agent understand its security
constraints and use the `policy_check` tool appropriately.

## Features

- **Security Prompt Injection**: Adds SECURITY.md to agent's bootstrap files
- **Policy Summary**: Includes summary of active security constraints
- **Tool Guidance**: Advises agent to use policy_check before risky operations

## Behavior

On `agent:bootstrap` event:

1. Reads the current security policy configuration
2. Generates a SECURITY.md file with:
   - Summary of security constraints
   - List of forbidden paths/domains
   - Guidance on using policy_check tool
3. Adds SECURITY.md to the agent's bootstrap files

## Generated SECURITY.md Example

```markdown
# Security Policy

You are subject to the following security constraints:

## Forbidden Paths
- ~/.ssh, ~/.aws, ~/.gnupg
- /etc/shadow, /etc/passwd
- *.pem, *.key files

## Network Restrictions
- Only allowlisted domains are accessible
- Allowed: api.anthropic.com, api.openai.com, *.github.com

## Before Risky Operations
Use the `policy_check` tool to verify:
- File access is allowed
- Network egress is permitted
- Commands are safe to execute
```
