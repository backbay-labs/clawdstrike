# Hello Secure Agent

A simple example demonstrating Clawdstrike **tool-layer guardrails** in OpenClaw.

## Important limitations

This example demonstrates enforcement at the **OpenClaw tool boundary** (preflight `policy_check` + post-action `tool_result_persist` output blocking/redaction). It is **not** an OS sandbox and cannot prevent actions that bypass the OpenClaw tool layer.

## Setup

This example contains configuration files only (`openclaw.json` and `policy.yaml`). No `package.json` or `npm install` step is needed.

```bash
cd packages/adapters/clawdstrike-openclaw/examples/hello-secure-agent

# Ensure the clawdstrike-openclaw plugin is installed and enabled
openclaw plugins enable @clawdstrike/openclaw

# Start the OpenClaw gateway
openclaw start
```

## Try It

1. **Blocked operation**: Ask the agent to read `~/.ssh/id_rsa`
2. **Allowed operation**: Ask the agent to create `/tmp/hello-agent/test.txt`
3. **Policy check**: Ask the agent to check if it can access `api.github.com`

## Expected Behavior

| Request | Result | Guard |
|---------|--------|-------|
| Read ~/.ssh/id_rsa | BLOCKED | forbidden_path |
| Write /tmp/hello-agent/test.txt | ALLOWED | - |
| Fetch api.github.com | ALLOWED | - |
| Fetch evil.com | BLOCKED | egress |

Note: “BLOCKED” here means the OpenClaw tool result should be blocked/redacted and recorded as a violation. If a tool already performed a network request, the post-action hook cannot undo the side effect.

## Policy

See `policy.yaml` for the security configuration:

- **Egress**: Only `api.github.com` and `pypi.org` allowed
- **Filesystem**: `~/.ssh`, `~/.aws`, `.env` files forbidden
- **Violation**: Cancel (block the operation)

## Testing

Use the OpenClaw CLI to verify policy enforcement:

```bash
openclaw clawdstrike check file_read ~/.ssh/id_rsa
# Expected: Denied by forbidden_path
```
