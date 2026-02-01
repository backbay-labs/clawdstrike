# Hello Secure Agent

A simple example demonstrating hushclaw security enforcement in OpenClaw.

## Setup

```bash
cd examples/hello-secure-agent
npm install
openclaw plugins enable @hushclaw/openclaw
openclaw start
```

## Try It

1. **Blocked operation**: Ask the agent to read `~/.ssh/id_rsa`
2. **Allowed operation**: Ask the agent to create `/tmp/hello-agent/test.txt`
3. **Policy check**: Ask the agent to check if it can access `api.github.com`

## Expected Behavior

| Request | Result | Guard |
|---------|--------|-------|
| Read ~/.ssh/id_rsa | BLOCKED | ForbiddenPathGuard |
| Write /tmp/hello-agent/test.txt | ALLOWED | - |
| Fetch api.github.com | ALLOWED | - |
| Fetch evil.com | BLOCKED | EgressAllowlistGuard |

## Policy

See `policy.yaml` for the security configuration:

- **Egress**: Only `api.github.com` and `pypi.org` allowed
- **Filesystem**: `~/.ssh`, `~/.aws`, `.env` files forbidden
- **Violation**: Cancel (block the operation)

## Testing

```bash
npm test
```
