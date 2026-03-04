# hello-secure-agent-vercel

Secure AI agent using **Clawdstrike** + **Vercel AI SDK**.

Shows how to protect tool calls in a `generateText()` agent loop using the
`@clawdstrike/sdk` session API. In non-dry-run mode, the agent uses
`generateText()` with `tool()` definitions from the Vercel AI SDK.

## Quick start

```bash
# Install dependencies (from repo root)
npm install

# Dry-run mode -- no API key needed
npm run dry-run --prefix examples/hello-secure-agent-vercel

# Full agent mode -- requires OPENAI_API_KEY
export OPENAI_API_KEY=sk-...
npm start --prefix examples/hello-secure-agent-vercel
```

## Policy

`policy.yaml` extends the built-in `ai-agent` ruleset with:

- **path_allowlist** -- agent can only access `/tmp/workspace/**`
- **egress_allowlist** -- only `api.openai.com` is allowed
- **forbidden_path** -- inherited from `ai-agent`, blocks sensitive paths

## Expected dry-run output

```
=== Clawdstrike + Vercel AI Demo (dry-run) ===

Scenario: Read allowed file (/tmp/workspace/notes.txt)
  Result: Hello from the secure agent!

Scenario: Read blocked file (/etc/shadow)
  Result: BLOCKED by forbidden_path: Access to forbidden path: /etc/shadow

Scenario: Write to workspace
  Result: Wrote 12 bytes to /tmp/workspace/out.txt

Scenario: Write to ~/.ssh/evil_key
  Result: BLOCKED by forbidden_path: Access to forbidden path: .../.ssh/evil_key

Scenario: Fetch allowed domain (api.openai.com)
  Result: {

Scenario: Fetch blocked domain (evil.com)
  Result: BLOCKED by egress_allowlist: Egress to unlisted destination: evil.com

=== Session Summary ===
  Total checks:    6
  Allowed:         3
  Denied:          3
  Blocked actions: file_access, file_write, network_egress
```
