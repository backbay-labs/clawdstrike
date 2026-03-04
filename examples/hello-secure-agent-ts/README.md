# hello-secure-agent-ts

Minimal TypeScript example demonstrating Clawdstrike policy enforcement with the
OpenAI Agents SDK tool shape.

## Setup

```bash
npm install
```

## Run (dry-run mode, no API key needed)

```bash
npm run dry-run
```

## Run (`npm start`)

```bash
npm start
```

`npm start` currently runs the same local policy-check scenarios as dry-run.
For a live model-backed agent demo, use:

- `examples/hello-secure-agent-py/` (OpenAI Agents SDK)
- `examples/hello-secure-agent-vercel/` (Vercel AI SDK)

## Expected output

```
=== Clawdstrike Security Demo (dry-run) ===

Scenario: Read allowed file
  Result: Hello from the secure agent!

Scenario: Read /etc/shadow
  Result: BLOCKED by forbidden_path: Access to forbidden path: /etc/shadow

Scenario: Write to /tmp/workspace/out.txt
  Result: Wrote 12 bytes to /tmp/workspace/out.txt

Scenario: Write to ~/.ssh/evil_key
  Result: BLOCKED by forbidden_path: Access to forbidden path: .../.ssh/evil_key

Scenario: Fetch api.openai.com
  Result: {

Scenario: Fetch evil.com
  Result: BLOCKED by egress_allowlist: Egress to unlisted destination: evil.com

=== Session Summary ===
  Total checks:    6
  Allowed:         3
  Denied:          3
  Blocked actions: file_access, file_write, network_egress
```

## How it works

1. **policy.yaml** extends the built-in `ai-agent` ruleset and tightens the
   allowlists for this demo (only `/tmp/workspace` for files, only
   `api.openai.com` for network).

2. **agent.ts** defines three tools (`read_file`, `write_file`, `fetch_url`)
   and wraps each with `session.checkFile()` / `session.checkNetwork()` calls
   from `@clawdstrike/sdk`. Denied actions return a `BLOCKED` message instead
   of executing.

3. The session tracks all checks and prints a summary at the end.

## Files

| File           | Purpose                                    |
|----------------|--------------------------------------------|
| `package.json` | Dependencies and scripts                   |
| `policy.yaml`  | Security policy (schema 1.2.0)             |
| `agent.ts`     | Main demo with 6 allow/deny scenarios      |
| `README.md`    | This file                                  |
