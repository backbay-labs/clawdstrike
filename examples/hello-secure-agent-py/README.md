# hello-secure-agent-py

Minimal example of an AI agent secured by Clawdstrike, using the Python SDK and the OpenAI Agents SDK.

## Setup

```bash
pip install clawdstrike openai-agents requests
```

## Run (dry-run, no API key needed)

```bash
python agent.py --dry-run
```

Expected output:

```
=== Clawdstrike Security Demo (dry-run) ===

Scenario: Read allowed file (/tmp/workspace/notes.txt)
  Result: Hello from the secure agent!

Scenario: Read blocked file (/etc/shadow)
  Result: BLOCKED by ...

Scenario: Run allowed command (ls -la /tmp)
  Result: total ...

Scenario: Run blocked command (rm -rf /)
  Result: BLOCKED by ...

Scenario: Fetch allowed host (api.openai.com)
  Result: ...

Scenario: Fetch blocked host (evil.com)
  Result: BLOCKED by ...

=== Session Summary ===
Total checks: 6
Allowed:      3
Denied:       3
Blocked:      [...]
```

## Run (live agent, requires OPENAI_API_KEY)

```bash
export OPENAI_API_KEY=sk-...
python agent.py
```

The agent will use the OpenAI Agents SDK to run a conversational loop, with every tool call checked against the Clawdstrike policy before execution.
