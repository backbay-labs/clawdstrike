# Quick Start (Python)

The Python SDK (`clawdstrike`) is a **pure-Python** implementation of:

- policy loading (YAML)
- a local policy engine (`PolicyEngine`)
- five guards (ForbiddenPath, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool)
- crypto + receipts (signing/verification)

Prompt-security utilities (jailbreak detection, output sanitization, watermarking) currently live in Rust and TypeScript.

## Installation

```bash
pip install clawdstrike
```

## Basic usage

```python
from clawdstrike import Policy, PolicyEngine, GuardAction, GuardContext

policy = Policy.from_yaml_file("policy.yaml")
engine = PolicyEngine(policy)
ctx = GuardContext(cwd="/app", session_id="session-123")

allowed = engine.is_allowed(GuardAction.file_access("/home/user/.ssh/id_rsa"), ctx)
print("allowed:", allowed)
```

If you want per-guard details:

```python
results = engine.check(GuardAction.network_egress("api.openai.com", 443), ctx)
for r in results:
    print(r.guard, r.allowed, r.severity, r.message)
```

## Next steps

- [Policy Schema](../reference/policy-schema.md)
- [API Reference (Python)](../reference/api/python.md)
