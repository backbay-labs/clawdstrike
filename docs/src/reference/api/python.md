# Python API Reference

The Python SDK lives under `packages/hush-py` and is published as `clawdstrike` on PyPI.

It provides:

- policy loading from YAML (`Policy`)
- a local policy engine (`PolicyEngine`)
- five guards (ForbiddenPath, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool)
- crypto + receipt signing/verification compatible with `hush-core`

Prompt-security utilities (jailbreak detection, output sanitization, watermarking) are not yet implemented in Python.

## Installation

```bash
pip install clawdstrike
```

## Policy + engine

```python
from clawdstrike import Policy, PolicyEngine, GuardAction, GuardContext

policy = Policy.from_yaml_file("policy.yaml")
engine = PolicyEngine(policy)
ctx = GuardContext(cwd="/app", session_id="session-123")

results = engine.check(GuardAction.file_access("/home/user/.ssh/id_rsa"), ctx)
for r in results:
    print(r.guard, r.allowed, r.severity, r.message)

print("allowed:", engine.is_allowed(GuardAction.network_egress("api.github.com", 443), ctx))
```

## Receipts

```python
from clawdstrike import Receipt, SignedReceipt, Verdict, PublicKeySet, generate_keypair

private_key, public_key = generate_keypair()
receipt = Receipt.new(content_hash="0x" + "00" * 32, verdict=Verdict(passed=True))
signed = SignedReceipt.sign(receipt, private_key)

result = signed.verify(PublicKeySet(signer=public_key.hex()))
print("valid:", result.valid)
```

## See also

- [Quick Start (Python)](../../getting-started/quick-start-python.md)
