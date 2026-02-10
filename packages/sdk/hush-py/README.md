# clawdstrike (Python)

Official Python SDK for Clawdstrike policy evaluation and receipt verification workflows.

## Install

```bash
pip install clawdstrike
```

## Quick start

```python
from clawdstrike import Policy, PolicyEngine, GuardAction, GuardContext

policy = Policy.from_yaml_file("policy.yaml")
engine = PolicyEngine(policy)

context = GuardContext(cwd="/app")
result = engine.is_allowed(GuardAction.file_access("/app/src/main.py"), context)

print(result.allowed, result.reason)
```

## Capabilities

- Policy parsing from YAML
- Built-in guard evaluation helpers
- Receipt and signature helpers (Ed25519)
- Typed Python API with strict static-checking support (`py.typed`)

## Native extension status

The repository contains an optional Rust/PyO3 module under `packages/sdk/hush-py/hush-native`. The published PyPI package is currently pure Python.

## License

Apache-2.0
