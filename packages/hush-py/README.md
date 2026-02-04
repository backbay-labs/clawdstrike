# hush-py

Python SDK for clawdstrike security verification.

## Installation

```bash
pip install hush
```

## Usage

```python
from hush import Policy, PolicyEngine, GuardAction, GuardContext

# Load policy from YAML
policy = Policy.from_yaml_file("policy.yaml")
engine = PolicyEngine(policy)

# Check actions
context = GuardContext(cwd="/app")
result = engine.is_allowed(
    GuardAction.file_access("/app/src/main.py"),
    context,
)
```

## Features

- Pure Python implementation of 5 guards:
  - ForbiddenPathGuard
  - EgressAllowlistGuard
  - SecretLeakGuard
  - PatchIntegrityGuard
  - McpToolGuard
- Policy engine with YAML configuration
- Receipt signing and verification with Ed25519
- Experimental native bindings (not yet published)

## Native bindings (experimental)

This repo includes a Rust/PyO3 module at `packages/hush-py/hush-native`, but it is not packaged for PyPI yet.

## License

MIT
