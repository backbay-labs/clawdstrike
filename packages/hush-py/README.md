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

- Pure Python implementation of all 5 security guards
- Policy engine with YAML configuration
- Receipt signing and verification with Ed25519
- Optional native bindings via PyO3

## License

MIT
