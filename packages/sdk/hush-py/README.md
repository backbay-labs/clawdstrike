# clawdstrike

Python SDK for Clawdstrike security verification.

## Installation

```bash
pip install clawdstrike
```

## Quick Start

```python
from clawdstrike import Clawdstrike

cs = Clawdstrike.with_defaults("strict")

# Check file access
decision = cs.check_file("/etc/shadow")
if decision.denied:
    print(f"Blocked: {decision.message}")

# Check network egress
decision = cs.check_network("api.openai.com")
print(f"Allowed: {decision.allowed}")
```

## Usage

### Facade API (recommended)

```python
from clawdstrike import Clawdstrike, Decision, DecisionStatus

# Built-in rulesets: "permissive", "default", "strict", "ai-agent", "cicd"
cs = Clawdstrike.with_defaults("strict")

# All check methods return a Decision
decision = cs.check_file("/etc/passwd")
decision = cs.check_command("rm -rf /")
decision = cs.check_network("evil.com", 443)
decision = cs.check_patch("/app/main.py", diff_str)
decision = cs.check_mcp_tool("shell_exec", {"cmd": "ls"})

# Decision properties
print(decision.status)    # DecisionStatus.DENY
print(decision.denied)    # True
print(decision.allowed)   # False
print(decision.message)   # "Access to forbidden path: ..."
print(decision.guard)     # "forbidden_path"
print(decision.per_guard) # List of individual GuardResult objects
```

### Sessions

```python
cs = Clawdstrike.with_defaults("default")
session = cs.session(agent_id="my-agent")

session.check_file("/app/src/main.py")
session.check_network("api.openai.com")
session.check_file("/home/user/.ssh/id_rsa")

summary = session.get_summary()
print(f"Checks: {summary.check_count}")
print(f"Allowed: {summary.allow_count}")
print(f"Denied: {summary.deny_count}")
print(f"Blocked: {summary.blocked_actions}")
```

### Loading from YAML

```python
from clawdstrike import Clawdstrike

# From file
cs = Clawdstrike.from_policy("policy.yaml")

# From YAML string
cs = Clawdstrike.from_policy('''
version: "1.1.0"
name: my-policy
extends: strict
guards:
  egress_allowlist:
    allow:
      - "api.myservice.com"
''')
```

### Low-level API

```python
from clawdstrike import Policy, PolicyEngine, FileAccessAction, GuardContext

policy = Policy.from_yaml_file("policy.yaml")
engine = PolicyEngine(policy)
context = GuardContext(cwd="/app")

results = engine.check(FileAccessAction(path="/app/src/main.py"), context)
print(all(r.allowed for r in results))
```

## Features

- Pure Python implementation of 9 guards:
  - **ForbiddenPathGuard** - Blocks sensitive filesystem paths
  - **PathAllowlistGuard** - Allowlist-based path access control
  - **EgressAllowlistGuard** - Controls network egress by domain
  - **SecretLeakGuard** - Detects secrets in file writes
  - **PatchIntegrityGuard** - Validates patch safety
  - **ShellCommandGuard** - Blocks dangerous shell commands
  - **McpToolGuard** - Restricts MCP tool invocations
  - **PromptInjectionGuard** - Detects prompt injection
  - **JailbreakGuard** - Detects jailbreak attempts
- Facade API with `Clawdstrike` class and `Decision` return type
- Stateful sessions with `ClawdstrikeSession`
- Custom exception hierarchy (`ClawdstrikeError` base)
- Policy engine with YAML configuration and inheritance
- Receipt signing and verification with Ed25519
- Typed action variants (frozen dataclasses)

## Native bindings (experimental)

This repo includes a Rust/PyO3 module at `packages/sdk/hush-py/hush-native`, but it is not packaged for PyPI yet.

## License

Apache-2.0
