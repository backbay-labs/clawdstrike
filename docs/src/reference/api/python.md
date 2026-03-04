# Python API Reference

The Python SDK lives under `packages/sdk/hush-py` and is published as `clawdstrike` on PyPI.

It provides:

- `Clawdstrike` facade with built-in rulesets and typed check methods
- `Decision` return type aggregating per-guard results
- 10 pure-Python guards (ForbiddenPath, PathAllowlist, EgressAllowlist, SecretLeak, PatchIntegrity, ShellCommand, McpTool, PromptInjection, Jailbreak, SpiderSense)
- bundled native Rust engine on supported platforms (pure-Python fallback elsewhere) with all 13 guards
- crypto + receipt signing/verification compatible with `hush-core`
- stateful sessions via `ClawdstrikeSession`

## Installation

```bash
pip install clawdstrike
```

## Facade API (recommended)

```python
from clawdstrike import Clawdstrike, Decision, DecisionStatus

# Built-in rulesets: "permissive", "default", "strict", "ai-agent", "cicd", "spider-sense"
cs = Clawdstrike.with_defaults("strict")

# All check methods return a Decision
decision = cs.check_file("/etc/shadow")
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

## Loading from YAML

```python
# From file
cs = Clawdstrike.from_policy("policy.yaml")

# From YAML string
cs = Clawdstrike.from_policy('''
version: "1.2.0"
name: my-policy
extends: clawdstrike:strict
guards:
  egress_allowlist:
    allow:
      - "api.myservice.com"
  spider_sense:
    enabled: true
''')
```

## Sessions

```python
cs = Clawdstrike.with_defaults("default")
session = cs.session(agent_id="my-agent")

session.check_file("/app/src/main.py")
session.check_network("api.openai.com")
session.check_file("/home/user/.ssh/id_rsa")

summary = session.get_summary()
print(f"Checks: {summary.check_count}")
print(f"Denied: {summary.deny_count}")
print(f"Blocked: {summary.blocked_actions}")
```

## Native Engine

On supported platforms, the SDK auto-selects the bundled native Rust engine for evaluation. All 12 guards run in Rust with full detection capabilities. On unsupported platforms, it falls back to pure Python with 9 guards.

Native wheels are published for:

- Linux (`manylinux`): `x86_64`, `aarch64`
- macOS: `x86_64`, `arm64`
- Windows: `x86_64`

```python
from clawdstrike import Clawdstrike, NATIVE_AVAILABLE

print(f"Native: {NATIVE_AVAILABLE}")
cs = Clawdstrike.with_defaults("strict")
print(f"Backend: {cs._backend.name}")  # "native" or "pure_python"
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

## Low-level API

For advanced use, the `PolicyEngine` and typed actions are still accessible:

```python
from clawdstrike import Policy, PolicyEngine, FileAccessAction, GuardContext

policy = Policy.from_yaml_file("policy.yaml")
engine = PolicyEngine(policy)
context = GuardContext(cwd="/app")

results = engine.check(FileAccessAction(path="/app/src/main.py"), context)
print(all(r.allowed for r in results))
```

## See also

- [Quick Start (Python)](../../getting-started/quick-start-python.md)
