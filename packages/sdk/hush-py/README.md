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

## Native Engine (Recommended)

The SDK automatically uses the bundled native engine when available.
All 12 guards run in Rust with full detection capabilities.

On unsupported platforms, the SDK falls back to pure Python
with 9 guards and heuristic-only detection.

Native wheels are published for:

- Linux: `manylinux` (`x86_64`, `aarch64`)
- macOS: `x86_64`, `arm64`
- Windows: `x86_64`

```python
from clawdstrike import Clawdstrike, NATIVE_AVAILABLE, init_native

# Check if native engine is available
print(f"Native available: {NATIVE_AVAILABLE}")
print(f"Native engine: {init_native()}")

# The facade auto-selects the best backend
cs = Clawdstrike.with_defaults("strict")
print(f"Backend: {cs._backend.name}")  # "native" or "pure_python"
```

### Explicit Backend Selection

```python
from clawdstrike import Clawdstrike
from clawdstrike.backend import DaemonEngineBackend, NativeEngineBackend, PurePythonBackend
from clawdstrike.policy import Policy, PolicyEngine

# Force pure Python backend
yaml = 'version: "1.1.0"\nname: test\nextends: strict\n'
policy = Policy.from_yaml_with_extends(yaml)
cs = Clawdstrike(PurePythonBackend(PolicyEngine(policy)))

# Force native backend (raises if unavailable)
backend = NativeEngineBackend.from_ruleset("strict")
cs = Clawdstrike(backend)

# Force daemon-backed evaluation through hushd
daemon = DaemonEngineBackend("https://hushd.example.com", api_key="dev-token")
cs = Clawdstrike(daemon)
```

### Origin-Aware Checks

Origin-aware enforcement is available on:

- the bundled native Rust backend
- hushd via `Clawdstrike.from_daemon(...)` or `DaemonEngineBackend`

The pure-Python backend does not enforce `policy.origins`. It fails closed with
`UnsupportedOriginFeatureError` if you pass `origin` or use `origin.output_send`.

```python
from clawdstrike import Clawdstrike

origin = {
    "provider": "slack",
    "tenant_id": "T123",
    "space_id": "C456",
    "actor_role": "incident_commander",
}

cs = Clawdstrike.from_daemon("https://hushd.example.com", api_key="dev-token")

decision = cs.check_mcp_tool(
    "read_file",
    {"path": "/srv/runbook.md"},
    origin=origin,
)

send_decision = cs.check_output_send(
    "Posting sanitized status update",
    target="slack://incident-room",
    mime_type="text/plain",
    metadata={"thread_id": "1712502451.000100"},
    origin=origin,
)
```

Per-check origin changes also work through sessions:

```python
session = cs.session(session_id="sess-123", agent_id="triage-bot")

session.check_file(
    "/srv/runbook.md",
    origin={"provider": "github", "space_id": "repo-1"},
)

session.check_output_send(
    "Ready for review",
    target="slack://incident-room",
    origin={"provider": "slack", "space_id": "C456"},
)
```

## Features

- **Native Rust engine** (bundled in `clawdstrike` wheels on supported platforms) with all 12 guards
- Pure Python fallback with 9 guards:
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

## License

Apache-2.0
