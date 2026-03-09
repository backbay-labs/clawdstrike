# Python API Reference

The Python SDK lives under `packages/sdk/hush-py` and is published as `clawdstrike` on PyPI.

It provides:

- `Clawdstrike` facade with built-in rulesets and typed check methods
- `Decision` return type aggregating per-guard results
- pure-Python fallback with a core guard set, including Spider-Sense
- bundled native Rust engine on supported platforms (pure-Python fallback elsewhere) for the full Rust guard surface
- crypto + receipt signing/verification compatible with `hush-core`
- stateful sessions via `ClawdstrikeSession`
- origin-aware checks on the native and daemon-backed backends

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

Session checks keep the session's own `session_id` and `agent_id` pinned. Per-check `origin`,
`cwd`, request metadata, and `context_metadata` for outbound sends can still vary.

## Origin-aware checks

Current backend support is:

- native backend: supports `policy.origins`, `origin`, and `origin.output_send`
- daemon backend: supports `policy.origins`, `origin`, and `origin.output_send`
- pure-Python backend: fails closed with `UnsupportedOriginFeatureError` if you load an origin-aware policy or pass origin-aware request context

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

Session origin changes work too:

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
    context_metadata={"ticket_id": "INC-2042"},
)
```

Wire behavior:

- canonical outbound origin fields are snake_case
- mapping inputs accept camelCase aliases such as `tenantId`, `spaceId`, and `actorRole`
- `check_output_send(...)` maps to hushd `action_type: "output_send"`

## Native Engine

On supported platforms, the SDK auto-selects the bundled native Rust engine for evaluation. On unsupported platforms, it falls back to pure Python.

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
- [Origin Enclaves](../../guides/origin-enclaves.md)
