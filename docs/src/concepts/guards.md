# Guards

Guards are modular security checks that evaluate events against policies.

## What is a Guard?

A guard is a focused security check that:
1. Receives an event (file read, network call, etc.)
2. Evaluates it against policy rules
3. Returns a result (Allow, Warn, or Deny)

```rust
#[async_trait]
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    async fn check(&self, event: &Event, policy: &Policy) -> GuardResult;
}
```

## Built-in Guards

Hushclaw includes 5 battle-tested guards:

### ForbiddenPathGuard

Blocks access to sensitive filesystem paths.

```yaml
filesystem:
  forbidden_paths:
    - "~/.ssh/*"
    - "~/.aws/*"
    - ".env"
```

**Protects against:** Credential theft, secret exposure

[Full Reference →](../reference/guards/forbidden-path.md)

### EgressAllowlistGuard

Controls network connections via domain allowlist.

```yaml
egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"
    - "*.anthropic.com"
```

**Protects against:** Data exfiltration, C2 connections

[Full Reference →](../reference/guards/egress.md)

### SecretLeakGuard

Detects secrets in outputs and patches.

```yaml
# Enabled by default, no config needed
# Detects: AWS keys, GitHub tokens, private keys, etc.
```

**Protects against:** Accidental secret exposure

[Full Reference →](../reference/guards/secret-leak.md)

### PatchIntegrityGuard

Blocks dangerous code patterns in patches.

```yaml
execution:
  denied_patterns:
    - "curl.*|.*bash"
    - "eval\\("
```

**Protects against:** Code injection, RCE

[Full Reference →](../reference/guards/patch-integrity.md)

### McpToolGuard

Controls which MCP tools can be invoked.

```yaml
tools:
  allowed: []  # Empty = all allowed
  denied:
    - "shell_exec_raw"
```

**Protects against:** Unauthorized tool usage

[Full Reference →](../reference/guards/mcp-tool.md)

## Guard Results

Each guard returns one of three results:

| Result | Meaning | Behavior |
|--------|---------|----------|
| `Allow` | Event is safe | Proceed |
| `Warn` | Suspicious but allowed | Proceed + log warning |
| `Deny` | Dangerous, block it | Stop + log denial |

```rust
pub enum GuardResult {
    Allow,
    Warn { message: String },
    Deny { reason: String, severity: Severity },
}
```

## Guard Evaluation

Guards are evaluated in registration order. Evaluation stops on first Deny:

```
Event: FileRead("~/.ssh/id_rsa")

ForbiddenPathGuard: Deny (path forbidden)
  → Short-circuit, return Deny

Final: DENIED
```

For warnings, all guards run:

```
Event: FileRead("./suspicious.txt")

ForbiddenPathGuard: Allow
EgressAllowlistGuard: Skip (not network event)
SecretLeakGuard: Warn (filename suspicious)
PatchIntegrityGuard: Skip (not patch event)

Final: WARN
```

## Custom Guards

You can implement custom guards:

```rust
use hushclaw::{Guard, GuardResult, Event, Policy};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct RateLimitGuard {
    requests: AtomicUsize,
    limit: usize,
}

#[async_trait]
impl Guard for RateLimitGuard {
    fn name(&self) -> &str {
        "RateLimitGuard"
    }

    async fn check(&self, event: &Event, _policy: &Policy) -> GuardResult {
        let count = self.requests.fetch_add(1, Ordering::Relaxed);
        if count > self.limit {
            GuardResult::Deny {
                reason: "Rate limit exceeded".into(),
                severity: Severity::Medium,
            }
        } else {
            GuardResult::Allow
        }
    }
}
```

Register it:

```rust
let mut registry = GuardRegistry::with_defaults();
registry.register(Arc::new(RateLimitGuard::new(100)));
```

[Custom Guards Guide →](../guides/custom-guards.md)

## Guard Configuration

Enable/disable guards per policy:

```yaml
guards:
  forbidden_path: true
  egress_allowlist: true
  secret_leak: true
  patch_integrity: false  # Disabled
  mcp_tool: false         # Disabled
```

## Next Steps

- [Policies](./policies.md) - How policies configure guards
- [Decisions](./decisions.md) - How guard results become decisions
- [Guard Reference](../reference/guards/README.md) - Detailed guard docs
