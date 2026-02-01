# Decisions

Decisions are the outcomes of policy evaluation.

## Decision Types

Every evaluation produces one of three decisions:

### Allow

The event is safe and can proceed.

```rust
Decision::Allow
```

No logging by default (unless audit mode is enabled).

### Warn

The event is suspicious but allowed to proceed.

```rust
Decision::Warn {
    message: "Filename looks suspicious",
    guard: Some("SecretLeakGuard"),
}
```

The warning is logged and the operation continues.

### Deny

The event is blocked.

```rust
Decision::Deny {
    reason: "Path matches forbidden pattern: ~/.ssh/*",
    guard: "ForbiddenPathGuard",
    severity: Severity::Critical,
}
```

The operation is stopped and an error is returned.

## Severity Levels

Denials include a severity level:

| Severity | Meaning | Examples |
|----------|---------|----------|
| `Low` | Unusual but not dangerous | Rate limit exceeded |
| `Medium` | Potentially problematic | Suspicious filename |
| `High` | Likely dangerous | Unknown domain access |
| `Critical` | Definitely dangerous | SSH key access |

```yaml
# Decisions with Critical severity are always logged
# Lower severities depend on log level
```

## Decision Aggregation

Multiple guards produce multiple results. Aggregation rules:

```
All Allow → Allow
Any Warn + No Deny → Warn (combined messages)
Any Deny → Deny (first denial wins)
```

Example:

```
Event: file_write("./output.txt")

Guard 1 (ForbiddenPath): Allow
Guard 2 (SecretLeak): Warn "Contains API key pattern"
Guard 3 (PatchIntegrity): Allow

Final Decision: Warn
Message: "Contains API key pattern"
```

## Mode Effects

The evaluation mode affects how decisions are applied:

### Deterministic Mode (Default)

```
Allow → Proceed
Warn → Proceed + Log warning
Deny → Block + Log error
```

### Advisory Mode

```
Allow → Proceed
Warn → Proceed + Log warning
Deny → Proceed + Log warning (converted from Deny)
```

### Audit Mode

```
Allow → Proceed + Log
Warn → Proceed + Log
Deny → Proceed + Log (never blocks)
```

## Decision Logging

All decisions can be logged to the audit ledger:

```json
{
  "event_id": "evt_abc123",
  "timestamp": "2026-01-31T14:23:45Z",
  "event_type": "file_read",
  "target": "~/.ssh/id_rsa",
  "decision": "deny",
  "guard": "ForbiddenPathGuard",
  "reason": "Path matches forbidden pattern",
  "severity": "critical"
}
```

## Signed Receipts

For high-assurance environments, decisions can be signed:

```json
{
  "run_id": "run_xyz789",
  "events": [...],
  "merkle_root": "0x7f3a...",
  "signature": "ed25519:abc...",
  "public_key": "ed25519:xyz..."
}
```

Verify with:

```bash
hush verify receipt.json
```

## Programmatic Access

Check decisions in code:

```rust
let decision = engine.evaluate(&event).await;

match decision {
    Decision::Allow => {
        // Proceed with operation
    }
    Decision::Warn { message, .. } => {
        log::warn!("{}", message);
        // Proceed with operation
    }
    Decision::Deny { reason, severity, .. } => {
        log::error!("Blocked: {} (severity: {:?})", reason, severity);
        // Return error to caller
    }
}
```

Helper methods:

```rust
decision.is_allowed()  // true for Allow and Warn
decision.is_denied()   // true for Deny only
decision.severity()    // Some(Severity) for Deny, None otherwise
```

## Next Steps

- [Audit Logging](../guides/audit-logging.md) - Configure logging
- [Guards Reference](../reference/guards/README.md) - What each guard returns
- [CLI Reference](../reference/api/cli.md) - View decisions via CLI
