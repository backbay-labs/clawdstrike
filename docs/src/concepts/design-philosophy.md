# Design Philosophy

Clawdstrike is built on a set of core principles that guide its architecture and behavior. Understanding these principles helps you integrate it effectively and set appropriate expectations.

## Fail Closed

**If in doubt, deny.**

Clawdstrike follows a fail-closed security model. This means:

- **Invalid policies reject at load time.** A malformed regex pattern or invalid YAML will cause the policy to fail validation rather than silently ignoring the broken rule.
- **Missing guard configuration defaults to restrictive.** If you don't configure a guard, it runs with sensible defaults that err on the side of caution.
- **Errors during evaluation result in denial.** If a guard encounters an unexpected error while checking an action, the action is blocked rather than allowed.

This is the opposite of fail-open systems where errors or missing configuration result in permissive behavior. Fail-closed ensures that security degradation requires explicit action.

```yaml
# This policy will fail to load (invalid regex)
guards:
  forbidden_path:
    patterns:
      - "[invalid regex("  # Rejected at load time, not at check time
```

## Defense in Depth

Clawdstrike is one layer in a defense-in-depth strategy. It enforces policy at the **tool boundary**—the interface between your agent runtime and the actions it performs.

```text
┌─────────────────────────────────────────────────────────────┐
│                     Your Agent Runtime                       │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                   Clawdstrike                        │    │
│  │              (Tool Boundary Enforcement)             │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    OS-Level Sandbox                          │
│           (seccomp, gVisor, Firecracker, etc.)              │
└─────────────────────────────────────────────────────────────┘
```

**What Clawdstrike can enforce:**
- Actions routed through your tool layer
- Policy-based decisions on file access, network egress, tool invocation
- Detection of prompt injection and jailbreak attempts
- Signed receipts proving what was decided under which policy

**What Clawdstrike cannot enforce:**
- Direct syscalls bypassing your runtime
- Actions from code that doesn't use the tool layer
- Kernel-level isolation or sandbox escapes

**Recommendation:** Pair Clawdstrike with an OS-level sandbox (seccomp, gVisor, Firecracker) for comprehensive protection.

## Enforced vs. Attested

These are distinct concepts that should not be conflated:

| Concept | Meaning |
|---------|---------|
| **Enforced** | The action your runtime *chose not to perform* because a guard returned `allowed=false` |
| **Attested** | What Clawdstrike *recorded* in a `Receipt` or `SignedReceipt` (policy hash, verdict, violations) |

Receipts prove what Clawdstrike observed and decided under a specific policy. They do not prove that the underlying OS prevented all side effects. A signed receipt is only as strong as the integration.

```rust,ignore
// Enforcement: your runtime decides based on GuardResult
let result = engine.check_file_access("/etc/passwd", &ctx).await?;
if !result.allowed {
    // Your runtime blocks the action
    return Err("Access denied by policy");
}

// Attestation: create a tamper-evident record
let receipt = engine.create_signed_receipt(content_hash).await?;
// Receipt proves: "Under policy X, action Y was evaluated with verdict Z"
```

## Composable Guards

Guards are independent, composable checks. Each guard:

- Handles specific action types (files, network, patches, tools, text)
- Returns a verdict (allow, warn, block) with evidence
- Can be configured independently via policy YAML

This composability lets you:

1. **Enable only what you need.** Don't want MCP tool restrictions? Don't configure that guard.
2. **Layer multiple checks.** A file write might pass `ForbiddenPathGuard` but fail `SecretLeakGuard`.
3. **Add custom guards.** Extend `HushEngine` with your own guards via the `Guard` trait.

```rust,ignore
// Guards evaluate in order, fail-fast or aggregate
let report = engine.check_action_report(&action, &context).await?;
for evidence in &report.evidence {
    println!("{}: {:?}", evidence.guard_name, evidence.result);
}
```

## Canonical Serialization

Clawdstrike uses [RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) for canonical JSON serialization. This ensures:

- **Deterministic hashes.** The same data produces the same hash across Rust, TypeScript, and Python.
- **Portable signatures.** A receipt signed in Rust can be verified in TypeScript or Python.
- **No formatting ambiguity.** Key ordering, whitespace, and number formatting are standardized.

This is critical for the cryptographic attestation layer. Without canonical serialization, JSON formatting differences would break signature verification across implementations.

## Privacy-Preserving Detection

When detecting sensitive content (jailbreaks, secrets, PII), Clawdstrike:

- **Never stores raw secrets in findings.** Match previews are truncated or redacted.
- **Uses fingerprints for deduplication.** SHA-256 hashes identify repeated patterns without exposing content.
- **Supports configurable redaction.** Choose between full redaction, partial masking, or type labels.

```typescript
// Detection result shows category and location, not the secret itself
{
  category: "secret",
  type: "aws_access_key",
  span: { start: 142, end: 162 },
  matchPreview: "AKIA****EXAMPLE"  // Truncated, not raw
}
```

## Multi-language support

Rust is the reference implementation for policy evaluation and enforcement. TypeScript and Python focus on:

- **Interop** (crypto/receipts)
- **Integration glue** (framework adapters)

See [Multi-Language & Multi-Framework Support](./multi-language.md) for the current status by language and package.

## Explicit over implicit

Clawdstrike prefers explicit, auditable configuration:

- **Unknown fields are rejected** (fail-closed) where parsing is security-critical.
- **Invalid patterns fail at load time** (glob/regex validation), not at check time.
- **Policy linting** (`clawdstrike policy lint`) catches risky defaults and common mistakes early.
