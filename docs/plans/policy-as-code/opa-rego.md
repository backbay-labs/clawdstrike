# OPA/Rego Integration for Clawdstrike

## Problem Statement

The current YAML-based policy system in Clawdstrike is excellent for declarative configurations but has limitations when expressing complex conditional logic:

### Current Limitations

1. **No Conditional Logic**: Cannot express "allow egress to api.github.com only between 9am-5pm"
2. **No Data Joins**: Cannot reference external data sources (user roles, asset inventory)
3. **No Aggregation**: Cannot express "deny if more than 10 file writes in 1 minute"
4. **Limited Customization**: Guards are hard-coded; custom checks require SDK changes
5. **No Policy Composition**: Cannot compose multiple policies with custom precedence rules

### Use Cases Requiring Programmatic Policies

| Use Case | Why YAML Falls Short |
|----------|---------------------|
| Time-based access | No datetime functions |
| Role-based exceptions | No external data integration |
| Rate limiting | No aggregation/state |
| Risk scoring | No arithmetic operations |
| Custom business rules | Fixed guard types |

---

## Proposed Solution: OPA Integration

[Open Policy Agent (OPA)](https://www.openpolicyagent.org/) is the industry standard for policy-as-code. Its Rego language provides:

- Declarative, pure-functional policy authoring
- Rich built-in functions (regex, glob, datetime, etc.)
- External data integration
- Policy composition and modules
- Deterministic evaluation
- Excellent tooling (test, fmt, lint)

### Integration Architecture

```
+------------------------------------------------------------------+
|                     Policy Evaluation Flow                        |
+------------------------------------------------------------------+
|                                                                   |
|   +----------+     +----------+     +----------+                  |
|   |  YAML    |     |  Rego    |     | External |                  |
|   |  Policy  |     |  Policy  |     |   Data   |                  |
|   +----+-----+     +----+-----+     +----+-----+                  |
|        |               |                 |                        |
|        v               v                 v                        |
|   +--------------------------------------------------+           |
|   |              Policy Compiler                      |           |
|   |  +----------+  +----------+  +----------+        |           |
|   |  |  YAML    |  |  Rego    |  |  Data    |        |           |
|   |  |  Parser  |  |  Parser  |  |  Loader  |        |           |
|   |  +----+-----+  +----+-----+  +----+-----+        |           |
|   |       |             |             |               |           |
|   |       v             v             v               |           |
|   |  +------------------------------------------+    |           |
|   |  |        OPA Bundle (policy.bundle)        |    |           |
|   |  +------------------------------------------+    |           |
|   +--------------------------------------------------+           |
|                          |                                        |
|                          v                                        |
|   +--------------------------------------------------+           |
|   |              Policy Engine                        |           |
|   |  +----------+  +----------+  +----------+        |           |
|   |  | Native   |  |   OPA    |  | Decision |        |           |
|   |  | Guards   |  |  Engine  |  | Combiner |        |           |
|   |  +----+-----+  +----+-----+  +----+-----+        |           |
|   |       |             |             |               |           |
|   |       +-------------+-------------+               |           |
|   |                     |                             |           |
|   |                     v                             |           |
|   |              +------------+                       |           |
|   |              |  Decision  |                       |           |
|   |              +------------+                       |           |
|   +--------------------------------------------------+           |
|                                                                   |
+------------------------------------------------------------------+
```

---

## Rego Policy Schema

### Input Structure

Every Rego policy receives a standardized input object:

```rego
# input schema
{
  "event": {
    "eventId": "uuid",
    "eventType": "file_write | file_read | network_egress | ...",
    "timestamp": "2024-01-15T10:30:00Z",
    "sessionId": "session-uuid",
    "data": { ... }  # event-specific data
  },
  "context": {
    "user": {
      "id": "user-123",
      "roles": ["developer", "admin"],
      "groups": ["engineering"]
    },
    "environment": {
      "name": "production",
      "region": "us-west-2",
      "cluster": "prod-1"
    },
    "session": {
      "startTime": "2024-01-15T09:00:00Z",
      "toolCallCount": 42,
      "fileWriteCount": 10
    }
  },
  "policy": {
    "version": "1.0.0",
    "yaml": { ... }  # parsed YAML policy for reference
  }
}
```

### Output Structure

Policies must produce a decision object:

```rego
# Required output
{
  "allow": true | false,
  "deny": true | false,
  "warn": true | false,
  "reason": "Human-readable explanation",
  "guard": "policy-name",
  "severity": "low | medium | high | critical",
  "metadata": { ... }  # optional additional data
}
```

---

## Example Policies

### 1. Time-Based Access Control

```rego
# policies/time_based_egress.rego
package clawdstrike.guards.egress

import future.keywords.if
import future.keywords.in

# Allow egress to production APIs only during business hours
default allow := false

allow if {
    is_business_hours
    input.event.eventType == "network_egress"
    is_allowed_domain(input.event.data.host)
}

# Deny with clear reason outside business hours
deny if {
    not is_business_hours
    input.event.eventType == "network_egress"
    is_production_api(input.event.data.host)
}

reason := msg if {
    deny
    msg := sprintf(
        "Production API access denied outside business hours. Current time: %s (UTC). Allowed: 09:00-17:00 UTC",
        [time.format(time.now_ns())]
    )
}

is_business_hours if {
    t := time.clock([time.now_ns(), "UTC"])
    t[0] >= 9   # hour >= 9am
    t[0] < 17   # hour < 5pm
}

is_production_api(host) if {
    endswith(host, ".prod.internal")
}

is_allowed_domain(host) if {
    domains := data.allowed_domains
    some domain in domains
    glob.match(domain, [], host)
}
```

### 2. Role-Based Exceptions

```rego
# policies/rbac_filesystem.rego
package clawdstrike.guards.filesystem

import future.keywords.if
import future.keywords.in

# Default deny for sensitive paths
default allow := false

# Allow admins to read sensitive configs
allow if {
    input.event.eventType == "file_read"
    is_sensitive_path(input.event.data.path)
    "admin" in input.context.user.roles
}

# Allow anyone to read non-sensitive paths
allow if {
    input.event.eventType == "file_read"
    not is_sensitive_path(input.event.data.path)
}

# Deny writes to sensitive paths unless explicitly permitted
deny if {
    input.event.eventType == "file_write"
    is_sensitive_path(input.event.data.path)
    not has_write_permission
}

reason := "Write to sensitive path requires explicit permission" if deny

is_sensitive_path(path) if {
    sensitive_patterns := data.sensitive_patterns
    some pattern in sensitive_patterns
    glob.match(pattern, ["/"], path)
}

has_write_permission if {
    permitted := data.write_permitted_paths[input.context.user.id]
    input.event.data.path in permitted
}
```

### 3. Rate Limiting

```rego
# policies/rate_limit.rego
package clawdstrike.guards.rate_limit

import future.keywords.if

# Deny if session exceeds rate limits
default allow := true

deny if {
    input.event.eventType == "file_write"
    input.context.session.fileWriteCount > data.limits.max_file_writes_per_session
}

deny if {
    input.event.eventType == "tool_call"
    input.context.session.toolCallCount > data.limits.max_tool_calls_per_session
}

warn if {
    input.event.eventType == "file_write"
    count := input.context.session.fileWriteCount
    limit := data.limits.max_file_writes_per_session
    count > limit * 0.8  # 80% threshold
    count <= limit
}

reason := msg if {
    deny
    input.event.eventType == "file_write"
    msg := sprintf(
        "Session file write limit exceeded (%d/%d)",
        [input.context.session.fileWriteCount, data.limits.max_file_writes_per_session]
    )
}

severity := "high" if deny
```

### 4. Risk Scoring

```rego
# policies/risk_score.rego
package clawdstrike.guards.risk

import future.keywords.if
import future.keywords.in

# Calculate risk score based on multiple factors
default allow := true

deny if {
    risk_score >= 100
}

warn if {
    risk_score >= 50
    risk_score < 100
}

risk_score := score if {
    score := sum([
        time_risk,
        environment_risk,
        operation_risk,
        path_risk
    ])
}

time_risk := 20 if {
    t := time.clock([time.now_ns(), "UTC"])
    t[0] < 6   # before 6am
} else := 20 if {
    t := time.clock([time.now_ns(), "UTC"])
    t[0] >= 22  # after 10pm
} else := 0

environment_risk := 40 if {
    input.context.environment.name == "production"
} else := 0

operation_risk := 30 if {
    input.event.eventType == "file_write"
    contains(input.event.data.path, "config")
} else := 20 if {
    input.event.eventType == "command_exec"
} else := 0

path_risk := 50 if {
    input.event.eventType in ["file_read", "file_write"]
    is_critical_path(input.event.data.path)
} else := 0

is_critical_path(path) if {
    patterns := data.critical_paths
    some pattern in patterns
    glob.match(pattern, ["/"], path)
}

reason := msg if {
    msg := sprintf("Risk score: %d (threshold: 100). Factors: time=%d, env=%d, op=%d, path=%d",
        [risk_score, time_risk, environment_risk, operation_risk, path_risk])
}
```

---

## YAML and Rego Integration

### Hybrid Policy Configuration

```yaml
# policy.yaml - main policy file
version: "1.1.0"
name: "Production Policy"

# Traditional YAML guards (fast path)
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"

  egress_allowlist:
    allow:
      - "*.github.com"
      - "api.anthropic.com"
    default_action: block

# Rego policies (complex logic)
rego:
  # Policies to load
  policies:
    - path: ./policies/time_based_egress.rego
      package: clawdstrike.guards.egress
      priority: 100  # Higher priority = evaluated first

    - path: ./policies/rbac_filesystem.rego
      package: clawdstrike.guards.filesystem
      priority: 90

    - path: ./policies/rate_limit.rego
      package: clawdstrike.guards.rate_limit
      priority: 80

  # External data sources
  data:
    # Inline data
    limits:
      max_file_writes_per_session: 100
      max_tool_calls_per_session: 500

    # File-based data
    allowed_domains: ./data/allowed_domains.json
    sensitive_patterns: ./data/sensitive_patterns.json

    # HTTP data source (fetched at policy load time)
    user_roles:
      url: https://internal.api/users/roles
      refresh_interval: 5m
      auth_header: "X-API-Key"
      auth_env: "CLAWDSTRIKE_DATA_API_KEY"

  # Evaluation settings
  settings:
    # How to combine YAML and Rego decisions
    combination_mode: "most_restrictive"  # or: "rego_overrides", "yaml_overrides"

    # Whether Rego evaluation failures should deny
    fail_closed: true

    # Timeout for Rego evaluation
    eval_timeout_ms: 100

    # Enable detailed decision tracing
    trace: false
```

### Decision Combination Strategies

```
+----------------------------------------------------------------+
|                   Decision Combination Matrix                    |
+----------------------------------------------------------------+
|                                                                  |
|  Mode: most_restrictive (default)                               |
|  +-----------+-------------+---------------------------------+  |
|  | YAML      | Rego        | Final                           |  |
|  +-----------+-------------+---------------------------------+  |
|  | allow     | allow       | allow                           |  |
|  | allow     | deny        | deny                            |  |
|  | deny      | allow       | deny                            |  |
|  | deny      | deny        | deny                            |  |
|  +-----------+-------------+---------------------------------+  |
|                                                                  |
|  Mode: rego_overrides                                           |
|  +-----------+-------------+---------------------------------+  |
|  | YAML      | Rego        | Final                           |  |
|  +-----------+-------------+---------------------------------+  |
|  | any       | allow       | allow                           |  |
|  | any       | deny        | deny                            |  |
|  | any       | no_decision | YAML decision                   |  |
|  +-----------+-------------+---------------------------------+  |
|                                                                  |
|  Mode: yaml_overrides                                           |
|  +-----------+-------------+---------------------------------+  |
|  | YAML      | Rego        | Final                           |  |
|  +-----------+-------------+---------------------------------+  |
|  | allow     | any         | allow                           |  |
|  | deny      | any         | deny                            |  |
|  | no_rule   | any         | Rego decision                   |  |
|  +-----------+-------------+---------------------------------+  |
|                                                                  |
+----------------------------------------------------------------+
```

---

## CLI Interface

### Policy Compilation

```bash
# Compile YAML + Rego into OPA bundle
hush policy compile policy.yaml -o policy.bundle

# Compile with strict validation
hush policy compile --strict policy.yaml

# Verify existing bundle
hush policy compile --verify policy.bundle
```

### Policy Evaluation

```bash
# Evaluate single event
hush policy eval policy.yaml --input event.json

# Evaluate with trace output
hush policy eval policy.yaml --input event.json --trace

# Evaluate Rego policy directly
hush policy eval policy.rego --input event.json --package clawdstrike.guards.egress
```

### Rego Development

```bash
# Format Rego files
openclaw rego fmt policies/

# Lint Rego files
openclaw rego lint policies/

# Run Rego unit tests
openclaw rego test policies/ --verbose

# Generate coverage report
openclaw rego test policies/ --coverage --threshold 80
```

### Interactive REPL

```bash
# Start interactive Rego REPL
openclaw rego repl policy.yaml

> input := {"event": {"eventType": "file_write", "data": {"path": "/etc/passwd"}}}
> data.clawdstrike.guards.filesystem.allow
false
> data.clawdstrike.guards.filesystem.reason
"Write to sensitive path requires explicit permission"
```

---

## TypeScript API

```typescript
import { PolicyEngine, RegoPolicy, OpaBundle } from '@clawdstrike/openclaw';

// Load hybrid policy (YAML + Rego)
const engine = new PolicyEngine({
  policy: './policy.yaml',
  rego: {
    enabled: true,
    bundlePath: './policy.bundle',  // Optional pre-compiled bundle
  }
});

// Evaluate event
const decision = await engine.evaluate({
  eventId: 'evt-123',
  eventType: 'file_write',
  timestamp: new Date().toISOString(),
  data: {
    type: 'file',
    path: '/etc/config.yaml',
    operation: 'write'
  }
}, {
  // Optional context
  user: { id: 'user-1', roles: ['developer'] },
  environment: { name: 'production' }
});

// Compile Rego policy programmatically
const bundle = await OpaBundle.compile({
  policies: ['./policies/*.rego'],
  data: {
    limits: { maxFileWrites: 100 }
  }
});

// Hot-reload policy
await engine.reload();

// Get decision explanation
const explanation = await engine.explain(event);
console.log(explanation.trace);  // Full evaluation trace
```

---

## Rust API

```rust
use clawdstrike::{PolicyEngine, PolicyConfig, RegoConfig, Event};

// Create engine with Rego support
let config = PolicyConfig {
    yaml_path: "policy.yaml".into(),
    rego: Some(RegoConfig {
        policies: vec!["policies/".into()],
        data_paths: vec!["data/".into()],
        combination_mode: CombinationMode::MostRestrictive,
        eval_timeout: Duration::from_millis(100),
    }),
};

let engine = PolicyEngine::new(config)?;

// Evaluate event
let event = Event::FileWrite {
    path: "/etc/config.yaml".into(),
    content_hash: None,
};

let decision = engine.evaluate(&event, &context)?;

match decision {
    Decision::Allow => println!("Allowed"),
    Decision::Deny { reason, .. } => println!("Denied: {}", reason),
    Decision::Warn { message, .. } => println!("Warning: {}", message),
}

// Get evaluation trace for debugging
let trace = engine.evaluate_with_trace(&event, &context)?;
for step in trace.steps {
    println!("{}: {} = {:?}", step.rule, step.expression, step.result);
}
```

---

## Security Considerations

### Rego Sandboxing

```yaml
# policy.yaml - security settings
rego:
  security:
    # Disable dangerous built-ins
    disabled_builtins:
      - http.send       # No external HTTP
      - opa.runtime     # No runtime introspection
      - trace           # No debug tracing in production

    # Resource limits
    max_execution_time_ms: 100
    max_memory_mb: 64

    # Deny unknown built-ins
    strict_builtin_errors: true
```

### Data Source Authentication

```yaml
rego:
  data:
    user_roles:
      url: https://internal.api/roles
      auth:
        type: "bearer"
        env: "CLAWDSTRIKE_API_TOKEN"

      # TLS verification
      tls:
        verify: true
        ca_cert: /etc/ssl/internal-ca.pem

      # Response validation
      schema: ./schemas/roles.json
      max_size_kb: 1024
```

### Policy Signing

```bash
# Sign compiled bundle
hush policy sign policy.bundle --key private.pem

# Verify signature before loading
hush policy verify policy.bundle --key public.pem

# Require signed policies in config
```

```yaml
# clawdstrike.yaml
rego:
  security:
    require_signed_bundles: true
    trusted_keys:
      - ./keys/policy-signer.pub
```

---

## Performance Considerations

### Compilation vs. Interpretation

```
+----------------------------------------------------------------+
|                    Performance Comparison                        |
+----------------------------------------------------------------+
|                                                                  |
|  Approach              | Latency | Cold Start | Memory         |
|  ----------------------|---------|------------|----------------|
|  YAML-only (current)   | ~1ms    | ~10ms      | ~5MB           |
|  Rego interpreted      | ~5ms    | ~100ms     | ~20MB          |
|  Rego compiled (WASM)  | ~2ms    | ~50ms      | ~15MB          |
|  Pre-loaded bundle     | ~2ms    | ~5ms       | ~15MB          |
|                                                                  |
+----------------------------------------------------------------+
```

### Caching Strategy

```yaml
rego:
  performance:
    # Cache compiled policies
    bundle_cache: true
    bundle_cache_path: /tmp/clawdstrike/bundles

    # Cache partial evaluation results
    partial_eval_cache: true
    partial_eval_cache_size: 1000

    # Pre-compile common queries
    precompile_queries:
      - data.clawdstrike.guards.filesystem.allow
      - data.clawdstrike.guards.egress.allow
```

---

## Testing Rego Policies

### Unit Tests

```rego
# policies/time_based_egress_test.rego
package clawdstrike.guards.egress_test

import data.clawdstrike.guards.egress

# Test business hours allow
test_allow_during_business_hours if {
    egress.allow with input as {
        "event": {
            "eventType": "network_egress",
            "data": {"host": "api.github.com"}
        }
    } with data.allowed_domains as ["*.github.com"]
      with time.now_ns as time.parse_rfc3339_ns("2024-01-15T14:00:00Z")
}

# Test deny outside business hours
test_deny_outside_business_hours if {
    egress.deny with input as {
        "event": {
            "eventType": "network_egress",
            "data": {"host": "api.prod.internal"}
        }
    } with time.now_ns as time.parse_rfc3339_ns("2024-01-15T03:00:00Z")
}

# Test reason message
test_reason_includes_time if {
    reason := egress.reason with input as {
        "event": {
            "eventType": "network_egress",
            "data": {"host": "api.prod.internal"}
        }
    } with time.now_ns as time.parse_rfc3339_ns("2024-01-15T03:00:00Z")

    contains(reason, "business hours")
}
```

### Integration Tests

```yaml
# tests/integration/egress.test.yaml
name: "Egress Policy Integration Tests"
policy: ./policy.yaml

tests:
  - name: "Allow GitHub during business hours"
    mock:
      time: "2024-01-15T10:00:00Z"
      data:
        allowed_domains: ["*.github.com"]
    input:
      eventType: network_egress
      data:
        host: api.github.com
        port: 443
    expect:
      allow: true

  - name: "Deny production API at night"
    mock:
      time: "2024-01-15T02:00:00Z"
    input:
      eventType: network_egress
      data:
        host: api.prod.internal
        port: 443
    expect:
      deny: true
      reason_contains: "business hours"
```

---

## Migration from YAML-Only

### Phase 1: Parallel Operation

```yaml
# Keep existing YAML, add Rego alongside
version: "1.1.0"
guards:
  # Existing YAML guards continue to work
  forbidden_path:
    patterns: ["**/.ssh/**"]

rego:
  enabled: true
  combination_mode: "most_restrictive"
  policies:
    - path: ./policies/additional_checks.rego
```

### Phase 2: Gradual Migration

```yaml
# Migrate individual guards to Rego
rego:
  policies:
    - path: ./policies/egress.rego
      replaces_guard: egress_allowlist  # Disables YAML guard

guards:
  # This is now ignored, kept for documentation
  egress_allowlist:
    deprecated: true
    migrated_to: ./policies/egress.rego
```

### Phase 3: Full Rego

```yaml
# Pure Rego policy
version: "1.1.0"
name: "Production Policy"

rego:
  policies:
    - path: ./policies/
  combination_mode: "rego_only"
```

---

## Implementation Phases

### Phase 1: Core Integration (4 weeks)
- [ ] OPA engine integration (Rust/WASM)
- [ ] Basic Rego policy loading
- [ ] Input/output schema implementation
- [ ] CLI commands (compile, eval)

### Phase 2: YAML Integration (3 weeks)
- [ ] Hybrid YAML+Rego configuration
- [ ] Decision combination strategies
- [ ] Data source loading
- [ ] Hot-reload support

### Phase 3: Developer Tools (3 weeks)
- [ ] Rego REPL
- [ ] Testing framework integration
- [ ] Trace/explain functionality
- [ ] IDE support (VSCode extension)

### Phase 4: Production Hardening (2 weeks)
- [ ] Performance optimization
- [ ] Security hardening
- [ ] Documentation
- [ ] Migration guide

---

## Appendix: Built-in Functions Available

| Function | Description | Example |
|----------|-------------|---------|
| `glob.match(pattern, delimiters, match)` | Glob pattern matching | `glob.match("*.txt", [], "file.txt")` |
| `regex.match(pattern, value)` | Regex matching | `regex.match("^sk-", token)` |
| `time.now_ns()` | Current time (nanoseconds) | `time.now_ns()` |
| `time.clock(ns)` | Extract [hour, minute, second] | `time.clock([time.now_ns(), "UTC"])` |
| `time.parse_rfc3339_ns(string)` | Parse ISO timestamp | `time.parse_rfc3339_ns("2024-01-15T10:00:00Z")` |
| `net.cidr_contains(cidr, ip)` | CIDR membership | `net.cidr_contains("10.0.0.0/8", "10.1.2.3")` |
| `io.jwt.decode(token)` | Decode JWT | `io.jwt.decode(bearer_token)` |
| `crypto.sha256(string)` | SHA256 hash | `crypto.sha256(content)` |
| `json.marshal(value)` | JSON encode | `json.marshal({"key": "value"})` |
| `sprintf(format, args)` | Format string | `sprintf("user: %s", [user_id])` |
