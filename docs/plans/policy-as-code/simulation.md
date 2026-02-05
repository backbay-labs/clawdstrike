# Policy Simulation and Dry-Run for Clawdstrike

## Problem Statement

Deploying policy changes to production without understanding their impact is risky:

### Current Challenges

1. **Blind Deployment**: No way to preview policy behavior before enforcement
2. **Production Testing Only**: Must deploy to production to see real behavior
3. **Incident Replay Impossible**: Cannot reproduce past incidents with new policies
4. **Capacity Planning Gaps**: Unknown performance impact of policy changes
5. **Rollback Anxiety**: Fear of breaking changes prevents policy improvements

### Common Failure Scenarios

| Scenario | Impact | Root Cause |
|----------|--------|------------|
| Overly strict egress blocks API | Service outage | No pre-deploy testing |
| New pattern causes timeout | Performance degradation | No load testing |
| Policy change breaks workflow | Developer productivity loss | No workflow testing |
| Compliance audit fails | Regulatory penalty | No policy verification |

---

## Proposed Solution: Policy Simulation

### Feature Overview

```
+------------------------------------------------------------------+
|                    Policy Simulation System                        |
+------------------------------------------------------------------+
|                                                                   |
|   Modes:                                                          |
|   +------------------------------------------------------------+ |
|   | Interactive  - Real-time event simulation in terminal       | |
|   | Batch        - Process event files for CI/CD pipelines     | |
|   | Replay       - Re-run audit logs against new policies       | |
|   | Shadow       - Run alongside production without enforcing   | |
|   +------------------------------------------------------------+ |
|                                                                   |
|   Use Cases:                                                      |
|   +------------------------------------------------------------+ |
|   | - Preview policy impact before deployment                   | |
|   | - Test against historical production traffic                | |
|   | - Validate compliance requirements                          | |
|   | - Performance testing and benchmarking                      | |
|   | - Debug policy decisions                                    | |
|   +------------------------------------------------------------+ |
|                                                                   |
+------------------------------------------------------------------+
```

### Architecture

```
+------------------------------------------------------------------+
|                    Simulation Architecture                         |
+------------------------------------------------------------------+
|                                                                   |
|   +----------+     +----------+     +----------+                  |
|   |  Event   |     |  Policy  |     | Expected |                  |
|   |  Source  |     |  Under   |     | Outcomes |                  |
|   |          |     |  Test    |     | (opt)    |                  |
|   +----+-----+     +----+-----+     +----+-----+                  |
|        |               |                 |                        |
|        v               v                 v                        |
|   +--------------------------------------------------+           |
|   |              Simulation Engine                    |           |
|   |  +----------+  +----------+  +----------+        |           |
|   |  |  Event   |  |  Policy  |  | Decision |        |           |
|   |  |  Parser  |  |  Engine  |  | Recorder |        |           |
|   |  +----+-----+  +----+-----+  +----+-----+        |           |
|   |       |             |             |               |           |
|   |       v             v             v               |           |
|   |  +------------------------------------------+    |           |
|   |  |         Simulation Loop                  |    |           |
|   |  |  for each event:                         |    |           |
|   |  |    1. Parse event                        |    |           |
|   |  |    2. Evaluate against policy            |    |           |
|   |  |    3. Record decision                    |    |           |
|   |  |    4. Compare to expected (if provided)  |    |           |
|   |  |    5. Collect metrics                    |    |           |
|   |  +------------------------------------------+    |           |
|   +--------------------------------------------------+           |
|                          |                                        |
|                          v                                        |
|   +--------------------------------------------------+           |
|   |              Simulation Results                   |           |
|   |  +----------+  +----------+  +----------+        |           |
|   |  | Decision |  |  Metric  |  |  Diff    |        |           |
|   |  |  Report  |  |  Report  |  |  Report  |        |           |
|   |  +----------+  +----------+  +----------+        |           |
|   +--------------------------------------------------+           |
|                                                                   |
+------------------------------------------------------------------+
```

---

## CLI Interface

### Interactive Mode

```bash
# Start interactive simulation
clawdstrike policy simulate policy.yaml

# With specific context
clawdstrike policy simulate policy.yaml --context context.json

# With real-time event input
clawdstrike policy simulate policy.yaml --stdin
```

Interactive Session:
```
$ clawdstrike policy simulate policy.yaml

Clawdstrike Policy Simulator
============================
Policy: policy.yaml (v1.0.0)
Mode: Interactive

Type events as JSON or use shortcuts:
  file:read <path>     - Simulate file read
  file:write <path>    - Simulate file write
  egress <host>        - Simulate network egress
  tool <name> [params] - Simulate tool call
  help                 - Show all commands
  exit                 - Exit simulator

> file:read /home/user/.ssh/id_rsa
DENIED [forbidden_path] Access to path matching '**/.ssh/**' is forbidden
Severity: critical

> egress api.github.com
ALLOWED [egress_allowlist] Domain matches allow pattern '*.github.com'

> tool bash {"command": "rm -rf /"}
DENIED [patch_integrity] Command matches forbidden pattern '(?i)rm\s+-rf\s+/'
Severity: critical

> {"eventType": "file_write", "data": {"type": "file", "path": "/tmp/test.txt"}}
ALLOWED [no_violation] Event passed all guards

> history
Event History:
  1. file_read /home/user/.ssh/id_rsa -> DENIED
  2. network_egress api.github.com -> ALLOWED
  3. command_exec rm -rf / -> DENIED
  4. file_write /tmp/test.txt -> ALLOWED

> exit
Session ended. 4 events evaluated.
```

### Batch Mode

```bash
# Process event file
clawdstrike policy simulate policy.yaml --events events.json

# Process with expected outcomes
clawdstrike policy simulate policy.yaml --events events.json --expected expected.json

# CI-friendly output
clawdstrike policy simulate policy.yaml --events events.json --format json

# Fail if any unexpected denials
clawdstrike policy simulate policy.yaml --events events.json --fail-on-deny

# Summary only
clawdstrike policy simulate policy.yaml --events events.json --summary
```

### Replay Mode

```bash
# Replay audit log against new policy
clawdstrike policy simulate new-policy.yaml --replay audit.json

# Compare old vs new policy
clawdstrike policy simulate new-policy.yaml --replay audit.json --compare old-policy.yaml

# Replay with time range
clawdstrike policy simulate policy.yaml --replay audit.json \
  --since "2024-01-01" --until "2024-01-15"

# Replay with filters
clawdstrike policy simulate policy.yaml --replay audit.json \
  --filter-guard egress_allowlist \
  --filter-decision denied
```

### Shadow Mode

```bash
# Run in shadow mode (log decisions, don't enforce)
clawdstrike policy shadow policy.yaml --port 8080

# Shadow with comparison to existing policy
clawdstrike policy shadow new-policy.yaml --compare current-policy.yaml

# Shadow with alerting
clawdstrike policy shadow policy.yaml --alert-on-diff --webhook https://alerts.example.com
```

---

## Event Format

### Input Event Schema

```json
{
  "eventId": "evt-123",
  "eventType": "file_read | file_write | network_egress | command_exec | tool_call | patch_apply",
  "timestamp": "2024-01-15T10:30:00Z",
  "sessionId": "session-456",
  "data": {
    // Event-specific data
  },
  "context": {
    "user": {
      "id": "user-789",
      "roles": ["developer"]
    },
    "environment": {
      "name": "production"
    }
  }
}
```

### Event Shortcuts

```yaml
# Shortcut definitions for interactive mode
shortcuts:
  "file:read <path>":
    eventType: file_read
    data:
      type: file
      path: "{path}"
      operation: read

  "file:write <path>":
    eventType: file_write
    data:
      type: file
      path: "{path}"
      operation: write

  "egress <host> [port]":
    eventType: network_egress
    data:
      type: network
      host: "{host}"
      port: "{port:443}"

  "tool <name> [params...]":
    eventType: tool_call
    data:
      type: tool
      toolName: "{name}"
      parameters: "{params:{}}"

  "patch <file> <content>":
    eventType: patch_apply
    data:
      type: patch
      filePath: "{file}"
      patchContent: "{content}"
```

---

## Simulation Output

### Decision Report

```
$ clawdstrike policy simulate policy.yaml --events events.json

Simulation Report
=================

Events Processed: 1,000
Duration: 0.42s
Throughput: 2,380 events/sec

Decision Summary:
  ALLOWED:  890 (89.0%)
  DENIED:   100 (10.0%)
  WARNED:    10 (1.0%)

Denials by Guard:
  forbidden_path:  45 (45.0%)
  egress_allowlist: 35 (35.0%)
  secret_leak:     15 (15.0%)
  patch_integrity:  5 (5.0%)

Top Denied Events:
  1. file_read /home/user/.ssh/id_rsa (23 times)
  2. network_egress evil.com (18 times)
  3. tool_call shell_exec (12 times)

Denied Event Details (showing first 10):
---
Event #23:
  Type: file_read
  Path: /home/user/.ssh/id_rsa
  Decision: DENIED
  Guard: forbidden_path
  Reason: Access to path matching '**/.ssh/**' is forbidden
  Severity: critical
---
...
```

### Comparison Report

```
$ clawdstrike policy simulate new.yaml --replay audit.json --compare old.yaml

Policy Comparison Simulation
============================

Events: 10,000 (from audit log)
Period: 2024-01-01 to 2024-01-15

Decision Changes:
  Total Changed: 156 (1.56%)
  Allow -> Deny: 89
  Deny -> Allow: 12
  Allow -> Warn: 45
  Warn -> Deny: 10

Breaking Changes (Allow -> Deny):

  1. network_egress to cdn.example.com (45 events)
     Old Policy: ALLOWED (no matching block)
     New Policy: DENIED (default_action changed to block)

  2. file_read /app/config/secrets.yaml (23 events)
     Old Policy: ALLOWED (path not forbidden)
     New Policy: DENIED (new pattern **/secrets.yaml)

  3. tool_call: shell_exec (21 events)
     Old Policy: ALLOWED (tool not blocked)
     New Policy: DENIED (added to mcp_tool.block)

New Allowances (Deny -> Allow):

  1. network_egress to *.anthropic.com (12 events)
     Old Policy: DENIED (not in allow list)
     New Policy: ALLOWED (added to egress_allowlist.allow)

Recommendation:
  - Review 89 new denials before deployment
  - Consider gradual rollout with shadow mode
  - Add cdn.example.com to allow list if needed
```

### Performance Report

```
$ clawdstrike policy simulate policy.yaml --events events.json --benchmark

Performance Benchmark
=====================

Events: 10,000
Iterations: 5

Latency (per event):
  p50: 0.12ms
  p90: 0.28ms
  p95: 0.45ms
  p99: 1.20ms
  max: 8.50ms

Throughput:
  mean: 8,333 events/sec
  min:  7,500 events/sec
  max:  9,100 events/sec

Latency by Guard:
  forbidden_path:   0.08ms (avg)
  egress_allowlist: 0.15ms (avg)
  secret_leak:      0.42ms (avg)  [regex heavy]
  patch_integrity:  0.35ms (avg)

Slow Events (>1ms):
  1. patch_apply with 50KB patch: 8.5ms (regex scanning)
  2. tool_call with large params: 3.2ms (secret detection)
  3. patch_apply with complex diff: 2.1ms

Recommendations:
  - secret_leak regex patterns could be optimized
  - Consider caching compiled regex patterns
  - Large patches may need streaming evaluation
```

---

## Shadow Mode

### Concept

Shadow mode runs the new policy in parallel with production without enforcing:

```
+------------------------------------------------------------------+
|                    Shadow Mode Architecture                        |
+------------------------------------------------------------------+
|                                                                   |
|   Production Traffic                                              |
|         |                                                         |
|         v                                                         |
|   +------------+                                                  |
|   |  Load      |                                                  |
|   |  Balancer  |                                                  |
|   +-----+------+                                                  |
|         |                                                         |
|         +--------------------+                                    |
|         |                    |                                    |
|         v                    v                                    |
|   +------------+       +------------+                             |
|   |  Primary   |       |  Shadow    |                             |
|   |  Policy    |       |  Policy    |                             |
|   |  (enforce) |       |  (observe) |                             |
|   +-----+------+       +-----+------+                             |
|         |                    |                                    |
|         |                    v                                    |
|         |              +------------+                             |
|         |              | Comparison |                             |
|         |              |   Engine   |                             |
|         |              +-----+------+                             |
|         |                    |                                    |
|         v                    v                                    |
|   +------------+       +------------+                             |
|   |  Production|       |  Diff Log  |                             |
|   |  Decisions |       |  & Alerts  |                             |
|   +------------+       +------------+                             |
|                                                                   |
+------------------------------------------------------------------+
```

### Shadow Configuration

```yaml
# shadow-config.yaml
mode: shadow

primary_policy: ./current-policy.yaml
shadow_policy: ./new-policy.yaml

comparison:
  # Log all differences
  log_all_diffs: true

  # Alert on decision changes
  alert_on:
    - allow_to_deny   # Breaking changes
    - severity_increase

  # Webhook for alerts
  webhook:
    url: https://alerts.example.com/clawdstrike
    method: POST
    headers:
      Authorization: "Bearer ${ALERT_TOKEN}"

  # Slack integration
  slack:
    webhook_url: "${SLACK_WEBHOOK}"
    channel: "#security-alerts"

# Sampling (for high-traffic systems)
sampling:
  rate: 0.1  # Sample 10% of traffic
  seed: 42   # For reproducibility

# Duration
duration: 24h
auto_promote: false  # Don't auto-switch to shadow policy

# Metrics
metrics:
  prometheus:
    enabled: true
    port: 9090
```

### Shadow CLI

```bash
# Start shadow mode
clawdstrike policy shadow new-policy.yaml

# With comparison
clawdstrike policy shadow new-policy.yaml --compare current-policy.yaml

# With duration
clawdstrike policy shadow new-policy.yaml --duration 24h

# With sampling
clawdstrike policy shadow new-policy.yaml --sample-rate 0.1

# With alerting
clawdstrike policy shadow new-policy.yaml \
  --alert-on-diff \
  --slack-webhook "$SLACK_URL"

# View shadow metrics
clawdstrike policy shadow --status

# Promote shadow to primary
clawdstrike policy shadow --promote

# Abort shadow mode
clawdstrike policy shadow --abort
```

### Shadow Metrics

```
$ clawdstrike policy shadow --status

Shadow Mode Status
==================

Duration: 4h 32m (20h 28m remaining)
Events Processed: 45,230

Primary Policy: current-policy.yaml
Shadow Policy: new-policy.yaml

Decision Comparison:
  Identical: 44,950 (99.38%)
  Different: 280 (0.62%)

Difference Breakdown:
  Allow -> Deny: 12 (0.03%)
  Deny -> Allow: 8 (0.02%)
  Allow -> Warn: 260 (0.57%)

Top Differences:
  1. network_egress to analytics.example.com
     Primary: ALLOWED
     Shadow: DENIED
     Count: 8

  2. file_read /var/log/app.log
     Primary: ALLOWED
     Shadow: WARNED
     Count: 156

Recommendation:
  - Minor differences detected
  - Review analytics.example.com egress before promotion
  - Continue shadow for full 24h before decision
```

---

## Programmatic API

### TypeScript API

```typescript
import {
  PolicySimulator,
  SimulationConfig,
  SimulationResult,
  EventStream
} from '@clawdstrike/openclaw';

// Create simulator
const simulator = new PolicySimulator({
  policy: './policy.yaml',
  mode: 'batch'
});

// Simulate batch of events
const events = await EventStream.fromFile('events.json');
const result = await simulator.run(events);

console.log(`Allowed: ${result.allowed}`);
console.log(`Denied: ${result.denied}`);
console.log(`Duration: ${result.duration}ms`);

// Compare policies
const comparison = await simulator.compare({
  oldPolicy: './old-policy.yaml',
  newPolicy: './new-policy.yaml',
  events: events
});

console.log(`Changed decisions: ${comparison.changes.length}`);
for (const change of comparison.breakingChanges) {
  console.log(`BREAKING: ${change.eventType} - ${change.description}`);
}

// Interactive mode
const interactive = new PolicySimulator({
  policy: './policy.yaml',
  mode: 'interactive'
});

const decision = await interactive.evaluate({
  eventType: 'file_read',
  data: { type: 'file', path: '/etc/passwd', operation: 'read' }
});

console.log(`Decision: ${decision.allowed ? 'ALLOWED' : 'DENIED'}`);
if (decision.reason) {
  console.log(`Reason: ${decision.reason}`);
}

// Shadow mode
const shadow = new PolicySimulator({
  policy: './new-policy.yaml',
  mode: 'shadow',
  compareWith: './current-policy.yaml',
  onDiff: (diff) => {
    console.log(`Decision changed: ${diff.oldDecision} -> ${diff.newDecision}`);
  }
});

await shadow.start();
// ... shadow runs in background
await shadow.stop();
const shadowReport = shadow.getReport();
```

### Rust API

```rust
use clawdstrike::simulation::{Simulator, SimulationConfig, EventSource};

// Create simulator
let config = SimulationConfig {
    policy_path: "policy.yaml".into(),
    mode: SimulationMode::Batch,
    ..Default::default()
};

let simulator = Simulator::new(config)?;

// Simulate events
let events = EventSource::from_file("events.json")?;
let result = simulator.run(&events)?;

println!("Allowed: {}", result.allowed_count);
println!("Denied: {}", result.denied_count);
println!("Throughput: {:.0} events/sec", result.throughput());

// Compare policies
let comparison = simulator.compare(CompareConfig {
    old_policy: "old-policy.yaml".into(),
    new_policy: "new-policy.yaml".into(),
    events: events.clone(),
})?;

for change in comparison.breaking_changes() {
    eprintln!("BREAKING: {} at {}", change.description, change.event_id);
}

// Shadow mode
let shadow = Simulator::shadow(ShadowConfig {
    primary: "current-policy.yaml".into(),
    shadow: "new-policy.yaml".into(),
    duration: Duration::from_hours(24),
    sample_rate: 0.1,
    on_diff: |diff| {
        log::warn!("Decision change: {:?}", diff);
    },
})?;

shadow.start()?;
// ... runs in background
shadow.stop()?;

let report = shadow.report()?;
println!("Diff count: {}", report.diff_count);
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/policy-simulation.yml
name: Policy Simulation

on:
  pull_request:
    paths:
      - 'policy.yaml'

jobs:
  simulate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Clawdstrike
        uses: clawdstrike/setup-action@v1

      - name: Download Production Audit Log
        run: |
          # Fetch recent audit log for simulation
          openclaw audit export \
            --since "7 days ago" \
            --output audit.json

      - name: Simulate Policy Changes
        id: simulate
        run: |
          clawdstrike policy simulate policy.yaml \
            --replay audit.json \
            --compare origin/main:policy.yaml \
            --format json \
            --output simulation-report.json

          # Extract metrics for PR comment
          BREAKING=$(jq '.changes.allow_to_deny' simulation-report.json)
          echo "breaking_changes=$BREAKING" >> $GITHUB_OUTPUT

      - name: Comment on PR
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('simulation-report.json'));

            const body = `## Policy Simulation Results

            **Events Simulated:** ${report.total_events}
            **Decision Changes:** ${report.changes.total} (${report.changes.percentage}%)

            | Change Type | Count |
            |-------------|-------|
            | Allow -> Deny | ${report.changes.allow_to_deny} |
            | Deny -> Allow | ${report.changes.deny_to_allow} |
            | Allow -> Warn | ${report.changes.allow_to_warn} |

            ${report.changes.allow_to_deny > 0 ?
              '**Warning:** This change will deny previously allowed operations.' : ''}
            `;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });

      - name: Fail on Breaking Changes
        if: steps.simulate.outputs.breaking_changes > 0
        run: |
          echo "::error::Policy change would deny ${{ steps.simulate.outputs.breaking_changes }} previously allowed operations"
          echo "Review simulation-report.json for details"
          exit 1
```

### Deployment Pipeline

```yaml
# .github/workflows/deploy-policy.yml
name: Deploy Policy

on:
  push:
    branches: [main]
    paths:
      - 'policy.yaml'

jobs:
  shadow:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start Shadow Mode
        run: |
          clawdstrike policy shadow policy.yaml \
            --duration 24h \
            --compare ${{ secrets.CURRENT_POLICY_URL }} \
            --webhook ${{ secrets.ALERT_WEBHOOK }}

  monitor:
    runs-on: ubuntu-latest
    needs: shadow
    steps:
      - name: Wait for Shadow Period
        run: sleep 86400  # 24 hours

      - name: Check Shadow Results
        id: check
        run: |
          DIFF_RATE=$(clawdstrike policy shadow --status --format json | jq '.diff_rate')
          echo "diff_rate=$DIFF_RATE" >> $GITHUB_OUTPUT

          if (( $(echo "$DIFF_RATE > 0.05" | bc -l) )); then
            echo "::warning::High diff rate in shadow mode: $DIFF_RATE"
          fi

      - name: Promote Policy
        if: steps.check.outputs.diff_rate < 0.05
        run: |
          clawdstrike policy shadow --promote
          echo "Policy promoted to production"
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - simulate
  - shadow
  - deploy

policy-simulate:
  stage: simulate
  image: clawdstrike/cli:latest
  script:
    - |
      # Export recent audit log
      openclaw audit export \
        --since "7 days ago" \
        --output audit.json
    - |
      # Run simulation against audit log
      clawdstrike policy simulate policy.yaml \
        --replay audit.json \
        --compare $CI_MERGE_REQUEST_DIFF_BASE_SHA:policy.yaml \
        --format json \
        --output simulation-report.json
    - |
      # Check for breaking changes
      BREAKING=$(jq '.changes.allow_to_deny' simulation-report.json)
      if [ "$BREAKING" -gt 0 ]; then
        echo "ERROR: $BREAKING breaking changes detected"
        exit 1
      fi
  artifacts:
    paths:
      - simulation-report.json
    reports:
      dotenv: simulation.env
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - policy.yaml

policy-shadow:
  stage: shadow
  image: clawdstrike/cli:latest
  script:
    - |
      clawdstrike policy shadow policy.yaml \
        --duration 4h \
        --sample-rate 0.1 \
        --webhook $ALERT_WEBHOOK
    - |
      # Wait and check results
      sleep 14400  # 4 hours
      DIFF_RATE=$(clawdstrike policy shadow --status --format json | jq '.diff_rate')
      if (( $(echo "$DIFF_RATE > 0.05" | bc -l) )); then
        echo "High diff rate: $DIFF_RATE - manual review required"
        exit 1
      fi
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      changes:
        - policy.yaml
  when: manual

policy-deploy:
  stage: deploy
  image: clawdstrike/cli:latest
  script:
    - clawdstrike policy shadow --promote
    - echo "Policy deployed to production"
  needs:
    - policy-shadow
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

## Guard Type Simulation Examples

### Complete Guard Coverage

The simulation system supports all Clawdstrike guard types. Here are examples for each:

#### Forbidden Path Guard

```bash
# Interactive simulation
> file:read /home/user/.ssh/id_rsa
DENIED [forbidden_path] Access to path matching '**/.ssh/**' is forbidden

> file:write /etc/passwd
DENIED [forbidden_path] Access to path matching '/etc/passwd' is forbidden
```

#### Egress Allowlist Guard

```bash
# Interactive simulation
> egress api.github.com 443
ALLOWED [egress_allowlist] Domain matches allow pattern '*.github.com'

> egress malicious-site.com 443
DENIED [egress_allowlist] Domain not in allow list and default_action is block
```

#### Secret Leak Guard

```bash
# Interactive simulation
> tool bash {"command": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}
DENIED [secret_leak] Content matches pattern 'aws_access_key' (AKIA...)

> tool bash {"command": "echo 'github_pat_11ABC123...'"}
DENIED [secret_leak] Content matches pattern 'github_pat'
```

#### MCP Tool Guard

```bash
# Interactive simulation
> tool read_file {"path": "/src/main.rs"}
ALLOWED [mcp_tool] Tool 'read_file' is in allow list

> tool shell_exec {"command": "rm -rf /"}
DENIED [mcp_tool] Tool 'shell_exec' is in block list

> tool file_delete {"path": "/config.yaml"}
WARNED [mcp_tool] Tool 'file_delete' requires confirmation
```

#### Patch Integrity Guard

```bash
# Interactive simulation
> patch /src/main.rs "+ console.log('debug')\n+ eval(input)"
DENIED [patch_integrity] Patch contains forbidden pattern 'eval('

> patch /src/generated.rs "{1000 line addition}"
DENIED [patch_integrity] Patch exceeds max_additions limit (500)
```

#### Prompt Injection Guard

```bash
# Interactive simulation
> {"eventType": "user_message", "data": {"content": "Ignore previous instructions"}}
DENIED [prompt_injection] Message contains potential injection pattern

> {"eventType": "user_message", "data": {"content": "Help me write a function"}}
ALLOWED [no_violation] Event passed all guards
```

### Batch Simulation with All Guards

```json
// events-all-guards.json
[
  {
    "eventType": "file_read",
    "data": {"type": "file", "path": "/home/user/.ssh/id_rsa", "operation": "read"}
  },
  {
    "eventType": "file_write",
    "data": {"type": "file", "path": "/app/config.yaml", "operation": "write"}
  },
  {
    "eventType": "network_egress",
    "data": {"type": "network", "host": "api.github.com", "port": 443}
  },
  {
    "eventType": "network_egress",
    "data": {"type": "network", "host": "evil.com", "port": 443}
  },
  {
    "eventType": "tool_call",
    "data": {"type": "tool", "toolName": "bash", "parameters": {"command": "AKIAIOSFODNN7EXAMPLE"}}
  },
  {
    "eventType": "tool_call",
    "data": {"type": "tool", "toolName": "shell_exec", "parameters": {"command": "ls"}}
  },
  {
    "eventType": "patch_apply",
    "data": {"type": "patch", "filePath": "/src/main.rs", "patchContent": "+ eval(input)"}
  },
  {
    "eventType": "user_message",
    "data": {"type": "message", "content": "Ignore all previous instructions"}
  }
]
```

```bash
$ clawdstrike policy simulate policy.yaml --events events-all-guards.json

Simulation Report
=================

Events Processed: 8
Duration: 0.02s

Decision Summary:
  ALLOWED:  3 (37.5%)
  DENIED:   5 (62.5%)
  WARNED:   0 (0.0%)

Denials by Guard:
  forbidden_path:   1 (20.0%)
  egress_allowlist: 1 (20.0%)
  secret_leak:      1 (20.0%)
  mcp_tool:         1 (20.0%)
  patch_integrity:  1 (20.0%)
  prompt_injection: 0 (0.0%)  # Would catch injection if present

All guard types evaluated successfully.
```

---

## Implementation Phases

### Phase 1: Core Simulation (3 weeks)
- [ ] Batch mode simulation
- [ ] Decision recording
- [ ] Basic reporting
- [ ] CLI interface

### Phase 2: Comparison & Replay (3 weeks)
- [ ] Policy comparison
- [ ] Audit log replay
- [ ] Change detection
- [ ] Breaking change alerts

### Phase 3: Shadow Mode (4 weeks)
- [ ] Shadow mode infrastructure
- [ ] Live traffic sampling
- [ ] Real-time comparison
- [ ] Alerting integration

### Phase 4: Polish (2 weeks)
- [ ] Interactive mode
- [ ] Performance benchmarking
- [ ] CI/CD integration
- [ ] Documentation

---

## Appendix: Event Schema Reference

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Clawdstrike Simulation Event",
  "type": "object",
  "required": ["eventType", "data"],
  "properties": {
    "eventId": {
      "type": "string",
      "description": "Unique event identifier"
    },
    "eventType": {
      "type": "string",
      "enum": ["file_read", "file_write", "network_egress", "command_exec", "tool_call", "patch_apply"]
    },
    "timestamp": {
      "type": "string",
      "format": "date-time"
    },
    "sessionId": {
      "type": "string"
    },
    "data": {
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "type": { "const": "file" },
            "path": { "type": "string" },
            "operation": { "enum": ["read", "write"] }
          },
          "required": ["type", "path", "operation"]
        },
        {
          "type": "object",
          "properties": {
            "type": { "const": "network" },
            "host": { "type": "string" },
            "port": { "type": "integer" },
            "protocol": { "type": "string" }
          },
          "required": ["type", "host"]
        },
        {
          "type": "object",
          "properties": {
            "type": { "const": "command" },
            "command": { "type": "string" },
            "args": { "type": "array", "items": { "type": "string" } }
          },
          "required": ["type", "command"]
        },
        {
          "type": "object",
          "properties": {
            "type": { "const": "tool" },
            "toolName": { "type": "string" },
            "parameters": { "type": "object" }
          },
          "required": ["type", "toolName"]
        },
        {
          "type": "object",
          "properties": {
            "type": { "const": "patch" },
            "filePath": { "type": "string" },
            "patchContent": { "type": "string" }
          },
          "required": ["type", "filePath", "patchContent"]
        }
      ]
    },
    "context": {
      "type": "object",
      "properties": {
        "user": {
          "type": "object",
          "properties": {
            "id": { "type": "string" },
            "roles": { "type": "array", "items": { "type": "string" } }
          }
        },
        "environment": {
          "type": "object",
          "properties": {
            "name": { "type": "string" }
          }
        }
      }
    }
  }
}
```
