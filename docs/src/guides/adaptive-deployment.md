# Adaptive Deployment Guide

This guide covers how to configure and deploy the Clawdstrike Desktop Agent in each of the three Adaptive Architecture deployment modes: Standalone, Connected, and Headless. For background on the architecture and mode selection, see [Adaptive Architecture](../concepts/adaptive-architecture.md).

## Standalone Mode

Standalone mode is the default. The agent runs entirely on the local machine with no enterprise dependency.

### Prerequisites

- Clawdstrike CLI installed ([Installation](../getting-started/installation.md))
- Desktop Agent built or installed
- A policy file (local YAML) or a built-in ruleset name

### Configuration

Create or edit `~/.clawdstrike/config.yaml`:

```yaml
mode: standalone
engine:
  type: cli
  policy_ref: default        # Built-in ruleset: permissive, default, strict, ai-agent, cicd
  hush_path: hush            # Path to hush CLI binary
  timeout_ms: 10000
agent:
  port: 9878
  bind: 127.0.0.1
```

You can also use a project-level policy by placing a `.hush/policy.yaml` file in your project root. The agent loads project-level policies automatically when working in that directory.

### Starting the Agent

```bash
# Build and run from source
cd apps/desktop
cargo tauri dev

# Or launch the installed application
open /Applications/Clawdstrike.app
```

### Verifying It Works

```bash
# Health check
curl -fsS http://127.0.0.1:9878/api/v1/agent/health | jq .

# Test a policy check
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike"
AGENT_TOKEN="$(tr -d '[:space:]' < "${CONFIG_DIR}/agent-local-token")"

curl -fsS -X POST \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"action_type":"file_access","target":"~/.ssh/id_rsa"}' \
  http://127.0.0.1:9878/api/v1/agent/policy-check | jq .
```

The health check should show `daemon.state` as `running`. The policy check against `~/.ssh/id_rsa` should return `allowed: false` under the default or stricter rulesets.

---

## Connected Mode

Connected mode links the agent to enterprise infrastructure for centralized policy management, audit telemetry, and fleet control while maintaining local evaluation as a fallback.

### Prerequisites

- Enterprise infrastructure deployed (NATS cluster, hushd, Cloud API)
- An enrollment token from your enterprise administrator (see [Enterprise Enrollment](enterprise-enrollment.md))
- Network access to the enterprise Cloud API endpoint (HTTPS)
- Desktop Agent installed and running in standalone mode

### Enrollment

Before configuring connected mode, you must enroll the agent with your enterprise. Follow the [Enterprise Enrollment Guide](enterprise-enrollment.md) for the complete process. Enrollment provisions NATS credentials and transitions the agent from standalone to connected mode automatically.

### Configuration

After successful enrollment, the agent updates `~/.clawdstrike/config.yaml` automatically. The resulting configuration looks like this:

```yaml
mode: connected
enterprise:
  hushd_url: https://hushd.acme.clawdstrike.cloud
  nats_url: nats://nats.acme.clawdstrike.cloud:4222
  nats_auth:
    creds_file: ~/.clawdstrike/nats.creds
engine:
  remote:
    timeout_ms: 10000
    token: ${CLAWDSTRIKE_API_KEY}
  local:
    policy_ref: default
    hush_path: hush
  fallback: true
  probe_interval_ms: 30000
agent:
  port: 9878
  bind: 127.0.0.1
telemetry:
  flush_interval_ms: 5000
  offline_queue_max: 10000
```

Key settings:

| Setting | Description |
|---------|-------------|
| `enterprise.hushd_url` | Enterprise hushd endpoint for remote policy evaluation |
| `enterprise.nats_url` | NATS cluster URL for policy sync and telemetry |
| `enterprise.nats_auth.creds_file` | Path to NATS credentials file (provisioned during enrollment) |
| `engine.fallback` | Enable local fallback when enterprise is unreachable (default: `true`) |
| `engine.probe_interval_ms` | How often to check enterprise connectivity (default: 30000ms) |
| `telemetry.offline_queue_max` | Maximum offline receipts to queue before evicting oldest (default: 10000) |

### Verifying Connectivity

```bash
# Check agent health -- should show mode: connected
curl -fsS http://127.0.0.1:9878/api/v1/agent/health | jq .

# Check enrollment status
curl -fsS \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  http://127.0.0.1:9878/api/v1/enrollment-status | jq .
```

The health response should show `mode: "connected"` and the enrollment status should show `enrolled: true` with your tenant ID.

### What Happens During a Network Outage

When the enterprise becomes unreachable, the agent handles the transition automatically:

1. The remote engine probe detects the connectivity failure.
2. The agent transitions to **degraded** mode.
3. Policy evaluation continues using the local engine with the most recently synced policy cache.
4. All decisions made in degraded mode include `provenance.mode: "degraded"` so they are clearly marked in the audit trail.
5. Decisions are queued in the local store-and-forward buffer.
6. The agent continues probing the enterprise at the configured interval.
7. When connectivity is restored, the agent promotes back to **connected** mode and drains the offline queue.

> **Warning:** If the local policy cache is older than 24 hours, the agent logs a warning in both the decision provenance and heartbeat. Enterprise administrators should investigate agents with stale caches.

### Monitoring Agent Health

Enterprise administrators can monitor agent health through:

- **Heartbeat:** Each agent sends a status report every 30 seconds. Agents missing heartbeats for 120 seconds are marked stale; after 300 seconds they are marked dead.
- **Policy version:** Each heartbeat includes the agent's current policy version. Agents running outdated policies are visible in the fleet dashboard.
- **Telemetry stream:** All security decisions flow to the enterprise audit stream for centralized review.

---

## Headless Mode

Headless mode runs without a local agent process. The agent runtime calls the enterprise hushd service directly. This mode is designed for CI/CD pipelines, serverless functions, and managed compute environments.

### Prerequisites

- Enterprise hushd deployed and accessible over HTTPS
- An API key or service account token issued by your enterprise administrator
- Network access from the compute environment to the enterprise hushd endpoint

### Configuration for CI/CD Pipelines

Set environment variables in your pipeline configuration:

```yaml
# Environment variables
CLAWDSTRIKE_MODE: headless
CLAWDSTRIKE_HUSHD_URL: https://hushd.acme.clawdstrike.cloud
CLAWDSTRIKE_API_KEY: cs_live_...
CLAWDSTRIKE_OFFLINE_FALLBACK: "false"
```

> **Warning:** In headless mode, `CLAWDSTRIKE_OFFLINE_FALLBACK` is `false` by default. If the enterprise hushd is unreachable, all actions are denied. This is intentional -- headless environments should not operate without centralized policy enforcement.

### Configuration for Serverless Environments

For Lambda, Cloud Functions, or similar environments, configure the same environment variables in your function settings. The `hushd-engine` package handles connection pooling and timeout management.

```yaml
CLAWDSTRIKE_MODE: headless
CLAWDSTRIKE_HUSHD_URL: https://hushd.acme.clawdstrike.cloud
CLAWDSTRIKE_API_KEY: cs_live_...
```

### Example: GitHub Actions Integration

```yaml
name: CI with Clawdstrike
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      CLAWDSTRIKE_MODE: headless
      CLAWDSTRIKE_HUSHD_URL: ${{ secrets.CLAWDSTRIKE_HUSHD_URL }}
      CLAWDSTRIKE_API_KEY: ${{ secrets.CLAWDSTRIKE_API_KEY }}
    steps:
      - uses: actions/checkout@v4
      - name: Install Clawdstrike CLI
        run: cargo install clawdstrike-cli
      - name: Run security checks
        run: clawdstrike check --mode headless --action-type file --ruleset strict .
```

### Example: Kubernetes Sidecar

Deploy the Clawdstrike agent as a sidecar container alongside your application:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-agent-pod
spec:
  containers:
    - name: agent-runtime
      image: my-agent:latest
      env:
        - name: CLAWDSTRIKE_MODE
          value: headless
        - name: CLAWDSTRIKE_HUSHD_URL
          value: https://hushd.internal.svc.cluster.local
        - name: CLAWDSTRIKE_API_KEY
          valueFrom:
            secretKeyRef:
              name: clawdstrike-secrets
              key: api-key
```

For Helm-based deployments, see the Clawdstrike Helm chart documentation.

---

## Mode Transitions

### Upgrading from Standalone to Connected

Standalone agents can be promoted to connected mode through the enrollment process. No reinstallation is required.

1. Obtain an enrollment token from your enterprise administrator.
2. Run the enrollment command (see [Enterprise Enrollment](enterprise-enrollment.md)).
3. The agent automatically transitions from standalone to connected mode.
4. Verify the transition via the health endpoint.

### Handling Temporary Disconnections

When a connected agent loses enterprise connectivity:

| Phase | Duration | Agent Behavior |
|-------|----------|----------------|
| Initial detection | 0-5 seconds | Remote probe fails; agent transitions to degraded mode |
| Degraded operation | 5 seconds - indefinite | Local engine enforces cached policy; decisions queued for later submission |
| Reconnection | Automatic | Agent probes enterprise every 30 seconds; promotes to connected on success |
| Queue drain | On reconnection | Offline decisions are submitted to the enterprise audit stream |

The agent tracks the age of its cached policy. If the cache becomes stale (default: older than 24 hours), the agent includes a warning in decision provenance and heartbeat metadata.

### Emergency Procedures

Enterprise administrators have access to the following emergency controls for connected agents:

**Kill switch:** Immediately locks an agent into deny-all mode. All actions are denied regardless of policy. The kill switch can only be reversed by an administrator issuing a posture command to restore normal operation.

```bash
# Issue kill switch (enterprise admin)
curl -X POST \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"command": "kill_switch"}' \
  https://api.clawdstrike.cloud/api/v1/agents/${AGENT_ID}/command
```

**Forced posture change:** Change an agent's posture remotely (e.g., to `restricted` mode) without waiting for automatic posture transitions.

**Agent revocation:** Permanently revoke an agent's enrollment. The agent's NATS credentials are deleted, and it transitions back to standalone mode on the next connection attempt.

> **Tip:** Test emergency procedures during onboarding rather than during an incident. Verify that kill switch and revocation work as expected in a staging environment before relying on them in production.

## Related

- [Adaptive Architecture](../concepts/adaptive-architecture.md) -- Architecture overview and mode selection
- [Enterprise Enrollment](enterprise-enrollment.md) -- Step-by-step enrollment guide
- [Desktop Agent Deployment](desktop-agent.md) -- Base desktop agent setup
- [Posture Policies](posture-policy.md) -- Posture states and transitions
