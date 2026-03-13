# Adaptive Deployment Guide

This guide covers how to configure and deploy the Clawdstrike Desktop Agent in each of the three Adaptive Architecture deployment modes: Standalone, Connected, and Headless. For background on the architecture and mode selection, see [Adaptive Architecture](../concepts/adaptive-architecture.md).

## Standalone Mode

Standalone mode is the default. The agent runs entirely on the local machine with no enterprise dependency.

### Prerequisites

- Clawdstrike CLI installed ([Installation](../getting-started/installation.md))
- Desktop Agent built or installed
- A policy file (local YAML) or a built-in ruleset name

### Configuration

Create or edit `${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/agent.json`:

```json
{
  "policy_path": "/Users/<you>/.config/clawdstrike/policy.yaml",
  "daemon_port": 9876,
  "agent_api_port": 9878,
  "enabled": true
}
```

You can also use a project-level policy by placing a `.hush/policy.yaml` file in your project root. The agent loads project-level policies automatically when working in that directory.

### Starting the Agent

```bash
# Build and run from source
cd apps/agent
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

- Enterprise infrastructure deployed (NATS cluster, hushd, Control API)
- An enrollment token from your enterprise administrator (see [Enterprise Enrollment](enterprise-enrollment.md))
- Network access to the enterprise Control API endpoint (HTTPS)
- Desktop Agent installed and running in standalone mode

### Enrollment

Before configuring connected mode, you must enroll the agent with your enterprise. Follow the [Enterprise Enrollment Guide](enterprise-enrollment.md) for the complete process. Enrollment provisions NATS credentials and transitions the agent from standalone to connected mode automatically.

### Configuration

After successful enrollment, the agent updates `${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/agent.json` automatically. The resulting configuration includes tenant-scoped NATS settings:

```json
{
  "nats": {
    "enabled": true,
    "nats_url": "nats://nats.acme.clawdstrike.cloud:4222",
    "tenant_id": "2f9f15f9-...",
    "agent_id": "agent-2f6dbe4b-...",
    "nats_account": "tenant-acme",
    "subject_prefix": "tenant-acme.clawdstrike",
    "token": "nats-acme-..."
  },
  "enrollment": {
    "enrolled": true,
    "agent_uuid": "f37df9b7-...",
    "tenant_id": "2f9f15f9-...",
    "enrollment_in_progress": false
  }
}
```

Key settings:

| Setting | Description |
|---------|-------------|
| `nats.enabled` | Enables enterprise NATS connectivity features |
| `nats.nats_url` | NATS cluster URL for policy sync and telemetry |
| `nats.subject_prefix` | Tenant-scoped prefix used for all publish/subscribe subjects |
| `nats.token` | Enrolled NATS auth token stored in local settings |
| `enrollment.enrolled` | Enrollment completion flag |
| `enrollment.agent_uuid` | Control API-issued agent UUID |

### Verifying Connectivity

```bash
# Check agent health
curl -fsS http://127.0.0.1:9878/api/v1/agent/health | jq .

# Check enrollment status
curl -fsS \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  http://127.0.0.1:9878/api/v1/enrollment-status | jq .
```

The enrollment status should show `enrolled: true` with your `agent_uuid` and `tenant_id`.

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
- **Heartbeat payload:** Heartbeats include session posture and budget state plus host/version metadata for fleet monitoring.
- **Telemetry stream:** All security decisions flow to the enterprise audit stream for centralized review.

### Control API Enterprise Runtime Defaults

The Control API enables the core adaptive workers by default. Make these settings explicit in production deployments:

| Environment variable | Default | Notes |
|----------------------|---------|-------|
| `NATS_PROVISIONING_MODE` | `external` | Control API starts without a provisioner URL, but tenant/agent provisioning calls fail until `NATS_PROVISIONER_BASE_URL` is set. |
| `JWT_ISSUER` | `clawdstrike-control-api` | Expected `iss` claim for Control API JWT bearer tokens. |
| `JWT_AUDIENCE` | `clawdstrike-control-api` | Expected `aud` claim for Control API JWT bearer tokens. |
| `APPROVAL_SIGNING_ENABLED` | `true` | Signed approval responses are enabled by default. |
| `APPROVAL_SIGNING_KEYPAIR_PATH` | unset | Optional but recommended. If unset or unreadable while signing is enabled, Control API falls back to an ephemeral keypair and logs a warning. |
| `APPROVAL_CONSUMER_ENABLED` | `true` | Ingests agent approval requests from NATS into the Control API database. |
| `APPROVAL_SUBJECT_FILTER` | `tenant-*.>` | Default is dotted-slug-safe while still tenant-scoped; keep strict subject parsing enabled in consumers. |
| `APPROVAL_STREAM_NAME` | `clawdstrike_adaptive_ingress` | Shared ingress stream used by both approval and heartbeat consumers to avoid overlapping-stream conflicts with broad filters. |
| `APPROVAL_RESOLUTION_OUTBOX_ENABLED` | `true` | Retries cloud -> agent resolution delivery until sent. |
| `HEARTBEAT_CONSUMER_ENABLED` | `true` | Reconciles NATS heartbeats into `agents.last_heartbeat_at`. |
| `HEARTBEAT_SUBJECT_FILTER` | `tenant-*.>` | Default is dotted-slug-safe while still tenant-scoped; keep strict subject parsing enabled in consumers. |
| `HEARTBEAT_STREAM_NAME` | `clawdstrike_adaptive_ingress` | Shared with approvals by default; if you split streams, use truly non-overlapping filters. |
| `STALE_DETECTOR_ENABLED` | `true` | Periodic stale/dead lifecycle transitions (120s/300s default thresholds). |
| `AUDIT_CONSUMER_ENABLED` | `false` | Optional; enable when ingesting Spine audit envelopes in this service. |

If you disable any worker in the table above, document the replacement path in your runbook (for example, an external processor or separate service) to avoid silent fleet drift.

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
        run: cargo install hush-cli --locked
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
