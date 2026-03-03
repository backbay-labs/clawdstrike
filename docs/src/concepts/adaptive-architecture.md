# Adaptive Architecture

Clawdstrike's Adaptive Architecture enables security enforcement agents to operate across a spectrum of deployment scenarios -- from a single developer laptop with no network dependency, to a fully managed enterprise fleet with centralized policy management, real-time telemetry, and remote control. The architecture adapts automatically to network conditions, promoting agents to enterprise-managed mode when connectivity is available and gracefully degrading to local enforcement when it is not.

At its core, the Adaptive Architecture solves a fundamental tension in agent security: organizations need centralized visibility and control, but individual agents must remain functional (and secure) even when disconnected. Rather than choosing between local-only and cloud-only enforcement, the Adaptive Architecture provides both simultaneously, with well-defined rules for how agents transition between modes.

The system is designed around a **fail-closed** principle. Every error path -- connectivity loss, invalid credentials, corrupt policies, evaluation failures -- results in a deny decision. An agent that cannot reach the enterprise does not become permissive; it continues enforcing its last known policy locally while queuing audit records for later submission.

## Deployment Modes

The Adaptive Architecture defines three deployment modes. Each mode represents a different balance of autonomy, connectivity, and enterprise control.

| Mode | Local Agent | Enterprise Connection | Use Case |
|------|-------------|----------------------|----------|
| **Standalone** | Yes | No | Individual developers, air-gapped environments |
| **Connected** | Yes | Yes | Enterprise teams with centralized management |
| **Headless** | No | Yes (required) | CI/CD pipelines, serverless, managed compute |

### Standalone Mode

The agent operates entirely on the developer's machine with no network dependency. Policy evaluation uses local YAML policy files and the local `hush` CLI engine. Decisions are logged locally but not sent to any central system.

Standalone mode is the default starting point. It requires no enterprise infrastructure and works in air-gapped environments. The tradeoff is that there is no centralized policy management, no fleet-wide audit trail, and no remote control.

### Connected Mode

The agent maintains a connection to enterprise infrastructure while preserving full local evaluation capability as a fallback. In this mode:

- **Policy sync:** The enterprise pushes policy updates to the agent in real time via NATS KV. The agent validates and caches each update locally.
- **Telemetry:** Every security decision is packaged as a cryptographically signed envelope and published to the enterprise audit stream.
- **Heartbeat:** The agent sends periodic status reports (every 30 seconds) so the enterprise can track fleet health.
- **Remote control:** Administrators can issue posture commands -- including an emergency kill switch -- to any connected agent.
- **Approval escalation:** Denied actions can be escalated to a SOC analyst for centralized decision-making.

If connectivity to the enterprise is lost, the agent automatically degrades to local enforcement using its cached policy. Decisions made while offline are queued and submitted when connectivity is restored (store-and-forward). The agent continuously probes the enterprise and re-promotes to full connected operation as soon as the connection recovers.

### Headless Mode

No local agent process runs. The agent runtime (in a CI runner, Lambda function, or Kubernetes pod) calls the enterprise `hushd` service directly over HTTPS. There is no local fallback -- if the enterprise is unreachable, all actions are denied.

Headless mode is designed for ephemeral compute environments where installing a persistent agent is impractical. Authentication uses API keys or short-lived tokens rather than the enrollment flow used by connected agents.

## Which Mode Is Right for My Organization?

Use the following decision flow to choose a deployment mode:

1. **Is this for CI/CD, serverless, or managed compute (no persistent local agent)?**
   - Yes -> **Headless Mode**
   - No -> continue

2. **Do you need centralized policy management, fleet visibility, or remote control?**
   - Yes -> **Connected Mode**
   - No -> continue

3. **Is the environment air-gapped or does the team prefer full local autonomy?**
   - Yes -> **Standalone Mode**
   - Otherwise -> **Connected Mode** (recommended for most teams)

> **Tip:** You can start with Standalone mode and promote agents to Connected mode later via the enrollment process. No agent reinstallation is required. See the [Adaptive Deployment Guide](../guides/adaptive-deployment.md) for details.

## Key Security Properties

### Fail-Closed Everywhere

Every error path in the Adaptive Architecture results in a deny decision. This applies across all modes:

| Failure | Behavior |
|---------|----------|
| Enterprise unreachable (connected mode) | Degrade to local engine; continue enforcing cached policy |
| Local engine error | Deny the action |
| Invalid or corrupt policy update | Reject the update; keep the last known good policy |
| Enrollment token expired or invalid | Reject enrollment |
| Approval request times out | Deny the action |
| Receipt queue overflow | Evict oldest entries; log alert |

### Dual Attestation

In connected mode, security decisions can be attested by both the local and enterprise engines. Every decision is packaged as a Spine signed envelope -- a cryptographically signed record containing the decision, the policy that produced it, and the context in which it was made. Envelopes are chained via hash linking, providing tamper-evident ordering.

### Store-and-Forward Audit

When an agent operates in degraded mode (enterprise temporarily unreachable), decisions are still made locally and queued as signed envelopes. When connectivity is restored, the queue is drained and all offline decisions are submitted to the enterprise audit stream. This ensures a complete audit trail even during network outages.

## Trust Model

The architecture defines two trust zones separated by authenticated transport:

- **Agent Trust Zone:** The agent process, local policy cache, local evaluation engine, offline receipt queue, and the agent's Ed25519 keypair. This zone is controlled by the machine owner.
- **Enterprise Trust Zone:** The enterprise hushd service, Control API, Spine services, NATS infrastructure, and the enterprise's Ed25519 keypair. This zone is controlled by the organization's security team.

Communication between zones is authenticated via NATS credentials (issued during enrollment) and hushd API keys. Tenant isolation is enforced at the NATS account level -- each tenant's agents operate in a dedicated NATS account with strict subject-level access controls. Control API delegates account/user/ACL lifecycle to an external NATS provisioner service (`NATS_PROVISIONING_MODE=external`); when the provisioner endpoint is missing, Control API can still start, but tenant/agent provisioning operations fail until it is configured. Agents cannot publish posture commands or forge approval responses; only enterprise services have those permissions.

## Relationship to Existing Components

The Adaptive Architecture builds on existing Clawdstrike components rather than replacing them:

| Component | Role in Adaptive Architecture |
|-----------|-------------------------------|
| `hush-cli-engine` | Local evaluation engine (standalone and degraded fallback) |
| `hushd-engine` | Remote evaluation engine (connected and headless) |
| `engine-adaptive` (new) | Wraps local and remote engines; manages mode transitions |
| Desktop Agent | Local API server; hosts NATS client for policy sync, telemetry, heartbeat |
| Spine | Signed envelope format for tamper-evident audit records |
| Control API | Enterprise-side fleet management, enrollment, and control console |
| Framework adapters | Unchanged; work with any engine via the `PolicyEngineLike` interface |

All existing framework adapters (OpenClaw, Vercel AI, LangChain, Claude, OpenAI, OpenCode) continue to work without modification. The adaptive engine implements the same `PolicyEngineLike` interface, so switching from a local-only to an adaptive deployment requires only a configuration change, not a code change.

## Further Reading

- [Adaptive Deployment Guide](../guides/adaptive-deployment.md) -- Step-by-step configuration for all three modes
- [Enterprise Enrollment Guide](../guides/enterprise-enrollment.md) -- How to enroll agents into enterprise management
- [Desktop Agent Deployment](../guides/desktop-agent.md) -- Base desktop agent setup
- [Architecture](architecture.md) -- Core Clawdstrike architecture and guard pipeline
- Spec 15 (Adaptive SDR Architecture) -- Full technical specification
