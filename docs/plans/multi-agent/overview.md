# Multi-Agent Coordination in Clawdstrike

## Executive Summary

As AI systems evolve from single-agent architectures to multi-agent orchestrations, security boundaries become exponentially more complex. This specification defines the security primitives, protocols, and enforcement mechanisms required to enable secure multi-agent coordination within the Clawdstrike security framework.

Multi-agent systems introduce novel threat vectors that single-agent security models cannot address:

- **Confused Deputy Attacks**: Agent A tricks Agent B into performing actions A cannot perform directly
- **Privilege Escalation via Delegation**: Chained delegations accumulate permissions beyond original intent
- **Identity Spoofing**: Malicious agents impersonate trusted agents
- **Cross-Agent Data Exfiltration**: Sensitive data flows between agents without audit
- **Coordination Protocol Manipulation**: Adversarial manipulation of agent-to-agent messages

This specification provides six interconnected components:

| Component | Purpose | Document |
|-----------|---------|----------|
| Cross-Agent Policy | Prevent unauthorized resource access across agent boundaries | `cross-agent-policy.md` |
| Delegation Tokens | Enable scoped, time-limited permission grants | `delegation-tokens.md` |
| Identity Attestation | Cryptographic proof of agent identity and actions | `identity-attestation.md` |
| Isolation Boundaries | Enforce separation between agent execution contexts | `isolation-boundaries.md` |
| Coordination Protocols | Secure message passing and task handoff | `coordination-protocols.md` |
| Audit Correlation | Unified audit trail across agent boundaries | `audit-correlation.md` |

## Design Principles

### 1. Zero Trust Between Agents

No agent is inherently trusted. Every inter-agent interaction requires:
- Cryptographic identity verification
- Explicit capability grants
- Policy evaluation at both sender and receiver
- Auditable evidence chain

### 2. Principle of Least Privilege

Agents receive only the minimum capabilities required for their task:
- Capabilities are scoped to specific resources
- Time-bounded by default
- Cannot be escalated without explicit re-grant
- Automatically revoked on task completion

### 3. Defense in Depth

Multiple independent security layers:
- Policy enforcement at agent boundary
- Cryptographic verification of all grants
- Runtime isolation at process/container level
- Audit trail for forensic analysis

### 4. Fail-Closed Semantics

When security state is ambiguous:
- Deny by default
- Log the denial with full context
- Alert operators on anomalous patterns
- Preserve evidence for investigation

## System Architecture

```
+------------------------------------------------------------------+
|                        Orchestration Layer                        |
|  +--------------------+  +--------------------+  +---------------+|
|  | Agent A            |  | Agent B            |  | Agent C       ||
|  | (Research)         |  | (Code Generation)  |  | (Deployment)  ||
|  +--------+-----------+  +--------+-----------+  +-------+-------+|
|           |                       |                      |        |
+-----------+-----------------------+----------------------+--------+
            |                       |                      |
            v                       v                      v
+------------------------------------------------------------------+
|                    Clawdstrike Security Layer                     |
|  +----------------+  +------------------+  +--------------------+ |
|  | Identity       |  | Delegation       |  | Policy             | |
|  | Attestation    |  | Token Service    |  | Enforcement        | |
|  +-------+--------+  +--------+---------+  +----------+---------+ |
|          |                    |                       |           |
|          v                    v                       v           |
|  +----------------+  +------------------+  +--------------------+ |
|  | Audit          |  | Isolation        |  | Coordination       | |
|  | Correlator     |  | Boundary         |  | Protocol           | |
|  +----------------+  +------------------+  +--------------------+ |
+------------------------------------------------------------------+
            |                       |                      |
            v                       v                      v
+------------------------------------------------------------------+
|                      Resource Layer                               |
|  [Filesystem]    [Network]    [Secrets]    [External APIs]       |
+------------------------------------------------------------------+
```

## Threat Model

### Adversary Capabilities

We assume adversaries can:

1. **Compromise Individual Agents**: Via prompt injection, jailbreaks, or supply chain attacks
2. **Observe Inter-Agent Communication**: Network-level observation (but not modification without detection)
3. **Inject Malicious Payloads**: Through untrusted external data sources
4. **Attempt Social Engineering**: Trick agents into granting excessive permissions

### Assets Under Protection

1. **Filesystem Resources**: Source code, configuration, credentials
2. **Network Access**: API endpoints, internal services, egress
3. **Execution Capabilities**: Shell commands, subprocess spawning
4. **Secrets**: API keys, tokens, certificates
5. **Audit Integrity**: Tamper-evident logs of all actions

### Trust Boundaries

```
+---------------------------------------------------------------+
|                    Trust Boundary 1: Orchestrator             |
|  The orchestrator is trusted to:                              |
|  - Instantiate agents with correct policies                   |
|  - Not modify agent code after attestation                    |
|  - Route messages faithfully (integrity, not confidentiality) |
+---------------------------------------------------------------+
        |
        v
+---------------------------------------------------------------+
|                    Trust Boundary 2: Per-Agent                |
|  Each agent is trusted to:                                    |
|  - Execute its declared purpose                               |
|  - NOT trusted to: self-limit, protect other agents' data,    |
|    or correctly implement security checks                     |
+---------------------------------------------------------------+
        |
        v
+---------------------------------------------------------------+
|                    Trust Boundary 3: Clawdstrike              |
|  The security layer is trusted to:                            |
|  - Correctly enforce all policies                             |
|  - Maintain cryptographic key material securely               |
|  - Preserve audit log integrity                               |
+---------------------------------------------------------------+
```

## Implementation Roadmap

### Phase 1: Foundation (Q1 2026)

- Agent identity registration and attestation
- Basic cross-agent policy enforcement
- Audit event correlation by trace ID

**Deliverables:**
- `AgentIdentity` type and registration API
- `CrossAgentGuard` implementation
- Trace ID propagation in audit events

### Phase 2: Delegation (Q2 2026)

- Delegation token format and signing
- Token verification and revocation
- Scoped capability grants

**Deliverables:**
- `DelegationToken` type and COSE signing
- Token verification middleware
- Capability attenuation logic

### Phase 3: Isolation (Q3 2026)

- Process-level isolation boundaries
- Namespace separation for filesystem
- Network policy per agent

**Deliverables:**
- Container/sandbox integration
- Per-agent network policies
- Resource quota enforcement

### Phase 4: Coordination (Q4 2026)

- Secure coordination protocol
- Encrypted message channels
- Distributed consensus for critical operations

**Deliverables:**
- Agent-to-agent message format
- TLS mutual auth for channels
- Multi-party approval workflows

## API Overview

### TypeScript SDK

```typescript
import {
  MultiAgentOrchestrator,
  AgentIdentity,
  DelegationToken,
  CoordinationChannel,
  CrossAgentPolicy
} from '@clawdstrike/multi-agent';

// Create orchestrator with multi-agent policy
const orchestrator = new MultiAgentOrchestrator({
  policy: CrossAgentPolicy.fromYaml('./multi-agent-policy.yaml'),
  attestationProvider: 'local-hsm',
  auditSink: 'https://audit.internal/v1/events'
});

// Register agents with attested identities
const researchAgent = await orchestrator.registerAgent({
  name: 'research-agent',
  capabilities: ['file:read', 'network:egress:*.github.com'],
  attestation: await AgentIdentity.attest('research-agent', keypair)
});

const codeAgent = await orchestrator.registerAgent({
  name: 'code-agent',
  capabilities: ['file:read', 'file:write:/workspace/**'],
  attestation: await AgentIdentity.attest('code-agent', keypair)
});

// Create delegation from research to code agent
const delegation = await researchAgent.delegate({
  to: codeAgent.id,
  capabilities: ['file:read:/workspace/research/**'],
  ttl: '1h',
  purpose: 'Access research notes for code generation'
});

// Open secure coordination channel
const channel = await orchestrator.openChannel(researchAgent, codeAgent, {
  encryption: 'aes-256-gcm',
  authentication: 'mutual-tls'
});

// Send task with audit correlation
await channel.send({
  type: 'task',
  payload: { action: 'generate-code', context: '...' },
  traceId: 'trace-abc123',
  delegationToken: delegation.token
});
```

### Rust SDK

```rust
use clawdstrike::multi_agent::{
    Orchestrator, AgentIdentity, DelegationToken,
    CoordinationChannel, CrossAgentPolicy
};

// Create orchestrator
let policy = CrossAgentPolicy::from_yaml("./multi-agent-policy.yaml")?;
let orchestrator = Orchestrator::new(policy)
    .with_attestation_provider(LocalHsm::new()?)
    .with_audit_sink("https://audit.internal/v1/events")?;

// Register agents
let research_agent = orchestrator.register_agent(AgentConfig {
    name: "research-agent".into(),
    capabilities: vec![
        Capability::FileRead,
        Capability::NetworkEgress("*.github.com".into()),
    ],
    attestation: AgentIdentity::attest("research-agent", &keypair).await?,
}).await?;

let code_agent = orchestrator.register_agent(AgentConfig {
    name: "code-agent".into(),
    capabilities: vec![
        Capability::FileRead,
        Capability::FileWrite("/workspace/**".into()),
    ],
    attestation: AgentIdentity::attest("code-agent", &keypair).await?,
}).await?;

// Create scoped delegation
let delegation = research_agent.delegate(DelegationRequest {
    to: code_agent.id(),
    capabilities: vec![Capability::FileRead("/workspace/research/**".into())],
    ttl: Duration::from_secs(3600),
    purpose: "Access research notes for code generation".into(),
}).await?;

// Open secure channel
let channel = orchestrator.open_channel(&research_agent, &code_agent, ChannelConfig {
    encryption: Encryption::Aes256Gcm,
    authentication: Authentication::MutualTls,
}).await?;

// Send coordinated task
channel.send(Message {
    msg_type: MessageType::Task,
    payload: serde_json::json!({ "action": "generate-code" }),
    trace_id: "trace-abc123".into(),
    delegation_token: Some(delegation.token.clone()),
}).await?;
```

## Configuration Schema

```yaml
# multi-agent-policy.yaml
version: "1.0.0"
name: "Multi-Agent Development Policy"

# Agent definitions
agents:
  research-agent:
    capabilities:
      - file:read
      - network:egress:*.github.com
      - network:egress:api.arxiv.org
    isolation:
      level: process
      network: restricted

  code-agent:
    capabilities:
      - file:read
      - file:write:/workspace/**
    isolation:
      level: container
      network: deny-all

  deploy-agent:
    capabilities:
      - file:read:/workspace/dist/**
      - network:egress:registry.internal
      - exec:kubectl
    isolation:
      level: container
      network: restricted

# Cross-agent rules
cross_agent:
  # Default: agents cannot access each other's resources
  default_action: deny

  rules:
    # Research can share read-only data with code agent
    - from: research-agent
      to: code-agent
      allow:
        - file:read:/workspace/research/**
      require_delegation: true
      max_delegation_ttl: 1h

    # Code agent can share build artifacts with deploy agent
    - from: code-agent
      to: deploy-agent
      allow:
        - file:read:/workspace/dist/**
      require_delegation: true
      require_approval:
        - human-operator

# Audit settings
audit:
  correlation:
    enabled: true
    propagate_trace_id: true

  events:
    - agent_registered
    - delegation_created
    - delegation_used
    - delegation_revoked
    - cross_agent_access
    - channel_opened
    - channel_closed
    - policy_violation
```

## Security Considerations

### Cryptographic Agility

All cryptographic operations support algorithm negotiation to enable future upgrades:

| Operation | Default Algorithm | Alternatives |
|-----------|------------------|--------------|
| Identity Signing | Ed25519 | ECDSA P-384, RSA-4096 |
| Token Signing | COSE Sign1 (EdDSA) | COSE Sign1 (ES384) |
| Channel Encryption | AES-256-GCM | ChaCha20-Poly1305 |
| Key Exchange | X25519 | ECDH P-384 |
| Hashing | SHA-256 | SHA-384, BLAKE3 |

### Side Channel Resistance

- Constant-time comparison for all cryptographic operations
- No timing-based branching on secret data
- Memory zeroing after cryptographic operations

### Audit Log Integrity

- Hash-chained audit entries (Merkle tree)
- Signed checkpoints every N entries
- Tamper-evident storage with append-only semantics

## Compatibility

### Minimum Versions

- Clawdstrike Core: 0.1.0
- OpenClaw Runtime: 0.1.0
- Node.js: 20.x LTS
- Rust: 1.75.0

### Protocol Versioning

Multi-agent protocols include version negotiation:

```
MAGIC (4 bytes) | VERSION (2 bytes) | FLAGS (2 bytes) | PAYLOAD
```

Version mismatches result in explicit errors, not silent degradation.

## References

- [NIST SP 800-204C: Attribute-Based Access Control](https://csrc.nist.gov/publications/detail/sp/800-204c/final)
- [RFC 8152: CBOR Object Signing and Encryption (COSE)](https://datatracker.ietf.org/doc/html/rfc8152) (Obsoleted by RFC 9052)
- [RFC 9052: COSE Signatures](https://datatracker.ietf.org/doc/html/rfc9052) (Current COSE standard)
- [RFC 9053: COSE Algorithms](https://datatracker.ietf.org/doc/html/rfc9053)
- [SLSA: Supply-chain Levels for Software Artifacts](https://slsa.dev/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/) (Trace propagation standard)
