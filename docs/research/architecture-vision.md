# ClawdStrike Architecture Vision: Kernel-Attested Zero Trust SDR for AI Agent Swarms

> Comprehensive architecture document synthesizing Tetragon runtime enforcement,
> Cilium network security, AegisNet cryptographic attestation, and marketplace
> trust decentralization into a unified security stack for AI agent workloads.
>
> **Status:** Vision | **Date:** 2026-02-07
> **Audience:** Engineering leadership, security architecture, product strategy

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Full Stack Vision](#2-the-full-stack-vision)
   - [2.4 Multi-Plane Transport Architecture](#24-multi-plane-transport-architecture)
3. [Data Flow Architecture](#3-data-flow-architecture)
4. [Novel Capabilities](#4-novel-capabilities)
   - [4.6 Marketplace-to-Spine Unification](#46-marketplace-to-spine-unification)
5. [Product Positioning](#5-product-positioning)
6. [Implementation Roadmap](#6-implementation-roadmap)
   - [6.7 Phase 6: Reticulum Transport and Spine Unification](#67-phase-6-reticulum-transport-and-spine-unification)
7. [Open Questions and Decision Points](#7-open-questions-and-decision-points)
8. [Risks and Mitigations](#8-risks-and-mitigations)
9. [Conclusion](#9-conclusion)

---

## 1. Executive Summary

The AI agent security market is projected to be part of a $52 billion AI agent economy by 2030 (CAGR 46.3%), yet 63% of organizations deploying agents today have no limits on what those agents are authorized to do. The gap between agentic AI deployment velocity and security controls represents one of the largest unaddressed risks in enterprise software.

ClawdStrike occupies a unique position to close this gap. Rather than bolting security onto agents after the fact, the architecture described in this document builds a **six-layer security stack** that provides cryptographically verifiable proof of what AI agents actually did at runtime -- from the Linux kernel syscall through network transit to the application-level tool boundary -- all backed by an append-only transparency log with independent witnesses, distributable even over offline mesh networks.

**The stack:**

| Layer | Technology | Function |
|-------|-----------|----------|
| **L0: Identity** | SPIRE/SPIFFE | Workload identity, mTLS, trust domains |
| **L1: Network** | Cilium + Hubble | eBPF network policy, L7 observability, WireGuard encryption |
| **L2: Kernel Runtime** | Tetragon | eBPF syscall monitoring, file integrity, process enforcement |
| **L3: Attestation** | AegisNet / Aegis Spine | Merkle tree transparency log, witness co-signatures, RFC 6962 proofs |
| **L4: Agent SDR** | ClawdStrike | Guards, policy engine, receipts, desktop visualization, marketplace |
| **L5: Offline Transport** | Reticulum (Plane A-R) | Low-bandwidth mesh distribution of signed envelopes over LoRa, packet radio, serial, WiFi |

**NATS JetStream** connects L0-L4 as the primary event bus. **Reticulum** (L5) extends distribution to offline, disconnected, and constrained environments via Plane A-R, carrying the same signed Spine envelopes over heterogeneous carriers down to ~5 bps.

No existing product combines kernel-level runtime enforcement with cryptographic attestation and AI-agent-aware policy. CrowdStrike Falcon has kernel visibility but no agent-specific guards. Wiz has cloud posture but no runtime enforcement. Aqua and Sysdig have container runtime security but no attestation chain. None of them have a marketplace for community-curated security policies with decentralized trust.

This document synthesizes three research tracks into a unified architecture vision with a phased implementation plan.

---

## 2. The Full Stack Vision

### 2.1 Layer Architecture

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                        ClawdStrike Desktop (L4)                             │
 │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
 │  │  Threat   │ │  Attack  │ │  Network │ │  Event   │ │   Marketplace    │ │
 │  │  Radar    │ │  Graph   │ │  Map     │ │  Stream  │ │  (Policy Store)  │ │
 │  └─────┬────┘ └─────┬────┘ └─────┬────┘ └─────┬────┘ └───────┬──────────┘ │
 │        │            │            │             │              │            │
 │  ┌─────▼────────────▼────────────▼─────────────▼──────────────▼──────────┐ │
 │  │  HushEngine: Guards (7 built-in + async) + Policy Engine + Receipts  │ │
 │  │  ForbiddenPath | EgressAllowlist | SecretLeak | PatchIntegrity       │ │
 │  │  McpTool | PromptInjection | Jailbreak (4-layer)                     │ │
 │  └─────────────────────────────┬────────────────────────────────────────┘ │
 │                                │ SSE + Tauri IPC                         │
 │  ┌─────────────────────────────▼────────────────────────────────────────┐ │
 │  │  hushd (Daemon): HTTP enforcement, audit log, receipt signing        │ │
 │  └─────────────────────────────┬────────────────────────────────────────┘ │
 └────────────────────────────────┼─────────────────────────────────────────┘
                                  │ NATS JetStream
 ┌────────────────────────────────▼─────────────────────────────────────────┐
 │                          AegisNet (L3)                                    │
 │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
 │  │ Checkpointer │  │   Witness    │  │  Proofs API  │                   │
 │  │ Merkle trees │  │  Co-signs    │  │  RFC 6962    │                   │
 │  │ Checkpoints  │  │  Independent │  │  Inclusion   │                   │
 │  └──────┬───────┘  └──────────────┘  └──────────────┘                   │
 │         │                                                                │
 │  ┌──────▼───────────────────────────────────────────────────────────────┐│
 │  │  NATS JetStream: AEGISNET_LOG (3 replicas, 50Gi/node)               ││
 │  │  Subjects: aegis.spine.envelope.{tetragon,hubble,clawdstrike}.>     ││
 │  └──────────────────────────────────────────────────────────────────────┘│
 └──────────────────────────────────────────────────────────────────────────┘
                                  │
 ┌────────────────────────────────▼─────────────────────────────────────────┐
 │                          Tetragon (L2)                                    │
 │  ┌──────────────────┐  ┌────────────────────────────────┐               │
 │  │ Tetragon Agent   │  │  tetragon-nats-bridge          │               │
 │  │ (DaemonSet)      │  │  gRPC → SignedEnvelope → NATS  │               │
 │  │ kprobes, LSM,    │──│  Ed25519 signing per node      │               │
 │  │ tracepoints      │  │  Process/file/network events   │               │
 │  └──────────────────┘  └────────────────────────────────┘               │
 │  TracingPolicies (CRDs): exec-allowlist, FIM, egress, escape detection  │
 └──────────────────────────────────────────────────────────────────────────┘
                                  │
 ┌────────────────────────────────▼─────────────────────────────────────────┐
 │                          Cilium (L1)                                      │
 │  ┌──────────────────┐  ┌──────────────┐  ┌─────────────────────────────┐│
 │  │ eBPF Datapath    │  │ Hubble       │  │ CiliumNetworkPolicy         ││
 │  │ L3/L4/L7 policy  │  │ Flow logs    │  │ Identity-based (not IP)     ││
 │  │ kube-proxy repl  │  │ L7 HTTP/gRPC │  │ L7 method+path filtering    ││
 │  │ WireGuard enc    │  │ DNS, Kafka   │  │ FQDN-based egress           ││
 │  └──────────────────┘  └──────────────┘  │ Mutual auth + SPIRE         ││
 │                                           └─────────────────────────────┘│
 └──────────────────────────────────────────────────────────────────────────┘
                                  │
 ┌────────────────────────────────▼─────────────────────────────────────────┐
 │                          SPIRE (L0)                                       │
 │  ┌──────────────────┐  ┌──────────────┐  ┌─────────────────────────────┐│
 │  │ SPIRE Server     │  │ SPIRE Agent  │  │ SPIFFE CSI Driver           ││
 │  │ trustDomain:     │  │ (DaemonSet)  │  │ Mount SVIDs into pods       ││
 │  │ aegis.local      │  │ Node + K8s   │  │ Auto rotation               ││
 │  │ X.509 SVIDs      │  │ attestation  │  │                             ││
 │  └──────────────────┘  └──────────────┘  └─────────────────────────────┘│
 └──────────────────────────────────────────────────────────────────────────┘
                                 │
 ┌───────────────────────────────▼─────────────────────────────────────────┐
 │                     Reticulum / Plane A-R (L5)                          │
 │  ┌──────────────────┐  ┌──────────────┐  ┌─────────────────────────────┐│
 │  │ Reticulum Adapter│  │ Translation  │  │ Off-Grid Distribution       ││
 │  │ (Python sidecar) │  │ Gateway      │  │ LoRa / packet radio /       ││
 │  │ Envelope TX/RX   │  │ A-R ⇄ Plane B│  │ serial / WiFi / TCP/UDP    ││
 │  │ Head announces   │  │ (NATS bridge)│  │ Down to ~5 bps             ││
 │  │ Sync req/resp    │  │ Verify+fwd   │  │ Store-and-forward (LXMF)   ││
 │  └──────────────────┘  └──────────────┘  └─────────────────────────────┘│
 │  Carries: revocations, checkpoints, incident summaries, receipt ptrs    │
 └──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 What Already Exists (Deployed on EKS)

From the current ArgoCD application manifests in `platform/infra/gitops/`:

| Component | Status | Namespace | ArgoCD App |
|-----------|--------|-----------|------------|
| SPIRE 0.13.0 | **Deployed** | `spire-system` | `spire` |
| NATS JetStream (3-replica cluster) | **Deployed** | `aegisnet` | `aegisnet-nats` |
| AegisNet Checkpointer | **Deployed** | `aegisnet` | `aegisnet-checkpointer` |
| AegisNet Witness | **Deployed** | `aegisnet` | `aegisnet-witness` |
| AegisNet Proofs API | **Deployed** | `aegisnet` | `aegisnet-proofs-api` |
| AegisNet Observability | **Deployed** | `aegisnet` | `aegisnet-observability` |
| kube-prometheus-stack | **Deployed** | `monitoring` | `monitoring` |
| Envoy Gateway | **Deployed** | (gateway) | `envoy-gateway` |
| Karpenter | **Deployed** | (karpenter) | `karpenter` |
| aws-load-balancer-controller | **Deployed** | `kube-system` | `aws-load-balancer-controller` |
| Cilium | **Not deployed** | -- | -- |
| Tetragon | **Not deployed** | -- | -- |
| tetragon-nats-bridge | **Not deployed** | -- | -- |
| Reticulum Adapter (Plane A-R) | **Not deployed** | -- | -- |
| Reticulum-NATS Gateway | **Not deployed** | -- | -- |

The identity layer (SPIRE) and attestation layer (AegisNet) are already operational. The remaining work is deploying Cilium + Tetragon and wiring everything together.

### 2.3 Why Six Layers

Each layer addresses a fundamentally different attack surface:

| Attack Surface | Without This Stack | With This Stack |
|---|---|---|
| **Agent impersonation** | No workload identity | SPIRE SVID proves workload identity via node+k8s attestation |
| **Network lateral movement** | Flat network, IP-based rules | Cilium identity-based L3-L7 policy, WireGuard encryption |
| **Kernel-level tampering** | No runtime visibility | Tetragon eBPF hooks observe every syscall, enforce at kernel |
| **Evidence tampering** | Mutable logs | AegisNet RFC 6962 Merkle tree, witness co-signatures |
| **Agent tool abuse** | No tool boundary control | ClawdStrike guards at MCP/file/network/prompt boundary |
| **Policy supply chain** | Trust single vendor | Marketplace with multi-curator attestation, IPFS, P2P |
| **Disconnected / offline ops** | No policy distribution without internet | Reticulum carries signed revocations, checkpoints, and policy deltas over LoRa/radio/serial at ~5 bps |

The key insight is that **no single layer is sufficient**. An attacker who compromises the application layer (bypassing ClawdStrike guards) is still caught by Tetragon's kernel-level enforcement. An attacker who manipulates eBPF programs is still detected by Hubble's independent observation path. An attacker who tampers with logs is caught by AegisNet's cryptographic proofs. An environment that loses internet connectivity still receives revocations and policy updates via Reticulum's offline mesh. Defense in depth is not optional -- it is the architecture.

### 2.4 Multi-Plane Transport Architecture

The Aegis Spine protocol defines a **multi-plane transport model** where the same signed envelopes can traverse different network planes depending on environment constraints. All planes carry identical Layer 4 objects (envelopes, facts, heads); only membership, routing, and transport differ.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        Aegis Spine Layer 4                                │
│        SignedEnvelope + Facts + Heads + Sync + Checkpoint Proofs          │
│     (identical format regardless of transport plane)                      │
└──────────┬──────────────────┬──────────────────┬─────────────────────────┘
           │                  │                  │
    ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐   ┌──────────────┐
    │  Plane A-L  │   │  Plane A-R  │   │   Plane B   │   │   Plane C    │
    │  (libp2p)   │   │ (Reticulum) │   │   (NATS)    │   │ (WireGuard)  │
    │  Public     │   │  Off-grid   │   │  Regional   │   │  Private     │
    │  internet   │   │  low-bw     │   │  high-tput  │   │  enclave     │
    │  mesh       │   │  mesh       │   │  backbone   │   │  overlay     │
    └─────────────┘   └─────────────┘   └─────────────┘   └──────────────┘
```

**Plane A-L (libp2p):** Internet-friendly public gossip mesh for envelope propagation across clusters.

**Plane A-R (Reticulum):** Offline-capable mesh over heterogeneous carriers (LoRa, packet radio, serial, WiFi, TCP/UDP). Optimized for small signed commitments: revocations, checkpoints, incident summaries, receipt pointers. Supports store-and-forward delivery (LXMF semantics) down to ~5 bps. Priority scheduling ensures revocations propagate first. See the [Reticulum transport profile spec](../../../../platform/docs/specs/cyntra-aegis-spine-reticulum.md) for full details.

**Plane B (NATS JetStream):** Regional high-throughput backbone for real-time event streaming within a cluster. Primary transport for Tetragon, Hubble, and ClawdStrike events.

**Plane C (WireGuard):** Private enclave overlay for institution-to-institution or operator-to-operator communication.

Translation gateways bridge between planes (e.g., Reticulum <-> NATS), verifying envelope signatures before forwarding and enforcing disclosure policy, rate limits, and audit logging.

---

## 3. Data Flow Architecture

### 3.1 Primary Event Flows

The system generates four categories of security events, each following a path from origin through attestation to visualization.

#### Flow 1: Kernel Runtime Event (Tetragon -> AegisNet -> ClawdStrike)

```
 Linux Kernel
    │ eBPF hook fires (kprobe/LSM/tracepoint)
    │ In-kernel filtering: only matching events pass
    ▼
 Tetragon Agent (DaemonSet, per node)
    │ K8s enrichment: pod name, namespace, labels, container image
    │ Process ancestry: parent_exec_id chain
    ▼ gRPC GetEvents stream (localhost:54321)
 tetragon-nats-bridge (sidecar container)
    │ Transform to AegisNet SignedEnvelope
    │ Sign with node-specific Ed25519 keypair
    │ Dedup key: sha256(exec_id + time + function_name)
    ├──► NATS: aegis.spine.envelope.tetragon.process_exec.v1
    ├──► NATS: aegis.spine.envelope.tetragon.process_kprobe.v1
    └──► NATS: aegis.spine.envelope.tetragon.enforcement.v1
         │
         ▼
 AegisNet Checkpointer
    │ Subscribe: aegis.spine.envelope.tetragon.>
    │ Extract envelope_hash, append to AEGISNET_LOG stream
    │ Build RFC 6962 Merkle tree (batched, every 5-10 seconds)
    │ Emit checkpoint statement
    ▼
 AegisNet Witness
    │ Co-sign checkpoint with independent Ed25519 key
    │ Publish witness_signature to NATS
    ▼
 hushd (subscribes to tetragon NATS subjects)
    │ Map Tetragon events to SecurityEvent types
    │ Correlate with active ClawdStrike guard decisions
    │ Broadcast via SSE to connected desktop clients
    ▼
 ClawdStrike Desktop
    ├──► ThreatRadarView: Map severity + pod namespace to 3D radar position
    ├──► AttackGraphView: Correlate process trees to MITRE ATT&CK chains
    └──► EventStreamView: Real-time feed with receipt panel
```

**Estimated end-to-end latency (event to desktop)**:
- Kernel to Tetragon userspace: 1-5ms
- Tetragon to NATS: 10-30ms
- NATS to hushd to SSE: 5-15ms
- **Total to desktop: 16-50ms** (real-time)

**Estimated latency to attestation (event to checkpoint)**:
- All above plus checkpointer batching: 5-10 seconds
- Witness co-sign: 50-200ms
- **Total to checkpoint: 5-15 seconds**

#### Flow 2: Network Flow Event (Hubble -> AegisNet -> ClawdStrike)

```
 Pod-to-pod traffic
    │ eBPF datapath captures L3/L4/L7 flow metadata
    ▼
 Cilium Agent (Hubble ring buffer, per node)
    │ Per-flow data: source/dest identity, namespace, labels, protocol
    │ L7 enrichment: HTTP method/path/status, gRPC service/method, DNS query
    │ Encryption status: WireGuard yes/no
    ▼ Hubble Relay (cluster-wide aggregation, gRPC :4245)
    │
    ├──► Hubble Exporter (file: /var/run/cilium/hubble/events.log)
    │    │
    │    ▼ Fluent Bit DaemonSet
    │    │ Parse JSON, publish to NATS
    │    ▼
    │    NATS: aegisnet.hubble.flows
    │    NATS: aegisnet.hubble.flows.dropped
    │    NATS: aegisnet.hubble.flows.l7
    │
    ├──► Prometheus (:9965)
    │    hubble_flows_processed_total, hubble_drop_total
    │    hubble_http_requests_total, hubble_dns_queries_total
    │
    └──► (Future) hubble-ws-bridge for direct desktop streaming
         │
         ▼
 AegisNet Witness
    │ Receive flows from NATS
    │ Create network attestation envelope
    │ Sign with Ed25519, include:
    │   - Hubble flow UUID
    │   - CiliumNetworkPolicy hash that governed the flow
    │   - Source/destination SPIFFE IDs
    │   - Verdict (FORWARDED/DROPPED/AUDIT)
    ▼
 AegisNet Checkpointer → Merkle tree → Checkpoint → Proofs API
    │
    ▼
 ClawdStrike Desktop
    └──► NetworkMapView: Live topology from Hubble flow aggregation
         Node discovery: unique (namespace, pod_name) pairs
         Edge discovery: unique (src, dst, protocol, port) tuples
         Status inference: >5% DROPPED → suspicious
         Encryption overlay: flow.IP.encrypted → WireGuard status
```

#### Flow 3: ClawdStrike Guard Decision (hushd -> AegisNet)

```
 AI Agent Runtime
    │ Agent requests action: file_access, egress, mcp_tool, shell, patch
    ▼
 ClawdStrike SDK / Adapter
    │ Intercept at tool boundary
    │ Build ActionRequest with context
    ▼
 hushd (HTTP daemon)
    │ Load policy (YAML, schema v1.1.0)
    │ Evaluate all applicable guards:
    │   ForbiddenPathGuard, EgressAllowlistGuard, SecretLeakGuard,
    │   PatchIntegrityGuard, McpToolGuard, PromptInjectionGuard,
    │   JailbreakGuard (4-layer: heuristic + statistical + ML + LLM-judge)
    │ Produce aggregate verdict: ALLOW | DENY | WARN
    │ Sign receipt (Ed25519): decision + policy hash + evidence
    │
    ├──► SSE broadcast to desktop: SecurityEvent with receipt
    ├──► NATS: aegis.spine.envelope.clawdstrike.receipt.v1
    │    (SignedEnvelope wrapping the ClawdStrike receipt)
    │
    ▼
 AegisNet Checkpointer → Merkle tree → Checkpoint
    │
    ▼ (Verifiable proof that guard decision occurred)
 AegisNet Proofs API
    GET /v1/proofs/inclusion?envelope_hash=0x<receipt-hash>
```

#### Flow 4: Cross-Layer Identity Attestation (SPIRE -> Cilium -> Tetragon -> AegisNet)

```
 SPIRE Server (trustDomain: aegis.local)
    │ Issue X.509 SVID to workload
    │ spiffe://aegis.local/ns/<namespace>/sa/<service-account>
    │
    ├──► Cilium Agent
    │    Map SPIFFE ID → Cilium Security Identity
    │    Enforce CiliumNetworkPolicy with authentication.mode: "required"
    │    eBPF datapath triggers mTLS handshake (no sidecar proxy)
    │
    ├──► Tetragon Agent
    │    TracingPolicy selectors filter by workload identity
    │    Runtime proof fact includes:
    │      - Binary hash (IMA)
    │      - Process ancestry
    │      - SPIFFE ID of the workload
    │      - Capabilities and namespaces
    │
    └──► AegisNet
         Full proof chain in a single envelope:
         {
           execution: { binary, binary_hash_ima, pid, exec_id },
           identity:  { spiffe_id, svid_serial, trust_domain },
           kubernetes: { namespace, pod, node, container_image_digest },
           network_enforcement: { tetragon_policy, cilium_policy },
           attestation_chain: {
             tetragon_exec_id,
             spire_svid_hash,
             clawdstrike_receipt_hash,
             aegisnet_envelope_hash
           }
         }
```

### 3.2 NATS Subject Hierarchy (Consolidated)

```
aegis.spine.envelope.>                              # All envelopes (checkpointer subscribes here)
  aegis.spine.envelope.heartbeat.v1                 # System heartbeats
  aegis.spine.envelope.log_checkpoint.v1            # Checkpoint envelopes
  aegis.spine.envelope.tetragon.>                   # All Tetragon events
    aegis.spine.envelope.tetragon.process_exec.v1   # Process execution
    aegis.spine.envelope.tetragon.process_exit.v1   # Process exit
    aegis.spine.envelope.tetragon.process_kprobe.v1 # Kprobe triggers
    aegis.spine.envelope.tetragon.process_lsm.v1    # LSM hook events
    aegis.spine.envelope.tetragon.enforcement.v1    # Enforcement actions
  aegis.spine.envelope.clawdstrike.>                # ClawdStrike events
    aegis.spine.envelope.clawdstrike.receipt.v1     # Guard decision receipts
    aegis.spine.envelope.clawdstrike.policy.v1      # Policy change events
aegisnet.hubble.>                                   # Hubble flow data
  aegisnet.hubble.flows                             # All flows
  aegisnet.hubble.flows.dropped                     # Dropped packets
  aegisnet.hubble.flows.l7                          # L7-enriched flows
aegisnet.attestations.>                             # Signed attestations
  aegisnet.attestations.network                     # Network attestations
  aegisnet.attestations.runtime                     # Runtime proof attestations
aegis.spine.witness.sign.v1                         # Witness signing RPC
aegis.spine.log.leaf.v1                             # Log leaf appends
```

### 3.3 JetStream Resources

| Resource | Type | Replicas | Subjects | Purpose |
|----------|------|----------|----------|---------|
| `AEGISNET_LOG` | Stream | 3 | `aegis.spine.log.leaf.v1`, `aegis.spine.envelope.tetragon.>`, `aegis.spine.envelope.clawdstrike.>` | Primary append-only log |
| `AEGISNET_LOG_INDEX` | KV Bucket | 3 | -- | envelope_hash -> log_seq mapping (dedup) |
| `AEGISNET_CHECKPOINTS` | KV Bucket | 3 | -- | Checkpoint storage (latest + by seq) |
| `AEGISNET_HUBBLE_RAW` | Stream | 1 | `aegisnet.hubble.>` | Raw Hubble flows (debug/replay) |
| `AEGISNET_TETRAGON_RAW` | Stream | 1 | `aegis.spine.envelope.tetragon.>` | Raw Tetragon events (debug) |

---

## 4. Novel Capabilities

This architecture enables capabilities that no existing product provides. Each capability is novel because it requires the interplay of multiple layers.

### 4.1 Kernel-Level Execution Proofs

**What it is:** Prove not just what container image was deployed, but what binary actually executed, with what arguments, in what process context, at kernel granularity -- backed by a cryptographic proof chain.

**How it works:**

```
Tetragon process_exec event
  ├── binary: /usr/bin/aegisnet-checkpointer
  ├── binary_hash_ima: sha256:abc123...      ← Kernel IMA subsystem
  ├── arguments: --checkpoint-every 10
  ├── uid: 0, pid: 95921
  ├── capabilities: 0x00000000a80425fb
  └── namespaces: { mnt: 4026532256, pid: 4026532259 }
          │
          ▼ Wrapped in SignedEnvelope → AegisNet log → Merkle tree
          │
          ▼ RFC 6962 inclusion proof
          │
          ▼ Witness co-signature
          │
  Verifiable statement: "Binary X with hash Y ran with args Z at time T,
  and this fact is included in a Merkle tree signed by operator + witness."
```

**Why it matters:** Sigstore/Cosign proves what was *deployed*. This proves what was *executed*. The gap between deploy-time and run-time is where most runtime attacks live (process injection, library substitution, argument manipulation). Bridging this gap with kernel-level evidence eliminates an entire class of supply chain attacks.

**Enforcement tiers** that this enables in the TrustBundle:

| Tier | Meaning | Verification |
|------|---------|-------------|
| `best_effort` | ClawdStrike SDK checked, no kernel enforcement | Receipt signature only |
| `daemon_enforced` | hushd made the decision, signed receipt | Receipt + policy hash |
| `linux_kernel_enforced` | Tetragon eBPF policy active, kernel enforcement | Tetragon event in AegisNet log |
| `linux_kernel_attested` | Tetragon + SPIRE identity + AegisNet proof chain | Full proof chain |

### 4.2 Cross-Layer Attestation Chain

**What it is:** A single verifiable proof chain that spans from a Linux syscall through network transit to an AI agent's tool invocation, cryptographically linking all layers.

**The chain:**

```
1. Kernel event captured by Tetragon (eBPF, tamper-resistant)
   └─► exec_id links to process tree
2. Network flow captured by Hubble (eBPF, independent code path)
   └─► Cilium security identity links to SPIFFE ID
3. SPIRE SVID proves workload identity (X.509, trust domain)
   └─► Short-lived, auto-rotated, node-attested
4. CiliumNetworkPolicy governs the flow (identity-based, not IP)
   └─► Policy hash included in attestation
5. ClawdStrike guard evaluates the agent action
   └─► Receipt links to Tetragon exec_id and network flow UUID
6. AegisNet envelope captures all evidence
   └─► Merkle inclusion proof, witness co-signature
7. (Optional) EAS on-chain timestamp anchors to blockchain
   └─► Checkpoint hash timestamped on L2
```

**Why it matters:** Today, security tools operate in silos. Your EDR does not know what your network policy allowed. Your attestation system does not know what your EDR observed. This architecture creates a **unified proof chain** where a single verification request (`GET /v1/proofs/inclusion?envelope_hash=0x...`) returns evidence that spans all layers. An auditor can verify the entire chain offline with just the trusted root keys.

### 4.3 Zero Trust for AI Agents

**What it is:** A four-layer zero-trust enforcement model specifically designed for AI agent workloads, where each layer independently constrains agent behavior.

```
┌─────────────────────────────────────────────────────────┐
│ Layer 4: ClawdStrike Guards (application boundary)       │
│ McpToolGuard: "Agent X can call tools A, B but not C"    │
│ PromptInjectionGuard: "Block injected instructions"      │
│ JailbreakGuard: "4-layer detection of jailbreak"         │
│ PatchIntegrityGuard: "Code changes must be safe"         │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Tetragon (kernel enforcement)                   │
│ "Process can only access files in /workspace"            │
│ "No egress to IPs outside cluster CIDR"                  │
│ "Kill process if setuid(0) attempted in container"       │
│ "Monitor all binary executions, collect IMA hashes"      │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Cilium (network enforcement)                    │
│ "Agent pod can only reach API pod on port 8080"          │
│ "Only HTTP POST to /v1/attestations allowed (L7)"        │
│ "DNS only resolves *.backbay.io (FQDN filtering)"       │
│ "Mutual authentication required (SPIRE SVID)"           │
├─────────────────────────────────────────────────────────┤
│ Layer 1: SPIRE (identity)                                │
│ "This workload IS spiffe://aegis.local/ns/x/sa/y"       │
│ "Identity attested by node + k8s workload attestor"      │
│ "SVID rotated every 60 minutes"                          │
└─────────────────────────────────────────────────────────┘
```

**Why it matters:** AI agents are autonomous code execution engines. They can write files, make network requests, invoke tools, and modify code -- all without human approval. Each of these actions passes through at least two enforcement layers (application guards + kernel enforcement), and every decision is attested in the AegisNet log. Even if an agent is compromised by prompt injection, it cannot:
- Access files outside its policy (Tetragon + ForbiddenPathGuard)
- Call network endpoints outside its allowlist (Cilium + EgressAllowlistGuard)
- Invoke unauthorized MCP tools (McpToolGuard)
- Escalate its own privileges (Tetragon container escape detection)
- Modify its own policy files (Tetragon guard enforcement TracingPolicy)

### 4.4 Decentralized Policy Marketplace with Runtime-Attested Trust

**What it is:** A community-curated marketplace for security policies where trust is derived from cryptographic attestation rather than a single vendor's authority. Policies are signed by their authors, reviewed and attested by community reviewers, included in curator-signed feeds, and recorded in an append-only transparency log.

**The trust delegation chain:**

```
Author signs PolicyBundle (Ed25519)
  └─► Reviewers co-sign review attestations (M-of-N threshold)
      └─► Curator includes in signed MarketplaceFeed
          └─► Curator submits attestation to AegisNet
              └─► Checkpointer includes in Merkle tree
                  └─► Witness co-signs checkpoint
                      └─► (Optional) EAS on-chain timestamp
```

**Why it matters:** CrowdStrike, Wiz, and every other vendor control their own detection logic. Users must trust the vendor completely. With this marketplace model:
- Multiple independent curators can publish policy feeds
- Users choose which curators to trust (configurable, not hardcoded)
- Every policy has a verifiable provenance chain
- Community reviewers can audit and co-sign policies
- Policies are content-addressed on IPFS (censorship-resistant distribution)
- Revocation is transparent (AegisNet revocation envelopes, time-bound attestations)
- Offline verification is possible via portable proof bundles

### 4.5 Kernel-Level Guard Enforcement

**What it is:** ClawdStrike's application-level guards are backed by kernel-level enforcement via Tetragon, creating an unbyppassable security floor.

| ClawdStrike Guard | Tetragon Reinforcement | Combined Effect |
|---|---|---|
| ForbiddenPathGuard | LSM `file_open` hook | App denies + kernel blocks access |
| EgressAllowlistGuard | `tcp_connect` kprobe + CiliumNetworkPolicy | App denies + kernel blocks connection + network drops packet |
| SecretLeakGuard | `security_file_permission` with MAY_WRITE | App detects secret content + kernel blocks write |
| PatchIntegrityGuard | N/A (semantic analysis) | App-only (kernel cannot evaluate patch semantics) |
| McpToolGuard | N/A (application protocol) | App-only (kernel cannot parse MCP messages) |
| PromptInjectionGuard | N/A (NLP analysis) | App-only |
| JailbreakGuard | N/A (ML/LLM judge) | App-only |

For the guards that Tetragon can reinforce, the kernel enforcement fires even if the ClawdStrike daemon is compromised. This is a critical defense-in-depth property: the attacker must compromise both the application and the kernel to bypass enforcement.

### 4.6 Marketplace-to-Spine Unification

**What it is:** ClawdStrike's marketplace (Ed25519-signed policy bundles + libp2p gossip + notary verification) is already a subset of the Aegis Spine protocol. The natural evolution is to unify them, replacing marketplace-specific trust infrastructure with Spine primitives.

**The mapping:**

| ClawdStrike Marketplace Concept | Aegis Spine Equivalent | Migration Path |
|---|---|---|
| Signed PolicyBundle (Ed25519) | `aegis.spine.envelope.v1` wrapping a `policy_bundle` fact | Bundle becomes an envelope; existing signatures are preserved as the `signature` field |
| MarketplaceFeed (curator-signed) | `head_announcement` from the curator's issuer identity | Feed HEAD is a Spine head; feed entries are envelopes in the curator's log |
| Feed updates (new policies added) | `head_announcement.v1` with incremented `seq` | Desktop subscribes to curator heads via Spine sync instead of polling HTTP |
| Notary verification (`GET /verify/{uid}`) | `GET /v1/proofs/inclusion?envelope_hash=0x...` (Proofs API) | Notary becomes Spine checkpointer + witness; inclusion proofs replace HTTP verify |
| Review attestations (M-of-N co-signs) | `aegis.spine.fact.review_attestation.v1` envelopes | Reviews become facts in reviewers' logs; M-of-N threshold checked against Spine |
| Revocation (time-bound, signed) | `aegis.spine.fact.revocation.v1` | Revocations propagate via all planes including Reticulum (priority 1) |
| IPFS distribution (content-addressed) | IPFS CIDs referenced as `artifact_uri` in Spine facts | No change -- Spine facts carry pointers, not blobs |
| P2P discovery (libp2p gossipsub) | Plane A-L (libp2p) + Plane A-R (Reticulum) | Marketplace gossip becomes Spine gossip; Reticulum adds offline distribution |

**Why this matters:** Unifying the marketplace with Spine eliminates a parallel trust infrastructure. Instead of maintaining separate signing, verification, and distribution systems for policies, everything flows through the same Merkle tree, the same witnesses, and the same multi-plane transport. This also means policy updates and revocations can reach disconnected edge nodes via Reticulum -- a capability the current HTTP-based marketplace cannot provide.

**Phasing:** This unification should happen after the marketplace trust evolution (Phase 4) is stable, as a Phase 5 workstream. The existing marketplace protocol continues to work during migration; Spine-backed verification is additive, not a breaking change.

---

## 5. Product Positioning

### 5.1 The Problem

The AI agent market is exploding. By 2027, enterprise adoption of autonomous agents will reach 50% (up from 25% in 2025). Gartner projects 40% of enterprise applications will embed task-specific agents by 2026.

Yet the security story is abysmal:
- **63% of organizations** have no limits on what AI agents are authorized to do
- **60% of organizations** cannot terminate AI agents quickly
- No mainstream security product provides **runtime enforcement at the AI agent tool boundary**
- No product provides **cryptographic proof** of what an AI agent did at runtime
- **Zero** products offer community-curated, cryptographically-attested security policies for agent workloads

The result: organizations are deploying agents with the security posture of 2010-era cloud -- wide open, no visibility, trust-and-hope.

### 5.2 Target Personas

**Primary: Security Engineers at AI-First Companies**
- Building with Claude, GPT, Codex, or custom models
- Running agents that write code, access databases, make API calls
- Need to prove to compliance that agents operated within policy
- Currently using no runtime security for their agent infrastructure

**Secondary: Compliance Officers and Auditors**
- Responsible for SOC2, HIPAA, PCI-DSS, EU AI Act compliance
- Need audit trails that prove agent behavior was policy-compliant
- Need to demonstrate that enforcement was active and effective
- The EU AI Act (full implementation 2027) will require exactly this kind of transparency

**Tertiary: AI Safety Researchers**
- Studying agent alignment, tool use safety, jailbreak resistance
- Need kernel-level observability of what agents actually do (vs. what they claim to do)
- Tetragon visibility into agent process trees is a research capability nobody else offers

**Emerging: Platform Engineering Teams**
- Running multi-tenant agent infrastructure on Kubernetes
- Need network segmentation, identity-based policy, encryption for agent-to-agent comms
- Cilium + SPIRE + Tetragon is the infrastructure layer they need

### 5.3 Competitive Differentiation

| Capability | ClawdStrike | CrowdStrike Falcon | Wiz | Sysdig | Aqua | Lacework |
|---|---|---|---|---|---|---|
| **Agent-specific guards** (MCP, prompt injection, jailbreak) | 7 built-in + async | No | No | No | No | No |
| **Kernel runtime enforcement** (eBPF) | Via Tetragon integration | Falcon sensor (proprietary) | No (agentless) | Falco (detect only) | Runtime policies | No |
| **Kernel-level execution proofs** | AegisNet Merkle proofs | No | No | No | No | No |
| **Cross-layer attestation chain** | SPIRE -> Cilium -> Tetragon -> AegisNet | No | No | No | No | No |
| **Cryptographic receipt for every decision** | Ed25519 signed receipts | No | No | No | No | No |
| **Transparency log with witness** | RFC 6962 Merkle tree + witness | No | No | No | No | No |
| **Identity-based network policy** | Cilium + SPIRE mTLS | Limited | Cloud-native | Limited | Limited | No |
| **L7 visibility** (HTTP, gRPC, DNS) | Hubble | Falcon Insight | Cloud APIs | Sysdig Monitor | Limited | Polygraph |
| **Policy marketplace** | Community-curated, signed | CrowdStrike Store (vendor-controlled) | No | No | No | No |
| **Decentralized trust** | Multi-curator, IPFS, EAS | No | No | No | No | No |
| **Offline verification** | Portable proof bundles | No | No | No | No | No |
| **Offline distribution** | Reticulum mesh (LoRa/radio/serial, ~5 bps) | No | No | No | No | No |
| **Open source components** | Tetragon, Cilium, SPIRE, NATS, Reticulum | Proprietary | Proprietary | Falco (partial) | Trivy (partial) | Proprietary |

### 5.4 The "Swarm Detection & Response" Market Category

ClawdStrike is creating a new category: **Swarm Detection & Response (SDR)** -- EDR, but purpose-built for AI agent swarms.

The analogy: CrowdStrike created the EDR market in 2013 by putting an agent on every endpoint that could detect and respond to threats in real time. The "endpoints" of 2026 are AI agents. ClawdStrike puts enforcement at the tool boundary of every agent, with kernel-level visibility into what those agents actually do.

The market for this category does not formally exist yet. AccuKnox published a "Top 5 ADR Security Solutions" in 2026, recognizing the emerging space (we use the term **SDR** to emphasize swarm-level coordination rather than single-agent scope). The Cloud Security Alliance published an "Agentic Trust Framework" in February 2026 outlining zero-trust governance for AI agents -- which this architecture directly implements.

### 5.5 Business Model Alignment with Backbay

ClawdStrike's marketplace integrates with the broader Backbay Industries ecosystem:

- **Policy bundles** are tradeable goods in the Backbay marketplace economy
- **Curator reputation** is a form of social capital within the platform
- **Attestation throughput** through AegisNet is a metered infrastructure resource
- **Community review** creates engagement loops and expertise signaling

The decentralized marketplace model (multi-curator, community curation, IPFS distribution) aligns with Backbay's vision of "themed subdomains + subeconomies + social experiences."

The execution plan for consolidating AegisNet's open-source components into ClawdStrike's public repository -- including repo structure, governance model, licensing, and community strategy -- is documented in the [Open Source Consolidation Strategy](./open-source-strategy.md).

---

## 6. Implementation Roadmap

### 6.1 Phase Summary

```
Phase 1: Infrastructure (Weeks 1-4)
    Deploy Cilium + Tetragon on EKS
    │
Phase 2: Event Pipeline (Weeks 3-8)
    Wire Tetragon → NATS → AegisNet attestation pipeline
    Wire Hubble → NATS → ClawdStrike network map
    │
Phase 3: Live Data Integration (Weeks 6-12)
    Replace ClawdStrike mock data with live feeds
    Runtime proof chain implementation
    │
Phase 4: Marketplace Trust (Weeks 10-16)
    Multi-curator, AegisNet notary, IPFS distribution
    Community review workflow
    │
Phase 5: Cross-Layer Proofs (Weeks 14-20)
    Full attestation chain, compliance reporting
    EAS on-chain anchoring, portable proof bundles
    │
Phase 6: Reticulum Transport + Spine Unification (Weeks 18-26)
    Reticulum adapter (Plane A-R) for offline envelope distribution
    Marketplace → Aegis Spine protocol unification
    Radio gateway deployments (LoRa / packet radio)
```

### 6.2 Phase 1: Infrastructure Foundation

**Goal:** Deploy Cilium and Tetragon on the existing EKS cluster alongside current infrastructure.

**Workstreams:**

1. **Cilium Deployment (CNI Chaining Mode)**
   - Create `platform/infra/gitops/apps/platform/cilium.yaml` ArgoCD Application
   - Cilium 1.19.0 in CNI chaining mode (Cilium alongside existing VPC CNI)
   - Enable Hubble (relay, UI, metrics with ServiceMonitor)
   - Enable SPIRE mutual authentication (pointing to existing SPIRE at `spire-server.spire-system.svc:8081`, trustDomain: `aegis.local`)
   - Enable WireGuard transparent encryption
   - Keep kube-proxy during this phase
   - Add Karpenter startup taint: `node.cilium.io/agent-not-ready` with NoExecute
   - Set `cni.enableRouteMTUForCNIChaining=true` for WireGuard MTU handling

2. **Tetragon Deployment**
   - Create `platform/infra/gitops/apps/platform/tetragon.yaml` ArgoCD Application
   - Tetragon DaemonSet in `kube-system` namespace
   - Enable process credentials and namespaces enrichment
   - Deploy initial TracingPolicies:
     - `aegisnet-exec-allowlist`: Allowlist AegisNet binaries, alert on others
     - `aegisnet-fim`: File integrity monitoring for `/etc/aegisnet/`, SPIRE mount paths
     - `aegisnet-network-egress`: Alert on non-cluster egress from AegisNet pods
     - `container-escape-detection`: Monitor setuid(0), unshare, namespace changes
   - Resource budget: CPU 100m-1000m, Memory 256Mi-1Gi per node

3. **Validation**
   - `cilium status --wait` and `cilium connectivity test`
   - `hubble observe` confirms flow visibility
   - `hubble observe --verdict AUDIT` for policy audit mode
   - `kubectl -n kube-system exec ds/tetragon -c tetragon -- tetra getevents -o compact`
   - iperf3 benchmark: pod-to-pod throughput with and without WireGuard
   - Verify Hubble ServiceMonitor appears in Grafana

**Dependencies:** None (greenfield deployment alongside existing infrastructure)
**Risk:** Low (chaining mode preserves VPC CNI as fallback; Tetragon is read-only by default)
**Rollback:** `helm uninstall cilium` + pod rolling restart

### 6.3 Phase 2: Event Pipeline

**Goal:** Connect Tetragon and Hubble events to AegisNet's attestation pipeline via NATS JetStream.

**Workstreams:**

1. **tetragon-nats-bridge (new Rust service)**
   - gRPC client connecting to Tetragon's `GetEvents` stream
   - Transform Tetragon events into AegisNet `SignedEnvelope` with `fact` payload
   - Sign envelopes with node-specific Ed25519 keypair (provisioned via SPIRE in Phase 3, manual secret in Phase 2)
   - Publish to NATS subjects: `aegis.spine.envelope.tetragon.{event_type}.v1`
   - Deploy as sidecar container in Tetragon DaemonSet pods
   - Persist last-published NATS sequence for crash recovery
   - Dedup via `fact_id = sha256(exec_id + time + function_name)`
   - Resource budget: CPU 50m-250m, Memory 64Mi-256Mi per node

2. **Hubble-to-NATS Pipeline**
   - Deploy Fluent Bit DaemonSet to tail `/var/run/cilium/hubble/events.log`
   - Publish parsed JSON to `aegisnet.hubble.flows` NATS subject
   - Filter to relevant namespaces (aegisnet, default, workloads) to control volume
   - Field masking to reduce flow size (see Cilium Helm values `hubble.export.static.fieldMask`)

3. **AegisNet Stream Configuration**
   - Update `AEGISNET_LOG` stream subjects to include `aegis.spine.envelope.tetragon.>`
   - Create `AEGISNET_HUBBLE_RAW` stream for raw Hubble flows
   - Verify checkpointer ingests Tetragon envelopes and produces checkpoints
   - Verify proofs API returns inclusion proofs for Tetragon envelope hashes

4. **hushd NATS Subscriber**
   - Add NATS subscription to hushd for Tetragon subjects
   - Map Tetragon events to existing `SecurityEvent` type
   - Broadcast via SSE to desktop clients alongside existing hushd events
   - Recommended: bridge through hushd to maintain single event stream

**Dependencies:** Phase 1 (Cilium + Tetragon deployed)
**Risk:** Medium (new service development; NATS subject config changes; event volume management)

### 6.4 Phase 3: Live Data Integration

**Goal:** Replace ClawdStrike desktop mock data with live Tetragon and Hubble feeds.

**Workstreams:**

1. **ThreatRadarView: Tetragon Events**
   - Replace `MOCK_THREATS` array with live Tetragon event subscription
   - Map Tetragon events to `Threat` type:
     - `id`: Tetragon `exec_id`
     - `angle`: Hash of pod namespace (cluster segment visualization)
     - `distance`: Inverse of severity (closer = more severe)
     - `severity`: Derived from enforcement action and policy tags
     - `type`: Map from Tetragon tags (`malware`, `exfiltration`, `fim`, etc.)
     - `active`: `true` if event was observational (Post), `false` if killed (Sigkill)
     - `label`: `policy_name: message` from TracingPolicy

2. **AttackGraphView: MITRE ATT&CK Correlation**
   - Replace `MOCK_CHAINS` with Tetragon event correlation
   - Build process trees from `exec_id` + `parent_exec_id` lineage
   - Map policy tags (`MITRE:T1003`, `MITRE:T1041`, etc.) to ATT&CK techniques
   - Infer kill chain progression from time-ordered events in the same process tree
   - Show enforcement status: "contained" if any event in chain was Sigkill'd

3. **NetworkMapView: Hubble Flow Topology**
   - Replace `MOCK_NODES` and `MOCK_EDGES` with live Hubble flow aggregation
   - Implement `TopologyState` manager (node/edge upsert from flow events)
   - Topology via aggregation over sliding time window:
     - Each unique `(namespace, pod_name)` = node
     - Each unique `(src, dst, protocol, port)` = edge
     - Verdict aggregation determines edge status
     - `flow.IP.encrypted` shows WireGuard status
   - Data pipeline: NATS subscription -> Tauri IPC -> React state -> R3F canvas

4. **EventStreamView: Tetragon Event Types**
   - Already supports live hushd SSE events
   - Add Tetragon-sourced event types: `process_exec`, `process_exit`, `kernel_hook`, `namespace_change`, `capability_change`
   - Show AegisNet attestation fields: `envelope_hash`, `checkpoint_seq`, `inclusion_proof_available`

5. **Runtime Proof Chain**
   - Implement `aegis.spine.fact.runtime_proof.v1` fact schema combining Tetragon + SPIRE data
   - Each runtime proof links: Tetragon exec_id, SPIRE SVID hash, ClawdStrike receipt hash, AegisNet envelope hash
   - Desktop UI: "Verify Proof" button fetches inclusion proof from Proofs API and validates locally

**Dependencies:** Phase 2 (event pipeline operational)
**Risk:** Medium-High (frontend rearchitecture of 3 views; real-time data handling complexity)

### 6.5 Phase 4: Marketplace Trust Evolution

**Goal:** Evolve the marketplace from single-curator to multi-curator with AegisNet-backed attestation.

**Workstreams:**

1. **Multi-Curator Support (Config-Based)**
   - Load trusted curator keys from `~/.clawdstrike/trusted_curators.toml`
   - `verify_trusted()` already accepts `&[PublicKey]`; change is in key loading
   - Desktop Settings UI: manage trusted curator keys (add, remove, trust-level)
   - Support `trust_level`: `full` (auto-install) vs `audit-only` (require explicit approval)

2. **AegisNet as Notary Replacement**
   - Define `clawdstrike.marketplace.policy_attestation.v1` fact schema
   - Curator tooling submits attestation envelopes to AegisNet on feed publish
   - Replace HTTP notary calls (`GET /verify/{uid}`) with AegisNet proofs API queries
   - `GET /v1/proofs/inclusion?envelope_hash=0x<attestation_envelope_hash>`
   - Add RFC 6962 Merkle proof verification to desktop client (Rust side via hush-core)
   - Store inclusion proofs alongside feed entries for offline verification

3. **IPFS-First Distribution**
   - Curator tooling pins signed feeds and bundles to IPFS (Pinata + self-hosted)
   - Feed entries use `ipfs://` CIDs as primary `bundle_uri`
   - P2P discovery gossips feed CIDs instead of HTTPS URLs
   - Desktop client: IPFS gateway fallback chain for fetching

4. **Community Review Workflow**
   - Define `clawdstrike.marketplace.review_attestation.v1` fact schema
   - Build reviewer submission flow (CLI `clawdstrike review` + desktop UI)
   - Curator tooling checks M-of-N review attestations before inclusion
   - Reputation tracking from attestation history

**Dependencies:** Phase 2 (AegisNet integration for attestation)
**Risk:** Medium (UX design for trust configuration; migration from single-curator)

### 6.6 Phase 5: Cross-Layer Proofs and Compliance

**Goal:** Deliver the full vision: end-to-end proof chains, compliance reporting, and optional blockchain anchoring.

**Workstreams:**

1. **Portable Proof Bundles**
   - Package complete proof chains alongside policies:
     - Signed bundle, feed entry, attestation envelope, inclusion proof, checkpoint with witness signatures
   - Verifiable entirely offline with trusted root keys
   - Format: `clawdstrike-portable-proof-v1` JSON

2. **EAS On-Chain Anchoring (Optional)**
   - Register ClawdStrike attestation schema on EAS (Base L2)
   - Curator tooling optionally timestamps attestation UIDs on-chain
   - Off-chain attestations with batched on-chain timestamps (cost: ~$0.50/month for 100 policies)
   - Desktop client verifies EAS timestamps for `type: "eas"` provenance

3. **Compliance Reporting**
   - Generate audit reports from AegisNet log:
     - "All agent actions in namespace X during period Y"
     - "All enforcement actions with kernel-level attestation"
     - "Policy compliance coverage: N% of actions had receipt + kernel proof"
   - Export to SOC2/HIPAA/AI-Act-compatible formats
   - Attestation of the report itself in AegisNet (meta-attestation)

4. **CiliumNetworkPolicy + Receipt Integration**
   - Network attestation receipts combining Hubble flow + CiliumNetworkPolicy hash + SPIFFE IDs
   - Policy bypass detection: compare Hubble observations against CiliumNetworkPolicy specs
   - Anomaly detection: flows from identities that should not exist, unencrypted flows when WireGuard active

5. **TUF Metadata Structure (Long-term)**
   - Adopt TUF root/targets/snapshot/timestamp role structure
   - Key rotation protocol (root delegates to new root)
   - Threshold signing (M-of-N curators for feed updates)
   - This is a significant refactor and should only be attempted after Phases 1-4 are stable

**Dependencies:** Phases 3 + 4
**Risk:** High (cross-cutting concerns; compliance framework integration; blockchain dependencies)

### 6.7 Phase 6: Reticulum Transport and Spine Unification

**Goal:** Extend envelope distribution to offline/disconnected environments via Reticulum (Plane A-R) and unify the ClawdStrike marketplace with the Aegis Spine protocol.

**Workstreams:**

1. **Reticulum Adapter (Python sidecar)**
   - Implement Reticulum adapter per the [transport profile spec](../../../../platform/docs/specs/cyntra-aegis-spine-reticulum.md)
   - Carry `SignedEnvelope`, `head_announcement`, `sync_request`, `sync_response` over Reticulum
   - Priority scheduling: revocations > checkpoints > incidents > policy deltas > run facts > heartbeats
   - Compact encoding (CBOR or zstd-compressed canonical JSON) for ~500 byte MTU links
   - Store-and-forward delivery via LXMF semantics for intermittent connectivity
   - Dedupe by `envelope_hash`, enforce per-issuer monotonic `seq`

2. **Translation Gateway (Reticulum <-> NATS)**
   - Bridge Plane A-R to Plane B (NATS JetStream) at cluster boundaries
   - Verify envelope hash + signature before forwarding in either direction
   - Enforce disclosure policy (allow/deny by fact schema, issuer, or policy)
   - Rate-limit and dedupe; audit log all forward/drop decisions
   - Deploy as "radio gateway" node: LoRa/serial on one side, NATS on the other

3. **Identity Binding**
   - Extend `node_attestation.v1` fact with `transports.reticulum` metadata
   - Bind Aegis Ed25519 issuer identity to Reticulum destination hash
   - Separate keys model (Model A from spec): Aegis keys for truth, Reticulum keys for transport

4. **Marketplace -> Spine Migration**
   - Define Spine fact schemas for policy bundles, feed entries, and review attestations
   - Curator tooling publishes feed updates as Spine `head_announcement` objects
   - Replace HTTP notary verification with Spine Proofs API inclusion proofs
   - Desktop client subscribes to curator heads via Spine sync (replaces feed polling)
   - Revocations propagate via all planes including Reticulum (priority 1)

5. **Validation: Offline Distribution**
   - Test scenario: revocation created in NATS cluster propagates to off-grid node via Reticulum
   - Test scenario: edge node catches up missing `(issuer, seq)` ranges after reconnecting
   - Test scenario: radio gateway bridges LoRa <-> NATS with sub-second envelope verification
   - Bandwidth validation: verify operation at ~5 bps (LoRa worst case)

**Dependencies:** Phase 2 (NATS/AegisNet operational), Phase 4 (marketplace trust stable)
**Risk:** Medium (Python Reticulum stack is mature; gateway bridging is new development; radio hardware testing required)

---

## 7. Open Questions and Decision Points

### 7.1 Architecture Decisions

**Q1: Cilium deployment mode -- chaining vs. full IPAM?**

Recommendation: **Start with chaining mode** (Phase 1), move to full IPAM only if VPC IP exhaustion becomes a concern. Chaining preserves the VPC CNI as a fallback and avoids the risk of a full CNI swap. The only features blocked in chaining mode are overlay networking and some advanced service mesh features, neither of which we need immediately.

**Q2: Where does the tetragon-nats-bridge run?**

Options:
- (A) Sidecar container in the Tetragon DaemonSet pod
- (B) Separate DaemonSet
- (C) Centralized Deployment (1 replica, connects to all nodes)

Recommendation: **(A) Sidecar** for simplicity and co-location with the gRPC source. The bridge connects via localhost gRPC, minimizing latency and failure modes. A separate DaemonSet (B) adds operational complexity without benefit. A centralized deployment (C) creates a bottleneck and single point of failure.

**Q3: On-chain vs. off-chain attestations for the marketplace?**

Recommendation: **AegisNet as primary, EAS as optional anchoring layer**. AegisNet provides Merkle-proof-based verifiability without blockchain costs. EAS on-chain timestamps are reserved for high-value attestations (e.g., root key rotation, feed signing key changes) where blockchain consensus provides additional censorship resistance. Off-chain EAS attestations with batched on-chain timestamps provide a good middle ground.

**Q4: SPIRE integration for the tetragon-nats-bridge's signing key?**

Recommendation: **Phase 2 uses manual K8s secrets** (same pattern as current AegisNet services). **Phase 5 migrates to SPIRE-issued keys** for automatic rotation. The bridge's SPIFFE ID would be `spiffe://aegis.local/ns/kube-system/sa/tetragon-nats-bridge`, and its Ed25519 signing key would rotate alongside the SVID.

**Q5: Build or buy the tetragon-nats-bridge?**

This must be **built**. No existing tool bridges Tetragon gRPC to NATS JetStream with AegisNet envelope signing. The bridge is ~500-800 lines of Rust using `tonic` (gRPC) + `async-nats` (NATS) + `ed25519-dalek` (signing). It is straightforward and well-scoped.

**Q6: When should Reticulum (Plane A-R) be integrated?**

Recommendation: **Phase 6 (after Phases 4-5 stabilize)**. The Reticulum adapter is a Python sidecar (Reticulum is Python-native), which means it can be developed independently of the Rust tetragon-nats-bridge. The gateway bridging (Reticulum <-> NATS) is the critical integration point. Early prototyping can happen in parallel with Phase 3-4, but production deployment should wait until the Spine protocol and marketplace trust model are stable.

**Q7: Should the marketplace fully migrate to Spine, or maintain backward compatibility?**

Recommendation: **Additive migration**. The existing marketplace HTTP protocol continues to work. Spine-backed verification is added as an alternative verification path. Desktop clients prefer Spine when available but fall back to HTTP notary. Full cutover happens only after Spine verification has been validated in production for at least one release cycle. See section 4.6 for the detailed mapping.

### 7.2 Scale Considerations

**Event volume estimates (50-node cluster):**

| Source | Events/sec/node | Total events/sec | Notes |
|--------|----------------|-----------------|-------|
| Tetragon process exec/exit | 100-1000 | 5K-50K | Depends on workload churn |
| Tetragon kprobe (file) | 50-500 | 2.5K-25K | With selector filtering |
| Tetragon kprobe (network) | 10-100 | 500-5K | With CIDR filtering |
| Hubble flows | 500-5000 | 25K-250K | Before field masking |
| ClawdStrike receipts | 1-10 | 50-500 | Per agent action |
| **Total** | | **33K-330K events/sec** | |

**Mitigation strategies:**
- Tetragon in-kernel filtering (events that do not match selectors never reach userspace)
- TracingPolicy rate limiting (`rateLimit: "1m"` for noisy policies)
- Hubble field masking and namespace filtering
- NATS JetStream backpressure (consumer-controlled flow)
- AegisNet checkpointer batching (1 checkpoint per 10+ envelopes or 5-second interval)
- Separate `AEGISNET_HUBBLE_RAW` stream (1 replica) for high-volume flow data vs. `AEGISNET_LOG` (3 replicas) for attested events

**Storage estimates (per day, 50 nodes):**

| Stream | Event rate | Event size | Daily volume |
|--------|-----------|------------|-------------|
| AEGISNET_LOG (attested events) | ~1K/sec | ~500 bytes | ~43 GB |
| AEGISNET_HUBBLE_RAW | ~5K/sec | ~300 bytes (masked) | ~130 GB |
| AEGISNET_TETRAGON_RAW | ~5K/sec | ~500 bytes | ~216 GB |

Current NATS JetStream allocation: 50Gi per node x 3 replicas = 150Gi. For the LOG stream this is sufficient for ~3 days of retention. RAW streams should use 1 replica with aggressive rotation (24-48 hours) or be disabled in production.

### 7.3 Performance Budget

**Acceptable latency targets:**

| Path | Target | Rationale |
|------|--------|-----------|
| Kernel event to desktop visualization | < 100ms | Real-time threat monitoring |
| Kernel event to AegisNet checkpoint | < 15 seconds | Batch efficiency vs. freshness |
| Guard decision to receipt signing | < 10ms | Cannot slow agent actions |
| Inclusion proof query (Proofs API) | < 50ms | Interactive verification |
| Full portable proof verification (offline) | < 100ms | Batch audit workflows |
| Cilium eBPF per-packet overhead | < 50 microseconds | Network throughput SLA |
| Tetragon per-event overhead | < 1% CPU | Production workload budget |

### 7.4 Regulatory and Compliance Angles

**EU AI Act (full implementation 2027):**
- Requires transparency and auditability for high-risk AI systems
- This architecture directly provides: runtime evidence, attestation, compliance reports
- The cross-layer proof chain is a natural fit for EU AI Act Article 12 (record-keeping)

**SOC2 Type II:**
- Continuous monitoring of controls (Tetragon + Hubble + AegisNet)
- Evidence of enforcement (receipts, kernel events, network policy verdicts)
- Audit trail with cryptographic integrity (Merkle proofs)

**HIPAA (for healthcare AI agents):**
- Access control enforcement (CiliumNetworkPolicy + guards)
- Audit logging (AegisNet transparency log)
- Integrity controls (Tetragon FIM + IMA hashes)

**FedRAMP:**
- Continuous monitoring (Hubble metrics + Tetragon events + Prometheus)
- Incident response (real-time detection + kernel-level enforcement)
- Cryptographic evidence chain for forensics

### 7.5 Relation to the Backbay Marketplace Economy

Open question: How do ClawdStrike policies participate in the broader Backbay marketplace?

Options:
- (A) ClawdStrike policies are standalone products traded independently
- (B) ClawdStrike policies are bundled with cluster economy access (Providence cluster)
- (C) ClawdStrike is the trust infrastructure underlying all Backbay marketplace transactions

Recommendation: **(A)** initially, evolving toward **(C)**. The AegisNet attestation infrastructure should be positioned as the trust layer for the entire Backbay ecosystem, not just ClawdStrike. Marketplace attestation envelopes, cluster membership proofs, and agent execution receipts all flow through the same Merkle tree.

---

## 8. Risks and Mitigations

### 8.1 Complexity Risk

**Risk:** Six layers of infrastructure is a lot of moving parts. Debugging issues that span kernel -> eBPF -> gRPC -> NATS -> Merkle tree -> Reticulum -> desktop is challenging.

**Likelihood:** High | **Impact:** Medium

**Mitigations:**
- Phased rollout with validation gates between phases
- Each layer operates independently (Tetragon without AegisNet, Cilium without Tetragon)
- Comprehensive observability: Prometheus metrics at every layer, Grafana dashboards, NATS monitoring
- Hubble UI provides visual service topology for debugging network issues
- Tetragon `tetra getevents` provides direct visibility into kernel events
- AegisNet Proofs API provides HTTP-accessible state for debugging attestation
- Start with audit mode (Cilium policy audit, Tetragon Post-only) before enforcement

### 8.2 Performance Risk

**Risk:** eBPF overhead + WireGuard encryption + attestation latency could degrade agent workload performance.

**Likelihood:** Low-Medium | **Impact:** Medium

**Mitigations:**
- Tetragon overhead is < 1% CPU with in-kernel filtering (events that do not match selectors never reach userspace)
- WireGuard overhead is 5-15% throughput reduction (ChaCha20-Poly1305 is hardware-accelerated on modern CPUs)
- Attestation is asynchronous (does not block the critical path of agent execution)
- ClawdStrike guard evaluation is synchronous but designed for < 10ms latency
- Benchmark in staging before production: iperf3 (network), Tetragon metrics, NATS throughput
- MTU configuration is critical for WireGuard on EKS: `enableRouteMTUForCNIChaining=true`

### 8.3 Adoption Risk

**Risk:** Who actually needs kernel-level AI agent security proofs? The market may not be ready.

**Likelihood:** Medium | **Impact:** High

**Mitigations:**
- The market is moving toward us: EU AI Act (2027), CSA Agentic Trust Framework (2026), 63% governance gap
- Start with simpler value propositions: Tetragon runtime visibility (no attestation needed) is immediately useful
- Hubble network observability is useful to any Kubernetes team, regardless of AI agents
- ClawdStrike guards are useful without the full stack (the SDK works standalone)
- Position early phases as "cloud-native security" (broad market), later phases as "AI agent security" (niche-to-mainstream)
- The 46.3% CAGR of the AI agent market means the customer base is growing rapidly

### 8.4 Dependency Risk

**Risk:** Cilium, Tetragon, SPIRE, and NATS are external projects with their own release cycles and compatibility matrices.

**Likelihood:** Low | **Impact:** Medium

**Mitigations:**
- All dependencies are CNCF projects (Cilium, Tetragon, SPIRE) or major OSS (NATS)
- Pin Helm chart versions in ArgoCD manifests (Cilium 1.19.0, SPIRE 0.13.0, NATS 2.12.3)
- Cilium + Tetragon mutual auth + Cluster Mesh incompatibility is a known limitation (documented in Phase 1 constraints)
- Maintain chaining mode as long as possible (fallback to VPC CNI on Cilium issues)
- NATS is operationally stable (deployed for months as AegisNet backbone)
- AegisNet is fully under our control (no external dependency for the attestation layer)

### 8.5 Operational Risk

**Risk:** Running Tetragon DaemonSet with `hostPID: true` and access to `/sys/kernel/tracing` has operational security implications.

**Likelihood:** Low | **Impact:** High

**Mitigations:**
- Tetragon is a CNCF project used by major enterprises in production
- The DaemonSet runs in `kube-system` namespace with strict RBAC
- Tetragon's signing keypair (for the bridge) is stored as K8s secret with namespace-scoped RBAC
- CiliumNetworkPolicy isolates the Tetragon pods' network access
- TracingPolicies are cluster-scoped CRDs requiring cluster-admin to deploy
- The tetragon-nats-bridge only connects to Tetragon's localhost gRPC and NATS -- no other network access

### 8.6 Risk Matrix Summary

| Risk | Likelihood | Impact | Mitigation Quality | Residual Risk |
|------|-----------|--------|--------------------|----|
| Complexity (6 layers) | High | Medium | Good (phased, independent layers) | **Medium** |
| Performance (eBPF + WireGuard + attestation) | Low-Medium | Medium | Good (async, in-kernel filtering) | **Low** |
| Adoption (market readiness) | Medium | High | Good (progressive value proposition) | **Medium** |
| Dependencies (CNCF projects) | Low | Medium | Good (pinned versions, fallbacks) | **Low** |
| Operational (hostPID, kernel access) | Low | High | Good (RBAC, network policy, CNCF trust) | **Low** |
| Event volume at scale | Medium | Medium | Good (filtering, backpressure, batching) | **Low-Medium** |

---

## 9. Conclusion

The architecture described in this document is ambitious but grounded. Every component either already exists in production (SPIRE, NATS, AegisNet, ClawdStrike guards) or is a well-understood CNCF technology (Cilium, Tetragon). The novel contribution is not any single layer but the *integration* -- the cross-layer proof chain that connects kernel syscalls to cryptographic receipts to community-curated policy marketplaces.

The market timing is favorable. AI agent adoption is accelerating at 46.3% CAGR. Governance frameworks are maturing (EU AI Act 2027, CSA Agentic Trust Framework 2026). The governance gap (63% of orgs with no agent controls) is widening. And no existing product offers the combination of kernel-level enforcement, cryptographic attestation, and agent-specific policy guards.

The six-phase implementation plan starts with low-risk infrastructure deployment (Cilium chaining + Tetragon DaemonSet) and progressively builds toward the full vision. Each phase delivers standalone value: Phase 1 provides runtime visibility and network observability; Phase 2 provides verifiable event logging; Phase 3 provides live threat visualization; Phase 4 provides a trusted policy ecosystem; Phase 5 provides end-to-end compliance proofs; Phase 6 extends distribution to offline environments via Reticulum and unifies the marketplace with the Aegis Spine protocol.

The end state is a security stack where every AI agent action -- every file access, network request, tool invocation, and code patch -- is:

1. **Enforced** at the kernel level (cannot be bypassed by application compromise)
2. **Observed** at the network level (cannot be hidden by process-level evasion)
3. **Attested** in a transparency log (cannot be tampered with after the fact)
4. **Witnessed** by an independent party (cannot be fabricated by a single key compromise)
5. **Verifiable** by anyone (clients, auditors, regulators) with just the trusted root keys
6. **Distributable** even without internet connectivity (Reticulum carries signed truth over any carrier)

This is not just a security product. It is a new primitive for trust in autonomous systems -- a **Swarm Detection & Response (SDR)** platform that secures not just individual agents but entire agent swarms, from kernel syscalls to offline mesh networks.

---

## References

### Research Documents (this repository)

- [Tetragon Integration with AegisNet](./tetragon-integration.md) -- Kernel runtime security, TracingPolicies, AegisNet pipeline
- [Cilium Network Security Layer](./cilium-network-security.md) -- CNI migration, SPIRE mTLS, Hubble, CiliumNetworkPolicy
- [Marketplace Trust Evolution](./marketplace-trust-evolution.md) -- Multi-curator, AegisNet notary, EAS, IPFS, P2P, community curation
- [Reticulum SDR Integration](./reticulum-sdr-integration.md) -- Plane A-R transport, offline mesh distribution, ClawdStrike SDR positioning
- [Open Source Consolidation Strategy](./open-source-strategy.md) -- AegisNet -> ClawdStrike consolidation, repo structure, governance, licensing

### Architecture Sources

- [AegisNet Architecture](../../../aegis/apps/aegis/services/aegisnet/ARCHITECTURE.md) -- Verifiable log system
- [Aegis Spine Reticulum Transport Profile](../../../../platform/docs/specs/cyntra-aegis-spine-reticulum.md) -- Plane A-R transport spec
- [Aegis Spine Protocol](../../../../platform/docs/specs/cyntra-aegis-spine.md) -- Layer 4 envelope/fact schemas
- [ClawdStrike CLAUDE.md](../../CLAUDE.md) -- Project overview and guard system

### External References

- [Tetragon Documentation](https://tetragon.io/) -- eBPF runtime security
- [Cilium Documentation](https://docs.cilium.io/) -- eBPF networking and security
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/) -- Workload identity
- [NATS JetStream](https://docs.nats.io/nats-concepts/jetstream) -- Event streaming
- [RFC 6962 (Certificate Transparency)](https://datatracker.ietf.org/doc/html/rfc6962) -- Merkle tree proofs
- [Ethereum Attestation Service](https://attest.org/) -- On-chain attestation
- [The Update Framework (TUF)](https://theupdateframework.io/) -- Secure update distribution
- [Sigstore](https://docs.sigstore.dev/) -- Keyless signing and transparency

### Market Research

- [CNAPP Market Size, Share & 2030 Growth Trends Report](https://www.mordorintelligence.com/industry-reports/cloud-native-application-protection-platform-market) -- $10.9B (2025) to $28B (2030)
- [AI Agents Market Size, Share & Trends (2026-2034)](https://www.demandsage.com/ai-agents-market-size/) -- $7.8B (2025) to $52.6B (2030), 46.3% CAGR
- [The 2025 AI Agent Security Landscape](https://www.obsidiansecurity.com/blog/ai-agent-market-landscape) -- Market players and risks
- [What's Shaping the AI Agent Security Market in 2026](https://www.cyberark.com/resources/blog/whats-shaping-the-ai-agent-security-market-in-2026) -- 63% governance gap
- [Agentic Trust Framework: Zero Trust for AI Agents (CSA)](https://cloudsecurityalliance.org/blog/2026/02/02/the-agentic-trust-framework-zero-trust-governance-for-ai-agents) -- Zero trust governance
- [Top 5 ADR Security Solutions in 2026](https://accuknox.com/blog/adr-security-solutions) -- Emerging SDR/ADR category
- [EDR Killers: Kernel Integrity and Runtime Attestation](https://cloudsecurityalliance.org/blog/2025/09/15/edr-killers-how-modern-attacks-are-outpacing-traditional-defenses) -- Runtime attestation need
- [6 Cybersecurity Predictions for the AI Economy in 2026 (HBR/Palo Alto)](https://hbr.org/sponsored/2025/12/6-cybersecurity-predictions-for-the-ai-economy-in-2026) -- AI economy security trends
- [2026 Data Security Forecast: 15 Predictions for AI Governance](https://www.kiteworks.com/cybersecurity-risk-management/2026-data-security-forecast-ai-governance-predictions/) -- EU AI Act and governance
- [Wiz vs. CrowdStrike: 2026 Cloud Security Comparison](https://www.wiz.io/academy/cloud-security/wiz-vs-crowdstrike) -- Competitive landscape
