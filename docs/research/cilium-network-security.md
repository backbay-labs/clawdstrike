# Cilium Network Security Layer: CNI Migration, SPIRE Integration, and Hubble Observability

> Research document for planning the migration from AWS VPC CNI to Cilium on EKS, integrating SPIRE/SPIFFE identity-based mTLS, feeding Hubble flow data into ClawdStrike's Network Map plugin, and connecting the observability pipeline to AegisNet.

**Status**: Research
**Date**: 2026-02-07
**Audience**: Platform engineering, security team, ClawdStrike desktop team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Cilium on EKS: Architecture and Migration](#2-cilium-on-eks-architecture-and-migration)
3. [SPIRE + Cilium mTLS: Identity-Based Network Security](#3-spire--cilium-mtls-identity-based-network-security)
4. [Hubble Observability: Flow Data and Metrics](#4-hubble-observability-flow-data-and-metrics)
5. [CiliumNetworkPolicy: L3/L4/L7 Microsegmentation](#5-ciliumnetworkpolicy-l3l4l7-microsegmentation)
6. [WireGuard Transparent Encryption](#6-wireguard-transparent-encryption)
7. [Network Map Data Source for ClawdStrike](#7-network-map-data-source-for-clawdstrike)
8. [AegisNet Integration](#8-aegisnet-integration)
9. [Microsegmentation with Receipts](#9-microsegmentation-with-receipts)
10. [Migration Strategy](#10-migration-strategy)
11. [Open Questions and Risk Assessment](#11-open-questions-and-risk-assessment)

---

## 1. Executive Summary

The Backbay platform currently runs on EKS with the AWS VPC CNI (`aws-vpc-cni-k8s`), Karpenter for node autoscaling, SPIRE for workload identity (`trustDomain: aegis.local`), NATS JetStream for the AegisNet event backbone, and kube-prometheus-stack for monitoring.

Cilium replaces both the CNI data plane and kube-proxy with eBPF programs, providing:

- **Identity-based network policies** (L3-L7) decoupled from IP addresses
- **Native SPIFFE mutual authentication** without sidecar proxies
- **Hubble observability** with per-flow L7 visibility (HTTP, gRPC, DNS, Kafka)
- **WireGuard transparent encryption** for pod-to-pod traffic across nodes
- **kube-proxy replacement** via eBPF service load balancing

The migration can be phased: start in CNI chaining mode (Cilium alongside VPC CNI), validate, then cut over to full Cilium IPAM. Hubble flow data feeds directly into ClawdStrike's Network Map plugin and AegisNet's attestation pipeline.

---

## 2. Cilium on EKS: Architecture and Migration

### 2.1 Current State

```
platform-dev EKS cluster
  CNI:        aws-vpc-cni-k8s (ENI-based IPAM)
  Proxy:      kube-proxy (iptables mode)
  Identity:   SPIRE 0.13.0 (trustDomain: aegis.local)
  Autoscaler: Karpenter 1.8.0
  LB:         aws-load-balancer-controller
  Gateway:    Envoy Gateway
  Monitoring: kube-prometheus-stack 81.2.0
```

### 2.2 Why Migrate

| Concern | VPC CNI | Cilium |
|---------|---------|--------|
| NetworkPolicy | Not natively supported (requires Calico addon) | Native L3-L7 via eBPF |
| L7 visibility | None | HTTP, gRPC, DNS, Kafka via Hubble |
| mTLS | Requires Istio/Linkerd sidecar | Native SPIFFE integration, no sidecars |
| Encryption | Not built-in | WireGuard transparent encryption |
| IP exhaustion | 1 ENI IP per pod, VPC CIDR pressure | Overlay mode avoids ENI limits |
| kube-proxy | iptables rules scale O(n^2) | eBPF hash maps O(1) lookup |

### 2.3 Deployment Modes on EKS

**Mode A: CNI Chaining (recommended for migration)**

Cilium chains behind VPC CNI. VPC CNI handles IPAM and ENI management; Cilium attaches eBPF programs for policy enforcement and load balancing.

```bash
helm install cilium cilium/cilium --version 1.19.0 \
  --namespace kube-system \
  --set cni.chainingMode=aws-cni \
  --set cni.exclusive=false \
  --set enableIPv4Masquerade=false \
  --set routingMode=native
```

Pros: No change to IP allocation, ENI routing preserved, incremental rollout.
Cons: Some L7 features limited, no overlay mode, still consumes ENI IPs.

**Mode B: Full Cilium IPAM (BYOCNI overlay)**

Cilium replaces VPC CNI entirely. Uses overlay networking (VXLAN/Geneve) or native routing with Cilium IPAM.

```bash
# Create EKS cluster with --without-node-group first, disable default VPC CNI
# Then install Cilium as primary CNI

helm install cilium cilium/cilium --version 1.19.0 \
  --namespace kube-system \
  --set eni.enabled=true \
  --set ipam.mode=eni \
  --set egressMasqueradeInterfaces=eth0 \
  --set routingMode=native \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost=${API_SERVER_ENDPOINT} \
  --set k8sServicePort=443
```

Pros: Full feature set, kube-proxy replacement, overlay avoids IP exhaustion.
Cons: Requires node rotation, more invasive change.

### 2.4 Helm Values for EKS (Production-Ready)

```yaml
# cilium-values.yaml - Phase 1: Chaining mode
cni:
  chainingMode: aws-cni
  exclusive: false
  # Enable route MTU propagation for WireGuard
  enableRouteMTUForCNIChaining: true

routingMode: native
enableIPv4Masquerade: false

# kube-proxy replacement (optional in chaining, recommended)
kubeProxyReplacement: false  # Keep kube-proxy in chaining phase

# Hubble observability
hubble:
  enabled: true
  relay:
    enabled: true
  ui:
    enabled: true
  metrics:
    enabled:
      - dns
      - drop
      - tcp
      - flow
      - port-distribution
      - icmp
      - httpV2:exemplars=true;labelsContext=source_namespace,destination_namespace
    serviceMonitor:
      enabled: true  # Auto-discovered by our kube-prometheus-stack
  export:
    static:
      enabled: true
      filePath: /var/run/cilium/hubble/events.log
    fileMaxSizeMb: 50
    fileMaxBackups: 5

# SPIRE/SPIFFE mutual authentication
authentication:
  enabled: true
  mutual:
    spire:
      enabled: true
      install:
        enabled: false  # We already have SPIRE deployed via ArgoCD
      # Point to our existing SPIRE deployment
      serverAddress: spire-server.spire-system.svc:8081
      trustDomain: aegis.local

# WireGuard transparent encryption
encryption:
  enabled: true
  type: wireguard

# Node selector to match our Karpenter-managed nodes
nodeSelector:
  workload: cpu

# Tolerations for GPU nodes
tolerations:
  - key: workload
    operator: Equal
    value: gpu
    effect: NoSchedule

# Prometheus metrics
prometheus:
  enabled: true
  serviceMonitor:
    enabled: true

# Operator settings
operator:
  nodeSelector:
    workload: cpu
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true
```

### 2.5 Kubernetes Version Compatibility

The platform currently targets EKS. Cilium 1.19.x supports Kubernetes 1.27-1.32. EKS 1.34 (if targeting future versions) should be validated against the Cilium compatibility matrix at release time.

**Kernel requirements:**
- WireGuard: Linux 5.6+ (EKS Amazon Linux 2023 ships 6.1+)
- eBPF host routing: Linux 5.10+
- BPF-based kube-proxy replacement: Linux 4.19.57+

All EKS AMIs from Amazon Linux 2023 satisfy these requirements.

---

## 3. SPIRE + Cilium mTLS: Identity-Based Network Security

### 3.1 Current SPIRE Deployment

From `platform/infra/gitops/apps/platform/spire.yaml`:

```yaml
global:
  spire:
    trustDomain: aegis.local
    clusterName: cluster
  telemetry:
    prometheus:
      enabled: true
      podMonitor:
        enabled: true
```

SPIRE server runs on CPU nodes (`workload: cpu`), agents tolerate GPU nodes. The SPIFFE CSI driver mounts SVIDs into workload pods.

### 3.2 How Cilium Consumes SPIFFE Identities

Cilium's mutual authentication architecture:

```
                   SPIRE Server
                   (aegis.local)
                       |
            +---------+---------+
            |                   |
       SPIRE Agent         SPIRE Agent
       (node-1)            (node-2)
            |                   |
       Cilium Agent        Cilium Agent
            |                   |
     eBPF datapath         eBPF datapath
            |                   |
     Pod A (frontend)      Pod B (backend)
```

1. **Identity assignment**: Cilium agents get a common SPIFFE identity and request identities on behalf of workloads.
2. **SVID issuance**: SPIRE issues X.509 SVIDs (SPIFFE Verified Identity Documents) containing TLS keypairs.
3. **Policy enforcement**: When a CiliumNetworkPolicy requires `authentication.mode: "required"`, the eBPF datapath triggers a TLS handshake using the SPIFFE identities.
4. **No sidecars**: Unlike Istio/Linkerd, the mTLS handshake happens at the eBPF layer, not in a proxy container.

### 3.3 Mapping SPIFFE IDs to Cilium Security Identities

A Cilium Security Identity is a numeric label set hash assigned to pods sharing the same labels. SPIFFE IDs follow the format:

```
spiffe://aegis.local/ns/<namespace>/sa/<service-account>
```

Cilium maps its security identity to a SPIFFE ID, so a CiliumNetworkPolicy selecting by labels also validates the SPIFFE identity during mutual auth.

### 3.4 CiliumNetworkPolicy with Mutual Authentication

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: backend-api-mutual-auth
  namespace: aegisnet
spec:
  endpointSelector:
    matchLabels:
      app: aegisnet-api
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: aegisnet-witness
      authentication:
        mode: "required"
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: POST
                path: "/v1/attestations"
              - method: GET
                path: "/v1/flows.*"
```

This policy:
- Selects `aegisnet-api` pods as the target
- Only allows traffic from `aegisnet-witness` pods
- **Requires mutual authentication** via SPIFFE/SPIRE
- Restricts to specific HTTP methods and paths (L7)

### 3.5 Integration with Existing SPIRE Deployment

Since we already deploy SPIRE via ArgoCD (`spire.yaml`), we should NOT use Cilium's built-in SPIRE installation (`authentication.mutual.spire.install.enabled=false`). Instead, point Cilium to the existing SPIRE server:

```yaml
authentication:
  mutual:
    spire:
      enabled: true
      install:
        enabled: false
      serverAddress: spire-server.spire-system.svc:8081
      trustDomain: aegis.local
```

### 3.6 Limitations (Beta Feature)

- Mutual authentication is beta in Cilium 1.19
- Only validated with SPIRE (no other SPIFFE implementations tested)
- Cluster Mesh + mutual auth are not compatible yet
- Per-connection handshake and WireGuard integration are on the Cilium roadmap (TODO)
- External mTLS (outside the cluster) is not supported

---

## 4. Hubble Observability: Flow Data and Metrics

### 4.1 Architecture

```
Pod traffic
    |
    v
eBPF datapath (cilium-agent)
    |
    +---> Hubble ring buffer (per-node, in-memory)
    |         |
    |         +---> Hubble gRPC API (per-node)
    |         |         |
    |         |         +---> hubble observe CLI
    |         |         +---> Hubble Relay (cluster-wide aggregation)
    |         |                   |
    |         |                   +---> Hubble UI (service map)
    |         |                   +---> hubble-otel (OpenTelemetry export)
    |         |                   +---> Custom consumers (gRPC client)
    |         |
    |         +---> Hubble Exporter (file-based, per-node)
    |         |         |
    |         |         +---> /var/run/cilium/hubble/events.log
    |         |
    |         +---> Hubble Metrics (Prometheus endpoint)
    |                   |
    |                   +---> /metrics (port 9965)
    |
    v
Network (forwarded/dropped per policy)
```

### 4.2 Hubble Flow Data Model (Protobuf)

The canonical data model is defined in `cilium/api/v1/flow/flow.proto`:

```protobuf
message Flow {
  google.protobuf.Timestamp time = 1;
  string uuid = 34;
  Verdict verdict = 2;           // FORWARDED, DROPPED, AUDIT, REDIRECTED, ERROR, TRACED
  uint32 drop_reason = 3;
  Endpoint source = 8;
  Endpoint destination = 12;
  IP IP = 7;
  Layer4 l4 = 9;
  Layer7 l7 = 16;
  Ethernet ethernet = 6;
  EventType event_type = 10;
  string node_name = 18;
  bool is_reply = 20;
  TrafficDirection traffic_direction = 30;
  TraceContext trace_context = 33;
  string Summary = 100001;
}

message Endpoint {
  uint32 ID = 1;
  uint32 identity = 2;           // Cilium security identity
  string namespace = 3;
  repeated string labels = 4;    // "k8s:app=aegisnet-api"
  string pod_name = 5;
}

message IP {
  string source = 1;
  string destination = 2;
  IPVersion ipVersion = 3;
  bool encrypted = 4;
}

message Layer4 {
  oneof protocol {
    TCP TCP = 1;
    UDP UDP = 2;
    ICMPv4 ICMPv4 = 3;
    ICMPv6 ICMPv6 = 4;
    SCTP SCTP = 5;
  }
}

message Layer7 {
  L7FlowType type = 1;          // REQUEST, RESPONSE, SAMPLE
  uint64 latency_ns = 2;
  oneof record {
    DNS dns = 100;
    HTTP http = 101;
    Kafka kafka = 102;
  }
}
```

### 4.3 Example Flow JSON (hubble observe -o json)

```json
{
  "time": "2026-02-07T10:15:32.456789Z",
  "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "verdict": "FORWARDED",
  "ethernet": {
    "source": "0a:58:0a:f4:00:0e",
    "destination": "0a:58:0a:f4:00:1a"
  },
  "IP": {
    "source": "10.244.0.14",
    "destination": "10.244.0.26",
    "ipVersion": "IPv4",
    "encrypted": true
  },
  "l4": {
    "TCP": {
      "source_port": 48234,
      "destination_port": 8080,
      "flags": { "SYN": true }
    }
  },
  "source": {
    "ID": 1234,
    "identity": 56789,
    "namespace": "aegisnet",
    "labels": [
      "k8s:app=aegisnet-witness",
      "k8s:io.kubernetes.pod.namespace=aegisnet"
    ],
    "pod_name": "aegisnet-witness-7d8f9b6c4-x2k9p"
  },
  "destination": {
    "ID": 5678,
    "identity": 12345,
    "namespace": "aegisnet",
    "labels": [
      "k8s:app=aegisnet-api",
      "k8s:io.kubernetes.pod.namespace=aegisnet"
    ],
    "pod_name": "aegisnet-api-5c7d8e9f1-m3n4o"
  },
  "l7": {
    "type": "REQUEST",
    "latency_ns": 0,
    "http": {
      "method": "POST",
      "url": "/v1/attestations",
      "protocol": "HTTP/2.0",
      "headers": [
        { "key": "content-type", "value": "application/json" }
      ]
    }
  },
  "event_type": { "type": 129 },
  "node_name": "ip-10-0-1-42",
  "is_reply": false,
  "traffic_direction": "INGRESS",
  "trace_context": {
    "parent": {
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
    }
  },
  "Summary": "HTTP/2.0 POST http://aegisnet-api:8080/v1/attestations"
}
```

### 4.4 L7 Protocol Visibility

| Protocol | Hubble Metric | Details |
|----------|---------------|---------|
| HTTP/1.1, HTTP/2 | `httpV2` | Method, URL, status code, latency, headers |
| gRPC | `httpV2` (gRPC over HTTP/2) | Service, method, status code |
| DNS | `dns` | Query name, types, response codes, IPs |
| Kafka | `kafka` | Topic, API key, correlation ID |
| TCP | `tcp` | Flags (SYN/ACK/FIN/RST), connection state |
| UDP | N/A | Source/dest ports, packet counts |
| ICMP | `icmp` | Type, code |

### 4.5 Hubble Relay Architecture

Hubble Relay is a standalone component that connects to all Cilium agents' gRPC APIs and provides a unified cluster-wide view:

```
                    Hubble UI / CLI / Custom Client
                              |
                         gRPC (4245)
                              |
                       Hubble Relay
                      /      |       \
               gRPC    gRPC     gRPC
               /          |          \
        cilium-agent  cilium-agent  cilium-agent
        (node-1)      (node-2)      (node-3)
```

Relay is deployed as a Kubernetes Deployment (not DaemonSet). It discovers Cilium agents via Kubernetes peer discovery.

### 4.6 Export to Prometheus / OTLP / NATS

**Prometheus (built-in):**

Hubble exposes metrics on port 9965 (`/metrics`). Our existing `kube-prometheus-stack` (monitoring.yaml) auto-discovers ServiceMonitors:

```yaml
hubble:
  metrics:
    enabled:
      - dns
      - drop
      - tcp
      - flow
      - port-distribution
      - icmp
      - httpV2:exemplars=true;labelsContext=source_namespace,destination_namespace
    serviceMonitor:
      enabled: true
```

Key metrics:
- `hubble_flows_processed_total` - Total flows by type, verdict, namespace
- `hubble_drop_total` - Dropped packets by reason
- `hubble_dns_queries_total` - DNS queries by query type, response code
- `hubble_http_requests_total` - HTTP requests by method, status, source/dest namespace
- `hubble_tcp_flags_total` - TCP flag counts

**OpenTelemetry (hubble-otel):**

The `hubble-otel` project converts Hubble flows to OTLP traces and logs:

```yaml
# otel-collector-config.yaml
receivers:
  hubble:
    endpoint: hubble-relay.kube-system.svc:4245
    tls:
      insecure: true
    buffer_size: 10000

processors:
  batch:
    timeout: 5s
    send_batch_size: 1000

exporters:
  otlp/jaeger:
    endpoint: jaeger-collector.monitoring.svc:4317
    tls:
      insecure: true
  # NATS exporter for AegisNet
  nats:
    url: nats://aegisnet-nats.aegisnet.svc:4222
    subject: "aegisnet.hubble.flows"
    encoding: json

service:
  pipelines:
    traces:
      receivers: [hubble]
      processors: [batch]
      exporters: [otlp/jaeger]
    logs:
      receivers: [hubble]
      processors: [batch]
      exporters: [nats]
```

**NATS JetStream (via file export + Fluent Bit):**

For direct integration with our existing NATS JetStream (`aegisnet-nats`):

```yaml
# fluent-bit configmap
[INPUT]
    Name        tail
    Path        /var/run/cilium/hubble/events.log
    Parser      json
    Tag         hubble.flows
    Refresh_Interval 1

[OUTPUT]
    Name        nats
    Match       hubble.flows
    Server      aegisnet-nats.aegisnet.svc
    Port        4222
    Subject     aegisnet.hubble.flows
```

---

## 5. CiliumNetworkPolicy: L3/L4/L7 Microsegmentation

### 5.1 Comparison: CiliumNetworkPolicy vs Kubernetes NetworkPolicy

| Feature | CiliumNetworkPolicy | K8s NetworkPolicy |
|---------|---------------------|-------------------|
| L3/L4 ingress/egress | Yes | Yes |
| L7 (HTTP, gRPC, DNS, Kafka) | Yes | No |
| FQDN-based egress | Yes (`toFQDNs`) | No |
| DNS query filtering | Yes (`matchName`, `matchPattern`) | No |
| Identity-based (labels, not IPs) | Yes | Partially (labels, but no cross-NS) |
| Deny policies | Yes (`egressDeny`, `ingressDeny`) | No |
| Entity selectors | Yes (`world`, `host`, `kube-apiserver`) | No |
| Host/node policies | Yes (`CiliumClusterwideNetworkPolicy`) | No |
| Mutual authentication | Yes (`authentication.mode`) | No |
| Audit mode | Yes (policy audit) | No |
| Port ranges | Yes (`endPort`) | Yes (K8s 1.25+) |

### 5.2 Identity-Based Selectors

Cilium assigns a security identity (numeric hash) to each unique label set. Policies select by labels, and enforcement happens via identity lookup in eBPF maps -- not IP-based iptables rules. This means policies survive pod rescheduling, IP changes, and scale events without any reconfiguration.

### 5.3 Concrete Policy Examples for the Platform

**Example 1: Namespace isolation (AegisNet)**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: aegisnet-namespace-isolation
  namespace: aegisnet
spec:
  endpointSelector: {}  # All pods in aegisnet namespace
  ingress:
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: aegisnet
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app: prometheus
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: aegisnet
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
```

**Example 2: L7 API gateway policy**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: api-gateway-l7
  namespace: aegisnet
spec:
  endpointSelector:
    matchLabels:
      app: aegisnet-api
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: envoy-gateway
      authentication:
        mode: "required"
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: GET
                path: "/v1/flows"
              - method: POST
                path: "/v1/attestations"
              - method: GET
                path: "/healthz"
```

**Example 3: FQDN-based egress for external APIs**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-external-apis
  namespace: aegisnet
spec:
  endpointSelector:
    matchLabels:
      app: aegisnet-witness
  egress:
    # Allow DNS resolution
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
          rules:
            dns:
              - matchPattern: "*.amazonaws.com"
              - matchName: "sts.us-east-1.amazonaws.com"
    # Allow HTTPS to AWS services
    - toFQDNs:
        - matchPattern: "*.amazonaws.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
```

**Example 4: DNS-aware policy with deny**

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: restrict-external-egress
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: worker
  egress:
    - toEntities:
        - cluster
    - toFQDNs:
        - matchPattern: "*.backbay.io"
        - matchName: "api.github.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
  egressDeny:
    - toEntities:
        - world
```

**Example 5: Host-level firewall (CiliumClusterwideNetworkPolicy)**

```yaml
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: node-lockdown
spec:
  description: "Restrict node-level ingress to required ports"
  nodeSelector:
    matchLabels:
      workload: cpu
  ingress:
    - fromEntities:
        - remote-node
        - health
    - toPorts:
        - ports:
            - port: "22"
              protocol: TCP
            - port: "10250"
              protocol: TCP
            - port: "4240"
              protocol: TCP
            - port: "51871"
              protocol: UDP
```

### 5.4 Audit Mode for Safe Rollout

Cilium supports policy audit mode where policies are logged but not enforced. This is critical for the migration:

```bash
# Enable audit mode globally
cilium config set policy-audit-mode enabled

# Check audit events
hubble observe --verdict AUDIT
```

Per-policy audit is not yet available; it's a global toggle. The CNCF blog (Nov 2025) recommends using `L7 allow-all scaffolding` during migration to capture traffic patterns before tightening policies.

---

## 6. WireGuard Transparent Encryption

### 6.1 How It Works

Cilium creates a WireGuard tunnel interface (`cilium_wg0`) on each node. Each node automatically generates an encryption keypair and publishes its public key via the `CiliumNode` custom resource annotation `network.cilium.io/wg-pub-key`.

```
Pod A (node-1)                       Pod B (node-2)
    |                                     |
    v                                     v
cilium eBPF                          cilium eBPF
    |                                     |
    v                                     v
cilium_wg0 ----[WireGuard tunnel]----> cilium_wg0
  (encrypt)     UDP port 51871        (decrypt)
    |                                     |
    v                                     v
eth0 (ENI)                           eth0 (ENI)
```

### 6.2 What Gets Encrypted

| Traffic Path | Encrypted? |
|-------------|------------|
| Pod-to-pod (different nodes) | Yes |
| Pod-to-pod (same node) | No (raw traffic observable on-host) |
| Pod-to-node (with nodeEncryption=true) | Yes (beta) |
| Node-to-node (with nodeEncryption=true) | Yes (beta) |
| External client to pod | No |
| Control plane node traffic | No (auto opt-out) |

### 6.3 EKS Configuration

```yaml
# In cilium-values.yaml
encryption:
  enabled: true
  type: wireguard
  # Node-to-node encryption (beta)
  # nodeEncryption: true

# Critical for EKS with VPC CNI chaining:
cni:
  enableRouteMTUForCNIChaining: true
```

**MTU considerations**: WireGuard adds 60 bytes overhead (40 IPv6 header + 8 UDP + 4 WireGuard + 16 MAC). On EKS with Jumbo Frames (MTU 9001), set pod MTU to `9001 - 60 = 8941`. Without the `enableRouteMTUForCNIChaining` setting, pods may experience fragmentation and degraded performance.

In one reported EKS deployment, network throughput dropped from 4.6 Gbps to 80 Mbps due to incorrect MTU. After setting MTU below 8928, throughput recovered to 3.5 Gbps.

### 6.4 Key Rotation

WireGuard keys are automatically rotated by Cilium. Each node generates a new keypair and updates the `CiliumNode` annotation. Other nodes discover the new public key and update their WireGuard peer configuration. No manual intervention required.

### 6.5 Performance Overhead

Based on benchmarks and reported production deployments:

- **Throughput**: ~5-15% reduction with WireGuard on EKS (varies by instance type)
- **Latency**: ~10-50 microseconds additional per packet
- **CPU**: WireGuard uses ChaCha20-Poly1305, highly efficient with kernel crypto
- **Key consideration**: Avoid tunnel mode + WireGuard (double encapsulation); use native routing mode

---

## 7. Network Map Data Source for ClawdStrike

### 7.1 Current State

ClawdStrike's `NetworkMapView` (`features/network-map/NetworkMapView.tsx`) currently uses hardcoded mock data:

```typescript
const MOCK_NODES: NetworkNode[] = [
  { id: "fw-1", type: "firewall", hostname: "edge-fw-01", ip: "10.0.0.1", status: "healthy", ... },
  // 12 static nodes
];

const MOCK_EDGES: NetworkEdge[] = [
  { id: "e1", source: "fw-1", target: "rt-1", protocol: "tcp", bandwidth: 8000, encrypted: true, ... },
  // 14 static edges
];
```

The view renders a 3D R3F (React Three Fiber) canvas with `@backbay/glia` `NetworkTopology`, `GlassPanel`, and `Badge` components.

### 7.2 Hubble Flow Data as Network Map Source

Hubble flow data maps directly to the existing `NetworkNode` and `NetworkEdge` types:

```typescript
// Mapping Hubble Flow -> NetworkNode
interface HubbleEndpoint {
  ID: number;
  identity: number;
  namespace: string;
  labels: string[];
  pod_name: string;
}

function hubbleEndpointToNetworkNode(ep: HubbleEndpoint, ip: string): NetworkNode {
  const type = inferNodeType(ep.labels); // "server" | "firewall" | "cloud" etc.
  return {
    id: `${ep.namespace}/${ep.pod_name}`,
    type,
    hostname: ep.pod_name,
    ip,
    status: "healthy",   // Derived from verdict aggregation
    services: extractServices(ep.labels),
    vulnerabilities: 0,  // Cross-reference with ClawdStrike guard data
  };
}

// Mapping Hubble Flow -> NetworkEdge
function hubbleFlowToNetworkEdge(flow: HubbleFlow): NetworkEdge {
  return {
    id: flow.uuid,
    source: `${flow.source.namespace}/${flow.source.pod_name}`,
    target: `${flow.destination.namespace}/${flow.destination.pod_name}`,
    protocol: extractProtocol(flow.l4),
    port: extractPort(flow.l4),
    bandwidth: 0,       // Aggregate from flow rate
    encrypted: flow.IP.encrypted,
    status: verdictToStatus(flow.verdict),
  };
}
```

### 7.3 Real-Time Data Pipeline

```
Hubble Relay (gRPC stream)
    |
    v
WebSocket gateway (BFF or dedicated service)
    |
    v
ClawdStrike Desktop App (Tauri IPC)
    |
    v
NetworkMapView (React state -> R3F canvas)
```

**Option A: Hubble Relay gRPC -> WebSocket bridge**

Deploy a lightweight service that streams from Hubble Relay's gRPC API and translates to WebSocket frames:

```
hubble-relay:4245 --gRPC--> ws-bridge:8080 --WebSocket--> ClawdStrike
```

**Option B: NATS JetStream consumer**

ClawdStrike subscribes to the `aegisnet.hubble.flows` NATS subject (populated by the Hubble export pipeline from Section 4.6):

```
Hubble Exporter -> NATS JetStream -> ClawdStrike NATS client
```

**Option C: REST polling with aggregation**

A backend service aggregates Hubble flows into a topology snapshot, served via REST:

```
GET /api/v1/network-map/topology
{
  "nodes": [...],
  "edges": [...],
  "last_updated": "2026-02-07T10:15:32Z"
}
```

### 7.4 Topology Discovery

Hubble automatically discovers service dependencies at L3/L4/L7. By aggregating flows over a time window, we can build a live topology:

1. **Node discovery**: Each unique `(namespace, pod_name)` pair becomes a node
2. **Edge discovery**: Each unique `(source, destination, protocol, port)` tuple becomes an edge
3. **Status inference**: Aggregate verdicts -- if >5% DROPPED, mark edge as "suspicious"
4. **Bandwidth estimation**: Count bytes per flow per second
5. **Encryption status**: `flow.IP.encrypted` indicates WireGuard encryption

### 7.5 Data Model Extension

The current `NetworkNode` type in `@backbay/glia` could be extended with Cilium-specific fields:

```typescript
interface CiliumNetworkNode extends NetworkNode {
  ciliumIdentity: number;     // Cilium security identity
  namespace: string;
  labels: Record<string, string>;
  spiffeId?: string;          // spiffe://aegis.local/ns/xxx/sa/yyy
  policyVerdict?: "allowed" | "denied" | "audited";
}

interface CiliumNetworkEdge extends NetworkEdge {
  l7?: {
    type: "HTTP" | "gRPC" | "DNS" | "Kafka";
    latency_ms?: number;
    status_code?: number;
    method?: string;
    path?: string;
  };
  authentication?: {
    mode: "required" | "disabled";
    verified: boolean;
  };
  verdict: "FORWARDED" | "DROPPED" | "AUDIT" | "ERROR";
}
```

---

## 8. AegisNet Integration

### 8.1 Current AegisNet Architecture

AegisNet is the security/trust surface of Backbay, comprising:

- **aegisnet-witness**: Attestation service that signs security events
- **aegisnet-api**: REST API for querying attestations and flows
- **aegisnet-nats** (NATS JetStream): Event backbone for the AegisNet plane
- **Prometheus + Grafana**: Metrics and dashboards (via `monitoring.yaml`)

NATS JetStream runs as a 3-replica cluster in the `aegisnet` namespace with 50Gi persistent storage per node.

### 8.2 Hubble Flows as Attestable Events

The key insight: **Hubble flow logs are cryptographically verifiable evidence of network communication patterns**. Combined with ClawdStrike receipts (Ed25519-signed attestations), they create a chain of trust:

```
Network event occurs
    |
    v
Cilium eBPF captures flow (kernel-level, tamper-resistant)
    |
    v
Hubble exports flow to NATS JetStream
    |
    v
aegisnet-witness receives flow
    |
    v
aegisnet-witness creates attestation:
  - Signs flow data with Ed25519
  - Includes CiliumNetworkPolicy that governed the flow
  - Includes SPIFFE identity of source and destination
  - Includes timestamp and node attestation
    |
    v
Attestation stored as ClawdStrike receipt (HushEngine)
```

### 8.3 NATS Subject Schema

```
aegisnet.hubble.flows              # Raw Hubble flows
aegisnet.hubble.flows.dropped      # Dropped packets only
aegisnet.hubble.flows.l7           # L7 (HTTP/gRPC/DNS) flows
aegisnet.hubble.policies           # Policy verdict changes
aegisnet.attestations.network      # Signed network attestations
```

### 8.4 Observability Dashboards

Hubble metrics feed into our existing kube-prometheus-stack. Grafana dashboards to create:

1. **Network Policy Enforcement**: `hubble_drop_total` by reason, namespace, source/dest labels
2. **Service Topology**: Service-to-service traffic map using `hubble_flows_processed_total`
3. **L7 API Performance**: HTTP latency percentiles from `hubble_http_requests_total`
4. **DNS Health**: Query volume, failure rates from `hubble_dns_queries_total`
5. **Encryption Coverage**: Percentage of flows with `encrypted=true`
6. **Attestation Pipeline**: Flow rate through NATS -> aegisnet-witness -> receipt store

Pre-built Grafana dashboards are available:
- [Hubble Network Overview (Namespace)](https://grafana.com/grafana/dashboards/19424) - Dashboard ID 19424
- [Cilium v1.12 Hubble Metrics](https://grafana.com/grafana/dashboards/16613) - Dashboard ID 16613

---

## 9. Microsegmentation with Receipts

### 9.1 The Trust Model

The combination of Cilium + AegisNet + ClawdStrike creates a three-layer trust model:

1. **Enforcement layer** (Cilium): eBPF programs enforce network policies at the kernel level. This is the actual access control.
2. **Observation layer** (Hubble): eBPF captures all network events regardless of policy decisions. This provides tamper-resistant evidence.
3. **Attestation layer** (AegisNet/ClawdStrike): Signs and verifies that enforcement matches policy intent. This provides cryptographic proof.

### 9.2 Receipt Structure for Network Events

```rust
// ClawdStrike receipt for a network policy enforcement event
struct NetworkPolicyReceipt {
    // Standard HushEngine receipt fields
    receipt_id: String,
    timestamp: DateTime<Utc>,
    signature: Ed25519Signature,

    // Network-specific evidence
    policy: NetworkPolicyEvidence,
    flow: FlowEvidence,
    attestation: AttestationEvidence,
}

struct NetworkPolicyEvidence {
    policy_name: String,           // "aegisnet-namespace-isolation"
    policy_namespace: String,      // "aegisnet"
    policy_hash: Sha256Hash,       // Hash of the CiliumNetworkPolicy YAML
    policy_generation: u64,        // K8s generation number
}

struct FlowEvidence {
    hubble_flow_uuid: String,
    verdict: String,               // "FORWARDED" | "DROPPED"
    source_identity: u32,          // Cilium security identity
    destination_identity: u32,
    source_spiffe_id: String,      // spiffe://aegis.local/ns/aegisnet/sa/witness
    destination_spiffe_id: String,
    protocol: String,
    port: u16,
    encrypted: bool,
    node_name: String,
}

struct AttestationEvidence {
    witness_identity: String,      // SPIFFE ID of the attestor
    attestation_time: DateTime<Utc>,
    merkle_root: Keccak256Hash,    // Merkle root of flow batch
}
```

### 9.3 Detecting Policy Bypass

By comparing Hubble flow data against CiliumNetworkPolicy specs, AegisNet can detect:

- **Flows that should have been dropped but weren't** (policy enforcement gap)
- **Flows from identities that shouldn't exist** (identity spoofing attempt)
- **Unencrypted flows when WireGuard should be active** (encryption bypass)
- **L7 requests to paths not in the policy** (policy spec drift)

This creates an independent verification channel: even if an attacker compromises the eBPF datapath, the Hubble observation layer (running in a different code path) would capture the anomalous flows.

---

## 10. Migration Strategy

### 10.1 Phased Approach

```
Phase 0: Prepare (1 week)
    |
    v
Phase 1: Chaining Mode (2-3 weeks)
    |
    v
Phase 2: Network Policies (2-3 weeks)
    |
    v
Phase 3: Mutual Auth + WireGuard (2-3 weeks)
    |
    v
Phase 4: Full Cilium IPAM (optional, 2-3 weeks)
```

### Phase 0: Preparation

1. **Audit existing network policies**: Document all SecurityGroups, NACLs, and any Calico policies
2. **Inventory services**: Map all service-to-service communication patterns (use VPC Flow Logs as baseline)
3. **Validate kernel versions**: Ensure all EKS AMIs are Amazon Linux 2023 (kernel 6.1+)
4. **Create rollback plan**: Tag current working cluster state, document VPC CNI version

```bash
# Verify kernel version on EKS nodes
kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo.kernelVersion}'

# Verify current VPC CNI version
kubectl -n kube-system get ds/aws-node -o jsonpath='{.spec.template.spec.containers[0].image}'
```

### Phase 1: Install Cilium in Chaining Mode

1. Deploy Cilium via ArgoCD (new Application resource):

```yaml
# platform/infra/gitops/apps/platform/cilium.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: cilium
  namespace: argocd
  annotations:
    argocd.argoproj.io/sync-wave: "0"
spec:
  project: default
  source:
    repoURL: https://helm.cilium.io
    chart: cilium
    targetRevision: 1.19.0
    helm:
      valueFiles:
        - values-eks-chaining.yaml
  destination:
    server: https://kubernetes.default.svc
    namespace: kube-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

2. **Validate**: Run `cilium status --wait` and `cilium connectivity test`
3. **Enable Hubble**: Confirm flow visibility with `hubble observe`
4. **Restart all pods**: Required for chaining to take effect on existing workloads

```bash
# Rolling restart all deployments
kubectl get deployments --all-namespaces -o json | \
  jq -r '.items[] | "\(.metadata.namespace) \(.metadata.name)"' | \
  while read ns name; do
    kubectl -n "$ns" rollout restart deployment "$name"
  done
```

### Phase 2: Deploy Network Policies

1. **Enable audit mode**: `cilium config set policy-audit-mode enabled`
2. **Deploy policies in audit mode**: Apply CiliumNetworkPolicies from Section 5.3
3. **Monitor audit events**: `hubble observe --verdict AUDIT`
4. **Analyze traffic patterns**: Use Hubble UI service map to validate policies match actual traffic
5. **Switch to enforcement**: `cilium config set policy-audit-mode disabled`
6. **Monitor for drops**: `hubble observe --verdict DROPPED`

### Phase 3: Enable Mutual Auth + WireGuard

1. **Update Cilium values** to enable mutual auth pointing to existing SPIRE
2. **Deploy CiliumNetworkPolicies with `authentication.mode: required`** on critical paths first (aegisnet-witness -> aegisnet-api)
3. **Enable WireGuard encryption**: Update Cilium values with `encryption.enabled=true`
4. **Verify encryption**: `hubble observe -o json | jq '.IP.encrypted'` should show `true` for cross-node flows
5. **Validate MTU**: Run iperf3 between pods on different nodes, verify throughput

### Phase 4: Full Cilium IPAM (Optional)

Only if VPC IP exhaustion is a concern:

1. Create new Karpenter NodePool with Cilium IPAM labels
2. Cordon old nodes
3. Let Karpenter provision new nodes with Cilium as primary CNI
4. Drain old nodes
5. Remove VPC CNI DaemonSet and kube-proxy DaemonSet

### 10.2 Rollback Plan

**Chaining mode rollback**: Simply uninstall Cilium Helm release. VPC CNI continues operating independently.

```bash
helm uninstall cilium -n kube-system
# Rolling restart pods to remove eBPF programs
kubectl get deployments --all-namespaces -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name' --no-headers | \
  while read ns name; do kubectl -n "$ns" rollout restart deployment "$name"; done
```

**Full IPAM rollback**: More involved -- requires reinstalling VPC CNI, rotating nodes, and restarting all workloads. This is why Phase 4 should only be attempted after extensive validation.

### 10.3 Impact on Existing Infrastructure

| Component | Impact | Notes |
|-----------|--------|-------|
| Karpenter | Low | Cilium DaemonSet auto-deploys on new nodes. No changes to NodePool/EC2NodeClass needed. |
| aws-load-balancer-controller | Low | Compatible with Cilium in chaining mode. Test NLB/ALB health checks. |
| Envoy Gateway | Low | Envoy sits above the CNI layer. L7 policies may overlap -- coordinate with Gateway API routes. |
| SPIRE | Medium | Cilium needs to connect to existing SPIRE server. Validate trust domain and registration entries. |
| NATS JetStream | None | Application-layer, unaffected by CNI change. |
| kube-prometheus-stack | Low | Add Hubble ServiceMonitor for new metrics. |
| ArgoCD | None | Deploying Cilium as another ArgoCD Application. |

---

## 11. Open Questions and Risk Assessment

### 11.1 Performance Impact on EKS

**Question**: What is the real-world performance impact of Cilium on EKS with our workload profile (mixed CPU/GPU, Karpenter-managed nodes, NATS messaging)?

**Research findings**:
- AWS VPC CNI has the lowest raw latency in non-mTLS scenarios
- Cilium in chaining mode adds ~10-50us per packet for eBPF processing
- WireGuard adds ~5-15% throughput overhead (ChaCha20-Poly1305)
- Pod creation is actually faster with Cilium (no ENI API calls)
- The hybrid approach (Cilium + VPC CNI chaining) is a good middle ground

**Recommendation**: Benchmark with our actual workloads in a staging cluster before production rollout. Key metrics: HTTP P99 latency, NATS message throughput, pod startup time.

### 11.2 Cilium kube-proxy Replacement + aws-load-balancer-controller

**Question**: Does Cilium's kube-proxy replacement affect aws-load-balancer-controller?

**Research findings**:
- In chaining mode (Phase 1-3), keep kube-proxy. No impact on LB controller.
- In full replacement mode (Phase 4), Cilium's eBPF handles service routing. The LB controller creates NLB/ALB target groups pointing to node ports -- this still works because Cilium's eBPF service maps handle the nodePort -> pod routing.
- One reported issue: Gateway API + Cilium kube-proxy replacement on EKS had Envoy proxy issues (cilium/cilium#33967). Monitor this.

**Recommendation**: Keep kube-proxy during Phases 1-3. Only remove kube-proxy in Phase 4 after extensive testing.

### 11.3 Cilium + Karpenter Node Provisioning

**Question**: How does Cilium interact with Karpenter's rapid node provisioning?

**Research findings**:
- Cilium runs as a DaemonSet. When Karpenter provisions a new node, the Cilium agent pod is scheduled and initializes the eBPF datapath.
- Cilium initialization takes 2-5 seconds on a fresh node. During this window, pods scheduled on the node may have no network connectivity.
- The `cilium-agent` pod has a readiness probe. Karpenter does not wait for DaemonSet pods specifically, but the kubelet won't mark the node as Ready until critical DaemonSets (including CNI) are running.

**Recommendation**: Add a startup probe to the Cilium DaemonSet. Consider adding a Karpenter `startupTaint` that Cilium removes after initialization:

```yaml
# In EC2NodeClass
spec:
  kubelet:
    startupTaints:
      - key: node.cilium.io/agent-not-ready
        effect: NoExecute
```

Cilium automatically removes this taint when the agent is ready.

### 11.4 Hubble Storage and Retention

**Question**: How much storage do Hubble flow logs consume?

**Estimate**: At 1000 flows/second cluster-wide, with ~500 bytes per JSON flow:
- Per second: 500 KB
- Per hour: 1.8 GB
- Per day: 43 GB
- Per week: 300 GB

**Recommendation**: Use field masking to reduce flow size, filter to relevant namespaces (aegisnet, default), and set aggressive rotation (50MB max per node, 5 backups). For long-term storage, compress and ship to S3 via Fluent Bit.

### 11.5 Multi-Cluster / Cluster Mesh

**Question**: If we expand to multiple EKS clusters, does Cilium support cross-cluster communication?

**Limitation**: Cilium Cluster Mesh is NOT compatible with mutual authentication (SPIRE) as of Cilium 1.19. This means cross-cluster mTLS via Cilium is not possible today. If multi-cluster is needed, use NATS JetStream for cross-cluster messaging (already deployed) and handle mTLS at the application layer.

### 11.6 Risk Matrix

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Pod connectivity loss during migration | Medium | High | Chaining mode preserves VPC CNI as fallback |
| MTU misconfiguration with WireGuard | Medium | High | Set `enableRouteMTUForCNIChaining=true`, test with iperf3 |
| SPIRE integration failure | Low | Medium | Cilium can operate without mutual auth; disable auth feature flag |
| Performance regression | Low | Medium | Benchmark in staging; chaining mode has minimal overhead |
| Karpenter node bootstrap delay | Low | Low | Cilium startup taint ensures no pods scheduled before CNI ready |
| Hubble storage exhaustion | Low | Low | File rotation + field masks + namespace filtering |
| aws-load-balancer-controller incompatibility | Low | High | Keep kube-proxy in Phases 1-3; test thoroughly before Phase 4 |

---

## Appendix A: Complete ArgoCD Application for Cilium

```yaml
# platform/infra/gitops/apps/platform/cilium.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: cilium
  namespace: argocd
  annotations:
    argocd.argoproj.io/sync-wave: "0"
spec:
  project: default
  source:
    repoURL: https://helm.cilium.io
    chart: cilium
    targetRevision: 1.19.0
    helm:
      values: |
        cni:
          chainingMode: aws-cni
          exclusive: false
          enableRouteMTUForCNIChaining: true
        routingMode: native
        enableIPv4Masquerade: false
        kubeProxyReplacement: false
        hubble:
          enabled: true
          relay:
            enabled: true
          ui:
            enabled: true
          metrics:
            enabled:
              - dns
              - drop
              - tcp
              - flow
              - port-distribution
              - icmp
              - "httpV2:exemplars=true;labelsContext=source_namespace,destination_namespace"
            serviceMonitor:
              enabled: true
          export:
            static:
              enabled: true
              filePath: /var/run/cilium/hubble/events.log
              fieldMask:
                - time
                - source.namespace
                - source.pod_name
                - source.identity
                - destination.namespace
                - destination.pod_name
                - destination.identity
                - IP
                - l4
                - l7
                - verdict
                - drop_reason_desc
                - traffic_direction
                - is_reply
                - Summary
              denyList:
                - '{"source_pod":["kube-system/"]}'
            fileMaxSizeMb: 50
            fileMaxBackups: 5
        authentication:
          enabled: true
          mutual:
            spire:
              enabled: true
              install:
                enabled: false
              serverAddress: spire-server.spire-system.svc:8081
              trustDomain: aegis.local
        encryption:
          enabled: true
          type: wireguard
        nodeSelector:
          workload: cpu
        tolerations:
          - key: workload
            operator: Equal
            value: gpu
            effect: NoSchedule
        operator:
          nodeSelector:
            workload: cpu
        prometheus:
          enabled: true
          serviceMonitor:
            enabled: true
  destination:
    server: https://kubernetes.default.svc
    namespace: kube-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

## Appendix B: Hubble Flow to ClawdStrike Adapter (TypeScript)

```typescript
/**
 * Adapter: Hubble Flow JSON -> ClawdStrike NetworkNode/NetworkEdge
 *
 * This module processes Hubble flow events from NATS JetStream
 * and maintains a live topology model for the Network Map plugin.
 */

import type { NetworkNode, NetworkEdge } from "@backbay/glia/primitives";

// --- Hubble Flow Types (subset of flow.proto) ---

interface HubbleFlow {
  time: string;
  uuid: string;
  verdict: "FORWARDED" | "DROPPED" | "AUDIT" | "REDIRECTED" | "ERROR" | "TRACED";
  drop_reason_desc?: string;
  source: HubbleEndpoint;
  destination: HubbleEndpoint;
  IP: { source: string; destination: string; ipVersion: string; encrypted: boolean };
  l4?: {
    TCP?: { source_port: number; destination_port: number; flags?: Record<string, boolean> };
    UDP?: { source_port: number; destination_port: number };
  };
  l7?: {
    type: "REQUEST" | "RESPONSE" | "SAMPLE";
    latency_ns: number;
    http?: { method: string; url: string; protocol: string; code?: number };
    dns?: { query: string; rrtypes: string[]; rcode: string };
    kafka?: { topic: string; api_key: string };
  };
  event_type: { type: number };
  node_name: string;
  is_reply: boolean;
  traffic_direction: "INGRESS" | "EGRESS";
  Summary: string;
}

interface HubbleEndpoint {
  ID: number;
  identity: number;
  namespace: string;
  labels: string[];
  pod_name: string;
}

// --- Topology State ---

interface TopologyState {
  nodes: Map<string, NetworkNode & { lastSeen: number; flowCount: number }>;
  edges: Map<string, NetworkEdge & { lastSeen: number; flowCount: number; verdicts: Record<string, number> }>;
}

function createTopologyState(): TopologyState {
  return { nodes: new Map(), edges: new Map() };
}

function nodeKey(ep: HubbleEndpoint): string {
  return `${ep.namespace}/${ep.pod_name}`;
}

function edgeKey(flow: HubbleFlow): string {
  const src = nodeKey(flow.source);
  const dst = nodeKey(flow.destination);
  const port = flow.l4?.TCP?.destination_port ?? flow.l4?.UDP?.destination_port ?? 0;
  const proto = flow.l4?.TCP ? "tcp" : flow.l4?.UDP ? "udp" : "unknown";
  return `${src}->${dst}:${proto}/${port}`;
}

function inferNodeType(labels: string[]): NetworkNode["type"] {
  const labelStr = labels.join(",");
  if (labelStr.includes("gateway") || labelStr.includes("ingress")) return "firewall";
  if (labelStr.includes("router") || labelStr.includes("proxy")) return "router";
  if (labelStr.includes("iot") || labelStr.includes("sensor")) return "iot";
  return "server";
}

function inferStatus(verdicts: Record<string, number>): NetworkEdge["status"] {
  const total = Object.values(verdicts).reduce((a, b) => a + b, 0);
  const dropped = verdicts["DROPPED"] ?? 0;
  if (dropped / total > 0.1) return "suspicious";
  if (total === 0) return "idle";
  return "active";
}

function processFlow(state: TopologyState, flow: HubbleFlow): void {
  const now = Date.now();

  // Upsert source node
  const srcKey = nodeKey(flow.source);
  if (!state.nodes.has(srcKey)) {
    state.nodes.set(srcKey, {
      id: srcKey,
      type: inferNodeType(flow.source.labels),
      hostname: flow.source.pod_name,
      ip: flow.IP.source,
      status: "healthy",
      services: [],
      vulnerabilities: 0,
      lastSeen: now,
      flowCount: 0,
    });
  }
  const srcNode = state.nodes.get(srcKey)!;
  srcNode.lastSeen = now;
  srcNode.flowCount++;

  // Upsert destination node
  const dstKey = nodeKey(flow.destination);
  if (!state.nodes.has(dstKey)) {
    state.nodes.set(dstKey, {
      id: dstKey,
      type: inferNodeType(flow.destination.labels),
      hostname: flow.destination.pod_name,
      ip: flow.IP.destination,
      status: "healthy",
      services: [],
      vulnerabilities: 0,
      lastSeen: now,
      flowCount: 0,
    });
  }
  const dstNode = state.nodes.get(dstKey)!;
  dstNode.lastSeen = now;
  dstNode.flowCount++;

  // Upsert edge
  const ek = edgeKey(flow);
  if (!state.edges.has(ek)) {
    state.edges.set(ek, {
      id: ek,
      source: srcKey,
      target: dstKey,
      protocol: flow.l4?.TCP ? "tcp" : flow.l4?.UDP ? "udp" : "unknown",
      port: flow.l4?.TCP?.destination_port ?? flow.l4?.UDP?.destination_port,
      bandwidth: 0,
      encrypted: flow.IP.encrypted,
      status: "active",
      lastSeen: now,
      flowCount: 0,
      verdicts: {},
    });
  }
  const edge = state.edges.get(ek)!;
  edge.lastSeen = now;
  edge.flowCount++;
  edge.encrypted = flow.IP.encrypted;
  edge.verdicts[flow.verdict] = (edge.verdicts[flow.verdict] ?? 0) + 1;
  edge.status = inferStatus(edge.verdicts);
}

/**
 * Export topology as arrays suitable for NetworkTopology component
 */
function exportTopology(state: TopologyState, maxAge: number = 300_000): {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
} {
  const now = Date.now();
  const nodes: NetworkNode[] = [];
  const edges: NetworkEdge[] = [];

  for (const [, node] of state.nodes) {
    if (now - node.lastSeen < maxAge) {
      const { lastSeen, flowCount, ...rest } = node;
      nodes.push(rest);
    }
  }

  for (const [, edge] of state.edges) {
    if (now - edge.lastSeen < maxAge) {
      const { lastSeen, flowCount, verdicts, ...rest } = edge;
      edges.push(rest);
    }
  }

  return { nodes, edges };
}
```

## Appendix C: References

- [Cilium CNI Chaining with AWS VPC CNI](https://docs.cilium.io/en/stable/installation/cni-chaining-aws-cni/)
- [Cilium Mutual Authentication (Beta)](https://docs.cilium.io/en/stable/network/servicemesh/mutual-authentication/mutual-authentication/)
- [Cilium Mutual Authentication Example](https://docs.cilium.io/en/stable/network/servicemesh/mutual-authentication/mutual-authentication-example/)
- [CiliumNetworkPolicy Language Reference](https://docs.cilium.io/en/stable/security/policy/language/)
- [WireGuard Transparent Encryption](https://docs.cilium.io/en/stable/security/network/encryption-wireguard/)
- [Hubble Exporter Configuration](https://docs.cilium.io/en/stable/observability/hubble/configuration/export/)
- [Hubble Metrics and Prometheus](https://docs.cilium.io/en/stable/observability/metrics/)
- [Cilium Helm Reference](https://docs.cilium.io/en/stable/helm-reference/)
- [Hubble Flow Proto Definition](https://github.com/cilium/cilium/blob/main/api/v1/flow/flow.proto)
- [hubble-otel: OpenTelemetry Adapter](https://github.com/cilium/hubble-otel)
- [Cilium kube-proxy Replacement](https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/)
- [DNS-Based Network Policies](https://docs.cilium.io/en/stable/security/dns/)
- [AWS: Transparent Encryption with WireGuard + Cilium on EKS](https://aws.amazon.com/blogs/containers/transparent-encryption-of-node-to-node-traffic-on-amazon-eks-using-wireguard-and-cilium/)
- [AWS: Getting Started with Cilium Service Mesh on EKS](https://aws.amazon.com/blogs/opensource/getting-started-with-cilium-service-mesh-on-amazon-eks/)
- [Migration from AWS VPC CNI to Cilium (Medium)](https://medium.com/@akshayjn93/migration-from-aws-vpc-cni-to-cilium-cni-on-eks-08f0fda47332)
- [Zero Downtime Migration to Cilium (Medium)](https://medium.com/codex/migrate-to-cilium-from-amazon-vpc-cni-with-zero-downtime-493827c6b45e)
- [Guidewire CNI Migration Strategy](https://medium.com/guidewire-engineering-blog/cni-migration-made-simple-ed5f80783537)
- [Cilium CNI Performance Benchmark](https://docs.cilium.io/en/stable/operations/performance/benchmark/)
- [Cilium vs AWS VPC CNI Latency](https://imesh.ai/blog/cilium-vs-aws-cni-latency-kubernetes/)
- [SPIFFE Workload Identity with Cilium (AccuKnox)](https://accuknox.com/blog/spiffe-workload-identity-integration-with-cilium)
- [Safely Managing Cilium Policies (CNCF, Nov 2025)](https://www.cncf.io/blog/2025/11/06/safely-managing-cilium-network-policies-in-kubernetes-testing-and-simulation-techniques/)
- [Cilium Hubble Cheatsheet (Isovalent)](https://isovalent.com/blog/post/cilium-hubble-cheat-sheet-observability/)
- [Hubble Network Overview Grafana Dashboard](https://grafana.com/grafana/dashboards/19424)
