# Spec 02: CiliumNetworkPolicy Manifests for SDR Services

**Status:** Draft
**Author:** spec-writers
**Date:** 2026-02-07
**Effort:** 4 engineer-days
**Dependencies:** Cilium installed on EKS cluster (CNI chaining mode or full IPAM)

---

## Summary / Objective

Create identity-based CiliumNetworkPolicy manifests that microsegment the SDR (Swarm Detection & Response) service stack. These policies enforce L3/L4/L7 access control between Spine services (checkpointer, witness, proofs-api), bridges (tetragon-bridge, hubble-bridge), the enforcement daemon (hushd), NATS JetStream, and external dependencies (SPIRE, kube-dns, AWS APIs).

This spec implements the network security layer described in Sections 5.3, 8, and 9 of `docs/research/cilium-network-security.md`. The policies use Cilium's identity-based selectors (label-based, not IP-based) and SPIFFE mutual authentication where applicable.

---

## Current State

### Infrastructure context

From the research document Section 2.1:
- **Current CNI**: AWS VPC CNI (`aws-vpc-cni-k8s`)
- **No network policies**: Currently enforced. There are no CiliumNetworkPolicy or Kubernetes NetworkPolicy manifests in the clawdstrike repo.
- **SPIRE** is deployed at `spire-server.spire-system.svc:8081` with trust domain `aegis.local`
- **NATS JetStream** runs as a 3-replica StatefulSet in the `aegisnet` namespace (Note: the CiliumNetworkPolicy manifests in this spec reference NATS in the `clawdstrike` namespace. This reflects the planned namespace migration from `aegisnet` to `clawdstrike`. Until that migration is complete, the NATS endpoint selectors in the policies will need to target the `aegisnet` namespace instead.)
- **kube-prometheus-stack** provides monitoring (ServiceMonitor auto-discovery)

### What exists in the codebase

- `crates/spine/` -- Spine protocol crate with binaries: `spine-checkpointer`, `spine-witness`, `spine-proofs-api` (see `crates/spine/Cargo.toml` lines 39-51)
- `crates/tetragon-bridge/` -- Binary `tetragon-bridge` that connects to Tetragon gRPC (port 54321) and publishes to NATS
- `crates/hubble-bridge/` -- Binary `hubble-bridge` that connects to Hubble Relay gRPC (port 4245) and publishes to NATS
- `crates/hushd/` -- HTTP enforcement daemon with SSE event broadcast and NATS subscriber
- No `deploy/` directory for Cilium policies exists yet

### Service communication patterns (from research doc and crate dependencies)

| Source | Destination | Protocol | Port | Notes |
|--------|-------------|----------|------|-------|
| spine-checkpointer | NATS JetStream | TCP | 4222 | Subscribe to envelope subjects, publish checkpoints |
| spine-witness | NATS JetStream | TCP | 4222 | Subscribe to checkpoint subjects, publish co-signatures |
| spine-proofs-api | NATS JetStream | TCP | 4222 | Query log index KV bucket |
| spine-proofs-api | Ingress (clients) | HTTP | 8080 | Serves `/v1/checkpoints/latest`, `/v1/proofs/inclusion` |
| tetragon-bridge | Tetragon agent | gRPC | 54321 | gRPC GetEvents stream |
| tetragon-bridge | NATS JetStream | TCP | 4222 | Publish Tetragon envelopes |
| hubble-bridge | Hubble Relay | gRPC | 4245 | gRPC GetFlows stream |
| hubble-bridge | NATS JetStream | TCP | 4222 | Publish Hubble flow envelopes |
| hushd | NATS JetStream | TCP | 4222 | Subscribe to Tetragon/Hubble subjects |
| hushd | Ingress (agents) | HTTP | 8080 | Policy check API, SSE events |
| All services | kube-dns | UDP/TCP | 53 | DNS resolution |
| All services | SPIRE agent | UDS | N/A | SVID issuance (SPIFFE CSI driver) |
| spine-witness | AWS STS | HTTPS | 443 | IAM authentication (optional) |
| Prometheus | All services | HTTP | 9090/2112 | Metrics scraping |

---

## Target State

A `deploy/cilium-policies/` directory containing CiliumNetworkPolicy manifests:

```
deploy/cilium-policies/
  kustomization.yaml
  00-namespace-isolation.yaml
  01-spine-checkpointer.yaml
  02-spine-witness.yaml
  03-spine-proofs-api.yaml
  04-tetragon-bridge.yaml
  05-hubble-bridge.yaml
  06-hushd.yaml
  07-nats-jetstream.yaml
  08-allow-dns.yaml
  09-allow-prometheus.yaml
```

Each policy:
- Uses `cilium.io/v2` CiliumNetworkPolicy API
- Selects endpoints by Kubernetes labels (identity-based, not IP-based)
- Requires mutual authentication (`authentication.mode: "required"`) for Spine-internal traffic
- Includes both ingress and egress rules (deny-all-except pattern)
- Uses L7 HTTP rules where applicable (proofs-api, hushd)

---

## Implementation Plan

### Step 1: Create directory structure

```bash
mkdir -p deploy/cilium-policies
```

### Step 2: Define label conventions

All SDR services must carry these labels for policy selection:

```yaml
# Standard SDR labels applied to all Deployments/StatefulSets
app.kubernetes.io/part-of: clawdstrike
app.kubernetes.io/component: <component-name>  # e.g., spine-checkpointer
clawdstrike.io/tier: <tier>                    # spine | bridge | daemon | infra
```

### Step 3: Create `00-namespace-isolation.yaml`

Default deny-all for the `clawdstrike` namespace, with explicit allowances for intra-namespace and monitoring traffic.

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: sdr-namespace-default-deny
  namespace: clawdstrike
  labels:
    app.kubernetes.io/part-of: clawdstrike
    clawdstrike.io/policy-scope: namespace
spec:
  description: "Default deny for clawdstrike namespace. Explicit allow rules override."
  endpointSelector: {}  # All pods in namespace
  ingress:
    # Allow intra-namespace traffic
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: clawdstrike
    # Allow Prometheus scraping from monitoring namespace
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app.kubernetes.io/name: prometheus
      toPorts:
        - ports:
            - port: "9090"
              protocol: TCP
            - port: "2112"
              protocol: TCP
  egress:
    # Allow intra-namespace traffic
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: clawdstrike
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
              - matchPattern: "*"
```

### Step 4: Create `01-spine-checkpointer.yaml`

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: spine-checkpointer
  namespace: clawdstrike
  labels:
    app.kubernetes.io/part-of: clawdstrike
spec:
  description: "Spine checkpointer: subscribe to envelopes, publish checkpoints to NATS"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/component: spine-checkpointer
  ingress:
    # Prometheus metrics
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app.kubernetes.io/name: prometheus
      toPorts:
        - ports:
            - port: "2112"
              protocol: TCP
  egress:
    # NATS JetStream
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/component: nats
      authentication:
        mode: "required"
      toPorts:
        - ports:
            - port: "4222"
              protocol: TCP
    # DNS
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
```

### Step 5: Create `02-spine-witness.yaml`

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: spine-witness
  namespace: clawdstrike
  labels:
    app.kubernetes.io/part-of: clawdstrike
spec:
  description: "Spine witness: subscribe to checkpoints, publish co-signatures to NATS"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/component: spine-witness
  ingress:
    # Prometheus metrics
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app.kubernetes.io/name: prometheus
      toPorts:
        - ports:
            - port: "2112"
              protocol: TCP
  egress:
    # NATS JetStream
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/component: nats
      authentication:
        mode: "required"
      toPorts:
        - ports:
            - port: "4222"
              protocol: TCP
    # AWS STS (for IAM auth in production)
    - toFQDNs:
        - matchPattern: "*.amazonaws.com"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
    # DNS
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
              - matchPattern: "*.svc.cluster.local"
```

### Step 6: Create `03-spine-proofs-api.yaml`

L7 HTTP rules restrict the proofs-api to its documented endpoints.

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: spine-proofs-api
  namespace: clawdstrike
  labels:
    app.kubernetes.io/part-of: clawdstrike
spec:
  description: "Spine proofs-api: serves inclusion proofs, queries NATS KV"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/component: spine-proofs-api
  ingress:
    # hushd queries proofs-api
    - fromEndpoints:
        - matchLabels:
            app.kubernetes.io/component: hushd
      authentication:
        mode: "required"
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: GET
                path: "/v1/checkpoints/.*"
              - method: GET
                path: "/v1/proofs/.*"
              - method: GET
                path: "/healthz"
    # External clients via ingress gateway
    - fromEndpoints:
        - matchLabels:
            app.kubernetes.io/component: envoy-gateway
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: GET
                path: "/v1/checkpoints/.*"
              - method: GET
                path: "/v1/proofs/.*"
              - method: GET
                path: "/healthz"
    # Prometheus metrics
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app.kubernetes.io/name: prometheus
      toPorts:
        - ports:
            - port: "2112"
              protocol: TCP
  egress:
    # NATS JetStream (KV queries)
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/component: nats
      authentication:
        mode: "required"
      toPorts:
        - ports:
            - port: "4222"
              protocol: TCP
    # DNS
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
```

### Step 7: Create `04-tetragon-bridge.yaml`

The tetragon-bridge runs as a sidecar in the Tetragon DaemonSet (kube-system namespace), so this policy uses `CiliumNetworkPolicy` in `kube-system` or `CiliumClusterwideNetworkPolicy`.

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: tetragon-bridge
  namespace: kube-system
  labels:
    app.kubernetes.io/part-of: clawdstrike
spec:
  description: "Tetragon bridge: gRPC from Tetragon, publish to NATS"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/component: tetragon-bridge
  ingress:
    # Prometheus metrics
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app.kubernetes.io/name: prometheus
      toPorts:
        - ports:
            - port: "2112"
              protocol: TCP
  egress:
    # Tetragon gRPC (localhost within same pod)
    - toEntities:
        - host
      toPorts:
        - ports:
            - port: "54321"
              protocol: TCP
    # NATS JetStream (cross-namespace)
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: clawdstrike
            app.kubernetes.io/component: nats
      toPorts:
        - ports:
            - port: "4222"
              protocol: TCP
    # DNS
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
```

### Step 8: Create `05-hubble-bridge.yaml`

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: hubble-bridge
  namespace: clawdstrike
  labels:
    app.kubernetes.io/part-of: clawdstrike
spec:
  description: "Hubble bridge: gRPC from Hubble Relay, publish to NATS"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/component: hubble-bridge
  ingress:
    # Prometheus metrics
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app.kubernetes.io/name: prometheus
      toPorts:
        - ports:
            - port: "2112"
              protocol: TCP
  egress:
    # Hubble Relay gRPC
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            app.kubernetes.io/name: hubble-relay
      toPorts:
        - ports:
            - port: "4245"
              protocol: TCP
    # NATS JetStream
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/component: nats
      authentication:
        mode: "required"
      toPorts:
        - ports:
            - port: "4222"
              protocol: TCP
    # DNS
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
```

### Step 9: Create `06-hushd.yaml`

L7 HTTP rules for the hushd enforcement daemon's API endpoints.

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: hushd
  namespace: clawdstrike
  labels:
    app.kubernetes.io/part-of: clawdstrike
spec:
  description: "hushd: enforcement daemon serving agent check API and SSE events"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/component: hushd
  ingress:
    # Agent SDK clients (from any namespace, via ingress or direct)
    - fromEndpoints:
        - matchLabels:
            app.kubernetes.io/component: envoy-gateway
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: POST
                path: "/api/v1/check"
              - method: GET
                path: "/api/v1/events"
              - method: GET
                path: "/api/v1/audit/.*"
              - method: GET
                path: "/health"
    # Desktop app SSE (from within namespace)
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: clawdstrike
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
    # Prometheus metrics
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app.kubernetes.io/name: prometheus
      toPorts:
        - ports:
            - port: "2112"
              protocol: TCP
  egress:
    # NATS JetStream (subscribe to Tetragon/Hubble subjects)
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/component: nats
      authentication:
        mode: "required"
      toPorts:
        - ports:
            - port: "4222"
              protocol: TCP
    # Spine proofs-api (verify receipts, fetch inclusion proofs)
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/component: spine-proofs-api
      authentication:
        mode: "required"
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
    # DNS
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
```

### Step 10: Create `07-nats-jetstream.yaml`

NATS JetStream accepts connections from Spine services and bridges. It also needs inter-replica clustering.

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: nats-jetstream
  namespace: clawdstrike
  labels:
    app.kubernetes.io/part-of: clawdstrike
spec:
  description: "NATS JetStream: accept connections from SDR services, inter-replica clustering"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/component: nats
  ingress:
    # Client connections from all SDR services
    - fromEndpoints:
        - matchLabels:
            app.kubernetes.io/part-of: clawdstrike
      toPorts:
        - ports:
            - port: "4222"
              protocol: TCP
    # Cross-namespace bridge connections (tetragon-bridge in kube-system)
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            app.kubernetes.io/component: tetragon-bridge
      toPorts:
        - ports:
            - port: "4222"
              protocol: TCP
    # NATS cluster routing (inter-replica)
    - fromEndpoints:
        - matchLabels:
            app.kubernetes.io/component: nats
      toPorts:
        - ports:
            - port: "6222"
              protocol: TCP
    # Prometheus metrics
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app.kubernetes.io/name: prometheus
      toPorts:
        - ports:
            - port: "8222"
              protocol: TCP
  egress:
    # NATS cluster routing (inter-replica)
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/component: nats
      toPorts:
        - ports:
            - port: "6222"
              protocol: TCP
    # DNS
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
```

### Step 11: Create `08-allow-dns.yaml` and `09-allow-prometheus.yaml`

These are convenience policies already covered by the namespace-isolation policy but broken out for clarity and independent management.

**`08-allow-dns.yaml`** -- Cluster-wide DNS access for all SDR pods (already in namespace policy, this is the explicit fallback).

**`09-allow-prometheus.yaml`** -- Ensures Prometheus can scrape all SDR service metrics endpoints.

```yaml
# 08-allow-dns.yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: sdr-allow-dns
  namespace: clawdstrike
  labels:
    app.kubernetes.io/part-of: clawdstrike
spec:
  description: "Allow all SDR pods to resolve DNS"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/part-of: clawdstrike
  egress:
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
              - matchPattern: "*"
```

```yaml
# 09-allow-prometheus.yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: sdr-allow-prometheus
  namespace: clawdstrike
  labels:
    app.kubernetes.io/part-of: clawdstrike
spec:
  description: "Allow Prometheus to scrape all SDR service metrics"
  endpointSelector:
    matchLabels:
      app.kubernetes.io/part-of: clawdstrike
  ingress:
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: monitoring
            app.kubernetes.io/name: prometheus
      toPorts:
        - ports:
            - port: "2112"
              protocol: TCP
            - port: "9090"
              protocol: TCP
```

### Step 12: Create `kustomization.yaml`

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - 00-namespace-isolation.yaml
  - 01-spine-checkpointer.yaml
  - 02-spine-witness.yaml
  - 03-spine-proofs-api.yaml
  - 04-tetragon-bridge.yaml
  - 05-hubble-bridge.yaml
  - 06-hushd.yaml
  - 07-nats-jetstream.yaml
  - 08-allow-dns.yaml
  - 09-allow-prometheus.yaml
commonLabels:
  app.kubernetes.io/managed-by: clawdstrike
```

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `deploy/cilium-policies/kustomization.yaml` | Create | Kustomize manifest |
| `deploy/cilium-policies/00-namespace-isolation.yaml` | Create | Default deny + intra-namespace allow |
| `deploy/cilium-policies/01-spine-checkpointer.yaml` | Create | Checkpointer egress to NATS |
| `deploy/cilium-policies/02-spine-witness.yaml` | Create | Witness egress to NATS + AWS STS |
| `deploy/cilium-policies/03-spine-proofs-api.yaml` | Create | Proofs API L7 ingress + NATS egress |
| `deploy/cilium-policies/04-tetragon-bridge.yaml` | Create | Bridge gRPC ingress + NATS egress |
| `deploy/cilium-policies/05-hubble-bridge.yaml` | Create | Bridge Hubble gRPC + NATS egress |
| `deploy/cilium-policies/06-hushd.yaml` | Create | Daemon L7 API + NATS + proofs-api egress |
| `deploy/cilium-policies/07-nats-jetstream.yaml` | Create | NATS client + cluster ingress/egress |
| `deploy/cilium-policies/08-allow-dns.yaml` | Create | DNS resolution for all SDR pods |
| `deploy/cilium-policies/09-allow-prometheus.yaml` | Create | Prometheus scraping for all SDR pods |

---

## Testing Strategy

### Phase 1: Audit mode validation

1. Deploy all policies with Cilium in `policy-audit-mode enabled`:
   ```bash
   cilium config set policy-audit-mode enabled
   kubectl apply -f deploy/cilium-policies/
   ```

2. Deploy the full SDR stack (Spine services, bridges, hushd, NATS).

3. Run integration tests (`crates/sdr-integration-tests/`) and verify no `AUDIT` verdicts appear for legitimate traffic:
   ```bash
   hubble observe --verdict AUDIT --namespace clawdstrike
   ```

4. Generate expected traffic patterns:
   - spine-checkpointer subscribing to NATS
   - tetragon-bridge publishing to NATS
   - hushd serving HTTP check requests
   - Prometheus scraping metrics
   - DNS resolution from all pods

5. Verify all flows show `FORWARDED` verdict.

### Phase 2: Enforcement mode validation

1. Disable audit mode: `cilium config set policy-audit-mode disabled`

2. Re-run integration tests. All should pass.

3. Negative tests -- verify unauthorized traffic is dropped:
   - Pod without `app.kubernetes.io/part-of: clawdstrike` label cannot reach NATS:4222
   - Pod from `default` namespace cannot reach hushd:8080 directly
   - hushd cannot make outbound connections to arbitrary external IPs
   - Verify drops: `hubble observe --verdict DROPPED --namespace clawdstrike`

### Phase 3: L7 policy validation

1. Verify proofs-api only accepts GET requests to documented paths:
   ```bash
   # Should succeed
   curl http://spine-proofs-api:8080/v1/checkpoints/latest
   # Should be dropped by L7 rule
   curl -X POST http://spine-proofs-api:8080/v1/admin/reset
   ```

2. Verify hushd only accepts documented HTTP methods/paths via ingress.

### Phase 4: Mutual authentication validation

1. Verify SPIRE SVIDs are issued for all SDR services.
2. Confirm that connections with `authentication.mode: "required"` complete the mTLS handshake:
   ```bash
   hubble observe --namespace clawdstrike -o json | jq 'select(.l7 != null)'
   ```

---

## Rollback Plan

### Immediate rollback (seconds)

Enable audit mode globally to stop enforcement while keeping visibility:
```bash
cilium config set policy-audit-mode enabled
```

### Full removal (seconds)

Delete all policies:
```bash
kubectl delete -f deploy/cilium-policies/
```

Without policies, Cilium defaults to allow-all. Traffic returns to its unrestricted state immediately.

### Per-policy rollback

If a specific policy causes connectivity issues, delete only that policy:
```bash
kubectl delete ciliumnetworkpolicy spine-witness -n clawdstrike
```

The other policies continue operating independently.

---

## Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| Cilium installed (chaining or full IPAM) | Required | Helm chart `cilium/cilium` v1.19+ |
| Hubble enabled | Required for testing | `hubble.enabled=true` in Cilium values |
| SPIRE server at `spire-server.spire-system.svc:8081` | Required for mutual auth | Already deployed via ArgoCD |
| Cilium mutual auth enabled | Required for `authentication.mode: required` | `authentication.mutual.spire.enabled=true` |
| kube-prometheus-stack | Recommended | For Prometheus ServiceMonitor auto-discovery |
| Spec 01 (TracingPolicy CRDs) | Recommended | Tetragon policies generate events that flow through bridges |
| Spec 09 (Helm chart) | Recommended | Helm chart deploys SDR services with correct labels |

---

## Acceptance Criteria

- [ ] Directory `deploy/cilium-policies/` exists with 10 YAML files + `kustomization.yaml`
- [ ] All policies use `cilium.io/v2` CiliumNetworkPolicy API
- [ ] Namespace isolation policy (`00-namespace-isolation.yaml`) implements default-deny with intra-namespace allow
- [ ] All Spine service policies restrict egress to only NATS (port 4222) and DNS (port 53)
- [ ] spine-proofs-api ingress has L7 HTTP rules restricting to `GET /v1/checkpoints/.*`, `GET /v1/proofs/.*`, `GET /healthz`
- [ ] hushd ingress has L7 HTTP rules restricting to `POST /api/v1/check`, `GET /api/v1/events`, `GET /api/v1/audit/.*`, `GET /health`
- [ ] Spine-internal connections (checkpointer, witness, proofs-api, hushd to NATS) require mutual authentication
- [ ] tetragon-bridge can reach Tetragon gRPC (port 54321) and NATS (port 4222)
- [ ] hubble-bridge can reach Hubble Relay (port 4245) and NATS (port 4222)
- [ ] NATS policy allows inter-replica clustering (port 6222) and Prometheus (port 8222)
- [ ] All policies include `app.kubernetes.io/part-of: clawdstrike` label
- [ ] All policies pass `kubectl apply --dry-run=server` against a Cilium-enabled cluster
- [ ] In audit mode, no legitimate SDR traffic receives AUDIT verdict
- [ ] In enforcement mode, unauthorized traffic is DROPPED
