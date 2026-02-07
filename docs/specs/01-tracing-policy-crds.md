# Spec 01: Tetragon TracingPolicy CRDs

**Status:** Draft
**Author:** spec-writers
**Date:** 2026-02-07
**Effort:** 3 engineer-days
**Dependencies:** Tetragon Helm chart deployed (see docs/specs/09-helm-chart.md)

---

## Summary / Objective

Create six Tetragon TracingPolicy CRD manifests that provide kernel-level runtime security enforcement and observability for the SDR (Swarm Detection & Response) stack. These policies implement the eBPF enforcement floor beneath ClawdStrike's application-level guards, as described in Section 3 and Section 8 of `docs/research/tetragon-integration.md`.

The six policies cover:

1. **Exec Allowlist** -- Block unauthorized process execution in SDR namespaces
2. **File Integrity Monitoring (FIM)** -- Detect and optionally block access to sensitive configuration, keys, and policy files
3. **Network Egress** -- Alert on outbound connections to non-cluster destinations
4. **Container Escape Detection** -- Detect privilege escalation and namespace escape attempts
5. **Crypto Mining Detection** -- Kill processes connecting to known mining pool ports
6. **Guard Enforcement** -- Prevent unauthorized writes to ClawdStrike policy files (only hushd/clawdstriked may write)

---

## Current State

### What exists today

- The `crates/tetragon-bridge/` crate exists and bridges Tetragon gRPC events to signed Spine envelopes on NATS. It depends on `spine` and `hush-core` for envelope signing, and uses `tonic` for gRPC + `async-nats` for NATS publishing (see `crates/tetragon-bridge/Cargo.toml`).
- The research document at `docs/research/tetragon-integration.md` (Sections 3.1-3.6) provides draft TracingPolicy YAML for all six policies with detailed comments.
- The Cargo workspace already includes `crates/tetragon-bridge` as a member (Cargo.toml line 14).
- No `deploy/tetragon-policies/` directory exists yet.
- No TracingPolicy CRD manifests have been committed to the repository.
- The research doc references NATS subjects like `clawdstrike.spine.envelope.tetragon.process_exec.v1` (Section 4.3) that the bridge publishes to -- the policies must produce events compatible with the bridge's expected Tetragon event types.

### What the bridge expects

From `crates/tetragon-bridge/Cargo.toml` and the research doc Section 4.2, the bridge:
1. Subscribes to Tetragon's gRPC `GetEvents` streaming endpoint (port 54321 default)
2. Receives `GetEventsResponse` protobuf messages
3. Transforms events into Spine `SignedEnvelope` facts
4. Publishes to NATS subjects scoped by event type

The bridge currently consumes `process_exec`, `process_exit`, and `process_kprobe` event types (`ProcessExec`, `ProcessExit`, `ProcessKprobe` variants of `TetragonEventKind` in `crates/tetragon-bridge/src/tetragon.rs`). Our TracingPolicies must generate events of these types.

> **Note:** The FIM policy (02-file-integrity-monitoring.yaml) uses `lsmhooks`, which generates `process_lsm` events. The bridge does **not** currently support this event type. Before deploying the FIM policy, a new `ProcessLsm` variant must be added to the `TetragonEventKind` enum in `crates/tetragon-bridge/src/tetragon.rs` and handled in the bridge's event processing pipeline. Without this change, LSM hook events will be silently dropped by the bridge.

---

## Target State

A `deploy/tetragon-policies/` directory containing six TracingPolicy CRD manifests ready for `kubectl apply`:

```
deploy/tetragon-policies/
  kustomization.yaml
  01-exec-allowlist.yaml
  02-file-integrity-monitoring.yaml
  03-network-egress.yaml
  04-container-escape-detection.yaml
  05-crypto-mining-detection.yaml
  06-guard-enforcement.yaml
```

Each manifest:
- Is a valid `cilium.io/v1alpha1` TracingPolicy CRD
- Includes metadata labels (`app.kubernetes.io/part-of: clawdstrike`, `clawdstrike.io/policy-tier: kernel`)
- Includes MITRE ATT&CK tags where applicable
- Has rate limiting configured to prevent event flooding
- Is namespace-aware (uses `matchNamespaces` to scope to non-host PIDs)
- Has been validated against the Tetragon CRD schema

---

## Implementation Plan

### Step 1: Create directory structure

```bash
mkdir -p deploy/tetragon-policies
```

### Step 2: Create `01-exec-allowlist.yaml`

Based on research doc Section 3.1. This policy monitors `sys_execve` in non-host PID namespaces and:
- Silently allows known SDR binaries (`/usr/bin/aegisnet-*`, `/usr/bin/hushd`, `/usr/bin/clawdstriked`, `/usr/bin/spine-*`, `/usr/bin/tetragon-bridge`, `/usr/bin/hubble-bridge`)
- Alerts (Post) on any other exec with 1-minute rate limiting

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: sdr-exec-allowlist
  labels:
    app.kubernetes.io/part-of: clawdstrike
    clawdstrike.io/policy-tier: kernel
    clawdstrike.io/category: process
  annotations:
    clawdstrike.io/mitre-techniques: "T1059,T1204"
    clawdstrike.io/description: "Allowlist authorized binaries in SDR namespaces"
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    # Allow known SDR binaries silently
    - matchBinaries:
      - operator: In
        values:
        - "/usr/bin/aegisnet-checkpointer"
        - "/usr/bin/aegisnet-witness"
        - "/usr/bin/aegisnet-proofs-api"
        - "/usr/bin/aegisnet-model-registry"
        - "/usr/bin/aegisctl"
        - "/usr/bin/hushd"
        - "/usr/bin/clawdstriked"
        - "/usr/bin/spine-checkpointer"
        - "/usr/bin/spine-witness"
        - "/usr/bin/spine-proofs-api"
        - "/usr/bin/tetragon-bridge"
        - "/usr/bin/hubble-bridge"
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: NoPost
    # Alert on any other exec in non-host namespace
    - matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Post
        rateLimit: "1m"
```

### Step 3: Create `02-file-integrity-monitoring.yaml`

Based on research doc Section 3.2. Uses LSM hooks (`file_open`) to monitor access to:
- `/etc/aegisnet/` -- AegisNet configuration
- `/etc/clawdstrike/` -- ClawdStrike policies
- `/var/run/secrets/kubernetes.io/` -- K8s service account tokens
- `/var/run/spire/agent/` -- SPIRE agent sockets/SVIDs

Enables IMA hash collection on supported kernels (requires kernel 5.11+, satisfied by AL2023's 6.1+).

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: sdr-file-integrity-monitoring
  labels:
    app.kubernetes.io/part-of: clawdstrike
    clawdstrike.io/policy-tier: kernel
    clawdstrike.io/category: fim
  annotations:
    clawdstrike.io/mitre-techniques: "T1003,T1552"
    clawdstrike.io/description: "Monitor access to sensitive config and key material"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/aegisnet/"
        - "/etc/clawdstrike/"
        - "/var/lib/clawdstrike/policies/"
        - "/var/run/secrets/kubernetes.io/"
        - "/var/run/spire/agent/"
      matchActions:
      - action: Post
        imaHash: true
```

### Step 4: Create `03-network-egress.yaml`

Based on research doc Section 3.3. Monitors `tcp_connect` for outbound connections outside expected CIDR ranges (10.0.0.0/8, 172.16.0.0/12, 127.0.0.0/8). Alerts but does not kill -- network enforcement is delegated to Cilium NetworkPolicy (spec 02).

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: sdr-network-egress
  labels:
    app.kubernetes.io/part-of: clawdstrike
    clawdstrike.io/policy-tier: kernel
    clawdstrike.io/category: network
  annotations:
    clawdstrike.io/mitre-techniques: "T1041,T1071"
    clawdstrike.io/description: "Alert on outbound connections outside cluster CIDR"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "127.0.0.0/8"
      matchActions:
      - action: Post
```

### Step 5: Create `04-container-escape-detection.yaml`

Based on research doc Section 3.5. Detects:
- `sys_setuid(0)` in non-host PID namespace -- kill
- `sys_unshare` with Mnt/Pid/Net namespace changes -- alert

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: sdr-container-escape-detection
  labels:
    app.kubernetes.io/part-of: clawdstrike
    clawdstrike.io/policy-tier: kernel
    clawdstrike.io/category: escape
  annotations:
    clawdstrike.io/mitre-techniques: "T1611,T1548"
    clawdstrike.io/description: "Detect container escape and privilege escalation attempts"
spec:
  kprobes:
  # Detect setuid to root from non-host namespace
  - call: "sys_setuid"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "0"
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Sigkill
  # Detect unshare (new namespace creation)
  - call: "sys_unshare"
    syscall: true
    args:
    - index: 0
      type: "int"
    selectors:
    - matchNamespaceChanges:
      - operator: In
        values:
        - "Mnt"
        - "Pid"
        - "Net"
      matchActions:
      - action: Post
```

### Step 6: Create `05-crypto-mining-detection.yaml`

Based on research doc Section 3.4. Kills processes connecting to common stratum mining pool ports. This is a high-confidence indicator -- legitimate workloads do not connect to these ports.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: sdr-crypto-mining-detection
  labels:
    app.kubernetes.io/part-of: clawdstrike
    clawdstrike.io/policy-tier: kernel
    clawdstrike.io/category: cryptominer
  annotations:
    clawdstrike.io/mitre-techniques: "T1496"
    clawdstrike.io/description: "Kill processes connecting to known crypto mining pool ports"
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    - matchArgs:
      - index: 0
        operator: "DPort"
        values:
        - "3333"
        - "4444"
        - "5555"
        - "7777"
        - "8888"
        - "9999"
        - "14444"
        - "14433"
      matchActions:
      - action: Sigkill
```

### Step 7: Create `06-guard-enforcement.yaml`

Based on research doc Section 3.6. Prevents unauthorized writes to ClawdStrike policy directories. Only `hushd` and `clawdstriked` binaries are permitted to write to `/etc/clawdstrike/` and `/var/lib/clawdstrike/policies/`. All other write attempts are killed.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: sdr-guard-enforcement
  labels:
    app.kubernetes.io/part-of: clawdstrike
    clawdstrike.io/policy-tier: kernel
    clawdstrike.io/category: enforcement
  annotations:
    clawdstrike.io/mitre-techniques: "T1562"
    clawdstrike.io/description: "Prevent unauthorized writes to ClawdStrike policy files"
spec:
  kprobes:
  - call: "security_file_permission"
    syscall: false
    args:
    - index: 0
      type: "file"
    - index: 1
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc/clawdstrike/"
        - "/var/lib/clawdstrike/policies/"
      - index: 1
        operator: "Mask"
        values:
        - "2"  # MAY_WRITE
      matchBinaries:
      - operator: NotIn
        values:
        - "/usr/bin/hushd"
        - "/usr/bin/clawdstriked"
      matchActions:
      - action: Sigkill
```

### Step 8: Create `kustomization.yaml`

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - 01-exec-allowlist.yaml
  - 02-file-integrity-monitoring.yaml
  - 03-network-egress.yaml
  - 04-container-escape-detection.yaml
  - 05-crypto-mining-detection.yaml
  - 06-guard-enforcement.yaml
commonLabels:
  app.kubernetes.io/managed-by: clawdstrike
```

### Step 9: Validate manifests

```bash
# Syntax check with kubectl (dry-run against Tetragon CRD)
kubectl apply -f deploy/tetragon-policies/ --dry-run=server

# If Tetragon is not installed yet, at minimum validate YAML syntax
for f in deploy/tetragon-policies/*.yaml; do
  python3 -c "import yaml; yaml.safe_load(open('$f'))"
done
```

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `deploy/tetragon-policies/kustomization.yaml` | Create | Kustomize manifest aggregating all 6 policies |
| `deploy/tetragon-policies/01-exec-allowlist.yaml` | Create | Exec allowlist TracingPolicy |
| `deploy/tetragon-policies/02-file-integrity-monitoring.yaml` | Create | FIM TracingPolicy |
| `deploy/tetragon-policies/03-network-egress.yaml` | Create | Network egress TracingPolicy |
| `deploy/tetragon-policies/04-container-escape-detection.yaml` | Create | Container escape TracingPolicy |
| `deploy/tetragon-policies/05-crypto-mining-detection.yaml` | Create | Crypto mining TracingPolicy |
| `deploy/tetragon-policies/06-guard-enforcement.yaml` | Create | Guard enforcement TracingPolicy |

---

## Testing Strategy

1. **Static validation**: Parse each YAML file and verify it conforms to the TracingPolicy CRD schema. Use `kubectl apply --dry-run=server` against a cluster with Tetragon CRDs installed.

2. **Tetragon simulator test**: Deploy Tetragon on a local Kind/k3d cluster, apply all six policies, and verify they load:
   ```bash
   kubectl get tracingpolicies
   kubectl describe tracingpolicy sdr-exec-allowlist
   ```
   All policies should show `Status: Loaded`.

3. **Event generation tests** (per policy):
   - **Exec allowlist**: Run `curl` inside a non-SDR pod -> expect `process_kprobe` event.
   - **FIM**: `cat /etc/aegisnet/config.yaml` inside a pod -> expect event with IMA hash.
   - **Network egress**: `curl http://1.2.3.4` from a pod -> expect `process_kprobe` with tcp_connect.
   - **Container escape**: Run a test pod attempting `unshare --mount` -> expect event.
   - **Crypto mining**: `nc -z 1.2.3.4 4444` from a pod -> expect SIGKILL.
   - **Guard enforcement**: `touch /etc/clawdstrike/evil.yaml` from a non-hushd process -> expect SIGKILL.

4. **Bridge integration test**: Verify that events generated by the TracingPolicies are correctly consumed by `tetragon-bridge` and published to NATS as signed Spine envelopes. This is covered by `crates/sdr-integration-tests/`.

5. **Rate limiting validation**: Generate a burst of exec events and verify the `rateLimit: "1m"` on the exec allowlist suppresses duplicate events.

---

## Rollback Plan

TracingPolicies are Kubernetes CRDs and can be removed instantly:

```bash
kubectl delete -f deploy/tetragon-policies/
```

Removing a TracingPolicy immediately stops the eBPF programs associated with it. No process kills or network blocks will occur after deletion. This is fully reversible with zero downtime.

If a specific policy causes issues (e.g., false-positive SIGKILL):
1. Delete the offending policy: `kubectl delete tracingpolicy sdr-container-escape-detection`
2. Fix and reapply
3. The other 5 policies continue operating independently

---

## Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| Tetragon installed on cluster | Required | Helm chart: `cilium/tetragon` (see docs/specs/09-helm-chart.md) |
| Kernel 5.11+ for IMA hashes | Required for FIM | AL2023 ships kernel 6.1+, satisfied |
| BPF LSM support for `lsmhooks` | Required for FIM | Enabled in AL2023 kernel config |
| `crates/tetragon-bridge` built and deployed | Recommended | Policies work without bridge (events logged to tetragon.log) |
| `crates/spine` NATS infrastructure | Recommended | Required for events to flow through Spine |

---

## Acceptance Criteria

- [ ] Directory `deploy/tetragon-policies/` exists with 6 YAML files + `kustomization.yaml`
- [ ] Each YAML file is a valid `cilium.io/v1alpha1` TracingPolicy
- [ ] All policies include `app.kubernetes.io/part-of: clawdstrike` label
- [ ] All policies include `clawdstrike.io/mitre-techniques` annotation with relevant MITRE IDs
- [ ] Exec allowlist permits the 12 known SDR binaries (NoPost) and alerts on all others (Post with rateLimit)
- [ ] FIM policy monitors all 5 sensitive path prefixes with IMA hash collection
- [ ] Network egress alerts on connections outside 10.0.0.0/8, 172.16.0.0/12, 127.0.0.0/8
- [ ] Container escape detection kills setuid(0) in non-host namespace and alerts on unshare
- [ ] Crypto mining detection kills connections to all 8 stratum ports
- [ ] Guard enforcement kills non-hushd/clawdstriked writes to policy directories
- [ ] `kustomization.yaml` references all 6 policies
- [ ] All policies pass YAML syntax validation
- [ ] (Stretch) All policies load successfully on a test cluster with Tetragon installed
