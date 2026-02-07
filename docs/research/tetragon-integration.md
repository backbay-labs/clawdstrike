# Tetragon Integration with AegisNet and ClawdStrike

> Research document for integrating Cilium Tetragon (eBPF runtime security)
> into the AegisNet verifiable log system and ClawdStrike desktop security console.

---

## Table of Contents

1. [Tetragon Overview and Capabilities](#1-tetragon-overview-and-capabilities)
2. [Event Format and Export](#2-event-format-and-export)
3. [TracingPolicy Examples](#3-tracingpolicy-examples)
4. [AegisNet Integration Patterns](#4-aegisnet-integration-patterns)
5. [ClawdStrike Feed Integration](#5-clawdstrike-feed-integration)
6. [Runtime Proof Chains](#6-runtime-proof-chains)
7. [Deployment on EKS with AL2023](#7-deployment-on-eks-with-al2023)
8. [Open Questions](#8-open-questions)

---

## 1. Tetragon Overview and Capabilities

[Tetragon](https://tetragon.io/) is Cilium's eBPF-based runtime security observability and enforcement tool, now a CNCF project. It hooks directly into the Linux kernel to monitor and enforce security policies at the syscall/function level with minimal overhead.

### 1.1 Core Architecture

```
  ┌─────────────────────────────────────────────────────────┐
  │                    Linux Kernel                          │
  │                                                         │
  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
  │  │  kprobes  │ │tracepoint│ │LSM hooks │ │  uprobes  │  │
  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │
  │       │            │            │             │         │
  │  ┌────▼────────────▼────────────▼─────────────▼─────┐  │
  │  │           eBPF Programs (Tetragon)                │  │
  │  │  In-kernel filtering, aggregation, enforcement    │  │
  │  └────────────────────┬──────────────────────────────┘  │
  └───────────────────────┼─────────────────────────────────┘
                          │ perf ring buffer
  ┌───────────────────────▼─────────────────────────────────┐
  │              Tetragon Agent (userspace)                   │
  │  ┌──────────┐  ┌──────────┐  ┌────────────────────────┐ │
  │  │K8s enrich│  │Event proc│  │Export: JSON/gRPC/stdout │ │
  │  └──────────┘  └──────────┘  └────────────────────────┘ │
  └──────────────────────────────────────────────────────────┘
```

### 1.2 Hook Points

| Hook Type     | Use Case                              | Portability           |
|---------------|---------------------------------------|-----------------------|
| **kprobes**   | Any kernel function (dynamic)         | Tied to kernel version|
| **tracepoints** | Stable kernel trace events          | Portable across versions |
| **LSM hooks** | Security module decision points       | Requires BPF LSM support |
| **uprobes**   | User-space function instrumentation   | Tied to binary layout |
| **USDTs**     | User Statically-Defined Tracing       | Application-defined   |

### 1.3 Key Capabilities for Our Use Case

1. **Process lifecycle tracking** -- fork/exec/exit with full ancestry, Kubernetes pod/container metadata, binary path, args, CWD, UID, capabilities, namespaces.

2. **File integrity monitoring** -- Hook `security_file_open`, `security_file_permission` LSM hooks or `fd_install` kprobe. IMA hash collection supported on kernel 5.11+ via `imaHash: true` in TracingPolicy selectors.

3. **Network observability** -- TCP connect/accept/close, UDP, DNS, with process correlation. Track bytes sent/received per socket. Detect lateral movement and exfiltration.

4. **Syscall filtering and enforcement** -- In-kernel `Sigkill`, `Override` (return value replacement), `Signal` actions. Block unauthorized operations before they complete.

5. **Privilege escalation detection** -- Monitor `sys_setuid`, `sys_setgid`, `unshare`, namespace changes, capability changes. Detect container escape attempts.

6. **Kubernetes-native** -- TracingPolicy is a CRD. Pod labels, annotations, namespace, workload info enriched automatically. Namespace-scoped policies via `TracingPolicyNamespaced`.

### 1.4 Performance Profile

- **Process exec tracking overhead**: ~1.68% worst case
- **Typical production overhead**: < 1% CPU
- **In-kernel filtering**: Events that don't match selectors never reach userspace
- **Recommended resource limits**: CPU 1000m, Memory 1Gi (DaemonSet per node)
- **Event throughput**: Thousands of events/sec with negligible CPU overhead

---

## 2. Event Format and Export

### 2.1 Event Types

Tetragon emits these primary event types via both JSON log and gRPC:

| Event Type             | Trigger                                   |
|------------------------|-------------------------------------------|
| `process_exec`         | Process execution (fork+exec)             |
| `process_exit`         | Process termination                       |
| `process_kprobe`       | Kprobe match in TracingPolicy             |
| `process_tracepoint`   | Tracepoint match in TracingPolicy         |
| `process_lsm`          | LSM hook match in TracingPolicy           |
| `process_uprobe`       | Uprobe match in TracingPolicy             |
| `process_loader`       | Binary/shared library loading             |
| `process_throttle`     | Rate-limiting notification                |

### 2.2 Process Message Schema (Protobuf)

Every event contains a `process` field with:

```
Process {
  exec_id:        string        // Cluster-wide unique ID (correlates all activity)
  pid:            uint32        // Host PID
  uid:            uint32        // Effective UID
  cwd:            string        // Current working directory
  binary:         string        // Absolute path of executed binary
  arguments:      string        // Command-line arguments
  flags:          string        // Exec flags
  start_time:     Timestamp     // Process start time
  auid:           uint32        // Audit UID (survives su/sudo)
  pod:            Pod           // K8s pod metadata
  docker:         string        // First 15 chars of container ID
  parent_exec_id: string        // Parent process correlation
  cap:            Capabilities  // Linux capabilities
  ns:             Namespaces    // Linux namespaces
  tid:            uint32        // Thread ID
  process_credentials: ProcessCredentials
  binary_properties:   BinaryProperties
  user:                UserRecord
  in_init_tree:        bool
}
```

### 2.3 Example: process_exec JSON Event

```json
{
  "process_exec": {
    "process": {
      "exec_id": "a]7iu:198274312:95921",
      "pid": 95921,
      "uid": 0,
      "cwd": "/",
      "binary": "/usr/bin/curl",
      "arguments": "https://api.backbay.industries/health",
      "flags": "execve clone",
      "start_time": "2026-02-06T10:30:00.123456789Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "aegisnet",
        "name": "aegisnet-checkpointer-7d4b8f6c-k9x2m",
        "uid": "abc123-def456",
        "container": {
          "id": "containerd://a1b2c3d4e5f6",
          "name": "checkpointer",
          "image": {
            "id": "419659069643.dkr.ecr.us-east-1.amazonaws.com/aegisnet@sha256:abc123",
            "name": "419659069643.dkr.ecr.us-east-1.amazonaws.com/aegisnet:sha-1a2b3c4"
          },
          "start_time": "2026-02-06T10:00:00Z",
          "pid": 1
        },
        "pod_labels": {
          "app": "aegisnet-checkpointer",
          "app.kubernetes.io/part-of": "aegisnet"
        },
        "workload": "aegisnet-checkpointer",
        "workload_kind": "Deployment"
      },
      "docker": "a1b2c3d4e5f6abc",
      "parent_exec_id": "a]7iu:198274100:1",
      "tid": 95921
    },
    "parent": {
      "exec_id": "a]7iu:198274100:1",
      "pid": 1,
      "uid": 0,
      "binary": "/usr/bin/aegisnet-checkpointer",
      "arguments": "--checkpoint-every 10 --witness-timeout-sec 5",
      "start_time": "2026-02-06T10:00:00Z",
      "pod": { "..." : "same pod metadata" }
    }
  },
  "node_name": "ip-10-0-1-42.ec2.internal",
  "time": "2026-02-06T10:30:00.123456789Z",
  "cluster_name": "backbay-prod-us-east-1"
}
```

### 2.4 Example: process_kprobe JSON Event (File Access)

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "a]7iu:198274312:95921",
      "pid": 95921,
      "binary": "/usr/bin/cat",
      "arguments": "/etc/shadow",
      "pod": { "namespace": "default", "name": "suspicious-pod-xyz" }
    },
    "parent": { "..." : "parent process info" },
    "function_name": "security_file_open",
    "args": [
      {
        "file_arg": {
          "path": "/etc/shadow",
          "permission": "-rw-r-----",
          "flags": "O_RDONLY"
        }
      }
    ],
    "action": "KPROBE_ACTION_SIGKILL",
    "policy_name": "file-integrity-enforcement",
    "message": "Unauthorized access to /etc/shadow blocked",
    "tags": ["fim", "sensitive-file", "MITRE:T1003"]
  },
  "node_name": "ip-10-0-1-42.ec2.internal",
  "time": "2026-02-06T10:31:15.987654321Z"
}
```

### 2.5 Example: process_kprobe JSON Event (Network)

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "a]7iu:198274500:96001",
      "pid": 96001,
      "binary": "/usr/bin/python3",
      "arguments": "exfil.py",
      "pod": { "namespace": "workloads", "name": "ml-training-abc" }
    },
    "function_name": "tcp_connect",
    "args": [
      {
        "sock_arg": {
          "family": "AF_INET",
          "type": "SOCK_STREAM",
          "protocol": "IPPROTO_TCP",
          "saddr": "10.0.1.42",
          "sport": 45678,
          "daddr": "198.51.100.99",
          "dport": 4444
        }
      }
    ],
    "action": "KPROBE_ACTION_POST",
    "policy_name": "network-exfiltration-detection",
    "message": "Outbound connection to suspicious port 4444",
    "tags": ["network", "exfiltration", "MITRE:T1041"]
  },
  "node_name": "ip-10-0-1-42.ec2.internal",
  "time": "2026-02-06T10:32:00Z"
}
```

### 2.6 Export Methods

| Method         | Path                                          | Notes                               |
|----------------|-----------------------------------------------|--------------------------------------|
| **JSON file**  | `/var/run/cilium/tetragon/tetragon.log`       | Default. Collect via Fluentd/Filebeat|
| **gRPC stream**| `localhost:54321` (configurable)               | `GetEvents` server-streaming RPC     |
| **stdout**     | Container stdout                              | For `tetra getevents`                |
| **Elastic**    | Via Filebeat + Elastic integration             | Native Elastic integration exists    |

**Key limitation**: Tetragon does not have a native NATS exporter. The integration path for AegisNet requires a **sidecar bridge** (see Section 4).

---

## 3. TracingPolicy Examples

### 3.1 Unauthorized Process Execution in Pods

Detect and optionally kill processes not in an approved allowlist within sensitive namespaces:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: aegisnet-exec-allowlist
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    args:
    - index: 0
      type: "string"
    selectors:
    # Allow known AegisNet binaries silently
    - matchBinaries:
      - operator: In
        values:
        - "/usr/bin/aegisnet-checkpointer"
        - "/usr/bin/aegisnet-witness"
        - "/usr/bin/aegisnet-proofs-api"
        - "/usr/bin/aegisnet-model-registry"
        - "/usr/bin/aegisctl"
      matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: NoPost
    # Alert on any other exec in aegisnet namespace
    - matchNamespaces:
      - namespace: Pid
        operator: NotIn
        values:
        - "host_ns"
      matchActions:
      - action: Post
        rateLimit: "1m"
```

### 3.2 File Integrity Monitoring with Hash Collection

Monitor access to sensitive configuration and key material:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: aegisnet-fim
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
        - "/var/run/secrets/kubernetes.io/"
        - "/var/run/spire/agent/"
      matchActions:
      - action: Post
        imaHash: true
```

### 3.3 Network Exfiltration Detection

Alert on outbound connections to non-cluster, non-NATS destinations from AegisNet pods:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: aegisnet-network-egress
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    # Alert on connections outside expected CIDR ranges
    - matchArgs:
      - index: 0
        operator: "NotDAddr"
        values:
        - "10.0.0.0/8"       # Cluster CIDR
        - "172.16.0.0/12"    # Service CIDR
        - "127.0.0.0/8"      # Loopback
      matchActions:
      - action: Post
```

### 3.4 Crypto Mining Detection

Detect common crypto mining indicators (stratum protocol connections):

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: cryptominer-detection
spec:
  kprobes:
  - call: "tcp_connect"
    syscall: false
    args:
    - index: 0
      type: "sock"
    selectors:
    # Common stratum mining ports
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

### 3.5 Container Escape Detection

Monitor namespace changes and privilege escalation attempts:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: container-escape-detection
spec:
  kprobes:
  # Detect setuid to root
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

### 3.6 ClawdStrike Guard Enforcement (hushd Integration)

Monitor processes that attempt to bypass ClawdStrike policy enforcement:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: clawdstrike-guard-enforcement
spec:
  kprobes:
  # Monitor writes to policy files
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

---

## 4. AegisNet Integration Patterns

### 4.1 Architecture: Tetragon to AegisNet Pipeline

```
  ┌──────────────────────────────────────────────────────────────┐
  │                     EKS Node                                  │
  │                                                              │
  │  ┌─────────────┐   gRPC     ┌───────────────────────────┐   │
  │  │  Tetragon    │──────────>│  tetragon-nats-bridge      │   │
  │  │  DaemonSet   │ :54321    │  (sidecar / DaemonSet)     │   │
  │  │              │           │                             │   │
  │  │  - kprobes   │           │  1. Subscribe gRPC stream   │   │
  │  │  - LSM hooks │           │  2. Filter + transform      │   │
  │  │  - tracepoints│          │  3. Sign as envelope fact   │   │
  │  └─────────────┘           │  4. Publish to NATS JS      │   │
  │                             └──────────┬────────────────┘   │
  └────────────────────────────────────────┼─────────────────────┘
                                           │
                    NATS JetStream         │
  ┌────────────────────────────────────────▼─────────────────────┐
  │  aegis.spine.envelope.tetragon.v1                             │
  │  aegis.spine.envelope.tetragon.process_exec.v1               │
  │  aegis.spine.envelope.tetragon.process_kprobe.v1             │
  │  aegis.spine.envelope.tetragon.process_exit.v1               │
  └──────────────────────────┬───────────────────────────────────┘
                             │
  ┌──────────────────────────▼───────────────────────────────────┐
  │  AegisNet Checkpointer                                        │
  │  - Subscribes to aegis.spine.envelope.>                       │
  │  - Extracts envelope_hash, appends to AEGISNET_LOG stream    │
  │  - Builds Merkle tree, emits checkpoint                       │
  │  - Witness co-signs checkpoint                                │
  └──────────────────────────┬───────────────────────────────────┘
                             │
  ┌──────────────────────────▼───────────────────────────────────┐
  │  AegisNet Proofs API                                          │
  │  GET /v1/checkpoints/latest                                   │
  │  GET /v1/proofs/inclusion?envelope_hash=0x...                 │
  └──────────────────────────────────────────────────────────────┘
```

### 4.2 The tetragon-nats-bridge Service

This is a new Rust service that bridges Tetragon's gRPC export to AegisNet's NATS JetStream-based envelope system. It:

1. Connects to Tetragon's gRPC `GetEvents` streaming endpoint
2. Receives `GetEventsResponse` messages
3. Transforms each event into an AegisNet `SignedEnvelope` with a `fact` payload
4. Publishes to the appropriate NATS subject

**Proposed implementation** (Rust, using `tonic` for gRPC client and `async-nats` for NATS):

```rust
// Pseudocode for the bridge
async fn bridge_loop(
    tetragon_client: TetragonClient,
    nats_client: async_nats::Client,
    signing_keypair: aegisnet::Keypair,
) -> Result<()> {
    let mut stream = tetragon_client
        .get_events(GetEventsRequest::default())
        .await?
        .into_inner();

    let mut seq: u64 = 0;
    let mut prev_hash: Option<String> = None;

    while let Some(response) = stream.message().await? {
        let (fact, subject_suffix) = transform_event(&response)?;

        seq += 1;
        let envelope = aegisnet::spine::build_signed_envelope(
            &signing_keypair,
            seq,
            prev_hash.clone(),
            fact,
            aegisnet::spine::now_rfc3339(),
        )?;

        prev_hash = Some(
            envelope["envelope_hash"]
                .as_str()
                .unwrap()
                .to_string()
        );

        let subject = format!(
            "aegis.spine.envelope.tetragon.{}.v1",
            subject_suffix
        );
        let payload = serde_json::to_vec(&envelope)?;
        nats_client.publish(subject, payload.into()).await?;
    }

    Ok(())
}
```

### 4.3 NATS Subject Naming Convention

Extending AegisNet's existing subject hierarchy:

| Subject                                            | Direction | Purpose                               |
|----------------------------------------------------|-----------|---------------------------------------|
| `aegis.spine.envelope.tetragon.v1`                 | Publish   | All Tetragon events (wildcard)        |
| `aegis.spine.envelope.tetragon.process_exec.v1`    | Publish   | Process execution events              |
| `aegis.spine.envelope.tetragon.process_exit.v1`    | Publish   | Process exit events                   |
| `aegis.spine.envelope.tetragon.process_kprobe.v1`  | Publish   | Kprobe-triggered events               |
| `aegis.spine.envelope.tetragon.process_lsm.v1`    | Publish   | LSM hook events                       |
| `aegis.spine.envelope.tetragon.enforcement.v1`     | Publish   | Events where enforcement action fired |

These subjects should be added to the `AEGISNET_LOG` stream's subject filter so the checkpointer automatically ingests them.

### 4.4 Tetragon Event to AegisNet Envelope Transformation

The `fact` field within the `SignedEnvelope` wraps the Tetragon event:

```json
{
  "schema": "aegis.spine.fact.tetragon_event.v1",
  "fact_id": "tet_<uuid>",
  "event_type": "process_kprobe",
  "node_name": "ip-10-0-1-42.ec2.internal",
  "cluster_name": "backbay-prod-us-east-1",
  "timestamp": "2026-02-06T10:31:15.987654321Z",
  "policy_name": "file-integrity-enforcement",
  "action": "KPROBE_ACTION_SIGKILL",
  "tags": ["fim", "sensitive-file", "MITRE:T1003"],
  "process": {
    "exec_id": "a]7iu:198274312:95921",
    "pid": 95921,
    "binary": "/usr/bin/cat",
    "arguments": "/etc/shadow",
    "uid": 1000,
    "pod_namespace": "default",
    "pod_name": "suspicious-pod-xyz",
    "container_id": "containerd://a1b2c3d4e5f6",
    "container_image": "docker.io/library/ubuntu:22.04"
  },
  "kprobe": {
    "function_name": "security_file_open",
    "args_summary": {
      "path": "/etc/shadow",
      "flags": "O_RDONLY"
    }
  },
  "severity": "critical",
  "mitre_technique": "T1003"
}
```

The complete envelope wrapping:

```json
{
  "schema": "aegis.spine.envelope.v1",
  "issuer": "aegis:ed25519:<bridge-pubkey-hex>",
  "seq": 42,
  "prev_envelope_hash": "0x<prev-sha256>",
  "issued_at": "2026-02-06T10:31:16Z",
  "capability_token": null,
  "fact": { "...tetragon fact above..." },
  "envelope_hash": "0x<sha256-of-canonical-json>",
  "signature": "0x<ed25519-signature>"
}
```

### 4.5 JetStream Resources (Extended)

Add to existing AegisNet JetStream resources:

| Resource                | Type   | Replicas | Purpose                               |
|-------------------------|--------|----------|---------------------------------------|
| `AEGISNET_LOG`          | Stream | 3        | Existing -- add `tetragon.*` subjects |
| `AEGISNET_TETRAGON_RAW`| Stream | 1        | Optional: raw Tetragon events (debug) |

Configuration update for `AEGISNET_LOG`:

```json
{
  "name": "AEGISNET_LOG",
  "subjects": [
    "aegis.spine.log.leaf.v1",
    "aegis.spine.envelope.tetragon.>"
  ],
  "num_replicas": 3,
  "storage": "file",
  "retention": "limits"
}
```

---

## 5. ClawdStrike Feed Integration

### 5.1 Current State Analysis

ClawdStrike's desktop app has three views that currently use mock/limited data:

1. **ThreatRadarView** (`apps/desktop/src/features/threat-radar/ThreatRadarView.tsx`)
   - Uses `MOCK_THREATS` array with 8 hardcoded threats
   - Each threat: `{ id, angle, distance, severity, type, active, label }`
   - Types: `malware | intrusion | anomaly | ddos | phishing`

2. **AttackGraphView** (`apps/desktop/src/features/attack-graph/AttackGraphView.tsx`)
   - Uses `MOCK_CHAINS` with 3 hardcoded MITRE ATT&CK chains
   - Each chain: `{ id, name, actor, campaign?, status, techniques[] }`
   - Techniques mapped to MITRE IDs (T1566.001, T1059.001, etc.)

3. **EventStreamView** (`apps/desktop/src/features/events/EventStreamView.tsx`)
   - **Already real**: Connects to hushd via SSE at `/api/v1/events`
   - Processes `check`, `violation`, `eval` events from hushd daemon
   - Has filter, live/pause toggle, receipt panel

### 5.2 Tetragon Event to Threat Radar Mapping

Map Tetragon events to the `Threat` type used by `@backbay/glia ThreatRadar`:

```typescript
// Proposed: tetragonToThreat mapping
interface Threat {
  id: string;        // Tetragon exec_id or event UUID
  angle: number;     // Derived from hash of pod namespace (cluster segment)
  distance: number;  // Inversely proportional to severity (closer = worse)
  severity: number;  // 0-1 scale from Tetragon event context
  type: ThreatType;  // Map from Tetragon event type
  active: boolean;   // True if enforcement action was Post (not Sigkill)
  label: string;     // policy_name + message from TracingPolicy
}

function tetragonEventToThreat(event: TetragonEvent): Threat {
  return {
    id: event.process.exec_id,
    angle: hashToAngle(event.process.pod?.namespace ?? "unknown"),
    distance: 1.0 - mapSeverity(event),
    severity: mapSeverity(event),
    type: mapThreatType(event),
    active: event.action !== "KPROBE_ACTION_SIGKILL",
    label: `${event.policy_name}: ${event.message ?? event.function_name}`,
  };
}

function mapThreatType(event: TetragonEvent): ThreatType {
  // Map based on policy tags and function name
  if (event.tags?.includes("malware")) return "malware";
  if (event.tags?.includes("exfiltration")) return "intrusion";
  if (event.function_name?.includes("tcp_connect")) return "intrusion";
  if (event.tags?.includes("fim")) return "anomaly";
  if (event.action === "KPROBE_ACTION_SIGKILL") return "malware";
  return "anomaly";
}
```

### 5.3 Tetragon Events to Attack Graph

Map Tetragon events to MITRE ATT&CK chains using policy tags:

```typescript
// Proposed: Build attack chains from correlated Tetragon events
// Key insight: Tetragon's exec_id + parent_exec_id form a process tree
// that maps naturally to ATT&CK kill chains

function buildAttackChains(events: TetragonEvent[]): AttackChain[] {
  // Group events by parent_exec_id lineage
  const processTree = buildProcessTree(events);

  // Map process trees to ATT&CK chains using MITRE tags
  return processTree.roots.map(root => ({
    id: `chain-${root.exec_id}`,
    name: inferCampaignName(root),
    actor: inferActor(root), // From threat intel correlation
    status: hasEnforcementAction(root) ? "contained" : "active",
    techniques: root.descendants
      .filter(e => e.tags?.some(t => t.startsWith("MITRE:")))
      .map(e => ({
        id: e.tags.find(t => t.startsWith("MITRE:"))!.slice(6),
        name: e.message ?? e.function_name,
        tactic: inferTactic(e),
        detected: true,
        confidence: e.action === "KPROBE_ACTION_SIGKILL" ? 0.99 : 0.75,
      })),
  }));
}
```

### 5.4 Tetragon Events in Event Stream

The EventStreamView already supports real hushd SSE events. Tetragon events can be surfaced two ways:

**Option A: Bridge through hushd** -- The tetragon-nats-bridge publishes to NATS, hushd subscribes to Tetragon NATS subjects and re-emits them as SSE events with `type: "tetragon"`.

**Option B: Direct WebSocket** -- Add a new SSE/WebSocket endpoint in hushd or a separate service that streams Tetragon events directly to the ClawdStrike desktop app.

Recommended: **Option A** (bridge through hushd) to maintain a single event stream and leverage hushd's existing audit/receipt infrastructure.

### 5.5 New Event Types for EventStreamView

Extend the `DaemonEvent` type system:

```typescript
// Extend existing types in apps/desktop/src/types/events.ts

export type ActionType =
  | "file_access" | "file_write" | "egress" | "shell"
  | "mcp_tool" | "patch" | "secret_access" | "custom"
  // New Tetragon-sourced types:
  | "process_exec" | "process_exit" | "kernel_hook"
  | "namespace_change" | "capability_change";

export interface TetragonEventData {
  event_type: "process_exec" | "process_exit" | "process_kprobe" | "process_lsm";
  exec_id: string;
  binary: string;
  arguments?: string;
  pid: number;
  pod_namespace?: string;
  pod_name?: string;
  container_id?: string;
  function_name?: string;
  policy_name?: string;
  enforcement_action?: string;
  tags?: string[];
  mitre_technique?: string;
  // AegisNet attestation fields
  envelope_hash?: string;
  checkpoint_seq?: number;
  inclusion_proof_available?: boolean;
}
```

### 5.6 Data Flow: End to End

```
  Kernel eBPF hook fires
       │
       ▼
  Tetragon agent (in-kernel filter, K8s enrichment)
       │
       ▼ gRPC GetEvents stream
  tetragon-nats-bridge
       │
       ├──► NATS: aegis.spine.envelope.tetragon.process_kprobe.v1
       │         (SignedEnvelope with Tetragon fact)
       │
       ▼
  AegisNet Checkpointer
       │
       ├──► Merkle tree append
       ├──► Checkpoint emission
       └──► Witness co-signature
       │
       ▼
  hushd (subscribes to NATS tetragon subjects)
       │
       ├──► Maps to SecurityEvent (existing SIEM type)
       ├──► SSE broadcast to desktop clients
       └──► Audit log append
       │
       ▼
  ClawdStrike Desktop
       │
       ├──► EventStreamView (real-time feed)
       ├──► ThreatRadarView (3D threat positions)
       └──► AttackGraphView (MITRE ATT&CK correlation)
```

---

## 6. Runtime Proof Chains

### 6.1 The Novel Concept

The unique value proposition of combining Tetragon + AegisNet + SPIRE is **verifiable execution proof at the kernel level**:

```
  Kernel-Level Evidence    +  Cryptographic Identity  +  Append-Only Log
  ─────────────────────       ──────────────────────     ────────────────
  Tetragon process_exec       SPIRE SVID (X.509)        AegisNet Merkle
  - binary path + hash        - SPIFFE ID               - RFC 6962 proof
  - args, UID, capabilities   - Workload attestation    - Witness co-sign
  - file IMA hashes           - mTLS certificate        - Checkpoint chain
  - network connections        - Trust domain
  - parent process lineage
```

This creates a chain of proof:

1. **What binary executed** -- Tetragon `process_exec` with `binary_properties.imaHash`
2. **With what identity** -- SPIRE SVID linking the workload to a SPIFFE ID
3. **In what context** -- Kubernetes pod/namespace/node, process ancestry
4. **Verifiably recorded** -- AegisNet SignedEnvelope in Merkle tree
5. **Independently witnessed** -- Witness co-signature on checkpoint
6. **Externally anchored** -- Future: Rekor/EAS/Solana timestamp

### 6.2 Execution Proof Envelope

A "runtime proof" fact that combines Tetragon + SPIRE data:

```json
{
  "schema": "aegis.spine.fact.runtime_proof.v1",
  "fact_id": "rp_<uuid>",
  "proof_type": "execution",
  "timestamp": "2026-02-06T10:30:00.123Z",

  "execution": {
    "binary": "/usr/bin/aegisnet-checkpointer",
    "binary_hash_ima": "sha256:abc123def456...",
    "arguments": "--checkpoint-every 10",
    "pid": 95921,
    "uid": 0,
    "exec_id": "a]7iu:198274312:95921",
    "parent_exec_id": "a]7iu:198274100:1",
    "capabilities": "0x00000000a80425fb",
    "namespaces": {
      "mnt": 4026532256,
      "pid": 4026532259
    }
  },

  "identity": {
    "spiffe_id": "spiffe://aegis.backbay.industries/ns/aegisnet/sa/checkpointer",
    "svid_serial": "abc123",
    "trust_domain": "aegis.backbay.industries"
  },

  "kubernetes": {
    "namespace": "aegisnet",
    "pod": "aegisnet-checkpointer-7d4b8f6c-k9x2m",
    "node": "ip-10-0-1-42.ec2.internal",
    "container_image": "419659069643.dkr.ecr.us-east-1.amazonaws.com/aegisnet:sha-1a2b3c4",
    "container_image_digest": "sha256:...",
    "service_account": "aegisnet-checkpointer"
  },

  "network_enforcement": {
    "tetragon_policy": "aegisnet-network-egress",
    "cilium_network_policy": "aegisnet-checkpointer-egress",
    "observed_connections": [
      {
        "daddr": "10.0.1.100",
        "dport": 4222,
        "protocol": "TCP",
        "service": "nats"
      }
    ]
  },

  "attestation_chain": {
    "tetragon_exec_id": "a]7iu:198274312:95921",
    "spire_svid_hash": "sha256:...",
    "clawdstrike_receipt_hash": "sha256:...",
    "aegisnet_envelope_hash": "0x..."
  }
}
```

### 6.3 Enforcement Tier Model

The AegisNet TrustBundle already supports `required_receipt_enforcement_tiers`. Tetragon enables a new tier:

| Tier                        | Meaning                                               | How Verified                         |
|-----------------------------|-------------------------------------------------------|--------------------------------------|
| `best_effort`               | ClawdStrike SDK checked, but no kernel enforcement    | Receipt signature only               |
| `daemon_enforced`           | hushd made the decision, signed receipt               | hushd receipt + policy hash          |
| `linux_kernel_enforced`     | Tetragon eBPF policy active, kernel-level enforcement | Tetragon event in AegisNet log       |
| `linux_kernel_attested`     | Tetragon observed + SPIRE identity + AegisNet proof   | Full proof chain (see 6.2)           |

The `require_kernel_loader_signatures` field in TrustBundle can be extended to require Tetragon policy attestation signatures.

### 6.4 Verification Flow

```
  Verifier (client or auditor)
       │
       ├─ 1. Fetch latest checkpoint from Proofs API
       │      GET /v1/checkpoints/latest
       │
       ├─ 2. Verify witness signature(s)
       │      checkpoint_hash → witness co-sign
       │
       ├─ 3. Fetch inclusion proof for specific envelope
       │      GET /v1/proofs/inclusion?envelope_hash=0x...
       │
       ├─ 4. Verify RFC 6962 Merkle inclusion proof
       │      audit_path → reconstruct root → match checkpoint merkle_root
       │
       ├─ 5. Verify envelope signature (bridge's Ed25519 key)
       │      canonical JSON → SHA-256 → Ed25519 verify
       │
       └─ 6. Verify fact contents
              - Tetragon event matches expected policy
              - SPIRE SVID was valid at timestamp
              - Binary hash matches expected image digest
```

---

## 7. Deployment on EKS with AL2023

### 7.1 Kernel Compatibility

| AMI                    | Kernel Version | BTF Support | eBPF Support | Tetragon Compatible |
|------------------------|----------------|-------------|--------------|---------------------|
| AL2023 (original)      | 6.1.x          | Yes         | Yes          | Yes                 |
| AL2023.7 (2025 Q2)    | 6.12.x         | Yes         | Enhanced     | Yes (recommended)   |
| Amazon Linux 2 (EKS)  | 5.10.x         | Partial     | Yes          | Yes (basic)         |

AL2023 ships with kernel 6.1+ which exceeds Tetragon's minimum requirement of kernel 5.8. The 6.12 kernel available in AL2023.7 provides enhanced eBPF support and is recommended.

BTF is enabled by default in AL2023 (`CONFIG_DEBUG_INFO_BTF=y`), which Tetragon requires for CO-RE (Compile Once, Run Everywhere) eBPF programs.

### 7.2 Helm Deployment

```bash
# Add Cilium Helm repo
helm repo add cilium https://helm.cilium.io
helm repo update

# Install Tetragon as DaemonSet
helm install tetragon cilium/tetragon \
  -n kube-system \
  --set tetragon.grpc.address="localhost:54321" \
  --set tetragon.exportFilename="/var/run/cilium/tetragon/tetragon.log" \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true \
  --set tetragonOperator.enabled=true \
  --set resources.requests.cpu="100m" \
  --set resources.requests.memory="256Mi" \
  --set resources.limits.cpu="1000m" \
  --set resources.limits.memory="1Gi"

# Verify rollout
kubectl rollout status -n kube-system ds/tetragon -w
```

### 7.3 Resource Requirements

| Component              | CPU Request | CPU Limit | Memory Request | Memory Limit |
|------------------------|-------------|-----------|----------------|--------------|
| Tetragon DaemonSet     | 100m        | 1000m     | 256Mi          | 1Gi          |
| tetragon-nats-bridge   | 50m         | 250m      | 64Mi           | 256Mi        |
| Tetragon Operator      | 10m         | 100m      | 32Mi           | 128Mi        |

### 7.4 DaemonSet Architecture on EKS

```
  ┌─────────────────────────────────────────────────┐
  │  EKS Node (AL2023, kernel 6.1+)                  │
  │                                                  │
  │  ┌────────────────────────────────────────────┐  │
  │  │  tetragon Pod (DaemonSet, kube-system)      │  │
  │  │                                              │  │
  │  │  ┌──────────────┐  ┌──────────────────────┐ │  │
  │  │  │ tetragon     │  │ tetragon-nats-bridge │ │  │
  │  │  │ container    │  │ sidecar container    │ │  │
  │  │  │              │  │                      │ │  │
  │  │  │ eBPF progs   │  │ gRPC client          │ │  │
  │  │  │ gRPC server  │──│ NATS publisher       │ │  │
  │  │  │ JSON log     │  │ Ed25519 signer       │ │  │
  │  │  └──────────────┘  └──────────────────────┘ │  │
  │  │                                              │  │
  │  │  hostPID: true                               │  │
  │  │  volumes: /sys/kernel/tracing, /proc          │  │
  │  └────────────────────────────────────────────┘  │
  │                                                  │
  │  ┌─────────────┐  ┌─────────────┐               │
  │  │ App Pod A   │  │ App Pod B   │ ...            │
  │  └─────────────┘  └─────────────┘               │
  └─────────────────────────────────────────────────┘
```

### 7.5 TracingPolicy Deployment

TracingPolicies are cluster-scoped CRDs applied via kubectl or GitOps:

```bash
# Apply all ClawdStrike/AegisNet policies
kubectl apply -f deploy/tetragon-policies/

# Verify policies loaded
kubectl get tracingpolicies
kubectl describe tracingpolicy aegisnet-exec-allowlist
```

### 7.6 Monitoring Tetragon Health

```bash
# Check Tetragon status
kubectl -n kube-system exec ds/tetragon -c tetragon -- tetra status

# View events (compact)
kubectl -n kube-system exec ds/tetragon -c tetragon -- tetra getevents -o compact

# View events (full JSON)
kubectl -n kube-system exec ds/tetragon -c tetragon -- tetra getevents -o json

# Prometheus metrics
# Exposed at :2112/metrics by default
```

---

## 8. Open Questions

### 8.1 Event Volume at Scale

**Question**: What is the expected event volume per node/cluster with our TracingPolicies?

**Estimation**:
- Process exec/exit: ~100-1000 events/sec/node (depends on workload)
- Kprobe file access: ~50-500 events/sec/node (with selector filtering)
- Network connect: ~10-100 events/sec/node (with CIDR filtering)
- Total per cluster (50 nodes): ~5K-50K events/sec

**Mitigation**: Use rate limiting in TracingPolicy selectors (`rateLimit: "5m"`), aggressive in-kernel filtering via `matchBinaries` / `matchNamespaces`, and NATS JetStream backpressure.

### 8.2 Event Deduplication

**Question**: How to handle duplicate events from overlapping policies or node failures?

**Approach**: Each Tetragon event has a unique `exec_id` + `time` pair. The tetragon-nats-bridge should include a dedup key in the envelope's `fact_id` field derived from `sha256(exec_id + time + function_name)`. The AegisNet checkpointer already handles duplicate envelope hashes via the `AEGISNET_LOG_INDEX` KV bucket.

### 8.3 Latency: Kernel Event to Attestation

**Question**: What is the end-to-end latency from kernel hook to AegisNet checkpoint inclusion?

**Estimated breakdown**:
| Stage                           | Latency       |
|---------------------------------|---------------|
| eBPF hook to userspace          | ~1-5ms        |
| Tetragon processing + K8s enrichment | ~5-20ms |
| gRPC to bridge                  | ~1-5ms        |
| Bridge transform + sign         | ~1-2ms        |
| NATS publish                    | ~1-5ms        |
| Checkpointer ingestion          | ~5-10ms       |
| Checkpoint emission (batched)   | 5-10 seconds  |
| Witness co-sign                 | ~50-200ms     |
| **Total to checkpoint**         | **5-15 seconds** |

The checkpoint latency is dominated by the batching interval (`--checkpoint-interval-sec 5`).

### 8.4 Tetragon Enforcement vs. ClawdStrike Guards

**Question**: Can Tetragon enforcement mode replace some ClawdStrike guards?

**Analysis**:
| ClawdStrike Guard       | Tetragon Replacement?  | Notes                                    |
|-------------------------|------------------------|------------------------------------------|
| ForbiddenPathGuard      | Yes (LSM file_open)    | Kernel-level, no bypass possible         |
| EgressAllowlistGuard    | Yes (tcp_connect)      | Combined with Cilium NetworkPolicy       |
| SecretLeakGuard         | Partial                | Can detect file writes, not content scan |
| PatchIntegrityGuard     | No                     | Requires semantic patch analysis         |
| McpToolGuard            | No                     | Application-layer MCP protocol           |
| PromptInjectionGuard    | No                     | Requires NLP analysis                    |
| JailbreakGuard          | No                     | Requires ML/LLM judge                    |

**Recommendation**: Use Tetragon as a **kernel-level enforcement floor** beneath ClawdStrike's application-level guards. Tetragon handles low-level filesystem, network, and process enforcement that cannot be bypassed. ClawdStrike handles semantic, content-aware, and AI-specific guards.

### 8.5 Bridge Service HA and Recovery

**Question**: How does the bridge handle restarts and message loss?

**Approach**:
- The bridge should persist its last-published NATS sequence number to a local file or NATS KV bucket
- On restart, reconnect to Tetragon gRPC stream (which replays recent events)
- Use NATS JetStream publish with ack to ensure at-least-once delivery
- The AegisNet checkpointer's dedup via `AEGISNET_LOG_INDEX` handles duplicates

### 8.6 Multi-Cluster Federation

**Question**: How do Tetragon events from multiple EKS clusters feed into a single AegisNet log?

**Approach**: Each cluster runs its own tetragon-nats-bridge with a cluster-specific signing keypair. Events are published to cluster-scoped NATS subjects (`aegis.spine.envelope.tetragon.{cluster_name}.>`). A NATS Leaf Node or Gateway bridges inter-cluster traffic. The AegisNet checkpointer can subscribe to `aegis.spine.envelope.>` across all clusters.

### 8.7 SPIRE Integration for Bridge Identity

**Question**: How does the tetragon-nats-bridge authenticate itself?

**Approach**: The bridge obtains a SPIRE SVID with SPIFFE ID `spiffe://aegis.backbay.industries/ns/kube-system/sa/tetragon-nats-bridge`. The Ed25519 signing key for envelope creation should be derived from or rotated alongside the SPIRE identity. The bridge's node ID (`aegis:ed25519:<pubkey>`) is added to the TrustBundle's `allowed_receipt_signer_node_ids`.

---

## Appendix A: Reference Links

- [Tetragon Documentation](https://tetragon.io/docs/overview/)
- [Tetragon GitHub](https://github.com/cilium/tetragon)
- [Tetragon gRPC API Reference](https://tetragon.io/docs/reference/grpc-api/)
- [Tetragon TracingPolicy Concepts](https://tetragon.io/docs/concepts/tracing-policy/)
- [Tetragon Hook Points](https://tetragon.io/docs/concepts/tracing-policy/hooks/)
- [Tetragon Selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/)
- [Tetragon Helm Chart](https://tetragon.io/docs/reference/helm-chart/)
- [Tetragon Policy Library](https://tetragon.io/docs/policy-library/observability/)
- [Tetragon File Integrity Monitoring](https://tetragon.io/features/file-integrity-monitoring/)
- [Tetragon Network Observability](https://tetragon.io/docs/use-cases/network-observability/)
- [Tetragon on EKS](https://www.stream.security/post/how-to-deploy-tetragon-on-an-eks-cluster)
- [Tetragon Container Escape Detection](https://isovalent.com/blog/post/2021-11-container-escape/)
- [AL2023 Kernel Changes](https://docs.aws.amazon.com/linux/al2023/ug/compare-with-al2-kernel.html)
- [AegisNet Architecture](../../standalone/aegis/apps/aegis/services/aegisnet/ARCHITECTURE.md)
- [ClawdStrike CLAUDE.md](../CLAUDE.md)

## Appendix B: Glossary

| Term                  | Definition                                                                 |
|-----------------------|----------------------------------------------------------------------------|
| **BTF**               | BPF Type Format -- kernel debug info enabling portable eBPF programs       |
| **CO-RE**             | Compile Once Run Everywhere -- eBPF portability across kernel versions     |
| **CRD**               | Custom Resource Definition -- Kubernetes extension mechanism               |
| **DaemonSet**         | K8s workload that runs one pod per node                                    |
| **exec_id**           | Tetragon's cluster-wide unique process identifier                          |
| **IMA**               | Integrity Measurement Architecture -- Linux kernel integrity subsystem     |
| **kprobe**            | Dynamic kernel function hook                                               |
| **LSM**               | Linux Security Module -- mandatory access control framework                |
| **RFC 6962**          | Certificate Transparency Merkle tree specification                         |
| **SignedEnvelope**    | AegisNet's cryptographically signed log entry                              |
| **SPIFFE/SPIRE**      | Secure Production Identity Framework / SPIFFE Runtime Environment          |
| **SVID**              | SPIFFE Verifiable Identity Document                                        |
| **TracingPolicy**     | Tetragon's CRD for defining eBPF security policies                        |
| **tracepoint**        | Stable kernel trace hook (more portable than kprobes)                      |
