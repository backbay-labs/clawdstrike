# PACT: Provable Agent Capability Transport

## Protocol Design Document

**Version:** 0.1.0-draft
**Date:** 2026-03-17
**Status:** Pre-RFC
**Authors:** ClawdStrike Protocol Team

---

## Abstract

PACT (Provable Agent Capability Transport) is a protocol for secure, attested
tool access in AI agent systems. It replaces the Model Context Protocol (MCP)
with a ground-up design rooted in capability-based security, cryptographic
attestation, and privilege separation. Every tool invocation flows through a
kernel that the agent cannot address, is gated by a time-bounded capability
token the agent must present, and produces a signed receipt that forms an
immutable audit trail. Policy correctness is formally verifiable before a single
tool call is made.

PACT is not an incremental improvement to MCP. It is a new protocol designed
from ClawdStrike's first principles:

1. **Fail closed.** If something goes wrong, deny access.
2. **Sign the truth.** Every decision gets a cryptographic receipt.
3. **The enforcement layer is not in the agent's addressable universe.**
4. **Capabilities, not permissions.** Agents hold attenuated, revocable, time-bounded tokens.
5. **Prove it works.** Policy correctness is formally verified.

---

## 1. Architecture

### 1.1 Components

PACT defines five principal components. Each runs in a separate trust domain.

| Component | Role | Trust Level |
|-----------|------|-------------|
| **Agent** | LLM-powered process that consumes tools | Untrusted |
| **Runtime Kernel** (Kernel) | Mediator between agent and tools; enforces policy, validates capabilities, signs receipts | Trusted (TCB) |
| **Tool Server** | Process that implements one or more tools; executes actions on request from the Kernel | Semi-trusted (authenticated, sandboxed) |
| **Capability Authority** (CA) | Issues, attenuates, and revokes capability tokens; maintains the revocation store | Trusted (offline or isolated) |
| **Receipt Log** | Append-only, Merkle-committed log of signed receipts and attestations | Trusted (transparency log) |

Additionally, the system includes:

| Supporting Component | Role |
|---------------------|------|
| **Policy Store** | Holds verified YAML policies; serves them to the Kernel |
| **Identity Registry** | Maps agent IDs and tool server IDs to Ed25519 public keys |

### 1.2 Communication

All inter-component communication uses one of two transports:

- **Kernel <-> Agent:** A unidirectional message channel. The agent sends
  requests to the Kernel via a file descriptor, Unix domain socket, or
  named pipe. The Kernel responds over a separate return channel. The agent
  never learns the Kernel's network address or process identity. The Kernel
  may be in a separate pid namespace, cgroup, or VM. The wire format is
  length-prefixed canonical JSON (RFC 8785 / JCS).

- **Kernel <-> Tool Server:** mTLS over a Unix domain socket or TCP
  connection. The Kernel authenticates the Tool Server via its SPIFFE
  identity or a signed manifest pinned to the Tool Server's Ed25519 key.
  The Tool Server authenticates the Kernel the same way. The wire format
  is length-prefixed canonical JSON.

- **Kernel <-> Capability Authority:** mTLS or signed request/response
  envelopes over HTTPS. The CA may be co-located (same host, separate
  process) or remote.

- **Kernel -> Receipt Log:** Append-only writes via the Spine protocol
  (signed envelopes over NATS JetStream or HTTPS POST). Receipts are
  batched into Merkle trees and periodically checkpointed with witness
  co-signatures.

### 1.3 Serialization

All protocol messages use **canonical JSON (RFC 8785)** for deterministic
hashing and signing. Binary fields (hashes, signatures, public keys) are
hex-encoded with optional `0x` prefix. Timestamps are ISO-8601 / RFC 3339
with second or millisecond precision in UTC.

This matches ClawdStrike's existing `hush-core::canonical::canonicalize`
implementation and ensures cross-language determinism (Rust, TypeScript,
Python, Go, WASM).

### 1.4 Trust Boundaries

```
 +------------------------------------------------------------------+
 |                        UNTRUSTED ZONE                             |
 |                                                                   |
 |  +-------------------+                                            |
 |  |      Agent        |  Cannot see Kernel address, PID, or keys  |
 |  |  (LLM + client)   |  Holds only: capability tokens + results  |
 |  +--------+----------+                                            |
 |           | (1) request + cap token                               |
 |           | (anonymous pipe / UDS)                                |
 +-----------|------------------------------------------------------+
             |
 ============|====== PROCESS / NAMESPACE BOUNDARY ====================
             |
 +-----------|------------------------------------------------------+
 |           v                  TRUSTED ZONE (TCB)                   |
 |  +--------+----------+                                            |
 |  |  Runtime Kernel    |  Validates caps, runs guards, signs       |
 |  |  (clawdstrike      |  receipts, mediates all I/O               |
 |  |   enforcement)     |                                           |
 |  +---+----------+----+                                            |
 |      |          |                                                 |
 |      | mTLS     | mTLS         +---------------------+            |
 |      |          |              | Capability Authority|            |
 |      |          |              | (issues + revokes   |            |
 |      |          |              |  cap tokens)        |            |
 |      |          |              +---------------------+            |
 |      |          |                                                 |
 +------|----------|------------------------------------------------+
        |          |
 =======|==========|=== PER-SERVER SANDBOX BOUNDARY ==================
        |          |
 +------v---+ +---v--------+  +------------------+
 | Tool Srv | | Tool Srv   |  |   Receipt Log    |
 | A        | | B          |  |  (Spine / NATS)  |
 | (sandbox)| | (sandbox)  |  |  append-only     |
 +-----------+ +------------+  +------------------+
```

**Key trust properties:**

- The Agent never communicates with Tool Servers directly. There is no
  discoverable address.
- Tool Server A cannot communicate with Tool Server B. They share no IPC
  channels, file descriptors, or network paths.
- The Kernel is the sole nexus. It is the only component that holds the
  receipt signing key, the policy, and the connections to all Tool Servers.
- The Capability Authority may be offline (pre-issued tokens) or online.
  It never communicates with Tool Servers or the Agent directly.

### 1.5 Trust Model Comparison with MCP

| Property | MCP | PACT |
|----------|-----|------|
| Agent <-> Server communication | Direct (stdio/HTTP) | Mediated by Kernel (never direct) |
| Server isolation | None (shared process or sibling) | Per-server sandbox (namespaces, separate user) |
| Authentication | None or bearer token | mTLS + SPIFFE / signed manifests |
| Authorization | None (all tools available) | Capability tokens per-tool |
| Attestation | None | Ed25519 signed receipts in Merkle log |
| Policy enforcement | None at protocol level | Kernel evaluates guards before forwarding |
| Tool discovery | Server advertises all tools | Capability tokens enumerate allowed tools |

---

## 2. Capability Model

### 2.1 Capability Token Structure

A PACT capability token is a signed, self-describing, attenuatable authorization
to invoke a specific set of tool operations. It is conceptually inspired by
macaroons and Biscuit tokens, but uses ClawdStrike's existing Ed25519 +
canonical JSON signing infrastructure rather than introducing a new crypto
format.

```
PactCapability {
    // Header
    capability_id:  String,          // UUIDv7 (time-ordered)
    schema:         "pact.capability.v1",
    issued_at:      DateTime<Utc>,
    expires_at:     DateTime<Utc>,
    not_before:     Option<DateTime<Utc>>,

    // Issuer chain
    issuer:         AgentId,         // CA or delegating agent
    subject:        AgentId,         // Agent authorized to use this token
    audience:       "pact:kernel",   // Expected verifier

    // Scope (what the token authorizes)
    scope: PactScope {
        tools: Vec<ToolGrant>,       // Which tools, which operations
        max_invocations: Option<u32>,// Total call count budget
        max_bytes_out:   Option<u64>,// Bandwidth ceiling
        resource_constraints: Option<ResourceConstraints>,
    },

    // Attenuation
    ceiling:        Option<PactScope>,   // Maximum privilege for re-delegation
    delegation_chain: Vec<String>,       // Parent capability IDs (append-only)
    delegation_depth: u32,               // Current depth (0 = root)
    max_delegation_depth: Option<u32>,   // Hard cap

    // Binding (prevents stolen tokens)
    proof_binding:  Option<ProofBinding>,// DPoP, mTLS thumbprint, or SPIFFE

    // Policy (what was verified at issuance)
    policy_hash:    String,          // SHA-256 of the verified policy
    attestation_level: AttestationLevel, // Logos verification depth

    // Context
    purpose:        Option<String>,
    metadata:       Option<serde_json::Value>,
}
```

A `ToolGrant` specifies access to a single tool:

```
ToolGrant {
    server_id:  String,              // Tool server identity
    tool_name:  String,              // Specific tool (or "*" for all on server)
    operations: Vec<String>,         // "invoke", "describe", "schema"
    argument_constraints: Option<ArgumentConstraints>,
    // e.g., file_patterns: ["src/**"], hosts: ["api.example.com"]
}
```

### 2.2 Token Lifecycle

```
 Capability Authority (CA)
        |
        | (1) Issue: CA signs PactCapability
        |     - Validates agent identity
        |     - Checks policy allows requested scope
        |     - Sets TTL (short: 60s-3600s)
        |     - Optionally binds to proof (DPoP key)
        v
 +------+------+
 |    Agent     |  Holds token as opaque signed blob
 +------+------+
        |
        | (2) Present: Agent sends token + tool call request
        |     to Kernel over anonymous channel
        v
 +------+------+
 |   Kernel     |  Validates:
 |              |  a. Signature (against CA public key)
 |              |  b. Time bounds (not expired, not before)
 |              |  c. Scope (requested tool in token's ToolGrant list)
 |              |  d. Revocation (check revocation store)
 |              |  e. Proof binding (if required, verify DPoP/mTLS)
 |              |  f. Invocation budget (decrement counter)
 |              |  g. Policy guards (run HushEngine)
 +------+------+
        |
        | (3) If all checks pass: forward to Tool Server
        | (4) If any check fails: deny, sign denial receipt
        v
    [Tool Server or Denial]
```

### 2.3 Capability Acquisition

An agent acquires capabilities through one of three paths:

**Path A: Direct issuance.** The deployment configuration pre-authorizes a
set of tool grants for an agent. At session start, the Kernel requests
capabilities from the CA on the agent's behalf. The agent receives tokens
through its input channel. The agent never contacts the CA.

**Path B: On-demand request.** The agent sends a `pact.request_capability`
message to the Kernel, describing the tools it needs. The Kernel validates
the request against policy, forwards it to the CA, and returns the issued
token (or a denial). The agent cannot request capabilities that exceed what
policy allows.

**Path C: Delegation.** Agent A delegates a subset of its capability to
Agent B by constructing a new PactCapability with:
- `delegation_chain` = A's chain + A's capability_id
- `scope` that is a subset of A's scope
- `expires_at` <= A's expires_at
- `ceiling` = A's effective ceiling
- Signed by A's key (not the CA)

The Kernel verifies the entire delegation chain back to a CA-issued root.

### 2.4 Attenuation

Attenuation is monotonically restrictive. A delegated capability can only
narrow, never widen:

- **Scope reduction:** Remove tools, restrict operations, tighten argument
  constraints.
- **Time reduction:** Shorter TTL (expires_at <= parent's expires_at).
- **Budget reduction:** Lower max_invocations, lower max_bytes_out.
- **Depth limits:** max_delegation_depth prevents unbounded chains.

The `ceiling` field records the maximum privileges available for further
delegation. When a token is delegated, its `cap` (granted capabilities)
must be a subset of the ceiling. The ceiling itself can only be narrowed.

This is enforced identically to ClawdStrike's existing
`DelegationClaims::validate_redelegation_from`, which checks
`is_capability_subset(child.cap, parent.effective_ceiling())`.

### 2.5 Revocation

PACT uses a dual strategy:

1. **Short TTL (primary).** Default capability lifetime is 300 seconds.
   Maximum is 3600 seconds. Short-lived tokens naturally expire, limiting
   the window of misuse.

2. **Explicit revocation (supplementary).** The CA maintains a revocation
   store (in-memory or SQLite-backed, matching ClawdStrike's existing
   `RevocationStore` trait). The Kernel checks revocation status on every
   capability presentation.

3. **Cascade revocation.** When a root capability is revoked, all
   capabilities in its delegation chain are implicitly revoked. The Kernel
   checks every entry in `delegation_chain` against the revocation store.
   If any ancestor is revoked, the descendant is rejected.

4. **Revocation propagation.** For distributed deployments, revocation
   events are published as Spine envelopes on a dedicated NATS subject.
   Kernels subscribe and update their local revocation caches.

### 2.6 Preventing the Confused Deputy Problem

The confused deputy problem occurs when a trusted component (the deputy)
is tricked into misusing its authority on behalf of an untrusted requestor.
In MCP, this is endemic: an MCP server runs with full authority, and the
agent can invoke any tool it offers.

PACT prevents this through capability designation:

- The capability token is the **sole authority** to invoke a tool. There
  is no ambient authority. The Kernel does not have a "default allow" mode.
- The token names the specific tool, operation, and argument constraints.
  The Kernel matches the actual request against the token's scope.
  A mismatch is a hard deny.
- The token is bound to a specific subject (agent identity). A different
  agent cannot use a stolen token (proof binding via DPoP or mTLS
  further strengthens this).
- The Kernel does not act on its own authority. It acts only when presented
  with a valid capability from a requestor. The Kernel is not a deputy;
  it is a validator.

---

## 3. Privilege Separation

### 3.1 Kernel Isolation from the Agent

The Runtime Kernel is architecturally invisible to the agent. The agent
interacts with a file descriptor (pipe, UDS) that was established at
process creation time. The agent does not know:

- The Kernel's PID, port, or socket path.
- The Kernel's signing key.
- The policy being enforced.
- What other Tool Servers exist.

Implementation strategies (in order of increasing strength):

| Level | Mechanism | What it prevents |
|-------|-----------|-----------------|
| 1: Process | Kernel in a separate process, agent's FD table restricted | Agent cannot signal/ptrace the Kernel |
| 2: Namespace | Kernel in a separate PID + network namespace | Agent cannot discover Kernel via /proc or netstat |
| 3: User | Kernel runs as a different user, agent has no sudo | Agent cannot read Kernel's memory or key material |
| 4: Sandbox | Agent runs inside a seccomp-bpf / Landlock / Sandbox-exec policy | Agent cannot make unauthorized syscalls |
| 5: VM | Kernel in a microVM (Firecracker, gVisor) | Agent cannot escape even with a kernel exploit |

The receipt's `metadata.sandbox.enforcement_level` field (already present in
ClawdStrike's `SignedReceipt`) records which isolation level was active,
enabling verifiers to make trust decisions based on enforcement strength.

### 3.2 Tool Server Isolation

Each Tool Server runs in its own sandbox:

- **Separate process.** No shared address space with other Tool Servers.
- **Separate filesystem namespace.** Each Tool Server sees only its own
  root filesystem plus explicitly granted mounts.
- **No shared IPC.** No Unix sockets, shared memory segments, or named
  pipes between Tool Servers.
- **Network isolation.** Tool Servers are in separate network namespaces.
  They cannot reach each other over TCP/UDP. Only the Kernel can reach
  them (via the pre-established mTLS connection).
- **Resource limits.** CPU, memory, and I/O are cgroup-bounded per server.

This prevents a compromised Tool Server A from influencing Tool Server B
through shared context, side channels, or direct communication.

### 3.3 Communication Path Enforcement

```
Agent --[pipe/UDS]--> Kernel --[mTLS/UDS]--> Tool Server A
                          |
                          +--[mTLS/UDS]--> Tool Server B
                          |
                          +--[mTLS/HTTPS]--> Capability Authority
                          |
                          +--[Spine/NATS]--> Receipt Log
```

The agent has exactly one communication path: a unidirectional channel to
the Kernel. It cannot:

- Enumerate Tool Servers (it does not know their addresses).
- Communicate with the CA (the Kernel proxies capability requests).
- Read the Receipt Log (receipts are write-only from the Kernel's perspective).
- Communicate with other agents except through explicit delegation (which
  itself requires a capability token).

### 3.4 Agent Discovery Prevention

To prevent the agent from discovering the Kernel or Tool Servers:

1. **No environment variables** expose the Kernel's address. The pipe FD is
   inherited at exec time.
2. **`/proc/self/fd`** shows only the agent's own descriptors. In a PID
   namespace, `/proc` is remounted to hide other processes.
3. **Seccomp-bpf** blocks `ptrace`, `process_vm_readv`, `mount`,
   `pivot_root`, and network-related syscalls (socket, connect, bind) that
   could probe the host.
4. **Landlock** restricts filesystem access to the agent's working directory.
5. On macOS, the **Sandbox-exec** profile (the darwin-telemetry-bridge path)
   restricts network and process operations.

---

## 4. Tool Call Flow

### 4.1 Complete Sequence

```
Agent                     Kernel                    Tool Server        Receipt Log
  |                         |                           |                  |
  |  (1) ToolCallRequest    |                           |                  |
  |  + PactCapability token |                           |                  |
  |------------------------>|                           |                  |
  |                         |                           |                  |
  |                   (2) Validate capability:          |                  |
  |                    a. Deserialize signed envelope   |                  |
  |                    b. Verify CA signature           |                  |
  |                    c. Check not expired             |                  |
  |                    d. Check not-before              |                  |
  |                    e. Verify subject matches agent  |                  |
  |                    f. Check revocation store        |                  |
  |                    g. Verify delegation chain       |                  |
  |                    h. Verify proof binding (DPoP)   |                  |
  |                    i. Check invocation budget       |                  |
  |                    j. Match tool + operation        |                  |
  |                       against scope                 |                  |
  |                         |                           |                  |
  |                   (3) Evaluate policy guards:       |                  |
  |                    - ForbiddenPathGuard             |                  |
  |                    - EgressAllowlistGuard           |                  |
  |                    - ShellCommandGuard              |                  |
  |                    - SecretLeakGuard                |                  |
  |                    - McpToolGuard                   |                  |
  |                    - PromptInjectionGuard           |                  |
  |                    - SpiderSenseGuard               |                  |
  |                    - [custom WASM guards]           |                  |
  |                    - [async guards]                 |                  |
  |                         |                           |                  |
  |                   (4) [IF DENIED at step 2 or 3]    |                  |
  |                    Build denial receipt:            |                  |
  |                    - content_hash of request        |                  |
  |                    - verdict: {passed: false}       |                  |
  |                    - provenance + violations        |                  |
  |                    Sign with Kernel key             |                  |
  |  <-----(DenialResponse + signed denial receipt)-----|                  |
  |                         |---(append denial receipt)--------------->|   |
  |                         |                           |                  |
  |                   (5) [IF ALLOWED]                  |                  |
  |                    Forward request to Tool Server:  |                  |
  |                         |                           |                  |
  |                         | ToolInvocation {          |                  |
  |                         |   invocation_id,          |                  |
  |                         |   tool_name,              |                  |
  |                         |   arguments,              |                  |
  |                         |   argument_hash,          |                  |
  |                         |   kernel_nonce,           |                  |
  |                         | }                         |                  |
  |                         |-------------------------->|                  |
  |                         |                           |                  |
  |                         |                     (6) Execute tool         |
  |                         |                      - Run in sandbox       |
  |                         |                      - Enforce resource     |
  |                         |                        limits              |
  |                         |                           |                  |
  |                         |  ToolResult {             |                  |
  |                         |    invocation_id,         |                  |
  |                         |    result_hash,           |                  |
  |                         |    result,                |                  |
  |                         |    server_signature,      |                  |
  |                         |  }                        |                  |
  |                         |<--------------------------|                  |
  |                         |                           |                  |
  |                   (7) Sign receipt:                 |                  |
  |                    Receipt {                        |                  |
  |                      version: "1.0.0",             |                  |
  |                      receipt_id,                   |                  |
  |                      timestamp,                    |                  |
  |                      content_hash: SHA256(         |                  |
  |                        canonical(request +         |                  |
  |                        result)),                   |                  |
  |                      verdict: {passed: true},      |                  |
  |                      provenance: {                 |                  |
  |                        policy_hash,                |                  |
  |                        capability_id,              |                  |
  |                        tool_server_id,             |                  |
  |                        attestation_level,          |                  |
  |                        guard_results[],            |                  |
  |                      },                            |                  |
  |                      metadata: {                   |                  |
  |                        sandbox: {                  |                  |
  |                          enforced: true,           |                  |
  |                          enforcement_level,        |                  |
  |                        },                          |                  |
  |                        invocation: {               |                  |
  |                          tool_name,                |                  |
  |                          argument_hash,            |                  |
  |                          result_hash,              |                  |
  |                          server_signature,         |                  |
  |                        },                          |                  |
  |                        delegation_chain[],         |                  |
  |                      },                            |                  |
  |                    }                               |                  |
  |                    SignedReceipt::sign(receipt, kp) |                  |
  |                         |                           |                  |
  |  <---(ToolCallResponse + signed receipt)------------|                  |
  |                         |                           |                  |
  |                   (8) Append receipt to log         |                  |
  |                         |---(Spine envelope)------------------------->|
  |                         |                           |                  |
```

### 4.2 Message Types

**Request (Agent -> Kernel):**

```json
{
  "schema": "pact.tool_call.v1",
  "request_id": "req-UUIDv7",
  "capability": "<signed-capability-envelope>",
  "tool_name": "file_read",
  "arguments": { "path": "/app/src/main.rs" },
  "proof": {
    "mode": "dpop",
    "signature": "0x...",
    "nonce": "...",
    "issued_at": "2026-03-17T12:00:00Z"
  }
}
```

**Response (Kernel -> Agent):**

```json
{
  "schema": "pact.tool_result.v1",
  "request_id": "req-UUIDv7",
  "status": "allowed",
  "result": { "content": "fn main() { ... }" },
  "receipt": "<signed-receipt-json>"
}
```

**Denial (Kernel -> Agent):**

```json
{
  "schema": "pact.tool_result.v1",
  "request_id": "req-UUIDv7",
  "status": "denied",
  "reason": "capability_expired",
  "violations": [
    { "guard": "capability_validator", "severity": "error",
      "message": "Capability expired at 2026-03-17T11:55:00Z" }
  ],
  "receipt": "<signed-denial-receipt-json>"
}
```

### 4.3 Fail-Closed Guarantees

At every decision point, the default is denial:

| Failure Mode | Behavior |
|-------------|----------|
| Capability signature invalid | Deny |
| Capability expired | Deny |
| Capability revoked (including ancestor) | Deny |
| Tool not in capability scope | Deny |
| Guard evaluation error | Deny |
| Tool Server unreachable | Deny |
| Tool Server returns error | Return error to agent, sign receipt |
| Receipt signing fails | Deny (do not return result without receipt) |
| Revocation store unreachable | Deny (assume revoked) |
| Policy load fails | Deny all (sticky config error, matching HushEngine) |
| Unknown message schema | Deny |

This matches ClawdStrike's existing fail-closed design where
`HushEngine::config_error` causes all subsequent checks to deny, and the
SQLite revocation store's `is_revoked` returns `true` on database errors.

---

## 5. Tool Discovery and Trust

### 5.1 Capability-Driven Discovery

In MCP, tool discovery works by asking a server to list its tools. The
server returns names, descriptions, and schemas, which are passed directly
to the LLM as prompt content. This is a prompt injection vector.

In PACT, the agent does not discover tools by asking servers. Instead:

1. **Capability tokens enumerate what's allowed.** When the CA issues a
   capability, it includes `ToolGrant` entries naming specific tools. The
   agent knows what it can call by inspecting its tokens.

2. **Tool schemas are signed by the tool server** and verified by the
   Kernel. The Kernel maintains a local cache of verified tool schemas
   (the "Tool Manifest"). Schemas are JSON Schema documents signed with the
   Tool Server's Ed25519 key.

3. **Tool descriptions are sanitized before reaching the LLM.** The Kernel
   strips raw description text and replaces it with a structured,
   length-bounded summary. The Kernel may optionally run the
   PromptInjectionGuard and SpiderSenseGuard on tool descriptions at
   manifest load time, rejecting servers whose descriptions score above
   the injection threshold.

### 5.2 Tool Manifest

Each Tool Server publishes a signed manifest at startup:

```
ToolManifest {
    schema:     "pact.manifest.v1",
    server_id:  String,
    server_key: PublicKey,          // Ed25519 public key
    spiffe_id:  Option<String>,     // SPIFFE identity
    tools: Vec<ToolDefinition>,
    signed_at:  DateTime<Utc>,
    signature:  Signature,          // Over canonical JSON of above fields
}

ToolDefinition {
    name:        String,
    version:     String,
    description: String,            // Max 500 chars, validated at manifest verify
    input_schema: serde_json::Value,// JSON Schema for arguments
    output_schema: Option<serde_json::Value>,
    capabilities_required: Vec<HostCapability>,  // fs_read, network, etc.
    estimated_latency_ms: Option<u64>,
    idempotent:  bool,
    side_effects: Vec<String>,      // ["filesystem", "network", "database"]
}
```

The Kernel verifies the manifest signature at connection time. If
verification fails, the Tool Server is rejected and no tools from it are
available.

### 5.3 Tool Server Authentication

Tool Servers are authenticated via one or more mechanisms:

| Mechanism | When Used |
|-----------|-----------|
| **Signed manifest** | Always. Manifest signature verified against a pinned key or the Identity Registry |
| **mTLS** | When Tool Server connects over TCP. Both sides present certificates. The Kernel verifies the Tool Server's certificate chain |
| **SPIFFE** | In Kubernetes or mesh deployments. The Kernel verifies the Tool Server's SVID against the trust domain |
| **Process attestation** | When Tool Server is a local process. The Kernel verifies the binary hash matches a pinned value |

The TrustBundle (from ClawdStrike's Spine crate) configures which
authentication mechanisms are required for a given deployment.

---

## 6. Multi-Agent Delegation

### 6.1 Delegation Model

PACT's delegation model extends ClawdStrike's existing `hush-multi-agent`
crate. When Agent A wants Agent B to have access to a subset of its tools:

```
Agent A (delegator)           Kernel              Agent B (delegatee)
    |                           |                       |
    | (1) DelegationRequest {   |                       |
    |   parent_capability,      |                       |
    |   subject: B,             |                       |
    |   scope: <subset>,        |                       |
    |   expires_at: <shorter>,  |                       |
    | }                         |                       |
    |-------------------------->|                       |
    |                           |                       |
    |                     (2) Kernel validates:         |
    |                      - A's parent cap is valid    |
    |                      - Requested scope is subset  |
    |                      - expires_at <= parent's     |
    |                      - delegation_depth < max     |
    |                      - Policy allows delegation   |
    |                           |                       |
    |                     (3) Kernel constructs child   |
    |                        PactCapability:            |
    |                      - issuer = A                 |
    |                      - subject = B               |
    |                      - scope = requested subset   |
    |                      - chain = A's chain + A's ID |
    |                      - ceiling = A's ceiling      |
    |                           |                       |
    |                     (4) A signs the child cap     |
    |  <----(sign challenge)----|                       |
    |  ----(signature)--------->|                       |
    |                           |                       |
    |                     (5) Kernel delivers to B      |
    |                           |----(child cap)------->|
    |                           |                       |
    |                     (6) Sign delegation receipt   |
    |                           |                       |
```

### 6.2 Receipt Chain

When Agent B uses a delegated capability, the receipt includes the full
provenance:

```json
{
  "receipt": {
    "provenance": {
      "delegation_chain": [
        { "capability_id": "cap-root-123", "issuer": "ca:authority", "subject": "agent:A" },
        { "capability_id": "cap-del-456",  "issuer": "agent:A",     "subject": "agent:B" }
      ],
      "delegation_depth": 1,
      "root_capability_id": "cap-root-123"
    }
  }
}
```

This creates an unbroken chain from B's action back through A's delegation
to the CA's original issuance. Auditors can trace any tool invocation to
the human or system that authorized it.

### 6.3 Revocation Cascade

Revoking any capability in a delegation chain revokes all descendants:

```
CA revokes cap-root-123
  -> Kernel checks B's cap-del-456
  -> delegation_chain contains "cap-root-123"
  -> Kernel queries revocation store for "cap-root-123"
  -> Found: revoked
  -> cap-del-456 is rejected
```

This matches ClawdStrike's existing chain validation in
`SignedDelegationToken::verify_redelegated_from`, which verifies the parent
token before accepting the child.

### 6.4 Cross-Agent Audit

Every delegation and every delegated invocation produces a receipt. The
Receipt Log's Merkle tree includes both delegation receipts and invocation
receipts, enabling:

- **Delegation graph reconstruction:** Given any receipt, walk the
  delegation_chain to reconstruct who delegated what to whom.
- **Blast radius analysis:** Given a revoked capability, query the Receipt
  Log for all receipts referencing it in their delegation_chain.
- **Temporal analysis:** UUIDv7 capability IDs are time-ordered, so the
  delegation graph has a natural temporal ordering.

---

## 7. Formal Verification Surface

### 7.1 What Can Be Verified

PACT is designed so that its core safety properties are mechanically
verifiable. The verification surface spans three layers, matching
ClawdStrike's existing Logos attestation levels:

| Property | Layer | Tool | Status |
|----------|-------|------|--------|
| **Capability monotonicity** | Token logic | Lean 4 | Provable |
| **Revocation completeness** | Token logic | Lean 4 | Provable |
| **Fail-closed guarantee** | Kernel state machine | Lean 4 + Logos | Provable |
| **Policy consistency** | Policy logic | Logos / Z3 | Existing |
| **Policy completeness** | Policy logic | Logos / Z3 | Existing |
| **Deny monotonicity (inheritance)** | Policy logic | Logos / Z3 | Existing |
| **Receipt chain integrity** | Cryptographic | Lean 4 | Provable |
| **Delegation graph acyclicity** | Token logic | Lean 4 | Provable |
| **Scope subsumption** | Token logic | Lean 4 | Provable |
| **Implementation correctness** | Rust code | Aeneas | Future |

### 7.2 Formal Properties

**Property 1: Capability Monotonicity.**
For any delegation chain C0 -> C1 -> ... -> Cn, for all i:
scope(C_{i+1}) is a subset of scope(C_i). Equivalently: delegation
can only attenuate, never amplify.

```lean
theorem capability_monotonicity (chain : DelegationChain) :
  ∀ i, i + 1 < chain.length →
    scope_subset (chain.get (i + 1)).scope (chain.get i).effective_ceiling = true
```

**Property 2: Revocation Completeness.**
If capability C is revoked at time t, then for all capabilities D
where C is in D.delegation_chain, and for all times t' >= t, the
Kernel rejects D at time t'.

```lean
theorem revocation_completeness (C D : Capability) (t t' : Timestamp)
  (h_revoked : revoked C t)
  (h_ancestor : C.id ∈ D.delegation_chain)
  (h_time : t' ≥ t) :
  kernel_rejects D t' = true
```

**Property 3: Fail-Closed.**
For any Kernel state s and any request r, if any validation step
returns an error, the Kernel produces a denial.

```lean
theorem fail_closed (s : KernelState) (r : Request) :
  (∃ step, step_fails s r step) →
    kernel_decision s r = Decision.Deny
```

**Property 4: Receipt Chain Integrity.**
For any receipt R in the Receipt Log, the content_hash in R equals
SHA256(canonical_json(request, result)), and the signature is valid
under the Kernel's public key.

```lean
theorem receipt_integrity (R : SignedReceipt) (kp : PublicKey) :
  R.verify kp →
    R.receipt.content_hash = sha256 (canonical_json R.receipt.content) ∧
    valid_signature kp (canonical_json R.receipt) R.signatures.signer
```

**Property 5: Delegation Graph Acyclicity.**
The delegation graph is a DAG. No capability can appear in its own
delegation chain.

```lean
theorem delegation_acyclicity (C : Capability) :
  C.id ∉ C.delegation_chain
```

### 7.3 Connection to ClawdStrike's Existing Verification

PACT's verification surface extends ClawdStrike's existing stack:

- **Logos Layer 3 (normative):** ClawdStrike's `clawdstrike-logos` crate
  already compiles policies into Logos formulas and verifies consistency,
  completeness, and inheritance. PACT adds capability scope as a new
  atom domain: tool grants become permission atoms, capability ceilings
  become obligation atoms.

- **Z3 backend:** The existing `logos-z3` crate provides SMT-backed
  verification. PACT capability constraints (subset checking, time bound
  ordering) are naturally expressible as Z3 assertions.

- **Attestation levels:** The existing 5-level attestation hierarchy
  (Heuristic -> Formula-Verified -> Z3-Verified -> Lean-Proved ->
  Implementation-Verified) carries directly into PACT. Capability tokens
  include their `attestation_level`, telling the verifier how deeply the
  issuing policy was checked.

- **Receipt metadata:** PACT receipts use the existing
  `Receipt::merge_metadata` to embed verification reports, matching the
  existing `VerificationReport::to_receipt_metadata()` pattern.

---

## 8. Migration Path from MCP

### 8.1 MCP Adapter Architecture

Existing MCP servers can be wrapped in a PACT-compatible adapter without
modifying the server code:

```
                    PACT World                          MCP World

Agent --[PACT]--> Kernel --[mTLS]--> MCP Adapter --[stdio/HTTP]--> MCP Server
                                     (Tool Server)
```

The **MCP Adapter** is a PACT Tool Server that:

1. Connects to an MCP server using the standard MCP transport (stdio or
   SSE over HTTP).
2. Translates the MCP server's `tools/list` response into a PACT
   ToolManifest, signing it with the adapter's key.
3. On receiving a `ToolInvocation` from the Kernel, translates it into an
   MCP `tools/call` request, forwards it to the MCP server, and returns
   the result.
4. Runs the PromptInjectionGuard on all tool descriptions from the MCP
   server before including them in the manifest.
5. Enforces argument size limits and output sanitization.

The MCP server runs inside the adapter's sandbox. It has no direct
communication channel to the agent or the Kernel. From the MCP server's
perspective, it is being called normally; from PACT's perspective, it is
a sandboxed tool implementation.

### 8.2 Adapter Configuration

```yaml
# pact-mcp-adapter.yaml
server_id: "mcp-adapter:github-tools"
upstream:
  transport: stdio
  command: ["npx", "-y", "@modelcontextprotocol/server-github"]
  env:
    GITHUB_TOKEN: "${GITHUB_TOKEN}"

security:
  # Scan MCP tool descriptions for prompt injection
  scan_descriptions: true
  injection_threshold: 0.7

  # Argument size limits
  max_argument_bytes: 65536

  # Output sanitization
  sanitize_output: true

  # Only expose these tools from the MCP server
  tool_allowlist:
    - "search_repositories"
    - "get_file_contents"
    - "create_pull_request"
```

### 8.3 MCP Client Migration

For MCP clients that want to speak PACT natively, the migration is
incremental:

**Level 1: Wrap.** Run the existing MCP client behind the MCP Adapter.
Zero code changes. The client gets capability-gated access to all its
existing MCP servers.

**Level 2: Add capability handling.** The client adds a
`pact.request_capability` call before each tool invocation. This requires
adding the PACT client library and changing the tool call flow from:
```
client -> mcp_server.tool_call(name, args)
```
to:
```
cap = kernel.request_capability(tool_name)
result = kernel.tool_call(cap, tool_name, args)
```

**Level 3: Native PACT.** The client drops MCP entirely and uses the PACT
client SDK. Tool Servers are native PACT servers with signed manifests.

### 8.4 SDK Support

PACT provides client SDKs in the same languages as ClawdStrike:

| Language | Package | Status |
|----------|---------|--------|
| Rust | `pact-client` | Core implementation |
| TypeScript | `@clawdstrike/pact` | Wraps WASM + native bindings |
| Python | `clawdstrike-pact` | Pure Python + native extension |
| Go | `clawdstrike-pact-go` | Pure Go |

Each SDK provides:
- Capability request/presentation
- Tool call marshaling
- Receipt verification
- Delegation helpers
- MCP adapter bindings

### 8.5 Framework Adapters

Matching ClawdStrike's existing adapter pattern, PACT provides framework
adapters:

| Framework | Adapter | Migration Path |
|-----------|---------|---------------|
| OpenAI SDK | `pact-openai` | Replace MCP server config with PACT Kernel config |
| Vercel AI SDK | `pact-vercel-ai` | Drop `experimental_toToolResultContent`, use PACT tool provider |
| LangChain | `pact-langchain` | Replace `Tool` base class with `PactTool` |
| Claude Code | `pact-claude` | Native integration via ClawdStrike adapter |

---

## 9. Wire Protocol Specification

### 9.1 Message Framing

All PACT messages are framed as:

```
[4 bytes: message length (big-endian u32)] [message bytes (canonical JSON)]
```

Maximum message size: 16 MiB (configurable). Messages exceeding the limit
are rejected and a denial receipt is generated.

### 9.2 Message Types

| Schema | Direction | Purpose |
|--------|-----------|---------|
| `pact.hello.v1` | Kernel -> Agent | Session initialization, available capabilities |
| `pact.request_capability.v1` | Agent -> Kernel | Request a new capability token |
| `pact.capability_response.v1` | Kernel -> Agent | Issued capability or denial |
| `pact.tool_call.v1` | Agent -> Kernel | Invoke a tool with capability |
| `pact.tool_result.v1` | Kernel -> Agent | Tool result or denial |
| `pact.delegate.v1` | Agent -> Kernel | Delegate capability to another agent |
| `pact.delegate_response.v1` | Kernel -> Agent | Delegation result |
| `pact.revoke.v1` | Agent -> Kernel | Request revocation of own capability |
| `pact.heartbeat.v1` | Kernel <-> Agent | Liveness check |
| `pact.tool_invocation.v1` | Kernel -> Tool Server | Execute a tool |
| `pact.tool_response.v1` | Tool Server -> Kernel | Tool execution result |
| `pact.manifest.v1` | Tool Server -> Kernel | Signed tool manifest |

All messages include a `request_id` (UUIDv7) for correlation and a
`timestamp` (RFC 3339) for ordering.

### 9.3 Error Codes

PACT errors use a hierarchical code taxonomy:

```
PACT_CAP_EXPIRED          - Capability has expired
PACT_CAP_REVOKED          - Capability has been revoked
PACT_CAP_SCOPE_MISMATCH   - Requested tool not in capability scope
PACT_CAP_SIGNATURE_INVALID - Capability signature verification failed
PACT_CAP_CHAIN_BROKEN     - Delegation chain verification failed
PACT_CAP_BUDGET_EXHAUSTED - Invocation budget exceeded
PACT_CAP_BINDING_FAILED   - Proof binding verification failed
PACT_GUARD_DENIED         - Policy guard denied the action
PACT_GUARD_ERROR          - Policy guard evaluation error (fail-closed)
PACT_SERVER_UNREACHABLE   - Tool server not available
PACT_SERVER_ERROR         - Tool server returned an error
PACT_SERVER_TIMEOUT       - Tool server did not respond in time
PACT_SCHEMA_UNKNOWN       - Unknown message schema version
PACT_POLICY_INVALID       - Policy failed to load
PACT_RECEIPT_SIGN_FAILED  - Receipt signing failed
```

---

## 10. Security Analysis

### 10.1 Threat Model

| Threat | MCP Vulnerable? | PACT Mitigation |
|--------|----------------|-----------------|
| Malicious agent calls privileged tool | Yes (all tools available) | Capability scope restricts to granted tools |
| Stolen tool credentials | Yes (server holds secrets) | Broker pattern: secrets never touch agent or tool server |
| Prompt injection via tool descriptions | Yes (raw text to LLM) | Descriptions signed, sanitized, injection-scanned |
| Compromised server A attacks server B | Yes (shared context) | Server isolation (namespaces, no IPC) |
| Agent discovers enforcement layer | Yes (sibling process) | Kernel in separate namespace, no discoverable address |
| Replay attack (reuse old tool call) | Yes (no nonces) | Capability TTL + nonce in proof binding |
| Capability escalation | N/A (no capabilities) | Monotonic attenuation, formal proof |
| Unaudited tool calls | Yes (no logging) | Every call produces a signed receipt in Merkle log |
| Policy bypass | Yes (no policy) | Guards run before every tool call, fail-closed |
| Man-in-the-middle | Yes (stdio, no auth) | mTLS between Kernel and Tool Servers |

### 10.2 Residual Risks

- **Side channels:** CPU cache timing between Kernel and Agent processes
  on the same host. Mitigated by VM isolation (Level 5).
- **Kernel compromise:** If the Kernel is compromised, all security
  guarantees are lost. Mitigated by minimal TCB, formal verification of
  Kernel logic, and hardware attestation (TPM-backed signing keys).
- **CA compromise:** A compromised CA can issue arbitrary capabilities.
  Mitigated by short TTLs, offline CA mode, and transparency logging of
  all issued capabilities.
- **Clock skew:** Capability time bounds depend on synchronized clocks.
  Mitigated by requiring NTP and including clock-skew tolerance in the
  Kernel's validation (configurable, default 30s).

---

## 11. Deployment Modes

### 11.1 Local Development

```
Agent process
  |
  +-- embedded Kernel (same process, library mode)
       |
       +-- Tool Servers as child processes (stdio)
       +-- In-memory CA (auto-issues capabilities)
       +-- In-memory Receipt Log
```

In development mode, the Kernel runs as a library inside the agent
process. This provides no isolation but enables rapid iteration. Receipts
are still generated and can be verified offline.

### 11.2 Production (Single Host)

```
Agent (sandboxed, user: agent)
  |-- pipe
  v
Kernel (user: kernel, PID namespace)
  |-- UDS
  +-- Tool Server A (user: tool-a, namespace A)
  +-- Tool Server B (user: tool-b, namespace B)
  +-- CA (user: ca, co-located)
  +-- Receipt Log (NATS on localhost or remote)
```

### 11.3 Production (Distributed)

```
Agent (VM A)
  |-- TLS
  v
Kernel (VM B, Kubernetes pod)
  |-- mTLS
  +-- Tool Server A (Pod C, SPIFFE identity)
  +-- Tool Server B (Pod D, SPIFFE identity)
  +-- CA (Service E, HSM-backed signing)
  +-- Receipt Log (NATS cluster, Spine protocol)
```

---

## 12. Comparison Summary

| Dimension | MCP | PACT |
|-----------|-----|------|
| Trust model | Binary (installed = trusted) | Capability-based (token = authority) |
| Authorization | None | Per-tool, time-bounded, attenuatable tokens |
| Authentication | None or bearer | mTLS, SPIFFE, signed manifests |
| Isolation | None | Process, namespace, VM |
| Attestation | None | Ed25519 signed receipts, Merkle log |
| Policy enforcement | None | Guard pipeline, fail-closed |
| Formal verification | None | Logos + Z3 + Lean 4 |
| Tool discovery | Server advertisement | Capability enumeration |
| Description safety | Raw text to LLM | Signed, sanitized, injection-scanned |
| Multi-agent | Not supported | Delegation with monotonic attenuation |
| Revocation | Not supported | Short TTL + explicit revocation + cascade |
| Audit | Not supported | Receipt chain with Merkle proofs |
| Transport | stdio / HTTP SSE | Length-prefixed canonical JSON over pipe/mTLS |
| Migration from MCP | N/A | Adapter wraps existing MCP servers |

---

## Appendix A: Cryptographic Primitives

PACT reuses ClawdStrike's existing `hush-core` primitives:

| Primitive | Algorithm | Usage |
|-----------|-----------|-------|
| Signing | Ed25519 (ed25519-dalek) | Capabilities, receipts, manifests, envelopes |
| Hashing | SHA-256 | Content hashes, capability hashes, Merkle trees |
| Hashing | Keccak-256 | Ethereum attestation anchoring (optional) |
| Canonical serialization | RFC 8785 (JCS) | Deterministic JSON for cross-language signing |
| Merkle tree | RFC 6962 (CT) | Receipt log integrity, inclusion proofs |
| Key zeroization | ZeroizeOnDrop | Private key material cleared on drop |
| TPM binding | tpm2-tss | Hardware-backed signing keys (optional) |

## Appendix B: Relationship to ClawdStrike Crates

| PACT Component | ClawdStrike Crate | Relationship |
|----------------|-------------------|-------------|
| Capability tokens | `clawdstrike-broker-protocol` | Extends `BrokerCapability` with tool scope |
| Delegation | `hush-multi-agent` | Reuses `DelegationClaims`, `RevocationStore` |
| Receipt signing | `hush-core` | Reuses `Receipt`, `SignedReceipt`, `Keypair` |
| Guard pipeline | `clawdstrike` (engine) | Reuses `HushEngine`, all 13 built-in guards |
| Formal verification | `clawdstrike-logos`, `logos-ffi`, `logos-z3` | Extends with capability scope atoms |
| Audit log | `spine` | Reuses signed envelopes, checkpoints, NATS transport |
| Trust bundles | `spine::trust` | Reuses `TrustBundle` for Tool Server authentication |
| WASM guards | `clawdstrike-guard-sdk` | Plugin guards run inside Kernel's WASM sandbox |
| Tool manifests | New | New crate: `pact-manifest` |
| Kernel | New | New crate: `pact-kernel` (orchestrates existing crates) |
| MCP adapter | New | New crate: `pact-mcp-adapter` |

## Appendix C: Open Questions

1. **Capability token format:** Should PACT use its own signed JSON format
   (consistent with ClawdStrike) or adopt Biscuit tokens (which have
   built-in attenuation semantics and a Datalog authorization language)?
   The current design favors consistency with ClawdStrike's canonical JSON
   + Ed25519 stack, but Biscuit's offline attenuation is compelling.

2. **Streaming results:** How should PACT handle tool calls that return
   streaming results (e.g., long-running processes, SSE)? The current
   design assumes request-response. Options: (a) multiple result messages
   with a single receipt at the end, (b) periodic intermediate receipts,
   (c) stream chunking with per-chunk hashes.

3. **Bidirectional tool communication:** Some tools need to ask the agent
   for clarification mid-execution (MCP's "sampling" capability). PACT
   could support this via a `pact.tool_callback.v1` message, but this
   creates a re-entrant control flow that complicates the Kernel's state
   machine. This needs careful design.

4. **Capability caching:** Should the Kernel cache validated capabilities
   to avoid re-verifying on every call? Cache invalidation must respect
   revocation (TTL on cache entries <= revocation propagation latency).

5. **Multi-Kernel coordination:** In distributed deployments with multiple
   Kernels, how are invocation budgets (max_invocations) enforced across
   Kernels? Options: (a) partitioned budgets at issuance, (b) distributed
   counter via the CA, (c) approximate enforcement with reconciliation.

6. **Backward compatibility window:** How long should the MCP adapter be
   supported as a first-class migration path? Proposal: 18 months from
   PACT 1.0 GA.
