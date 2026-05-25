# Endpoint Decision Engine Target Architecture

> **Status:** Draft | **Date:** 2026-05-15
> **Depends on:** `docs/plans/clawdstrike/macos-es-ne/**`,
> `docs/src/fleet-security/**`, and `docs/plans/clawdstrike/secret-broker/**`

## Goal

Turn ClawdStrike endpoints into local security decision engines.

The endpoint should not just report that "PowerShell ran" or "a shell command executed." It should
preserve the causal chain:

```text
Slack download
  -> browser helper
  -> shell
  -> Python
  -> package install script
  -> token read
  -> outbound POST
  -> policy decision
  -> response action
  -> signed evidence receipt
```

The target system has seven local planes plus one cloud-assisted projection plane.

## 1. Sensor Plane

The sensor plane turns operating-system, agent, browser, package-manager, and developer-tool
activity into canonical endpoint observations.

### Required sources

- process exec, exit, fork, parentage, code-signing state, command line, environment summary
- file read, write, create, rename, delete, metadata change, quarantine attributes
- network flow, DNS, TLS/server identity where available, NetworkExtension verdict
- persistence locations such as LaunchAgents, LaunchDaemons, login items, shell startup files,
  browser extensions, cron, systemd, and scheduled tasks
- credential access for SSH keys, package-registry tokens, cloud CLI credentials, browser cookies,
  signing keys, CI tokens, and repo secrets
- browser downloads and extension installs
- package-manager install scripts and postinstall hooks for npm, pnpm, yarn, pip, cargo, brew, go,
  and gem
- agent/tool activity including MCP calls, browser automation, shell agents, patch application,
  local API calls, and brokered egress
- policy decisions and response acknowledgements

### Contract

Sensors emit `EndpointObservation` or loss/degradation records. Loss is not hidden. Deadline misses,
provider inactive states, missing permissions, dropped events, and outbox backlog are first-class
evidence inputs.

## 2. Local Causal Graph Plane

The graph plane owns the local flight recorder.

### Responsibilities

- maintain a durable graph of processes, files, network endpoints, tools, credentials, packages,
  browser artifacts, policy decisions, deception artifacts, and response actions
- represent edges such as spawned, executed, read, wrote, connected, ran script, loaded library,
  created persistence, installed extension, downloaded, accessed credential, made decision,
  touched honey, and temporal next
- support process-subtree, session, user, tool, endpoint, and incident-scope queries
- preserve graph slices for receipts and evidence bundles
- compact or age graph data without losing signed proof pointers

### Required local workflows

- show everything this process caused
- show every secret this session touched
- group findings by causal relationship
- explain what caused this outbound request
- prove which policy and sensor state applied at the decision time

The existing `CausalGraphRecorder` is the seed. The target needs persistence, indexing, and query
APIs.

## 3. Policy And Simulation Plane

The policy plane evaluates current actions and replays recent endpoint history under candidate
rules.

### Online decision contract

Every local decision includes:

- policy version and resolved policy hash
- policy epoch and rollout channel
- sensor state and provider health
- identity and session context
- actor and process tree context
- graph-neighborhood evidence
- verdict and confidence
- action taken or audit-mode result

### Simulation contract

Before a rule becomes blocking, the endpoint can answer:

- how many historical events would change verdict
- which causal chains would be blocked
- which developer workflows would break
- which package installs, cloud CLIs, MCP calls, browser automations, or shells would be affected
- whether a narrower rule stops the threat path with lower operational damage

The existing `hush policy simulate` and `hush policy impact` behavior should become graph-aware
and stage-aware:

```text
observe -> simulate -> score impact -> audit mode -> limited enforcement -> full enforcement
```

## 4. Detection And Deception Plane

This plane turns observations and graph state into local findings.

### Detection families

- supply-chain runtime guard
- developer secret access
- package-manager lifecycle abuse
- code-signature drift
- dynamic library injection
- launch persistence
- browser extension drift
- AI-agent/tool misuse
- prompt-injected tool execution patterns
- anomalous brokered egress
- deception artifact touch

### Deception contract

Endpoint deception is not just file creation. The endpoint must:

- render a deception plan
- materialize honey artifacts safely
- register monitoring for those artifacts
- generate high-confidence findings when touched
- rotate or remove artifacts by policy
- record the causal process tree and adjacent real credentials
- emit a receipt for the deception hit

## 5. Response Plane

Response is local first and bounded. Cloud may request actions, but the endpoint must be able to
protect itself offline.

### Allowed first-class local actions

- isolate network or restrict egress policy
- suspend or terminate a process tree
- revoke a local grant, capability, or broker credential
- quarantine a file
- block or unload a persistence item
- disable or quarantine a browser extension
- roll back a known configuration change
- collect evidence bundle

### Non-negotiable response rules

- every action has a TTL unless explicitly configured otherwise
- every action has rollback semantics or a documented irreversible boundary
- every action records target, actor, reason, source finding, policy epoch, and graph slice
- every action is acknowledged locally and reflected in the response ledger
- provider-unavailable and action-failed states produce receipts instead of silence

The existing `control-api` response-action ledger is the cloud/operator projection. The target
requires endpoint-local executors and acknowledgement receipts.

## 6. Evidence Ledger Plane

Every important decision produces a signed receipt or signed envelope.

### Receipt families

- sensor-state receipt
- observation receipt
- policy decision receipt
- detection receipt
- simulation receipt
- response request receipt
- response execution receipt
- response rollback receipt
- deception materialization receipt
- evidence-bundle manifest receipt

### Minimum receipt fields

- receipt schema version
- endpoint ID and host identity
- user, session, agent, workload, and approval identity where available
- monotonic local sequence
- wall-clock timestamp and clock-quality state
- policy version, policy hash, and policy epoch
- sensor/provider state and degradation reasons
- process tree and graph slice identifiers
- evidence hashes and redaction class
- verdict, confidence, action, TTL, and rollback pointer
- signer identity and signature

Receipts should avoid raw artifact upload by default. Raw artifacts are attached only when policy
permits it.

## 7. Privacy And Cloud Projection Plane

Local protection cannot require cloud round trips. Cloud exists to enrich, correlate, store, and
coordinate.

### Default upload levels

| Level | Default contents | Use case |
| --- | --- | --- |
| `local_only` | no upload | sensitive investigations, offline mode |
| `hashes_features` | hashes, normalized fields, graph summaries, redacted evidence | default fleet telemetry |
| `summary_with_receipts` | findings, receipts, graph slice references, policy metadata | operator investigation |
| `raw_artifacts` | selected files, command output, packet excerpts, screenshots | explicit policy or approval only |

Privacy mode is itself part of the receipt. Operators must know whether missing raw evidence is a
privacy decision, a sensor failure, or a collection failure.

## 8. Operator Projection

The console should organize around causal workflows, not alert rows.

### Required workflows

- show everything this process caused
- replay this incident under today's policy
- find the rule that stops this without breaking developers
- contain this process tree for 10 minutes
- show all endpoints where an AI agent touched secrets
- group alerts by causal relationship
- prove protection state at execution time
- generate, simulate, and stage a detection

These are not separate dashboard widgets. They are the product contract. Each workflow should
round-trip through local graph, policy simulation, response, and receipts.

## 9. Release Truth Boundaries

The architecture should be explicit about what can be claimed.

### Claimable after the first integrated wave

- local endpoint observations can produce supply-chain and deception findings
- local causal graph slices can explain process/file/network/tool relationships for submitted
  observations
- local policy replay can compare policy outcomes over captured events
- macOS provider health and degraded states are visible
- signed receipts can prove policy/evidence state for covered decisions

### Not claimable until later gates pass

- full endpoint prevention across all macOS file/process/network events
- Linux and Windows parity
- safe autonomous response for arbitrary process trees
- durable all-event flight recorder with complete graph queries
- privacy-preserving telemetry for every raw artifact class
- commodity EDR replacement

## 10. Architecture Invariants

1. Local decisions continue when cloud is unavailable.
2. Sensor degradation is evidence, not an implementation detail.
3. Causality is a first-class data model, not a UI grouping trick.
4. Every enforcement claim is tied to policy epoch, provider state, and receipt.
5. Response actions are bounded, acknowledged, reversible where possible, and receipt-backed.
6. AI-agent and developer-workstation protection is the first wedge.
7. Policy simulation precedes broad blocking.
8. Privacy mode is explicit and auditable.
