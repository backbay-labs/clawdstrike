# Clawdstrike Agent

A lightweight system tray application that provides security policy enforcement for AI coding tools like Claude Code, Cursor, and Cline.

## Features

- **Daemon Management**: Automatically spawns and manages the hushd daemon
- **Broker Sidecar**: Optionally bundles and supervises `clawdstrike-brokerd` for local secret-broker execution
- **System Tray**: Shows status (running/stopped) and recent events
- **Desktop Notifications**: Alerts when actions are blocked
- **Claude Code Integration**: Auto-installs hooks for policy checking
- **MCP Server**: Exposes policy_check tool for Cursor/Cline
- **OpenClaw Session Manager**: Agent-owned gateway transport with reconnect logic
- **Local Authenticated API**: Loopback API used by desktop OpenClaw client
- **Policy Management**: Quick access to policy reload and settings

## Prerequisites

- macOS 10.15+ (Linux support planned)
- For Claude Code: Claude Code CLI installed

The packaged app bundles `hushd` and can also bundle `clawdstrike-brokerd`.
Separate installs are only needed for advanced external-daemon or remote-broker setups.

## Installation

### Build from source

```bash
cd apps/agent
cargo tauri build
```

The build step compiles and bundles `hushd` and `clawdstrike-brokerd` into the app automatically.
The built app will be in `src-tauri/target/release/bundle/`.

### Development

```bash
cargo tauri dev
```

## Usage

1. Launch the Clawdstrike Agent app
2. The agent will automatically start the hushd daemon on port 9876
3. If `brokerd.enabled` is set in agent settings, the agent will also start `clawdstrike-brokerd` on port 9889 after hushd is healthy
4. A tray icon will appear showing the current status

### Tray Menu

- **Status**: Shows daemon state and blocks count
- **Enable/Disable**: Toggle policy enforcement
- **Recent Events**: Last 10 policy checks
- **Install Claude Code Hooks**: Auto-configure Claude Code
- **Reload Policy**: Reload policy without restart
- **Open SDR Desktop**: Launch the full debugging UI
- **Quit**: Stop the agent and daemon

### Claude Code Integration

Click "Install Claude Code Hooks" to automatically configure Claude Code with policy checking. This creates:

- `~/.claude/hooks/clawdstrike-check.sh` - Pre-tool hook script
- Updates `~/.claude/hooks.json` - Hook configuration

The hook also publishes best-effort local developer-activity telemetry after
each policy check. Claude tool invocations are recorded as local tool/shell
observations, and credential-like path targets are recorded as bounded
secret-touch observations without changing the hook's fail-closed enforcement
behavior.

### MCP Server

The agent runs an MCP server on port 9877 that exposes the `policy_check` tool. To use with Cursor or other MCP-compatible tools, add to your MCP config:

```json
{
  "mcpServers": {
    "clawdstrike": {
      "url": "http://127.0.0.1:9877"
    }
  }
}
```

Successful MCP `policy_check` calls also publish best-effort local
developer-activity telemetry into the agent EDR API. MCP tool calls are recorded
as tool observations, shell checks for package-manager lifecycle commands and
sensitive cloud-CLI operations are recorded as first-class package/cloud
observations, and credential-like path targets are recorded as bounded
secret-touch observations without blocking the policy-check response if
telemetry delivery fails.

### Local Agent API (Desktop + Hooks)

The agent also runs a local authenticated API (default `127.0.0.1:9878`) for:

- hook policy checks (`/api/v1/agent/policy-check`)
- endpoint EDR analysis (`/api/v1/agent/edr/*`)
- desktop OpenClaw operations (`/api/v1/openclaw/*`)
- health/settings control (`/api/v1/agent/*`)

`POST /api/v1/openclaw/request` is policy-gated (fail-closed) before gateway
relay when enforcement is enabled. `POST /api/v1/agent/policy-check` returns
the allow/block decision plus a signed `policy_decision` receipt in the local
endpoint decision ledger.

Auth token file:

- Platform config directory plus `clawdstrike/agent-local-token`
  - macOS: `~/Library/Application Support/clawdstrike/agent-local-token`
  - Linux/dev fallback: `~/.config/clawdstrike/agent-local-token`

EDR endpoints accept canonical endpoint observations from the agent, system
extension, or developer-tool collectors:

- `POST /api/v1/agent/edr/findings` records observations and evaluates them for
  supply-chain runtime risk, including risky package scripts, developer-secret
  access, cloud CLI secret/token/IAM/key operations, and honey artifact access.
  Detection findings emit signed `hush-core` receipts in the response and append them to
  `~/.config/clawdstrike/edr/decision-receipts.jsonl`.
- `POST /api/v1/agent/edr/developer-activity` accepts normalized developer and
  agent collector facts for MCP tools, browser automation/download/extension
  events, DNS lookups, package scripts, cloud CLIs, shell commands, repo
  secrets, CI tokens, local API keys, and browser cookies, then maps them into the same local
  observation, flight-recorder, detection, and receipt path while preserving
  supplied host, user, session, agent, workload, approval, and policy metadata.
  The bundled MCP
  `policy_check` server feeds this path best-effort for tool calls, classified
  package-manager/cloud-CLI shell checks, and credential-like path targets; the
  Claude Code pre-tool hook feeds tool calls and credential-like path targets;
  the OpenClaw tool-result guard feeds result-discovered downloads, browser
  extension installs, credential-like paths, and secret-like tool outputs without
  raw result bodies; and the OpenClaw CUA bridge feeds recognized
  computer-use/browser automation actions plus local-path file downloads when
  the local agent token is available.
- `POST /api/v1/agent/edr/endpoint-security/events` accepts delivered
  EndpointSecurity process-exec, file-access, auth-open, and event-loss facts,
  normalizes them into endpoint observations with provider metadata, deadline
  evidence, and local identity context, then records them through the same
  flight-recorder, detection, and receipt path. Each recorded provider
  observation also returns a signed `observation` receipt that binds the
  observation ID, event kind, graph slice, provider state, and observation
  content hash. Event-loss, deadline-miss, and missing Full Disk Access facts
  also return dedicated signed `provider_degradation` receipts for
  `macos.endpoint_security`.
  `scripts/endpoint-security-live-dogfood.sh` is the operator gate for the
  deployed provider path: it does not POST synthetic EndpointSecurity events,
  and only passes when a benign file/process probe appears in the agent flight
  recorder and causal graph from provider-delivered telemetry with a matching
  `macos.endpoint_security` observation receipt for the probe target.
  The Swift EndpointSecurity package also exposes an injectable
  `EndpointSecurityAuthOpenRuntime`/`EndpointSecurityAgentEventPublisher`
  boundary that subscribes to `AUTH_OPEN`, responds with
  `es_respond_flags_result`, and publishes the resulting authorization
  observation into the same authenticated agent route; it is the provider-side
  delivery boundary, not a replacement for a deployed provider smoke run. The
  `endpoint-security-status-tool observe-auth-open [seconds]` mode runs that
  subscriber for a bounded operator window, writes
  `CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH` when configured, and
  lets the normal `live` mode return the most recent runtime snapshot to the
  agent collector. The live dogfood script can start that observer itself when
  `CLAWDSTRIKE_ES_DOGFOOD_STATUS_TOOL` is set to a signed status-tool path, or
  when `CLAWDSTRIKE_ES_DOGFOOD_OBSERVE_AUTH_OPEN=1` opts into the local
  `swift run` fallback. It passes the agent URL/token and shared runtime
  snapshot path into the observer, records observer stdout/stderr in the
  dogfood artifact directory, and tears the observer down on exit. The live
  dogfood script permits only the initial `live_authorization_signal_missing`
  degradation as a bootstrap condition; it still rejects inactive, uninstalled,
  approval-blocked, missing Full Disk Access, dropped-event, and deadline-miss
  provider states.
- `POST /api/v1/agent/edr/policy-events` validates canonical `PolicyEvent`
  submissions, converts them into endpoint observations, records them in the
  local flight recorder, evaluates detections, and emits signed detection
  receipts through the same endpoint decision ledger. Endpoint/user identity
  aliases from metadata or bounded `PolicyEvent.context` fields, such as
  `endpointId` and `principalId`, are preserved as observation host/user
  identity, and agent/workload/approval aliases are preserved into graph
  attributes and receipt actors. The OpenClaw general
  tool-preflight hook can best-effort feed its canonical file, command, patch,
  network, and tool policy events into this path when the local agent token is
  available. The shared `@clawdstrike/adapter-core` `BaseToolInterceptor` can
  also opt in to local EDR publishing for Claude/OpenAI/OpenCode-style wrappers,
  posting scrubbed pre-execution decisions and custom post-execution result
  events with raw input/output omitted, and emitting package-manager lifecycle
  commands plus sensitive cloud-CLI commands through the normalized
  developer-activity path. Its shared inbound-message interceptor can also emit
  hashed prompt-decision custom events without raw prompt text or raw sender
  names. The OpenClaw tool-result guard can also feed scrubbed post-execution
  policy events with result/content bodies omitted and hashed; the OpenClaw
  inbound-message guard can feed custom prompt-decision events with message
  hashes and decision metadata but no raw prompt text.
- `POST /api/v1/agent/edr/policy-events/jsonl` accepts line-delimited
  `PolicyEvent` captures, validates each non-empty line with line-numbered
  errors, and imports the events into the same flight-recorder, detection, and
  receipt path.
- `POST /api/v1/agent/edr/policy-events/replay` and
  `/policy-events/replay/jsonl` replay supplied `PolicyEvent` JSON or JSONL
  against the currently configured local policy without recording observations,
  return per-event allow/warn/block decisions, bind the raw policy
  version/hash/epoch plus event/result hashes, and emit a signed simulation
  receipt for current-policy historical replay.
- `POST /api/v1/agent/edr/policy-events/replay/history` reads the durable
  local flight recorder through a durable sidecar index, retains the newest
  matching observations by optional time window/age/limit/event-kind filters,
  seeks only the selected JSONL records, projects them into `PolicyEvent`
  candidates, and replays that local history against the current policy without
  mutating the recorder.
- `POST /api/v1/agent/edr/policy-events/impact` compares supplied
  `PolicyEvent` records between the current local policy and a proposed policy
  YAML payload, returns per-event changed verdicts plus allow/warn/block
  transition counts and guard/reason driver summaries, and emits a signed
  simulation receipt for proposed-policy breakage analysis.
- `POST /api/v1/agent/edr/policy-events/impact/history` applies the same
  current-vs-proposed impact analysis to projected flight-recorder history, so
  an operator can test a draft policy against local endpoint behavior without
  pasting an external event stream. Its response also joins changed verdicts
  back to bounded local causal contexts so the operator sees the process, file,
  network, credential, or tool chain affected by the draft policy. The causal
  impact payload includes ordered root-to-target chains, aggregate chain-driver
  summaries grouped by chain shape, target kind, verdict transition, guard, and
  proposed action, and a signed `graph_slice` receipt over the union slice. It
  also returns explicit promotion suggestions with request bodies for the
  existing `detection-candidate` and `staged-detections` endpoints, defaulting
  to an audit-stage handoff rather than auto-staging.
- `GET /api/v1/agent/edr/finding-groups` clusters recent local findings by
  overlapping causal graph context and returns each group with a signed
  `graph_slice` receipt plus affected identity and tool summaries for fast
  attribution to the responsible host/user/session/agent/workload/approval and
  tool-call context.
- `GET /api/v1/agent/edr/flight-recorder` returns the local recorder path plus
  persisted observation and graph counts.
- `POST /api/v1/agent/edr/flight-recorder/compact` performs dry-run-first
  JSONL flight-recorder compaction by age and/or maximum observation count while
  protecting observations referenced by retained signed receipts.
- `GET /api/v1/agent/edr/protection-state` returns the local policy snapshot,
  including an explicit YAML policy epoch when present, agent/provider sensor
  state, a signed sensor-state receipt, and dedicated provider-degradation
  receipts when local providers are degraded.
- `POST /api/v1/agent/edr/privacy-report` classifies submitted observations
  into local privacy projections, hashing or suppressing raw paths, command
  lines, scripts, tool parameters, URLs, and artifact previews unless
  `raw_artifact_permitted` mode is requested, allowed by local policy via
  `edr.telemetry.raw_artifact_upload: true`, and accompanied by
  `rawArtifactApprovalId` plus `rawArtifactApprovalReason`. The response
  includes the requested/effective privacy mode, raw-artifact policy and
  approval state, and emits a signed `privacy_report` receipt for the effective
  privacy mode and projection counts.
- `GET /api/v1/agent/edr/receipts` returns recent signed endpoint decision
  receipts from the local JSONL ledger, with optional filters for receipt
  family, action, finding ID, rule ID, graph slice ID, and root node ID.
- `POST /api/v1/agent/edr/receipts/compact` performs dry-run-first receipt
  ledger compaction by age and/or maximum receipt count while preserving signed
  receipt contents for retained records.
- `GET /api/v1/agent/edr/evidence-bundles` lists local evidence bundles with
  age and active-response protection metadata.
- `POST /api/v1/agent/edr/evidence-bundles/compact` performs dry-run-first
  evidence-bundle retention compaction by age and/or maximum bundle count while
  protecting bundles referenced by active response executions.
- `GET /api/v1/agent/edr/evidence-bundles/{bundle_id}` returns a locally
  stored collect-evidence graph bundle by ID.
- `GET /api/v1/agent/edr/evidence-bundles/{bundle_id}/archive` returns a
  hash-addressed archive package that binds the stored graph, bundle metadata,
  matching signed receipts, and local verification metadata.
- `POST /api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish`
  publishes a privacy-bounded archive metadata event to the enrolled agent
  NATS hunt-event subject when enterprise NATS is configured. The event carries
  archive/bundle hashes, graph counts, receipt hashes, and verification status;
  it does not inline raw graph nodes, receipt bodies, or local artifact paths.
  If NATS is disconnected, the same metadata event is queued in the private
  local outbox at `~/.config/clawdstrike/edr/fleet-hunt-event-outbox.json`
  with a bounded retry timestamp instead of dropping the archive publication
  request.
- `POST /api/v1/agent/edr/fleet-hunt-events/retry` drains due queued fleet
  hunt events from that private outbox when the enrolled NATS publisher is
  available. The request accepts `force` and `limit`; delivered events are
  removed, and failed attempts are retained with bounded retry backoff. The
  agent also drains due fleet hunt events during its fleet sync loop.
- When `control_api.enabled` is configured with a Control API URL and API key,
  local policy explicitly allows `edr.telemetry.raw_artifact_upload: true`, and
  the publish request includes `rawArtifactApprovalId` plus
  `rawArtifactApprovalReason` query parameters, fleet-publishing an
  evidence-bundle archive also posts the verified raw archive to
  `/api/v1/hunt/evidence-bundle-archives`. The upload payload carries the
  approval ID and hashed approval reason. The NATS hunt event remains
  metadata-only; raw upload failures are reported in the local publish response
  and queued in a private local retry ledger at
  `~/.config/clawdstrike/edr/control-archive-upload-retries.json`.
- `POST /api/v1/agent/edr/control-archive-uploads/retry` drains due queued
  Control API raw archive uploads using the currently configured Control API URL
  and API key. The retry ledger stores the approved upload payload and delivery
  hashes, but not the Control API key; delivered uploads are removed, and failed
  attempts are retained with bounded retry backoff. Retries refuse payloads that
  lack raw-artifact approval evidence.
- `POST /api/v1/agent/edr/control-archive-uploads/backfill` uploads already
  stored local evidence-bundle archives to the configured Control API without
  requiring NATS or a prior failed fleet publish. Pass `bundleId` for one bundle,
  or omit it to backfill the newest stored bundles up to `limit`; each archive is
  re-verified before upload, and raw upload still requires
  `rawArtifactApprovalId` plus `rawArtifactApprovalReason` in the backfill body.
- `POST /api/v1/agent/edr/evidence-bundles/archive/verify` re-verifies an
  archive package by recomputing its canonical archive hash, expected archive
  ID, receipt count, verification block, graph hash, graph counts, graph-slice
  and manifest graph-count evidence, response lifecycle graph/content evidence,
  artifact byte count, required receipt-family coverage with structured
  present/missing family lists and family cardinality, known bundle-family
  contracts, response actor continuity, endpoint identity continuity, root-node
  continuity, policy continuity, sensor-state coverage, endpoint-decision
  content-hash binding, receipt-ID and local-sequence uniqueness, receipt
  timestamp parsing/chronology, signer consistency, generatedAt coverage of
  enclosed receipts, validated optional trusted signer matching, and receipt
  bindings to bundle ID, graph slice, root node, and content hash.
- `POST /api/v1/agent/edr/causal-graph` returns a local process/file/network/DNS
  causality graph for the supplied observations, or the persisted local flight
  recorder graph when called with an empty observation list.
- `POST /api/v1/agent/edr/causal-subgraph` returns the persisted downstream
  graph slice for a root node or process identity and emits a signed
  `graph_slice` receipt with affected identity and tool-call summaries.
- `POST /api/v1/agent/edr/causal-context` returns bounded upstream cause and
  downstream effect context around a root node or process identity and emits a
  signed `graph_slice` receipt with affected identity and tool-call summaries.
- `POST /api/v1/agent/edr/graph-search` searches the persisted local graph by
  node kind, label substring, session/user/agent/workload/approval attributes,
  or a specific graph attribute key/value, then returns bounded signed context
  slices for matching host, user, session, agent, workload, approval, process,
  tool, credential, file, network, DNS, or policy nodes, with affected
  identity/tool-call summaries on each match.
  The response includes a query plan showing whether indexed candidate
  selection was used before final graph matching.
- `POST /api/v1/agent/edr/graph-slices/export` stores a bounded causal
  subgraph or causal context slice as a local evidence bundle under
  `~/.config/clawdstrike/edr/evidence-bundles/`, returns the bundle reference,
  returns affected identity/tool-call summaries, and emits a signed
  `graph_slice` receipt without requiring a response action.
- `POST /api/v1/agent/edr/agent-secret-touches` returns local credential-access
  graph slices causally linked to agent or tool activity, with optional
  session and credential-kind filters, and emits signed `graph_slice` receipts.
- `POST /api/v1/agent/edr/agent-secret-touches/fleet-publish` publishes those
  graph-backed facts to the enrolled agent NATS hunt-event subject when
  enterprise NATS is configured. The agent also best-effort publishes matching
  current credential-access ingestion and periodically drains unpublished
  persisted agent-secret-touch facts from the local flight recorder.
- `POST /api/v1/agent/edr/policy-simulation` replays a proposed blocking rule
  against a persisted graph target and returns affected nodes, developer
  breakage scoring, affected host/user/session/agent/workload/approval context,
  affected tool-call context, the graph slice, and a signed simulation receipt.
- `POST /api/v1/agent/edr/policy-replay` resolves a captured graph target by
  node ID or process identity, binds the replay to the currently configured
  local policy version/hash/epoch, returns graph-impact scoring plus affected
  identity/tool context, and emits a signed simulation receipt for "replay this
  incident under today's policy" workflows.
- `POST /api/v1/agent/edr/detection-candidate` generates a staged detection
  candidate from a persisted graph target, simulates the candidate, recommends a
  rollout stage, and emits a signed simulation receipt.
- `POST /api/v1/agent/edr/staged-detections` regenerates a detection candidate
  from the current graph, stores the selected rollout stage in the local staged
  detection ledger, and retains the signed simulation receipt with the record.
- `GET /api/v1/agent/edr/staged-detections` lists recent staged detections with
  optional stage and rule filters.
- `POST /api/v1/agent/edr/policy-deltas` promotes a staged detection into a
  versioned local policy-delta overlay under
  `~/.config/clawdstrike/edr/policy-deltas/`, binds the artifact hash to a
  signed `policy_delta` receipt, and preserves the source simulation receipt.
- `GET /api/v1/agent/edr/policy-deltas` lists generated policy deltas with
  optional stage and rule filters.
- `POST /api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply` dry-runs by
  default, verifies the current local policy hash still matches the generated
  delta's base hash, merges the overlay into the configured policy file when
  `dryRun` is `false`, writes a backup beside the policy, and emits a signed
  `policy_delta` receipt for the apply operation. Real applies also emit a
  post-apply enforcement proof with the new local policy snapshot, current
  daemon status, current sensor state, degraded-provider receipts, and a signed
  `sensor_state` receipt. By default they also request `hushd`
  `/api/v1/policy/reload` after the file update and record whether the reload
  succeeded. The proof includes per-provider policy acknowledgements for the
  macOS Endpoint Security and Network Extension status readouts, including
  observed policy epoch, policy-sync/readiness flags, and mismatch reasons; the
  signed `sensor_state` receipt binds the daemon reload result, provider-refresh
  result, acknowledgement poll result, and per-provider acknowledgement fields.
  Set
  `providerAckTimeoutMs` to control the direct provider-status refresh request
  and bounded wait for refreshed provider status; active waits must be between
  1 and 5000 ms. Set `reloadDaemonPolicy` to
  `false` to skip the reload attempt, or `restartDaemon` to `true` to request a
  managed daemon restart as well; dry-runs never reload, restart, poll providers,
  or emit post-apply receipts.
- `POST /api/v1/agent/edr/network-extension/egress-policy/proof` verifies the
  agent-generated NetworkExtension egress policy snapshot on disk, reports the
  snapshot hash, active and expired restriction counts, optional provider-status
  refresh result, current NetworkExtension provider readout, and emits a signed
  `sensor_state` receipt whose evidence binds the snapshot path, content hash,
  counts, generated timestamp, provider-refresh result, provider status, and an
  enforcement-ready bit that is true only when the snapshot is decodable and
  the provider reports active policy sync and enforcement readiness. This
  proves the provider-loadable artifact and local status boundary. When called
  with a `restrict_egress` execution ID, the route also returns a strict
  `liveEnforcementProven` verdict only when an active restriction, provider
  readiness, observed flow/block counters with no dropped verdicts, and
  execution-matched provider reload delivery are all present.
- `POST /api/v1/agent/edr/network-extension/events` accepts content-filter
  flow verdict events and records them as optional `dns_lookup`, `network_flow`,
  and `policy_decision` endpoint observations with provider ID, flow ID,
  verdict, policy snapshot hash/path, generation, and flow/remediation counters.
  Each recorded provider observation also returns a signed `observation`
  receipt that binds the observation ID, event kind, graph slice, provider
  state, and observation content hash. This lets delivered NetworkExtension
  flow decisions enter the local causal graph while deployed provider delivery
  remains separately verifiable.
- `POST /api/v1/agent/edr/deception-plan` renders a standard local honey
  artifact plan for an endpoint root. `POST
  /api/v1/agent/edr/deception-plan/materialize` creates those honey artifacts
  without overwriting existing files, registers them for future finding
  evaluation, and emits a signed `deception_materialization` receipt that binds
  the plan hash, materialization report hash, artifact counts, and registered
  artifact count. Registered honey artifacts are evaluated against later file
  touches, network flows and DNS lookups to planted internal hostnames, and
  browser-cookie credential observations that carry planted honey values. `POST
  /api/v1/agent/edr/deception-plan/cleanup` is dry-run-first and removes only
  registered honey files whose current contents still match the original
  artifact contents, then emits a signed `deception_cleanup` receipt with
  removal, refusal, and registry counts. `POST
  /api/v1/agent/edr/deception-plan/rotate` combines cleanup and
  re-materialization into one dry-run-first audited operation and emits cleanup,
  materialization, and `deception_rotation` receipts.
- `POST /api/v1/agent/edr/response-action` creates a local response plan for a
  graph target and emits a signed response receipt with TTL and rollback
  metadata bound to the current local session/posture actor. The response also
  returns affected host/user/session/agent/workload/approval and tool-call
  summaries derived from the response graph slice, so operators can see who and
  what a proposed containment plan affects before execution. Non-dry-run
  requests must include an `actor` identity object with at least `userId`,
  `sessionId`, `agentId`, `workloadId`, or `approvalId`; that actor is carried
  into the response-request and response-execution receipts and persisted on
  the response execution record for later lookup. Response-execution receipts
  also bind the current agent API, EndpointSecurity, and NetworkExtension
  provider state for proof-at-execution; `restrict_egress` adds
  NetworkExtension-specific policy-sync/readiness/counter evidence. Failed
  non-dry-run attempts after planning are also recorded as failed response
  executions with signed receipts before the route returns the error. The
  non-dry-run actions currently
  enabled are `collect_evidence`,
  which captures the target graph slice as a local evidence bundle reference,
  constrained `restrict_egress`, which creates TTL-bound local host:port
  restrictions for network nodes and makes `/api/v1/agent/policy-check` deny
  matching agent-mediated egress until rollback or expiry, constrained
  `quarantine_file`, which only accepts file/browser-download
  graph roots in temp, download, cache, dependency, or build-output paths and
  moves the file under `~/.config/clawdstrike/edr/quarantine/`, plus
  constrained `disable_persistence`, which accepts bounded LaunchAgent or
  LaunchDaemon plist graph roots, user-scoped and system systemd unit/drop-in files,
  XDG autostart desktop entries, KDE Plasma env/autostart scripts, Linux/macOS home shell startup
  files and Fish `conf.d` drop-ins, system `profile.d` drop-ins, ordinary user cron spool files, system cron drop-ins,
  and bounded
  Chromium-family or unpacked Firefox browser extension graph roots by moving only their
  `manifest.json`, then moves them under the same local response quarantine
  root, plus constrained `revoke_grant`,
  which currently rotates the
  local agent API token without preserving a grace token when the graph target
  contains the local API credential or calls local `clawdstrike-brokerd` to
  revoke broker-capability graph targets, including brokerd-supported
  provider-side revocation for brokered GitHub App installation tokens and
  Slack tokens, or clears and disables local agent-owned SIEM API key / webhook
  signing-secret integration settings when the graph target names those stored
  third-party secrets, plus constrained
  `suspend_process_tree`,
  which accepts only process graph roots with signalable PIDs, refuses protected
  system/agent processes, sends Unix `SIGSTOP` to the root/downstream process
  set, and records the affected PID set for rollback. Live
  `terminate_process_tree` is rejected because it is not rollback-capable; it
  remains available only for dry-run/simulation modeling and cannot be promoted
  into limited/full-block staged policy deltas. All
  live actions emit signed response-execution and evidence-bundle manifest
  receipts. Executed response reports are written to
  `~/.config/clawdstrike/edr/response-executions.jsonl` with TTL and rollback
  metadata. The bundle graph is stored under
  `~/.config/clawdstrike/edr/evidence-bundles/` for later local retrieval.
  Egress restrictions are stored in
  `~/.config/clawdstrike/edr/egress-restrictions.jsonl`, and the active
  restriction set is projected into a provider-loadable
  `~/.config/clawdstrike/edr/network-extension-egress-policy.json` snapshot for
  the macOS content-filter package. The NetworkExtension status helper can
  report that this snapshot is decodable; the proof route only claims
  enforcement readiness when current provider status also reports active policy
  sync and enforcement readiness. The provider runtime can reload changed
  snapshots before flow decisions and now has a unit-tested `reload_policy`
  command envelope that can accept a watched policy path, increments
  `remediation_requests`, refreshes the watched snapshot, and returns a provider
  snapshot with counters. The provider runtime persists that provider-authored
  snapshot to `network-extension-egress-policy.json.provider-runtime.json` by
  default, and `network-extension-status-tool live` prefers that runtime
  snapshot before falling back to a degraded policy-file-only readout. The same
  command can be represented as
  `NEFilterProviderConfiguration.vendorConfiguration` payload data for the
  macOS content-filter control surface, and `network-extension-status-tool
  request-reload <policy-snapshot-path> [generation]` can persist that payload
  through `NEFilterManager` preferences when an installed provider configuration
  is available. Live `restrict_egress` now fails closed
  before persisting a restriction unless the NetworkExtension provider reports
  active runtime, synced policy, and enforcement readiness; that refusal is
  recorded as a failed response execution with a signed receipt. Successful
  `restrict_egress` execution receipts also hash the current NetworkExtension
  runtime, policy sync/readiness bits, and flow/remediation counters when the
  agent has them. After writing the snapshot, the agent now asks the macOS host
  collector to persist a `request-reload` vendor configuration through the
  status helper when available. The content-filter provider has a tested
  vendor-configuration handler and observes saved reload commands through its
  runtime filter configuration. Deployed macOS delivery of that saved
  configuration, OS-wide NetworkExtension activation, and real-flow counter
  verification,
  provider-side third-party-token revocation beyond brokered GitHub/Slack token
  revocation, and broader system-wide persistence coverage beyond bounded
  launch/shell/profile-d/cron/systemd-user/systemd-system/systemd-drop-in/xdg-autostart/kde-plasma-env/kde-autostart-script/system-cron-drop-in/browser-extension manifest files remain
  open.
  `scripts/network-extension-live-dogfood.sh` is the operator harness for that
  deployed-provider proof: it records a target network-flow graph, executes live
  `restrict_egress`, triggers real TCP flows, polls the strict proof route, and
  rolls the response execution back unless explicitly told to keep it active.
  A claimed pass also runs
  `scripts/network-extension-live-dogfood-verify.py` against `summary.json`,
  rejecting weak proof, missing provider reload delivery, non-blocked final
  flows, skipped or failed rollback, failed post-rollback reachability, and
  dropped verdicts.
- `GET /api/v1/agent/edr/response-executions` returns recent local response
  execution records, including expiration and rollback metadata.
- `POST /api/v1/agent/edr/response-executions/expire` marks locally expired
  response executions and emits signed expiration receipts. For rollback-capable
  side-effect actions such as `restrict_egress`, `quarantine_file`,
  `disable_persistence`, and `suspend_process_tree`, the sweep first executes the
  local rollback path and returns signed rollback receipts alongside expiration
  receipts.
- `POST /api/v1/agent/edr/response-executions/{execution_id}/cancel` closes an
  active `collect_evidence` window or active `restrict_egress` restriction before
  TTL expiry and emits a signed cancellation receipt. File quarantine,
  persistence disablement, process suspension, and other local side-effect
  actions must use the explicit rollback route.
- `GET /api/v1/agent/edr/response-acknowledgements` returns recent local
  response acknowledgement reports from
  `~/.config/clawdstrike/edr/response-acknowledgements.jsonl`.
- `POST /api/v1/agent/edr/response-executions/{execution_id}/rollback` restores
  a constrained `quarantine_file` or `disable_persistence` execution when the
  response artifact still matches its recorded hash and the original target path
  does not already exist, removes constrained `restrict_egress` local
  policy-check restrictions, or resumes a constrained `suspend_process_tree`
  execution with Unix `SIGCONT`, then emits a signed rollback receipt and a
  terminal `response_execution` transition receipt with status `rolled_back`.
- `POST /api/v1/agent/edr/response-executions/{execution_id}/acknowledge`
  records the local operator or agent acknowledgement for a response execution
  and emits a signed acknowledgement receipt that binds the acknowledged status,
  actor, note, rollback reference, effects, and graph slice. When supplied, a
  `control` block with `responseActionId`, `deliveryId`, `targetKind`,
  `targetId`, `ackToken`, `status`, and `resultingState` is persisted as
  control-plane correlation metadata; omitted control acknowledgement status
  defaults to `rolled_back` for rolled-back terminal transitions, `expired` for
  expired transitions, `failed` for failed executions, and `acknowledged`
  otherwise. Receipts hash the acknowledgement token and never store it raw. If
  the same `control` block includes
  `controlApiUrl` plus `controlApiToken` / `controlApiKey`, or agent settings
  include `control_api.enabled: true` with `control_api.url`, the agent also
  attempts a direct Control API acknowledgement postback. When a Control API key
  is configured it uses the authenticated `/acks` route with `x-api-key`;
  otherwise it uses the bearerless `/agent-acks` route authorized by the
  delivery `ackToken`. Enrollment persists the Control API URL for this path.
  The local acknowledgement response never returns the Control API credential,
  and the settings API reports only whether a Control API key is configured.
  Failed postbacks are persisted to the private local retry queue at
  `~/.config/clawdstrike/edr/control-ack-postback-retries.json` with bounded
  backoff. That queue temporarily stores the raw delivery `ackToken` so the
  postback can be replayed, but the token is still omitted from local
  acknowledgement receipts and API responses.
- `POST /api/v1/agent/edr/control-ack-postbacks/retry` drains due failed
  Control API acknowledgement postbacks. The route is local-token
  authenticated, honors each entry's `nextAttemptAt` unless `force: true` is
  supplied, removes delivered entries, and requeues failures with bounded
  backoff.
- `GET /api/v1/agent/edr/response-executions/{execution_id}` returns one local
  response execution record.
- `GET /api/v1/agent/edr/response-executions/{execution_id}/proof` returns the
  durable proof package for that execution: the response execution record, graph
  slice reference, affected host/user/session/agent/workload/approval and
  tool-call summaries derived from the stored evidence-bundle graph, provider
  state captured at execution time, response-request receipt, response-execution
  receipt, evidence-bundle manifest receipt, and any later signed terminal
  transition, rollback, or acknowledgement receipts for the same action
  contract. Rollback-capable side-effect actions have
  route-level proof coverage for the restored or resumed target after manual
  rollback. Before serving the package, the route verifies the
  selected response-request, response-execution, terminal transition, rollback,
  and acknowledgement receipts against the local ledger signer, revalidates the
  embedded endpoint-decision receipt contract, binds each receipt's content hash
  and receipt ID back to that contract, cross-checks the selected
  response-request, response-execution, evidence-bundle manifest, terminal
  transition, rollback, and acknowledgement receipts against the persisted
  execution row including execution, rollback, and acknowledgement effect
  evidence, reloads the stored local evidence-bundle artifact from disk instead
  of trusting a stale in-memory copy, verifies it still hashes to the signed
  execution bundle reference, and rejects actor drift when the persisted
  execution actor, signed receipt actor, `actorHash`, or `executionActorHash`
  evidence diverge.
- `POST /api/v1/agent/edr/deception-plan` renders a standard deception plan.
- `POST /api/v1/agent/edr/deception-plan/materialize` creates the honey files
  with safe no-overwrite semantics and registers the artifacts in
  `~/.config/clawdstrike/edr/honey-artifacts.jsonl` for future finding
  evaluation.
- `POST /api/v1/agent/edr/deception-plan/cleanup` dry-runs by default and, when
  `dryRun: false`, removes only registered exact-match honey files while
  deregistering removed or already-missing artifacts.
- `POST /api/v1/agent/edr/deception-plan/rotate` dry-runs by default and, when
  `dryRun: false`, replaces an old registered honey plan with a new plan while
  returning cleanup, materialization, and rotation receipts.

EDR detection receipts bind the local policy file hash/epoch, endpoint or
agent identity, signer public key, graph references, sensor state, confidence,
and hashed evidence values. The agent signs with its enrollment key when
available, otherwise with a private local EDR receipt key stored under the
agent config directory. Provider-originated `observation` receipts bind the
provider's recorded observation ID, event kind, event target, graph slice,
process node, provider ID/kind, and a canonical observation content hash.
Protection-state receipts bind the local policy snapshot, agent API state, and
macOS EndpointSecurity/NetworkExtension provider health; degraded providers
also emit dedicated `provider_degradation` receipts with hashed reason and
counter evidence. When a previously installed degraded provider becomes active
and healthy, the protection-state response returns a provider recovery row and
the `sensor_state` receipt binds hashed recovery count and provider IDs.
Response-action dry runs use the same local receipt ledger and require a root
graph target plus bounded TTL before a receipt is created.
Privacy reports are local classifier outputs: default
`hashes_features` mode emits hashes and low-content features, marks raw artifact
fields as local-only, and omits raw values; `raw_artifact_permitted` is the only
mode that can include raw artifact values, and the agent downgrades that request
to `hashes_features` unless local policy explicitly allows raw artifact upload
with `edr.telemetry.raw_artifact_upload: true` and the request carries
`rawArtifactApprovalId` plus `rawArtifactApprovalReason`. Privacy-report
receipts bind the report ID, effective privacy mode, raw-artifact permission
bit, observation count, field count, redaction-class counts, raw-suppressed
count, and, for raw-permitted reports, hashed approval ID and approval-reason
hash evidence. Causal subgraph and causal-context exports emit `graph_slice`
receipts that bind the
root node, graph slice ID, slice kind, node count, and edge count. Policy-check
receipts bind the action type, target,
allow/block result, guard, severity, message, endpoint identity, current local
posture, runtime agent identity, sensor state, and policy snapshot.
Policy-simulation receipts bind the proposed or current-policy graph replay
rule, graph slice, affected node counts, affected identity/tool context, impact
level, developer breakage score, and current local policy snapshot. Policy-event replay receipts reuse the
simulation family and bind the replay ID, event-stream hash, result hash,
allow/warn/block counts, posture-tracking mode, and current policy snapshot.
Policy-event impact receipts bind the impact ID, current/proposed result hashes,
proposed policy hash/epoch, changed count, allow-to-block count, event-stream
hash, posture-tracking mode, and current policy snapshot. History-backed replay
and impact use the same receipt families after projecting durable
flight-recorder observations into `PolicyEvent` candidates; the API response
also reports the recorder path, selected observation count, filters, and
projection-mode hash. Impact responses include driver buckets that aggregate
changed events by transition, current/proposed guard, and current/proposed
reason code with sample event IDs. History-backed impact responses additionally
include bounded causal-impact contexts for changed events, with node-kind counts,
ordered root-to-target chains, and local graph slices joined from the flight
recorder, plus a signed `graph_slice` receipt over the union causal-impact
slice. They also include operator promotion suggestions that point to the
existing candidate/staging workflow without mutating staged-detection state.
Detection-candidate responses reuse that receipt family for generated rules and
include staged rollout guidance for observe, audit, warn, limited block, and
full block.
Policy-delta receipts bind the generated overlay ID, staged-detection ID,
source simulation ID, source affected identity/tool context, graph slice, root
node, selected rollout stage, action, artifact hash, and, for apply operations,
the previous policy hash, new policy hash, and backup path. Apply responses also emit a separate post-apply
`sensor_state` receipt when protection-state verification is enabled. Response
requests bind the graph slice and graph content hash before execution. Live
response executions emit a response-execution receipt that binds the evidence
bundle ID, graph slice, content hash, TTL, rollback reference, execution status,
execution effects, and hashed effect-type evidence for each effect.
`collect_evidence` adds a dedicated `evidence_bundle_manifest` receipt for the
bundle ID, graph slice, content hash, node count, and edge count.
`restrict_egress` receipts bind the restricted host:port target set, TTL,
rollback reference, and graph slice; rollback emits a `restore_egress` effect
for the same target set.
`quarantine_file` receipts also bind the original file path, quarantine artifact
path, file content hash, and byte count as hashed execution effects. The agent
verifies the graph content hash before storing the evidence bundle artifact and
revalidates persisted artifact IDs, graph hashes, byte counts, and graph
cardinality before direct bundle loads or bundle listing.
`disable_persistence` receipts bind the persistence file path, disabled
artifact path, content hash, and byte count as hashed execution effects.
`revoke_grant` receipts bind the local API grant target and hash of the revoked
token, or the local broker-capability target and brokerd revoke result hash,
including brokerd provider-token revocation reports when present, as hashed
execution effects; replacement credentials are not returned in the response.
`suspend_process_tree` receipts bind the root PID plus affected PID set as
hashed execution effects. Live terminate receipts are not emitted by the local
executor because non-rollbackable process termination is outside the safe
autonomous response set.
Quarantine and persistence rollbacks refuse overwrite, verify the response
artifact hash, and emit `response_rollback` receipts that bind the restored
target, response artifact, hash, byte count, TTL, rollback reference, and graph
slice. Rollback receipts also hash the rollback effect type so restored-effect
classes cannot be relabeled against the signed response action. Process-tree
rollback emits a `resume_process_tree` effect for the recorded PID set.
Response execution records are separately queryable so operators can inspect TTL
expiration and rollback references after the original response call. The
expiration sweep emits signed `response_execution` receipts with status
`expired` for TTL-expired local executions and emits `response_rollback` receipts
when it restores rollback-capable side effects. The cancellation route emits the
same execution receipt family with status `cancelled` only when an operator
closes an active collect-evidence window or restrict-egress restriction before
TTL expiry. Manual rollback emits status `rolled_back` as a terminal transition
so rolled-back side-effect executions stop counting as active local response
windows.
Response request, execution, rollback, and acknowledgement receipts all bind the
local response actor context, including endpoint ID, current session where
available, local posture, agent ID, and response-engine workload ID.
Acknowledgement receipts bind both the acknowledged execution-effect hashes and
their effect-type evidence.
Agent-secret-touch queries use the same graph-slice receipt family to bind each
returned credential node, slice kind, node count, and edge count while the graph
itself carries local session, user, host, agent, workload, approval, and posture
attributes when submitted by collectors.
Finding-group queries use graph-slice receipts to bind each local causal alert
group to the root node, grouped graph slice, slice kind, node count, and edge
count, while the response summarizes the responsible identity and tool nodes in
that signed graph slice.
Materialized deception artifacts are loaded from the local honey registry during
future finding evaluations, so honey-file touches, network flows and DNS lookups
to planted internal hostnames, and browser-cookie credential observations that
carry planted honey values can be detected without resubmitting the original
deception plan.
Deception materialization receipts bind each planted honey plan and
materialization report before later honey-touch detections fire. Cleanup
receipts bind the cleanup report and registry counts for dry-run or applied
deception removal. Rotation receipts bind the old plan hash, new plan hash,
cleanup report, materialization report, and final registry counts for a
first-class rotation operation.

## Configuration

Settings are stored in the platform config directory plus
`clawdstrike/agent.json`:

- macOS: `~/Library/Application Support/clawdstrike/agent.json`
- Linux/dev fallback: `~/.config/clawdstrike/agent.json`

```json
{
  "policy_path": "~/.config/clawdstrike/policy.yaml",
  "daemon_port": 9876,
  "mcp_port": 9877,
  "agent_api_port": 9878,
  "enabled": true,
  "auto_start": true,
  "notifications_enabled": true,
  "notification_severity": "block",
  "dashboard_url": "http://127.0.0.1:9878/ui",
  "ota_enabled": true,
  "ota_mode": "auto",
  "ota_channel": "stable",
  "ota_manifest_url": null,
  "ota_allow_fallback_to_default": false,
  "ota_check_interval_minutes": 360,
  "ota_pinned_public_keys": [],
  "ota_last_check_at": null,
  "ota_last_result": null,
  "ota_current_hushd_version": null,
  "brokerd": {
    "enabled": false,
    "port": 9889,
    "binary_path": null,
    "allow_http_loopback": false,
    "allow_private_upstream_hosts": false,
    "allow_invalid_upstream_tls": false,
    "secret_backend": {
      "kind": "file",
      "file_path": "~/.config/clawdstrike/broker-secrets.json",
      "env_prefix": "CLAWDSTRIKE_SECRET_",
      "http_base_url": null,
      "http_bearer_token": null,
      "http_path_prefix": "/v1/secrets"
    }
  },
  "openclaw": {
    "gateways": [],
    "active_gateway_id": null
  }
}
```

The authenticated settings API rejects unknown fields, applies local API security
updates atomically, and validates URL-bearing fields before persistence. Control
API and OTA manifest URLs must use HTTPS, except loopback HTTP for local
development; URL userinfo is rejected. Notification severity, OTA mode/channel,
OTA check interval, local API token rotation, token grace, and mTLS port
settings must stay within the route's explicit allow-lists or bounds instead of
being silently rewritten.

### Default Policy

The agent bundles a default policy at `resources/default-policy.yaml` and copies
it to the platform config directory as `clawdstrike/policy.yaml` on first run.

### Local broker mode

When `brokerd.enabled` is `true`, the agent:

- copies the bundled `clawdstrike-brokerd` binary into `~/.config/clawdstrike/bin/`
- keeps a persistent local hushd signing key under `~/.config/clawdstrike/runtime/`
- fetches hushd's broker signing public key and injects it into brokerd on startup
- starts brokerd with the configured `file`, `env`, or managed `http` secret backend

### Signed hushd OTA updates

The agent can verify and apply signed `hushd` updates from release manifests:

- Status: `GET /api/v1/agent/ota/status`
- Check now: `POST /api/v1/agent/ota/check`
- Apply now: `POST /api/v1/agent/ota/apply`

Release automation:

- `scripts/generate-hushd-ota-manifest.sh` creates per-channel manifests from `hushd-*` release artifacts.
- `scripts/sign-hushd-ota-manifest.sh` signs manifests with Ed25519.
- `.github/workflows/release.yml` publishes `hushd-ota-manifest-stable.json` and `hushd-ota-manifest-beta.json`.

Release workflow secret:

- `HUSHD_OTA_SIGNING_PRIVATE_KEY_PEM` (required)
- `HUSHD_OTA_SIGNING_PUBLIC_KEY_HEX` (optional override; otherwise derived from the private key)

## Architecture

```
┌─────────────────┐     ┌─────────────────────────────────┐
│   System Tray   │     │         Daemon (hushd)          │
│   ┌─────────┐   │     │  ┌─────────────────────────┐    │
│   │ 🛡️ SDR  │◄──┼─────┼──┤ Policy Engine           │    │
│   └─────────┘   │     │  ├─────────────────────────┤    │
│   Menu:         │     │  │ HTTP API (:9876)        │    │
│   • Status      │     │  ├─────────────────────────┤    │
│   • Events      │     │  │ Audit Ledger (SQLite)   │    │
│   • Settings    │     │  └─────────────────────────┘    │
└─────────────────┘     └─────────────────────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────┐     ┌─────────────────────────────────┐
│  Notifications  │     │      AI Tool Integrations       │
│  • Block alerts │     │  ┌───────────┐  ┌───────────┐   │
│  • Warnings     │     │  │Claude Code│  │  Cursor   │   │
└─────────────────┘     │  │  (hooks)  │  │  (MCP)    │   │
                        │  └───────────┘  └───────────┘   │
                        └─────────────────────────────────┘
```

## Verification

1. **Check daemon health**: `curl http://localhost:9876/health`
2. **Test policy check**:
   ```bash
   curl -X POST http://localhost:9876/api/v1/check \
     -H "Content-Type: application/json" \
     -d '{"action_type":"file_access","target":"/etc/passwd"}'
   ```
3. **Verify Claude Code hook**: Test with Claude Code, should see policy checks in events
4. **Run OpenClaw smoke harness**:
   ```bash
   scripts/openclaw-agent-smoke.sh --gateway-url ws://127.0.0.1:18789 --gateway-token dev-token
   ```

## Operations Runbook

- Full runbook: `docs/src/guides/agent-openclaw-operations.md`
- Verification and smoke checks: `#verification` section in this README

## Troubleshooting

### Daemon won't start
- Check agent logs for bundled `hushd` copy/start errors
- For external daemon mode, set `hushd_binary_path` in settings
- Check if port 9876 is available: `lsof -i :9876`
- View logs: `Console.app` > search "clawdstrike"

### Claude Code hooks not working
- Ensure `~/.claude/` directory exists
- Check hook is executable: `ls -la ~/.claude/hooks/`
- Test hook manually: `echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | ~/.claude/hooks/clawdstrike-check.sh`

### No notifications
- Check macOS notification permissions for the app
- Verify `notifications_enabled: true` in settings

### Desktop cannot call local API
- Confirm `agent-local-token` exists and is non-empty in the platform
  `clawdstrike` config directory
- Confirm API port in `agent.json` matches desktop expectation
- Confirm health endpoint:
  ```bash
  curl -fsS "http://127.0.0.1:9878/api/v1/agent/health" | jq .
  ```

## License

MIT
