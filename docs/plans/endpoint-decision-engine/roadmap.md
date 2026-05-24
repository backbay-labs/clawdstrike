# Endpoint Decision Engine Roadmap

> **Status:** Draft | **Date:** 2026-05-16
> **Purpose:** phased implementation plan for the local endpoint decision-engine architecture

## Phase 0: Freeze Contracts And Evidence Boundaries

**Goal:** prevent the product story from outrunning the implementation.

**Initial progress:** `EndpointDecisionReceipt` now defines the first endpoint receipt contract for
detection evidence and signs through the existing `hush-core::Receipt` format. Validation fails
closed when policy hash, policy epoch, sensor state, endpoint identity, signer identity, detection
IDs, graph references, receipt evidence entries, unique evidence keys, evidence hashes, explicit
evidence redaction classes, raw evidence hash binding, unknown endpoint-decision receipt, actor,
clock, policy, signer, sensor-state, provider-state, decision, graph-reference, or evidence-item fields, or confidence bounds are missing/invalid.
Response plan, execution report, execution-effect, evidence-bundle reference, rollback report,
acknowledgement report, and control-correlation metadata also reject unknown fields before feeding
receipt evidence or local proof surfaces.
Sensor-state validation binds provider count, active/healthy/degraded counts, provider IDs, full
sensor-state content hash, and the signed sensor-state ID back to the signed
endpoint/policy/provider-state body, and rejects contradictory
provider health, so inactive, unhealthy, event-dropping,
deadline-missing,
missing-Full-Disk-Access, or uninstalled providers must be explicitly marked degraded with non-empty
reason strings, and provider IDs must be unique within each receipt. Active or healthy provider rows
must include `last_seen` timestamps so protection-state proofs have an observation time, and provider
`last_seen` values cannot be after the receipt capture time. Provider runtime, last-error, and
attestation degradation reason strings are redacted for embedded secret-like tokens before they are
returned or signed into sensor-state/provider-degradation metadata. Endpoint receipt signing now embeds the
actual signer public key when callers do not prefill signer metadata. The local agent now emits,
persists, and can query signed policy-decision, protection-state, detection, simulation,
response-request, and collect-evidence response-execution/evidence-bundle-manifest receipts.
Causal-subgraph and causal-context exports now emit signed `graph_slice` receipts that bind graph
content hashes and reject roots or graph-slice IDs inconsistent with the signed graph.
Collect-evidence graph bundles are now stored locally and retrievable by bundle ID. Dedicated
`provider_degradation` receipts are now
emitted when the protection-state API observes degraded local providers, and validation binds
provider identity/state/reason/counter/full-disk-access evidence to the degraded provider named by
the signed rule ID and derives the provider-degradation ID from the endpoint, policy hash, provider
identity/state, reason, counter, and full-disk-access evidence hashes.
Policy-decision and local
response receipts now carry local actor context for endpoint ID, current session where available,
posture, agent ID, and response-engine workload ID, and response receipt validation now rejects
response-family receipts that lack any accountable user, session, agent, workload, or approval
context beyond the endpoint ID. The local developer-activity ingress now accepts
top-level `processGuid`, `parentProcessGuid`, pid/ppid, process image, process command line, and cwd
fields from lightweight collectors as causal process ancestry. Adapter-core developer-activity facts
now carry available host/user/session/agent/workload/approval identity and policy epoch/version/hash
correlation metadata so local tool-boundary observations can be tied back to endpoint and approval
context before receipt generation. Canonical `PolicyEvent` ingestion now also maps endpoint and
principal identity aliases such as `endpointId` and `principalId` into endpoint observations, and
maps agent/workload/approval aliases from metadata and bounded `PolicyEvent.context` fields into
graph attributes and receipt actors.
Direct endpoint-observation, runtime process, code-signature, causal-graph, node, edge, and
flight-recorder sidecar-index envelopes now reject unknown fields before those values can shape
endpoint runtime-integrity state, graph search, or receipt surfaces. Receipt sidecar-index records
now reject unknown fields too, and indexed receipt lookup rebuilds invalid receipt indexes from the
signed ledger instead of trusting derived sidecar metadata. Invalid flight-recorder sidecars are
rebuilt from the JSONL observation log.
Persisted staged-detection and policy-delta promotion records now reject unknown fields on direct
deserialization, including nested candidate, stage-plan, target-policy, rollout, and artifact
envelopes, so generated enforcement overlays cannot carry silent shadow promotion metadata into
later replay/apply flows.
Stored evidence-bundle artifacts and archive/verification envelopes reject unknown fields too, so
local proof-package verification cannot silently accept shadow bundle, artifact, archive, or
verification metadata.
Persisted egress restriction records and NetworkExtension egress-policy snapshots now reject
unknown fields, so local containment state and provider-loadable policy snapshots cannot silently
carry shadow active/target/provider metadata.
Persisted fleet hunt-event outbox entries and Control API acknowledgement/archive retry queue
records now reject unknown fields before queued data can be replayed toward NATS or Control API, so
shadow retry metadata cannot steer later delivery.
Local findings, policy-event, developer-activity, package-manager, EndpointSecurity, and
NetworkExtension ingress bodies now reject unknown top-level and nested collector-record fields
before those values can enter redaction, graph, detection, or receipt paths.
Broker-capability and provider-token revocation reports from brokerd now reject unknown fields
before provider-facing revoke results can shape signed response-effect hashes.

### Work

- Define `EndpointDecisionReceipt` schema for local policy decisions, detections, simulations,
  response actions, provider degradation, and graph slices. Initial policy-decision receipt
  validation now binds `actionType` evidence to the signed rule ID, binds `allowed` evidence to the
  signed pass/fail bit, rejects allow/block action mismatches, and requires target/guard proof
  evidence. It now derives the policy-decision ID from the endpoint, policy hash, action type,
  target evidence hash, allow/block bit, and guard evidence hash.
- Define durable `EndpointObservation` ingestion contract for agent API, macOS providers, and
  bridge events.
- Decide the local graph storage backend for v1.
- Define privacy upload classes and raw-artifact policy gates. Initial local privacy reports now
  classify observation fields into hash-only, metadata-only, local-only, and explicitly
  raw-permitted projections, downgrade raw-artifact requests unless local policy sets
  `edr.telemetry.raw_artifact_upload: true`, and emit signed `privacy_report` receipts; fleet upload
  enforcement and fleet-side approval workflow are still open. Receipt validation now binds
  `privacyReportId` evidence to the signed report ID, derives that report ID from the signed privacy
  mode, raw-artifact permission, and count evidence hashes, and rejects raw evidence values unless
  the item is explicitly `raw_artifact_permitted` and the raw value matches the evidence hash.
  Privacy report, observation-projection, and field-projection metadata now reject unknown fields
  before local redaction/proof surfaces can consume them.
  Control Console now has a
  `Privacy Report` operator tool that surfaces effective mode, raw-artifact upload decisions,
  distinct redacted/local-only/hash-only/metadata/raw-permitted projection labels, hashes, feature
  projections, raw-suppressed/local-only counts, raw-permitted values when policy allows them, and
  the signed receipt family.
- Record the macOS provider health contract from `docs/plans/clawdstrike/macos-es-ne/**` as an
  input to every endpoint decision receipt.

### Acceptance gates

- Schema fixtures for decision, detection, response, degraded-provider, and graph-slice receipts.
- A documented mapping from `EndpointObservation` fields to receipt evidence fields.
- A migration or local store design for graph persistence.
- Tests that reject receipts missing policy hash, policy epoch, sensor state, signer identity, and
  valid evidence entries.

### Remaining receipt work

- Promote the first local evidence-bundle store into retention, compaction, and fleet upload
  semantics. The local store now supports listing and dry-run-first age/count compaction while
  protecting bundles referenced by active response executions, and can export hash-addressed local
  archive packages that bind the stored graph, bundle metadata, matching signed receipts, canonical
  archive hashes, and local verification metadata for graph content hashes, artifact-vs-bundle
  metadata consistency, graph node/edge counts, receipt families, receipt signatures, and
  graph-slice/content-hash binding, plus a local verifier route for later package checks. Local
  archive metadata can now be fleet-published as a hunt event with archive/bundle hashes, graph
  counts, receipt IDs/hashes, receipt families, and verification status while omitting raw graph
  nodes, receipt bodies, and local artifact paths, and disconnected publication requests are queued in
  a private local fleet hunt-event outbox with bounded retry timestamps. A local retry route drains
  due queued fleet hunt events when NATS is available, and the fleet sync loop also drains due outbox
  entries at startup and on interval. The Control API now accepts admin API-key raw archive uploads,
  validates canonical archive hashes, clamps retention to the tenant policy, and exposes metadata and
  retained archive download routes. The agent now uploads verified raw archives during
  evidence-bundle fleet publish when `control_api.enabled` has a URL/API key and local policy allows
  `edr.telemetry.raw_artifact_upload: true`; failed raw uploads are queued in a private local retry
  ledger and drained through an authenticated local retry route. An authenticated local backfill
  route can upload already-stored verified archives to Control API without NATS or a prior failed
  fleet publish. The control console event drawer now recognizes endpoint evidence archive hunt
  events, fetches retained archive metadata by archive ID, attaches that metadata to incident
  exports, and can export retained raw archives through the Control API download route, which now
  rejects viewer/member credentials for raw archive bodies, keeps metadata lookup available, and
  requires admin/owner roles for raw body retrieval. Raw body uploads reject viewer/member
  credentials and non-API-key actors. Successful raw body upload/retrieval plus denied raw-body
  attempts record sanitized compliance audit metadata with archive identifiers and actor identity,
  without storing raw archive bodies in the audit row. The compliance export path carries that
  sanitized metadata through JSON, CSV, and CEF output, and also carries case evidence-bundle
  custody events with sanitized bundle IDs, case IDs, digests, sizes, counts, and actor metadata.
  The Control API case artifact service can
  also attach retained endpoint evidence archives as verified
  `endpoint_evidence_archive` references with server-derived archive hashes, bundle IDs, raw refs,
  retention metadata, and verification blocks. The event drawer can now load existing remote cases,
  attach the archive artifact to a selected case, or create a new archive-focused remote case and
  attach the artifact immediately. It can also load the selected remote case detail and timeline,
  request a signed case evidence-bundle export that includes raw references plus a sanitized
  `audit-events.jsonl` trail for matching raw-archive upload/download/denial events, and download
  the completed signed bundle through the Control API evidence-bundle download route. Control
  Console also has a first-class `Fleet Cases` operator tool that lists remote cases, queries
  text/status/severity filters through the Control API, creates new investigation cases, updates
  selected case status through the existing case patch route, bulk-transitions selected cases through
  lifecycle statuses, loads selected case artifacts and timeline events, exports signed case evidence
  bundles with raw references and related sanitized raw-archive audit trails, and downloads completed
  bundle archives. Bundle metadata and ZIP downloads follow the export boundary and reject viewer
  credentials with sanitized denial audit events; denied bundle creation attempts are audited by
  case ID, and successful export creation, metadata reads, plus completed ZIP downloads are audited
  with sanitized bundle ID, case ID, digest, size, count, and actor metadata. Later case evidence
  exports include those sanitized bundle custody events in `audit-events.jsonl`.
- Promote graph-slice receipts into fleet upload semantics. Durable local slice export storage now
  exists through the local evidence-bundle store.
- Promote the current local-policy mtime epoch into an explicit policy epoch from policy bundle
  state. The local receipt snapshot now prefers explicit YAML epoch fields such as
  `policy_epoch`, `policyEpoch`, `policy.epoch`, and `bundle.policyEpoch`, with file mtime as the
  fallback for ad hoc policies. Endpoint-side policy-cache sync now persists a private
  `policy-cache.manifest.json` sidecar with source URL, fetch time, byte count, bundle hash,
  version, and explicit policy epoch, and rejects fetched bundles that downgrade the cached epoch,
  omit an epoch after an epoch-bearing cache, or mutate content without advancing the epoch. Control
  API tenant policy deployment, heartbeat reconciliation, and enrollment backfill now resolve each
  agent's effective policy from the tenant active policy plus matching tenant, swarm, project,
  capability-group, and principal overlays, stamp the distributed KV/broadcast YAML with a monotonic
  `policy_epoch`; Control API policy preview now validates proposed tenant YAML and compiles
  non-persistent agent effective-policy previews without writing tenant policy or KV state; durable
  Control API policy proposals now let write-scoped authors submit policy YAML for admin/owner
  reject or two-approver approve-deploy review while failing closed if the active policy version
  changed under the proposal, retaining generated version/hash/diff preview evidence on the
  proposal record, automatically estimating fleet-history impact from recent signed hunt events,
  and allowing pending proposals to attach hash-bound local/fleet/manual impact evidence before
  review; when a pending proposal includes a signed endpoint policy-event impact receipt, the
  Control API verifies the signature, validates the endpoint-decision contract is the
  `endpoint.policy_event_impact` simulation over `policy_event_stream`, requires canonical impact
  evidence keys, computes the canonical signed-receipt SHA-256, and stores the verified receipt body
  plus binding metadata on the proposal; proposal impact attachment also accepts a bounded batch of
  endpoint impact receipts, rejects duplicate signed-receipt hashes, and stores aggregate fleet proof
  metadata including distinct endpoint count, signed receipt hashes, endpoint IDs, and per-receipt
  signed bodies; generated proposal preview evidence now includes a fleet rule-diff validation plan
  that selects candidate endpoints from recent hunt history and emits endpoint-specific
  `/api/v1/agent/edr/policy-events/impact/history` request bodies plus the expected signed receipt
  contract; pending proposals can now dispatch that plan through the durable response-action ledger
  as `policy_rule_diff_validation` endpoint actions, publish signed NATS response-command payloads,
  have enrolled agents verify and execute those signed commands against the local impact-history API,
  require ack-token postback from each endpoint, and collect acknowledged signed impact receipts into
  fleet-history proposal impact evidence without manual attachment;
  and agent NATS KV policy sync persists a local hash/epoch manifest and rejects missing-epoch
  updates, epoch downgrades, or same-epoch content mutation.
- Add indexed receipt search and receipt compaction. Bounded local lookup already supports filtering
  by family, action, finding ID, rule ID, graph slice ID, root node ID, receipt ID, execution ID,
  execution status, local sequence, and actor endpoint/user/session/agent/workload/approval fields,
  the receipt ledger now maintains a private sidecar JSONL index with filter fields and ledger byte
  offsets, missing, stale, mismatched, corrupt, or unknown-field sidecars are rebuilt from the local
  ledger on lookup, and the receipt ledger supports dry-run-first age/count compaction. A local
  authenticated receipt-upload route now dry-runs by default, verifies each selected signed endpoint
  receipt against its embedded endpoint signer, projects it into the Control API
  `/api/v1/receipts/batch` schema with signed receipt bodies, policy names, guards, metadata, and
  evidence, and posts it when `control_api.enabled`, URL, and API key are configured. Receipt
  emission paths now also attempt automatic Control API upload after local signing with a short
  per-request timeout so local protection is not held hostage by a slow control plane; failed
  automatic uploads are persisted in a private bounded retry queue and can drain on the scheduled
  background loop or through an authenticated local retry route. Delivered EndpointSecurity
  auth-open and NetworkExtension egress allow/block observations now emit provider-sensor-state
  `policy_decision` receipts; broader deployed-sensor dogfood and remaining provider-originated
  receipt paths remain open.
- Add live containment response/action receipts to the local agent API. The bounded local action
  families now emit signed response-execution receipts for successful execution and failed live
  attempts.

## Phase 1: Durable Local Flight Recorder

**Goal:** promote the existing in-memory graph recorder into a local queryable flight recorder.

**Initial progress:** `EndpointFlightRecorder` now persists endpoint observations to JSONL and the
local agent API uses it for the empty-input causal graph projection, downstream `causal-subgraph`
process/root queries, bounded upstream/downstream `causal-context` queries, bounded graph search by
node kind, label, exact path, path prefix, anchored path pattern,
session/user/agent/workload/approval, tool-call ID, graph attribute key/value with durable
graph-node prefiltering plus graph-edge sidecar adjacency expansion for file-backed graph search and
causal-context queries, explicit
graph-slice export into local evidence-bundle storage, dry-run-first evidence-bundle retention
compaction, dry-run-first receipt compaction, dry-run-first receipt-protected flight-recorder
compaction, and endpoint-local agent-secret-touch queries over credential-access graph slices. The
same recorder now serves sidecar-indexed history replay/impact windows with timestamp, event-kind,
host, user, session, process, parent-process-guid, process-image-hash, process-command-line-hash, agent, workload, approval, tool, tool-call, credential-kind, event-target, and event-target-hash filters, and rebuilds missing, stale,
schema-old, or mismatched sidecar metadata from the JSONL source of truth. The remaining Phase 1
work is durable fleet upload semantics, automatic streaming import from all sensors, and more
scalable graph storage/query planning beyond sidecar indexes.

### Work

- Persist endpoint observations and graph nodes/edges locally.
- Add local APIs for process-subtree, session, tool, secret, and outbound-request queries. Initial
  bounded graph search now covers host, user, session, agent, workload, approval, exact path, path
  prefix, anchored path pattern, tool name, tool-call ID, process, tool, credential, file, network, DNS, and policy nodes with
  signed context slices and query-plan metadata backed by an in-process kind/attribute candidate
  index for transient graphs and durable graph-node prefilter plus graph-edge adjacency sidecars for
  file-backed flight recorders.
- Add bounded retention and graph compaction that preserves receipt references. Initial
  evidence-bundle, receipt, and flight-recorder retention compaction exist locally; indexed graph
  storage and fleet archival remain open.
- Add import paths from `PolicyEvent` JSONL and local agent EDR API submissions. Initial local API
  ingestion now accepts validated `PolicyEvent` JSON and JSONL submissions and emits endpoint
  observations, findings, and signed detection receipts; detection receipt validation now binds
  finding/observation/rule identity plus title, severity, confidence, graph slice, and process-node
  evidence to signed fields, derives the finding ID from the signed rule and observation IDs,
  rejects process-node references outside the receipt graph node set, and rejects graph-slice IDs
  inconsistent with the signed observation, process node, and graph counts.
  Streaming import remains open.
- Add graph-slice export for evidence bundles. Initial local API export now stores causal subgraph
  or causal-context slices as local evidence bundles with signed `graph_slice` receipts; receipt
  validation binds graph-slice/root/count evidence and rejects graph roots outside the receipt graph
  node set; local age/count retention compaction, self-checking local archive-package export, local
  archive package verification with artifact, graph-count, receipt-family, and
  receipt-to-content-hash binding, and privacy-bounded fleet archive metadata publication with
  disconnected local outbox queueing and a local/automatic retry drain path exist. The Control API
  remote archive store now supports
  authenticated upload, tenant-bounded retention, metadata reads, and archive download. The agent
  can upload verified raw archives from the local archive store during fleet-publish when Control
  API credentials and the local raw-artifact policy gate are present; failed raw uploads are now
  retried from a private bounded-backoff local ledger, and already-stored verified archives can be
  backfilled to Control API through a local authenticated route.

### Acceptance gates

- `show everything this process caused` works against persisted data.
- `what caused this network/file/tool node` returns bounded upstream context from persisted data.
- empty-process, missing-parent, duplicate-event, and out-of-order-event cases are covered.
- graph slice export includes validated stable IDs and evidence hashes.
- local API can return a graph without relying on process memory.

## Phase 2: macOS Sensor Integration

**Goal:** feed real privileged macOS provider observations into the local flight recorder.

**Initial NetworkExtension progress:** the Swift content-filter package now has a provider-side
egress policy primitive for exact host:port restrictions. It can distinguish active unexpired
matches from expired restrictions, produce block decisions for matching flow targets, expose an
`enforcement_ready` status bit, and project active/healthy provider state only when a synced
provider also has an enforcement engine loaded. The agent now writes active local `restrict_egress`
entries into a provider-loadable
`~/.config/clawdstrike/edr/network-extension-egress-policy.json` snapshot and clears that snapshot
on rollback, cancellation, and expiration. The NetworkExtension status helper and Rust collector can
now surface that the snapshot is decodable; enforcement-ready proof now also requires current
provider policy sync and enforcement readiness instead of treating the file alone as live
enforcement. The provider runtime now has a file-signature reload path that can refresh changed
snapshots before flow decisions plus a tested `reload_policy` command envelope that can accept a
watched policy path, increments `remediation_requests`, refreshes the watched snapshot, and returns
provider snapshot/counter evidence. The provider runtime now persists that provider-authored
snapshot to `network-extension-egress-policy.json.provider-runtime.json` by default, and
`network-extension-status-tool live` prefers that runtime snapshot before falling back to a
degraded policy-file-only readout. The same reload command has a tested
`NEFilterProviderConfiguration.vendorConfiguration` payload representation for the content-filter
control surface, and the status helper can persist that payload through `NEFilterManager`
preferences when an installed provider configuration is available. `restrict_egress` execution receipts
now bind the current NetworkExtension runtime, policy sync/readiness fields, policy epoch, and
reported flow/remediation counters plus the reload-request requested/saved/request-id/generation
outcome for the generated snapshot. The egress-policy proof can now accept an execution ID, compare
the provider-observed reload request ID, generation, and snapshot path against the signed
`response_execution` evidence, and emit signed delivery-match bits. Live `restrict_egress` fails
closed before persisting a restriction unless the NetworkExtension provider reports active runtime,
synced policy, and enforcement readiness. Provider not-ready refusals are recorded as failed
response executions with signed receipts. The missing
integration is deployed system-extension validation: prove the installed macOS provider reports the
same reload delivery path under dogfood conditions, block an actual flow, and return verified
flow/remediation counter increments into receipts. The live dogfood verifier now also requires the
summary to bind raw findings-request, action-request, action-response, proof-response,
blocked-flow, rollback, and post-rollback flow artifacts inside the run output directory, and
cross-checks summary fields plus host/user/session/agent/workload context against those raw
artifacts. The proof artifact must also carry provider runtime readiness, live flow-counter proof,
sensor-state, and sensor-state receipt metadata for `macos.network_extension`, while the raw
agent-health artifact must show installed, approved, active, healthy NetworkExtension provider
attestation.
The local NetworkExtension proof route now exposes a strict `liveEnforcementProven` verdict plus
hashed receipt evidence and failure reasons, so a snapshot-only or provider-ready-only state cannot
be mistaken for a deployed runtime enforcement proof.
The local API can now ingest delivered content-filter flow verdict events through
`POST /api/v1/agent/edr/network-extension/events` and convert each event into DNS lookup,
`network_flow`, and `policy_decision` observations for the flight recorder when provider DNS fields
are present, with recursive redaction for secret-bearing caller metadata and explicit process
command lines. Those NetworkExtension allow/block verdict observations now also emit dedicated
signed `policy_decision` receipts bound to the `macos.network_extension` sensor state.
It can also ingest delivered EndpointSecurity process-exec, file-access, and auth-open events
through `POST /api/v1/agent/edr/endpoint-security/events`, preserving process lineage, file
targets, auth decisions, deadline evidence, local identity context, sanitized provider metadata, and
redacted process command lines plus exec args. EndpointSecurity auth-open allow/block decisions now
emit dedicated signed `policy_decision` receipts bound to the `macos.endpoint_security` sensor
state.
Delivered EndpointSecurity event-loss/deadline/FDA facts on that route now record an observation and
return signed `provider_degradation` receipts, so dropped-event and deadline-miss evidence can block
false "fully enforced" claims at the local API boundary.
The EndpointSecurity live dogfood verifier now requires the generated summary to bind raw
health, causal-graph, observation-receipt, probe-activity, and protection-state artifact files
inside the run output directory, then cross-checks the embedded probe, provider, provider
attestation, and receipt matches against those files before a passing provider-delivery claim is
    accepted. The combined macOS provider dogfood gate also rejects deployment, ES, and NE summaries
that do not share the same host/user context, exact run ID, or bounded run window. A one-command
`scripts/macos-provider-live-dogfood.sh` wrapper now runs signed/notarized deployment evidence
collection, the ES harness, NE harness, combined gate, recursive hash-manifest generation, and
manifest self-verification under one QA-host output root with the same run ID passed through all
child artifacts, and it writes the provider manifest with explicit `evidenceMode=live`; its
manifest verifier rejects boolean/non-integer recursive inventory counts and selected-artifact byte
fields plus hidden manifest envelope, selected-artifact, inventory envelope, and inventory-file
fields before trusting the saved hash manifest; its
`--preflight` mode validates commands, child tools, numeric settings, target
syntax, generated run ID shape, output-root safety, empty-or-explicit-replace output semantics, and
the required signed `.app` bundle path before any provider collection or live containment side
effect, and its no-live `--self-test` mode regression-checks that preflight accepts valid argv/env
inputs without creating the output directory while rejecting missing bundles, loopback targets,
invalid skew, malformed boolean flags, and non-empty output roots unless replacement is explicit.
`scripts/test-macos-provider-dogfood-contract.sh` now groups that wrapper self-test with shell
syntax checks, Python compile checks, explicit live `evidenceMode` wiring checks, and all
ES/NE/deployment/gate/manifest verifier self-tests, plus
`scripts/endpoint-decision-engine-readiness-audit.py --self-test`. The readiness audit accepts
a macOS provider dogfood manifest, verifies the manifest/fresh-gate/provider bindings, maps that
evidence to the north-star checklist, requires the provider manifest and supplemental source
manifest to declare `evidenceMode=live` before production readiness can pass, and keeps the full
objective red when non-manifest evidence such as policy simulation, agent/developer-workstation,
deception, supply-chain, privacy, operator workflow, or wider sensor-breadth proof is absent. It
also accepts repeated strict
`--proof KEY=PATH` supplemental proof artifacts for those non-macOS checklist items, rejecting bare
proxy claims unless the proof binds the exact key, SHA-256/byte-bound artifacts, successful
SHA-256/byte-bound command-result artifacts, and key-specific evidence fields. Operators can now
discover that shape with `--proof-template KEY` or `--proof-template all`, then generate strict
proof JSON with `--write-proof KEY --proof-output PATH --proof-evidence PATH --proof-artifact PATH
--proof-command-result PATH`; the writer hashes the supplied artifacts and command-result JSON
files, writes the supplemental proof, and immediately runs the same proof validator used by the
audit. The policy-simulation proof contract now requires SHA-256-bound policy, event-stream,
impact-result, breakage-driver, and simulation-receipt hashes, current/proposed policy references,
the named impact engine, replayed event count, bounded recent-history window, audit-mode support,
staged-enforcement support, blocking-change count, breakage score, impact level, recommended stage,
and the `simulation` receipt family instead of accepting a naked changed-count proxy.
`scripts/policy-simulation-impact-proof.py` derives those fields from `clawdstrike policy impact
--json` output or a captured impact JSON artifact, requires the event count to match the replayed
JSONL stream, hashes the supporting artifacts, and delegates final proof generation to the
readiness-audit writer.
The AI-agent/developer-workstation proof contract now requires raw-secret omission evidence with a
SHA-256 binding, protected-surface coverage for MCP/browser/shell/package-manager/cloud-CLI plus
local API key, repo secret, CI token, and prompt-injected tool execution surfaces, secret-kind
coverage for local API keys, repo secrets, CI tokens, browser cookies, package-registry tokens, and
cloud credentials, identity-field coverage, collector-kind coverage, receipt-to-activity bindings,
and non-isolated causal graph activity nodes. `scripts/ai-agent-developer-workstation-proof.py`
derives those fields from structured local EDR coverage rows and rejects raw secret-like material,
unbound receipts, and graph gaps before delegating final proof generation to the readiness-audit
writer.
The endpoint-deception proof contract now requires materialization and detection receipt IDs, exact
`deception.honey_artifact_touched` rule identity, causal graph slice evidence, receipt bindings from
materialization to honey artifacts and detection to the materialization receipt, touched artifacts,
and graph slice, process-to-honey causal graph edges, SHA-256-bound
materialization/detection/causal-graph payloads, materialized and touched artifact counts, plus
file, SSH-key, browser-cookie, API-token, and hostname honey-kind coverage.
`scripts/endpoint-deception-proof.py` derives those fields from structured deception coverage rows
and rejects wrong-rule findings, unbound receipts, and graph gaps before delegating final proof
generation to the readiness-audit writer.
The supply-chain runtime-guard proof contract now requires npm/pip/Cargo manager coverage,
package-script, unsigned-binary, signature-drift, dynamic-library-injection, launch-persistence,
browser-extension, and developer-tool surfaces, the concrete `supply_chain.*` guard rule IDs,
positive observation and receipt counts, receipt-to-observation bindings, non-isolated graph nodes
for every observation, and SHA-256-bound package-script, signature/drift, persistence,
browser-extension, developer-tool, and graph evidence slices.
`scripts/supply-chain-runtime-guard-proof.py` derives those fields from structured supply-chain
coverage rows and rejects missing managers, surfaces, rule IDs, unbound receipts, isolated graph
observations, or graph evidence before delegating final proof generation to the readiness-audit
writer.
The privacy-preserving telemetry proof contract now requires a non-raw default projection, default
raw-artifact suppression, unapproved raw-request downgrade evidence, policy-plus-approval-gated raw
artifact upload, matching approval ID and reason hash, signed `privacy_report` receipt evidence
that binds the report ID, approval ID, approval reason hash, and raw-upload permission,
SHA-256-bound report/policy/downgrade/approved-raw/receipt artifacts, required projection classes,
positive count evidence, and raw values only in the approved report.
`scripts/privacy-preserving-telemetry-proof.py` derives those fields from privacy-report response
artifacts and rejects default raw leakage, missing approvals, missing approved raw artifacts, or
wrong or unbound receipt evidence before delegating final proof generation to the readiness-audit
writer.
The operator-workflow proof contract now requires concrete workflow dogfood rather than names:
process-cause, policy replay, rule impact, local containment, agent secret touches, causal grouping,
proof-at-execution, privacy report, and detection-staging workflows must all map to the local EDR
API routes, include simulation/response/sensor/privacy receipt-family coverage, prove verified runs
within the 10-second north-star latency bound, prove local decisions and containment survive
cloud/NATS unavailability, export an operator proof package, bind the run/export/proof artifacts
with SHA-256 hashes, preserve bounded containment TTL plus rollback evidence, prove isolate-network,
suspend-process-tree, revoke-token, quarantine-file, block-persistence, rollback-config, and
collect-evidence response actions with per-action TTL, rollback, and receipt evidence that binds
policy, sensor state, actor, process tree, evidence, confidence, and action, and prove staged
detection generation.
`scripts/operator-workflows-proof.py` derives those fields from operator workflow dogfood/export
artifacts and rejects missing workflows, unverified runs, missing rollback, missing controlled
response action coverage, unreceipted response actions, weak response receipt bindings,
cloud-dependent local-first claims, over-latency workflow runs, missing staged detection, or
unverified exports before delegating final proof generation to the readiness-audit writer.
The cross-platform sensor-breadth proof contract now requires sensor inventory rather than a broad
coverage assertion: process, file, network, DNS, persistence, identity, browser, package-manager,
and secrets modules must span macOS, Linux, and Windows, map to required local EDR ingestion
routes, include required event kinds and host/user/session/agent/workload/approval identity fields,
including separate file-write, shell-command, tool-call, and policy-decision event coverage, bind
sensor/event/route coverage with SHA-256 hashes, and prove redaction plus graph persistence with
required causal node/edge kinds and upstream/downstream/process-tree query coverage.
`scripts/cross-platform-sensor-breadth-proof.py` derives those fields from structured coverage
artifacts and rejects missing sensors, platforms, routes, event kinds, identity fields, redaction
evidence, missing causal graph node/edge coverage, or graph persistence before delegating final
proof generation to the readiness-audit writer.
`scripts/endpoint-decision-engine-qualification-bundle.py` now enforces the final QA evidence
handoff as one bundle: it discovers the macOS provider manifest and all strict supplemental proof
files, runs the readiness audit, writes the persisted self-hashed audit, and immediately
re-verifies that persisted audit against the recorded source manifest/proofs. By default, it
requires the manifest, proof roots, explicit proof files, supplemental source manifest, staged
source artifacts, and persisted audit output to remain inside `--bundle-dir`;
`--allow-external-evidence` and `--allow-external-output` are explicit escape hatches for externally
staged evidence or audit output. The qualification summary reports external evidence/output paths
when those escape hatches are used, and the verifier refuses to write the persisted audit over the
manifest, a proof artifact, or the supplemental source manifest. The verifier also accepts bounded
machine-safe `--metadata KEY=VALUE` annotations: at most 16 entries, 64-byte keys, 512-byte values,
key characters limited to letters, digits, `_`, `.`, and `-`, no empty values, no control
characters, and no duplicate keys. The live QA-host driver records its driver name, target,
provider/proof replacement opt-ins, and supplemental-source configuration in the qualification
summary. That summary now carries `qualificationSummarySha256`, and `--verify-summary PATH`
rechecks the summary digest plus the referenced persisted readiness audit. The verifier also
cross-checks summary audit hash, counts, failed/unresolved/missing keys, persisted-verification
flags and payload, external evidence/output opt-in flags, bundle directory, manifest path, proof
paths, source-manifest `verified`, `evidenceMode`, and metadata, and external evidence/output
disclosures against the audit payload and live source manifest while rejecting hidden
qualification-summary and supplemental-source-summary fields plus boolean summary/source-manifest
`schemaVersion`, boolean/non-integer summary counts, and supplemental-source summary count/verified
coercions.
Qualification
metadata, external trust-boundary opt-ins, and the qualification bundle directory are also
persisted into the audit provenance, so rehashed summary metadata, source verification/evidence-mode
drift, external flag drift, or bundle-boundary drift fails verification.
Its self-test proves
complete fixture-bundle replayability while keeping production readiness failed because
`evidenceMode=fixture` is not live evidence, plus summary mutation rejection, hash-rebound summary
drift rejection, boolean summary-count and source-manifest verified/count rejection,
summary-underlying-audit drift rejection, persisted-verification payload drift, source
verification/evidence-mode drift, external trust-boundary flag drift, hidden
summary/metadata/disclosure rejection, bundle-boundary drift rejection,
missing-source-manifest rejection, missing bridge-script record rejection, missing-proof rejection,
duplicate-proof rejection, staged supplemental-source mutation rejection, metadata reporting,
invalid-metadata rejection, output-overwrite rejection, and external opt-in behavior.
The self-test proves every template satisfies the evidence validator, mutates a supplemental
artifact after proof generation, rejects hidden proof envelope/evidence/artifact/command fields and
boolean integer-like proof command values, and requires the audit to fail. Audit output includes an
`auditSha256`, can be persisted with `--output`, and can later be checked with `--verify-audit`;
persisted audits reject hidden audit envelope, provenance, checklist, manifest-verification, and
supplemental-source provenance fields, boolean audit/proof/source-manifest `schemaVersion`,
boolean/non-integer audit counts, manifest-verification counters, checklist evidence/gap rows, and
supplemental-source provenance counts, retain source provenance, and `--verify-audit` re-runs the recorded manifest, proof,
and supplemental source-manifest checks so later provider, proof, staged-source, topology, verified
status, invalid byte-size schema, unsupported source-manifest fields, or bridge-script drift fails the audit; generated-proof,
source-artifact, and bridge-script counts plus proofRoot/sourceRoot topology in that provenance are
also cross-checked against the live source manifest, each bridge key must point at its expected bridge script, generated-proof records
must match the proof paths being qualified, and source artifact records must live under the declared
sourceRoot unless qualification provenance explicitly discloses the exact external staged source
artifact map. The source manifest policy metadata must
also carry non-empty current/proposed refs, a `sha256:<64-hex>` proposed policy hash, and a positive
policy epoch; when the proposed ref resolves to a local file, the recorded proposed hash must match
that file. A direct readiness audit with every supplemental proof now also requires
`--supplemental-source-manifest PATH`; otherwise the prove-later criterion stays failed and the
persisted audit verifier rejects the complete proof set as lacking source provenance.
`scripts/endpoint-decision-engine-live-qualification.sh`
now provides the full QA-host driver: it preflights the signed app, external target, script
permissions, and proof-root layout, enforces non-overlapping provider/proof/output paths inside the
bundle, creates runtime output parent directories only after preflight, runs the deployed macOS
provider dogfood into `macos-provider/`, and then invokes the qualification-bundle verifier over
the resulting manifest plus staged supplemental proofs. Stale macOS provider evidence under
`macos-provider/` fails preflight unless `CLAWDSTRIKE_EDE_MACOS_PROVIDER_REPLACE_OUTPUT=1` is set;
that opt-in is passed through to the lower-level macOS provider wrapper without making preflight
delete anything. If every `CLAWDSTRIKE_EDE_*` source artifact variable is supplied, the driver
also preflights and runs `scripts/endpoint-decision-engine-supplemental-proof-bundle.py` to build
that proof root with explicit `evidenceMode=live` before live provider dogfood. It keeps missing
supplemental proofs red rather than fabricating them. The supplemental proof bundle builder
validates source artifact readability and
output path safety in `--preflight`, dry-runs the same strict bridge pipeline in a temporary
directory, then builds the proof root from explicit policy-impact,
AI-agent, deception, supply-chain, privacy, operator-workflow, and sensor-breadth coverage artifacts
by staging those inputs under `source-artifacts/`, writing
`supplemental-proof-source-manifest.json` with `evidenceMode=live`, SHA-256/size records for staged
inputs and bridge scripts, omitting unverified origin `sourcePath` metadata, running every strict
proof bridge, and rejecting missing or duplicate generated proof keys.
It now refuses a non-empty proof root unless `--replace-output` is explicit; the QA-host wrapper
maps that to `CLAWDSTRIKE_EDE_SUPPLEMENTAL_PROOF_REPLACE_OUTPUT=1`, keeping stale generated proof
artifacts from contaminating a live qualification run. The live driver preserves the qualification
verifier exit code and logs the summary plus persisted audit
paths on failure, so a red readiness audit stops the QA-host run without hiding the evidence file
needed for triage. The local
platform/changed-file gates call the
contract helper for relevant script changes. Manifest verification also reruns the
combined deployment/ES/NE gate fresh against the bundled summaries and rejects saved gate results
whose selected artifact paths escape the run root, that do not name the manifest-selected summaries,
that do not carry ES/NE provider-health bindings, that do not match manifest run/target metadata,
that do not match the fresh gate's portable decision projection, that carry hidden top-level,
provider-binding, provider-health, or embedded verifier-output fields, whose saved gate counters
or provider-health flags use bool/int coercions, whose embedded verifier `verified` fields are not
booleans, whose deployment extension-point bindings contain non-string entries, whose manifest uses
boolean `schemaVersion`, or whose manifest lacks a non-empty absolute recorded `runRoot`. Deployment
evidence must bind the expected Team ID, exact app bundle ID, combined system-extension bundle ID,
activated/enabled
`systemextensionsctl` state, strict app, deep app-bundle, and embedded-system-extension
code-signature verification, required app/system-extension entitlements, embedded provider path,
stapled notarization validation, app/extension plist identity, and both EndpointSecurity plus
NetworkExtension extension points.
The local protection-state route also reports installed provider recovery transitions from the
previous degraded macOS snapshot to the current healthy snapshot and signs recovery count/provider
IDs into the `sensor_state` receipt.

### Work

- Prove the running content-filter provider observes the persisted reload command, reloads the local
  `network-extension-egress-policy.json` snapshot, and reflects verified counters back into receipts.
- Carry provider installed, active, healthy, degraded, recovered, deadline-miss, dropped-event, and
  Full Disk Access state through local decision receipts and provider-degradation receipts.
- Keep Darwin bridge Spine emission for cloud/stream projection, but make the local decision loop
  independent of NATS availability.
- Add deployed provider-inactive/recovery fixtures beyond the local synthetic event-loss API
  regression.

### Acceptance gates

- allow and deny fixtures for the frozen ES contract.
- NE unavailable state produces degraded receipt evidence.
- content-filter provider can block a local response restriction through its live policy channel and
  report `enforcement_ready`.
- deadline miss and dropped-event paths prevent false "enforced" claims in both the local API and
  deployed provider loops.
- local decisions still work without cloud/NATS connectivity.

## Phase 3: Graph-Aware Policy Simulation

**Goal:** answer "what would break if we blocked this?" using recent endpoint history.

**Initial progress:** the local agent now supports a graph-aware `policy-simulation` route. It
requires a persisted causal graph target, scores the affected downstream graph slice for developer
breakage, returns affected process/file/network/tool/credential counts, and emits a signed
simulation receipt. Graph-simulation receipt validation now derives the graph-policy simulation ID
from the signed root, graph slice, rule, action, and breakage score, rejects graph roots outside the
receipt graph node set, and rejects graph-slice IDs that do not match the root plus graph counts.
Simulation rule, report, affected-node, identity-context, and tool-context metadata now reject
unknown fields before those values feed breakage scoring or signed simulation receipts.
The local `policy-replay` route now covers a bounded "replay this incident under
today's policy" workflow by resolving a captured graph target, binding the replay to the current
local policy version/hash/epoch, returning graph-impact scoring, and emitting the same signed
simulation receipt family. The local `policy-events/replay` and `policy-events/replay/jsonl` routes
now replay supplied `PolicyEvent` JSON or JSONL against the current local policy without recording
observations, return per-event allow/warn/block decisions, and sign the event-stream hash plus
result hash as simulation receipts. Replay receipt validation now also binds the stream graph slice
reference to the signed replay ID, requires the stream node to remain `policy_event_stream`, and
requires that pseudo-node to be present in the receipt graph node set. It derives replay IDs from
signed current-policy, stream/result/count, and posture evidence, and rejects non-boolean
`trackPosture` evidence hashes.
The local `policy-events/impact` route now compares supplied
`PolicyEvent` records between the current local policy and a proposed policy YAML payload, returns
per-event changed verdicts plus allow/warn/block transition counts, and signs the current/proposed
result hashes plus allow-to-block count as a simulation receipt. Impact receipt validation binds the
stream graph slice reference to the signed impact ID and requires the stream node to remain
`policy_event_stream` and present in the receipt graph node set. It derives impact IDs from signed
current/proposed policy, stream/result/impact/count, and posture evidence, and rejects non-boolean
`trackPosture` evidence hashes. The impact response now also
includes driver summaries that aggregate changed events by transition, current/proposed guard,
current/proposed reason code, and sample event IDs. The local
`policy-events/replay/history` and `policy-events/impact/history` routes now run those replay and
impact workflows against durable flight-recorder history by projecting selected endpoint
observations into `PolicyEvent` candidates under sidecar-indexed
time-window/age/limit/event-kind plus identity/parent-process-guid/process-image-hash/process-command-line-hash/tool/tool-call/credential-kind/event-target/event-target-hash selection that seeks only selected JSONL records.
History impact responses now also join changed verdicts back to bounded causal graph contexts, with
node-kind counts, affected identity/tool counts and summaries, blocking-change count,
developer-breakage score, impact level, top breakage drivers with workflow categories, ordered
root-to-target chains, local graph slices, and a signed `graph_slice` receipt over the union
causal-impact slice for the affected event chains. With optional `validationWindowSeconds`, they
also partition the selected history into populated validation windows and report per-window event,
changed-verdict, and blocking-change counts plus a conservative rollout recommendation, promotion
readiness flag, deterministic summary/recommendation hashes, and reason that feeds the generated
staged-detection request payloads together with the cross-window proof hashes, which the local
staged-detection ledger preserves for later policy-delta promotion. Generated policy-delta
artifacts, generated patches, policy-delta receipt evidence, dry-run/live apply response records,
and post-apply enforcement proofs now preserve those hashes across the
simulation-to-staging-to-policy-delta proof chain. They also return
chain-driver summaries that group repeated changed root-to-target chains by edge sequence, target
kind, verdict transition, guard/reason delta, and proposed endpoint action, plus audit-stage
promotion suggestions with request payloads for the existing `detection-candidate` and
`staged-detections` endpoints, without mutating staged-detection state. The local
`detection-candidate` route now generates a candidate rule from a persisted graph root, simulates
it, and returns staged rollout guidance for observe, audit, warn, limited block, and full block. The
local
`staged-detections` route now persists the selected stage, policy snapshot, simulation report, and
signed simulation receipt in a JSONL staged-detection ledger. The local `policy-deltas` route now
promotes a staged detection into a versioned endpoint policy overlay artifact and signs a
`policy_delta` receipt over the artifact hash, staged source, action, generation time, and graph
target. Validation derives the delta ID from those signed fields and rejects graph-slice evidence
mismatches plus root-node membership failures; it also binds generated/applied operation evidence,
rejects apply evidence on generated receipts, and requires previous/new policy plus backup evidence
on applied receipts. Live policy-bundle application has
started: the local apply route can dry-run and merge a generated overlay into the configured policy
file only when the base policy hash still matches, rejects stale target epochs so drift-tolerant
applies cannot downgrade a newer local policy, writes a backup, advances the policy epoch, signs a
`policy_delta` apply receipt, and emits a post-apply protection-state proof with daemon status,
sensor state, degraded-provider receipts, and a signed `sensor_state` receipt. It now requests
`hushd` `/api/v1/policy/reload` by default after real applies and records the reload result, sends a
NetworkExtension provider `reload_policy` command for the changed local policy path when post-apply
provider verification is enabled, binds that requested/saved/request-id/generation/path proof into
the post-apply `sensor_state` receipt, asks the macOS status collector for a direct provider-status
refresh, waits briefly for ES/NE provider status readouts to report the new policy epoch, and can
request a managed daemon restart with `restartDaemon: true`. Control Console now exposes the
candidate, staging, policy-delta generation,
dry-run apply, dry-run-gated live apply, validation-window proof hashes, post-apply proof family,
policy-sync status, aggregate provider acknowledgement, and per-provider acknowledgement state in a
`Rule Impact` operator tool. Pending Control API policy proposals can now retain verified signed
endpoint policy-event impact receipts from this path, including the computed canonical
signed-receipt hash, endpoint-decision metadata, and multi-endpoint receipt batches for fleet
impact evidence. Proposal previews now generate endpoint selection and request plans for fleet
rule-diff validation, and Control API can dispatch those plans as response actions and collect
acknowledged signed endpoint impact receipts into proposal impact evidence. The enrolled agent now
has a canonical response-action command subscriber for `policy_rule_diff_validation` that verifies
the signed envelope, binds the command tenant to the enrolled NATS tenant, rejects expired or
non-acknowledgement-enabled commands, constrains execution to its own endpoint ID and the local
impact-history route, and posts the rule-diff acknowledgement payload back to Control API. Agent-side
regression coverage now exercises the loopback impact-history POST and bearerless Control API
`agent-acks` postback boundary without requiring a live NATS server.
Postback failures from that response-command path now enqueue the completed acknowledgement payload
into the existing private bounded-backoff Control API acknowledgement retry ledger instead of only
logging the failure, and the enrolled agent drains due queued acknowledgement postbacks through the
same scheduled retry loop used by the authenticated local retry route.
A gated live dogfood test now covers that same response-command subscription with operator-provided
NATS credentials:
`cargo test --manifest-path apps/agent/src-tauri/Cargo.toml live_nats_response_action_command_executes_and_acknowledges -- --ignored --nocapture`.
It requires `CLAWDSTRIKE_LIVE_NATS_URL`, `CLAWDSTRIKE_LIVE_NATS_TENANT_ID`,
`CLAWDSTRIKE_LIVE_NATS_AGENT_ID`, `CLAWDSTRIKE_LIVE_NATS_SUBJECT_PREFIX`, and one supported NATS
auth input. Provider-process reload commands and an executed live multi-endpoint NATS dogfood run
remain open.

### Work

- Extend policy impact analysis from event diffs to causal chains.
- Add blast-radius scoring for developer workflows: package installs, repo commands, cloud CLIs,
  MCP calls, browser automation, and brokered egress.
- Generate candidate rules that stop a causal threat path with minimum breakage.
- Replay captured incident graph slices under the current policy snapshot before promotion.
- Replay supplied `PolicyEvent` JSON/JSONL streams under the current policy without recording them.
- Compare supplied `PolicyEvent` streams between current and proposed policy before promotion.
- Add staged rollout states: observe, audit, warn, limited block, full block.
- Emit signed simulation receipts.
- Bind graph-simulation receipt evidence for simulation ID, root, graph slice, would-block result,
  developer breakage score, impact level, affected graph counts, and graph content hash; derive
  graph-policy simulation IDs from signed root/graph/rule/action/score fields, reject graph roots
  outside the receipt graph node set, and reject graph-slice IDs inconsistent with root/counts.
- Derive policy-event replay and impact IDs from signed policy, stream/result/count, and posture
  evidence so replay/impact simulation receipts cannot be consistently relabeled.
- Emit signed policy-delta receipts for generated staged overlays; derive policy-delta IDs from
  signed endpoint/rule/action/staged-source/generated-at/simulation/graph fields and enforce the
  generated-versus-applied evidence contract.
- Emit signed post-apply protection-state proof, daemon reload results, NetworkExtension provider
  reload command proof, direct status-collector refresh results, and bounded provider policy-epoch
  acknowledgement polling after local policy-delta application.
- Apply generated overlays to the local policy bundle with base-hash guard, backup, and signed
  receipt.

### Acceptance gates

- persisted graph simulation for a proposed blocking rule returns affected graph, breakage score,
  impact level, and signed receipt.
- Given an incident graph slice, the simulator generates a candidate blocking rule and staged rollout
  recommendation.
- Given an incident graph slice, the replay route binds the current policy version/hash/epoch to a
  signed simulation receipt.
- Given a `PolicyEvent` stream, the replay route returns per-event decisions and signs the
  event/result hashes under the current policy snapshot.
- Given a proposed policy YAML and `PolicyEvent` stream, the impact route returns changed verdicts,
  allow-to-block counts, and a signed impact receipt.
- Simulation output includes changed verdict count, blocking-change count, developer-breakage score,
  impact level, local selected-window rule-diff summaries with rollout recommendations, affected
  identity/tool counts and summaries, top breakage drivers with workflow categories, and affected
  causal chains.
- Staged enforcement can be represented in policy metadata, local overlay artifacts, local policy
  application records, and receipts.
- Tests cover allow-to-block, warn-to-block, and block-to-allow regressions across graph paths.

## Phase 4: Developer Workstation And AI-Agent Sensor Pack

**Goal:** make the first wedge concrete before broad EDR parity claims.

### Work

- Add collectors/mappers for MCP calls, browser automation, shell agents, package-manager scripts,
  cloud CLIs, repo secrets, CI tokens, and brokered egress. The first dedicated package-manager
  lifecycle mapper now exists as a local agent API route, and adapter-core ships a best-effort
  npm/pnpm/yarn/Bun lifecycle hook that reads package-manager environment and posts redacted
  `package_script` events into it. The same hook accepts explicit
  pip/Cargo/RubyGems/Go/Homebrew/Composer/Maven/Gradle/uv/Poetry/Pipenv/.NET/NuGet/SwiftPM/Mix
  lifecycle metadata via `CLAWDSTRIKE_PACKAGE_*` environment for wrappers and build scripts;
  native automatic hooks for broader package-manager ecosystems and fleet correlation remain.
  Adapter-core now also exposes a repo-scanner
  and the shared shell classifiers cover Composer/Maven/Gradle/uv/Poetry/Pipenv/.NET/NuGet/SwiftPM/Mix
  package-manager command forms, with the local package-manager event schema accepting those extended
  manager values.
  credential-finding publisher and bounded local repository scanner that map discovered credential
  paths into raw-value-omitting developer-activity facts. A CI-agent environment publisher maps
  GitHub Actions, GitLab CI, Buildkite, CircleCI, Azure Pipelines, Bitbucket Pipelines, Jenkins,
  TeamCity, Travis CI, Drone CI, Semaphore CI, AppVeyor, Woodpecker CI, and Codefresh token
  variable names plus run/job/repository context into `ci_token`
  developer-activity facts without sending token values; the same publisher
  is packaged as `clawdstrike-ci-env` for CI job wrappers. Adapter-core now also exposes a
  browser-runtime publisher that maps browser automation actions, downloads, and extension installs
  into developer-activity facts with parameters and URLs scrubbed and raw prompt, page, result, and
  artifact bodies omitted, and can infer common browser identity from profile or extension paths
  when collectors omit the browser field while preserving optional download content hashes and byte
  counts through local agent observation, graph, and privacy-projection storage. The same
  adapter-core EDR enrichment path now maps translated CUA
  `PolicyEvent`s from shared Claude/OpenAI-style tool boundaries into scrubbed `browser_automation`
  facts automatically, and the shared CUA translators preserve bounded browser, path, source URL,
  and size metadata for file-transfer downloads so they can become `browser_download` facts.
  Standard ClawdStrike honey artifact paths touched through shell or file-tool boundaries now carry
  deception metadata into the credential-access developer-activity feed, allowing the local honey
  registry to fire `deception.honey_artifact_touched` without uploading file contents.
  Shell-agent network utilities that target hostnames now also emit `dns_lookup` developer activity
  with secret-bearing URLs redacted and planted internal-hostname hints for deception correlation.
- Feed existing supply-chain runtime guard rules with sensor-backed evidence for package scripts,
  unsigned/signature-drifted binaries, dynamic library injection, launch persistence, browser
  extensions, developer credentials, and cloud CLI activity. The pure guard now detects sensitive
  cloud CLI secret/token/IAM/key operations from process-exec observations, including GitHub CLI
  secret/auth/variable operations, Vercel env operations, Netlify env operations, Cloudflare
  Wrangler secret operations, DigitalOcean doctl registry/kube credential operations, and Fly
  secrets/token operations, plus 1Password `op`, Bitwarden `bw`, HashiCorp Vault, Doppler, Heroku, Supabase,
  Firebase Functions Secrets, Railway variables, Stripe CLI API-key and webhook-signing-secret commands, Sentry/Snyk auth tokens, AWS/GCP/Azure credential and kubeconfig operations, Kubernetes `kubectl`, Pulumi secret/config operations, Terraform/Terragrunt/OpenTofu state/output/login operations, CircleCI context secret / runner-token
  operations, GitLab `glab` CI/CD variable operations, Buildkite `buildkite-agent`/`bk`
  secret operations, and Drone/Semaphore/AppVeyor/Woodpecker/Codefresh CI secret or token
  operations; broader collector-specific coverage is
  still needed.
- Bind tool calls and brokered egress to user, session, agent, approval, and policy epoch.
- Add honey artifacts for SSH keys, API token files, package registry tokens, browser cookies,
  cloud credentials, and internal hostnames.

**Initial deception progress:** materialized deception plans are now registered in a local honey
artifact registry and reused by `/api/v1/agent/edr/findings`, so honey touches can be detected after
materialization without resubmitting the original plan. The local model/API path now detects honey
file touches, network flows and DNS lookups to planted internal hostnames, and browser-cookie
credential observations that carry planted honey values. Delivered EndpointSecurity file-access
events and NetworkExtension DNS/network-flow events now reuse that registered honey registry too, so
sensor-ingested honey touches can fire `deception.honey_artifact_touched` without resubmitting the
plan artifacts. Materialization now also emits a signed `deception_materialization` receipt binding
the plan hash, report hash, artifact counts, and registered artifact count; validation binds endpoint
evidence to the signed actor, derives the materialization ID from endpoint, policy hash, plan-root
evidence, plan-hash evidence, report-hash evidence, count evidence, and artifact-ID evidence, and
requires the plan/report/count/artifact-ID evidence fields.
Honey-artifact, deception-plan, materialization-report, cleanup-report, rotation-report,
detection-finding, detection-evidence, and supply-chain guard metadata now reject unknown fields
before those values can drive honey registration, finding generation, or deception receipts.
The local API now also supports
dry-run-first cleanup that removes only registered exact-match honey files, deregisters removed or
already-missing artifacts, refuses unsafe or mismatched targets, and emits a signed
`deception_cleanup` receipt; validation binds endpoint evidence to the signed actor, derives the
cleanup ID from endpoint, policy hash, plan-root evidence, plan-hash evidence, cleanup-report
evidence, dry-run evidence, cleanup-count evidence, and registry-count evidence, requires
plan/report/count/registry evidence, binds `dryRun` evidence to the signed cleanup title, and
checks refused-target count evidence against the signed pass state. It now also supports
dry-run-first rotation that preflights old-artifact cleanup,
removes and deregisters the old plan, materializes and registers the new plan, and emits a signed
`deception_rotation` receipt binding old/new plan hashes plus cleanup, materialization, and final
registry counts; validation binds endpoint evidence to the signed actor, derives the rotation ID
from endpoint, policy hash, old/new plan-root evidence, old/new plan-hash evidence, rotation-report
evidence, dry-run evidence, cleanup-count evidence, materialization-count evidence, and
registry-count evidence, requires old/new plan, rotation report, count, and registry evidence, binds
`dryRun` evidence to the signed rotation title, and checks cleanup refused-target count evidence
against the signed pass state.
Sensor-backed automatic monitoring for those observations remains future work.

**Initial AI-agent query progress:** `/api/v1/agent/edr/agent-secret-touches` now returns
endpoint-local credential-access graph slices causally linked to agent/tool activity, with optional
session and credential-kind filters and signed graph-slice receipts. `PolicyEvent::SecretAccess`
conversion now classifies common secret scopes and names into typed endpoint credentials, including
API tokens, package-registry tokens, cloud credentials, SSH keys, signing keys, and browser cookies.
The local API can also ingest validated `PolicyEvent` JSON and JSONL submissions and run them
through the same observation, flight-recorder, detection, and receipt path after redacting
secret-bearing converted metadata, process command lines, sensitive header command fragments, URL
and CLI userinfo credentials, query credentials, JSON-like secret fields, secret-bearing
environment values, policy-decision targets, file content previews, and exec args. Direct endpoint-observation ingestion
preserves local-only content-preview honey-marker detection while stripping previews from durable
recorder, graph, receipt, and response surfaces, and specialized converted ingress routes now run
the same final observation scrubber before response, recorder, graph, and receipt use. The local agent also has
`/api/v1/agent/edr/developer-activity`, which gives developer and agent collectors a first-class
local ingress for MCP tools, browser automation/download/extension events, DNS lookups, package
scripts, cloud CLI commands, shell commands, repo secrets, CI tokens, local API keys, and browser
cookies before mapping those facts into the same observation, flight-recorder, detection, receipt,
and graph query paths while preserving supplied host, user, session, agent, workload, approval,
tool-call, and policy metadata after recursive secret-bearing metadata redaction. The local agent also has
`/api/v1/agent/edr/package-manager/events`, which accepts package-manager lifecycle
manager/package/phase/script records and emits `package_script` observations, supply-chain
install-script findings, signed receipts, and causal graph nodes through the same local path after
redacting secret-bearing script, process-command, and caller-metadata tokens.
Adapter-core now ships `clawdstrike-package-lifecycle`, a best-effort npm/pnpm/yarn/Bun lifecycle hook
that reads `npm_lifecycle_event`, redacts `npm_lifecycle_script`, preserves package and working
directory context, and posts to that dedicated endpoint without failing dependency installation. The
hook also accepts explicit
pip/Cargo/RubyGems/Go/Homebrew/Composer/Maven/Gradle/uv/Poetry/Pipenv/.NET/NuGet/SwiftPM/Mix
lifecycle metadata through `CLAWDSTRIKE_PACKAGE_MANAGER`,
`CLAWDSTRIKE_PACKAGE_PHASE`, `CLAWDSTRIKE_PACKAGE_SCRIPT`, `CLAWDSTRIKE_PACKAGE_NAME`, and
`CLAWDSTRIKE_PACKAGE_WORKING_DIR` so wrappers and build scripts can feed the same local route. The
adapter-core local EDR helpers also expose `publishRepoScannerCredentialFindingToLocalEdr()`, which
lets repo scanners submit credential-path findings as normalized developer-activity facts with
path, rule, confidence, repository, and identity metadata while omitting raw secret values. The
bounded `scanRepositoryCredentialPathsForLocalEdr()` helper walks local repositories, skips common
dependency/build directories, and publishes credential-looking path findings without reading file
contents. `publishCiAgentEnvironmentToLocalEdr()` captures common CI provider context and token
variable names as raw-value-omitting `ci_token` facts for GitHub Actions, GitLab CI, Buildkite,
CircleCI, Azure Pipelines, Bitbucket Pipelines, Jenkins, TeamCity, Travis CI, Drone CI,
Semaphore CI, AppVeyor, Woodpecker CI, and Codefresh, and the package
exposes `clawdstrike-ci-env` as the job-wrapper executable.
`publishBrowserRuntimeActivityToLocalEdr()` maps browser automation, download, and extension-install
facts into the same local developer-activity ingress without raw prompt/page/result/artifact bodies.
Translated CUA `PolicyEvent`s flowing through adapter-core are also promoted into scrubbed
`browser_automation` developer-activity facts for shared Claude/OpenAI-style tool boundaries.
File-transfer download CUA events now preserve bounded browser/path/source URL/size metadata for
`browser_download` enrichment while still relying on local EDR scrubbing before submission, and
profile or extension paths can supply browser identity when collectors omit it; content hashes and
byte counts are preserved when translators provide them.
The OpenClaw general tool-preflight hook now feeds its canonical file, command, patch,
network, and tool policy events into the `PolicyEvent` ingestion path when the local agent token is
available, and emits package-manager lifecycle commands, package-registry token commands, plus
sensitive cloud/developer-platform CLI commands for the current first-pass CLI set, including
GitHub CLI secret/auth/variable operations,
Vercel env operations, Netlify env operations, Cloudflare Wrangler secret operations, DigitalOcean
doctl registry/kube credential operations, Fly secrets/token operations, 1Password `op`, Bitwarden `bw`, HashiCorp
Vault, Doppler, Heroku, Supabase, Firebase Functions Secrets, Railway variables, Stripe CLI API-key and webhook-signing-secret commands, Sentry/Snyk auth tokens, AWS/GCP/Azure credential and kubeconfig operations, Kubernetes `kubectl`, Pulumi secret/config operations, Terraform/Terragrunt/OpenTofu state/output/login operations, CircleCI
context secret / runner-token operations, GitLab `glab` CI/CD variable operations, Buildkite
`buildkite-agent`/`bk` secret operations, and Drone/Semaphore/AppVeyor/Woodpecker/Codefresh CI
secret or token operations, as
normalized developer-activity facts with supplied host/user/session/agent/workload/approval
identity bound into the posted EDR payloads. The shared `@clawdstrike/adapter-core`
`BaseToolInterceptor`
can now explicitly opt in to local EDR publishing, adding scrubbed pre-execution decision telemetry
and custom post-execution result telemetry with raw input/output omitted for wrappers built on the
shared boundary, including modern LangChain wrappers that pass adapter config through
`secureTool`/`secureTools`, and emits classified package-manager lifecycle commands,
package-registry token commands including Docker registry login, pip index credential config
reads, Cargo registry auth commands, and RubyGems registry auth commands, plus sensitive cloud-CLI commands, including GitHub CLI
secret/auth/variable operations, Vercel env operations,
Netlify env operations, Cloudflare Wrangler secret operations, DigitalOcean doctl registry/kube
credential operations, Fly secrets/token operations, 1Password `op`, Bitwarden `bw`, HashiCorp Vault, Doppler,
Heroku, Supabase, Firebase Functions Secrets, Railway variables, Stripe CLI API-key and webhook-signing-secret commands, Sentry/Snyk auth tokens, AWS/GCP/Azure credential and kubeconfig operations, Kubernetes `kubectl`, Pulumi secret/config operations, Terraform/Terragrunt/OpenTofu state/output/login operations, CircleCI context secret /
runner-token operations, GitLab `glab` CI/CD variable operations, Buildkite
`buildkite-agent`/`bk` secret operations, and Drone/Semaphore/AppVeyor/Woodpecker/Codefresh CI
secret or token operations, as normalized
developer-activity facts. It also emits generic `tool_call` policy
events as scrubbed `mcp_tool` facts, classifies shell commands that read credential-looking
repo-secret, CI-token, local-API-key, or browser-cookie paths plus macOS Keychain, local password-store, SSH-agent
key enumeration, Git credential-helper reads, and Docker registry credential reads into normalized developer-activity
facts, maps direct Cargo/RubyGems registry credential file reads plus
Yarn/pnpm/pip/Poetry/Maven/Gradle/NuGet credential-store reads, GitHub/GitLab developer CLI
token-store reads, kubeconfig/Terraform/Pulumi cloud credential-store reads, SOPS/age and GnuPG
signing/decryption key-store reads, and file-read/file-write `PolicyEvent`s for those paths into the same
credential-access feed, adds deception metadata for ClawdStrike-specific standard honey artifact
paths so registered honey files can produce local deception detections, maps translated
`secret_access` events into the same feed, maps agent-driven `launchctl`, `crontab`, and
`systemctl` persistence operations plus direct LaunchAgent/LaunchDaemon plist writes and
shell-startup file writes into raw-content-omitting `persistence_change` developer-activity facts,
maps direct `network_egress` policy events into redacted protocol/host/port/method/URL-path network
developer-activity facts with request bodies omitted,
maps ordinary `file_read` and `file_write` policy events into raw-content-omitting file
developer-activity facts with computed text/binary/base64 or supplied content hashes after credential and persistence specialization,
maps `patch_apply` policy events into raw-patch-omitting patch developer-activity facts with file
path, patch byte count, and computed or supplied patch hash,
maps shell-agent hostname utilities such as `curl`,
`wget`, `dig`, `nslookup`, `host`, `ping`, `ssh`, and `scp` into redacted `dns_lookup` facts, and emits
remaining command executions as redacted `shell_command` facts while preserving supplied tool-call
IDs, process GUID, parent process GUID, pid/ppid, process image, redacted process command line,
and cwd in correlation metadata. The shared inbound-message interceptor can also emit hashed custom `PolicyEvent` telemetry
for prompt/message decisions with raw prompt text and raw sender names omitted. The Vercel AI
middleware prompt-security layer can publish
scrubbed custom `PolicyEvent` telemetry for jailbreak, instruction-hierarchy, watermark,
output-sanitization, and WASM-degraded audit events when local EDR publishing is enabled, without
sending raw prompts or model outputs. The OpenClaw tool-result guard now feeds scrubbed
post-execution `PolicyEvent` telemetry with raw result/content bodies omitted and hashed while
preserving supplied host/user/session/agent/workload/approval identity, and emits normalized
developer-activity facts for result-discovered downloads, browser extension installs,
credential-like paths, and secret-like tool outputs with tokenized browser source URLs scrubbed and
the same endpoint/principal/session, agent, workload, approval, and tool-call identity. The
OpenClaw inbound-message guard now feeds
hashed custom `PolicyEvent` telemetry for prompt/message decisions without raw prompt text while
preserving supplied host/user/session/agent/workload/approval identity. The
bundled MCP `policy_check` server and Claude Code pre-tool hook now best-effort feed that ingress
for tool calls and credential-like path targets, and both shell paths classify package-manager
lifecycle commands plus sensitive cloud/developer-platform CLI commands for the current first-pass
CLI set into first-class developer-activity facts with credential-bearing command tokens redacted.
The OpenClaw CUA bridge now also feeds
recognized computer-use/browser automation actions and
local-path file downloads with scrubbed tool parameters/source URLs plus supplied
endpoint/principal/session, agent, workload, approval, and tool-call identity into the same ingress
when the local agent token is available. The control
API now has
`/api/v1/hunt/agent-secret-touches`, which queries already-ingested signed hunt events for
agent/runtime-caused secret touches and groups matches by endpoint/runtime/principal identifiers.
The local agent also has `/api/v1/agent/edr/agent-secret-touches/fleet-publish`, which publishes
selected endpoint-local agent-secret-touch facts to the enrolled agent NATS hunt-event subject, and
local findings/`PolicyEvent` ingestion can best-effort auto-publish matching current
credential-access graph facts when enterprise NATS is connected. The agent API server also starts a
bounded periodic flight-recorder sync loop when a fleet hunt publisher is configured, so unpublished
persisted agent-secret-touch graph facts are drained into the same NATS hunt-event path after
restart or temporary publish gaps. The automatic paths deduplicate by credential-access observation
edge inside the agent process, not by the shared credential node. The control API has a hunt-event
consumer that validates the tenant/agent subject binding, server-signs the canonical event, and
persists it through signed hunt ingest. This is still not broad automatic sensor fanout or
first-class collector coverage for every tool/runtime.

### Acceptance gates

- endpoint-local `show where this AI agent touched secrets` has a real query path; fleet-side
  `all endpoints` correlation exists for signed hunt events, and selected local agent-secret-touch
  facts can now be published over NATS into signed hunt ingest; the current local ingestion path can
  best-effort auto-publish current credential-access graph facts, and a bounded periodic
  flight-recorder sync can drain unpublished persisted agent-secret-touch facts, while broad sensor
  fanout still needs to continuously feed richer events into the control plane.
- OpenClaw general tool-preflight evaluations can best-effort feed canonical file, command, patch,
  network, and tool `PolicyEvent` telemetry into local flight-recorder/detection/receipt ingestion
  when the local agent token is available, and can also feed classified package-manager lifecycle,
  package-registry token, and sensitive cloud/developer-platform CLI command facts for the current
  first-pass CLI set into normalized developer-activity ingestion while preserving supplied
  endpoint/principal/session, agent, workload, approval, and tool-call identity.
- Adapter-core tool boundaries can explicitly opt in to best-effort local EDR publishing for
  scrubbed pre-execution decisions and custom post-execution result summaries without uploading raw
  tool inputs or outputs, and can emit package-manager lifecycle, package-registry token, and
  sensitive cloud-CLI command facts for the current first-pass cloud/developer-platform CLI set,
  plus credential-path shell reads for repo secrets, CI tokens, local API keys,
  browser-cookie stores, and ClawdStrike-specific standard honey artifact paths, direct
  credential-like file-read/file-write events, translated `secret_access` events, and shell-agent
  hostname utilities as redacted `dns_lookup` facts, into
  normalized developer-activity ingestion; unmatched command
  executions fall back to redacted `shell_command` facts, supplied tool-call IDs are preserved in
  developer-activity correlation metadata, and modern LangChain
  `secureTool`/`secureTools` wrappers can pass that adapter config directly.
- Adapter-core inbound message interception can explicitly opt in to best-effort local EDR
  publishing for hashed prompt-decision events without uploading raw prompt text or raw sender names.
- Vercel AI prompt-security audit events can explicitly opt in to best-effort local EDR publishing
  for scrubbed custom `PolicyEvent` telemetry covering jailbreak, instruction-hierarchy, watermark,
  output-sanitization, and WASM-degraded events without uploading raw prompts or model outputs.
- OpenClaw tool-result persistence can best-effort feed scrubbed post-execution `PolicyEvent`
  telemetry plus normalized result-discovered download, browser-extension, credential-path, and
  secret-output facts without uploading raw result bodies while preserving supplied
  endpoint/principal/session, agent, workload, approval, and tool-call identity.
- OpenClaw inbound-message handling can best-effort feed custom prompt-decision `PolicyEvent`
  telemetry with message hashes/sizes, decision metadata, and supplied endpoint/principal/session,
  agent, workload, and approval identity, without uploading raw prompt text.
- normalized developer-activity ingestion can map MCP tools, browser automation, DNS lookups,
  direct network egress, file read/write, patch apply, persistence-change facts, package-manager
  scripts, cloud CLIs, repo secrets, CI tokens, local API keys, browser cookies, and shell commands
  into endpoint observations; the dedicated package-manager lifecycle ingress can
  emit `package_script` observations, supply-chain findings, receipts, and graph nodes from
  manager/package/phase/script records; and the bundled MCP `policy_check` server plus Claude Code pre-tool
  hook feed tool calls and credential-like path targets into it; both shell checks now classify
  package-manager lifecycle, package-registry token, and sensitive cloud/developer-platform CLI
  commands for the current first-pass CLI set, LangChain wrappers can opt in through adapter config, shared adapter-core
  boundaries classify credential-path reads, direct
  credential-like file events, translated secret-access events, and generic shell commands, and the
  OpenClaw CUA bridge now feeds recognized browser automation/download facts with supplied
  endpoint/principal/session, agent, workload, approval, and tool-call identity plus scrubbed
  source URLs and parameters, and adapter-core
  provides both a shared browser-runtime publisher for automation/download/extension facts and
  automatic translated-CUA enrichment for shared Claude/OpenAI-style boundaries, including
  file-transfer download metadata preservation for `browser_download` facts; remaining dedicated
  runtime adapters still need to call the publisher for runtime-native extension evidence.
- honey file touch, planted hostname flow, and planted browser-cookie value observations produce
  critical findings, graph slices, and receipts; delivered EndpointSecurity file-access and
  NetworkExtension DNS/flow events can trigger the same registered honey-artifact findings without
  resubmitting the deception plan.
- materialized honey artifacts are automatically registered for future local finding evaluation and
  emit signed materialization, cleanup, and rotation receipts.
- brokered egress evidence links provider request, credential reference, policy decision, and
  response body hash without exposing the secret.

## Phase 5: Safe Local Response Executors

**Goal:** execute bounded local containment without turning response into an unsafe remote-control
feature.

**Initial progress:** the local agent now supports a `response-action` route. It requires a
persisted graph target, rejects zero or greater-than-3600-second TTLs, generates rollback metadata,
rejects over-1024-byte response reasons, rejects unknown or over-256-byte actor fields, returns the
affected graph slice, and rejects unknown nested process-selector fields before target resolution,
and emits a signed response-request receipt. Non-dry-run execution currently supports
`collect_evidence`, which binds the graph slice as an evidence-bundle reference, constrained
`restrict_egress`, which writes TTL-bound host:port restrictions for network graph nodes and makes
local policy-check deny matching agent-mediated egress until rollback or expiry, and constrained
`quarantine_file`, which only accepts file/browser-download graph roots in bounded writable
locations and moves the file into the local EDR quarantine directory. It also supports constrained
`disable_persistence`, which accepts bounded LaunchAgent or LaunchDaemon plist graph roots,
user-scoped systemd unit files, shell startup files such as `.zshrc`, ordinary user cron spool
files, and bounded Chromium-family browser extension graph roots by moving only their
`manifest.json`, then moves them into the same local response quarantine root, and
constrained `revoke_grant`, which rotates the local
agent API token without preserving a grace token when the graph target contains the local API
credential or calls local `clawdstrike-brokerd` to revoke broker-capability graph targets, including
brokerd-supported provider revocation for brokered GitHub App installation tokens and Slack tokens.
It also
supports constrained Unix `suspend_process_tree`, which accepts only process graph
roots with signalable PIDs, refuses protected system/agent processes, sends `SIGSTOP` to the root and
downstream process set, and records that PID set for `SIGCONT` rollback. Live
`terminate_process_tree` is rejected by the local executor because it cannot satisfy the
rollback-capable response contract; it remains a dry-run/simulation action only. Live actions emit signed
response-execution receipts
plus signed evidence-bundle manifest receipts. The bundle graph is stored locally and can be fetched
by bundle ID. Executed response reports are also written to a local response-execution ledger with
TTL and rollback metadata. Quarantine and persistence rollbacks verify the artifact hash, refuse
overwrite at the original target path, restore the file, and emit signed `response_rollback`
receipts; egress rollback removes the local policy-check restrictions and emits a signed
`restore_egress` effect; process-tree rollback emits a signed `resume_process_tree` effect for the
recorded PID set. The macOS NetworkExtension package now has a provider-side host:port drop
primitive, active/healthy status when enforcement is ready, and an agent-generated
provider-loadable active-restriction snapshot. The status helper can surface snapshot readiness into
local protection-state evidence, the provider has a changed-snapshot reload path, and the local
agent now has a proof route that hashes and decodes the generated egress-policy snapshot, reports
active/expired restriction counts, optionally refreshes provider status, returns the current
NetworkExtension provider readout, and signs a `sensor_state` receipt whose evidence binds the
snapshot path, content hash, counts, generated timestamp, provider-refresh result, provider status,
and an enforcement-ready bit that is true only when the snapshot is decodable and the provider
reports active policy sync and enforcement readiness.
The proof now also surfaces observed/blocked flow counts, remediation requests, dropped verdicts,
provider-reported reload observation fields, signed reload-observed bits, and, when called with an
execution ID, signed reload-delivery match bits from the provider readout. Real external flow
replay/counter verification remains open.
`restrict_egress` execution receipts bind the current provider status/counters plus the
NetworkExtension reload-request outcome for the generated snapshot, and policy-delta
post-apply enforcement receipts now bind daemon reload, NetworkExtension provider reload command
proof for the changed local policy path, provider refresh, acknowledgement polling, and per-provider
policy epoch/sync/readiness acknowledgement evidence. OS-wide response isolation remains open until a
deployed content-filter provider run proves real flow blocks and
returns verified counter increments.
A local expiration sweep now marks expired collect-evidence executions and emits signed
`response_execution` receipts with status `expired`. A cancellation route closes active
collect-evidence response windows or active `restrict_egress` restrictions before TTL expiry and
emits signed `response_execution` receipts with status `cancelled`; rollback-capable local
side-effect actions such as quarantine, persistence disablement, and process suspension are rejected
by the cancel route so operators must use the explicit rollback path that restores local state and
emits a `response_rollback` receipt. Local response executions can now be acknowledged with a signed
`response_acknowledgement` receipt that binds the acknowledged status, actor, note, rollback
reference, effects, and graph slice. Per-execution proof packages now include matching signed
acknowledgement receipts alongside terminal transition and rollback receipts. A local
response-execution ledger now scopes terminal transitions to the concrete execution entry, so a later
reissued response with the same deterministic action contract is not blocked by an older rollback or
cancellation for that contract. A local
response-acknowledgement ledger stores the
acknowledgement reports separately from generic receipt history. Local acknowledgement reports and
receipts can now bind control response-action ID, delivery ID, target kind/id, acknowledgement
status, resulting state, and a hash of the control acknowledgement token without storing that token
raw, and the local agent rejects unsupported acknowledgement status/target-kind values before
append/signing with fixed allow-list errors instead of echoing those raw discriminator values.
When the acknowledgement control block includes an explicit Control API base URL/token, or agent
settings define `control_api.enabled: true` with a Control API URL, the local agent also attempts
Control API acknowledgement postback. It uses `/api/v1/response-actions/{id}/acks` with
`x-api-key` when an API key is configured, otherwise it uses the bearerless
`/api/v1/response-actions/{id}/agent-acks` route authorized by the delivery acknowledgement token.
The Control API acknowledgement parser bounds target ID, acknowledgement token, message,
resulting-state, observed-at timestamp, and raw-payload fields before delivery lookup or
persistence.
The Control API response-action create validator bounds action type, target kind/ID, reason, and
JSON payload before target resolution or persistence, and create/target/acknowledgement request
bodies reject unknown top-level fields instead of silently dropping them. Unsupported
response-action, target-kind, and acknowledgement status errors return fixed allow-list messages
instead of echoing raw caller values.
The local agent now applies the same fail-closed unknown-field posture to state-changing EDR
maintenance and response-proof request bodies, including causal subgraph/context/search proofs,
graph-slice export, policy-event replay/impact, policy-simulation/replay, privacy reports,
policy-event history replay/impact, agent-secret-touch queries, detection-candidate generation,
staged detection and policy-delta generation, policy-delta apply, NetworkExtension egress proofs,
acknowledgement/archive retry and backfill, fleet-hunt retry, archive verification,
evidence/flight-recorder/receipt compaction, and deception materialize/cleanup/rotation inputs.
Graph-root process selectors on causal subgraph/context, graph-slice export,
policy-simulation/replay, detection-candidate/staged detection, and response-action requests also
reject unknown nested fields before target resolution. Receipt-producing graph proof, policy
simulation/replay, policy-event history impact, detection staging, and agent-secret-touch routes
reject graph depths above the local maximum instead of silently clamping the requested evidence
scope. POST-body `limit` fields for graph search, agent-secret-touch lookup, fleet hunt retry, and
Control API acknowledgement/archive retry or backfill now reject out-of-range values instead of
silently shrinking the requested operation scope. Active provider acknowledgement/refresh timeout
fields on policy-delta apply and NetworkExtension egress proof requests now reject `0` and values
above 5000 ms instead of silently disabling or shortening the provider confirmation window.
The authenticated agent settings route now rejects unknown top-level and nested settings fields,
applies changes through an all-or-nothing validated snapshot, bounds local API token/mTLS security
values, and validates dashboard, OTA manifest, and Control API URLs before persistence. Control API
and OTA manifest settings require HTTPS except for loopback HTTP, and URL userinfo is rejected.
Notification severity and OTA mode/channel/check-interval settings also use explicit allow-lists or
bounds instead of being silently normalized by runtime loops.
Enrollment now persists the normalized Control API URL into local settings for that bearerless path.
Local acknowledgement responses do not return Control API credentials. Failed postbacks are now
persisted to the private local
`~/.config/clawdstrike/edr/control-ack-postback-retries.json` queue with bounded backoff; the queue
temporarily stores the raw delivery acknowledgement token so the agent can replay either Control API
postback route, while receipts and local API responses remain token-redacted. The authenticated
local `POST /api/v1/agent/edr/control-ack-postbacks/retry` route drains due entries, removes
delivered entries, and requeues failures with bounded backoff.
Response request and execution receipts now bind caller-supplied live response actor identity,
including user, session, agent, workload, and approval IDs, require `actorHash` evidence for the
canonical signed actor object, and execution reports persist that actor for later local ledger reads
plus cancellation/expiration receipts. Response-execution receipts also require `executionActorHash`
evidence to match the actor persisted on the execution report. Live response-execution
receipts now bind current local provider state for the agent API, EndpointSecurity, and
NetworkExtension providers for every local executor; `restrict_egress` continues to add dedicated
NetworkExtension policy-sync/readiness/counter, reload-request, and reload-delivery evidence. Failed live response attempts after
planning now persist a failed execution report and signed `response_execution` receipt before the
route returns the execution error. Rollback receipts still bind the current local response-engine
actor, acknowledgement receipts bind the acknowledging local operator or agent, and settings-backed
fleet-side acknowledgement postback no longer requires callers to supply the Control API URL/token on
each local ack. Enrollment-derived Control API URL persistence plus the bearerless delivery-token
acknowledgement route now cover enrolled agents, and failed postbacks have a durable bounded-backoff
retry queue.

### Work

- Implement endpoint-local response executor API.
- Support initial live actions: restrict egress, suspend process tree, quarantine file, revoke local
  grant/capability, disable persistence item, collect evidence. Keep non-rollbackable
  `terminate_process_tree` to dry-run/simulation only, including rejecting limited/full-block
  policy-delta promotion for terminate staged detections.
- Require TTL, rollback metadata, acknowledgement, bounded response action validation, and receipts
  for each action.
- Mirror execution state into `control-api` response action delivery and acknowledgement ledger.
- Add dry-run response mode.

### Acceptance gates

- `contain this process tree for 10 minutes` executes with TTL and rollback state.
- dry-run containment for a graph target returns TTL, rollback metadata, affected graph, and signed
  receipt before live execution is enabled.
- non-destructive `collect_evidence` execution returns evidence bundle metadata plus signed
  response-execution and evidence-bundle manifest receipts, and the bundle graph can be retrieved
  later by ID.
- constrained `restrict_egress` extracts literal network host:port targets from the graph, refuses
  broad/local/private targets, denies matching agent-mediated egress through local policy-check until
  rollback or expiry, requires active/synced/ready NetworkExtension provider state before persisting
  live restrictions, and binds target set, TTL, rollback ref, and graph slice into signed receipts.
- constrained `quarantine_file` moves only bounded file graph targets into local quarantine and binds
  original path, quarantine artifact, file hash, byte count, TTL, rollback ref, and graph slice into
  signed receipts.
- constrained `disable_persistence` moves bounded LaunchAgent/LaunchDaemon plist, user-scoped
  systemd unit, shell startup, ordinary user cron spool, or Chromium-family browser extension
  manifest graph targets into local response quarantine and binds original path, disabled artifact,
  file hash, byte count, TTL, rollback ref, and graph slice into signed receipts.
- constrained `revoke_grant` rotates the local agent API token only for graph targets containing the
  local API credential, drops previous-token grace, or revokes broker-capability graph targets through
  local `clawdstrike-brokerd`; brokerd also attempts supported provider-side revocation for brokered
  GitHub App installation tokens and Slack tokens, and the agent binds the revoked-token hash or full
  brokerd revoke result hash, TTL, rollback ref, and graph slice into signed receipts. Graph-level
  revoke requests now fail closed when the subgraph contains multiple distinct revocable credential
  targets, and brokerd/shared failure bodies are redacted before they can become local API errors or
  signed failed response-execution reason evidence.
- constrained Unix `suspend_process_tree` only signals process graph roots with allowed PIDs,
  refuses protected system/agent processes, binds the root PID plus affected PID set into signed
  receipts, rolls back partial suspend failure immediately, and resumes the recorded PID set through
  signed `response_rollback` receipts.
- live `terminate_process_tree` is rejected by the local response executor because it is not
  rollback-capable; dry-run/simulation may still model that action without signalling processes.
- quarantine and persistence rollback restore only matching response artifacts, refuse overwrite, and
  emit signed `response_rollback` receipts.
- egress rollback removes only matching local response restrictions and emits signed
  `response_rollback` receipts with `restore_egress` effects.
- TTL expiration now executes the same rollback path for rollback-capable side-effect actions before
  marking them expired, so egress restrictions, quarantined files, disabled persistence artifacts,
  and suspended process trees are not left active past their response window without rollback
  evidence.
- cancellation is limited to active collect-evidence windows and active `restrict_egress`
  restrictions; rollback-capable file, persistence, and process-suspend side effects are rejected by
  the cancel route and must use explicit rollback.
- content-filter egress response bridges the same restricted host:port set into the generated
  NetworkExtension policy snapshot, signs a local proof for the provider-loadable artifact and
  current provider readout, then later adds live app-to-extension reload IPC, real-flow block
  verification, and fail-closed receipts when the provider is unavailable, inactive, not synced, or
  not `enforcement_ready`.
- local response executions can be acknowledged with signed receipts and local ledger entries that
  bind actor, acknowledged status, rollback ref, effects, local session/posture context, graph
  evidence, and optional control response-action/delivery correlation with hashed acknowledgement
  token.
- response-family receipt validation requires common response-action, graph-target, TTL, and
  rollback evidence; graph-target, TTL, and rollback hashes must match the signed decision/graph
  fields, and response-request receipts derive the signed action ID from the graph target, action,
  TTL, and dry-run/live request title before binding `responseActionId`, `rollbackRef`, and the
  signed finding ID to that contract. Controlled-response proof packages therefore cannot lose or
  substitute the bounded action contract while retaining the receipt family. It also rejects graph
  roots outside the receipt graph node set and graph-slice IDs that do not match the root plus graph
  counts.
- non-request response receipt validation derives the expected live action ID from the signed graph
  target, response action, and TTL, then binds both `responseActionId` and `rollbackRef` evidence to
  that action contract, so execution, rollback, and acknowledgement proofs cannot relabel action
  correlation.
- response-request receipt validation binds `dryRun` evidence to the signed request title and uses
  that dry-run/live mode in action-ID derivation, so proof packages cannot relabel a dry-run plan as
  live execution or substitute a self-consistent request action ID while preserving the request
  receipt family.
- response request, execution, and rollback receipt validation rejects missing or empty `reason`
  evidence, so proof packages cannot satisfy the recorded-reason contract with a blank reason hash.
- response-execution receipt validation requires explicit execution-status evidence whose hash
  matches the signed execution outcome title and pass/fail flag, so later proof packages cannot lose
  or substitute the status binding while retaining the receipt family.
- response-execution receipt validation binds `executionId` evidence to the signed execution receipt
  ID and, for successful collect-evidence executions, derives that ID from the signed action
  contract and graph content, so proof packages cannot relabel an effect-free execution while
  preserving the receipt family. Collect-evidence execution receipts also reject injected
  `executionEffect:*` evidence.
- successful effect-bearing response-execution IDs are derived from the signed action contract,
  evidence bundle, and signed `executionEffect:*` evidence digest, so proof packages cannot relabel
  an execution while preserving the effect proof.
- successful non-`collect_evidence` response-execution receipts now reject proof packages that drop
  every `executionEffect:*` entry while retaining the execution ID and receipt family.
- response-rollback receipt validation requires explicit rollback-status evidence whose hash matches
  the signed rollback outcome title and pass/fail flag, so restore proofs cannot lose or substitute
  the rollback outcome binding.
- response-rollback receipt validation binds `rollbackId` evidence to the signed rollback receipt
  ID, so restore proof packages cannot relabel rollback execution while preserving the receipt
  family.
- response-rollback receipt validation derives rollback IDs from the signed action contract,
  rollback reference, parent `executionId` evidence hash, and signed `rollbackEffect:*` evidence
  digest, so restore proof packages cannot relabel the parent execution correlation while preserving
  the rollback proof.
- response-acknowledgement receipt validation requires explicit acknowledged-status evidence whose
  hash matches the signed acknowledgement outcome title and pass/fail flag, so operator
  acknowledgement proofs cannot lose or substitute the acknowledged outcome binding.
- response-acknowledgement receipt validation binds `acknowledgementId` evidence to the signed
  acknowledgement receipt ID, so proof packages cannot relabel operator acknowledgement while
  preserving the receipt family.
- response-acknowledgement receipt validation binds `acknowledgedBy` evidence to the signed
  acknowledgement actor identity, so operator acknowledgement proofs cannot substitute the local
  operator or agent while retaining the receipt family.
- response-acknowledgement receipt validation derives acknowledgement IDs from the signed action
  contract, rollback reference, acknowledged actor, parent `executionId` evidence hash, and note
  evidence hash or explicit note-absence marker plus signed `acknowledgementEffect:*` evidence
  digest or explicit effect-absence marker, so acknowledgement proof packages cannot relabel the
  parent execution correlation or substitute acknowledged effects while preserving the
  acknowledgement proof.
- response-acknowledgement receipt validation rejects empty optional `note` evidence, so
  acknowledgement proofs cannot keep only a blank operator note.
- `collect_evidence` response-acknowledgement receipts now reject injected
  `acknowledgementEffect:*` evidence even when the acknowledgement ID is relabeled around that
  injected digest, preserving the effect-free collect-evidence contract.
- successful non-`collect_evidence` response-acknowledgement receipts now reject proof packages
  that drop every `acknowledgementEffect:*` entry while retaining the acknowledgement ID and receipt
  family.
- response-acknowledgement receipt validation requires complete, non-empty hash-only control-plane
  acknowledgement correlation when any `control*` evidence is present, so proof packages cannot
  retain a partial or blank control acknowledgement. Control acknowledgement status is limited to
  `acknowledged`, `rejected`, `failed`, or `expired`, control target kind is limited to `endpoint`,
  `runtime`, `session`, `principal`, `grant`, `swarm`, or `project`, and the acknowledgement ID is
  also derived from the control-correlation evidence digest when control evidence is present, so
  proof packages cannot relabel the control target, delivery, status, or result state while
  preserving the acknowledgement proof.
- response execution, rollback, and acknowledgement receipt validation binds `effectCount` evidence
  to the number of signed per-effect evidence entries, so proof packages cannot relabel response
  effect cardinality while preserving the receipt family, and rejects empty per-effect evidence
  hashes under `executionEffect:*`, `rollbackEffect:*`, or `acknowledgementEffect:*`, so proof
  packages cannot replace counted effect proof material with blank digests.
- response-execution receipt validation binds `evidenceBundleId` evidence to the bundle ID derived
  from the signed action contract and graph content, and binds `evidenceBundleContentHash` evidence
  to the receipt graph content hash, so execution proof packages cannot drop or relabel the captured
  evidence-bundle graph reference while preserving the receipt family.
- response-execution receipt validation binds `dryRun` evidence to `false`, so live execution proof
  packages cannot be relabeled as dry-run execution evidence.
- evidence-bundle manifest receipt validation binds `evidenceBundleId`, `graphSliceId`,
  `contentHash`, `nodeCount`, and `edgeCount` evidence to the signed bundle ID and graph reference,
  rejects roots outside the receipt graph node set, and rejects graph-slice IDs that do not match
  the root plus graph counts, so proof packages cannot relabel bundle identity, graph content, or
  graph cardinality while preserving the manifest receipt family.
- response executions remain queryable after the original call, including TTL expiration and
  rollback references.
- response execution proof packages are now queryable by execution ID, joining the persisted
  execution record with response-request, response-execution, and evidence-bundle manifest receipts
  verified against the local ledger signer plus the provider state and graph reference captured in
  the execution receipt, plus any later signed cancellation/expiration transition, rollback, and
  acknowledgement receipts for the same action contract. The proof route also recomputes the stored
  evidence-bundle graph hash, node/edge counts, and byte count, and rejects actor drift across the
  persisted execution actor, signed response request/execution/transition receipt actors,
  `actorHash`, and `executionActorHash` evidence before returning the package.
- non-dry-run response execution now requires an explicit actor identity object, carries that actor
  into response-request and response-execution receipts, persists the actor on the execution record
  for later lookup and cancellation/expiration receipt signing, and response-family validation now
  requires `actorHash` evidence to match the canonical signed actor object. Response-execution
  validation additionally requires `executionActorHash` evidence to match the execution-report
  actor.
- post-plan live response failures are stored as failed execution reports with signed
  `response_execution` receipts before the route returns the error.
- failed, expired, and cancelled response-execution receipt validation derives execution IDs from
  the signed response action contract, evidence-bundle ID, rollback reference, status class, and
  reason evidence hash, so transition proof packages cannot relabel execution identity while
  preserving the signed transition evidence.
- expired execution transitions produce receipts, TTL expiration now returns rollback
  reports/receipts for rollback-capable side-effect actions, and cancellation receipts are limited to
  collect-evidence and restrict-egress windows; partial, OS-wide network isolation, provider-side
  third-party-token revocation beyond brokered GitHub/Slack token revocation, and broader persistence
  executions beyond bounded launch/systemd-user/shell/cron files still need receipt-producing live
  executors.
- response execution cannot proceed without target graph slice and actor identity.
- local request, execution, acknowledgement, rollback, and evidence bundle can be correlated by
  receipt metadata, and local acknowledgement receipts can bind control response-action/delivery
  IDs plus hashed acknowledgement tokens; unsupported control acknowledgement status/target-kind
  values are rejected before append/signing without echoing raw discriminator values; Control API
  response-action create submissions and
  acknowledgement submissions, including discriminators, observed-at timestamps, and raw payloads,
  are bounded before persistence and reject unknown request fields; unsupported control
  discriminator errors do not echo raw caller values; direct Control API acknowledgement postback
  can be attempted from explicit acknowledgement URL/token input or from configured local
  `control_api` settings, with bearerless delivery-token postback available when no Control API key
  is configured, and failed postbacks can be durably retried through a private local
  bounded-backoff queue with both authenticated manual retry and scheduled due-entry drain paths.

## Phase 6: Operator Console Workflows

**Goal:** expose the local decision engine as causal operations, not alert browsing.

**Initial causal-grouping progress:** `/api/v1/agent/edr/finding-groups` now clusters recent local
findings by overlapping causal graph context and returns each group with the grouped graph slice and
a signed `graph_slice` receipt. Control Console now exposes that path in a `Causal Groups` desktop
tool with configurable limit/depth, grouped finding counts, graph roots, rule IDs, finding IDs,
graph node kinds, node/edge counts, signed receipt family, and group JSON export.

**Initial process-cause and graph-slice progress:** Control Console now exposes
`/api/v1/agent/edr/causal-subgraph`, `/api/v1/agent/edr/causal-context`, and
`/api/v1/agent/edr/graph-slices/export` in a `Process Cause` desktop tool. Operators can target a
root node or process GUID, inspect downstream effects, inspect upstream/downstream context, review
graph nodes and edges, see signed `graph_slice` receipt metadata, persist an evidence-bundle graph
slice with reason/depth controls, and export the persisted bundle response as JSON.

**Initial replay-under-policy progress:** Control Console now exposes
`/api/v1/agent/edr/policy-replay` in a `Policy Replay` desktop tool. Operators can target a root node
or process GUID, bind replay to the current local policy version/hash/epoch, select the simulated
action and graph depth, inspect whether enforcement would trigger, see impact level and
developer-breakage score, review affected nodes and graph node kinds, inspect the signed
`simulation` receipt family, and export the replay response as JSON.

**Initial rule-impact and staged-enforcement progress:** Control Console now exposes
`/api/v1/agent/edr/detection-candidate`, `/api/v1/agent/edr/staged-detections`,
`/api/v1/agent/edr/policy-deltas`, and
`/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply` in a `Rule Impact` desktop tool.
Operators can generate a graph-backed candidate rule from a root node or process GUID, inspect
impact level, developer-breakage score, affected nodes, signed `simulation` receipt family, and
staged rollout gates, persist a selected stage, promote the staged detection into a signed
`policy_delta` overlay, dry-run the policy-bundle apply, execute the dry-run-gated live apply,
inspect validation-window proof hashes, post-apply proof family, policy-sync state, and provider
acknowledgements, and export the workflow package as JSON.

**Initial local-containment progress:** Control Console now exposes
`/api/v1/agent/edr/response-action`, `/api/v1/agent/edr/response-executions`, and
`/api/v1/agent/edr/response-executions/{execution_id}/rollback` in a `Local Containment` desktop
tool. Operators can dry-run or execute TTL-bound response plans for captured graph roots or process
GUIDs, inspect action ID, graph-slice ID, TTL, rollback reference, response-request receipt family,
recent execution state, rollback-capable execution targets, rollback effects, and signed
`response_rollback` receipt family. Live `restrict_egress` responses also surface the signed
`response_execution` receipt family and NetworkExtension reload-request evidence hashes for the
generated policy snapshot. The tool now also requests
`/api/v1/agent/edr/network-extension/egress-policy/proof` and surfaces the egress snapshot hash,
`sensor_state` proof family, enforcement-ready state, observed/blocked flow counters,
remediation-request count, dropped-verdict count, provider-observed reload request details when
reported by the provider snapshot, execution-matched reload delivery proof when an execution is
selected, and provider IDs before exporting the containment workflow plus proof package as JSON.

**Initial agent-secret-touch progress:** Control Console now exposes
`/api/v1/agent/edr/agent-secret-touches` and
`/api/v1/agent/edr/agent-secret-touches/fleet-publish` in an `Agent Secret Touches` desktop tool.
Operators can filter endpoint-local credential-touch graph slices by session, credential kind,
upstream/downstream depth, limit, and agent-context requirement, inspect credential path/name,
agent labels, process nodes, graph node/edge counts, signed `graph_slice` receipt family, publish
the filtered touch set into fleet hunt events, and export the local/fleet evidence package as JSON.

**Initial proof-at-execution progress:** `/api/v1/agent/edr/response-executions/{execution_id}/proof`
now returns the local proof package for a response execution, including the persisted execution
record, provider state, graph reference, response-request receipt, response-execution receipt, and
evidence-bundle manifest receipt, plus later signed cancellation/expiration transition, rollback, and
acknowledgement receipts for the same action contract. Control Console now exposes that package in a
`Proof at Execution` desktop tool with recent execution selection, manual execution-ID lookup,
policy epoch, provider
health, distinct healthy/stale/missing/degraded provider-state labels, graph, ledger path,
receipt-chain display, in-browser receipt-chain signature verification, signer-continuity checks,
actor identity/hash continuity checks, package-correlation checks,
receipt evidence-hash checks, raw proof-package JSON export, and a single verification-verdict JSON
export for incident handoff.

**Initial privacy-report progress:** Control Console now exposes `/api/v1/agent/edr/privacy-report`
as a `Privacy Report` desktop tool. Operators can submit observation JSON, request a privacy mode,
see policy downgrades from raw-artifact requests to `hashes_features`, distinguish blocked raw
upload, distinguish redacted/local-only/hash-only/metadata/raw-permitted projection states, inspect
value hashes, feature projections, and raw-permitted values when policy allows them, see the signed
`privacy_report` receipt family, and export the report package.

### Work

- No remaining Phase 6 Control Console workflow UI gap is tracked here. Broader live-agent dogfood,
  stale/degraded/redacted-state polish, and fleet automation remain follow-up hardening rather than
  a missing required workflow surface.

### Acceptance gates

- each required workflow from the target architecture has a UI or CLI path.
- every UI claim links to graph evidence, policy decision, receipt, or provider-state evidence.
- stale, missing, degraded, and privacy-redacted states are visually and semantically distinct.

## Phase 7: Cross-Platform Expansion

**Goal:** move from macOS/developer-workstation wedge to broader endpoint coverage.

### Work

- Define Linux sensor/enforcement mapping separate from existing supervised-exec semantics.
- Define Windows ETW/Sysmon/minifilter/WFP strategy and claim boundaries.
- Normalize cross-platform observations into the same graph and receipt contracts.
- Add platform capability matrix to release docs.

### Acceptance gates

- each platform has explicit sensor coverage, enforcement coverage, response coverage, and known
  blind spots.
- receipts identify platform provider and degraded-state semantics.
- no platform inherits another platform's enforcement claim by implication.

## First Execution Slice

The highest-leverage first slice is:

1. persist local endpoint observations and causal graph
2. define and test endpoint decision receipt schema
3. connect local agent EDR API to receipt emission
4. add graph-slice query for `show everything this process caused`
5. add graph-aware impact report for a captured `PolicyEvent` JSONL set

That slice uses existing code paths and produces a measurable product loop without waiting for full
macOS provider hardening.
