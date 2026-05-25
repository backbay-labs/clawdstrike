# Endpoint Decision Engine Current State

> **Status:** Draft | **Date:** 2026-05-18
> **Reviewer:** Codex
> **Subject:** current repo support for local runtime integrity, causal evidence, and controlled response

## 1. Summary

ClawdStrike is not starting from zero. The repo already contains several of the hard ingredients:
canonical policy events, replay/simulation, signed receipts, local agent APIs, pure endpoint EDR
primitives, macOS provider planning, fleet response ledgers, and operator surfaces.

The strongest conclusion is also the most important warning: the repo has **credible primitives**,
not yet a complete next-generation EDR. The missing work is the integration layer that turns these
pieces into a local, durable, enforcement-capable endpoint decision engine.

## 2. What Already Exists

### 2.1 Canonical endpoint observations, detections, deception, and causal graph primitives

`crates/libs/clawdstrike-policy-event/src/edr.rs` already defines the core pure model:

- `EndpointObservation`
- `EndpointEvent`
- `EndpointProcess`
- `SupplyChainRuntimeGuard`
- `DetectionFinding`
- `DeceptionPlan`
- `HoneyArtifact`
- `CausalGraphRecorder`
- `EndpointFlightRecorder`

This is directly aligned with the product thesis. The model already includes process execution,
file access, network flows, DNS lookups, package scripts, dynamic library loads, launch persistence,
browser downloads, browser extension installs, credential access, tool calls, and policy decisions.

The implemented detections already cover early versions of:

- risky package-manager install scripts
- unsigned or unnotarized binaries from writable paths
- code-signature drift
- package-manager dynamic library injection
- dynamic library injection
- LaunchAgent / LaunchDaemon persistence changes
- unmanaged browser extension changes
- cloud CLI secret, token, IAM, and key operations
- developer credential access, including typed `PolicyEvent::SecretAccess` scope/name mapping for
  API tokens, package-registry tokens, cloud credentials, SSH keys, signing keys, and browser cookies
- honey artifact access

`EndpointFlightRecorder` now appends endpoint observations to JSONL and rebuilds the graph from
that durable log. This is not yet a complete indexed local database, but it moves the first flight
recorder slice beyond process memory.

`crates/libs/clawdstrike-policy-event/src/facade.rs` exposes helper methods for:

- converting `PolicyEvent` JSONL into endpoint observations, including typed credential observations
  for common secret scopes and names
- evaluating EDR findings
- generating a causal graph from endpoint-observation JSONL
- rendering and materializing standard deception plans

The local agent now also accepts `PolicyEvent` submissions over
`POST /api/v1/agent/edr/policy-events`, validates each event/data pairing, converts the events into
endpoint observations, redacts secret-bearing converted metadata, process command lines, and exec
args before recording them in the local flight recorder, evaluates detections, and emits signed
detection receipts. Direct endpoint-observation ingestion uses the same scrubber for process command
lines, sensitive header command fragments, URL and CLI userinfo credentials, query credentials,
JSON-like secret fields, secret-bearing environment values, file content previews,
policy-decision targets, source URLs, tool parameters, package scripts, and recursive caller
metadata before the observations are graphed or persisted. Specialized developer-activity,
package-manager, EndpointSecurity, and NetworkExtension ingress routes also pass their converted
observations through this final endpoint-observation scrubber before response, recorder, graph, and
receipt use. Registered honey artifacts loaded from the local deception registry are evaluated on
those converted observations too, so delivered EndpointSecurity file-access events and
NetworkExtension DNS/network-flow events can trigger deception findings without resubmitting the
original honey plan. Local-only honey-marker detection can still inspect submitted content previews
before that preview is stripped from durable recorder, graph, receipt, and response surfaces. It also
rejects unknown endpoint-observation, runtime process, code-signature, causal-graph, node, edge,
flight-recorder sidecar-index, and receipt-index fields on direct deserialization, so misspelled or
shadow observation/signature/process/graph/index fields cannot silently shape local runtime
integrity, causal evidence, or proof-lookup state. Invalid flight-recorder sidecar indexes are
rebuilt from the JSONL observation log, and invalid receipt indexes are rebuilt from the signed
receipt ledger. It also
rejects unknown staged-detection and policy-delta promotion fields, including nested candidate,
stage-plan, target-policy, rollout, and artifact envelopes, so generated enforcement overlays cannot
carry silent shadow promotion metadata into later replay/apply flows. Stored evidence-bundle
artifacts and archive/verification envelopes reject unknown fields too, so later proof-package
verification cannot silently accept shadow bundle, artifact, archive, or verification metadata.
Persisted egress restriction records and NetworkExtension egress-policy snapshots also reject
unknown fields, so local containment state and provider-loadable policy snapshots cannot silently
carry shadow active/target/provider metadata. It also
rejects unknown fleet hunt-event outbox fields and Control API acknowledgement/archive retry queue
fields before queued data can be replayed toward NATS or Control API, so shadow retry metadata
cannot steer later delivery. It also
rejects unknown top-level local findings, policy-event, developer-activity, package-manager,
EndpointSecurity, and NetworkExtension ingress fields plus nested collector record fields before
they enter redaction, graph, detection, or receipt paths. It also
rejects unknown broker-capability and provider-token revocation report fields from brokerd before
those provider-facing results can shape signed response-effect hashes. It also
accepts line-delimited `PolicyEvent` captures over
`POST /api/v1/agent/edr/policy-events/jsonl`, returning line-numbered parse/validation errors and
feeding valid captures into the same flight-recorder, detection, and receipt path. The OpenClaw
general tool-preflight hook can best-effort feed canonical file, command, patch, network, and tool
policy events into that path when the local agent token is available, and can also emit classified
package-manager lifecycle commands, package-registry token commands, and sensitive
cloud/developer-platform CLI commands for the current first-pass CLI set through normalized
developer-activity while binding supplied host/user/session/agent/workload/approval identity into
the posted EDR payloads. The shared
`@clawdstrike/adapter-core` `BaseToolInterceptor` can also
explicitly opt in to local EDR publishing, posting scrubbed pre-execution decisions and custom
post-execution result events with raw inputs and outputs omitted for Claude, OpenAI, OpenCode, and
LangChain wrappers that use the shared tool boundary, and emitting classified package-manager
lifecycle commands including Composer/Maven/Gradle/uv/Poetry/Pipenv/.NET/NuGet/SwiftPM/Mix shell
command forms, package-registry token commands, and sensitive cloud-CLI commands into normalized
developer-activity with command tokens redacted, including Docker registry login, pip index
credential config reads, Cargo registry auth commands, RubyGems registry auth commands,
1Password `op`, Bitwarden `bw`, HashiCorp
Vault, Doppler, Heroku, Supabase, Firebase Functions Secrets, Railway variables, Stripe CLI API-key and webhook-signing-secret commands, Sentry/Snyk auth tokens,
AWS/GCP/Azure credential and kubeconfig command forms, Kubernetes `kubectl`, Pulumi secret/config,
CircleCI context secret / runner-token, GitLab `glab` CI/CD variable,
Buildkite `buildkite-agent`/`bk` secret command forms,
Drone/Semaphore/AppVeyor/Woodpecker/Codefresh CI secret or token command forms, and
Terraform/Terragrunt/OpenTofu state/output/login command forms. It now also emits generic
`tool_call` policy
events as scrubbed `mcp_tool`
developer-activity facts, classifies shell reads of credential-looking repo-secret, CI-token,
local-API-key, and browser-cookie paths plus macOS Keychain, local password-store, SSH-agent
key enumeration, Git credential-helper reads, Docker registry credential reads, and direct
Cargo/RubyGems registry credential file reads plus Yarn/pnpm/pip/Poetry/Maven/Gradle/NuGet
credential-store reads, GitHub/GitLab developer CLI token-store reads,
kubeconfig/Terraform/Pulumi cloud credential-store reads, SOPS/age and GnuPG signing/decryption
key-store reads, plus direct file-read/file-write `PolicyEvent`s for those paths and translated
`secret_access` events, into
normalized developer-activity facts, maps agent-driven `launchctl`, `crontab`, and `systemctl`
persistence operations plus direct LaunchAgent/LaunchDaemon plist writes and shell-startup file
writes into raw-content-omitting `persistence_change` developer-activity facts, classifies
direct `network_egress` policy events into redacted protocol/host/port/method/URL-path network
developer-activity facts with request bodies omitted, maps ordinary `file_read` and `file_write`
policy events into raw-content-omitting file developer-activity facts with computed text/binary/base64 or supplied content hashes after credential and persistence
specialization, maps `patch_apply` policy events into raw-patch-omitting patch
developer-activity facts with file path, patch byte count, and computed or supplied patch hash, classifies
ClawdStrike-specific standard honey artifact paths into the same credential-access feed with
deception metadata so registered local honey artifacts can fire
`deception.honey_artifact_touched`, falls back to redacted `shell_command` facts for other command
executions, and binds those facts to available host/user/session/agent/workload/approval identity,
process GUID, parent process GUID, pid/ppid, process image, redacted process command line, cwd,
plus policy epoch/version/hash and tool-call correlation metadata from the shared security context.
Shell-agent hostname utilities now also emit normalized `dns_lookup` facts with secret-bearing URLs
redacted, including a planted-hostname hint for standard ClawdStrike internal-host deception names.
Top-level
developer-activity `toolCallId` input is also promoted into local observation metadata for
non-adapter collectors. Its shared inbound-message
interceptor can emit privacy-preserving custom prompt-decision
`PolicyEvent` telemetry with message hashes, sanitized-replacement hashes, sender-name hashes, and
decision metadata without uploading raw prompt text or raw sender names. The Vercel AI middleware
prompt-security layer can now publish scrubbed custom `PolicyEvent` telemetry for jailbreak,
instruction-hierarchy, watermark, output-sanitization, and WASM-degraded audit events when local
EDR publishing is enabled; those records carry fingerprints, counts, detector IDs, and omission
markers without raw prompts or model outputs. The OpenClaw tool-result
guard can also feed scrubbed post-execution `PolicyEvent` telemetry for `tool_result_persist`
events, omitting and hashing raw result/content bodies before local submission while preserving
supplied host/user/session/agent/workload/approval identity. The OpenClaw
inbound-message guard can feed custom prompt-decision `PolicyEvent` telemetry with message hashes,
sizes, sender/session metadata, decision status, and supplied host/user/session/agent/workload and
approval identity without raw prompt text. The local agent also
exposes `POST /api/v1/agent/edr/developer-activity`, a
normalized collector ingress that maps MCP tools, browser automation/download/extension events, DNS
lookups, direct network egress, file read/write, patch apply, persistence-change facts, package
scripts, cloud CLI commands, shell commands, repo secrets, CI tokens, local API keys, and browser
cookies into the existing
`EndpointObservation` model, and accepts top-level `processGuid`, `parentProcessGuid`, pid/ppid,
process image, process command line, and cwd fields from lightweight collectors as causal process
ancestry while recursively redacting secret-bearing caller metadata. It also exposes
`POST /api/v1/agent/edr/package-manager/events`, a dedicated package-manager lifecycle ingress that
accepts manager/package/phase/script records, redacts secret-bearing script and process-command
tokens plus caller metadata before local observation or graph persistence, records them as
`package_script` observations, accepts extended manager values including Composer, Maven, Gradle,
uv, Poetry, Pipenv, .NET/NuGet, SwiftPM, and Mix, and runs the existing supply-chain install-script
detection and receipt path. The bundled MCP
`policy_check` server and Claude Code pre-tool hook now feed the
developer-activity ingress best-effort for tool calls and credential-like path targets, and both
shell paths classify package-manager lifecycle, package-registry token, and sensitive
cloud/developer-platform CLI checks into first-class developer-activity facts for the current
first-pass CLI set. The OpenClaw
tool-result guard feeds result-discovered downloads,
browser extension installs, credential-like paths, and secret-like tool outputs without raw result
bodies, with tokenized browser source URLs scrubbed, while preserving supplied endpoint/principal/session,
agent, workload, approval, and tool-call identity, the OpenClaw CUA bridge feeds recognized
computer-use/browser automation actions plus local-path file downloads with scrubbed tool parameters
and source URLs plus supplied endpoint/principal/session, agent, workload, approval, and
tool-call identity when the local agent token is available, and adapter-core now exposes a
privacy-preserving browser-runtime publisher for browser automation actions, downloads, and
extension installs with parameters/URLs scrubbed, common browser identity inferred from profile or
extension paths when collectors omit it, optional download content hashes and byte counts preserved,
and raw prompt/page/result/artifact bodies omitted. Browser-download content hashes and byte counts
now survive the local agent developer-activity ingress into durable `browser_download`
observations, causal-graph node attributes, and telemetry privacy projections.
Shared adapter-core tool boundaries also map translated CUA `PolicyEvent`s from Claude/OpenAI-style
computer-use translators into scrubbed `browser_automation` developer-activity facts automatically,
and those translators now preserve bounded file-transfer browser/path/source URL/size metadata so
downloads can be promoted into scrubbed `browser_download` facts.
These are local API ingestion
paths, not yet broad streaming collectors or provider-backed sensor adapters.

### 2.2 Local agent EDR API surface

`apps/agent/src-tauri/src/api_server.rs` already exposes authenticated local endpoints:

- `POST /api/v1/agent/edr/findings`
- `POST /api/v1/agent/edr/developer-activity`
- `POST /api/v1/agent/edr/package-manager/events`
- `POST /api/v1/agent/edr/endpoint-security/events`
- `POST /api/v1/agent/edr/network-extension/events`
- `POST /api/v1/agent/edr/policy-events`
- `POST /api/v1/agent/edr/policy-events/jsonl`
- `POST /api/v1/agent/edr/policy-events/replay`
- `POST /api/v1/agent/edr/policy-events/replay/jsonl`
- `POST /api/v1/agent/edr/policy-events/replay/history`
- `POST /api/v1/agent/edr/policy-events/impact`
- `POST /api/v1/agent/edr/policy-events/impact/history`
- `GET /api/v1/agent/edr/flight-recorder`
- `POST /api/v1/agent/edr/flight-recorder/compact`
- `GET /api/v1/agent/edr/protection-state`
- `GET /api/v1/agent/edr/receipts`
- `POST /api/v1/agent/edr/receipts/compact`
- `GET /api/v1/agent/edr/evidence-bundles`
- `POST /api/v1/agent/edr/evidence-bundles/compact`
- `POST /api/v1/agent/edr/evidence-bundles/archive/verify`
- `GET /api/v1/agent/edr/evidence-bundles/{bundle_id}`
- `GET /api/v1/agent/edr/evidence-bundles/{bundle_id}/archive`
- `POST /api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish`
- `POST /api/v1/agent/edr/control-archive-uploads/retry`
- `POST /api/v1/agent/edr/control-archive-uploads/backfill`
- `GET /api/v1/agent/edr/response-executions`
- `POST /api/v1/agent/edr/response-executions/expire`
- `POST /api/v1/agent/edr/response-executions/{execution_id}/cancel`
- `GET /api/v1/agent/edr/response-acknowledgements`
- `POST /api/v1/agent/edr/response-executions/{execution_id}/rollback`
- `POST /api/v1/agent/edr/response-executions/{execution_id}/acknowledge`
- `POST /api/v1/agent/edr/control-ack-postbacks/retry`
- `GET /api/v1/agent/edr/response-executions/{execution_id}`
- `GET /api/v1/agent/edr/response-executions/{execution_id}/proof`
- `POST /api/v1/agent/edr/causal-graph`
- `POST /api/v1/agent/edr/causal-subgraph`
- `POST /api/v1/agent/edr/causal-context`
- `POST /api/v1/agent/edr/graph-search`
- `POST /api/v1/agent/edr/graph-slices/export`
- `POST /api/v1/agent/edr/agent-secret-touches`
- `POST /api/v1/agent/edr/agent-secret-touches/fleet-publish`
- `POST /api/v1/hunt/agent-secret-touches` (control API, over already-ingested signed fleet events)
- `POST /api/v1/agent/edr/policy-simulation`
- `POST /api/v1/agent/edr/policy-replay`
- `POST /api/v1/agent/edr/detection-candidate`
- `POST /api/v1/agent/edr/staged-detections`
- `GET /api/v1/agent/edr/staged-detections`
- `POST /api/v1/agent/edr/policy-deltas`
- `GET /api/v1/agent/edr/policy-deltas`
- `POST /api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply`
- `POST /api/v1/agent/edr/network-extension/egress-policy/proof`
- `POST /api/v1/agent/edr/response-action`
- `POST /api/v1/agent/edr/deception-plan`
- `POST /api/v1/agent/edr/deception-plan/materialize`
- `POST /api/v1/agent/edr/deception-plan/cleanup`
- `POST /api/v1/agent/edr/deception-plan/rotate`
- `GET /api/v1/agent/edr/finding-groups`

The route implementation redacts secret-bearing metadata, process command fields, sensitive header
command fragments, URL and CLI userinfo credentials, query credentials, JSON-like secret fields,
secret-bearing environment values, policy-decision targets, file content previews, and other raw
artifact fields from direct endpoint observations, specialized converted ingress observations, and
validated `PolicyEvent` submissions before recording them into a
JSONL-backed `EndpointFlightRecorder` at
`~/.config/clawdstrike/edr/flight-recorder.jsonl`, exposes recorder counts through
`GET /api/v1/agent/edr/flight-recorder`, can return a persisted downstream causal subgraph for a
root process or node with affected identity/tool summaries, can return bounded upstream-cause and
downstream-effect context around a graph target with affected identity/tool summaries, can search
the persisted graph by node kind, label substring, host/user/session/tool/tool-call identity, and
specific graph attribute key/value before returning signed bounded context slices with affected
identity/tool summaries,
promotes host, user, session, agent, workload, and approval context into explicit graph attribution
nodes with edges back to the responsible process, and attaches supplied tool-call IDs to process,
tool, and causal edge attributes so operators can pivot from one tool invocation to its local
causal context,
can explicitly export causal subgraphs or causal-context slices into the local evidence-bundle store
with affected identity/tool summaries and a signed `graph_slice` receipt without executing a response action,
can return endpoint-local credential-access graph slices causally linked to agent/tool activity with
session and credential-kind filters, can group recent findings by overlapping causal graph context
with signed graph-slice receipts and responsible identity/tool summaries,
can preserve endpoint/principal and agent/workload/approval identity aliases from `PolicyEvent`
metadata and bounded `PolicyEvent.context` fields, such as `endpointId`, `principalId`,
`endpointAgentId`, `workload_identity`, and `approval_id`, when validated `PolicyEvent`
submissions become endpoint observations, graph attributes, and receipt actors,
can accept OpenClaw general tool-preflight canonical `PolicyEvent` telemetry for file, command,
patch, network, and tool decisions plus classified package-manager/cloud-CLI developer activity when
the local agent token is available, including Firebase, Railway, Sentry/Snyk, Bitwarden, and
Terraform-family sensitive CLI facts, can accept opt-in adapter-core scrubbed pre-execution decisions
and custom post-execution result events plus normalized package-manager/cloud-CLI command facts from
shared Claude/OpenAI/OpenCode/LangChain-style tool boundaries, can accept adapter-core hashed inbound
prompt-decision custom events, can accept Vercel AI prompt-security custom events with raw prompts
and model outputs omitted, and can accept scrubbed OpenClaw tool-result `PolicyEvent` telemetry with
result/content bodies omitted and hashed, plus hashed OpenClaw inbound prompt-decision custom
`PolicyEvent` telemetry,
can accept normalized developer-activity collector facts for MCP tools, browser automation, DNS
lookups, package scripts, cloud CLIs, shell commands, repo secrets, CI tokens, local API keys, and
browser cookies before mapping them into the same flight-recorder/detection/receipt path while preserving supplied
host, user, session, agent, workload, approval, and policy metadata, and the bundled MCP
`policy_check` server can best-effort feed tool calls, classified package-manager/package-registry
token/cloud-CLI shell checks for the current first-pass cloud/developer-platform CLI set, and
credential-like path targets into that ingress while the Claude Code pre-tool hook feeds the same
first-pass shell facts plus
tool and credential-like path targets,
the OpenClaw tool-result guard feeds result-discovered
download/browser-extension/credential/secret-output facts, and the OpenClaw CUA bridge feeds
recognized browser automation/download facts with supplied identity context,
can publish those agent-secret-touch facts to the enrolled agent NATS hunt-event subject through an
operator-triggered route, a best-effort automatic path for current credential-access observations
submitted through local findings/`PolicyEvent` ingestion, and a bounded periodic flight-recorder
sync when enterprise NATS is connected, and the control API can consume endpoint-originated NATS
hunt events, server-sign the canonical event, persist it through the signed hunt ingest path, and
query agent/runtime-caused secret touches grouped by endpoint/runtime/principal identifiers,
can replay supplied `PolicyEvent` JSON or JSONL streams against the current local policy without
recording them and sign the event/result hashes as simulation receipts,
can compare supplied `PolicyEvent` records between the current local policy and a proposed policy
YAML payload with per-event changed verdicts and signed impact receipts,
emits signed `policy_decision` receipts from
`POST /api/v1/agent/policy-check`, emits
signed detection receipts to
`~/.config/clawdstrike/edr/decision-receipts.jsonl`, emits signed provider-originated
`observation` receipts for EndpointSecurity and NetworkExtension ingress observations that bind
observation ID, event kind, graph slice, provider state, event target, and canonical observation
hash, emits signed protection-state receipts that bind local policy plus agent/macOS provider state,
emits dedicated provider-degradation receipts when provider health is degraded, simulates proposed
blocking rules against persisted graph slices
with developer breakage scoring and signed simulation receipts, replays captured graph slices under
the currently configured local policy version/hash/epoch with signed simulation receipts, replays
supplied `PolicyEvent` JSON or JSONL streams under the current local policy with per-event decisions
and signed event/result hashes, generates staged detection candidates from graph roots with
observe/audit/warn/limited-block/full-block rollout guidance,
emits signed `graph_slice` receipts for causal-subgraph, causal-context, graph-search, and explicit
graph-slice exports, creates local privacy reports that classify submitted observations into
hash-only, metadata-only, local-only, and policy-gated raw-permitted projections and emits signed
`privacy_report` receipts, creates dry-run-first flight-recorder compaction reports and can prune
age/count-excess observations while retaining observations referenced by signed receipts, creates
dry-run response-action plans with
explicitly validated 1-3600 second TTL, 1024-byte response reason, strict bounded actor fields,
strict process-target selectors, rollback metadata, affected host/user/session/agent/workload/approval
and tool-call summaries derived from the response graph slice, and signed receipts bound to the
current local session/posture actor, requires
an explicit actor identity object on non-dry-run response-action requests before local execution,
carries that actor into the signed response-request and response-execution receipts, records
post-plan live response failures as failed execution reports with signed receipts, executes the
non-destructive `collect_evidence` response by binding a graph-slice evidence bundle and signed
response-execution plus evidence-bundle manifest receipts, verifies proof packages by
cross-checking selected response-request, response-execution, evidence-bundle manifest, terminal
transition, rollback, and acknowledgement receipts plus their effect evidence against the persisted
execution row and reloading then rehashing the stored evidence-bundle artifact before serving the
proof, executes constrained `restrict_egress`
responses by denying matching agent-mediated egress through local policy-check, executes constrained
`quarantine_file` responses for file/browser-download graph roots in temp, download, cache,
dependency, or build-output paths, stores local egress restrictions under
`~/.config/clawdstrike/edr/egress-restrictions.jsonl`, stores quarantine artifacts under
`~/.config/clawdstrike/edr/quarantine/`, stores response execution reports in
`~/.config/clawdstrike/edr/response-executions.jsonl` with TTL/rollback metadata, stores the graph
bundle under `~/.config/clawdstrike/edr/evidence-bundles/` for local retrieval, marks TTL-expired
local response executions and emits signed expired response-execution receipts, rolls back
rollback-capable side-effect actions before marking them expired, cancels active collect-evidence
windows or active `restrict_egress` restrictions with signed cancellation receipts while rejecting
cancel for rollback-capable file/persistence/process side effects, stores a bounded recent finding
list, restores constrained quarantine artifacts with signed rollback receipts, removes constrained
egress restrictions with signed rollback receipts,
executes constrained `revoke_grant` responses by rotating the local agent API token without
preserving a grace token when the target graph contains the local API credential or by calling local
`clawdstrike-brokerd` to revoke broker-capability graph targets, including brokerd-supported
provider-side revocation for brokered GitHub App installation tokens, Slack tokens, and
configured Generic HTTPS bearer/header secrets that declare a same-provider revocation path,
executes constrained Unix `suspend_process_tree` responses for process graph roots with signalable
PIDs while refusing protected system/agent processes, rejects live `terminate_process_tree`
execution as non-rollbackable while still allowing it to be modeled in dry-run/simulation flows,
acknowledges local response executions with signed receipts that bind actor, note, acknowledged
status, rollback ref, non-empty effect evidence, and graph slice, stores acknowledgement reports in
`~/.config/clawdstrike/edr/response-acknowledgements.jsonl`, including rolled-back terminal
transitions,
returns per-execution proof packages that join the persisted execution record, provider state
captured at execution time, response-request receipt, response-execution receipt,
evidence-bundle manifest receipt, and later signed cancellation/expiration transition, rollback, or
acknowledgement receipts for the same action contract after verifying selected receipts against the
local ledger signer, recomputing stored evidence-bundle graph hashes, node/edge counts, and byte
count, and rejecting actor drift across the persisted execution actor, signed response request,
response execution, and transition receipt actors, `actorHash`, and `executionActorHash` evidence,
surfaces those proof packages in the
Control Console `Proof at Execution` tool with
recent execution selection, manual execution-ID lookup, policy epoch, provider health, graph, and
receipt-chain display plus in-browser signature verification, signer-continuity checks,
actor identity/hash continuity checks, package-correlation checks,
receipt evidence-hash checks, raw proof-package JSON export, and unified verification-verdict JSON
export, exposes bounded local receipt queries with optional family, action, finding ID, rule ID,
graph slice, and root-node filters,
renders standard honey artifact plans, and materializes honey files with no-overwrite semantics
while registering them in a local honey artifact registry for future finding evaluation. Registered
honey artifacts now match later file touches, network flows and DNS lookups to planted internal
hostnames, and browser-cookie credential observations that carry planted honey values. The same
registered-artifact evaluation path is exercised by delivered EndpointSecurity file-access events
and NetworkExtension DNS/network-flow events, and materialization emits a signed
`deception_materialization` receipt over the plan hash,
materialization report hash, artifact counts, and registered artifact count. Materialization receipt
validation now binds endpoint evidence to the signed actor, derives the materialization ID from the
endpoint, policy hash, plan-root evidence, plan-hash evidence, report-hash evidence, count evidence,
and artifact-ID evidence, and requires non-empty plan root, plan hash, materialization report hash,
artifact-count, created-count, skipped-count, registered-artifact-count, and artifact-ID evidence.
Honey-artifact, deception-plan, materialization-report, cleanup-report, rotation-report,
detection-finding, detection-evidence, and supply-chain guard metadata now reject unknown fields
before those values can drive honey registration, finding generation, or deception receipts.
The local API can also
dry-run or apply deception cleanup for registered exact-match honey files, refusing unregistered
artifacts, symlinks, non-files, unsafe relative paths, and content mismatches, and emits a signed
`deception_cleanup` receipt over the cleanup report plus registry counts. Cleanup receipt validation
now binds endpoint evidence to the signed actor, derives the cleanup ID from the endpoint, policy
hash, plan-root evidence, plan-hash evidence, cleanup-report evidence, dry-run evidence,
cleanup-count evidence, and registry-count evidence, requires non-empty plan/report/count/registry
evidence, binds `dryRun` evidence to the signed cleanup title, and checks refused-target count
evidence against the signed pass state. The local API can also rotate deception plans as one
dry-run-first audited operation that preflights old-artifact
cleanup, removes and deregisters the old plan, materializes and registers the new plan, and emits
cleanup, materialization, and `deception_rotation` receipts binding the old/new plan hashes and
final registry counts. Rotation receipt validation now binds endpoint evidence to the signed actor,
derives the rotation ID from the endpoint, policy hash, old/new plan-root evidence, old/new
plan-hash evidence, rotation-report evidence, dry-run evidence, cleanup-count evidence,
materialization-count evidence, and registry-count evidence, requires non-empty old/new plan,
rotation report, cleanup/materialization count, and registry evidence, binds `dryRun` evidence to the signed
rotation title, and checks cleanup refused-target count evidence against the signed pass state.
`apps/agent/README.md` documents these endpoints as local agent APIs.

This is the clearest current runtime seam for the local decision engine.

### 2.3 macOS privileged-provider planning and scaffolding

The active macOS planning set in `docs/plans/clawdstrike/macos-es-ne/**` already captures the
right platform constraints:

- EndpointSecurity authorization is deadline-bound and can fail open if mishandled.
- ES receipts must distinguish intended denial from verified kernel outcome.
- provider installed, active, healthy, degraded, deadline-miss, dropped-event, and Full Disk
  Access state must be visible.
- the initial NetworkExtension baseline is a content filter provider, not a transparent proxy.
- the first wave uses a combined system extension nested under `apps/agent`.

The repo also contains Swift package scaffolding under:

- `apps/agent/src-tauri/macos/system-extension/endpoint-security/**`
- `apps/agent/src-tauri/macos/system-extension/network-extension/**`
- `apps/agent/src-tauri/macos/system-extension/entitlements/**`
- `apps/agent/src-tauri/macos/system-extension/plists/**`
- `apps/agent/src-tauri/macos/system-extension/profiles/**`

And host-side macOS status code under:

- `apps/agent/src-tauri/src/macos/collector.rs`
- `apps/agent/src-tauri/src/macos/host.rs`
- `apps/agent/src-tauri/src/macos/status.rs`

The NetworkExtension subtree now includes the first content-filter egress policy primitive. The
provider can load an exact host:port restriction policy, evaluate socket-flow targets, return a
drop verdict for active unexpired matches, increment blocked-flow counters, and project an
`enforcement_ready` health bit. The Rust response executor also writes the active local
`restrict_egress` set into
`~/.config/clawdstrike/edr/network-extension-egress-policy.json`, a compact snapshot that the Swift
provider policy decoder and status helper can load. The Rust macOS status collector preserves the
helper's `policy_synced` and `enforcement_ready` readouts for protection-state evidence without
claiming the provider runtime is active. The provider code can also watch the snapshot path and
reload changed policy before evaluating flows. The content-filter runtime now persists a
provider-authored runtime snapshot at
`~/.config/clawdstrike/edr/network-extension-egress-policy.json.provider-runtime.json` by default
or at `CLAWDSTRIKE_NETWORK_EXTENSION_RUNTIME_SNAPSHOT_PATH` when configured, and the status helper
prefers that live provider snapshot before falling back to the older policy-file-only readout. The
fallback remains explicitly degraded, so a decodable policy file still cannot masquerade as a live
provider counter/reload proof. The local agent now exposes
`POST /api/v1/agent/edr/network-extension/egress-policy/proof`, which verifies the generated
snapshot is present and decodable, reports its hash and active/expired restriction counts, optionally
refreshes provider status, returns the current NetworkExtension provider readout, and emits a signed
`sensor_state` receipt whose evidence binds the snapshot path, content hash, counts, generated
timestamp, provider-refresh result, provider status, and an enforcement-ready bit that is true only
when the snapshot is decodable and the provider reports active policy sync and enforcement
readiness. The same proof now returns observed/blocked flow counts, remediation-request count,
dropped-verdict count, and a signed flow-counter-observed bit so operators can tell config-ready
proofs apart from provider-counter-backed proofs. The local agent also exposes
`POST /api/v1/agent/edr/network-extension/events`, which accepts content-filter flow verdict events
and records paired `network_flow` plus `policy_decision` endpoint observations with provider ID,
flow ID, normalized verdict, policy snapshot path/hash, generation, and flow/remediation counters.
Caller-supplied NetworkExtension metadata and explicit process command lines are recursively
redacted for secret-bearing keys before they are recorded into observations or the graph.
`restrict_egress` execution receipts now bind the current NetworkExtension runtime,
policy sync/readiness flags, policy epoch, flow counters, and remediation-request counter when
those status fields are available. That is materially better than the previous allow-all provider
scaffold, but it is still not full OS-wide
response containment: deployed system-extension activation, live app-to-extension reload IPC, live
OS flow verification, and verified block-counter
increments still need to be validated on deployed hardware. The local NetworkExtension proof route
now separates provider-readiness ingredients from a strict `liveEnforcementProven` verdict: it only
claims live enforcement when the snapshot is decodable, an active restriction exists, provider
enforcement is ready, flow/block counters were observed without dropped verdicts, and provider
reload delivery matches the response execution.

### 2.4 Darwin telemetry bridge

`crates/bridges/darwin-telemetry-bridge/**` collects macOS process, file-system, and unified-log
telemetry and publishes signed Spine envelopes to NATS JetStream.

The bridge already has useful production-shaped behavior:

- process, FSEvents, and unified-log collectors
- `BridgeConfig` for filtering, stream retention, outbox, health, and SPIFFE SVID path
- Ed25519 key handling
- signed Spine envelope publication
- optional durable SQLite outbox
- health/readiness metrics
- SPIFFE workload identity injection into facts

This is a strong telemetry-publishing substrate, but it is not yet a full local EDR sensor stack.
The local agent can now ingest delivered EndpointSecurity process-exec, file-access, auth-open, and
event-loss events through `POST /api/v1/agent/edr/endpoint-security/events`, preserving provider
metadata after recursive secret-bearing metadata redaction, deadline evidence, host/user/session
context, process lineage, redacted process command lines and exec args, file targets, and auth
decisions as flight-recorder observations. Delivered EndpointSecurity file-access events also share
the registered honey-artifact evaluator, so a sensor-reported access to a materialized honey file
produces `deception.honey_artifact_touched` findings and signed detection receipts without the
request carrying `honey_artifacts`.
Delivered EndpointSecurity auth-open allow/block decisions now also emit dedicated signed
`policy_decision` receipts that bind the provider sensor state and observation-derived actor
identity, rather than relying on a separate detection finding to create receipt coverage.
EndpointSecurity event-loss, deadline-miss, dropped-event,
and missing Full Disk Access facts also return dedicated signed `provider_degradation` receipts for
`macos.endpoint_security`. Provider runtime, last-error, and attestation degradation reason strings
are redacted for embedded secret-like tokens before they are returned in protection-state responses
or signed into sensor-state/provider-degradation metadata.
`scripts/endpoint-security-live-dogfood.sh` is now the strict live-delivery operator gate for this
path: it can start a managed `observe-auth-open` status-tool observer with the same agent token,
agent URL, and runtime snapshot path used by the collector, checks EndpointSecurity provider health,
permits only the first-signal `live_authorization_signal_missing` bootstrap state, triggers a unique
benign file/process probe, and polls the authenticated flight-recorder, causal-graph, and receipt
APIs for a provider-delivered observation plus a matching `macos.endpoint_security` observation
receipt without calling the synthetic EndpointSecurity ingest route. This closes the local harness
gap. The harness now also runs `scripts/endpoint-security-live-dogfood-verify.py` against the
generated `summary.json` before claiming pass, so copied artifacts can be checked for synthetic
ingest, missing health/graph/receipt/probe/protection-state artifact files, missing graph proof,
missing receipt proof, missing signed sensor-state proof metadata, uninstalled/unapproved/inactive
or degraded macOS provider attestation, provider mismatch, malformed probe paths, probe-target hash
drift, and invalid managed-observer artifact metadata. The summary now records host, user, and
agent URL context and the verifier cross-checks that context against the raw probe-activity
artifact.
The product still needs an actual deployed macOS provider run that produces a passing summary and
verification artifact.
`scripts/endpoint-decision-engine-live-qualification.sh` is the QA-host closure driver for the
remaining evidence gap: it fixes the final bundle layout, preflights the signed app plus external
target without live side effects, enforces that the macOS provider directory, supplemental proof
root, persisted audit, qualification summary, and supplemental-builder summary stay inside the
bundle without overlapping, and creates the runtime output parent directories only after preflight
has passed. It then runs `scripts/macos-provider-live-dogfood.sh` into `macos-provider/` and
invokes the qualification-bundle verifier over the resulting manifest plus staged supplemental
proof root. A stale `macos-provider/` evidence directory remains a hard preflight failure unless
the operator explicitly sets `CLAWDSTRIKE_EDE_MACOS_PROVIDER_REPLACE_OUTPUT=1`, which the driver
passes through to the lower-level macOS provider wrapper; preflight still does not delete that
stale output. When all `CLAWDSTRIKE_EDE_*` source artifact variables are
provided, the driver also preflights and runs
`scripts/endpoint-decision-engine-supplemental-proof-bundle.py` with explicit `evidenceMode=live`
to build that proof root before the live provider dogfood. It deliberately does not fabricate
supplemental proofs, so an operator who has not staged strict proof JSON files or supplied strict
source artifacts still gets a red readiness audit rather than a false pass. The driver preserves
the qualification verifier exit code and logs the summary plus persisted audit paths on failure, so
a red readiness audit stops the QA-host run without hiding the evidence file needed for triage. The
supplemental proof bundle builder validates source
artifact readability and output path safety in `--preflight`, dry-runs the same strict bridge
pipeline in a temporary directory, then runs every strict proof bridge for the final proof root and
rejects missing or duplicate generated proof keys. It now stages the explicit input artifacts under
`source-artifacts/` and writes `supplemental-proof-source-manifest.json` with SHA-256 and byte-size
records plus `evidenceMode=live` for the staged policy events, policy-impact result, coverage
inputs, and bridge scripts while omitting unverified origin `sourcePath` metadata, so the generated
proofs remain tied to the exact staged inputs after the bundle is copied and fixture-generated
source manifests cannot satisfy production readiness.
`scripts/macos-provider-live-dogfood.sh` is the lower-level deployed-provider closure
path for this remaining proof: its `--preflight` mode validates required commands, child tools,
target syntax, run ID shape, numeric inputs, output-root safety, empty-or-explicit-replace output
semantics, and the signed `.app` bundle path before any live side effect, and the full run first
executes `scripts/macos-provider-deployment-evidence.py` against the signed/notarized app bundle
and writes the provider manifest with explicit `evidenceMode=live`.
The wrapper also has a no-live `--self-test` mode that regression-checks valid argv/env preflight,
trailing-slash `.app` paths, missing bundle rejection, loopback target rejection, invalid skew
rejection, invalid preflight/replace-flag rejection, non-empty output-root rejection without
replacement opt-in, replacement preflight without deletion, runtime stale-output cleanup when
replacement is explicitly enabled, and the invariant that preflight does not create the output
directory. `scripts/test-macos-provider-dogfood-contract.sh` wires that wrapper self-test
together with shell syntax checks, Python compile checks, explicit live `evidenceMode` wiring
checks, and all ES/NE/deployment/gate/manifest artifact verifier self-tests, and
`scripts/test-platform.sh` plus `scripts/ci-changed.sh` now run
that no-live contract gate when the relevant scripts move. The same no-live contract now includes
`scripts/endpoint-decision-engine-readiness-audit.py --self-test`; the audit helper accepts a
macOS provider dogfood `manifest.json`, verifies the manifest/fresh-gate/provider bindings, maps the
bundle to the north-star checklist, requires both the macOS provider manifest and supplemental
source manifest to declare `evidenceMode=live` before production readiness can pass, and
deliberately reports broader objective gaps for policy simulation, agent/developer-workstation
protection, deception, supply-chain, privacy, operator workflow, and wider sensor-breadth
requirements that are not covered by the macOS provider bundle.
It can also consume repeated strict `--proof KEY=PATH` supplemental proof artifacts for those
non-macOS checklist items; a supplemental proof must name the exact checklist key, carry
`verified: true`, include SHA-256/byte-bound artifact records, include command results with exit
code 0 and SHA-256/byte-bound command output, and satisfy key-specific evidence fields such as
simulation receipt family and impact scores, raw-secret omission and runtime coverage, honey-kind
coverage, supply-chain runtime coverage, privacy projection/approval gates, required operator
workflows, or required sensor modules. Operators do not have to hand-author that strict proof
envelope: `--proof-template KEY` or `--proof-template all` prints validator-backed evidence and
command-result skeletons, then `--write-proof KEY --proof-output PATH --proof-evidence PATH
--proof-artifact PATH --proof-command-result PATH` reads the key-specific evidence JSON, hashes each
supporting artifact, converts each successful command-result JSON into a command proof entry, writes
the supplemental proof, and immediately validates it with the same verifier used by the audit. Its
self-test proves every template satisfies the evidence validator, mutates a supplemental artifact
after proof generation, and requires the audit to fail, so stale proof metadata is not accepted.
The policy-simulation template is now stricter than a bare changed-count claim: it requires
SHA-256-bound policy, event-stream, impact-result, breakage-driver, and simulation-receipt hashes,
current/proposed policy references, the named impact engine, replayed event count, bounded
recent-history window, audit-mode support, staged-enforcement support, blocking-change count,
breakage score, impact level, recommended stage, and the `simulation` receipt family.
`scripts/policy-simulation-impact-proof.py` can produce that strict evidence from `clawdstrike
policy impact --json` output or normalize a captured impact JSON artifact, require the replayed
count to match the source JSONL event stream, hash the supporting artifacts, derive the breakage
metrics, and delegate final proof generation back to the readiness audit writer. The
AI-agent/developer-workstation template is
also stricter than a bare runtime list: it requires raw-secret omission evidence with a SHA-256
binding, protected-surface coverage for MCP servers, browser automation, shell agents, package
managers, cloud CLIs, local API keys, repo secrets, CI tokens, and prompt-injected tool execution,
secret-kind coverage for local API keys, repo secrets, CI tokens, browser cookies, package-registry
tokens, and cloud credentials, plus host/user/session/agent/workload/approval/tool-call identity
fields, collector-kind coverage, receipt-to-activity bindings, and non-isolated causal graph
activity nodes. `scripts/ai-agent-developer-workstation-proof.py` derives those fields from a
structured local EDR coverage artifact and rejects raw secret-like material, unbound receipts, and
graph gaps before delegating final proof generation back to the readiness audit writer. The
endpoint-deception
template now requires more than honey-kind names: it binds the materialization receipt ID, detection
receipt ID, finding ID, exact `deception.honey_artifact_touched` rule ID, causal graph slice ID,
receipt links from materialization to honey artifacts and detection to the materialization receipt,
touched artifacts, and graph slice, process-to-honey graph edges, SHA-256 hashes for materialization
receipt, detection receipt, and causal graph payloads, materialized/touched artifact counts, and
required honey kinds. `scripts/endpoint-deception-proof.py` derives those fields from a structured
deception coverage artifact and rejects wrong-rule findings, unbound receipts, and graph gaps before
delegating final proof generation back to the readiness audit writer. The supply-chain runtime guard
template is now bound to concrete guard behavior instead of broad booleans: it requires npm,
pip, and Cargo coverage, package-script, unsigned-binary, signature-drift, dynamic-library-injection,
launch-persistence, browser-extension, and developer-tool surfaces, the actual `supply_chain.*`
rule IDs emitted by the guard, positive observation and receipt counts, and SHA-256 hashes for the
package-script, signature/drift, persistence, browser-extension, developer-tool, and supply-chain
graph evidence slices. It also requires receipt-to-observation bindings and non-isolated graph nodes
for every supply-chain observation. `scripts/supply-chain-runtime-guard-proof.py` derives those
fields from a structured supply-chain coverage artifact and rejects missing managers, surfaces, rule
IDs, unbound receipts, isolated graph observations, or graph evidence before delegating final proof
generation back to the readiness audit writer. The
privacy-preserving telemetry template is now bound to local privacy-report behavior: it requires
non-raw default projection, raw-artifact suppression by default, downgrade evidence for unapproved
raw requests, policy-plus-approval-gated raw artifact upload, matching approval ID and reason hash,
signed `privacy_report` receipt evidence that binds the report ID, approval ID, approval reason
hash, and raw-upload permission, SHA-256 hashes for the report/policy/downgrade/approved raw/receipt
artifacts, required projection classes, positive count evidence, and raw values only in the approved
report. `scripts/privacy-preserving-telemetry-proof.py` derives those fields from privacy-report
response artifacts and rejects default raw leakage, missing approvals, missing raw approved
artifacts, or wrong or unbound receipt evidence before delegating final proof generation back to the
readiness audit writer. The operator-workflow template now requires concrete local workflow
evidence instead of a checklist of names: process-cause, policy replay, rule impact, local
containment, agent secret touches, causal grouping, proof-at-execution, privacy report, and
detection-staging workflows must all map to the corresponding local EDR API routes, include
simulation/response/sensor/privacy receipt-family coverage, prove verified workflow runs within the
10-second north-star latency bound, prove decisions and containment still work when cloud/NATS are
unavailable, export an operator proof package, bind the run/export/proof artifacts with SHA-256
hashes, preserve bounded containment TTL plus rollback evidence, prove isolate-network,
suspend-process-tree, revoke-token, quarantine-file, block-persistence, rollback-config, and
collect-evidence response actions with per-action TTL, rollback, and receipt evidence that binds
policy, sensor state, actor, process tree, evidence, confidence, and action, and prove staged
detection generation.
`scripts/operator-workflows-proof.py` derives those fields from operator workflow dogfood/export
artifacts and rejects missing workflows, unverified runs, missing rollback, missing controlled
response action kinds, unreceipted response actions, weak response receipt bindings,
cloud-dependent local-first claims, over-latency workflow runs, missing staged-detection output, or
unverified exports before delegating final proof generation back to the readiness audit writer. The
cross-platform sensor-breadth template now requires concrete sensor coverage instead of
a platform claim: process, file, network, DNS, persistence, identity, browser, package-manager, and
secrets modules must cover macOS, Linux, and Windows, map to required local EDR ingestion routes,
prove required event kinds and identity fields, including separate file-write, shell-command,
tool-call, and policy-decision event coverage, bind sensor inventory/event/route coverage with
SHA-256 hashes, and carry verified redaction plus graph-persistence evidence with required causal
node/edge kinds and upstream/downstream/process-tree query coverage.
`scripts/cross-platform-sensor-breadth-proof.py` derives those fields from structured coverage
artifacts and rejects missing sensors, platforms, event kinds, routes, identity fields, redaction
evidence, missing causal graph node/edge coverage, or graph-persistence evidence before delegating
final proof generation back to the readiness audit writer.
`scripts/endpoint-decision-engine-qualification-bundle.py` now wraps the
final QA handoff boundary: it discovers one macOS provider manifest plus all strict supplemental
proof files from an evidence bundle, runs the readiness audit, persists the self-hashed audit, and
immediately re-verifies the persisted audit against the recorded source manifest/proofs. Its
self-test proves complete fixture-bundle replayability while keeping production readiness failed
because `evidenceMode=fixture` is not live evidence, plus missing-source-manifest rejection, missing
bridge-script record rejection, missing-proof rejection, duplicate-proof rejection, and staged
supplemental-source mutation rejection. The qualification bundle verifier also treats the bundle as
self-contained by default: a complete supplemental proof set must include
`supplemental-proof-source-manifest.json`
with `evidenceMode=live`, staged-source hashes, and bridge-script hashes, and the macOS provider
manifest, proof roots, explicit proof files, supplemental source manifest, staged source artifacts,
and persisted audit output must live under `--bundle-dir` unless the operator passes
`--allow-external-evidence` or
`--allow-external-output`, and the self-test covers those opt-in paths. It also refuses to write
the persisted audit over the manifest, a proof artifact, or the supplemental source manifest, and
accepts explicit `--metadata
KEY=VALUE` driver/operator annotations for the qualification summary only under bounded
machine-safe rules: at most 16 entries, keys up to 64 bytes, values up to 512 bytes, keys limited to
letters, digits, `_`, `.`, and `-`, no empty values, no control characters, and no duplicate keys.
When either escape hatch is used, the verifier's summary reports the external manifest, proof,
staged-source, or output paths instead of hiding the expanded trust boundary. The summary carries a
`qualificationSummarySha256` digest over its payload, and
`scripts/endpoint-decision-engine-qualification-bundle.py --verify-summary PATH` rechecks that
digest plus the referenced persisted readiness audit. The verifier also cross-checks summary
`auditSha256`, counts, failed/unresolved/missing keys, persisted-verification flags and payload,
external evidence/output opt-in flags, bundle directory, manifest path, proof paths,
supplemental-source manifest `verified`, `evidenceMode`, and metadata, and external evidence/output
disclosures against the persisted audit provenance and live source manifest while rejecting hidden
qualification-summary and supplemental-source-summary fields plus boolean summary/source-manifest
`schemaVersion`, boolean/non-integer summary counts, and supplemental-source summary count/verified
coercions.
Qualification metadata, external trust-boundary opt-ins, and the qualification bundle directory are
also persisted into the audit provenance, so a copied summary cannot be edited and rehashed without
matching the audit beneath it. The live
qualification driver now writes metadata for its driver name, target, macOS-provider replacement
opt-in, supplemental-proof replacement opt-in, and whether supplemental source artifacts were
supplied.
`scripts/endpoint-decision-engine-supplemental-proof-bundle.py` refuses to build into a
non-empty proof root unless `--replace-output` is passed; the QA-host driver exposes the same guard
through `CLAWDSTRIKE_EDE_SUPPLEMENTAL_PROOF_REPLACE_OUTPUT=1`, so a live qualification cannot
silently mix stale generated proofs from an earlier run with new source artifacts. Audit output
itself now includes an `auditSha256` over the report payload, `--output`
can persist that report, and `--verify-audit` detects later report mutation or hidden audit
envelope, provenance, checklist, manifest-verification, and supplemental-source provenance fields,
boolean audit/proof/source-manifest `schemaVersion`, boolean/non-integer audit counts,
manifest-verification counters, checklist evidence/gap rows, and supplemental-source provenance
counts. Persisted audits also
retain source provenance for the macOS provider manifest, supplemental proofs, and supplemental
source manifest, so audit verification re-runs the recorded source checks and fails if a referenced
manifest, proof artifact, proof envelope/evidence/artifact/command schema, staged source artifact, or bridge-script record drifts after the report was
written; supplemental source-manifest verified status, strict non-boolean byte-size records, closed
source-manifest envelope, policy, sourceArtifacts, and `path`/`sha256`/`byteSize` record schemas,
generated-proof, source-artifact, and bridge-script counts plus proofRoot/sourceRoot topology in
that provenance are also cross-checked against the live source manifest, each bridge key must point at its expected bridge script,
generated-proof records must match the proof paths being qualified, and source artifact records must
live under the declared sourceRoot unless qualification
provenance explicitly discloses the exact external staged source artifact map.
The source manifest policy metadata must also carry non-empty current/proposed
refs, a `sha256:<64-hex>` proposed policy hash, and a positive policy epoch; when the proposed ref
resolves to a local file, the recorded proposed hash must match that file. A direct readiness audit with every supplemental proof now also requires
`--supplemental-source-manifest PATH`; otherwise the prove-later criterion stays failed and
`--verify-audit` rejects the complete proof set as lacking source provenance.
The live qualification driver and deployment evidence collector
requires the expected Team ID, exact app and system-extension bundle IDs, activated
and enabled `systemextensionsctl` state, strict app, deep app-bundle, and embedded-system-extension
code-signature verification, required app/system-extension entitlements, an embedded provider path, stapled
notarization-ticket validation, app/extension plist identity, and both EndpointSecurity plus
NetworkExtension extension points. It then runs the
EndpointSecurity dogfood, runs the NetworkExtension dogfood, invokes
`scripts/macos-provider-dogfood-gate.py`, and writes `gate-result.json` plus a hash manifest under
one output root while passing the same run ID through deployment, EndpointSecurity, NetworkExtension,
gate, and manifest artifacts. The manifest is written by `scripts/macos-provider-dogfood-manifest.py` and hashes
deployment, summary/gate files, and every raw artifact file under the run root. The same helper can
verify the manifest later by recomputing the recursive inventory and requiring
selected artifact paths to stay inside the run root, requiring a non-empty absolute recorded
`runRoot` while allowing relocated verification with an explicit warning, rejecting
boolean `schemaVersion`, boolean/non-integer inventory counts, selected-artifact byte fields, saved-gate counters, or
numeric provider-health flags, non-boolean embedded verifier `verified` fields, or non-string
deployment extension-point bindings plus hidden manifest envelope, selected-artifact, inventory
envelope, inventory-file, saved-gate envelope, provider-binding, provider-health, and embedded
deployment/EndpointSecurity/NetworkExtension verifier-output fields, requiring
`gate-result.json.verified == true`, requiring manifest run/target metadata to match the saved gate,
requiring the saved gate result to name the manifest-selected summary artifacts, include ES/NE
provider-health bindings, and match the portable decision projection from a fresh gate rerun against
the bundled summaries; the live wrapper runs that verification before claiming pass. The combined
gate requires deployment, ES, and NE summaries to pass their
strict artifact verifiers before returning an overall verified result, then rejects summaries that do
not share host/user context, whose ES/NE provider-health attestations do not bind installed/approved
active providers, whose run IDs do not exactly match, or whose run IDs fall outside the bounded run
window.
The EndpointSecurity Swift package now has an injectable `EndpointSecurityAuthOpenRuntime` and
`EndpointSecurityAgentEventPublisher` boundary that subscribes to `AUTH_OPEN`, uses the required
`es_respond_flags_result` API for allow/deny decisions, converts the point-in-time authorization
snapshot into the authenticated agent `/endpoint-security/events` contract, and rejects malformed
path/process facts before attempting delivery. The status helper now also has a bounded
`observe-auth-open [seconds]` mode that runs that subscriber and writes a runtime snapshot for the
agent collector's `live` mode, and the live dogfood harness can manage that process for the
operator window instead of requiring a separate manually launched helper. That is a concrete
provider-side delivery seam, but it is still not evidence that a notarized/approved ES provider is
installed, subscribed, receiving kernel events, and streaming them on a QA host.

### 2.5 Policy replay, simulation, observation, and impact analysis

`crates/libs/clawdstrike-policy-event/src/simulate.rs` can replay `PolicyEvent` streams against a
loaded policy and return per-event decisions and optional posture state.

The CLI already exposes policy workflows in `crates/services/hush-cli/src/main.rs`, including:

- `hush policy observe`
- `hush policy simulate`
- `hush policy impact`
- `hush policy synth`
- `hush policy eval`

`crates/services/hush-cli/src/policy_impact.rs` compares old and new policy decisions across an
event stream. That is the seed of "what would break if this rule blocked?", but the current form is
event-level rather than graph-aware blast-radius analysis.

The local agent now adds the first graph-aware endpoint slice through
`POST /api/v1/agent/edr/policy-simulation`. It resolves a persisted causal graph root by node ID or
process identity, builds the downstream graph slice, scores affected process/file/network/tool and
credential nodes, returns a developer breakage score, affected-node list, affected
host/user/session/agent/workload/approval context, affected tool-call context, and appends a signed
simulation receipt. Graph-simulation receipt validation now binds simulation ID, root node, graph
slice, would-block result, developer breakage score, impact level, affected graph counts, affected
identity/tool context, and graph content hash evidence to the signed receipt fields, and derives the graph-policy simulation ID from
the signed root, graph slice, rule, action, and breakage score. It also rejects graph roots outside
the receipt graph node set and graph-slice IDs that do not match the root plus graph counts.
Simulation rule, report, affected-node, identity-context, and tool-context metadata now reject
unknown fields before those values feed breakage scoring or signed simulation receipts.
`POST /api/v1/agent/edr/policy-replay` now
supports the narrower "replay this incident under today's policy" workflow: it resolves a captured
graph target, binds the replay to the current local policy version/hash/epoch, returns the
graph-impact score, affected graph slice, and same affected identity/tool context used by
graph-policy simulation, and emits the same signed simulation receipt family. It
is a current-policy-bound graph replay, not
an old-vs-new policy diff. `POST /api/v1/agent/edr/policy-events/replay` and
`POST /api/v1/agent/edr/policy-events/replay/jsonl` now expose the pure event-stream replay engine
through the local agent: supplied `PolicyEvent` JSON or JSONL is validated, evaluated against the
currently configured local policy, returned as per-event allow/warn/block decisions, and signed with
the event-stream hash, result hash, posture-tracking mode, summary counts, and current policy
snapshot. Replay receipt validation now also binds the graph slice reference to the signed replay
ID, requires the stream node to remain `policy_event_stream`, and rejects receipts that omit that
pseudo-node from the receipt graph node set. It derives replay IDs from the signed current policy,
event-stream/result/count, and posture evidence, and rejects non-boolean `trackPosture` evidence
hashes.
`POST /api/v1/agent/edr/policy-events/impact` compares the current local policy against a
supplied proposed policy YAML payload over the same submitted `PolicyEvent` stream, returns
per-event changed verdicts plus allow/warn/block transition counts, and signs the impact ID,
event-stream hash, current/proposed result hashes, proposed policy hash/epoch, changed count, and
allow-to-block count. Impact responses also include driver buckets that group changed events by
transition, current/proposed guard, current/proposed reason code, and sample event IDs. Impact
receipt validation binds the graph slice reference to the signed impact ID and requires the stream
node to remain `policy_event_stream` and present in the receipt graph node set. It derives impact
IDs from signed current/proposed policy, stream, result, impact, count, and posture evidence, and
rejects non-boolean `trackPosture` evidence hashes.
`POST /api/v1/agent/edr/policy-events/replay/history` and
`POST /api/v1/agent/edr/policy-events/impact/history` remove the paste-only requirement for the
first local-history slice: they maintain a durable sidecar index for the flight-recorder JSONL log,
rebuild missing, stale, schema-old, or mismatched sidecar metadata from the JSONL source of truth,
apply optional time-window/age/limit/event-kind plus host/user/session/process/parent-process-guid/process-image-hash/process-command-line-hash/agent/workload/approval/tool/tool-call/credential-kind/event-target/event-target-hash
identity filters to index metadata, seek only the selected observation records, project the selected
observations into `PolicyEvent` candidates, and reuse the same signed replay or impact receipt paths
without loading every retained observation into the API layer. History impact also joins
changed verdicts back to bounded local causal contexts, returning node-kind counts, top-level
affected identity/tool counts, blocking-change count, developer-breakage score, impact level, top
breakage drivers with workflow categories, affected host/user/session/agent/workload/approval
identities, affected tool names, graph slices, ordered root-to-target chains, and a signed
`graph_slice` receipt over the union causal-impact slice for the
changed event chains. It additionally returns chain-driver buckets that aggregate repeated
changed root-to-target chains by edge sequence, target kind, verdict transition, guard/reason delta,
and proposed endpoint action before handing the operator sample event and graph target IDs. It
accepts optional `validationWindowSeconds` history-impact bucketing that reports per-window event,
changed-verdict, and blocking-change counts so operators can see whether a proposed rule diff
repeats across selected recent history or only hits one slice, and turns that into a conservative
rollout recommendation (`observe`, `audit`, `warn`, or `limited_block`) with a promotion-ready flag
and reason. The cross-window summary and recommendation each carry deterministic hashes for later
export/comparison, and the recommendation is threaded into generated promotion suggestions and
staged-detection request payloads together with the cross-window impact/recommendation hashes. It also
returns explicit promotion suggestions with request payloads for the existing `detection-candidate`
and `staged-detections` endpoints, defaulting to an audit stage and leaving staged-detection
persistence under operator control while preserving submitted cross-window proof hashes in the
staged-detection ledger for later policy-delta promotion. The projection is explicit because the recorder stores canonical
endpoint observations, not the original submitted
`PolicyEvent` payloads.
`POST /api/v1/agent/edr/detection-candidate` now generates the first local candidate rule for a
graph root, simulates it, and returns staged rollout guidance.
`POST /api/v1/agent/edr/staged-detections` now regenerates that candidate from the current graph,
persists the selected rollout stage plus policy snapshot, simulation report, and signed simulation
receipt in a local JSONL staged-detection ledger, and `GET /api/v1/agent/edr/staged-detections`
lists the staged state with stage/rule filters. `POST /api/v1/agent/edr/policy-deltas` now promotes
that staged record into a versioned local policy-delta overlay, stores it under the endpoint EDR
policy-delta directory, and signs a `policy_delta` receipt that binds the staged-detection ID,
source simulation ID, graph slice, selected stage, action, and artifact hash. Non-rollbackable
`terminate_process_tree` remains available for simulation and dry-run response planning, but
candidate staging omits limited/full-block rollout stages for it and policy-delta generation rejects
legacy or crafted enforcing-stage terminate promotions; receipt validation also rejects
enforcing-stage policy-delta proofs whose action is not rollback-capable. Policy-delta receipt
validation now derives `policyDeltaId` from the signed endpoint, rule, action, staged source,
generation time, source simulation, and graph target; rejects graph-slice evidence mismatches;
rejects root nodes outside the receipt graph node set; and requires non-empty operation,
staged-detection, stage, generated-at, artifact-hash, and simulation evidence. It binds operation
evidence to the signed generated/applied title, rejects apply evidence on generated receipts, and
requires previous-policy, new-policy, and backup evidence on applied receipts. Dry-run and live
policy-delta apply response records and post-apply enforcement proofs now expose the preserved
cross-window impact and recommendation hashes, and the post-apply `sensor_state` receipt binds them
as hashed evidence. Operators can verify the selected local apply path against the validation-window
proof chain without unpacking the generated artifact. This is not full staged enforcement yet: the
policy-delta apply route can dry-run and apply the generated overlay to
the configured local policy file with a base-policy hash guard, a
monotonic policy-epoch guard that rejects stale deltas even when base-policy drift is explicitly
allowed, backup file, merged policy epoch, signed apply receipt, and default post-apply enforcement
proof that records the new local policy snapshot, daemon status, sensor state, degraded-provider
receipts, and a signed `sensor_state` receipt. That receipt now binds the daemon reload result,
provider-refresh result, acknowledgement poll result, and per-provider policy epoch/sync/readiness
acknowledgement fields as hashed evidence. Real applies now request `hushd`
`/api/v1/policy/reload` by default and record the reload result; they also send a
NetworkExtension `reload_policy` command for the changed local policy path when post-apply provider
verification is enabled, expose the requested/saved/request-id/generation/path proof in the
post-apply enforcement record, and bind that provider reload proof into the signed `sensor_state`
receipt. The proof compares the macOS Endpoint Security and Network Extension status readouts
against the new policy epoch and reports per-provider acknowledgement or mismatch reasons after a
direct status-collector refresh request and bounded `providerAckTimeoutMs` wait for refreshed
provider state; active provider waits reject zero or values above the local 5000 ms ceiling instead
of silently shortening or disabling the proof window. The route can also request a managed daemon
restart with `restartDaemon: true`. It still does not prove a deployed ES/NE provider observed that
policy-delta reload under dogfood conditions, compare historical streams across old/new policies,
replay by stored time windows from indexed local history, or provide operator promotion UX.
EDR read/list routes now reject out-of-range `limit` and query-depth values instead of silently
clamping them, so operators and proof tooling see bad evidence-window requests as explicit
validation failures.

### 2.6 Signed receipts, Merkle proofs, and Spine envelopes

`crates/libs/hush-core/**` provides:

- Ed25519 signing and verification
- canonical JSON
- SHA-256 and Keccak-256 hashing
- Merkle tree construction and proof verification
- receipt types and signing

`crates/libs/spine/**` and the bridges use signed envelopes for emitted facts. This gives the EDR
architecture a real proof substrate instead of a merely decorative audit-log claim.

The gap is not crypto availability. The gap is receipt coverage and schema unification for endpoint
detections, local response actions, sensor state, graph snapshots, policy epoch, and degraded
provider state.

`crates/libs/clawdstrike-policy-event/src/edr.rs` now has the first endpoint decision receipt
contract:

- `EndpointDecisionReceipt`
- `EndpointPolicySnapshot`
- `EndpointSensorState`
- `EndpointDecisionActor`
- `EndpointGraphReference`
- `EndpointReceiptEvidence`

The first builder covers detection receipts from `EndpointObservation` + `DetectionFinding` +
`CausalGraph`. It wraps the metadata in the existing signed `hush-core::Receipt`, hashes evidence
values by default, binds graph/process identifiers, and validates that policy hash, policy epoch,
sensor state, endpoint identity, signer identity, detection IDs, non-empty receipt evidence entries,
unique evidence keys, evidence value hashes, explicit evidence redaction classes, raw evidence
redaction permissions, raw evidence hash bindings, and the absence of unknown endpoint-decision
receipt, clock, actor, policy, signer, sensor-state, provider-state, decision, graph-reference, or evidence-item fields are present before signing.
Endpoint receipt signing rejects prefilled signer public-key mismatches and stamps the actual signer
public key into signed endpoint metadata when callers omit it.
Response plan, execution report, execution-effect, evidence-bundle reference, rollback report,
acknowledgement report, and control-correlation metadata now reject unknown fields at serde
boundaries before those values can feed receipt evidence or local proof surfaces.
Detection receipt validation now also binds dedicated finding ID, observation ID, rule ID, title,
severity, confidence, graph slice ID, and process node ID evidence to the signed receipt fields,
derives the finding ID from the signed rule and observation IDs, and rejects non-alert or passed
detection decisions. It also rejects a detection graph process-node reference that is not present in
the receipt's graph node set and rejects graph-slice IDs that do not match the signed observation,
process node, and graph counts.

`POST /api/v1/agent/edr/findings` now emits those signed detection receipts when findings are
created. The route hashes the local policy file, prefers an explicit policy epoch from policy
bundle YAML fields such as `policy_epoch`, `policyEpoch`, `policy.epoch`, or `bundle.policyEpoch`,
falls back to file metadata for ad hoc policies, uses enrollment key material when available, falls
back to a private local EDR receipt key, appends signed receipts to local JSONL, and returns them in
the response.

`GET /api/v1/agent/edr/protection-state` emits a signed `sensor_state` receipt over the local
policy snapshot and provider state. It includes the agent API provider plus macOS EndpointSecurity
and NetworkExtension state derived from the existing host-status snapshot. Degraded providers also
emit dedicated `provider_degradation` receipts with hashed provider identity, state, reason, and
counter evidence, and validation binds that evidence to the degraded provider named by the signed
rule ID. It now derives the provider-degradation ID from the endpoint, policy hash, provider
identity/state, reason, counter, and full-disk-access evidence hashes. `sensor_state` receipt
validation now binds provider count, active-provider count, healthy-provider count,
degraded-provider count, and provider-ID evidence to the signed sensor-state body, and recomputes
the signed sensor-state ID from the endpoint, policy hash/epoch, provider count, active-provider
count, healthy-provider count, degraded count, provider IDs, and a canonical full sensor-state
content hash. Receipt validation rejects
provider states that show degraded protection signals, such as inactive or unhealthy providers,
dropped events, deadline misses, missing Full Disk Access, or uninstalled
providers, unless those providers are explicitly marked degraded with non-empty reason strings, and
rejects duplicate provider IDs so a signed sensor-state receipt cannot describe ambiguous provider
rows. Active or healthy provider rows also require `last_seen` timestamps, so a protection-state
proof has an observation time for providers it claims are available, and those timestamps cannot be
later than the receipt capture time. The route now compares the previous and current macOS host
snapshots and reports provider recoveries when an installed degraded provider becomes active and
healthy; the same `sensor_state` receipt binds hashed recovery count and recovered provider IDs.
Provider runtime, last-error, and attestation degradation reasons are redacted for embedded
secret-like values before they enter those signed provider-state proofs.
This is the first local "prove protection state at execution time" API; it still needs richer
device posture, explicit policy-bundle epochs, and deployed provider recovery validation.

`POST /api/v1/agent/edr/privacy-report` now classifies submitted observations before telemetry
leaves the local agent. The default `hashes_features` mode hashes paths, URLs, process identifiers,
credential names, and user/session identifiers; emits low-content metadata features for normalized
event fields such as action, port, protocol, credential kind, and signature trust; and marks
command lines, environment variables, package scripts, tool parameters, file previews, and arbitrary
metadata as local-only raw artifacts. Raw values are included only when the caller requests
`raw_artifact_permitted` mode, the local policy file explicitly sets
`edr.telemetry.raw_artifact_upload: true`, and the request carries `rawArtifactApprovalId` plus
`rawArtifactApprovalReason`; otherwise the route downgrades the effective mode to
`hashes_features` and returns the policy/approval decision in the response. The Control Console
client now forwards entered approval ID/reason fields to the local agent instead of dropping them
from the request body. Privacy report, observation-projection, and field-projection metadata now
reject unknown fields before local redaction/proof surfaces can consume them. The route now emits a
signed `privacy_report` receipt that binds the report ID, effective privacy mode, raw-artifact
permission bit, observation count, field count, redaction-class counts, raw-suppressed count, and,
for raw-permitted reports, approval ID plus approval-reason-hash evidence. Receipt
validation now binds `privacyReportId` evidence to the signed report ID, derives the report ID from
the signed privacy mode, raw-artifact permission, count evidence hashes, and raw approval evidence
when raw artifacts are permitted, and rejects raw evidence values unless the evidence item is
explicitly `raw_artifact_permitted` and the raw value matches the evidence hash. Control Console now
exposes this source in a `Privacy Report` operator tool that submits observations, shows the
effective mode, raw policy and approval decision, signed receipt
family, distinct redacted/local-only/hash-only/metadata/raw-permitted projection labels, value
hashes,
feature projections, raw-permitted values when policy allows them, and raw-suppressed/local-only
counts, and exports the report package.
This is still a local report API and operator view, not a complete fleet upload policy engine.

Dry-run response requests now emit signed response receipts from the same local ledger. The agent
also exposes `GET /api/v1/agent/edr/receipts` for bounded local receipt lookup by family, action,
finding ID, rule ID, graph slice ID, or root node ID, plus dry-run-first receipt ledger compaction
by age and/or maximum receipt count. Response-family receipt validation rejects non-response actions
such as observe, allow, block, warn, or alert, so response receipts remain limited to bounded local
response actions. It also limits `terminate_process_tree` response proofs to dry-run response
requests; live execution, rollback, and acknowledgement receipts for terminate are rejected because
that action does not satisfy the local rollback-safe response contract. Response-family receipt
validation also requires common `responseActionId`,
`rootNodeId`, `graphSliceId`, `ttlSeconds`, and `rollbackRef` evidence. The graph target, bounded
duration, and rollback evidence hashes must match the signed decision and graph fields, and response
request receipts bind `responseActionId` to the signed action ID, so later proof packages cannot
strip or substitute the controlled-response target, bounded duration, or rollback binding while
retaining the receipt family. Response-family receipt validation also rejects graph roots that are
not present in the receipt graph node set and graph-slice IDs that do not match the root plus graph
counts. Response-request receipts now also require `contentHash` evidence whose hash matches the
signed graph content hash, so request proofs cannot preserve the same graph-slice count while
silently swapping graph contents. It now also requires `actorHash` evidence for the canonical signed response actor object, so
proof packages cannot drop or substitute the accountable user/session/agent/workload/approval
binding while preserving the receipt family. Response-execution receipts also bind
`executionActorHash` to the actor already persisted on the execution report and require it to match
`actorHash`, so proof packages cannot split receipt accountability from the execution ledger actor.
Non-request response receipts also derive the expected live action ID from the signed graph target,
response action, and TTL, then bind both `responseActionId` and `rollbackRef` evidence to that
action contract, so execution, rollback, and acknowledgement proofs cannot relabel action
correlation. Response-request receipts derive the expected action ID from the signed graph target,
response action, TTL, and signed dry-run/live request title, then bind the signed finding ID,
`responseActionId`, and `rollbackRef` to that request action contract. Their `dryRun` evidence also
binds to the signed request title, so proof packages cannot relabel a dry-run plan as live
execution or substitute a self-consistent action ID while retaining the request receipt family.
Response request, execution, and rollback receipts also reject missing or
empty `reason` evidence, so proof packages cannot satisfy the recorded-reason contract with a blank
reason hash. Response-execution receipts must also retain `executionStatus`
evidence whose hash matches the signed execution outcome title and pass/fail flag, so the signed
proof keeps an explicit status binding. Their `executionId` evidence must also hash to the signed
execution receipt ID, and successful collect-evidence execution IDs must match the ID derived from
the signed action contract and graph content while rejecting injected `executionEffect:*` evidence.
Successful effect-bearing execution IDs must match the ID derived from the signed action contract,
evidence bundle, and signed `executionEffect:*` evidence digest, and successful
non-`collect_evidence` executions now reject proof packages that drop every `executionEffect:*`
entry. Their `evidenceBundleId` evidence must match the bundle ID derived from
the signed action contract and graph content, and their `evidenceBundleContentHash` evidence must
hash the receipt graph content hash. Response-rollback receipts likewise must retain
`rollbackStatus` evidence whose hash matches the signed rollback outcome title and pass/fail flag
before they validate, their `rollbackId` evidence must hash to the signed rollback receipt ID, and
their rollback IDs must match the ID derived from the signed action contract, rollback reference,
parent `executionId` evidence hash, and signed `rollbackEffect:*` evidence digest.
Response-acknowledgement receipts must retain `acknowledgedStatus` evidence whose hash matches the
signed acknowledgement outcome title and pass/fail flag, so operator acknowledgement proofs cannot
lose or substitute the acknowledged outcome binding. Their `acknowledgementId` evidence must also
hash to the signed acknowledgement receipt ID, and their `acknowledgedBy` evidence must hash to the
signed acknowledgement actor identity. Their acknowledgement IDs must match the ID derived from the
signed action contract, rollback reference, acknowledged actor, parent `executionId` evidence hash,
note evidence hash or explicit note-absence marker, and signed `acknowledgementEffect:*` evidence
digest or explicit effect-absence marker. Any optional `note` evidence must be non-empty.
Successful non-`collect_evidence` acknowledgement receipts must also retain
`acknowledgementEffect:*` evidence, so operator acknowledgement proofs cannot drop or substitute the
effect list they are acknowledging while preserving the acknowledgement ID. `collect_evidence`
acknowledgement receipts remain effect-free and reject injected `acknowledgementEffect:*` evidence,
even when the acknowledgement ID is relabeled around that injected digest. When acknowledgement
receipts include control-plane correlation evidence, validation now
requires the control response-action ID, target kind, target ID, hash-only acknowledgement token,
and acknowledgement status to be present and non-empty, restricts the control acknowledgement status
to `acknowledged`, `rejected`, `failed`, `expired`, or `rolled_back`, restricts the control target kind to
`endpoint`, `runtime`, `session`, `principal`, `grant`, `swarm`, or `project`, and derives the
acknowledgement ID from the control-correlation evidence digest so proof packages cannot relabel the
control target, delivery, status, or result state while preserving the acknowledgement proof.
Response execution, rollback, and acknowledgement
receipts also require `effectCount` evidence whose hash matches the number of signed per-effect
evidence entries, so proof packages cannot relabel the effect cardinality while preserving the
receipt family, and reject empty per-effect evidence hashes under `executionEffect:*`,
`rollbackEffect:*`, or `acknowledgementEffect:*`, so proof packages cannot replace counted effect
proof material with blank digests. Response-execution receipts also bind the captured
evidence-bundle graph reference to signed graph content, so execution proof packages cannot drop or
relabel it while preserving the receipt family. Response-execution receipts also bind `dryRun`
evidence to `false`, so live execution proofs cannot be relabeled as dry-run execution evidence.
Policy checks emit signed `policy_decision` receipts that bind the action type, target,
allow/block result, guard, severity, message, endpoint identity, current local posture, runtime
agent identity, policy snapshot, and sensor state. Validation now binds `actionType` evidence to
the signed policy-decision rule ID, binds `allowed` evidence to the signed pass/fail bit, rejects
allow/pass or block/fail mismatches, requires non-empty target and guard evidence, and derives the
policy-decision ID from the endpoint, policy hash, action type, target evidence hash, allow/block
bit, and guard evidence hash.
The first non-dry-run response execution is `collect_evidence`: it captures the target graph slice
as an evidence-bundle reference and emits signed `response_execution` and
`evidence_bundle_manifest` receipts. Manifest receipt validation now binds `evidenceBundleId`,
`graphSliceId`, `contentHash`, `nodeCount`, and `edgeCount` evidence to the signed bundle ID and
graph reference, rejects roots outside the receipt graph node set, and rejects graph-slice IDs that
do not match the root plus graph counts. Proof packages cannot relabel the bundle, graph content, or
graph cardinality while preserving the manifest receipt family. The local evidence-bundle store can
list bundle metadata only after revalidating persisted artifact filenames, bundle IDs, graph hashes,
byte counts, and graph node/edge counts, and perform dry-run-first
compaction by age and/or maximum bundle count while protecting bundles referenced by still-active
response executions, and can export a bundle-local archive package that
binds the stored graph, bundle metadata, matching signed receipts, a canonical archive hash, and a
self-check verification block for the recomputed graph content hash, artifact-vs-bundle metadata
consistency, artifact byte count, graph node/edge counts, graph-slice and manifest graph-count
evidence, response lifecycle graph/content evidence, expected receipt families, receipt signatures,
required receipt-family coverage with structured present/missing family lists and
family cardinality, known bundle-family contracts, response actor continuity,
endpoint identity continuity, root-node continuity, policy continuity,
sensor-state coverage, endpoint-decision content-hash binding, receipt-ID and local-sequence uniqueness,
receipt timestamp parsing/chronology, signer consistency, generatedAt coverage of enclosed receipts,
validated optional trusted signer matching, receipt-to-bundle-ID,
receipt-to-graph-slice, receipt-to-root-node, plus receipt-to-content-hash binding.
It can also re-verify an archive
package later by recomputing the canonical archive hash, expected archive ID, receipt count,
supplied verification block, and graph/receipt checks, and
can publish a privacy-bounded archive metadata hunt event to fleet when enterprise NATS is
configured. That fleet event carries archive/bundle hashes, graph counts, receipt IDs/hashes, receipt
families, and the local verification block; it deliberately does not inline raw graph nodes, receipt
bodies, or local artifact paths. When NATS is disconnected, archive metadata publication is queued in
a private local `fleet-hunt-event-outbox.json` file with a bounded retry timestamp instead of being
dropped. A local authenticated retry route can drain due queued fleet hunt events when the NATS
publisher is available, removing delivered events and retaining failed attempts with bounded backoff.
The existing fleet sync loop also drains due fleet hunt events at startup and on interval. The
Control API now has an admin API-key raw endpoint-evidence archive upload path with canonical
archive-hash validation, tenant-bounded retention, metadata reads, and retained archive download.
When the agent
has `control_api.enabled` with a URL/API key, the local policy explicitly allows
`edr.telemetry.raw_artifact_upload: true`, and the caller provides `rawArtifactApprovalId` plus
`rawArtifactApprovalReason`, the evidence-bundle fleet-publish path also posts the verified raw
archive to that Control API store while keeping the NATS hunt event metadata-only. The raw upload
payload carries the approval ID and hashed approval reason, and the local response reports whether
approval was required/provided. A durable retry path now queues failed approved raw-archive uploads
in a private local ledger and drains them through an authenticated local retry route using the
currently configured Control API credentials; retries refuse payloads that lack raw-artifact
approval evidence. An authenticated local backfill route can also upload already-stored verified
archives to Control API without requiring NATS or a prior failed fleet publish, but raw backfill
requires the same approval ID/reason pair. The control console event drawer now
recognizes endpoint evidence archive hunt events, fetches retained archive metadata by archive ID,
attaches the metadata to incident exports, and can export the retained raw archive through the
Control API download route, which now rejects viewer credentials for raw archive bodies while
keeping metadata lookup available, and only allows admin/owner roles to retrieve those raw bodies.
Raw body uploads reject viewer/member credentials and non-API-key actors. Successful raw body upload
and retrieval plus denied raw-body attempts also record sanitized `usage_events` audit entries with
archive metadata, raw-archive approval ID, approval-reason hash, and actor identity, without
storing the archive body in the audit row. The Control
API compliance export now includes that sanitized audit metadata in JSON, CSV, and CEF output so
raw-archive access decisions remain externally reviewable without embedding raw archive bodies. The
same export path carries case evidence-bundle custody events with sanitized bundle IDs, case IDs,
digests, sizes, counts, and actor metadata. The
Control API case artifact service can also attach retained endpoint evidence archives as verified
`endpoint_evidence_archive` references with server-derived archive hashes, bundle IDs, raw refs,
retention metadata, and verification blocks. The event drawer can now load existing remote cases,
attach the archive artifact to a selected case, or create a new
archive-focused remote case and attach the artifact immediately. It also surfaces raw archive
approval IDs and approval-reason hashes from archive events, retained archive records, or retained
metadata, carries that evidence into newly created archive cases, and provides operator controls to
submit approval ID/reason pairs for approved raw-archive fleet publish or Control API archive
backfill. It can also load the selected remote case detail and timeline, and request a signed case
evidence-bundle export that includes raw
references plus a sanitized `audit-events.jsonl` trail for matching raw-archive
upload/download/denial events, then download the completed signed bundle through the Control API
evidence-bundle download route. Control Console also has a first-class `Fleet Cases` operator tool
that lists remote cases, queries text/status/severity filters through the Control API, creates new
investigation cases, updates selected case status through the existing case patch route,
bulk-transitions selected cases through lifecycle statuses, loads selected case artifacts and
timeline events, exports signed case evidence bundles with raw references and related sanitized
raw-archive audit trails, and downloads completed bundle archives. Bundle metadata and ZIP downloads
now follow the export boundary, reject viewer credentials, and record sanitized denial audit events;
successful export creation, metadata reads, and completed ZIP downloads also record sanitized bundle
ID, case ID, digest, size, count, and actor metadata, while denied bundle creation attempts are
audited by case ID. Later case evidence exports include those sanitized bundle custody events in
`audit-events.jsonl`.
The first egress-control executor is constrained
`restrict_egress`: it extracts literal host:port network nodes from the graph slice, refuses broad
wildcards plus local/private/link-local targets, writes TTL-bound local restrictions under
`~/.config/clawdstrike/edr/egress-restrictions.jsonl`, makes `/api/v1/agent/policy-check` deny
matching agent-mediated egress offline until rollback or expiry, binds the restricted target set into
signed execution effects, writes the active restriction set to a provider-loadable
`network-extension-egress-policy.json` snapshot, and removes the local restrictions plus the
snapshot entries through rollback, cancellation, or expiry. The macOS content-filter package now has
a tested provider-side host:port drop policy and `enforcement_ready` health projection, and the local
proof route signs the decodable provider-loadable snapshot plus current provider status without
claiming enforcement readiness unless the provider also reports active policy sync and enforcement
readiness. The provider runtime now has a tested `reload_policy` command envelope that can accept a
watched policy path, increments `remediation_requests`, refreshes changed watched snapshots, and
returns the provider snapshot/counters plus the last observed reload request ID, generation,
snapshot path, reloaded bit, and reload error when a delivered policy snapshot cannot be applied for
receipt binding. The runtime also persists that provider-authored snapshot to a JSON file that
`network-extension-status-tool live` reads before consulting the policy snapshot, including the
late-source case where the watched policy path arrives from a delivered reload command rather than
process environment. The provider snapshot also carries a top-level `last_error` and now preserves
specific policy snapshot load/readout reasons even when the provider runtime itself remains unknown,
so unreadable policy snapshots cannot collapse into a generic provider-unknown proof. That command also has a tested
`NEFilterProviderConfiguration.vendorConfiguration` payload representation for the macOS
content-filter control surface, and the status helper now exposes `request-reload` to load
`NEFilterManager` preferences, merge the reload payload without dropping existing vendor keys, and
save the preferences when an installed provider configuration is available. The response-execution
receipt binds the current provider status/counters plus NetworkExtension reload-request evidence
for the generated snapshot, including requested/saved state, generation, request ID when available,
and helper error when unavailable. Live `restrict_egress` fails closed before
persisting a restriction unless the NetworkExtension provider reports active runtime, synced policy,
and enforcement readiness; provider-not-ready refusals are captured as failed response executions
with signed receipts. Policy-delta post-apply enforcement receipts now
bind the daemon reload, provider refresh, acknowledgement poll, and per-provider policy
epoch/sync/readiness acknowledgement evidence. After writing the egress snapshot, the agent now
requests the macOS host collector to persist a NetworkExtension reload vendor configuration through
the status helper when available. The content-filter provider has a tested
vendor-configuration handler and observes saved reload commands through its runtime filter
configuration. The NetworkExtension egress-policy proof now returns observed/blocked flow counts,
remediation request count, dropped-verdict count, provider last-error state, provider-reported
reload observation fields including reload errors when available, and signed
`networkExtensionFlowCounterObserved` plus
`networkExtensionReloadObserved*` evidence bits. When called with a response execution ID, the proof
also compares the provider-observed reload request ID, generation, and policy snapshot path against
the signed `response_execution` reload-request evidence and emits signed reload-delivery match bits,
so operators can distinguish config-ready proofs, provider-counter/reload-backed proofs, and
execution-matched provider reload delivery.
Dogfood validation of that saved configuration on a deployed macOS provider, OS-wide flow blocking,
and verified provider
counter increments from real flows are not yet proven end to end.
The repo now has an operator-run harness for that proof boundary:
`scripts/network-extension-live-dogfood.sh` seeds a concrete network-flow graph, executes live
`restrict_egress`, triggers real TCP flows against the target, polls
`/api/v1/agent/edr/network-extension/egress-policy/proof` with the response execution ID until
`liveEnforcementProven` is strict, then rolls the response execution back by default. The harness now
also runs `scripts/network-extension-live-dogfood-verify.py` against the generated `summary.json`
before claiming pass, rejecting missing action/proof/flow/rollback artifact files, weak proof,
summary/proof drift, missing provider reload delivery, non-blocked final flows, skipped or failed
rollback, failed post-rollback reachability, and dropped verdicts. It is still a deployed macOS
dogfood gate, not a simulated CI proof. The summary now also binds host/user/session/agent/workload
context to raw findings/action request artifacts and requires the proof response to include live
provider runtime, sensor-state, sensor-state receipt metadata, and installed/approved active macOS
provider attestation from the raw agent-health artifact before a pass is accepted.
The combined `scripts/macos-provider-live-dogfood.sh` command is the expected release evidence
aggregator once a QA host is ready to produce both ES and NE `summary.json` artifacts.
The first live
containment executor is constrained
`quarantine_file`: it only accepts file/browser-download graph roots in bounded writable locations,
moves the file under the local EDR quarantine directory, binds the original path, quarantine artifact,
content hash, and byte count into execution effects, and emits signed response-execution plus
evidence-bundle manifest receipts. Quarantine rollback verifies the artifact hash, refuses overwrite
at the original target path, restores the file, and emits a signed `response_rollback` receipt. The
first persistence-control executor is constrained `disable_persistence`: it only accepts
bounded LaunchAgent or LaunchDaemon plist graph roots, user-scoped and system systemd unit/drop-in files,
XDG autostart desktop entries, KDE Plasma env/autostart scripts, Linux/macOS home shell startup
files and Fish `conf.d` drop-ins, system `profile.d` drop-ins, ordinary user cron spool files, system cron drop-ins, or bounded
Chromium-family or unpacked Firefox browser extension graph roots resolved to their `manifest.json`, moves the file under the local EDR quarantine
directory, binds the original path, disabled artifact, content hash, and byte count into execution
effects, and can restore the file through the same hash-verified rollback route. The
first local grant executor is constrained `revoke_grant`: it acts when the target graph contains
the local agent API token credential, a broker-capability credential, or an agent-owned local
integration secret credential for the SIEM API key / webhook signing secret. Local-token revocation
rotates that token immediately without preserving a previous-token grace window; broker-capability
revocation calls local `clawdstrike-brokerd`, lets brokerd attempt supported provider-side token
revocation for brokered GitHub App installation tokens, Slack tokens, and configured Generic HTTPS
bearer/header secrets that declare a same-provider revocation path, and binds the full brokerd
revoke result hash into execution effects while redacting brokerd failure bodies and all shared
failed response-execution reasons before returning or signing them; graph-level revocation now
refuses ambiguous subgraphs that contain multiple distinct revocable credential targets unless the
request selects the specific credential root node. Local integration-secret target resolution now
accepts explicit structured graph attributes such as `settingKey` / `localIntegrationSecret` in
addition to the existing credential label/name/path forms, and local integration-secret revocation
clears the stored secret, disables the affected integration, persists the settings update, and binds
a hash of the old secret/report into execution effects. These variants emit signed
response-execution plus evidence-bundle manifest receipts. The first
process-control executor
is constrained `suspend_process_tree`: it only accepts process graph roots with PIDs, refuses PID 0,
PID 1, the current agent process, the agent parent process, and protected system/agent labels,
checks that each PID is signalable, sends Unix `SIGSTOP` to the affected process set, rolls back
partial suspend failures with `SIGCONT`, binds the root PID plus affected PID set into execution
effects, and can resume the recorded PID set through a signed `response_rollback` receipt. Live
`terminate_process_tree` is no longer part of the local autonomous executor because it cannot satisfy
the rollback/TTL contract; operators can still dry-run or simulate that action, but live local
process containment uses suspend and generated policy-delta promotion will not turn terminate into a
limited/full-block rollout. The shared policy-event response-report helper also refuses to construct
successful terminate execution reports. The agent stores graph slices as local evidence bundle
artifacts and verifies
graph content hashes before
writing them. It also appends execution reports to a local response-execution ledger so TTL
expiration and rollback references can be queried after the call. A local expiration sweep marks
TTL-expired collect-evidence executions and emits a signed
`response_execution` receipt with status `expired`. A local cancellation route closes active
collect-evidence response windows or active `restrict_egress` restrictions before TTL expiry and
emits signed `response_execution` receipts with status `cancelled`; rollback-capable local
side-effect actions such as quarantine, persistence disablement, and process suspension are rejected
by the cancel route so operators must use the explicit rollback path that restores local state and
emits a `response_rollback` receipt plus a terminal `response_execution` receipt with status
`rolled_back`, so manually rolled-back side effects stop counting as active response windows.
The response proof route now has route-level coverage across the rollback-capable side-effect
set, including egress restrictions, file quarantine, process suspension, LaunchAgent
persistence, browser extension manifests, shell startup files, profile.d drop-ins, cron files,
systemd units/drop-ins, XDG autostart entries, and KDE/Plasma startup scripts; these proofs bind the
recorded execution target to the request, execution, terminal transition, rollback, acknowledgement,
and evidence-bundle receipt families where those families are expected.
OS-wide NetworkExtension isolation, first-class provider-specific third-party-token revocation beyond
brokered GitHub/Slack/configured Generic HTTPS token revocation, and broader system-wide
persistence response coverage beyond bounded launch/systemd-user/systemd-system/systemd-drop-in/xdg-autostart/kde-plasma-env/kde-autostart-script/shell/profile-d/cron/system-cron-drop-in/browser-extension
manifest files are still missing.
Response request and execution receipts now bind caller-supplied live response actor identity when
provided, including user, session, agent, workload, and approval IDs. Response-family receipt
validation now rejects receipts that have only endpoint ID/posture and no accountable user, session,
agent, workload, or approval context, and requires `actorHash` evidence to hash the canonical
signed actor object. Response-execution receipts additionally require `executionActorHash` evidence
to match the actor recorded on the execution report. Live response-execution
receipts now bind the current agent API, EndpointSecurity, and NetworkExtension provider state for
all local executors, while `restrict_egress` still adds dedicated NetworkExtension policy-sync,
readiness, and counter evidence. Execution reports persist the actor so later ledger reads and
cancellation/expiration receipts retain the original executor identity. Failed live response
attempts after planning are now stored as `failed`
response-execution records with signed receipts instead of returning a bare error. Failed, expired,
and cancelled response-execution IDs now derive from the signed response action contract, evidence
bundle ID, rollback reference, status class, and reason evidence hash, so transition receipts cannot
relabel execution identity while preserving the signed transition evidence. Rollback receipts still
bind the current local response-engine actor, and acknowledgement receipts bind the
acknowledging local operator or agent. Local acknowledgements can now also carry control-plane
response-action correlation fields, including response action ID, delivery ID, target kind/id,
control acknowledgement status, resulting state, and a hash of the control acknowledgement token
without storing that token raw. Omitted control acknowledgement status defaults to `rolled_back`
for rolled-back terminal transitions, `expired` for expired transitions, `failed` for failed
executions, and `acknowledged` otherwise. The local agent rejects unsupported acknowledgement
status and target-kind values before appending the acknowledgement or signing the receipt, and
returns fixed allow-list errors instead of echoing those raw discriminator values. When the acknowledgement
control block includes an explicit Control API base URL/token, or agent settings define
`control_api.enabled: true` with a Control API URL, the local agent also attempts Control API
acknowledgement postback. It uses
the authenticated
`/api/v1/response-actions/{id}/acks` route with `x-api-key` when an API key is configured, otherwise
it uses the bearerless `/api/v1/response-actions/{id}/agent-acks` route authorized by the delivery
acknowledgement token. The Control API acknowledgement parser bounds target ID, acknowledgement
token, message, resulting-state, observed-at timestamp, and raw-payload fields before delivery
lookup or persistence.
The Control API response-action create validator bounds action type, target kind/ID, reason, and
JSON payload before target resolution or persistence, and create/target/acknowledgement request
bodies reject unknown top-level fields instead of silently dropping them. Unsupported
response-action, target-kind, and acknowledgement status errors return fixed allow-list messages
instead of echoing raw caller values.
The local agent also rejects unknown fields on state-changing EDR maintenance and response-proof
request bodies covering causal subgraph/context/search proofs, graph-slice export,
policy-event replay/impact and history replay/impact, policy-simulation/replay, privacy reports,
agent-secret-touch queries, detection-candidate generation, staged detection and policy-delta
generation, policy-delta apply, NetworkExtension egress proofs, acknowledgement/archive retry and
backfill, fleet-hunt retry, archive verification, evidence/flight-recorder/receipt compaction, and
deception plan materialize/cleanup/rotation inputs. Graph-root process selectors on causal
subgraph/context, graph-slice export, policy-simulation/replay, detection-candidate/staged
detection, and response-action requests also reject unknown nested fields, so misspelled operator
intent is not silently ignored before receipts or side effects are produced. Receipt-producing
graph proof, policy simulation/replay, policy-event history impact, detection staging, and
agent-secret-touch routes now reject graph depths above the local maximum instead of silently
clamping the requested evidence scope. POST-body `limit` fields for graph search,
agent-secret-touch lookup, fleet hunt retry, and Control API acknowledgement/archive retry or
backfill also reject out-of-range values instead of silently shrinking the requested operation
scope. Active provider acknowledgement/refresh timeout fields on policy-delta apply and
NetworkExtension egress proof requests likewise reject `0` and values above 5000 ms, so provider
confirmation windows cannot be quietly disabled or capped.
The authenticated agent settings route now rejects unknown top-level and nested settings fields,
applies updates through an all-or-nothing validated settings snapshot, bounds local API token/mTLS
security values, and validates URL-bearing dashboard, OTA manifest, and Control API settings before
persistence. Control API and OTA manifest settings require HTTPS except for loopback HTTP, and URL
userinfo is rejected. Notification severity and OTA mode/channel/check-interval settings also use
explicit allow-lists or bounds instead of being silently normalized by runtime loops.
Enrollment now persists the normalized Control API URL into local settings for that bearerless path.
Local acknowledgement responses do not return Control API credentials.
Failed postbacks are written to a private local retry queue at
`~/.config/clawdstrike/edr/control-ack-postback-retries.json` with bounded backoff; the queue
temporarily stores the raw delivery acknowledgement token because both Control API postback routes
need that token, but local receipts and local API responses remain token-redacted. The authenticated
local `POST /api/v1/agent/edr/control-ack-postbacks/retry` route drains due entries, removes
delivered entries, and requeues failures with bounded backoff. The agent also runs the same due-entry
drain on a scheduled background loop, so queued acknowledgements do not require an operator-triggered
retry after temporary Control API outages clear.
Causal-subgraph, causal-context, graph-search, and explicit graph-slice exports also emit signed
`graph_slice` receipts that bind root node, graph slice ID, slice kind, graph content hash, node
count, and edge count. Validation rejects roots outside the receipt graph node set and graph-slice
IDs that do not match the root plus graph counts.
Explicit graph-slice exports store the slice as a local evidence-bundle artifact so it can be
retrieved by bundle ID later without coupling the artifact to a response execution.
Agent-secret-touch and finding-group queries use that same receipt family for each returned
credential-access or grouped-alert graph slice. Deception materialization emits its own signed
receipt before later honey-touch detections fire.

This is still not full receipt coverage. Bounded local response execution receipts now cover the
implemented containment/destructive action families and failed live attempts, bind hashed effect-type
evidence for each execution, rollback, and acknowledgement effect so the signed action family cannot
be relabeled across effect classes, and receipt lookup can filter by family, action,
finding/rule/graph/root identifiers, receipt ID, execution ID, execution status, local sequence, and
actor endpoint/user/session/agent/workload/approval fields through a private sidecar JSONL index
that stores receipt filter fields plus ledger byte offsets and is rebuilt from the local receipt
ledger when missing, stale, or mismatched with selected ledger receipts. Local policy-delta apply now
rejects stale target epochs instead of downgrading a newer local policy, and endpoint policy-cache
sync records a hash/epoch/source manifest while rejecting epoch downgrades or same-epoch content
mutation. Control API tenant policy deployment, heartbeat reconciliation, and enrollment backfill now
resolve each agent's effective policy from the tenant active policy plus matching tenant, swarm,
project, capability-group, and principal overlays before distributing KV YAML, stamp that distributed
payload with a monotonic `policy_epoch`, and agent NATS KV policy sync writes a local hash/epoch
manifest while rejecting missing-epoch updates, epoch downgrades, or same-epoch content mutation.
Control API also exposes a non-persistent policy preview path for policy authors that validates
proposed YAML, computes the would-deploy policy epoch, and, when given an agent, compiles the
candidate against that agent's directory-scoped overlays without writing tenant policy, NATS KV, or
legacy broadcasts. Write-scoped policy authors can now submit durable policy proposals without
mutating fleet state; viewers can inspect proposals; and admin/owner review can reject or approve a
still-current proposal. Deployment is gated on the proposal's multi-approver threshold, defaults to
two distinct non-submitter admin/owner approvers, rejects duplicate approvals, and then uses the
same effective-policy KV distribution path.
Proposal records retain generated preview evidence including base/proposed policy versions, hashes,
distribution epoch/hash, top-level YAML change summary, and an automatic control-plane fleet
history impact estimate from recent signed hunt events with sampled-event count, candidate breakage
count, blocking-event count, affected identity/tool/endpoint counts, verdict counts, top action and
detection drivers, recommendation, and a hash of the estimate. Proposal preview also produces a
deterministic fleet rule-diff validation plan from recent hunt history: selected endpoints, selected
event counts, endpoint history windows, top action/detection drivers, the exact local
`/api/v1/agent/edr/policy-events/impact/history` request body including proposed policy YAML, and
the signed endpoint impact receipt contract expected back from each endpoint.
Pending proposal records can also retain hash-bound impact evidence attached by a policy author,
including source, summary, simulation receipt/proof hashes, changed/blocking verdict counts,
developer-breakage score, affected identity/tool counts, and recommendation. When the author
attaches an exact signed endpoint policy-event impact receipt, Control API verifies the receipt
signature against the supplied Ed25519 public key, requires the endpoint-decision metadata to be a
`simulation` receipt for `endpoint.policy_event_impact` over the `policy_event_stream` pseudo-node,
requires the canonical impact evidence keys, computes the canonical signed-receipt SHA-256 itself,
and stores the verified receipt body plus binding metadata on the pending proposal. It can now bind
a bounded batch of verified endpoint impact receipts in one proposal attachment, reject duplicate
signed-receipt hashes, and retain aggregate fleet proof metadata including distinct endpoint count,
receipt hashes, endpoint IDs, and per-receipt signed bodies.
Control API can now dispatch that generated fleet rule-diff plan through the durable
`response_actions` ledger as `policy_rule_diff_validation` endpoint actions, publish signed NATS
response-command payloads per selected endpoint, require the existing acknowledgement token on
agent postback, and collect acknowledged `policyRuleDiffValidation` payloads into verified
fleet-history proposal impact evidence without a manual attachment step. The agent now subscribes
to the canonical endpoint response-action subject, verifies the signed response-command envelope
against its configured trusted issuer, binds the command `tenantId` to the enrolled NATS tenant,
rejects expired or non-acknowledgement-enabled rule-diff commands, restricts
`policy_rule_diff_validation` execution to the expected local impact-history POST path for its own
endpoint ID, calls the local agent API over loopback, and posts the exact
`policyRuleDiffValidation` acknowledgement payload back to the Control API using the delivery ack
token. A loopback regression test now exercises the local impact-history POST plus bearerless
Control API `agent-acks` postback contract. If that postback fails after local execution, the agent
writes the same acknowledgement payload and raw delivery ack token into the existing private
bounded-backoff Control API acknowledgement retry ledger, and the scheduled agent retry loop drains
due entries with the same delivery contract, so completed rule-diff validations are not lost during
temporary Control API outages. A gated live NATS dogfood test now exists for the same path and can
be run with `CLAWDSTRIKE_LIVE_NATS_URL`, `CLAWDSTRIKE_LIVE_NATS_TENANT_ID`,
`CLAWDSTRIKE_LIVE_NATS_AGENT_ID`, and `CLAWDSTRIKE_LIVE_NATS_SUBJECT_PREFIX` set, plus one of the
supported NATS auth inputs, using
`cargo test --manifest-path apps/agent/src-tauri/Cargo.toml live_nats_response_action_command_executes_and_acknowledges -- --ignored --nocapture`.
That live enrolled-agent NATS exercise remains unclosed until it is run against a real NATS
deployment.
The local bundle store and flight recorder now have bounded retention-compaction paths, and evidence
bundles can be exported as hash-addressed local archive packages with local graph/receipt
verification metadata. Control API also has an approved raw endpoint-evidence archive upload,
metadata, download, audit, and case-attachment path.

### 2.7 Fleet detection, hunt, response, cases, and evidence

`crates/services/control-api` already has database migrations and routes for the operator control
plane:

- `010_detection_core.sql`
- `011_response_actions_and_execution_ledger.sql`
- `012_hunt_backend.sql`
- `013_case_evidence_bundles.sql`
- `014_grants_delegation_graph.sql`
- `015_response_action_case_links.sql`

`crates/services/control-api/src/routes/response_actions.rs` supports response action creation,
approval, cancellation, retry, and acknowledgement. The current action types include posture
transition, policy reload request, session termination, kill switch, principal quarantine, grant
revocation, and principal revocation.

This is valuable, but it is currently more cloud/operator-control-plane oriented than local
endpoint containment.

### 2.8 Identity and agent context

The repo already has multiple identity surfaces:

- `PolicyEvent::to_guard_context()` enriches guard context with session, agent, identity,
  organization, request, origin, roles, and permissions metadata.
- `crates/services/hushd/src/identity/**` provides daemon identity functionality.
- `crates/services/control-api/src/models/delegation_graph.rs` models grants, delegation lineage,
  exercise events, and revocation.
- `crates/bridges/darwin-telemetry-bridge/src/lib.rs` can inject SPIFFE workload identity into
  emitted facts.

This is enough to specify identity-aware enforcement without inventing a new identity model.
The local agent now uses part of that model for response proofing: response request, execution,
rollback, and acknowledgement receipts include current session/posture actor context, and the
receipt validator fails closed if response-family receipts lack accountable actor context (user,
session, agent, workload, or approval) beyond endpoint ID. Response execution proof retrieval now
revalidates the embedded endpoint-decision contract for every selected proof receipt and rejects
signed wrappers whose content hash or receipt ID no longer bind to that contract. The local causal
graph now also promotes host, user, session, agent, workload, and approval context into explicit
attribution nodes, so graph search can start from an agent/session/workload identity and walk
downstream to the responsible process, tool call, credential access, network flow, or DNS
lookup. It does not yet bind OS user, workload identity, approval IDs, or fleet-side delegation
lineage into every endpoint decision path.

### 2.9 AI-agent and developer-workstation protection

The repo already has an unusually strong wedge for developer workstations:

- agent/tool policy guards in Rust and TypeScript
- MCP/tool-call event modeling
- Cursor plugin hooks and receipts in `cursor-plugin/**`
- `rulesets/ai-agent.yaml` and `rulesets/ai-agent-posture.yaml`
- local agent API for policy checks and EDR findings
- secret-broker planning and implementation surfaces under `docs/plans/clawdstrike/secret-broker/**`
- package-manager lifecycle ingestion, package-script detections, and credential-access detection
  primitives in `edr.rs`

That makes AI-agent/developer-workstation EDR a better first product wedge than a broad commodity
EDR claim.

## 3. Current Gaps

| Requirement | Current status | Gap |
| --- | --- | --- |
| Causal graph flight recorder | JSONL-backed local recorder, graph projection, durable graph-node sidecar prefiltering including exact path, path-prefix, and anchored path-pattern lookup, graph-edge sidecar adjacency expansion for file-backed graph search and causal-context queries, durable sidecar history index for timestamp/event-kind/identity-filtered replay windows including parent-process-guid, process-image-hash, process-command-line-hash, credential-kind, event-target, and event-target-hash selection, direct endpoint-observation ingestion including first-class DNS lookup observations, dedicated package-manager lifecycle script observations, EndpointSecurity process/file/auth observations, and NetworkExtension DNS/flow-verdict/decision observations, validated `PolicyEvent` JSON and JSONL local API ingestion, downstream subgraph query, upstream/downstream causal-context query, bounded graph search by node kind/label/path/path-prefix/path-pattern/session/user/agent/workload/approval/attribute with durable graph-node or in-process kind/path/path-prefix/path-pattern/attribute candidate indexing and query-plan metadata, explicit local graph-slice export storage, dry-run-first evidence-bundle retention compaction, dry-run-first receipt compaction, dry-run-first receipt-protected flight-recorder compaction, endpoint-local agent-secret touch query, and NATS hunt-event publish/consume seam for selected graph facts including best-effort auto-publish from current credential-access ingestion and bounded periodic flight-recorder sync exist | Needs automatic streaming import from all sensors, broader sensor-backed ingestion, and more scalable graph storage/query planning beyond sidecar indexes |
| Deep OS sensors | Darwin bridge and macOS ES/NE scaffolding exist, provider state/degradation/recovery can now be signed into local receipts, delivered EndpointSecurity process/file/auth/event-loss events can be ingested into endpoint observations with per-observation receipts and event-loss/deadline/FDA degradation receipts, delivered EndpointSecurity file events can match registered honey files, and delivered NetworkExtension content-filter events can be ingested as DNS lookup, network-flow, and policy-decision observations with per-observation receipts plus registered honey-hostname DNS/flow matching when provider DNS fields are present | Need verified ES/NE event coverage, Linux/Windows parity strategy, and deployed provider recovery validation |
| Evidence receipts | `hush-core` signing exists, and provider-originated ES/NE observations, protection-state captures, provider degradations, detection findings, graph-aware policy simulations, staged policy-delta generation, dry-run response requests, post-apply policy-delta enforcement proofs, collect-evidence executions, failed live response attempts after planning, collect-evidence expiration sweeps, collect-evidence cancellation transitions, deception materialization, cleanup, and rotation, constrained agent-mediated egress restriction, constrained file quarantine, constrained persistence-file disable, constrained local API grant revocation, constrained broker-capability revocation with brokerd provider-token revocation report binding when present, constrained Unix process-tree suspend with terminate limited to dry-run modeling only, generic response rollback, and response acknowledgement now produce signed local `EndpointDecisionReceipt` records with bounded local lookup by family/action/finding/rule/graph/root metadata plus receipt ID, execution ID, execution status, actor endpoint/user/session/agent/workload/approval, and local-sequence filters backed by a private sidecar JSONL receipt index with byte offsets and stale/missing/corrupt/unknown-field index rebuild from the signed ledger, explicit policy-bundle epoch preference with mtime fallback, endpoint policy-cache hash/epoch/source manifests with anti-downgrade and same-epoch mutation rejection, Control API KV policy distribution of directory-scoped effective policies stamped with monotonic `policy_epoch`, non-persistent Control API policy preview for proposed tenant YAML and agent effective-policy overlays, durable policy proposal submit/reject/approve-deploy flow with generated version/hash/diff preview evidence, automatic fleet-history impact estimates, fleet rule-diff endpoint selection/request plans, response-action dispatch for signed endpoint rule-diff validation, endpoint-side signed-command execution over the local impact-history route, ack-token-bound collection of endpoint policy-event impact receipts, signed endpoint policy-event impact receipt verification/binding for pending proposals, bounded multi-endpoint receipt-batch binding for fleet rule-diff impact attachments, authenticated dry-run-first local upload of filtered signed endpoint receipts to the Control API `/receipts/batch` store with exact signed receipt bodies, automatic best-effort Control API receipt upload after local signing with private bounded retry queue plus scheduled/local retry drain, approved raw endpoint-evidence archive upload/download/audit/case attachment, hash-bound attached impact evidence, and two-approver default deployment gating, agent KV policy-sync manifests with missing-epoch/downgrade/same-epoch-mutation rejection, stale policy-delta target epoch rejection, response-execution sensor state binding for agent API, EndpointSecurity, and NetworkExtension providers, optional hashed control-plane acknowledgement correlation, and dry-run-first receipt compaction | Need deployed-provider dogfood and broader provider-originated receipt coverage beyond current ES/NE ingress observations |
| Policy simulation | Event replay/impact commands exist, and the local agent can now score persisted causal graph slices for proposed blocking rules, replay captured graph targets under the current local policy version/hash/epoch with signed simulation receipts, replay supplied `PolicyEvent` JSON/JSONL streams under the current local policy with per-event decisions and signed event/result hashes, compare supplied `PolicyEvent` streams between current and proposed policy YAML with changed-verdict counts and signed impact receipts, replay/impact durable flight-recorder history through sidecar-indexed time-window/age/limit/event-kind plus host/user/session/process/parent-process-guid/process-image-hash/process-command-line-hash/agent/workload/approval/tool/tool-call/credential-kind/event-target/event-target-hash selection, return guard/reason driver summaries for changed impact events, partition selected history-impact results into validation windows with per-window changed/blocking counts and conservative rollout recommendations, join history-impact changes back to bounded causal graph contexts with affected identity/tool counts, blocking-change count, developer-breakage score, impact level, top breakage drivers with workflow categories, affected identities, affected tools, ordered root-to-target chains, aggregate causal-chain driver summaries, and signed graph-slice receipts, provide audit-stage promotion suggestions into the existing candidate/staging endpoints, generate staged detection candidates from graph roots, persist selected staged-detection state locally with the signed simulation receipt and optional cross-window proof hashes, promote staged detections into signed local policy-delta overlays whose artifact, generated patch, receipt evidence, and dry-run/live apply response records preserve source affected identity/tool context plus cross-window proof hashes, dry-run/apply those overlays to the configured local policy file with hash guard, backup, default daemon reload request, optional daemon restart, signed post-apply protection-state proof, direct status-collector refresh request, and bounded provider policy-epoch acknowledgement polling, expose the candidate/stage/delta/dry-run-first live apply promotion flow in Control Console with validation-window proof hashes, post-apply proof family visibility, policy-sync status, aggregate provider acknowledgement, and per-provider acknowledgement state, and dispatch/execute/collect fleet rule-diff validation receipts for pending Control API policy proposals | Need higher-cardinality indexes beyond the current history sidecar selection, deployed-provider dogfood for reload delivery, and a live enrolled-agent NATS exercise of the new response-command path |
| AI-agent and developer protection | Strong policy/event/tool surfaces, typed `PolicyEvent::SecretAccess` conversion for common developer credentials, validated local API ingestion for `PolicyEvent` JSON and JSONL submissions, normalized local developer-activity mappings for MCP tools, browser automation/download/extension events, DNS lookups, direct network egress, file read/write, patch apply, persistence-change facts, package scripts, cloud CLIs, shell commands, repo secrets, CI tokens, local API keys, and browser cookies, dedicated local package-manager lifecycle ingestion for `package_script` observations and supply-chain findings with extended manager values for Composer/Maven/Gradle/uv/Poetry/Pipenv/.NET/NuGet/SwiftPM/Mix, adapter-core npm/pnpm/yarn/Bun lifecycle hook publishing into that dedicated ingress plus explicit pip/Cargo/RubyGems/Go/Homebrew/Composer/Maven/Gradle/uv/Poetry/Pipenv/.NET/NuGet/SwiftPM/Mix wrapper metadata for language-package lifecycle hooks, adapter-core repo-scanner credential-finding publisher and bounded local repository scanner for raw-value-omitting `repo_secret`/`ci_token`/`local_api_key`/`browser_cookie` developer-activity facts, adapter-core CI-agent environment publisher and `clawdstrike-ci-env` executable for raw-value-omitting `ci_token` developer-activity facts from GitHub Actions/GitLab CI/Buildkite/CircleCI/Azure Pipelines/Bitbucket Pipelines/Jenkins/TeamCity/Travis CI/Drone CI/Semaphore CI/AppVeyor/Woodpecker CI/Codefresh token context, adapter-core browser-runtime publisher for raw-body-omitting browser automation/download/extension developer-activity facts, automatic adapter-core CUA `PolicyEvent` enrichment into scrubbed `browser_automation` developer activity for shared Claude/OpenAI-style tool boundaries with file-transfer metadata preservation for `browser_download` enrichment, adapter-core shell/file classification for ClawdStrike-specific standard honey artifact paths so registered honey artifacts can trigger deception detections from agent activity, adapter-core shell hostname classification for `dns_lookup` facts from network utilities with planted-hostname deception hints, bundled MCP `policy_check` and Claude Code hook best-effort developer-activity telemetry for tool calls and credential-like path targets, MCP shell classification for package-manager lifecycle, package-registry token commands, and sensitive cloud/developer-platform CLI commands covering the current first-pass CLI set, opt-in adapter-core scrubbed `PolicyEvent` telemetry plus normalized package-manager/package-registry-token/cloud/developer-platform CLI command facts and hashed inbound prompt-decision events for shared Claude/OpenAI/OpenCode/LangChain-style tool boundaries, Vercel AI prompt-security custom EDR events, OpenClaw CUA bridge best-effort browser automation/download telemetry, OpenClaw inbound-message hashed prompt-decision telemetry, pure package-registry token command detection for npm token/config auth-token operations, pure cloud CLI sensitive-operation detection including GitHub CLI secret/auth/variable operations, Vercel env operations, Netlify env operations, Cloudflare Wrangler secret operations, DigitalOcean doctl registry/kube credential operations, Fly secrets/token operations, 1Password `op` item/document/reference reads, Bitwarden `bw` item reads, HashiCorp Vault reads/token creation, Doppler secret downloads/config tokens, Heroku config access, Supabase secrets, Firebase Functions Secrets, Railway variables, Stripe CLI API-key and webhook-signing-secret commands, Sentry/Snyk auth tokens, AWS/GCP/Azure credential and kubeconfig operations, Kubernetes Secret/kubeconfig reads, Pulumi `--show-secrets` config reads, CircleCI context secret / runner-token operations, GitLab `glab` CI/CD variable operations, Buildkite secret operations through `buildkite-agent`/`bk`, Drone/Semaphore/AppVeyor/Woodpecker/Codefresh CI secret or token operations, and Terraform/Terragrunt/OpenTofu state/output/login operations, general local graph search for host/user/session/agent/workload/approval/tool/credential/network/DNS nodes, an endpoint-local query path for agent/tool-caused credential access, a local NATS publish route for those facts, best-effort auto-publish for current credential-access observations on the local ingestion path, bounded periodic flight-recorder sync for unpublished agent-secret-touch facts, a control-api NATS consumer that persists endpoint-published hunt events through signed ingest, and a control-api query over signed hunt events for agent secret touches grouped by endpoint/runtime/principal exist | Need browser-runtime-specific adapters to call the shared publisher across more runtimes, native automatic package-manager hooks beyond explicit wrapper metadata and shell classification, additional cloud/developer-platform CLIs beyond the current first-pass CLI set, plus broader automatic upload from sensor/recorder paths beyond selected agent-secret-touch graph facts |
| Local-first protection | Local agent API exists with JSONL flight recording, local receipt history, response execution ledgers, local policy-delta application with backup, default daemon reload request, optional daemon restart, post-apply protection-state receipts, direct status-collector refresh requests, bounded provider policy-epoch acknowledgement polling, provider-reported NetworkExtension reload observation, and several bounded live response executors | Need indexed local persistence, deployed NetworkExtension reload/enforcement dogfood, cloud-optional enrichment semantics, and broader live response coverage |
| Identity-aware enforcement | Identity context and delegation graph exist, local policy/response receipts now bind current session, posture, agent, workload, policy epoch, and endpoint identity where available, `PolicyEvent` ingestion now preserves endpoint/principal/agent/workload/approval aliases from metadata and bounded context fields into observations, graph attributes, receipt actors, and explicit host/user/session/agent/workload/approval attribution graph nodes, and adapter-core developer-activity facts now carry host/user/session/agent/workload/approval identity plus policy and tool-call correlation metadata | Need OS user/workload/approval/delegation lineage binding across all remaining endpoint decisions and fleet-side correlation |
| Safe autonomous response | Response action ledger exists, local agent can produce dry-run response plans with graph target, affected identity/tool summaries, TTL, rollback ref, and receipt, requires explicit actor identity before non-dry-run local response execution, can execute non-destructive collect-evidence with a signed execution receipt that binds current provider state, can retrieve a per-execution proof package that joins the execution record, graph reference, affected identity/tool summaries derived from the stored evidence-bundle graph, provider state, response-request receipt, response-execution receipt, evidence-bundle manifest receipt, and any later signed cancellation/expiration transition, rollback, or acknowledgement receipts for the same action contract, can mark expired executions with a signed receipt, can roll rollback-capable side-effect actions back during TTL expiration before recording the expired transition, scopes terminal response transitions to the concrete execution entry so a later reissued deterministic action contract is not blocked by an older rollback/cancellation, can cancel active collect-evidence windows or active restrict-egress restrictions with a signed receipt while rejecting cancellation for rollback-capable file/persistence/process side effects, can execute constrained agent-mediated egress restriction and project its active host:port set into a provider-loadable NetworkExtension policy snapshot, can request the macOS host collector to persist a NetworkExtension reload vendor configuration after snapshot sync and bind the reload requested/saved/request-id/generation outcome into the signed response-execution receipt, can handle observed reload vendor configurations in the content-filter provider, can sign a local proof that the NetworkExtension egress snapshot is present, decodable, hashed, tied to current provider status, annotated with observed/blocked flow counters, remediation-request count, dropped-verdict count, plus a signed flow-counter-observed bit, and can match that proof against the provider-observed reload request/generation/snapshot path when given an execution ID, can execute constrained file quarantine and constrained LaunchAgent/LaunchDaemon/systemd-user/systemd-system/systemd-drop-in/xdg-autostart/kde-plasma-env/kde-autostart-script/shell-startup/system-profile-drop-in/user-crontab/system-cron-drop-in/browser-extension-manifest persistence disable with signed effect receipts tied to current provider state, can execute constrained local API grant revocation with immediate token rotation and signed effect receipt tied to current provider state, can execute constrained broker-capability revocation through local `clawdstrike-brokerd` with signed effect receipt binding for supported brokerd provider-token revocation reports, can execute constrained local integration-secret revocation for agent-owned SIEM API key / webhook signing-secret settings from explicit structured graph attributes or credential label/name/path evidence with a signed effect receipt, can suspend/resume or terminate a constrained Unix process tree with signed effect receipts tied to current provider state, can roll egress, file-moving, and process-suspend actions back with signed receipts, and can acknowledge local response executions with a signed receipt plus local acknowledgement ledger entry that can bind control response-action/delivery IDs and hashed acknowledgement tokens, attempt explicit, settings-backed, or enrollment-derived bearerless Control API postback without leaking Control API credentials in local responses, and durably retry failed Control API acknowledgement postbacks through a private bounded-backoff local queue | Need deployed macOS enforcement proof for NetworkExtension reload/flow blocking, first-class provider-specific third-party-token revocation beyond brokered GitHub/Slack/configured Generic HTTPS token revocation, and broader persistence control beyond bounded launch/systemd-user/systemd-system/systemd-drop-in/xdg-autostart/kde-plasma-env/kde-autostart-script/shell/profile-d/cron/system-cron-drop-in/browser-extension manifest files |
| Endpoint deception | Deception plan, honey files, local honey artifact registration, dry-run-first registered-file cleanup, first-class dry-run-first rotation, honey-touch detection, honey-hostname flow and DNS lookup detection, browser-cookie honey-value detection, materialization receipts, cleanup receipts, and rotation receipts exist in the local model/API path, and delivered EndpointSecurity/NetworkExtension observations can match registered honey artifacts without resubmitting the plan | Need deployed sensor-provider dogfood that proves automatic ES/NE event emission, recovery behavior, and fleet correlation |
| Supply-chain runtime guard | Pure detections cover risky package scripts, unsigned/unnotarized writable-path binaries, code-signature drift, package-manager DYLD injection, writable-path dylib loads, LaunchAgent/LaunchDaemon changes, unmanaged browser extensions, developer credential access, package-registry token CLI operations for npm token/config auth-token commands, and sensitive cloud/developer-platform CLI operations including GitHub CLI secret/auth/variable operations, Vercel env operations, Netlify env operations, Cloudflare Wrangler secret operations, DigitalOcean doctl registry/kube credential operations, Fly secrets/token operations, 1Password `op`, Bitwarden `bw`, HashiCorp Vault, Doppler, Heroku, Supabase, Firebase Functions Secrets, Railway variables, Stripe CLI API-key and webhook-signing-secret commands, Sentry/Snyk auth tokens, AWS/GCP/Azure credential and kubeconfig operations, Kubernetes `kubectl`, Pulumi secret/config operations, CircleCI context secret / runner-token operations, GitLab `glab` CI/CD variable operations, Buildkite `buildkite-agent`/`bk` secret operations, Drone/Semaphore/AppVeyor/Woodpecker/Codefresh CI secret or token operations, and Terraform/Terragrunt/OpenTofu state/output/login operations; the local agent now has a dedicated package-manager lifecycle route that emits `package_script` observations, detections, receipts, and graph nodes from manager/package/phase/script records, accepts extended manager values for Composer/Maven/Gradle/uv/Poetry/Pipenv/.NET/NuGet/SwiftPM/Mix, and adapter-core ships a best-effort npm/pnpm/yarn/Bun lifecycle hook plus explicit pip/Cargo/RubyGems/Go/Homebrew/Composer/Maven/Gradle/uv/Poetry/Pipenv/.NET/NuGet/SwiftPM/Mix lifecycle metadata contract and shell command classifiers that feed redacted script content | Need native automatic package-manager hooks beyond explicit wrapper metadata and shell classification, broader cloud/developer-platform CLI telemetry beyond the current first-pass CLI set, and fleet-side correlation |
| Privacy-preserving telemetry | OCSF and normalized events exist, and the local agent now exposes privacy reports with hash/feature defaults, local-only raw artifact suppression, policy-plus-approval-gated raw-artifact-permitted mode, signed `privacy_report` receipts that bind raw approval evidence when raw values are permitted, local receipt lookup for privacy reports by family/report ID, Control Console surfacing for distinct redacted/local-only/hash-only/metadata/raw-permitted projection labels, raw-suppressed counts, hashes, feature projections, raw policy/approval state, and raw-permitted values when policy and approval allow them, plus raw endpoint archive upload/backfill paths that require approval ID/reason evidence before retaining archive bodies in Control API | Need broader privacy-mode audit workflow and end-to-end fleet policy for when raw archive retention may be authorized |
| Operator workflows | Control console, workbench, desktop surfaces exist, the local API can group recent findings by causal graph context with affected host/user/session/agent/workload/approval and tool summaries, and retrieve per-execution proof-at-execution packages. Control Console now has `Causal Groups`, `Process Cause`, `Policy Replay`, `Rule Impact`, `Local Containment`, `Agent Secret Touches`, `Proof at Execution`, `Privacy Report`, and `Fleet Cases` tools that surface graph evidence, policy/simulation/response/privacy receipt families, grouped alert identity/tool attribution, staged policy deltas, rollback state, signed response-execution NetworkExtension reload-request evidence hashes, NetworkExtension egress proof hashes, provider flow counters, execution-matched provider reload delivery proof, fleet-publishable credential-touch hunt evidence, proof-package verification, signer and actor identity/hash continuity, distinct healthy/stale/missing/degraded provider-state labels, distinct privacy projection labels, raw archive approval evidence, approved raw archive fleet publish/backfill controls, filtered case navigation, single-case and bulk case status changes, case artifacts/timeline, signed case evidence bundles, and JSON evidence exports | Needs broader live-agent dogfood across stale, missing, degraded, and privacy-redacted states; no missing required Phase 6 workflow surface is currently tracked |

## 4. Sharp Conclusion

The repo is closest to a defensible **developer-workstation decision engine**:

- agent/tool activity is already modeled
- local policy decisions already exist
- endpoint observations and causal graph primitives already exist
- package-manager and credential-access risks are already represented
- deception artifacts already have a pure model
- signed evidence primitives already exist

The repo is not yet a complete EDR because sensor coverage, durable graph storage, local response
execution, and endpoint receipt schemas are still incomplete. The next wave should integrate the
existing primitives around the local agent and macOS provider work rather than starting another
dashboard or generic SIEM connector.
