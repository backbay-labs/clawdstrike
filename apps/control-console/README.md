# ClawdStrike Control Console

React SPA for managing ClawdStrike security policies, viewing audit logs, and monitoring agent enforcement.

The desktop includes a `Proof at Execution` operator tool that loads recent local response
executions, fetches `/api/v1/agent/edr/response-executions/{execution_id}/proof`, and displays
policy epoch, provider health, distinct healthy/stale/missing/degraded provider states, graph
metadata, ledger paths, and receipt-chain families, including terminal transitions, rollbacks, and
acknowledgements. Operators can verify the displayed receipt-chain signatures and export either the
loaded proof package or a single verification verdict object as JSON for incident handoff or offline
review. The view also cross-checks signer continuity, action ID, execution ID, bundle ID, action type,
graph-slice bindings, response actor identity/hash continuity, acknowledgement actor binding, and
the receipt evidence hashes for action, execution, bundle, graph, content, and count values across
the API-joined proof package.

The desktop also includes a `Privacy Report` operator tool that posts endpoint observations to
`/api/v1/agent/edr/privacy-report`, displays the effective telemetry privacy mode, raw-artifact
upload decision, signed `privacy_report` receipt family, distinct redacted/local-only/hash-only/
metadata/raw-permitted projection labels, value hashes, feature projections, raw-permitted values
when policy allows them, and raw-suppressed/local-only counts, and exports the report package as JSON.

The desktop also includes a `Causal Groups` operator tool that fetches
`/api/v1/agent/edr/finding-groups`, displays grouped findings by causal graph root, rule IDs,
finding IDs, graph node kinds, node/edge counts, and signed `graph_slice` receipt family, and
exports a selected group as JSON.

The desktop also includes a `Process Cause` operator tool that calls
`/api/v1/agent/edr/causal-subgraph`, `/api/v1/agent/edr/causal-context`, and
`/api/v1/agent/edr/graph-slices/export` to show downstream process effects, upstream/downstream
context, graph nodes and edges, signed graph-slice receipt metadata, persisted evidence-bundle
references, artifact paths, content hashes, and graph-slice JSON exports.

The desktop also includes a `Policy Replay` operator tool that calls
`/api/v1/agent/edr/policy-replay` to replay a captured graph root or process under the current local
policy, display policy version/hash/epoch, enforcement action, impact level, developer-breakage
score, affected nodes, graph node kinds, simulation receipt family, and export the replay package as
JSON.

The desktop also includes a `Rule Impact` operator tool that calls
`/api/v1/agent/edr/detection-candidate`, `/api/v1/agent/edr/staged-detections`,
`/api/v1/agent/edr/policy-deltas`, and
`/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply` to generate a graph-backed candidate
rule, inspect staged rollout gates and blast radius, persist a selected stage, promote it into a
signed `policy_delta` overlay, dry-run the policy-bundle apply, execute the dry-run-gated live
apply, and surface validation-window proof hashes, the post-apply `sensor_state` proof family,
policy-sync status, aggregate provider acknowledgement, and per-provider acknowledgement state.

The desktop also includes a `Local Containment` operator tool that calls
`/api/v1/agent/edr/response-action`, `/api/v1/agent/edr/response-executions`, and
`/api/v1/agent/edr/response-executions/{execution_id}/rollback` to dry-run or execute TTL-bound
local response plans, display rollback references, graph-slice evidence, recent execution state,
response-request receipts, signed response-execution receipt family, NetworkExtension reload
request evidence hashes, rollback effects, and signed `response_rollback` receipts. It can also
request `/api/v1/agent/edr/network-extension/egress-policy/proof`, show the generated egress-policy
snapshot hash, `sensor_state` receipt family, enforcement-ready state, observed/blocked flow
counters, remediation-request count, dropped-verdict count, provider-observed reload request
details when reported, execution-matched reload delivery proof when an execution is selected, and
provider IDs, then export the containment and proof package as JSON.

The desktop also includes an `Agent Secret Touches` operator tool that calls
`/api/v1/agent/edr/agent-secret-touches` and
`/api/v1/agent/edr/agent-secret-touches/fleet-publish` to filter credential touches by session,
credential kind, graph depth, and agent-context requirement, display agent/process graph evidence
and signed `graph_slice` receipts, publish selected touches into fleet hunt events, and export the
local/fleet evidence package as JSON.

The event detail drawer recognizes endpoint evidence archive hunt events, fetches retained archive
metadata from `/api/v1/hunt/evidence-bundle-archives/{archive_id}`, attaches that metadata to
incident evidence exports, and can export retained raw archives from
`/api/v1/hunt/evidence-bundle-archives/{archive_id}/download` for case handoff when the operator
has admin or owner credentials; raw uploads require admin API-key credentials, and successful raw
uploads/downloads plus denied raw-body attempts create sanitized compliance audit events. It can
load remote cases from `/api/v1/cases`, attach the archive as an
`endpoint_evidence_archive` artifact to a selected case via `/api/v1/cases/{case_id}/artifacts`, or
create a new archive-focused remote case and attach the artifact immediately. The drawer can also
load selected case detail and timeline from
`/api/v1/cases/{case_id}` plus `/api/v1/cases/{case_id}/timeline`, and request a signed case
evidence bundle through `/api/v1/cases/{case_id}/evidence/export`, then download the completed
bundle from `/api/v1/evidence-bundles/{export_id}/download`.

Compliance exports from `/api/v1/compliance/export` include sanitized audit metadata in JSON, CSV,
and CEF output so retained raw-archive access decisions carry archive IDs, actor roles, denied
reasons, and retention context without embedding raw archive bodies. The same export path carries
case evidence-bundle custody events with sanitized bundle IDs, case IDs, digests, sizes, counts, and
actor metadata.

The desktop also includes a `Fleet Cases` operator tool that lists remote cases, queries
text/status/severity filters through the Control API, creates new investigation cases, updates
selected case status, bulk-transitions selected cases through lifecycle statuses, loads selected case
artifacts and timeline events, exports signed case evidence bundles with raw references and related
sanitized raw-archive audit trails, and downloads completed bundle archives. Bundle metadata and ZIP
downloads follow the export boundary, reject viewer credentials, and record sanitized denial audit
events; successful export creation, metadata reads, and completed ZIP downloads also record
sanitized bundle ID, case ID, digest, size, count, and actor metadata, while denied bundle creation
attempts are audited by case ID. Later case evidence exports include those sanitized bundle custody
events in `audit-events.jsonl`.

## Install

```bash
npm install
```

## Development

```bash
npm run dev        # Start Vite dev server
npm run build      # Type-check + production build
npm run preview    # Preview production build
npm run typecheck  # Type-check only
```

## Testing

```bash
npm run test:e2e   # Playwright end-to-end tests
```

## Stack

- React 19 + React Router 7
- Vite + TypeScript
- Tailwind CSS 4
- Playwright (E2E)

## License

Apache-2.0
