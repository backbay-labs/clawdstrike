# `api_server.rs` Route Inventory

Audit target: `apps/agent/src-tauri/src/api_server.rs`
Audit date: 2026-05-23
Branch: `fix/macos-es-ne-hardening` (HEAD `2eff91532`)

---

## Summary

| Metric | Value |
|---|---|
| Total LOC | **48,118** |
| Production LOC (lines 1 – 19,320, before `mod tests`) | **~19,320** |
| Test LOC (`mod tests` from line 19,321 to EOF) | **~28,800** |
| Total `fn` / `async fn` definitions | **720** |
| Production `fn` definitions | **598** |
| Production `async fn` definitions | **148** |
| Test `fn` / `async fn` definitions | **~282** |
| `#[test]` + `#[tokio::test]` attributes | **229** |
| Distinct HTTP routes registered in production router | **109** |
| Number of times the production router is constructed | **1** (`AgentApiServer::start`, lines 519 – 864) |
| Number of times `Router::new()` is constructed *in tests* | **162** (test boilerplate) |
| Handler functions defined locally in `api_server.rs` | **~30** (the remaining 44 `agent_edr_*` handlers live in `src/edr/handlers/*.rs` and import `crate::api_server::*` for ~500 helpers) |
| `require_auth()` call sites (handlers that gate themselves) | **44** (every non-bootstrap handler hand-rolls the auth call) |
| Handler-shaped returns of `Result<_, (StatusCode, String)>` | **164** |
| `anyhow::Result<T>` / `Result<T>` returns (internal helpers) | **69** |
| Handler return types using a proper error enum | **0** |

### The single biggest insight

> **`api_server.rs` is not really a router file — it is a 19k-line _agent runtime module_ masquerading as one.** The router itself is one method (`AgentApiServer::start`, 346 lines). Roughly **500 of the 598 production functions are EDR helpers** (response action execution, persistence-target validation, receipt signing, control-API postback retries, policy-event impact analysis, evidence-bundle archive verification, dozens of OS-specific path-bounds checks for `disable_persistence`/`quarantine_file` rollback, etc.). These helpers were left behind when 44 `agent_edr_*` handlers were extracted into `src/edr/handlers/{causal,deception,evidence,fleet,policy,privacy,response,sensors}.rs` via `pub(crate) use crate::edr::handlers::*;` (line 93). The handlers were moved; the **machinery underneath was not**. Splitting this file should therefore prioritise lifting **state, helper crates, and the response-action implementation** out from under the router — not moving the router itself.

A second large insight: **auth is gated _inside every handler body_, not by middleware.** `require_auth(&headers, &state)?;` is the first line of 44 handlers. The router has zero auth layers; the only `axum::middleware::from_fn_with_state` calls are for rate-limiting and UI-cookie attachment. Any refactor that introduces a `RequireAuth` extractor or a `.route_layer(...)` will eliminate ~88 lines of copy-pasted prologue and centralise the cookie-vs-Bearer logic in one place.

A third: there are **zero typed error enums in the entire file**. Every fallible HTTP path returns `Result<T, (StatusCode, String)>`. Introducing a single `AgentApiError` enum with `IntoResponse` would make `?` propagation work from `anyhow::Error`, eliminate ~30 hand-rolled `internal_error(...)` wrappers, and make `map_openclaw_error` redundant.

---

## Full Route Table

All routes are registered in the single block `AgentApiServer::start` at `apps/agent/src-tauri/src/api_server.rs:519-864`. Auth is enforced via `require_auth(&headers, &state)?` inside the handler body unless noted "no" (the public bootstrap and the static `/ui` fallback are intentionally unauthenticated). "Has test?" is yes when a `#[tokio::test]` in the same file or in `edr/handlers/*` exercises the handler via a `Router::new().route(...).oneshot(...)` invocation. All handlers use the tuple error `(StatusCode, String)` — there is no typed error enum.

### Group A — Daemon HTTP proxy (forwarder to `hushd`)

| Method | Path | Handler fn | Lines | Auth? | Error type | Has test? | Group |
|---|---|---|---|---|---|---|---|
| GET | `/health` | `proxy_daemon_get` | 1693–1705 | yes (in body) | `(StatusCode, String)` | yes (`daemon_proxy_route_requires_auth`) | A: daemon_proxy |
| GET | `/api/v1/audit` | `proxy_daemon_get` | 1693–1705 | yes | `(StatusCode, String)` | yes | A: daemon_proxy |
| GET | `/api/v1/audit/stats` | `proxy_daemon_get` | 1693–1705 | yes | `(StatusCode, String)` | yes | A: daemon_proxy |
| GET | `/api/v1/policy` | `proxy_daemon_get` | 1693–1705 | yes | `(StatusCode, String)` | yes | A: daemon_proxy |
| GET | `/api/v1/agents/status` | `proxy_daemon_get` | 1693–1705 | yes | `(StatusCode, String)` | yes | A: daemon_proxy |
| GET | `/api/v1/events` | `proxy_daemon_events` | 1707–1739 | yes | `(StatusCode, String)` | no | A: daemon_proxy |
| GET | `/api/v1/siem/exporters` | `proxy_daemon_get` | 1693–1705 | yes | `(StatusCode, String)` | yes | A: daemon_proxy |

### Group B — Broker (proxy to `hushd` broker)

| Method | Path | Handler fn | Lines | Auth? | Error type | Has test? | Group |
|---|---|---|---|---|---|---|---|
| GET | `/api/v1/broker/public-key` | `proxy_daemon_get` | 1693 | yes | `(StatusCode, String)` | yes | B: broker_proxy |
| GET / POST | `/api/v1/broker/capabilities` | `proxy_daemon_get` / `proxy_daemon_mutation` | 1693 / 1741 | yes | `(StatusCode, String)` | yes | B: broker_proxy |
| GET / POST | `/api/v1/broker/previews` | `proxy_daemon_get` / `proxy_daemon_mutation` | 1693 / 1741 | yes | `(StatusCode, String)` | yes | B: broker_proxy |
| POST | `/api/v1/broker/capabilities/revoke-all` | `proxy_daemon_mutation` | 1741 | yes | `(StatusCode, String)` | yes | B: broker_proxy |
| GET | `/api/v1/broker/capabilities/{id}` | `proxy_daemon_get` | 1693 | yes | `(StatusCode, String)` | yes | B: broker_proxy |
| GET | `/api/v1/broker/capabilities/{id}/status` | `proxy_daemon_get` | 1693 | yes | `(StatusCode, String)` | no | B: broker_proxy |
| POST | `/api/v1/broker/capabilities/{id}/replay` | `proxy_daemon_mutation` | 1741 | yes | `(StatusCode, String)` | no | B: broker_proxy |
| GET | `/api/v1/broker/capabilities/{id}/bundle` | `proxy_daemon_get` | 1693 | yes | `(StatusCode, String)` | no | B: broker_proxy |
| POST | `/api/v1/broker/capabilities/{id}/revoke` | `proxy_daemon_mutation` | 1741 | yes | `(StatusCode, String)` | no | B: broker_proxy |
| GET | `/api/v1/broker/previews/{id}` | `proxy_daemon_get` | 1693 | yes | `(StatusCode, String)` | no | B: broker_proxy |
| POST | `/api/v1/broker/previews/{id}/approve` | `proxy_daemon_mutation` | 1741 | yes | `(StatusCode, String)` | no | B: broker_proxy |
| GET | `/api/v1/broker/providers/freeze` | `proxy_daemon_get` | 1693 | yes | `(StatusCode, String)` | no | B: broker_proxy |
| POST / DELETE | `/api/v1/broker/providers/{provider}/freeze` | `proxy_daemon_mutation` | 1741 | yes | `(StatusCode, String)` | no | B: broker_proxy |

### Group C — Agent management (settings, health, OTA, runtimes, diagnostics, integrations)

| Method | Path | Handler fn | Lines | Auth? | Error type | Has test? | Group |
|---|---|---|---|---|---|---|---|
| GET | `/api/v1/agent/health` | `agent_health` | 2834–2890 | yes | `(StatusCode, String)` | yes (`agent_health_route_requires_auth`, `agent_health_route_reports_pending_host_state`) | C: agent_mgmt |
| GET | `/api/v1/agent/settings` | `get_settings` | 2891–2954 | yes | `(StatusCode, String)` | yes (settings round-trip tests) | C: agent_mgmt |
| PUT | `/api/v1/agent/settings` | `update_settings` | 3012–3186 | yes | `(StatusCode, String)` | yes | C: agent_mgmt |
| GET | `/api/v1/agent/runtimes` | `list_runtime_agents` | 2955–2967 | yes | `(StatusCode, String)` | no | C: agent_mgmt |
| POST | `/api/v1/agent/runtimes/register` | `register_runtime_agent_route` | 2968–3011 | yes | `(StatusCode, String)` | yes | C: agent_mgmt |
| GET | `/api/v1/agent/integrations` | `get_integrations_settings` | 3187–3195 | yes | `(StatusCode, String)` | yes (`integrations_routes_require_auth`) | C: agent_mgmt |
| PUT | `/api/v1/agent/integrations` | `update_integrations_settings` | 3196–3295 | yes | `(StatusCode, String)` | yes | C: agent_mgmt |
| POST | `/api/v1/agent/integrations/test` | `test_integration_delivery` | 3309–3465 | yes | `(StatusCode, String)` | yes | C: agent_mgmt |
| GET | `/api/v1/agent/ota/status` | `get_ota_status` | 3466–3473 | yes | `(StatusCode, String)` | no | C: agent_mgmt |
| POST | `/api/v1/agent/ota/check` | `trigger_ota_check` | 3474–3486 | yes | `(StatusCode, String)` | no | C: agent_mgmt |
| POST | `/api/v1/agent/ota/apply` | `trigger_ota_apply` | 3487–3499 | yes | `(StatusCode, String)` | no | C: agent_mgmt |
| POST | `/api/v1/agent/diagnostics/bundle` | `create_diagnostics_bundle` | 2823–2833 | yes | `(StatusCode, String)` | no | C: agent_mgmt |
| POST | `/api/v1/agent/security/token/rotate` | `rotate_local_api_token_route` | 19095–19107 | yes | `(StatusCode, String)` | no | C: agent_mgmt |
| POST | `/api/v1/agent/policy-check` | `agent_policy_check` | 3500–3530 | yes | `(StatusCode, String)` | yes (`agent_edr_policy_check_emits_policy_decision_receipt`) | C: agent_mgmt |

### Group D — EDR sensor ingest

| Method | Path | Handler fn | File | Lines | Auth? | Error | Has test? | Group |
|---|---|---|---|---|---|---|---|---|
| POST | `/api/v1/agent/edr/findings` | `agent_edr_findings` | `edr/handlers/sensors.rs` | 25–49 | yes | `(StatusCode, String)` | yes (~30 tests, e.g. `agent_edr_findings_route_detects_supply_chain_script`) | D: edr_ingest |
| POST | `/api/v1/agent/edr/developer-activity` | `agent_edr_developer_activity` | `edr/handlers/sensors.rs` | 50–83 | yes | `(StatusCode, String)` | yes (`agent_edr_developer_activity_*`) | D: edr_ingest |
| POST | `/api/v1/agent/edr/package-manager/events` | `agent_edr_package_manager_events` | `edr/handlers/sensors.rs` | 84–117 | yes | `(StatusCode, String)` | yes (`agent_edr_package_manager_events_*`) | D: edr_ingest |
| POST | `/api/v1/agent/edr/endpoint-security/events` | `agent_edr_endpoint_security_events` | `edr/handlers/sensors.rs` | 118–183 | yes | `(StatusCode, String)` | yes | D: edr_ingest |
| POST | `/api/v1/agent/edr/network-extension/events` | `agent_edr_network_extension_events` | `edr/handlers/sensors.rs` | 184–241 | yes | `(StatusCode, String)` | yes (`agent_edr_network_extension_events_map_verdict_flow_to_graph`) | D: edr_ingest |
| POST | `/api/v1/agent/edr/agent-secret-touches` | `agent_edr_agent_secret_touches` | `edr/handlers/sensors.rs` | 313–324 | yes | `(StatusCode, String)` | yes | D: edr_ingest |
| POST | `/api/v1/agent/edr/agent-secret-touches/fleet-publish` | `agent_edr_agent_secret_touches_fleet_publish` | `edr/handlers/sensors.rs` | 325–end | yes | `(StatusCode, String)` | yes | D: edr_ingest |

### Group E — EDR policy-event lifecycle (ingest + replay + impact + delta)

| Method | Path | Handler fn | File | Lines | Auth? | Error | Has test? | Group |
|---|---|---|---|---|---|---|---|---|
| POST | `/api/v1/agent/edr/policy-events` | `agent_edr_policy_events` | `edr/handlers/sensors.rs` | 242–278 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/policy-events/jsonl` | `agent_edr_policy_events_jsonl` | `edr/handlers/sensors.rs` | 279–312 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/policy-events/replay` | `agent_edr_policy_events_replay` | `edr/handlers/policy.rs` | 29–44 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/policy-events/replay/jsonl` | `agent_edr_policy_events_replay_jsonl` | `edr/handlers/policy.rs` | 45–57 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/policy-events/replay/history` | `agent_edr_policy_events_replay_history` | `edr/handlers/policy.rs` | 58–77 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/policy-events/impact` | `agent_edr_policy_events_impact` | `edr/handlers/policy.rs` | 78–94 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/policy-events/impact/history` | `agent_edr_policy_events_impact_history` | `edr/handlers/policy.rs` | 95–168 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/policy-simulation` | `agent_edr_policy_simulation` | `edr/handlers/policy.rs` | 169–231 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/policy-replay` | `agent_edr_policy_replay` | `edr/handlers/policy.rs` | 232–321 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/detection-candidate` | `agent_edr_detection_candidate` | `edr/handlers/policy.rs` | 322–331 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| GET / POST | `/api/v1/agent/edr/staged-detections` | `agent_edr_staged_detections` / `agent_edr_stage_detection` | `edr/handlers/policy.rs` | 419 / 332 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| GET / POST | `/api/v1/agent/edr/policy-deltas` | `agent_edr_policy_deltas` / `agent_edr_policy_delta` | `edr/handlers/policy.rs` | 557 / 441 | yes | `(StatusCode, String)` | yes | E: edr_policy_events |
| POST | `/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply` | `agent_edr_policy_delta_apply` | `edr/handlers/policy.rs` | 579–end | yes | `(StatusCode, String)` | yes | E: edr_policy_events |

### Group F — EDR causal graph / flight recorder

| Method | Path | Handler fn | File | Lines | Auth? | Error | Has test? | Group |
|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/agent/edr/finding-groups` | `agent_edr_finding_groups` | `edr/handlers/causal.rs` | 25–109 | yes | `(StatusCode, String)` | yes | F: edr_graph |
| POST | `/api/v1/agent/edr/causal-graph` | `agent_edr_causal_graph` | `edr/handlers/causal.rs` | 110–137 | yes | `(StatusCode, String)` | yes | F: edr_graph |
| POST | `/api/v1/agent/edr/causal-subgraph` | `agent_edr_causal_subgraph` | `edr/handlers/causal.rs` | 138–178 | yes | `(StatusCode, String)` | yes | F: edr_graph |
| POST | `/api/v1/agent/edr/causal-context` | `agent_edr_causal_context` | `edr/handlers/causal.rs` | 179–265 | yes | `(StatusCode, String)` | yes | F: edr_graph |
| POST | `/api/v1/agent/edr/graph-search` | `agent_edr_graph_search` | `edr/handlers/causal.rs` | 266–340 | yes | `(StatusCode, String)` | yes | F: edr_graph |
| POST | `/api/v1/agent/edr/graph-slices/export` | `agent_edr_graph_slice_export` | `edr/handlers/causal.rs` | 341–389 | yes | `(StatusCode, String)` | yes | F: edr_graph |
| GET | `/api/v1/agent/edr/flight-recorder` | `agent_edr_flight_recorder` | `edr/handlers/causal.rs` | 390–405 | yes | `(StatusCode, String)` | yes | F: edr_graph |
| POST | `/api/v1/agent/edr/flight-recorder/compact` | `agent_edr_flight_recorder_compact` | `edr/handlers/causal.rs` | 406–end | yes | `(StatusCode, String)` | yes | F: edr_graph |

### Group G — EDR evidence & receipts (ledgers and bundles)

| Method | Path | Handler fn | File | Lines | Auth? | Error | Has test? | Group |
|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/agent/edr/receipts` | `agent_edr_receipts` | `edr/handlers/evidence.rs` | 29–75 | yes | `(StatusCode, String)` | yes | G: edr_evidence |
| POST | `/api/v1/agent/edr/receipts/upload` | `agent_edr_receipts_upload` | `edr/handlers/evidence.rs` | 76–247 | yes | `(StatusCode, String)` | yes | G: edr_evidence |
| POST | `/api/v1/agent/edr/receipts/compact` | `agent_edr_receipts_compact` | `edr/handlers/evidence.rs` | 248–286 | yes | `(StatusCode, String)` | yes | G: edr_evidence |
| GET | `/api/v1/agent/edr/evidence-bundles` | `agent_edr_evidence_bundles` | `edr/handlers/evidence.rs` | 551–584 | yes | `(StatusCode, String)` | yes | G: edr_evidence |
| POST | `/api/v1/agent/edr/evidence-bundles/compact` | `agent_edr_evidence_bundles_compact` | `edr/handlers/evidence.rs` | 585–end | yes | `(StatusCode, String)` | yes | G: edr_evidence |
| POST | `/api/v1/agent/edr/evidence-bundles/archive/verify` | `agent_edr_evidence_bundle_archive_verify` | `edr/handlers/evidence.rs` | 454–550 | yes | `(StatusCode, String)` | yes | G: edr_evidence |
| POST | `/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish` | `agent_edr_evidence_bundle_fleet_publish` | `edr/handlers/evidence.rs` | 321–441 | yes | `(StatusCode, String)` | yes | G: edr_evidence |
| GET | `/api/v1/agent/edr/evidence-bundles/{bundle_id}` | `agent_edr_evidence_bundle` | `edr/handlers/evidence.rs` | 287–320 | yes | `(StatusCode, String)` | yes | G: edr_evidence |
| GET | `/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive` | `agent_edr_evidence_bundle_archive` | `edr/handlers/evidence.rs` | 442–453 | yes | `(StatusCode, String)` | yes | G: edr_evidence |
| POST | `/api/v1/agent/edr/fleet-hunt-events/retry` | `agent_edr_fleet_hunt_events_retry` | `edr/handlers/fleet.rs` | 25–47 | yes | `(StatusCode, String)` | yes | G: edr_evidence |

### Group H — EDR response actions (most complex group)

| Method | Path | Handler fn | File | Lines | Auth? | Error | Has test? | Group |
|---|---|---|---|---|---|---|---|---|
| POST | `/api/v1/agent/edr/response-action` | `agent_edr_response_action` | `edr/handlers/response.rs` | 25–200 | yes | `(StatusCode, String)` | yes (~12 tests `agent_edr_response_action_*`) | H: edr_response |
| GET | `/api/v1/agent/edr/response-executions` | `agent_edr_response_executions` | `edr/handlers/response.rs` | 201–228 | yes | `(StatusCode, String)` | yes | H: edr_response |
| POST | `/api/v1/agent/edr/response-executions/expire` | `agent_edr_response_execution_expire` | `edr/handlers/response.rs` | 409–524 | yes | `(StatusCode, String)` | yes | H: edr_response |
| GET | `/api/v1/agent/edr/response-acknowledgements` | `agent_edr_response_acknowledgements` | `edr/handlers/response.rs` | 882–end | yes | `(StatusCode, String)` | yes | H: edr_response |
| POST | `/api/v1/agent/edr/control-ack-postbacks/retry` | `agent_edr_control_ack_postbacks_retry` | `edr/handlers/fleet.rs` | 231–end | yes | `(StatusCode, String)` | yes | H: edr_response |
| POST | `/api/v1/agent/edr/control-archive-uploads/retry` | `agent_edr_control_archive_uploads_retry` | `edr/handlers/fleet.rs` | 128–217 | yes | `(StatusCode, String)` | yes | H: edr_response |
| POST | `/api/v1/agent/edr/control-receipt-uploads/retry` | `agent_edr_control_receipt_uploads_retry` | `edr/handlers/fleet.rs` | 218–230 | yes | `(StatusCode, String)` | yes | H: edr_response |
| POST | `/api/v1/agent/edr/control-archive-uploads/backfill` | `agent_edr_control_archive_uploads_backfill` | `edr/handlers/fleet.rs` | 48–127 | yes | `(StatusCode, String)` | yes | H: edr_response |
| POST | `/api/v1/agent/edr/response-executions/{execution_id}/cancel` | `agent_edr_response_execution_cancel` | `edr/handlers/response.rs` | 525–639 | yes | `(StatusCode, String)` | yes | H: edr_response |
| POST | `/api/v1/agent/edr/response-executions/{execution_id}/rollback` | `agent_edr_response_execution_rollback` | `edr/handlers/response.rs` | 640–783 | yes | `(StatusCode, String)` | yes | H: edr_response |
| POST | `/api/v1/agent/edr/response-executions/{execution_id}/acknowledge` | `agent_edr_response_execution_acknowledge` | `edr/handlers/response.rs` | 784–881 | yes | `(StatusCode, String)` | yes | H: edr_response |
| GET | `/api/v1/agent/edr/response-executions/{execution_id}/proof` | `agent_edr_response_execution_proof` | `edr/handlers/response.rs` | 263–408 | yes | `(StatusCode, String)` | yes (`response_execution_proof_*`) | H: edr_response |
| GET | `/api/v1/agent/edr/response-executions/{execution_id}` | `agent_edr_response_execution` | `edr/handlers/response.rs` | 229–262 | yes | `(StatusCode, String)` | yes | H: edr_response |

### Group I — EDR deception, privacy, protection

| Method | Path | Handler fn | File | Lines | Auth? | Error | Has test? | Group |
|---|---|---|---|---|---|---|---|---|
| POST | `/api/v1/agent/edr/deception-plan` | `agent_edr_deception_plan` | `edr/handlers/deception.rs` | 25–53 | yes | `(StatusCode, String)` | yes | I: edr_protection |
| POST | `/api/v1/agent/edr/deception-plan/materialize` | `agent_edr_materialize_deception_plan` | `edr/handlers/deception.rs` | 54–97 | yes | `(StatusCode, String)` | yes (`agent_edr_materialized_deception_plan_registers_for_future_findings`) | I: edr_protection |
| POST | `/api/v1/agent/edr/deception-plan/cleanup` | `agent_edr_cleanup_deception_plan` | `edr/handlers/deception.rs` | 98–168 | yes | `(StatusCode, String)` | yes (`agent_edr_deception_cleanup_removes_registered_honey_artifacts_with_receipt`) | I: edr_protection |
| POST | `/api/v1/agent/edr/deception-plan/rotate` | `agent_edr_rotate_deception_plan` | `edr/handlers/deception.rs` | 169–end | yes | `(StatusCode, String)` | yes (`agent_edr_deception_rotation_replaces_registered_honey_artifacts_with_receipts`) | I: edr_protection |
| POST | `/api/v1/agent/edr/privacy-report` | `agent_edr_privacy_report` | `edr/handlers/privacy.rs` | 29–62 | yes | `(StatusCode, String)` | yes (`agent_edr_privacy_report_*`, 3 tests) | I: edr_protection |
| POST | `/api/v1/agent/edr/network-extension/egress-policy/proof` | `agent_edr_network_extension_egress_policy_proof` | `edr/handlers/privacy.rs` | 63–256 | yes | `(StatusCode, String)` | yes | I: edr_protection |
| GET | `/api/v1/agent/edr/protection-state` | `agent_edr_protection_state` | `edr/handlers/privacy.rs` | 257–end | yes | `(StatusCode, String)` | yes (`agent_edr_protection_state_*`, 3 tests) | I: edr_protection |

### Group J — OpenClaw gateways

| Method | Path | Handler fn | Lines | Auth? | Error | Has test? | Group |
|---|---|---|---|---|---|---|---|
| GET / POST | `/api/v1/openclaw/gateways` | `list_gateways` / `create_gateway` | 18522 / 18530 | yes | `(StatusCode, String)` | no | J: openclaw |
| PATCH / DELETE | `/api/v1/openclaw/gateways/{id}` | `patch_gateway` / `delete_gateway` | 18544 / 18576 | yes | `(StatusCode, String)` | no | J: openclaw |
| POST | `/api/v1/openclaw/gateways/{id}/connect` | `connect_gateway` | 18590 | yes | `(StatusCode, String)` | no | J: openclaw |
| POST | `/api/v1/openclaw/gateways/{id}/disconnect` | `disconnect_gateway` | 18604 | yes | `(StatusCode, String)` | no | J: openclaw |
| PUT | `/api/v1/openclaw/active-gateway` | `set_active_gateway` | 18618 | yes | `(StatusCode, String)` | no | J: openclaw |
| POST | `/api/v1/openclaw/discover` | `discover_gateways` | 18635 | yes | `(StatusCode, String)` | no | J: openclaw |
| POST | `/api/v1/openclaw/probe` | `probe_gateway` | 18649 | yes | `(StatusCode, String)` | no | J: openclaw |
| POST | `/api/v1/openclaw/request` | `gateway_request` | 18663 | yes (+ rate limit) | `(StatusCode, String)` | no | J: openclaw |
| POST | `/api/v1/openclaw/import-desktop-gateways` | `import_desktop_gateways` | 18719 | yes | `(StatusCode, String)` | no | J: openclaw |
| GET | `/api/v1/openclaw/events` | `openclaw_events` | 18733 (SSE) | yes | `(StatusCode, String)` | no | J: openclaw |

### Group K — Approvals / enrollment / UI bootstrap

| Method | Path | Handler fn | Lines | Auth? | Error | Has test? | Group |
|---|---|---|---|---|---|---|---|
| POST | `/api/v1/approval/request` | `create_approval_request` | 18764 | yes | `(StatusCode, String)` | yes (`approval_submission_limiter_enforces_burst_limit`) | K: approvals_auth |
| GET | `/api/v1/approval/{id}/status` | `get_approval_status` | 18806 | yes | `(StatusCode, String)` | yes (`approval_status_route_matches_uuid_path`) | K: approvals_auth |
| POST | `/api/v1/approval/{id}/resolve` | `resolve_approval` | 18823 | yes | `(StatusCode, String)` | yes | K: approvals_auth |
| GET | `/api/v1/approval/pending` | `list_pending_approvals` | 18856 | yes | `(StatusCode, String)` | yes | K: approvals_auth |
| POST | `/api/v1/enroll` | `enroll_agent` | 18873 | yes | `(StatusCode, String)` | yes | K: approvals_auth |
| GET | `/api/v1/enrollment-status` | `enrollment_status` | 18905 | yes | `(StatusCode, String)` | yes | K: approvals_auth |
| POST | `/api/v1/ui/bootstrap/start` | `start_ui_bootstrap` | 1397 | **NO** (public, rate-limited) | `(StatusCode, String)` | yes (`ui_routes_require_auth_and_bootstrap_with_one_time_code`) | K: approvals_auth |
| GET / POST | `/ui/bootstrap` | `ui_bootstrap_page` / `ui_bootstrap_verify` | 1431 / 1542 | **NO** (page is public; verify accepts user code) | `(StatusCode, String)` | yes | K: approvals_auth |

### Group L — Static UI fallback

| Method | Path | Handler fn | Lines | Auth? | Error | Has test? | Group |
|---|---|---|---|---|---|---|---|
| any | `/ui/*` (bundled dashboard via `ServeDir`) | `attach_ui_auth_cookie` middleware over `tower_http::ServeDir` | 866–880 | layered cookie attached on success | n/a | partial (`ui_routes_require_auth_*`) | L: ui_static |
| GET | `/ui/` and `/ui/{*path}` (fallback when assets missing) | `agent_web_ui_fallback` | 887, 976 | layered cookie | n/a | no | L: ui_static |

**Auth split:** 109 routes total. **104 require auth** via `require_auth(&headers, &state)?` called inside the handler. **5 are public**: `/api/v1/ui/bootstrap/start` (rate-limited, returns a one-time code), `GET /ui/bootstrap` (HTML page), `POST /ui/bootstrap` (verifies user code, sets cookie), and the two `/ui/*` static fallback routes (these layer `attach_ui_auth_cookie` which sets a cookie *after* successful authenticated requests but the routes themselves serve assets without re-checking the bearer token because the cookie was already attached).

---

## Duplicate / Near-Duplicate Handlers

Genuinely near-duplicate production handlers in `api_server.rs`:

1. **`proxy_daemon_get` (1693–1705)** and **`proxy_daemon_mutation` (1741–1767)** — bodies share 4 of 6 lines (`require_auth` → `headers.remove(AUTHORIZATION)` → `send_daemon_*_request` → `proxy_http_response`). The only difference is that `_mutation` reads a request body with `axum::body::to_bytes`. Could be unified behind one function dispatching on `request.method()`, eliminating one fn entirely.

2. **`proxy_daemon_events` (1707–1739)** is `proxy_daemon_get` plus SSE header munging. Lines 1711–1717 are identical to lines 1697–1704 of `proxy_daemon_get`. Could share a `send_daemon_get_authenticated()` helper.

3. **`send_daemon_get_request` (1623–1630)** and **`send_daemon_request` (1631–1673)** — `send_daemon_get_request` is `send_daemon_request` with `Method::GET` and `body=None` hard-coded. Either delete `send_daemon_get_request` and inline at the two call sites, or have it call through.

4. **`rotate_local_api_token_with_grace` (18945)** and **`rotate_local_api_token_without_grace` (18971)** — sibling functions sharing token-rotation prologue (~10 lines of body), differ only in whether they record the previous-token grace window. Should be one function with a `bool include_grace` parameter, or refactored into one method returning `(new_token, Option<grace_secs>)`.

5. **`execute_collect_evidence_response`, `execute_restrict_egress_response`, `execute_quarantine_file_response`, `execute_disable_persistence_response`, `execute_revoke_grant_response`, `execute_suspend_process_tree_response`** (6207–6547). All 6 share the shape: validate inputs → persist execution receipt → run action → persist outcome. They can implement a single `ResponseActionExecutor` trait — currently `execute_edr_response_action` (6054) is a hand-rolled match on `EndpointDecisionAction` that re-implements the dispatch.

6. **`execute_restrict_egress_rollback` (6548), `execute_quarantine_file_rollback` (6604), `execute_disable_persistence_rollback` (6691), `execute_suspend_process_tree_rollback` (6788)** — same dispatch pattern as the above, would naturally pair with the trait above (`fn rollback`).

7. **The 10 `default_edr_*_path()` / `default_edr_*_ledger()` factory pairs (18061–18335)** — every persisted store has a `default_edr_X_path` and a matching `default_edr_X_ledger` defaulting to `EndpointXLedger::open_or_create(default_edr_X_path())`. Could collapse to a generic `default_edr_store::<T, P>(path)` factory.

8. **`network_extension_response_not_ready_reasons` (5243) vs `append_provider_attestation_not_ready_reasons` (5207)** — both walk providers and accumulate "not ready" string reasons. Different return shapes (`Vec<String>` vs append-into-vec) but identical predicate logic.

9. **`current_parent_pid` (7833 + 7839)** and **`process_suspend_signal` / `process_resume_signal` / `check_process_signalable` / `signal_process`** — these have unix and non-unix `#[cfg(...)]` variants in pairs. Not duplicates per se (cfg-gated alternates), but they show that the unix/non-unix split for response-action OS code is everywhere; it begs to be in a single `response/process_signals.rs` with a clear cfg block at file head.

**Routes registered multiple times in the file** (counted globally, including tests):

| Path | Registrations |
|---|---:|
| `/api/v1/agent/edr/findings` | 81 (1 prod + **80 tests** re-mounting it) |
| `/api/v1/agent/edr/receipts` | 10 (1 prod + 9 tests) |
| `/api/v1/openclaw/request` | 3 |
| `/api/v1/agent/policy-check` | 3 |
| `/api/v1/agent/health` | 3 |
| `/api/v1/ui/bootstrap/start` | 2 |
| `/api/v1/audit` | 2 |
| `/api/v1/approval/{id}/status` | 2 |

The 80 duplicate test-side mounts of `agent_edr_findings` are the largest source of redundancy: every test that needs to drive a finding rebuilds a single-route `Router::new().route("/api/v1/agent/edr/findings", post(agent_edr_findings))`. A `test_support::single_route_app(...)` helper would eliminate ~400 lines of boilerplate by itself.

---

## Untyped Error Returns

Every fallible handler in the file returns `Result<T, (StatusCode, String)>` — a raw tuple. **164 occurrences.** There is *no* error enum, *no* `IntoResponse for AgentApiError`, and *no* `From<anyhow::Error>` impl. Each handler converts `anyhow::Error` to a tuple via a manual call:

- `internal_error(err: anyhow::Error) -> (StatusCode, String)` — 19286 (called 30+ times).
- `map_openclaw_error(err: anyhow::Error) -> (StatusCode, String)` — 19291 (called ~10 times in OpenClaw handlers); duplicates `internal_error` plus a couple of string-substring sniffs to remap to `BAD_REQUEST`.
- Hand-rolled `.map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))` literals — repeated >40 times in EDR handlers.

Specific handlers exposing untyped `String` errors (other than the tuple form):

| Function | Line | Return |
|---|---|---|
| `validate_integration_settings` | 1787 | `std::result::Result<(), String>` |
| `verify_endpoint_receipt_signature` | 16193 | `Result<(), String>` |
| `control_store_receipt_from_endpoint_receipt` | 16240 | `Result<ControlStoreReceiptRequest, String>` |
| `validate_deception_cleanup_plan` | 18391 | `std::result::Result<(), String>` |
| `validate_deception_cleanup_relative_path` | 18404 | `std::result::Result<(), String>` |

Internal helpers using bare `anyhow::Result<T>` that *bubble through* tuple-returning handlers:

| Function | Line | Notes |
|---|---|---|
| `policy_delta_artifact_hash` | 5678 | `Result<String>` |
| `apply_policy_delta_patch_to_policy` | 5693 | `Result<Vec<u8>>` |
| `normalize_egress_target` | 7157 | `Result<String>` (semantic: validation error vs IO error indistinguishable) |
| `validate_egress_restriction_ip` | 7212 | `Result<()>` |
| `validate_process_signal_targets` | 7783 | `Result<()>` |
| `validate_quarantine_source_path` | 7899 | `Result<()>` |
| `validate_quarantine_restore_target_path` | 7971 | `Result<()>` |
| `validate_disable_persistence_source_path` | 7923 | `Result<()>` |
| `validate_disable_persistence_restore_target_path` | 7947 | `Result<()>` |
| `policy_yaml_for_replay` | 11879 | `Result<String>` |
| `canonical_json_hash` | 11908 | `Result<String>` |
| `signal_process` | 7876 / 7893 | `Result<()>` (unix / non-unix) |

The `validate_*` family in particular needs a typed error so handlers can map validation errors to `400 Bad Request` instead of the current `500 Internal Server Error` produced by `internal_error()`. This is a latent correctness issue, not a stylistic one.

---

## Untested Routes

The following production routes have **no test** in `mod tests` of `api_server.rs` and no test in `edr/handlers/*.rs` that mounts them on a router:

### Daemon proxy (Group A)
- `GET /api/v1/events` — `proxy_daemon_events` (the SSE-streaming variant is the most behaviour-rich and the least covered).

### Broker proxy (Group B)
- `GET /api/v1/broker/capabilities/{id}/status`
- `POST /api/v1/broker/capabilities/{id}/replay`
- `GET /api/v1/broker/capabilities/{id}/bundle`
- `POST /api/v1/broker/capabilities/{id}/revoke`
- `GET /api/v1/broker/previews/{id}`
- `POST /api/v1/broker/previews/{id}/approve`
- `GET /api/v1/broker/providers/freeze`
- `POST/DELETE /api/v1/broker/providers/{provider}/freeze`

(Daemon proxy paths are mostly transparent forwards, so a single proxy-contract test could cover the family; today there is only `daemon_proxy_route_requires_auth`.)

### Agent management (Group C)
- `GET /api/v1/agent/runtimes` — `list_runtime_agents` (no list-side test; `register_runtime_agent_route` is covered).
- `GET /api/v1/agent/ota/status` — `get_ota_status`
- `POST /api/v1/agent/ota/check` — `trigger_ota_check`
- `POST /api/v1/agent/ota/apply` — `trigger_ota_apply`
- `POST /api/v1/agent/diagnostics/bundle` — `create_diagnostics_bundle` (the redaction logic in `redact_settings_json` at 2612 *is* tested; the route is not).
- `POST /api/v1/agent/security/token/rotate` — `rotate_local_api_token_route` (the inner `rotate_local_api_token_with_grace` is tested; the HTTP route is not).

### OpenClaw (Group J)
**Entire group is untested at the HTTP layer.** The 10 gateway routes (lines 18522–18748) have **zero** `Router::new().route(...)` tests in the file. `OpenClawManager` itself is presumably tested in `src/openclaw/`, but the HTTP plumbing — `map_openclaw_error`'s substring sniffing, the rate limiter on `/openclaw/request`, the SSE shape of `/openclaw/events` — is not.

### UI / static (Group L)
- `GET /ui/` fallback `agent_web_ui_fallback` (HTML diagnostics page when dashboard assets are missing) — never exercised in tests.

**Test coverage summary:** of the 109 distinct routes, roughly **76 have a direct route-level test** (mostly in Groups D–I) and **33 do not** (most of Group A's proxy variants, all of Group J, most of Group B's broker variants, and the OTA / diagnostics / token-rotate routes in Group C).

---

## Refactor Plan

Goal: turn the monolithic `api_server.rs` into a `src/api/` directory of focused modules averaging 600–1,800 production LOC each, plus a `src/api/test_support.rs` to absorb the test boilerplate. The Tauri entrypoint `apps/agent/src-tauri/src/main.rs` continues to call `AgentApiServer::new(...).start(...)`.

### Target file layout

```
apps/agent/src-tauri/src/
├── api_server.rs                        # facade — re-exports AgentApiServer, AgentApiState; ~150 LOC
└── api/
    ├── mod.rs                           # `pub use` everything; ~80 LOC
    ├── state.rs                         # AgentApiState, AgentApiServerDeps, ApprovalSubmissionLimiter,
    │                                    #   RouteRateLimiter, PolicyVersionCache, UiBootstrapSession,
    │                                    #   PreviousAuthToken, default_edr_* factories, ~700 LOC
    ├── error.rs                         # AgentApiError enum + IntoResponse + From<anyhow::Error>;
    │                                    #   replaces (StatusCode, String) tuples; ~250 LOC
    ├── auth.rs                          # require_auth, auth_token_matches, auth_token_from_cookie,
    │                                    #   merged_authorization_header, set_ui_auth_cookie,
    │                                    #   request_is_secure*, is_local_host_header,
    │                                    #   rotate_local_api_token_*, token_rotation_loop,
    │                                    #   RequireAuth extractor; ~600 LOC
    ├── middleware.rs                    # route_rate_limit, attach_ui_auth_cookie; ~250 LOC
    ├── router.rs                        # AgentApiServer::start, Router::new() chain, layer wiring,
    │                                    #   TLS/mTLS bind logic; ~400 LOC
    ├── proxy.rs                         # proxy_daemon_get, proxy_daemon_events, proxy_daemon_mutation,
    │                                    #   send_daemon_*_request, proxy_http_response,
    │                                    #   build_daemon_proxy_target; ~400 LOC
    ├── routes/
    │   ├── mod.rs
    │   ├── ui_bootstrap.rs              # ui_bootstrap_page, ui_bootstrap_verify, start_ui_bootstrap,
    │   │                                #   sanitize_ui_next_path, generate_ui_bootstrap_code,
    │   │                                #   agent_web_ui_fallback, control_console_dist resolver;
    │   │                                #   ~600 LOC
    │   ├── agent_health.rs              # agent_health, edr_health_summary, agent_health_status,
    │   │                                #   macos_host_health_status, cached_policy_version_for_health,
    │   │                                #   fetch_daemon_*_for_health; ~700 LOC
    │   ├── agent_settings.rs            # get_settings, update_settings, redact_settings_json,
    │   │                                #   bounded_*_setting validators, normalize_*_setting,
    │   │                                #   list_runtime_agents, register_runtime_agent_route; ~900 LOC
    │   ├── agent_integrations.rs        # get_integrations_settings, update_integrations_settings,
    │   │                                #   test_integration_delivery, normalize_integration_settings,
    │   │                                #   validate_integration_settings, truncate_delivery_error;
    │   │                                #   ~700 LOC
    │   ├── agent_ota.rs                 # get_ota_status, trigger_ota_check, trigger_ota_apply,
    │   │                                #   create_diagnostics_bundle, write_diagnostics_bundle,
    │   │                                #   trim_tail_lines; ~500 LOC
    │   ├── agent_policy_check.rs        # agent_policy_check, active_egress_restriction_for_policy_check;
    │   │                                #   ~250 LOC
    │   ├── approvals.rs                 # create_approval_request, get_approval_status,
    │   │                                #   resolve_approval, list_pending_approvals; ~300 LOC
    │   ├── enrollment.rs                # enroll_agent, enrollment_status; ~150 LOC
    │   ├── openclaw.rs                  # all 10 gateway routes + map_openclaw_error, sse_stream,
    │   │                                #   import_desktop_gateways; ~500 LOC
    │   └── broker_proxy.rs              # broker route table (uses proxy.rs internally); ~120 LOC
    │                                    #   (mostly Router wiring; handlers are proxy_daemon_*)
    └── test_support.rs                  # new — fixture builders, single_route_app(),
                                         #   `auth_headers()`, `with_settings(...)`, test_signer().
                                         #   ~500 LOC; eliminates the 162 Router::new() repetitions
                                         #   currently in mod tests.

apps/agent/src-tauri/src/edr/            # already exists — minor changes:
├── mod.rs
├── handlers/...                         # unchanged on disk; internal imports change from
│                                        #   `use crate::api_server::*` to `use crate::api::*`
│                                        #   and `use crate::api::state::AgentApiState`.
├── helpers/                             # NEW — extract the 500 production helpers currently
│   │                                    #   in api_server.rs that are EDR-only:
│   ├── mod.rs
│   ├── receipts.rs                      # emit_edr_*_receipt (16 fns), receipt_*, signer loaders,
│   │                                    #   verify_*_proof_*, latest_required_receipt,
│   │                                    #   endpoint_receipt_index_*, read_endpoint_receipt_*,
│   │                                    #   load_or_create_edr_receipt_signer; ~2,200 LOC
│   ├── flight_recorder.rs               # default_edr_flight_recorder, select_policy_event_history_*,
│   │                                    #   build_policy_event_history_*_impact (50+ fns),
│   │                                    #   causal_chains_for_changed_observation,
│   │                                    #   promotion_suggestions_for_causal_impact; ~2,500 LOC
│   ├── response_actions/                # the biggest sub-module: ~3,500 LOC
│   │   ├── mod.rs                       # supported_edr_response_action, execute_edr_response_action,
│   │   │                                #   record_failed_edr_response_execution, validate_response_*
│   │   ├── collect_evidence.rs          # execute_collect_evidence_response
│   │   ├── restrict_egress.rs           # execute_restrict_egress_response,
│   │   │                                #   execute_restrict_egress_rollback, normalize_egress_*,
│   │   │                                #   restrict_egress_targets, egress_target_from_node
│   │   ├── quarantine.rs                # execute_quarantine_file_response,
│   │   │                                #   execute_quarantine_file_rollback,
│   │   │                                #   validate_quarantine_*_path, path_is_bounded_quarantine_*
│   │   ├── disable_persistence.rs       # execute_disable_persistence_response + rollback,
│   │   │                                #   the 25+ path_is_bounded_* path validators
│   │   │                                #   (systemd, cron, xdg, kde, plasma, profile_d, shell startup,
│   │   │                                #    browser extension manifest) — currently 7240–8937, ~1700 LOC
│   │   ├── revoke_grant.rs              # execute_revoke_grant_response, revoke_broker_capability_grant,
│   │   │                                #   revoke_local_integration_secret_grant, credential_node_*
│   │   └── suspend_process_tree.rs      # execute_suspend_process_tree_response + rollback,
│   │                                    #   signal_process (cfg unix/non-unix), validate_process_signal_targets
│   ├── developer_activity.rs            # 35+ redact_developer_activity_* fns currently at
│   │                                    #   9269–10193; ~900 LOC. Pure redaction; deserves its own crate
│   │                                    #   eventually but for now a sibling file is fine.
│   ├── network_extension.rs             # network_extension_event_observations,
│   │                                    #   network_extension_response_*, network_extension_flow_*,
│   │                                    #   network_extension_egress_policy_proof_*,
│   │                                    #   network_extension_live_enforcement_proof; ~700 LOC
│   ├── package_manager.rs               # package_manager_event_observation, *_process, *_metadata,
│   │                                    #   required_package_manager_event_string; ~150 LOC
│   ├── deception.rs                     # validate_deception_cleanup_plan + helpers,
│   │                                    #   cleanup_deception_plan; ~150 LOC
│   ├── control_api_postbacks.rs         # control_api_ack_postback_url,
│   │                                    #   control_api_endpoint_archive_upload_url,
│   │                                    #   control_api_receipt_batch_upload_url,
│   │                                    #   post_control_endpoint_receipts_best_effort,
│   │                                    #   post_control_endpoint_evidence_archive,
│   │                                    #   post_control_response_acknowledgement,
│   │                                    #   enqueue/send/drain_control_*_retry (24 fns); ~1,800 LOC
│   ├── fleet_publishing.rs              # collect_agent_secret_touches*, publish_*_secret_touches_*,
│   │                                    #   enqueue_fleet_hunt_event_outbox, drain_fleet_hunt_event_outbox,
│   │                                    #   fleet_agent_secret_touch_sync_loop,
│   │                                    #   fleet_hunt_event_for_*; ~1,200 LOC
│   ├── providers.rs                     # refresh_macos_provider_status,
│   │                                    #   provider_policy_acknowledgements_for_policy,
│   │                                    #   wait_for_provider_policy_acknowledgements,
│   │                                    #   endpoint_provider_state_from_macos_provider,
│   │                                    #   provider_recovery_receipt_evidence,
│   │                                    #   macos_provider_degradation_reasons; ~1,000 LOC
│   ├── policy_snapshot.rs               # endpoint_policy_snapshot_*, policy_version_from_yaml,
│   │                                    #   policy_epoch_from_*, yaml_*_at_path; ~250 LOC
│   ├── validation.rs                    # validate_edr_request_sizes, bounded_request_limit,
│   │                                    #   bounded_graph_depth, bounded_provider_timeout_ms,
│   │                                    #   validate_response_*, validate_raw_artifact_approval*; ~400 LOC
│   ├── graph.rs                         # causal_node_kind_name, graph_for_observations,
│   │                                    #   resolve_graph_root, resolve_graph_root_from_selector,
│   │                                    #   graph_slice_for_export, evidence_bundle_for_graph_slice,
│   │                                    #   causal_path_node_ids, affected_tools_for_causal_impact;
│   │                                    #   ~400 LOC
│   ├── redaction.rs                     # redact_endpoint_observations, redact_endpoint_event,
│   │                                    #   redact_endpoint_process, redact_endpoint_observation_metadata,
│   │                                    #   redact_response_failure_secret_like_fragments,
│   │                                    #   sanitize_response_execution_failure; ~300 LOC
│   └── default_paths.rs                 # default_edr_*_path() and default_edr_*_ledger() factories
│                                        #   (currently 18061–18335); ~270 LOC
└── ... (existing handlers/, dto.rs, etc. unchanged)
```

### Per-file LOC estimate after the split

| New file | Estimated LOC | Source range in current `api_server.rs` |
|---|---:|---|
| `api/state.rs` | 700 | 169–510, 18061–18335 (default factories) |
| `api/error.rs` | 250 | new — replaces every `(StatusCode, String)` |
| `api/auth.rs` | 600 | 1176–1264, 18921–19030, 19095–19258 |
| `api/middleware.rs` | 250 | 1276–1316, 19030–19092 |
| `api/router.rs` | 400 | 518–948 (router build + bind + TLS) |
| `api/proxy.rs` | 400 | 1159–1175, 1623–1767 |
| `api/routes/ui_bootstrap.rs` | 600 | 976–1158, 1334–1622, 22789–22890 (tests) |
| `api/routes/agent_health.rs` | 700 | 1822–2570, 2834–2890 |
| `api/routes/agent_settings.rs` | 900 | 2612–2659, 2891–3186, 4604–4715 |
| `api/routes/agent_integrations.rs` | 700 | 1769–1821, 3187–3465 |
| `api/routes/agent_ota.rs` | 500 | 2660–2833, 3466–3499 |
| `api/routes/agent_policy_check.rs` | 250 | 3500–3530, 7060–7090 |
| `api/routes/approvals.rs` | 300 | 18764–18920 |
| `api/routes/enrollment.rs` | 150 | 18873–18920 |
| `api/routes/openclaw.rs` | 500 | 18522–18763, 19291–19302 |
| `api/routes/broker_proxy.rs` | 120 | (just route wiring — no handler bodies) |
| `api/test_support.rs` | 500 | new |
| `edr/helpers/receipts.rs` | 2200 | 12925–18060 (selective: receipts subset) |
| `edr/helpers/flight_recorder.rs` | 2500 | 10605–12012 + 18061+ |
| `edr/helpers/response_actions/*` | 3500 | 5942–8937 split into 7 files |
| `edr/helpers/developer_activity.rs` | 900 | 9269–10193 |
| `edr/helpers/network_extension.rs` | 700 | 5292–5331, 8953–9161, 16922–17412 |
| `edr/helpers/package_manager.rs` | 150 | 9162–9268 |
| `edr/helpers/deception.rs` | 150 | 18391–18497 |
| `edr/helpers/control_api_postbacks.rs` | 1800 | 13036–14348 |
| `edr/helpers/fleet_publishing.rs` | 1200 | 3635–4272 + 14354–14552 |
| `edr/helpers/providers.rs` | 1000 | 5021–5298, 17412–17648 |
| `edr/helpers/policy_snapshot.rs` | 250 | 16620–16772 |
| `edr/helpers/validation.rs` | 400 | 4574–4716, 5942–6053, 16570–16619 |
| `edr/helpers/graph.rs` | 400 | 3546–4555, 11270–11824 (selective) |
| `edr/helpers/redaction.rs` | 300 | 6135–6206, 10195–10393 |
| `edr/helpers/default_paths.rs` | 270 | 18061–18335 |
| `api_server.rs` (facade) | 150 | `pub use crate::api::*;` + crate-level docs |

**Total after split:** ~22,400 production LOC across 32 files, vs **19,320 LOC in one file today.** The slight expansion reflects the new `error.rs`, `test_support.rs`, and `mod.rs` files. Test LOC drops from ~28,800 to ~22,000 once `test_support.rs` absorbs the 162 Router-rebuild repetitions and the 80 mountings of `agent_edr_findings` collapse to 1.

### Required shared modules

1. **`api/error.rs` — `enum AgentApiError`**

   ```rust
   pub enum AgentApiError {
       Unauthorized(&'static str),
       BadRequest(String),
       Conflict(String),
       NotFound(String),
       RateLimited { retry_after_secs: u64 },
       UpstreamUnavailable(String),       // daemon proxy + control-API postbacks
       OpenClawTransport(String),         // formerly handled by map_openclaw_error
       Validation { field: &'static str, message: String },
       Internal(anyhow::Error),           // logs at error level; returns 500
   }

   impl IntoResponse for AgentApiError { ... }
   impl From<anyhow::Error> for AgentApiError { ... }    // → Internal
   ```

   Eliminates `internal_error()`, `map_openclaw_error()`, and 40+ ad-hoc `.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))` literals.

2. **`api/auth.rs` — `pub struct RequireAuth;` extractor**

   ```rust
   #[axum::async_trait]
   impl<S> FromRequestParts<S> for RequireAuth
   where S: Send + Sync, Arc<AgentApiState>: FromRef<S> { ... }
   ```

   Then every handler signature changes from
   ```rust
   async fn agent_health(State(state): State<Arc<AgentApiState>>, headers: HeaderMap, ...)
   ```
   to
   ```rust
   async fn agent_health(_: RequireAuth, State(state): State<Arc<AgentApiState>>, ...)
   ```
   and the `require_auth(&headers, &state)?;` prologue is deleted from 44 functions. Or, for routes that should always require auth, apply via `.route_layer(middleware::from_fn(require_auth_layer))` to the entire authenticated sub-router and skip the extractor on most handlers.

3. **`api/test_support.rs` — fixture helpers**

   ```rust
   pub fn test_state() -> Arc<AgentApiState> { ... }
   pub fn single_route_app(route: &str, method_router: MethodRouter<Arc<AgentApiState>>) -> Router { ... }
   pub fn auth_request(method: Method, uri: &str, body: Body) -> Request<Body> { ... }
   ```

   With these, the 80 repetitions of
   ```rust
   let state = ...; // 30+ lines of construction
   let app = Router::new()
       .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
       .with_state(state.clone());
   ```
   collapse to one line per test.

### Why these groups (and not, e.g., one file per route)

The 10-group taxonomy maps cleanly to **owning subsystems** that already exist in the codebase: the daemon proxy (group A/B) is a forwarder to `hushd`; agent_mgmt (C) talks to `Settings` / `HushdUpdater` / `DaemonManager`; the five EDR groups (D–I) all flow through `AgentApiState.edr_*` ledgers; OpenClaw (J) wraps `OpenClawManager`; approvals/enrollment/bootstrap (K) wrap `ApprovalQueue` and `SessionManager`. Each group is independently testable and has roughly the right LOC for a single-author code review.

---

## Recommended Commit Sequence

Each commit compiles and `cargo test -p clawdstrike-agent` passes. No commit changes route behaviour or wire format. The PR can land in five if necessary; eight is more reviewable.

### Commit 1 — `refactor(agent-api): extract state, types, and rate limiters into api/state.rs`

- Create `apps/agent/src-tauri/src/api/mod.rs` and `apps/agent/src-tauri/src/api/state.rs`.
- Move `AgentApiServer`, `AgentApiServerDeps`, `AgentApiState`, `ControlAckPostbackRetrySink`, `ControlAckPostbackRetryRequest`, `FleetHuntEventPublisher`, `PolicyVersionCache`, `ApprovalSubmissionLimiter`, `RouteRateLimiter`, `UiBootstrapSession`, `PreviousAuthToken`, `UiBootstrapStartInput`/`Response`/`VerifyInput`, and the `impl AgentApiServer::new` constructor.
- Move the 16 `default_edr_*_path()` and `default_edr_*_ledger()` factories.
- In `api_server.rs`, add `mod api; pub use crate::api::*;` so external imports keep working.
- **LOC moved:** ~970. **Risk:** low (pure move, no behaviour change).

### Commit 2 — `refactor(agent-api): introduce AgentApiError and IntoResponse`

- Create `apps/agent/src-tauri/src/api/error.rs` with the enum from §Required Shared Modules.
- Add `From<anyhow::Error> for AgentApiError` and `IntoResponse`.
- Add type alias `pub type ApiResult<T> = Result<T, AgentApiError>;`.
- **Do not change any handler signature yet.** Add a back-compat `From<AgentApiError> for (StatusCode, String)` so existing call sites continue to work.
- Delete `internal_error()` and `map_openclaw_error()`; replace call sites with `AgentApiError::Internal(err.into())` / `AgentApiError::OpenClawTransport(...)`.
- **LOC moved:** +250, –60. **Risk:** low; behaviour preserved by the back-compat From impl.

### Commit 3 — `refactor(agent-api): split auth, middleware, proxy into api/`

- Move `require_auth`, `auth_token_matches`, `auth_token_from_cookie`, `auth_cookie_header_value`, `set_ui_auth_cookie`, `merged_authorization_header`, `request_is_secure*`, `is_local_host_header`, `has_query_param`, `query_param`, `current_auth_token`, `current_token_grace_minutes`, `set_token_grace_minutes`, `rotate_local_api_token_*` → `api/auth.rs`.
- Move `attach_ui_auth_cookie`, `route_rate_limit` → `api/middleware.rs`.
- Move `build_daemon_proxy_target`, `send_daemon_get_request`, `send_daemon_request`, `proxy_http_response`, `proxy_daemon_get`, `proxy_daemon_events`, `proxy_daemon_mutation` → `api/proxy.rs`.
- While moving proxy, **collapse duplicates 1, 2, 3 from §Duplicate Handlers** (see above): `proxy_daemon_get` becomes `proxy_daemon_get_or_events(..., stream: bool)`, `send_daemon_get_request` becomes a 1-line wrapper.
- **LOC moved:** ~1,400. **Risk:** medium (rate-limit and auth tests at 22620–22890 need their `use` paths updated).

### Commit 4 — `refactor(agent-api): extract non-EDR routes (router stays in api_server)`

- Create `api/routes/{ui_bootstrap,agent_health,agent_settings,agent_integrations,agent_ota,agent_policy_check,approvals,enrollment,openclaw,broker_proxy}.rs`.
- Move the 30 production handler bodies into the appropriate file.
- Leave `AgentApiServer::start` and its `Router::new()` chain in `api_server.rs` for now, importing handlers from `crate::api::routes::*`.
- **LOC moved:** ~6,800. **Risk:** medium (many imports; lots of `pub(crate)` visibility adjustments). Tests in `mod tests` at the bottom of `api_server.rs` still pass because they only need the handler symbols to be re-exported by `pub use crate::api::routes::*;`.

### Commit 5 — `refactor(agent-api): extract EDR helpers into edr/helpers/`

This is the largest commit; consider splitting in two (5a: receipts/flight-recorder/providers/redaction; 5b: response actions and control postbacks). The submodules are listed in the §Target file layout.

- Move ~14,000 LOC of EDR-only helpers out of `api_server.rs` into `edr/helpers/*.rs`.
- Update `edr/handlers/*.rs` imports from `use crate::api_server::*;` to `use crate::edr::helpers::*;`.
- The `pub(crate) use crate::edr::handlers::*;` re-exports at the top of `api_server.rs` (lines 91–96) can now be deleted because the handlers are referenced through `crate::edr::handlers::...` directly.
- **LOC moved:** ~14,000. **Risk:** high — this is the single biggest change. Strongly recommend running `cargo clippy --workspace -- -D warnings` after every sub-step and using `cargo expand` to verify macro-generated code didn't shift. Use feature-gated `#[cfg(unix)] / #[cfg(not(unix))]` pairs (`signal_process`, `current_parent_pid`, `process_suspend_signal`, etc.) collocated in `response_actions/suspend_process_tree.rs`.

### Commit 6 — `refactor(agent-api): move router to api/router.rs and add RequireAuth extractor`

- Move `AgentApiServer::start` and its `Router::new()` chain into `api/router.rs`.
- Reduce `api_server.rs` to a ~150-line facade containing only `pub use crate::api::*;` and the crate doc-comment.
- Replace the 44 in-body `require_auth(&headers, &state)?;` calls with `RequireAuth` extractor in handler arguments **or** lift to `.route_layer(middleware::from_fn(require_auth_layer))` applied to all `/api/v1/*` routes (excluding `/api/v1/ui/bootstrap/start`). Public-by-design routes — `/ui/bootstrap*`, the static `/ui/*` — stay out of that layer.
- Now Group K's `start_ui_bootstrap` no longer needs to be public because the route is on the outer (unlayered) router.
- **LOC moved:** ~400 (router) + 88 lines of `require_auth` prologue deleted from handlers. **Risk:** medium-low; the auth tests at 22620–22890 already cover the cookie-vs-Bearer matrix.

### Commit 7 — `refactor(agent-api): introduce test_support and dedupe single-route test rigs`

- Create `apps/agent/src-tauri/src/api/test_support.rs` (gated `#[cfg(test)]`) with `test_state()`, `single_route_app()`, `auth_request()`, and a `test_signer()` helper.
- Replace the 162 `let app = Router::new().route(...).with_state(...);` blocks in `mod tests` with `let app = single_route_app(path, handler);`.
- The 80 `agent_edr_findings` mountings collapse to one helper; the duplicated `let state = ...;` 30-line constructions collapse to `let state = test_state();`.
- Split the giant `mod tests` (currently ~28,800 lines) into per-file `#[cfg(test)] mod tests` blocks colocated with each module from commits 3–5. The mechanical rule: a test goes where the handler it exercises lives.
- **LOC moved:** ~28,000 (test code redistributed); ~6,800 lines of boilerplate deleted. **Risk:** low for correctness (tests still pass), high for diff size (mostly a `git mv` and a few sed passes). Recommend doing this as a separate PR.

### Commit 8 — `refactor(agent-api): unify response-action executors behind a trait`

- In `edr/helpers/response_actions/mod.rs`, define:
  ```rust
  #[axum::async_trait]
  pub(crate) trait ResponseActionExecutor: Send + Sync {
      fn supported_action(&self) -> EndpointDecisionAction;
      async fn execute(&self, ctx: &mut ResponseExecutionCtx<'_>) -> ApiResult<ResponseExecutionOutcome>;
      async fn rollback(&self, ctx: &mut ResponseExecutionCtx<'_>) -> ApiResult<RollbackOutcome>;
  }
  ```
- Implement for `CollectEvidence`, `RestrictEgress`, `QuarantineFile`, `DisablePersistence`, `RevokeGrant`, `SuspendProcessTree`.
- Replace the match-on-action dispatch in `execute_edr_response_action` (currently at line 6054) with `registry.executor_for(action).execute(&mut ctx).await`.
- Adds testability for response actions independent of HTTP wiring; collapses ~12 sibling-function pairs (`execute_X_response` + `execute_X_rollback`) to one impl block each.
- **LOC moved:** none (it's a refactor); ~500 lines of dispatch glue deleted. **Risk:** medium — the response-action tests (~30 of them) are the most behaviour-sensitive in the file. Run them under `RUST_LOG=debug` to verify no receipt-emission ordering change.

---

## Notes for the owner

- **Backwards-compatible URL surface.** No route paths or response shapes change across any commit. The Tauri frontend (`apps/agent/src/`) and the control-console (`packages/control-console/`) need zero changes.
- **Cargo unit-of-compilation.** Splitting into a `mod api` submodule does not change the compilation unit — `api_server.rs` is part of `clawdstrike-agent` and so are all the new files. There is no need to split into a workspace crate, although doing so for `edr/helpers/response_actions/` later (e.g. `clawdstrike-agent-response`) would make sense given its volume and self-contained nature.
- **The pre-existing `edr/handlers/` split is the model.** Whoever did that work in commit `eff…` showed the pattern is feasible. Commits 4–5 above just complete the job by moving the helpers the handlers depend on.
- **Don't refactor and rebehave at the same time.** Commits 1–7 are pure structural moves with the back-compat `From<AgentApiError> for (StatusCode, String)` impl preserving wire output. Commit 8 (response-action trait) is the first commit that could theoretically change observable behaviour — keep it last and lean on the existing `agent_edr_response_action_*` tests.
- **CI gates.** Run `mise run ci` (the project's local CI script) after every commit. The file-by-file moves should leave clippy lint-clean because the workspace already enforces `-D warnings`.

---

*Audit produced 2026-05-23 against `apps/agent/src-tauri/src/api_server.rs` at branch HEAD `2eff91532`.*
