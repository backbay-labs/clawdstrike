# Clawdstrike SIEM/SOAR Full Roadmap (Combined Plan)

This document consolidates the SIEM/SOAR integration specs in this folder into one end-to-end implementation roadmap:
- `docs/plans/siem-soar/overview.md`
- `docs/plans/siem-soar/splunk.md`
- `docs/plans/siem-soar/elastic.md`
- `docs/plans/siem-soar/datadog.md`
- `docs/plans/siem-soar/sumo-logic.md`
- `docs/plans/siem-soar/pagerduty-opsgenie.md`
- `docs/plans/siem-soar/slack-teams.md`
- `docs/plans/siem-soar/stix-taxii.md`

## Goals

1. Export high-fidelity Clawdstrike security telemetry to common SOC platforms (SIEM + SOAR).
2. Standardize on a canonical security event model and support schema transforms (ECS/CEF/OCSF).
3. Provide production-grade delivery guarantees (batching, retry/backoff, DLQ, health checks, rate limiting).
4. Enable common workflows: detection + correlation, alerting + escalation, and threat-intel-driven blocking.

## Non-goals (initial GA)

- A full SOAR playbook engine (beyond “hooks” and outbound integrations).
- Full bidirectional “approve/deny” controls in Slack/Teams (leave as post-GA).
- Replacing or redesigning existing Clawdstrike audit storage (reuse and map where possible).

## Guiding principles

- **Canonical first:** emit a stable `SecurityEvent` early, then transform downstream.
- **Least privilege & secret safety:** never log secrets, enable rotation, and default to TLS verification.
- **Privacy by default:** support PII redaction and configurable field exclusion before export.
- **Backpressure over loss:** when exporters cannot keep up, apply buffering + rate limiting + DLQ with clear operator signals.
- **Composable exports:** multiple exporters can run concurrently with independent filtering/routing.
- **Test like prod:** include mock servers + integration tests per platform, and an E2E harness for the pipeline.

## Target capabilities (scope matrix)

| Capability | GA | Notes |
|---|---:|---|
| Canonical `SecurityEvent` schema (Rust + TS) | ✅ | With versioning + validation |
| Exporter framework (batching/retry/rate limit/DLQ) | ✅ | Shared base for all exporters |
| Splunk (HEC) | ✅ | Including ack tracking + Splunk knowledge objects |
| Elastic (ECS + Bulk API) | ✅ | Including ILM + detection rule templates |
| Datadog (Logs + Metrics + APM correlation) | ✅ | Including dashboards + monitors templates |
| Sumo Logic (HTTP Source) | ✅ | Including field extraction + dashboard/search templates |
| PagerDuty (Events API v2) | ✅ | Including routing + auto-resolve |
| OpsGenie (Alerts API + heartbeat) | ✅ | Including routing + heartbeat |
| Slack + Teams webhooks | ✅ | With routing, formatting, and rate limiting |
| Generic webhooks (templated) | ✅ | Auth + headers + templates |
| STIX/TAXII consumption + enrichment | ✅ | Guard integration + caching |
| Publish Clawdstrike detections as STIX | ⏳ | Post-GA enhancement (TI-6) |

## Architecture implementation decisions (to lock early)

1. **Where exporters run**
   - **Preferred:** run exporters inside `hushd` (or a dedicated “exporter service”) so they can subscribe to the same event stream used for SSE and persist via existing audit storage.
   - **Optional:** provide a library-first path for embedding exporters directly into TypeScript runtimes (for client-side or edge use).

2. **Event source of truth**
   - Use the canonical `SecurityEvent` as the “export model”.
   - Provide deterministic mapping from the existing audit representation (e.g., `AuditEvent`) into `SecurityEvent`.

3. **Schema transforms**
   - ECS (Elastic) is the first-class transform.
   - CEF and OCSF are implemented as additional transforms that can be selected per-exporter.

4. **Reliability stance**
   - Retries for retryable errors (429/5xx/network) with exponential backoff.
   - DLQ for permanent failures and repeated retry exhaustion.
   - Health checks per exporter + aggregated “export health”.

## Roadmap overview (12-week plan)

Weeks are relative to project kickoff (`Week 1 = start of implementation`). This aligns with the phase breakdown in `overview.md` and the per-integration phase notes in each platform spec.

### Phase 1: Foundation (Weeks 1–4)

**Primary outcomes:** `SecurityEvent` + `EventBus` + exporter framework + first two P0 integrations (Splunk + PagerDuty) + E2E harness.

| Week | Deliverables (high-level) |
|---:|---|
| 1 | Canonical `SecurityEvent` schema + validation; Event emission points; EventBus (Rust + TS) |
| 2 | Exporter base (batching/flush/retry/rate limit); credential provider abstraction; global configuration |
| 3 | Splunk HEC exporter (core) + PagerDuty exporter (core); unit tests + mocks |
| 4 | Splunk reliability (ack/DLQ/rate limiting); credential rotation; Prometheus metrics; E2E harness v1 + docs |

### Phase 2: Enterprise SIEMs (Weeks 5–8)

**Primary outcomes:** Elastic ECS exporter, Datadog + Sumo exporters, CEF/OCSF transforms, multi-exporter routing, and performance hardening.

| Week | Deliverables (high-level) |
|---:|---|
| 5 | Elastic exporter (Bulk API) + ECS transformation pipeline; index templates + ILM |
| 6 | Datadog exporter (Logs/Metrics/APM) + Sumo exporter (HTTP Source); prod-grade retry/DLQ/health for both |
| 7 | CEF transform + OCSF transform; schema validation + field mapping overrides |
| 8 | Multi-exporter routing + conditional rules; benchmarks + backpressure tuning; operator runbooks |

### Phase 3: SOAR & Intelligence (Weeks 9–12)

**Primary outcomes:** OpsGenie, Slack/Teams/Generic webhooks, STIX/TAXII ingestion + guard integration, response automation hooks, final QA and GA.

| Week | Deliverables (high-level) |
|---:|---|
| 9 | OpsGenie exporter + Slack webhook exporter; routing/dedup/state management hardening |
| 10 | Teams exporter + generic webhook exporter; templating + auth options |
| 11 | TAXII 2.1 client + STIX 2.1 parsing; feed polling + cache persistence + dedup |
| 12 | Guard integration + event enrichment; multi-feed + rate limit; response hooks; final testing + GA |

## Detailed work breakdown (workstreams + checklists)

### Workstream A — Canonical events, validation, and enrichment

**Deliverables**
- `SecurityEvent` (Rust + TS) with stable field naming, versioning, and validation.
- Deterministic mapping from existing audit records into `SecurityEvent`.
- Optional enrichment hooks (MITRE mapping, threat-intel context, environment/tenant labels).

**Implementation checklist**
- [ ] Freeze `SecurityEvent` schema and enumerations (event types/categories/severity/outcome).
- [ ] Introduce schema version field and compatibility policy (additive vs breaking).
- [ ] Implement validation (type checks, required fields, timestamp format, ID format).
- [ ] Implement mapping layer `AuditEvent -> SecurityEvent` (lossless where possible).
- [ ] Define canonical severity scale and mappings to platform severity fields.
- [ ] Define and implement pre-export privacy controls:
  - [ ] PII/secret redaction policy (configurable)
  - [ ] Field allowlist/denylist and value masking support
  - [ ] “include raw event” behavior aligned with privacy settings
- [ ] Add enrichment hooks:
  - [ ] MITRE ATT&CK mapping fields (`threat.tactic`, `threat.technique`)
  - [ ] Threat intel enrichment (STIX/TAXII-driven indicator context)
  - [ ] Environment/tenant labels (from global config)

**Acceptance criteria**
- All exported events validate against the canonical schema and unit-test fixtures.
- A single source event results in stable transformed outputs (deterministic transforms).

### Workstream B — EventBus + export pipeline orchestration

**Deliverables**
- A runtime event stream (`EventBus`) supporting multiple subscribers (audit storage, SSE streaming, exporters).
- `ExporterManager` that hosts multiple exporters concurrently with filtering, routing, and lifecycle management.

**Implementation checklist**
- [ ] Implement `EventBus` in Rust and TS:
  - [ ] Typed subscriptions and event filtering
  - [ ] Backpressure strategy (bounded channels, drop policy, or spill-to-disk)
  - [ ] Graceful shutdown semantics
- [ ] Add `ExporterManager`:
  - [ ] Multi-exporter fanout (N exporters receive the same canonical events)
  - [ ] Per-exporter filtering (min severity, include/exclude types/guards/tenants)
  - [ ] Conditional routing rules (e.g., severity -> exporter/index/channel)
  - [ ] Exporter lifecycle: init, periodic health checks, shutdown
  - [ ] Aggregated export health + metrics
- [ ] Emit exporter operational audit events (for compliance/forensics):
  - [ ] Per-batch success/failure summaries
  - [ ] DLQ enqueue events and replay attempts
  - [ ] Exporter config reload/change events (when supported)
- [ ] Add on-disk buffering for outage tolerance (optional but recommended for GA):
  - [ ] Spill buffer to disk when queues exceed memory thresholds
  - [ ] Replay on restart with idempotency/dedup considerations

**Acceptance criteria**
- Multiple exporters can be enabled simultaneously without event duplication bugs or head-of-line blocking.
- Export pipeline survives transient outages without crashing and provides operator-visible signals (health/metrics/DLQ).

### Workstream C — Exporter framework (shared building blocks)

**Deliverables**
- Shared exporter trait/interface + base implementation supporting batching, retries, rate limiting, compression, and DLQ integration.
- Shared HTTP client building blocks (timeouts, pooling, TLS, proxy, headers).
- Credential provider abstraction with multiple backends.

**Implementation checklist**
- [ ] Implement `Exporter` trait/interface and `BaseExporter` buffering/flush logic.
- [ ] Standardize export result reporting (per-event errors, retryable flag, counts).
- [ ] Add retry/backoff utilities (exponential backoff, jitter, max retry cap).
- [ ] Add rate limiting (token bucket + adaptive limiter support).
- [ ] Add compression helpers (gzip) for exporters that support it.
- [ ] Implement DLQ interface + default implementation:
  - [ ] Persist failed events to disk (bounded size)
  - [ ] Provide replay tooling and visibility (count, last error, sample)
- [ ] Credentials:
  - [ ] Define a `CredentialProvider` interface (env/file/k8s/vault)
  - [ ] Add rotation/refresh and caching semantics
  - [ ] Ensure secret redaction in logs/errors
- [ ] Add common health check and metrics conventions across exporters.

**Acceptance criteria**
- Every exporter uses the shared framework (no bespoke retry/batching logic).
- Exporter common behaviors are unit-tested once and reused everywhere.

### Workstream D — Schema transformations (ECS / CEF / OCSF)

**Deliverables**
- A schema registry/transform layer that converts canonical events into target schemas.
- Configurable field mapping overrides and “include raw event” option.

**Implementation checklist**
- [ ] Implement ECS transformer (driven by `elastic.md` mapping tables).
- [ ] Implement CEF transformer (ArcSight-focused mapping).
- [ ] Implement OCSF transformer (v1.x mapping).
- [ ] Add validation for transformed events (schema-specific checks).
- [ ] Add user-configurable field mappings and allowlist/denylist field inclusion.
- [ ] Ensure deterministic transforms and stable field naming.

**Acceptance criteria**
- ECS output indexes cleanly in Elastic without custom mapping hacks.
- CEF and OCSF outputs validate and pass sample ingestion tests.

### Workstream E — SIEM exporters

#### E1. Splunk (HEC)

**Deliverables**
- `SplunkExporter` using HEC with batching, compression, and optional indexer acknowledgments.
- Knowledge objects bundle (field extractions + lookups + severity CSV) and dashboard/search templates.

**Implementation checklist**
- [ ] Core HEC client (HTTPS POST) with connection pooling and timeouts.
- [ ] Event formatting for HEC payloads (host/source/sourcetype/index fields).
- [ ] BatchManager (size + time flush), gzip compression.
- [ ] AckTracker (channel management + polling acknowledgments).
- [ ] Adaptive rate limiting (respond to 429).
- [ ] Token rotation support (Vault) and Kubernetes secret integration.
- [ ] TLS hardening:
  - [ ] Custom CA support
  - [ ] Optional mTLS (client cert/key)
- [ ] DLQ wiring and replay support for permanently failed events.
- [ ] Prometheus metrics exposure for exporter internals.
- [ ] Artifacts:
  - [ ] `props.conf` and `transforms.conf` per spec
  - [ ] `clawdstrike_severity.csv`
  - [ ] Search examples + dashboard XML

**Acceptance criteria**
- Events appear in Splunk within target latency; ack mode provides delivery guarantees.
- Splunk knowledge objects provide usable searches/dashboards without custom parsing.

#### E2. Elastic (ECS + Bulk API)

**Deliverables**
- `ElasticExporter` with ECS transformation and Bulk API indexing, including templates + ILM policies.
- Detection rule templates + Kibana dashboard exports.

**Implementation checklist**
- [ ] ECS transformer completeness for all canonical event types.
- [ ] BulkProcessor with flush thresholds, backpressure, and partial failure handling.
- [ ] IndexManager:
  - [ ] index templates, mappings, and settings
  - [ ] ILM policy creation and rollover strategy
- [ ] ConnectionPool + retry/backoff + DLQ.
- [ ] Auth provider support (API key, user/pass, Elastic Cloud).
- [ ] Enterprise:
  - [ ] mTLS support
  - [ ] Cross-cluster replication support (if required)
- [ ] Artifacts:
  - [ ] Example detection rules JSON
  - [ ] Kibana saved objects (dashboards)

**Acceptance criteria**
- ECS-formatted events are searchable in Elastic Security with out-of-the-box dashboards/rules.
- Bulk indexing handles high volume with predictable backpressure and no silent drops.

#### E3. Datadog (Logs + Metrics + APM correlation)

**Deliverables**
- `DatadogExporter` for logs ingestion (and optional metrics + APM correlation).
- Dashboard + monitor JSON templates.

**Implementation checklist**
- [ ] Logs intake (Logs API v2) with gzip compression and tag formatting.
- [ ] Site routing (datadoghq.com / datadoghq.eu / etc.).
- [ ] Metrics emission (Series API) and aggregation strategy.
- [ ] Trace correlation (inject trace/span IDs when available).
- [ ] Multi-region and failover considerations.
- [ ] Post-GA / optional enhancements:
  - [ ] Cloud SIEM detection rule guidance
  - [ ] Security Signals integration strategy
- [ ] Artifacts:
  - [ ] Dashboard JSON template
  - [ ] Monitor JSON templates (critical violations, high denial rate)

**Acceptance criteria**
- Security events are visible in Datadog logs with useful tags and can trigger monitors.

#### E4. Sumo Logic (HTTP Source)

**Deliverables**
- `SumoLogicExporter` using HTTP Source with metadata headers and configurable message formats.
- Field extraction rules + saved search/alert/dashboard templates.

**Implementation checklist**
- [ ] HTTPSourceClient with gzip compression and timeouts.
- [ ] MessageFormatter (json/text/key-value) and timestamp behavior.
- [ ] Metadata headers (category, name, host, fields).
- [ ] PartitionRouter for multi-tenant and severity routing.
- [ ] Retry/backoff, DLQ integration.
- [ ] Post-GA / optional enhancements:
  - [ ] Cloud SIEM integration patterns and detections
- [ ] Artifacts:
  - [ ] Field extraction rules (FER)
  - [ ] Query templates + alert configs
  - [ ] Dashboard JSON export

**Acceptance criteria**
- Events land in correct source categories/partitions and can be queried with provided templates.

### Workstream F — SOAR + notifications exporters

#### F1. PagerDuty + OpsGenie (incident management)

**Deliverables**
- PagerDuty Events API v2 integration with routing, deduplication, and auto-resolve.
- OpsGenie Alerts API integration with routing and heartbeat monitoring.

**Implementation checklist**
- [ ] Implement clients (`PagerDutyClient`, `OpsGenieClient`) with auth and endpoint configuration.
- [ ] AlertRouter:
  - [ ] severity mapping and filtering
  - [ ] routing by guard and tenant
- [ ] Deduplication manager (configurable key templates + window).
- [ ] State tracking (open/acked/resolved) + auto-resolve logic.
- [ ] OpsGenie heartbeat integration for exporter health.
- [ ] Reliability:
  - [ ] retry/backoff + circuit breaker
  - [ ] DLQ for non-retryable failures
- [ ] Documentation and examples.

**Acceptance criteria**
- Critical violations trigger incidents/alerts with stable dedup keys and correct routing.
- Auto-resolve closes incidents when violations stop per configured policy.

#### F2. Slack + Microsoft Teams + generic webhooks (collaboration + lightweight SOAR)

**Deliverables**
- Slack webhook integration with Block Kit formatting, routing, threading, and rate limiting.
- Teams webhook integration with Adaptive Cards (and MessageCard fallback).
- Generic webhook exporter with templated payload formatting and auth options.

**Implementation checklist**
- [ ] Slack:
  - [ ] SlackFormatter (Block Kit + rich context)
  - [ ] ChannelRouter (severity/guard/tenant)
  - [ ] ThreadManager (session-based grouping with TTL)
  - [ ] Per-channel rate limiting
- [ ] Teams:
  - [ ] TeamsFormatter (Adaptive Cards + fallback)
  - [ ] Routing configuration
- [ ] Generic:
  - [ ] Template engine (Handlebars) and payload rendering
  - [ ] Auth methods (bearer/basic/header) and custom headers
- [ ] Documentation and examples.

**Acceptance criteria**
- Notifications are actionable and readable, avoid flooding via routing + rate limiting, and group related events.

### Workstream J — Response automation hooks (SOAR)

**Deliverables**
- A small, safe “response hook” layer to trigger automation from selected security events (without becoming a full playbook engine).

**Implementation checklist**
- [ ] Define `ResponseHook` interface (event in → action out) with:
  - [ ] strict allowlisting of hook types/actions
  - [ ] idempotency keys and deduplication guidance
  - [ ] timeout + sandboxing strategy (no unbounded user code)
- [ ] Provide built-in hook implementations:
  - [ ] invoke generic webhook with a response payload
  - [ ] optional: integrate with existing incident creation exporters (PagerDuty/OpsGenie) as “actions”
- [ ] Configuration:
  - [ ] select which event types/severities trigger hooks
  - [ ] rate limiting and retry policy per hook
- [ ] Observability:
  - [ ] per-hook success/failure metrics and DLQ integration where applicable

**Acceptance criteria**
- Hooks can be enabled safely with bounded blast radius and clear operator signals.

### Workstream G — Threat intelligence (STIX/TAXII)

**Deliverables**
- TAXII 2.1 client + STIX 2.1 parser for indicator ingestion.
- Feed manager with polling, caching, deduplication, and persistence.
- Guard integration (egress and path protections) + event enrichment.

**Implementation checklist**
- [ ] TAXII client:
  - [ ] TAXII 2.1 requests with pagination
  - [ ] auth (basic / API key / client cert)
  - [ ] rate limiting and error handling
- [ ] STIX:
  - [ ] Parse STIX 2.1 indicators + supported types
  - [ ] Support key indicator pattern types (domain/ip/url/file hashes)
- [ ] FeedManager:
  - [ ] polling schedules and incremental fetch (addedAfter)
  - [ ] IndicatorCache (TTL + persistence + eviction)
  - [ ] Deduplication strategy (hash/id based)
- [ ] Guard integration:
  - [ ] EgressGuard integration (block malicious domains/IPs)
  - [ ] Optional path blocking integration (as configured)
  - [ ] Event enrichment with threat context (confidence, actor, campaign)
- [ ] Operationalization:
  - [ ] Health monitoring and metrics (cache stats, poll results)
  - [ ] Example TAXII server configurations (OpenCTI/MISP/OTX/CISA patterns)

**Acceptance criteria**
- Indicators are ingested and applied within configured polling windows.
- Guard decisions reflect threat intel updates without requiring manual allowlist edits.

### Workstream H — Testing, QA, and performance

**Deliverables**
- Unit tests per module and exporter with mock endpoints.
- Integration tests against real services (or containers) where feasible.
- End-to-end harness that generates canonical events and validates ingestion.
- Performance benchmarks and load tests tied to success metrics.

**Implementation checklist**
- [ ] Build mock servers for:
  - [ ] Splunk HEC (including ack endpoints)
  - [ ] Elasticsearch Bulk API
  - [ ] Datadog intake endpoints
  - [ ] Sumo HTTP source
  - [ ] PagerDuty + OpsGenie APIs
  - [ ] Slack/Teams webhooks
  - [ ] TAXII server (STIX payload fixtures)
- [ ] E2E harness scenarios:
  - [ ] “critical violation” fanout to all enabled exporters
  - [ ] retryable outage simulation (429/5xx) + recovery
  - [ ] DLQ write + replay workflow
  - [ ] threat intel feed update -> egress block -> exported enriched event
- [ ] Benchmarks:
  - [ ] sustained throughput tests (events/sec)
  - [ ] p99 latency from decision to exporter send
  - [ ] memory growth under backpressure

**Acceptance criteria**
- Meets success metrics from `overview.md` (latency, success rate, schema compliance, coverage).
- Failure modes are observable and recoverable (no silent drops).

### Workstream I — Documentation, packaging, and operator experience

**Deliverables**
- A single “how to enable SIEM/SOAR exports” guide (config + examples).
- Per-platform setup guides (tokens, endpoints, dashboards/alerts/rules import).
- Runbooks for troubleshooting (429, auth failures, DLQ replay).

**Implementation checklist**
- [ ] Consolidated configuration reference (global + per exporter).
- [ ] Example configs for:
  - [ ] local development (single exporter)
  - [ ] production (multiple exporters + routing)
  - [ ] Kubernetes deployment (secrets/configmaps)
- [ ] Platform artifact packaging and versioning strategy:
  - [ ] Splunk app bundle
  - [ ] Elastic rule and dashboard exports
  - [ ] Datadog dashboards/monitors JSON
  - [ ] Sumo FER + dashboards + saved searches
- [ ] Operator UX:
  - [ ] clear logs and metrics naming conventions
  - [ ] exporter health status summaries
- [ ] Access control and change auditability:
  - [ ] RBAC/authz for exporter management (where configuration is exposed via an API)
  - [ ] audit trail for exporter configuration changes
  - [ ] separate credentials per exporter and environment

## Success metrics (GA targets)

| Metric | Target |
|---|---|
| Event latency (p99) | < 500ms (decision → ingestion attempt) |
| Export success rate | > 99.9% |
| Schema compliance | 100% for enabled transform outputs |
| Integration coverage | 8 platforms (as listed above) |
| Documentation coverage | 100% of public config and APIs |

## Risks and mitigations

1. **Backpressure + memory growth**
   - Mitigation: bounded queues, spill-to-disk buffers, explicit drop policy + alerts.
2. **Schema drift across languages**
   - Mitigation: single source schema definition + generated types (recommended), shared test vectors.
3. **Vendor API throttling and limits**
   - Mitigation: adaptive rate limiting, batching, retry budgets, and per-exporter circuit breakers.
4. **Credential leakage**
   - Mitigation: redaction, never log raw secrets, rotation support, least-privilege scopes.
5. **Operational complexity**
   - Mitigation: strong defaults, examples, health dashboards, and runbooks.

## Post-GA enhancements (backlog)

- Publish Clawdstrike detections back out as STIX (TI-6).
- Interactive Slack/Teams actions (acknowledge, open incident, “request approval” flows).
- More SIEMs via CEF/OCSF targets and additional native connectors (ArcSight, Sentinel, Chronicle).
- Advanced correlation: join audit, runtime, and network telemetry via trace IDs.
