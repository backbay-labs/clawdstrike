# Secret Broker

> **Status:** Draft | **Date:** 2026-03-12
> **Audience:** platform, daemon, adapter, cloud, and enterprise teams
> **Scope:** plan set for a brokered egress execution tier in Clawdstrike

This planning set defines how Clawdstrike should evolve from a tool-boundary policy engine into a
policy-governed **egress execution plane** for outbound requests that require secrets.

The core thesis is simple:

1. Clawdstrike already decides whether outbound actions should be allowed.
2. It does not yet own the point where provider credentials are materialized.
3. A broker tier is valuable only if it binds credential use to Clawdstrike identity, posture,
   policy hash, and receipts.
4. The first version should be **explicit and provider-scoped**, not a generic transparent proxy.

## Reading Order

1. [Current State](./current-state.md)
2. [Target Architecture](./target-architecture.md)
3. [Spec 19: Secret-Broker Egress Tier](../../../specs/19-secret-broker-egress-tier.md)
4. [Implementation Roadmap](./roadmap.md)

## Initial Thesis

- Existing egress and output controls are necessary but not sufficient for secret-safe outbound
  execution.
- The broker should be treated as a **new enforcement tier**, not as a replacement for `hushd` or
  `HushEngine`.
- The first release should optimize for enterprise differentiation, clear proofs, and low
  operational ambiguity.
- A transparent MITM design is too large a first bet. Explicit broker execution is the right path.

## Second-Pass Conclusions

- The repo already names brokered tools as **Tier 2** enforcement, so this project extends the
  current architecture instead of inventing a parallel model.
- The current TS adapter contract is more capable than it first appears:
  `InterceptResult.modifiedInput`, `modifiedParameters`, and especially `replacementResult` already
  allow broker-backed execution without breaking `PolicyEngineLike`.
- The cleanest first adoption path is **provider/framework wrappers** such as
  `packages/adapters/clawdstrike-openai/src/secure-tools.ts`, not a repo-wide dispatcher rewrite.
- `hushd` already has enough identity and session context to mint meaningful broker capabilities.
- `hush-proxy` should be treated as reusable parsing/policy utility code, not as the future broker
  daemon.

## Existing Code Touchpoints

| Area | Current Files | Direction |
| --- | --- | --- |
| Interceptor execution handoff | `packages/adapters/clawdstrike-adapter-core/src/base-tool-interceptor.ts` | Add broker intent plumbing and optional synthetic execution |
| Tool-boundary wrappers | `packages/adapters/clawdstrike-adapter-core/src/framework-tool-boundary.ts`, `packages/adapters/clawdstrike-adapter-core/src/secure-tool-wrapper.ts` | Reuse existing `replacementResult` / input rewrite flow before adding new interfaces |
| Adapter contract types | `packages/adapters/clawdstrike-adapter-core/src/adapter.ts`, `packages/adapters/clawdstrike-adapter-core/src/interceptor.ts`, `packages/adapters/clawdstrike-adapter-core/src/engine.ts` | Keep `PolicyEngineLike` stable in v1; add broker config/types around it |
| Network target parsing | `packages/adapters/clawdstrike-adapter-core/src/policy-event-factory.ts`, `packages/adapters/clawdstrike-adapter-core/src/network-target.ts` | Reuse for explicit HTTPS target normalization |
| Framework adoption seam | `packages/adapters/clawdstrike-openai/src/secure-tools.ts`, `packages/adapters/clawdstrike-openai/src/tool-boundary.ts` | First broker-backed framework integration path |
| Remote engine fallback | `packages/adapters/clawdstrike-hushd-engine/src/strike-cell.ts` | Preserve degraded mode for normal evals, but fail closed for broker-required actions |
| Policy engine egress checks | `crates/libs/clawdstrike/src/engine.rs` | Keep as authorization source of truth |
| Policy schema | `crates/libs/clawdstrike/src/policy.rs` | Add broker policy surface alongside guards/origins |
| Daemon request handling | `crates/services/hushd/src/api/mod.rs`, `crates/services/hushd/src/api/check.rs`, `crates/services/hushd/src/state.rs`, `crates/services/hushd/src/config.rs` | Add capability issuance, evidence ingestion, and broker config/dependencies |
| Agent packaging | `apps/agent/src-tauri/src/settings.rs`, `apps/agent/scripts/prepare-bundled-hushd.sh`, `apps/agent/README.md` | Add local broker lifecycle and packaging plan |
| Existing architectural docs | `docs/src/concepts/enforcement-tiers.md` | Keep terminology aligned with current Tier 2 brokered-tools model |
| Proxy utilities | `crates/libs/hush-proxy/src/lib.rs` | Reuse only for DNS/SNI/domain policy helpers if useful |

## Deliverables In This Set

- a current-state review of what the repo already provides
- a target architecture for a brokered egress tier
- a formal product/architecture spec
- a phased implementation roadmap tied to likely repo touchpoints

## Local Dev Bring-Up

The first runnable slice now has three concrete components:

1. `hushd` with `broker.enabled = true`
2. `clawdstrike-brokerd` with a trusted hushd signing public key and a local secret file
3. a TS caller using `@clawdstrike/broker-client` or the broker-aware OpenAI wrapper

### Minimum policy snippet

```yaml
version: "1.5.0"
guards:
  egress_allowlist:
    enabled: true
    allow:
      - "api.openai.com"
broker:
  enabled: true
  providers:
    - name: "openai"
      host: "api.openai.com"
      port: 443
      exact_paths: ["/v1/responses"]
      methods: ["POST"]
      secret_ref: "openai/prod"
      allowed_headers: ["content-type"]
      require_body_sha256: true
```

### `hushd` config

Set:

- `broker.enabled = true`
- `broker.capability_ttl_secs = 60`
- `broker.allow_http_loopback = true` only for local loopback tests; leave it `false` for real deployments
- a persistent `signing_key` so brokerd can trust a stable hushd public key

### `brokerd` environment

`clawdstrike-brokerd` currently reads env vars directly:

- `CLAWDSTRIKE_BROKERD_LISTEN`
- `CLAWDSTRIKE_BROKERD_HUSHD_URL`
- `CLAWDSTRIKE_BROKERD_HUSHD_TOKEN` optional
- `CLAWDSTRIKE_BROKERD_SECRET_BACKEND=file|env|http`
- `CLAWDSTRIKE_BROKERD_SECRET_FILE` when `SECRET_BACKEND=file`
- `CLAWDSTRIKE_BROKERD_SECRET_ENV_PREFIX` when `SECRET_BACKEND=env` (defaults to `CLAWDSTRIKE_SECRET_`)
- `CLAWDSTRIKE_BROKERD_SECRET_HTTP_URL` when `SECRET_BACKEND=http`
- `CLAWDSTRIKE_BROKERD_SECRET_HTTP_TOKEN` optional bearer token for the managed secret service
- `CLAWDSTRIKE_BROKERD_SECRET_HTTP_PATH_PREFIX` optional path prefix for the managed secret service (defaults to `/v1/secrets`)
- `CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS`
- `CLAWDSTRIKE_BROKERD_BINDING_PROOF_TTL_SECS` for DPoP proof freshness checks
- `CLAWDSTRIKE_BROKERD_ALLOW_HTTP_LOOPBACK=true` only for loopback dev/test upstreams
- `CLAWDSTRIKE_BROKERD_ALLOW_PRIVATE_UPSTREAM_HOSTS=true` only for explicit private/link-local/loopback test targets
- `CLAWDSTRIKE_BROKERD_ALLOW_INVALID_TLS=true` only for self-signed test upstreams

`CLAWDSTRIKE_BROKERD_SECRET_FILE` should be a JSON object mapping secret refs to plaintext values,
for example:

```json
{
  "openai/prod": "sk-live-..."
}
```

If `CLAWDSTRIKE_BROKERD_SECRET_BACKEND=env`, `secret_ref` values are normalized into uppercase
environment variable names. For example, `openai/prod` resolves from
`CLAWDSTRIKE_SECRET_OPENAI_PROD` by default.

If `CLAWDSTRIKE_BROKERD_SECRET_BACKEND=http`, the broker resolves secrets from a managed service by
GETting `CLAWDSTRIKE_BROKERD_SECRET_HTTP_URL` plus the configured path prefix and URL-escaped
secret ref, expecting a JSON response shaped like `{ "value": "..." }`.

Broker evidence now also records provider metadata when the executor can derive it safely. The
OpenAI path attaches fields such as `operation`, `request_model`, `response_id`, and
`response_model` when they are present in the brokered request/response payloads. Streaming
executions emit a `started` evidence record before the response body is handed to the caller and a
`completed` evidence record with final bytes, hash, and chunk count after the stream closes.

The broker now also supports typed GitHub and Slack provider execution:

- `github` validates and forwards typed issue creation, issue-comment creation, and check-run creation requests
- `slack` validates and forwards typed `chat.postMessage` and `chat.update` requests
- these providers still use capability-scoped host/path/method authorization from `hushd`, but brokerd now rejects malformed request bodies before any upstream call is attempted

### Broker operator APIs

`clawdstrike-brokerd` now exposes local operator surfaces for the current execution plane:

- `GET /v1/capabilities` returns the active capability wallet plus local revoke and freeze state
- `POST /v1/capabilities/{capability_id}/revoke` locally revokes a capability so future executions fail closed
- `GET /v1/executions` returns the latest execution records and timeline events
- `POST /v1/admin/freeze` toggles a local execution freeze that blocks new broker executions

These are broker-local controls intended for local operator UX and testing. They complement, but do
not replace, the hushd authority status and revoke APIs.

### TypeScript integration

- `@clawdstrike/broker-client` auto-selects proof binding mode:
  loopback brokers use a one-shot loopback secret; non-loopback brokers use a DPoP-like Ed25519 proof bound to capability ID, method, URL, body hash, timestamp, and nonce
- `@clawdstrike/openai` now exposes broker mode for `responses.create`
- `SecretBrokerClient.executeStream()` calls `POST /v1/execute/stream` and returns the raw brokered response body stream plus execution metadata
- brokered OpenAI `stream: true` requests now route through the streaming broker path and return a `ReadableStream<Uint8Array>`
- broker-enabled OpenAI requests fail closed on hushd capability failures, broker execution failures, and missing broker authority

### Agent packaging

The desktop agent can now bundle and supervise `clawdstrike-brokerd` beside `hushd`:

- `apps/agent/scripts/prepare-bundled-hushd.sh` now copies both binaries into the Tauri resources bundle
- `apps/agent/src-tauri/src/settings.rs` exposes a `brokerd` block for local sidecar enablement, secret backend selection, and strict-target toggles
- the agent now materializes a persistent local hushd signing key so brokerd trust bootstrap does not rotate across restarts
