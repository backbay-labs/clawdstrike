# 19. Origin SDK Parity API Contract

> Status: Draft
> Initiative: Origin Enclaves follow-up after PR 177
> Branch baseline: `main` at merge commit `5837f4fc4`

## Purpose

PR 177 shipped origin-enclave enforcement in the Rust engine and hushd, plus TypeScript origin-core helpers. Python and Go still do not expose the same origin-aware contract, which means SDK users cannot consistently pass origin context or use origin-enclave flows outside TypeScript.

This spec defines the minimum cross-SDK contract required for Python and Go parity without silently over-claiming support on backends that cannot enforce origin policies yet.

## Current Gap Summary

- TypeScript now has a dedicated origin-core adapter package at `packages/adapters/clawdstrike-origin-core/`.
- Python `GuardContext` only exposes `cwd`, `session_id`, `agent_id`, and `metadata` in `packages/sdk/hush-py/src/clawdstrike/guards/base.py`.
- Python facade context building only forwards `session_id`, `agent_id`, and `metadata` in `packages/sdk/hush-py/src/clawdstrike/clawdstrike.py`.
- Python native bindings only parse `cwd`, `session_id`, `agent_id`, and `metadata` in `packages/sdk/hush-py/hush-native/src/lib.rs`.
- Go `guards.GuardContext` only exposes `Cwd`, `SessionID`, `AgentID`, `Context`, and `Metadata` in `packages/sdk/hush-go/guards/guard.go`.
- Go daemon requests do not carry `origin` in `packages/sdk/hush-go/daemon_checker.go`.
- Go session checks cannot attach per-action origin context because `packages/sdk/hush-go/session/session.go` only has `Check(action)` and synthesizes a context internally.
- Go policy parsing only supports `1.1.0` through `1.3.0` in `packages/sdk/hush-go/policy/policy.go`.
- Python pure-policy parsing only supports `1.1.0` through `1.3.0` in `packages/sdk/hush-py/src/clawdstrike/policy.py`.

## Scope

This follow-up is split into two compatibility levels:

1. Transport parity
   - Python native backend, Python daemon-backed flows, and Go daemon-backed flows can send origin-aware requests that match the Rust engine and hushd contract.
2. Local-engine parity
   - Python pure-Python backend and Go local engine understand `version: "1.4.0"` origin policies and enforce them locally.

This spec requires transport parity in the first follow-up PR. Local-engine parity is explicitly deferred unless the follow-up branch expands scope.

## Canonical OriginContext Contract

The canonical wire shape is snake_case JSON, matching the Rust `OriginContext`.

Required behavior:

- Canonical outbound serialization uses snake_case.
- SDK helpers may accept camelCase input aliases where the SDK ingests loose dict/map input.
- Unknown fields must not be silently dropped on paths that claim origin support.
- `actor_role` is first-class and must round-trip.

Fields:

| Field | Type | Notes |
|---|---|---|
| `provider` | enum/string | Canonical provider identifier |
| `tenant_id` | string | Tenant/workspace/org scope |
| `space_id` | string | Channel/room/issue/thread container |
| `space_type` | enum/string | Channel, group, dm, thread, issue, ticket, email_thread, custom |
| `thread_id` | string | Nested conversation identifier |
| `visibility` | enum/string | Private, internal, public, external_shared, unknown |
| `external_participants` | bool | External-presence signal |
| `tags` | list[string] | Origin-derived labels |
| `sensitivity` | string | Provider/application sensitivity label |
| `actor_id` | string | Origin actor stable identifier |
| `actor_type` | string | Human, bot, service, webhook, custom |
| `actor_role` | string | Role used in enclave matching |
| `provenance_confidence` | enum/string | Strong, medium, weak, unknown |
| `metadata` | object | Optional provider-specific metadata passthrough |

## Canonical Output Action Contract

The cross-SDK custom action for origin-aware outbound data checks is:

- `custom_type: "origin.output_send"`
- payload shape:
  - `text: string` required
  - `target: string` optional
  - `mime_type: string` optional
  - `metadata: object` optional

Python and Go must expose a convenience helper for this action instead of requiring callers to hand-build raw custom payloads.

## Backend Compatibility Rules

The first follow-up PR must make backend behavior explicit:

| SDK path | Origin-aware policy support | Required follow-up behavior |
|---|---|---|
| Python native backend | Yes | Full transport parity |
| Python daemon-backed usage | Yes | Full transport parity |
| Python pure-Python backend | No | Fail closed or raise a typed unsupported-feature error when `origin` or `origins` are used |
| Go daemon-backed usage | Yes | Full transport parity |
| Go local engine / policy package | No | Fail closed or return a typed unsupported-feature error for `origin`/`origins` until local-engine parity exists |

Silent ignore is not allowed on any path that accepts an origin-aware policy or caller-supplied `origin`.

## Python Contract

### Public types

- Add `OriginContext` and related enums/helpers under `packages/sdk/hush-py/src/clawdstrike/origin.py`.
- Re-export from `packages/sdk/hush-py/src/clawdstrike/__init__.py`.
- Extend `GuardContext` in `packages/sdk/hush-py/src/clawdstrike/guards/base.py` with `origin: OriginContext | None`.

### Facade and session plumbing

- Extend `_ctx_dict()` in `packages/sdk/hush-py/src/clawdstrike/clawdstrike.py` to accept `origin`.
- Preserve per-check context overrides needed for origin changes while keeping the SDK session's own `session_id` and `agent_id` pinned.
- Add `check_output_send(...)` helper on `Clawdstrike` and `ClawdstrikeSession`.

### Native binding contract

- Extend `build_guard_context()` in `packages/sdk/hush-py/hush-native/src/lib.rs` to parse `origin`.
- Accept snake_case and camelCase input aliases when Python callers pass plain dicts.
- Forward origin into Rust `GuardContext::with_origin(...)`.

### Daemon contract

- Any daemon-backed Python path must serialize `origin` into hushd `/api/v1/check` requests using snake_case JSON keys.

## Go Contract

### Public types

- Add a dedicated origin model in `packages/sdk/hush-go/origin/` or an equivalent stable package.
- Extend `packages/sdk/hush-go/guards/guard.go` so `GuardContext` can carry `Origin`.
- Add fluent setter `WithOrigin(...)`.

### Facade and session plumbing

- `Clawdstrike.CheckWithContext(...)` must preserve origin end to end.
- Add `CheckWithContext(...)` on `packages/sdk/hush-go/session/session.go` so callers can change origin between actions in one session.
- Keep `Session.Check(action)` for backward compatibility; it remains a legacy no-origin shorthand.
- Add `OutputSend(...)` helper alongside existing `guards.Custom(...)`.

### Daemon contract

- Extend `daemonCheckRequest` in `packages/sdk/hush-go/daemon_checker.go` with `Origin`.
- Marshal canonical snake_case JSON.
- If Go callers unmarshal origin JSON into a struct, accept camelCase aliases via custom `UnmarshalJSON`.

## Error Model

Both SDKs must add a typed unsupported-origin capability error for backends that cannot enforce origin policies yet.

Required triggers:

- loading `version: "1.4.0"` policies with an `origins` block on unsupported local engines
- passing `origin` into a backend that cannot enforce origin-aware checks

The error message must name the unsupported backend and recommend daemon-backed or native-backed execution when available.

## Required Tests

Python:

- origin dict alias parsing in the public SDK layer
- native binding passes origin through to Rust engine
- daemon request serialization includes `origin`
- session preserves per-check origin changes
- `origin.output_send` helper routes through `check_custom`
- pure-Python backend rejects origin-aware policy/config with explicit error

Go:

- `GuardContext.WithOrigin(...)` roundtrip
- daemon request serialization includes canonical snake_case `origin`
- `Session.CheckWithContext(...)` preserves per-check origin transitions
- `OutputSend(...)` helper encodes the expected custom action
- local engine/origin-aware policy usage returns explicit unsupported error

Cross-surface:

- shared golden vectors for snake_case and camelCase input acceptance
- shared `origin.output_send` payload vectors
- actor-role and external-participant fields verified end to end
