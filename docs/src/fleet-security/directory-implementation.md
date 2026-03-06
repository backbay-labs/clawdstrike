# Directory Implementation Plan

> **Status:** Draft | **Date:** 2026-03-06
>
> This plan turns the directory object model spec into mergeable engineering
> slices. It is intentionally biased toward additive change and compatibility
> with the current `control-api` and desktop agent flows.

## Overview

The cloud directory should be implemented in five milestones:

1. core schema and models
2. principal backfill and enrollment integration
3. CRUD routes for directory objects
4. policy attachments and effective-policy resolution
5. principal-aware joins for approvals, liveness, and event surfaces

Each milestone is intended to be independently reviewable and testable.

## Existing Infrastructure (Do Not Rebuild)

These are already real and should be extended rather than replaced:

- `tenants`, `users`, `agents`, `approvals`, `tenant_active_policies` schema in `crates/services/control-api/migrations/*.sql`
- enrollment and agent registration in `crates/services/control-api/src/routes/tenants.rs` and `crates/services/control-api/src/routes/agents.rs`
- policy fanout in `crates/services/control-api/src/routes/policies.rs`
- local scoped policy and RBAC semantics in `crates/services/hushd/src/api/policy_scoping.rs` and `crates/services/hushd/src/api/rbac.rs`
- multi-agent identity and delegation types in `crates/libs/hush-multi-agent/src/types.rs` and `crates/libs/hush-multi-agent/src/token.rs`

## Key Invariants

- additive migrations first, destructive cleanup last
- no breakage to existing enrollment or tenant policy deploy flows during Milestones 1-3
- `agents` remains the operational compatibility table until principal-backed APIs fully replace it
- every new table and route must stay tenant-scoped
- principal backfill must be deterministic and idempotent

## Milestone 0: Decision Freeze

These need to be settled before schema lands:

| ID | Decision | Status | Notes |
|---|---|---|---|
| DIR-D1 | Are runtime agents first-class principals in Phase 1? | `[ ]` | Recommended: no, keep runtime bindings for Milestone 5 |
| DIR-D2 | Do capability groups store raw `AgentCapability` JSON or policy refs? | `[ ]` | Recommended: raw JSON in Phase 1 |
| DIR-D3 | Should `principal_id` be added to `agents` immediately? | `[ ]` | Recommended: yes, nullable then backfilled |
| DIR-D4 | Should policy attachments store inline YAML, refs, or both? | `[ ]` | Recommended: both, matching current tenant-active-policy compatibility |

## Milestone 1: Core Directory Schema and Models

### Goal

Add the core cloud tables and Rust models for:

- `swarms`
- `projects`
- `capability_groups`
- `principals`
- `principal_memberships`
- `grants`
- `delegation_edges`
- `policy_attachments`

### File Change Table

| File Path | Action | Description |
|---|---|---|
| `crates/services/control-api/migrations/006_fleet_directory_core.sql` | create | Core additive schema for directory objects |
| `crates/services/control-api/src/models/` | modify | Add models for new directory object types |
| `crates/services/control-api/src/error.rs` | modify | Add validation and conflict errors for directory APIs |
| `crates/services/control-api/src/routes/mod.rs` | modify | Register new routers in later milestones |
| `crates/services/control-api/src/integration_tests.rs` | modify | Add migration + CRUD smoke coverage |

### Tickets

| ID | Task | Status | Deps | Ref |
|---|---|---|---|---|
| DIR-S1 | Create core schema migration | `[ ]` | DIR-D1, DIR-D2 | [Directory Object Model Spec](directory-object-model.md#7-proposed-postgres-schema) |
| DIR-S2 | Add Rust models for `Swarm`, `Project`, `CapabilityGroup`, `Principal`, `Grant`, `PolicyAttachment` | `[ ]` | DIR-S1 | [Directory Object Model Spec](directory-object-model.md#6-proposed-types) |
| DIR-S3 | Add row parsers, serde, and validation helpers | `[ ]` | DIR-S2 | same |
| DIR-S4 | Add migration tests for new tables and constraints | `[ ]` | DIR-S1 | same |

### Acceptance Criteria

- the migration applies cleanly to an empty and an already-initialized control-api database
- all new directory tables are tenant-scoped and indexed
- Rust models round-trip cleanly from SQL rows and JSON serialization

## Milestone 2: Principal Backfill and Enrollment Integration

### Goal

Introduce `principal_id` as the durable identity join for existing endpoint
agents and users, without breaking current flows.

### File Change Table

| File Path | Action | Description |
|---|---|---|
| `crates/services/control-api/migrations/007_fleet_directory_backfill.sql` | create | Add `principal_id` references and deterministic backfill |
| `crates/services/control-api/src/routes/agents.rs` | modify | Create principal on register/enroll |
| `crates/services/control-api/src/routes/tenants.rs` | modify | Optionally create operator principal from users in admin flows |
| `crates/services/control-api/src/models/agent.rs` | modify | Include `principal_id` in cloud agent model |
| `crates/services/control-api/src/services/` | modify | Add principal lookup/backfill helpers |

### Tickets

| ID | Task | Status | Deps | Ref |
|---|---|---|---|---|
| DIR-B1 | Add nullable `principal_id` to `agents` | `[ ]` | DIR-S1, DIR-D3 | [Directory Migration Plan](directory-migrations.md#slice-2-principal-backfill-and-compatibility-links) |
| DIR-B2 | Backfill endpoint principals from existing `agents` rows | `[ ]` | DIR-B1 | same |
| DIR-B3 | Backfill operator principals from existing `users` rows | `[ ]` | DIR-B1 | same |
| DIR-B4 | Create or upsert principal during `/agents` register and `/agents/enroll` | `[ ]` | DIR-B2 | [Directory Object Model Spec](directory-object-model.md#8-api-surface) |
| DIR-B5 | Add integration tests for enroll/register principal creation | `[ ]` | DIR-B4 | same |

### Acceptance Criteria

- every active agent has a linked endpoint principal
- enrollment creates both `agents` and `principals` records in one logical flow
- backfill is idempotent and safe to rerun

## Milestone 3: Directory CRUD APIs

### Goal

Expose the first usable control-plane APIs for swarms, projects, capability
groups, principals, and memberships.

### File Change Table

| File Path | Action | Description |
|---|---|---|
| `crates/services/control-api/src/routes/swarms.rs` | create | CRUD routes for swarms |
| `crates/services/control-api/src/routes/projects.rs` | create | CRUD routes for projects |
| `crates/services/control-api/src/routes/capability_groups.rs` | create | CRUD routes for capability groups |
| `crates/services/control-api/src/routes/principals.rs` | create | list/get/update principal routes |
| `crates/services/control-api/src/routes/principal_memberships.rs` | create | membership routes |
| `crates/services/control-api/src/routes/mod.rs` | modify | register routers |
| `crates/services/control-api/src/auth/` | modify | ensure role checks and tenant scoping |

### Tickets

| ID | Task | Status | Deps | Ref |
|---|---|---|---|---|
| DIR-A1 | Add swarms CRUD routes and models | `[ ]` | DIR-S2 | [Directory Object Model Spec](directory-object-model.md#8-api-surface) |
| DIR-A2 | Add projects CRUD routes and models | `[ ]` | DIR-A1 | same |
| DIR-A3 | Add capability-group CRUD routes | `[ ]` | DIR-S2 | same |
| DIR-A4 | Add principals list/get/update routes | `[ ]` | DIR-B4 | same |
| DIR-A5 | Add principal-membership create/delete/list routes | `[ ]` | DIR-A1, DIR-A2, DIR-A3, DIR-A4 | same |
| DIR-A6 | Add integration tests for tenant isolation and role gating | `[ ]` | DIR-A1 | same |

### Acceptance Criteria

- operators can create swarm and project topology in the cloud
- principals can be grouped through explicit memberships
- all CRUD surfaces enforce tenant scope and non-viewer authorization consistently

## Milestone 4: Policy Attachments and Effective Policy Resolution

### Goal

Move from tenant-only active policy deployment to attachment-backed effective
policy resolution while preserving the current tenant-wide deploy path.

### File Change Table

| File Path | Action | Description |
|---|---|---|
| `crates/services/control-api/migrations/008_fleet_directory_policy_attachments.sql` | create | Policy attachment schema if split from core |
| `crates/services/control-api/src/routes/policy_attachments.rs` | create | CRUD routes for policy attachments |
| `crates/services/control-api/src/services/policy_resolution.rs` | create | Resolve effective policy from attachments and memberships |
| `crates/services/control-api/src/routes/policies.rs` | modify | Support effective policy fanout and compatibility deploy |
| `apps/agent/src-tauri/src/policy_sync.rs` | verify | No contract break to agent KV watcher |

### Tickets

| ID | Task | Status | Deps | Ref |
|---|---|---|---|---|
| DIR-P1 | Add policy-attachment CRUD routes | `[ ]` | DIR-S2, DIR-A1 | [Directory Object Model Spec](directory-object-model.md#8-api-surface) |
| DIR-P2 | Implement effective-policy resolver from memberships and attachments | `[ ]` | DIR-P1, DIR-A5 | [Directory Object Model Spec](directory-object-model.md#9-effective-policy-resolution) |
| DIR-P3 | Preserve current tenant active policy as compatibility layer | `[ ]` | DIR-P2 | same |
| DIR-P4 | Fan out effective policy to agent-scoped KV buckets | `[ ]` | DIR-P2 | same |
| DIR-P5 | Add integration tests for attachment precedence and merge ordering | `[ ]` | DIR-P2 | same |

### Acceptance Criteria

- the cloud can compute effective policy for an endpoint principal using memberships
- existing tenant-wide policy deploy still functions during migration
- policy fanout remains compatible with the existing agent-side watcher

## Milestone 5: Principal-Aware Joins for Approvals, Liveness, and Events

### Goal

Make the rest of the fleet plane join on `principal_id` rather than only
`agent_id` strings.

### File Change Table

| File Path | Action | Description |
|---|---|---|
| `crates/services/control-api/migrations/009_fleet_directory_references.sql` | create | Add `principal_id` foreign keys to approvals and related tables |
| `crates/services/control-api/src/models/approval.rs` | modify | Include `principal_id` |
| `crates/services/control-api/src/services/approval_request_consumer.rs` | modify | Resolve principal on ingest |
| `crates/services/control-api/src/services/agent_heartbeat_consumer.rs` | modify | Resolve principal on heartbeat ingest |
| `crates/services/control-api/src/routes/events.rs` | modify | Emit principal-aware event payloads |

### Tickets

| ID | Task | Status | Deps | Ref |
|---|---|---|---|---|
| DIR-J1 | Add nullable `principal_id` to approvals and backfill from agent principal | `[ ]` | DIR-B4 | [Directory Migration Plan](directory-migrations.md#slice-5-principal-aware-joins) |
| DIR-J2 | Add principal resolution in approval-request consumer | `[ ]` | DIR-J1 | same |
| DIR-J3 | Add principal resolution in heartbeat consumer and event emission | `[ ]` | DIR-B4 | same |
| DIR-J4 | Extend cloud event payloads with `principal_id` and membership context | `[ ]` | DIR-J3 | [Hunt Backend API and Data Model Spec](hunt-backend.md#5-normalized-event-model) |
| DIR-J5 | Add regression tests proving old `agent_id` flows still work | `[ ]` | DIR-J1 | same |

### Acceptance Criteria

- cloud approvals and heartbeat-derived state are principal-aware
- fleet events can be joined to principals without losing old identifiers
- the hunt backend has a stable identity join to build on later

## Suggested Execution Order

1. Milestone 0 decisions
2. Milestone 1 schema
3. Milestone 2 backfill and enrollment integration
4. Milestone 3 CRUD APIs
5. Milestone 4 policy attachments
6. Milestone 5 principal joins

## Recommended First PR

The first PR should be deliberately narrow:

- `006_fleet_directory_core.sql`
- new model types
- zero route changes
- migration coverage

That gives the repo a stable schema foundation without immediately forcing
control-plane behavior changes.
