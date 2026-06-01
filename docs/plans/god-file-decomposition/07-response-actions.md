# Step 7 — `control-api/src/routes/response_actions.rs`

`crates/services/control-api/src/routes/response_actions.rs` — 3,909 lines
(~2,952 code / ~957 test, 24 test fns). Effort: **M (3–4.5h)**. Pairs with
[Step 8 `policies.rs`](./08-policies.md) — **land this one first** (it owns the shared
symbols).

## What it does / why it's big

HTTP route module for the fleet **response-action** lifecycle: create EDR/cloud response
actions, approve/cancel/retry, publish to a delivery transport, record acknowledgements
(operator + agent-facing). Big because one file fuses router wiring, ~13 serde DTOs, 9
Axum handlers, a large signed-receipt ack-validation subsystem (L826–1810), and a
delivery/execution engine (L1923–2835). Endpoints under `/response-actions`: `POST/GET /`,
`GET /{id}`, `POST /{id}/approve|cancel|retry|acks`, public `POST /{id}/agent-acks`.

## Current structure (line ranges)

- Header + imports (L1–22); router registration (L46–60: `router()` 6 authed routes +
  `public_ack_router()` 1 public route).
- DTOs & domain enums (L62–347): `ResponseTargetKind`, `ResponseActionType`,
  `ResponseActionRecord` (+from_row/to_transport_payload), `ResponseActionDelivery`,
  `ResponseActionAckRecord`, `CreateResponseActionRequest` ⚠, `ResponseTargetInput` ⚠, ...
- Internal control structs (L356–404): `ValidatedCreateAction`, `AckSubmission`,
  `AckContext`, `VerifiedEndpointDecisionReceipt`, `PublishContext`,
  `PrincipalLifecycleTarget`, `PublishPreparation`.
- Handlers (L407–605): the 9 handlers + `create_and_publish_internal_action` (L428) ⚠.
- Access guards + create/insert glue (L607–737).
- **Acknowledgement parsing + validation** (L738–1818, ~1080, largest): `parse_ack_
  submission`, signed-receipt verifiers, the dense **policy-rule-diff ack contract**
  cluster (`validate_policy_rule_diff_ack_receipt` + ~16 `*_policy_rule_diff_*` helpers,
  L1095–1671).
- Ack persistence (L1853–1921); publish/delivery engine (L1923–2835: `prepare_publish`,
  `execute_delivery`, subject derivation, payload builders,
  `execute_cloud_only_action`, `execute_principal_lifecycle_action`); DB row fetchers
  (L2837–2950).

## Test situation

`#[cfg(test)] mod tests` @ L2952–3909 (~957 LOC, 24 fns, `use super::*`). Exercise private
items (`parse_ack_submission`, `validate_create_request`, `delivery_plan`,
`transition_posture_value`, `scrub_delivery_metadata`, rule-diff validators) → **sibling
child module**. Extract to `response_actions/tests/` (~4 files): `ack_receipts.rs` (~400),
`create_validation.rs` (~250), `delivery.rs` (~200), `parse_ack.rs` (~110).

## Proposed module tree

```
routes/response_actions/
├── mod.rs            ~70   doc; router() + public_ack_router() (verbatim L46–60);
│                           `pub use handlers::create_and_publish_internal_action;`
│                           `pub use dto::{CreateResponseActionRequest, ResponseTargetInput};`
├── dto.rs            ~335  all public DTOs + internal control structs + DeliveryPlan/DeliveryExecution
├── handlers.rs       ~200  the 9 handlers + create_and_publish_internal_action
├── access.rs         ~30   ensure_write_access, ensure_api_key_executor
├── create.rs         ~180  prepare_create_action, insert_action, validate_create_request,
│                           resolve_action_target_id, validate_action_links, link_*
├── ack/
│   ├── mod.rs        ~30   declares parse/receipt/policy_rule_diff/persist + inward re-exports
│   ├── parse.rs      ~180  parse_ack_submission, validators, normalize_ack_status, window helpers
│   ├── receipt.rs    ~340  signed-receipt verifiers + receipt contract
│   ├── policy_rule_diff.rs ~560  validate_policy_rule_diff_ack_receipt + ~16 helpers
│   └── persist.rs    ~70   persist_ack_submission
├── publish.rs        ~200  publish_action, prepare_publish, execute_delivery, ensure_publishable
├── delivery.rs       ~140  delivery_plan, subject derivation, payload builders,
│                           transition_posture_value, scrub_delivery_metadata
├── execute.rs        ~160  execute_cloud_only_action, execute_principal_lifecycle_action, sync_*
├── fetch.rs          ~100  fetch_action/deliveries/acks/action_detail
└── tests/            ~960  mod.rs + ack_receipts + create_validation + delivery + parse_ack
```

Largest file ~560 (`ack/policy_rule_diff.rs`). Sub-files use `use super::*` so crate-level
`ApiError`/`AppState`/`AuthenticatedTenant` resolve.

**Router-registration plan:** `routes/mod.rs` `pub mod response_actions;` unchanged
(resolves to the dir). `mod.rs` keeps `pub fn router()` + `pub fn public_ack_router()`
with identical signatures + same `.route(...)` lines. **Public re-export contract:**
`policies.rs:15` imports `create_and_publish_internal_action`,
`CreateResponseActionRequest`, `ResponseTargetInput` — keep these `pub use` at the module
root (NOT `pub(crate)`). Everything else `pub(crate) use ...` inward.

## Risks & coupling

- **Sibling `policies.rs` (Step 8) hard dependency** on the 3 symbols above — do not
  rename or deep-nest them without a top-level re-export. Coupling is one-directional
  (response_actions has zero refs to `policies::`).
- No helper-name collisions (shared types come from `crate::error`/`state`/`auth`;
  private helpers become `response_actions/`-private).
- Internal value-types (`AckSubmission`/`DeliveryPlan`/`PublishPreparation`) threaded
  between handlers/ack/publish/tests → put in `dto.rs`, `pub(crate)` inward.
- `from_row` needs `sqlx::row::Row` in scope — add explicit `use sqlx::row::Row;` in
  `dto.rs`.
- Fail-closed preserved (validators return `Result<_, ApiError>`); regression net is
  `integration_tests/part_{4,5}.rs` `response_actions_*` cases.

## Sequencing (compile after each)

1. Create dir; `git mv` → `mod.rs`; `cargo build -p control-api` green.
2. Extract dependency-free leaves: `dto.rs`, `fetch.rs`, `access.rs`, `delivery.rs`.
3. Extract `ack/` subtree as one unit (parse → receipt → policy_rule_diff → persist).
4. Extract `create.rs`, `publish.rs`, `execute.rs`.
5. Move handlers to `handlers.rs`; trim `mod.rs` to doc + decls + router fns + `pub use`.
6. Extract `tests/` (4 files); `cargo test -p control-api`.
7. Gate: `cargo clippy -p control-api -- -D warnings` + full `cargo test -p control-api`
   (exercises integration regression). Coordinate merge with Step 8 — confirm the 3
   shared symbols still export at the module root.
