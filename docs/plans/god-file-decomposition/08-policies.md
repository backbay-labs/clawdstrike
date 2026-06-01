# Step 8 — `control-api/src/routes/policies.rs`

`crates/services/control-api/src/routes/policies.rs` — 3,596 lines
(~3,334 code / ~262 test, 13 test fns). Effort: **M (4–6h)**. Pairs with
[Step 7 `response_actions.rs`](./07-response-actions.md) — do Step 7 first, then rebase
this. Almost all real code — a genuine implementation split.

## What it does / why it's big

HTTP route module for tenant policy lifecycle: direct (break-glass) deploy, dry-run
preview, and a full multi-step **policy-proposal** workflow (create → attach impact →
fleet rule-diff dispatch/collect → approve-deploy / reject), plus reading active policy.
Big because the proposal workflow carries heavy **cryptographic evidence validation** —
verifying Ed25519 signed simulation receipts, binding receipts to a proposal's policy
identity, orchestrating signed fleet rule-diff validation receipts collected via the
`response_actions` subsystem. The 9 handlers are thin; the bulk (~2,000 lines) is receipt
verification, impact validation, preview/plan builders, and SQL glue.

Endpoints under `/api/v1` (router @ L29–59): `POST /policies/deploy`, `/preview`,
`GET/POST /policies/proposals`, `GET /policies/proposals/{id}`,
`POST /{id}/approve-deploy|impact|reject`, `POST /{id}/fleet-rule-diff/dispatch|collect`,
`GET /policies/active`.

## Current structure (line ranges)

1. Imports, consts, `router()` (L1–59).
2. Public DTOs (L61–245, 14 `pub` types).
3. Internal row/outcome structs (L247–288): `PolicyProposalRow` (+impl L2104),
   `PolicyDeploymentOutcome`, `PreparedPolicyDeployment`.
4. Core handlers deploy/preview/CRUD (L289–567).
5. Fleet rule-diff dispatch/collect handlers (L568–882) — `dispatch_…` (L568) calls
   `response_actions::create_and_publish_internal_action`.
6. Fleet rule-diff helpers (L883–1128).
7. Collect ack receipts + rule-diff receipt validation (L1129–1616, heaviest;
   `CollectedPolicyRuleDiffReceipt` @ L1089).
8. Approve/reject handlers (L1617–1854).
9. Active-policy + deploy glue (L1855–2018: `prepare_active_policy_deployment`,
   `distribute_prepared_policy_to_fleet`).
10. Row fetch + conversion (L2019–2139).
11. Authz + break-glass + approval-note helpers (L2140–2186).
12. Simulation-receipt verification + impact validation (L2188–2731, ~544, crypto core).
13. Preview / fleet-history / rule-diff plan builders (L2732–3194).
14. YAML-diff helpers + From impls + error mapper (L3195–3333).

## Test situation

`#[cfg(test)] mod tests` @ L3334–3596 (~263 LOC, 13 fns, `use super::*`). 10 of 13 touch
private items spread across **multiple proposed child modules**
(`require_direct_policy_deploy_break_glass`, `ensure_policy_proposal_deployable_impact`,
`validate_policy_proposal_impact_matches_proposal`, `reserve_policy_rule_diff_dispatch`,
`latest_policy_rule_diff_receipts_by_endpoint`, `CollectedPolicyRuleDiffReceipt`,
`PolicyProposalRow`, `DeployPolicyRequest`). Because tested items are private to *child*
modules, a single top-level `tests.rs` can't reach them via `super::*`.

→ **Co-locate each test cluster as a child `#[cfg(test)] mod tests` inside the module that
owns the item** (idiomatic; private items stay reachable). Avoids raising visibility to
`pub(super)`, which would fight the codebase's narrowing direction (#357/#358):
- break-glass tests → `deploy.rs`
- impact/identity tests → `impact_validation.rs`
- fleet rule-diff tests → `fleet_rule_diff.rs`
- the 3 `policy_distribution` contract tests (no private access) → `mod.rs`

## Proposed module tree

```
routes/policies/
├── mod.rs              ~70   module decls + `pub fn router()` (verbatim) + 3 contract tests
├── dto.rs             ~210  the 14 pub DTOs + the two From<policy_distribution::…> impls
├── deploy.rs          ~360  deploy/preview handlers + active-policy glue + break-glass tests
├── proposals.rs       ~360  create/list/get + reject/approve handlers + PolicyProposalRow + fetch/convert
├── impact_validation.rs ~560  simulation-receipt verification + impact validation +
│                              attach_policy_proposal_impact handler + simulation consts + tests
├── fleet_rule_diff.rs ~820  dispatch/collect handlers + all rule-diff helpers +
│                              CollectedPolicyRuleDiffReceipt + tests  (SPLIT — see below)
├── preview_builder.rs ~480  build_policy_proposal_preview / _fleet_history_impact /
│                              _fleet_rule_diff_validation_plan + selection structs + history helpers
├── yaml_diff.rs       ~80   top_level_policy_change_summary + yaml_* + sorted_difference
└── guard.rs           ~120  ensure_policy_author/_deployer, require_direct_policy_deploy_break_glass,
                             append_policy_proposal_approval_note, 3 field validators, policy_preview_error
```

`fleet_rule_diff.rs` @ ~820 exceeds the ~595 norm — **split** into `fleet_rule_diff/mod.rs`
(handlers ~330), `fleet_rule_diff/helpers.rs` (~290 + tests), `fleet_rule_diff/receipts.rs`
(~200).

**Wiring plan:** declare children (`pub(crate)` only where referenced cross-module). Keep
`pub fn router()` **verbatim** in `mod.rs` with handler paths qualified by new home
(`deploy::deploy_policy`, etc.). Only external reference is `routes/mod.rs:38
.merge(policies::router())`. **No glob re-exports** (#357/#358 direction) — grep confirms
none of policies' DTOs/handlers are imported outside this file, so the only required public
item is `router()`. Cross-child sharing via `pub(in crate::routes::policies)` (i.e.
`pub(super)` from a child).

## Risks & coupling

- **HIGH-PRIORITY coordination with Step 7:** `policies.rs:15` imports
  `response_actions::{self, CreateResponseActionRequest, ResponseTargetInput}` and L673
  calls `response_actions::create_and_publish_internal_action`. The Step-7 refactor MUST
  keep these reachable at `crate::routes::response_actions::{…}`. One-directional. Land
  Step 7 first, rebase this.
- `PolicyProposalRow` is the spine — keep one definition in `proposals.rs` (`pub(super)`),
  shared by impact/fleet/approve.
- Consts travel with their consumers (simulation consts → impact_validation; history/fleet
  limits → preview_builder/fleet_rule_diff); a couple may need `pub(super)` in `mod.rs`.
- **Ordering:** `deploy_policy` + `approve_policy_proposal` both call
  `prepare_active_policy_deployment`/`distribute_prepared_policy_to_fleet` — those 4 fns
  must be `pub(super)` in `deploy.rs` or `proposals.rs::approve_policy_proposal` won't
  compile.
- `hush_core` crypto confined to `impact_validation.rs` — keep the unsafe-evidence surface
  together. Fail-closed preserved by pure movement.
- Clippy: moving private items into children can trigger `dead_code`/`unused_imports` —
  `cargo clippy -p control-api -- -D warnings` after each extraction.

## Sequencing (compile + `cargo test -p control-api` after each)

1. `git mv policies.rs policies/mod.rs`; build green (directory switch inert).
2. Extract zero-dependency leaves: `dto.rs` (+ From impls), `yaml_diff.rs`, `guard.rs`.
3. Extract `preview_builder.rs` (deps: dto + yaml_diff + guard).
4. Extract `impact_validation.rs` + its test cluster; run the 4 impact/identity tests.
5. Extract `fleet_rule_diff.rs` (or its 3-way split) + tests — heaviest; depends on dto,
   guard, `PolicyProposalRow`, and `response_actions::create_and_publish_internal_action`.
   Verify the sibling symbol resolves; run the 3 fleet tests.
6. Extract `deploy.rs` (+ break-glass tests) and `proposals.rs`; wire shared deploy glue
   `pub(super)`.
7. Reduce `mod.rs` to decls + `router()` + 3 contract tests; confirm `routes/mod.rs:38`
   resolves. `cargo clippy -p control-api -- -D warnings && cargo test -p control-api`.
8. Coordinate merge with Step 7 — confirm `response_actions` still exports the 3 shared
   symbols at module root.
