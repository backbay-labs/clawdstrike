# Step 3 — `clawdstrike-policy-event/src/edr/mod.rs`

`crates/libs/clawdstrike-policy-event/src/edr/mod.rs` — 10,164 lines
(~2,437 code / ~7,727 test, 84 test fns). Effort: **M (6–9h)**.
Pairs with [Step 4](./04-edr-receipt.md) — **do this one first** (it owns the shared
`stable_id`).

## What it does / why it's big

Parent module of the EDR subsystem. Unlike `api_server`, the heavy domain types already
live in **15 sibling submodules** (`action`, `actor`, `causal`, `deception`, `detection`,
`event`, `flight_recorder`, `ids`, `privacy`, `process`, `receipt`, `response`,
`sensor_state`, `simulation`). The bloat is (a) ~2,370 lines of **module-root free
functions** that never got pushed into a submodule, and (b) a single ~7,727-line
`#[cfg(test)]` block. The `mod` decls at L10–23 are file/dir declarations (already
decomposed) — the work is the free-fn clusters + the test block.

## Current structure (free-fn clusters, line ranges)

- **Re-export hub** (L1–62): module docs, 15 `mod` decls, `pub use <submod>::*` globs
  (+ targeted `flight_recorder::{compaction,index}`), crate-wide `use`. **Public-API
  contract — stays in `mod.rs`.** Note `#![allow(dead_code, unused_imports)]` @ L8.
- Constants (L64–68): `FNV_OFFSET`, `FNV_PRIME`, 3 schema-version consts.
- Content-hash helpers (L70–94): `*_content_hash`, `observation_age_seconds`.
- **PolicyEvent → Endpoint conversion** (L104–642, ~540, largest): `endpoint_event_from_
  policy_event`, `promote_*`, `metadata_*`, the field-extractor family (`u32_field`,
  `string_field`, `tool_name_field`, `credential_kind_field`, `event_target_field`, …).
- Detection finding builders (L643–917, ~275): `FindingRule`, `finding`, `ev`/`opt_ev`,
  path predicates, `credential_kind_*`.
- Privacy projection (L919–1634, ~715, 2nd largest): `project_observation_privacy`,
  `project_event_privacy`, `push_*`.
- Supply-chain CLI classification (L1635–2044, ~410): package-manager + cloud CLI
  detection.
- Honey / deception construction (L2045–2229, ~185): `honey_artifact`, `honey_contents`,
  `ensure_safe_relative_path`, cfg'd `set_file_permissions`.
- ID / hash / path utilities (L2230–2436, ~205): `normalize_path_string`,
  `stable_id` ⚠, `evidence_hash_for_value`, `insert_json`, response/telemetry id
  derivation, `reconstruct_path`.

## Test situation

`#[cfg(test)] mod tests` @ L2437–10164 (~7,727 LOC, 84 `#[test]` fns + ~7 shared helpers
+ `TEMP_ROOT_COUNTER`). `use super::*` @ L2444; tests call module-private items
(`stable_id`, `endpoint_event_from_policy_event`, projection/honey helpers) and construct
non-`pub`-field types → **sibling child test module**. Extract to `edr/tests/` split by
domain (~6 files): `conversion_privacy.rs` (~1,300), `supply_chain.rs` (~1,200),
`deception.rs` (~900), `causal_graph.rs` (~700), `flight_recorder.rs` (~900),
`receipts.rs` (~2,500 — split into `receipts/part_{1,2}.rs` if > ~1,500). Shared helpers
+ counter → `tests/mod.rs`.

## Proposed module tree

```
edr/
├── mod.rs                ~120  15 existing mod decls + globs (UNCHANGED) + new
│                               `mod conversion; mod finding_builders; mod projection;
│                                mod supply_chain_cli; mod honey; mod util;`
│                               + `pub(crate) use util::stable_id;` + `#[cfg(test)] mod tests;`
├── conversion.rs         ~565  content-hash helpers + PolicyEvent→Endpoint cluster (incl. extractors)
├── finding_builders.rs   ~280  FindingRule + finding/ev/path/credential cluster
│                               ⚠ named to AVOID colliding with existing detection/finding.rs
├── projection.rs         ~720  project_observation_privacy / project_event_privacy + push_*
├── supply_chain_cli.rs   ~410  package-manager + cloud CLI classification
├── honey.rs              ~185  honey artifact construction + safe-path/file-perm
├── util.rs               ~210  stable_id, hashes, path/hostname normalize, insert_json,
│                               response/telemetry id derivation, reconstruct_path + FNV consts
└── tests/                ~7,727  mod.rs + conversion_privacy + supply_chain + deception +
                                  causal_graph + flight_recorder + receipts(.rs or part_{1,2})
```

**Re-export plan:** keep every `pub use action::*` … `pub use simulation::*` verbatim
(external contract for 20+ `wire/*.rs`, `facade.rs`, control-api, the agent app). Add
`pub(crate) use util::stable_id;` (siblings `simulation.rs`, `process.rs` do
`use super::stable_id`; `receipt/evidence.rs` does `super::super::stable_id`). The other
clusters have zero external/cross-sibling refs → declaring the modules suffices (tests
reach them via `super::super::<mod>::…`).

## Risks & coupling

- **`stable_id` is the one true shared seam** — re-export it at the root or 3 siblings
  break. Highest-risk item; do `util.rs` early and `cargo build --workspace`.
- **`finding` name collision** — there's already a `detection/finding.rs`; use
  `finding_builders.rs` and do NOT glob-re-export it.
- **`#![allow(dead_code, unused_imports)]` @ L8** currently blankets the file — carry an
  `#![allow(dead_code)]` into each carved file or clippy `-D warnings` fails on
  genuinely-unused-outside-tests helpers (`cloud_cli_name`, `package_registry_cli_name`).
- Conversion's field-extractors are used by projection/finding_builders — keep them in
  `conversion.rs` (`pub(crate)`) and `use super::conversion::{…}` where needed.
- Shared test fixtures → `tests/mod.rs` as `pub(super)`; mirror `api_server/tests/mod.rs`.

## Coordination with Step 4 (`receipt/`)

`receipt/evidence.rs` does `use super::super::stable_id`. Once `stable_id` moves to
`edr/util.rs`, that path resolves through the **root re-export** — so the
`pub(crate) use util::stable_id;` in `edr/mod.rs` is the joint contract. No file-name
collisions (this step adds `conversion/finding_builders/projection/supply_chain_cli/honey/
util` + `tests/`; receipt owns `receipt/{evidence,families,inputs}`). Future consolidation
of duplicated `telemetry_privacy_report_id_from_*` helpers into a shared `edr/util.rs` is
out of scope here (follow-up).

## Sequencing (compile + `cargo test -p clawdstrike-policy-event` after each)

1. Extract tests first: `edr/tests/mod.rs` (shared helpers + counter), `#[cfg(test)] mod
   tests;` in `mod.rs`, delete inline body. Green with one `tests/mod.rs` before splitting.
2. Split the test file into ~6 domain files.
3. Carve `util.rs` (the `stable_id` cluster); add `pub(crate) use util::stable_id;`;
   `cargo build --workspace` (siblings depend on it).
4. Carve independent clusters in increasing-coupling order: `honey` → `supply_chain_cli`
   → `finding_builders` → `projection` → `conversion`. `#![allow(dead_code)]` per file.
   Compile + clippy after each.
5. Confirm `mod.rs` ~120 LOC; `cargo clippy --workspace -- -D warnings`; grep workspace
   for `edr::` to confirm no external import broke.
