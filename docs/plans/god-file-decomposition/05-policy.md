# Step 5 — `clawdstrike/src/policy.rs`

`crates/libs/clawdstrike/src/policy.rs` — 4,156 lines (~2,381 code / ~1,775 test,
70 test fns). Effort: **M (6–9h)**. Do before [Step 6 `engine.rs`](./06-engine.md)
(engine imports these types).

## What it does / why it's big

Defines the entire **policy schema**: the `Policy` struct hierarchy, all 13 guard-config
wrappers (`GuardConfigs`), broker/origins/posture sub-schemas, schema-version gating
(v1.1.0–v1.5.0), `extends` inheritance + merge, fail-closed validation, the built-in
`RuleSet` registry (`include_str!`), and guard instantiation (`create_guards` →
`PolicyGuards`). Conflates type defs, merge logic, validation, and YAML/ruleset loading
plus ~1,775 lines of inline tests.

## Current structure (line ranges)

- Header + consts/defaults (L1–39); `PolicyValidationOptions` (L41–60); resolver/source
  (L61–164: `PolicyResolver`, `LocalPolicyResolver`); core `Policy` + `MergeStrategy` +
  load-verifier static (L165–249).
- **`GuardConfigs`** (L250–479): struct (13 guard config `Option` fields + 3
  `#[serde(skip)]` `*_present_fields` sidecars + cfg-gated `spider_sense`) + `merge_with`
  (L309–433) + `merge_prompt_injection_config`/`merge_jailbreak_config`.
- Async guard config group (L480–562); custom-guard + settings (L563–676:
  `PolicySettings`, `VerificationSettings`); broker schema (L677–746); origins schema
  (L747–909).
- **`impl Policy`** (L910–1801, ~892, core): `from_yaml*`/`to_yaml` (L947–1013);
  `validate`/`validate_with_options` (L1014–1475, the latter ~458 LOC); `resolve_base`;
  `merge` (L1497–1600); `from_yaml_with_extends` family + cycle detection (L1601–1723);
  `create_guards` (`pub(crate)`, L1724–1801).
- Validation free-fn cluster (L1802–2272, ~470): version helpers (`parse_semver_*`,
  `policy_version_supports_*`), `validate_globs`, placeholder validators, spec validators
  (virustotal/safe_browsing/snyk).
- `PolicyGuards` (L2273–2309); `RuleSet` registry (L2310–2380, `include_str!` ⚠).

## Test situation

Single `#[cfg(test)] mod tests` @ L2381–4156 (~1,775 LOC, 70 fns). Calls
`Policy::from_yaml_unvalidated` (private), `create_guards` (`pub(crate)`), and constructs
`GuardConfigs { …, spider_sense_present_fields: … }` (a `#[serde(skip)]` field) →
**sibling child module**. Extract to `policy/tests/` (~5 files): `schema_validation.rs`
(~430), `merge_extends.rs` (~400), `spider_sense_merge.rs` (~330), `origins.rs` (~340),
`rulesets_and_verifier.rs` (~330).

## Proposed module tree

```
policy/
├── mod.rs           ~120  module decls + FULL explicit re-export list + crate-level consts
│                          (POLICY_SCHEMA_VERSION, …) + default_true/json_object +
│                          install_policy_load_verifier + POLICY_LOAD_VERIFIER + PolicyLoadVerifier
├── types.rs         ~140  Policy + Default; MergeStrategy; PolicyLoadVerificationInput;
│                          PolicyValidationOptions; default_version
├── guard_configs.rs ~135  GuardConfigs (incl. #[serde(skip)] sidecars + cfg-gated spider_sense)
├── merge.rs         ~210  GuardConfigs::merge_with + merge_* helpers + Policy::merge (2nd impl)
├── settings.rs      ~120  PolicySettings, VerificationSettings, CustomGuardSpec, defaults
├── async_config.rs  ~90   TimeoutBehavior, AsyncExecutionMode, Async*PolicyConfig
├── broker.rs        ~75   BrokerMethod, BrokerConfig, BrokerProviderPolicy
├── origins.rs       ~170  OriginDefaultBehavior, OriginsConfig, OriginProfile, OriginMatch,
│                          OriginDataPolicy, OriginBudgets, BridgePolicy, BridgeTarget
├── resolver.rs      ~110  PolicyCustomGuardSpec, PolicyLocation, ResolvedPolicySource,
│                          PolicyResolver, LocalPolicyResolver
├── load.rs          ~330  impl Policy: new/from_yaml*/to_yaml/resolve_base/from_yaml_with_extends
│                          + maybe_verify_loaded_policy + spider_sense_present_fields_from_yaml
├── validate.rs      ~620  impl Policy::{validate, validate_with_options} + version helpers +
│                          glob/placeholder/spec validators (could split validate/{mod,version,specs})
├── ruleset.rs       ~75   RuleSet + yaml_by_name (include_str!) + by_name + list
├── guards.rs        ~40   pub(crate) PolicyGuards + builtin_guards_in_order (+ Policy::create_guards)
└── tests/           ~1,775 mod.rs + 5 theme files
```

**Re-export list (mandatory — `clawdstrike::policy::*` path surface):** `lib.rs` only
re-exports `policy::{Policy, RuleSet}` at crate root, so all other types are consumed as
`clawdstrike::policy::Foo`. `mod.rs` must `pub use` ALL of: `Policy, RuleSet, GuardConfigs,
MergeStrategy, PolicyValidationOptions, PolicyCustomGuardSpec, PolicyLocation,
ResolvedPolicySource, PolicyResolver, LocalPolicyResolver, PolicyLoadVerificationInput,
install_policy_load_verifier, CustomGuardSpec, PolicySettings, VerificationSettings,
TimeoutBehavior, AsyncExecutionMode, Async{Cache,RateLimit,CircuitBreaker,Retry,Guard}
PolicyConfig, BrokerMethod, BrokerConfig, BrokerProviderPolicy, OriginDefaultBehavior,
OriginsConfig, OriginProfile, OriginMatch, OriginDataPolicy, OriginBudgets, BridgePolicy,
BridgeTarget, POLICY_SCHEMA_VERSION, POLICY_SUPPORTED_SCHEMA_VERSIONS,
policy_version_supports_origins, policy_version_supports_broker`. Plus `pub(crate)`:
`PolicyGuards`, `Policy::create_guards`. External importers verified: `clawdstrike-logos`,
`hushd`, `hush-cli`, `clawdstrike-policy-event`, plus in-crate tests.

## Risks & coupling

- **`include_str!("../rulesets/…")` in `RuleSet`** — moving it into `policy/ruleset.rs`
  changes relative depth: paths become `../../rulesets/…`. **Most likely compile break.**
- serde `deny_unknown_fields` is per-struct — keep each struct whole in its module
  (don't split fields). The 3 `#[serde(skip)] *_present_fields` sidecars on `GuardConfigs`
  move WITH it; merge code reads them via `super::*`. No `#[serde(flatten)]` in play.
- Feature-gating: `spider_sense` has cfg variants; whole `policy` module is
  `#[cfg(any(feature = "full", feature = "policy-event"))]` — every file inherits the
  gate; keep inner `#[cfg(feature = "full")]` lines intact.
- `impl Policy` legally splits across `load.rs`/`validate.rs`/`merge.rs`.
- **Coordinate with Step 6:** `engine.rs` imports `crate::policy::{Policy, PolicyGuards,
  RuleSet, OriginDefaultBehavior, OriginsConfig, OriginBudgets}` — keep all re-exported at
  the same path; do NOT move these type *definitions* into `engine/`.

## Sequencing (compile + `cargo test -p clawdstrike` after each)

1. `git mv policy.rs policy/mod.rs`; confirm build.
2. Extract leaf schema groups: `async_config`, `broker`, `origins`, `resolver`,
   `settings`. Add `pub use` per file.
3. Extract `types.rs`; then `guard_configs.rs` (struct only, keep sidecars).
4. Extract `merge.rs` (incl. `Policy::merge` as a 2nd impl); run merge/spider-sense tests.
5. Extract `validate.rs` + `load.rs` (split `impl Policy`).
6. Extract `ruleset.rs` + `guards.rs` — **fix `include_str!` to `../../rulesets/…`**;
   run `test_rulesets*`.
7. Extract `tests/` (5 files); all 70 pass.
8. `cargo fmt --all`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`.
   Keep each commit independently green (bisectable serde regressions).
