# Step 2 — `hush-cli/src/pkg_cli.rs`

`crates/services/hush-cli/src/pkg_cli.rs` — 5,199 lines (~4,227 code / ~972 test).
Effort: **M (6–9h)**. Independent — only `main.rs` references it (2 sites). Mostly real
code; split primarily by subcommand.

## What it does / why it's big

The entire `hush pkg` command family (package management for `.cpkg` archives) in one
flat module. Bundles three concerns the precedent would split: clap arg-type
definitions, ~20 subcommand handlers, and a deep stack of private helpers
(scaffolding/template generators, registry HTTP + trust/attestation/transparency-proof
verification, install rollback, OIDC auth). Subcommands: **Init, Pack, Install, List,
Verify, Info, Test, Login, Publish, Search, Audit, Yank, Stats**, plus groups **Org**
(Create/Members/Invite/Remove/Info), **TrustedPublishers** (Add/List/Remove), and
**Mirror** (delegated to `crate::mirror`). Heaviest area: registry install + trust
verification (`cmd_pkg_install_registry` ~280 lines).

## Current structure (line ranges)

- Clap types & label mapping (L1–323): `CliPkgType` + impls, `PkgCommands`,
  `TrustedPublisherCommands`, `OrgCommands`; consts `PLUGIN_MANIFEST_FILENAME`,
  `MAX_REGISTRY_DOWNLOAD_BYTES`.
- Dispatcher (L329–397): `pub fn cmd_pkg` matches `PkgCommands` → handlers.
- init + scaffolding/templates (L403–867): `cmd_pkg_init`, `scaffold_*`, `generate_*`
  builders. Self-contained, cleanest seam.
- pack (L869–1023): `cmd_pkg_pack`, `validate_pack_contents`,
  `copy_dir_recursive_excluding_cpkg`, etc.
- install — local + registry + trust (L1025–1958, biggest concern): `cmd_pkg_install`
  router, `cmd_pkg_install_local`, `InstallRollbackBackup` + rollback helpers,
  `cmd_pkg_install_registry`; trust sub-cluster (L1624–1958): `RegistryAttestation`,
  `RegistryProof`, `AttestationVerification`, `verify_attestation_against_hash`,
  `verify_checkpoint_signature`, `verify_transparency_proof`, `verify_install_trust`.
- Registry auth headers (L1966–2014): `CallerAuthHeaders`, `build_caller_auth_headers`
  (shared by publish/yank/org/trusted-publisher).
- list / verify / info (L2016–2499): `cmd_pkg_verify` (~375 LOC, reuses trust).
- login / publish (L2500–2778): `cmd_pkg_login`, `cmd_pkg_publish`, `obtain_oidc_token`.
- trusted publishers (L2779–3059); search + fmt helpers (L3060–3189, incl.
  `urlencoding_simple`); audit / stats (L3190–3405); yank (L3406–3480).
- test (L3481–3758, **feature-gated**): paired `cmd_pkg_test`
  `#[cfg(feature = "wasm-plugin-runtime")]` impl + `#[cfg(not(...))]` stub, plus
  feature-gated helpers. Move both verbatim.
- org (L3759–4226): `cmd_pkg_org` + `cmd_org_*`.

## Test situation

Single `#[cfg(test)] mod tests` @ L4227–5199 (~972 LOC, 41 `#[test]` fns + `run_cmd`
helper, `use super::*`). Private-access confirmed (`run_cmd` calls private `cmd_pkg`;
tests call `scaffold_package`, `validate_pack_contents`, `urlencoding_simple`; reach
`is_file_source`/`RegistryConfig` via the glob). → sibling child module. Extract to
`pkg_cli/tests/` via the precedent's `include!`-split: `tests/mod.rs` (`use
super::super::*;` + `run_cmd`) including `scaffold.rs`, `pack.rs`, `install_registry.rs`,
`misc.rs` (~250 LOC each).

## Proposed module tree

```
src/pkg_cli/
├── mod.rs                ~120  module glue + `pub use command::{CliPkgType, OrgCommands,
│                               PkgCommands, TrustedPublisherCommands}; pub use dispatch::cmd_pkg;`
│                               + consts + `#[cfg(test)] mod tests;`
├── command.rs            ~300  the 4 clap enums + ValueEnum/to_pkg_type/label
├── dispatch.rs           ~70   pub(super) fn cmd_pkg (match arms)
├── auth.rs               ~55   CallerAuthHeaders + build_caller_auth_headers (shared)
├── util.rs               ~60   urlencoding_simple, truncate_with_ellipsis, format_number,
│                               HEX_UPPER, tempdir_for_download
├── init.rs               ~230  cmd_pkg_init
├── scaffold.rs           ~240  write_template_file, scaffold_*, generate_* builders
├── pack.rs               ~155  cmd_pkg_pack + validation + archive helpers
├── install.rs            ~480  cmd_pkg_install router/local/registry + rollback + fetch helpers
├── trust.rs              ~340  attestation structs + proof verifiers + verify_install_trust
│                               (shared by install AND verify — keep separate)
├── list_verify_info.rs   ~485  cmd_pkg_list / cmd_pkg_verify / cmd_pkg_info
├── publish.rs            ~280  cmd_pkg_login / cmd_pkg_publish / obtain_oidc_token
├── trusted_publishers.rs ~280  cmd_pkg_trusted_publishers + add/list/remove
├── search.rs             ~130  cmd_pkg_search
├── audit_stats.rs        ~215  cmd_pkg_audit / cmd_pkg_stats
├── yank.rs               ~75   cmd_pkg_yank
├── test_cmd.rs           ~280  both cfg-gated cmd_pkg_test defs + feature-gated helpers (verbatim)
├── org.rs                ~470  cmd_pkg_org + cmd_org_*
└── tests/                ~972  mod.rs + scaffold.rs + pack.rs + install_registry.rs + misc.rs
```

Internal handlers stay `pub(super)`/`pub(crate)` so `dispatch.rs` can call across mods.

## Risks & coupling

- **Feature-gate fidelity (top hazard):** `cmd_pkg_test` paired
  `#[cfg(feature = "wasm-plugin-runtime")]` / `#[cfg(not(...))]` impls + gated helpers
  must move together verbatim; `dispatch.rs` calls `cmd_pkg_test` unconditionally.
  **Build with and without `--features wasm-plugin-runtime`.**
- `trust.rs` shared by install AND verify — keep it a separate sibling, not buried in
  install.
- `auth.rs`/`util.rs` cross-cutting (publish/yank/org/trusted_publishers; multiple
  registry handlers). Keep as shared sibling mods.
- Tests reach `registry_config` via glob — `tests/mod.rs` should import directly from
  `crate::registry_config` after the split.
- File-level `#![allow(clippy::needless_pass_by_value)]` (L1) must be reapplied per-mod
  that passes `command` by value, or clippy `-D warnings` fails. Move the test
  `#![allow(...)]` block into `tests/mod.rs`.
- Two distinct recursive-copy helpers (`copy_dir_recursive` vs
  `copy_dir_recursive_excluding_cpkg`) — keep both, don't dedupe.

## Sequencing (compile after each)

1. `git mv pkg_cli.rs pkg_cli/mod.rs`; confirm build + tests pass (directory module
   inert).
2. Extract leaf-shared mods: `command.rs`, `util.rs`, `auth.rs`. Wire re-exports.
3. Extract `trust.rs` (shared dep) before its consumers.
4. Extract self-contained handlers: `init`+`scaffold`, `pack`, `search`, `audit_stats`,
   `yank`, `org`, `publish`, `trusted_publishers`.
5. Extract `install.rs`, `list_verify_info.rs` (pull `trust`).
6. Extract `test_cmd.rs` last — carry cfg pair verbatim; **build with + without** the
   wasm feature.
7. Move `cmd_pkg` into `dispatch.rs`; `pub use dispatch::cmd_pkg`.
8. Extract tests into `pkg_cli/tests/`; fix `use super::super::*` + `crate::registry_config`.
9. Gate: `cargo fmt --check && cargo clippy -p hush-cli --all-features -- -D warnings &&
   cargo test -p hush-cli`, plus a clippy run without the wasm feature. Verify
   `main.rs:289` (`pkg_cli::PkgCommands`) + `main.rs:1581` (`pkg_cli::cmd_pkg`) resolve.
