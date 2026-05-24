# TODO / shim / workaround inventory

Sweep date: 2026-05-23. Working tree: `/Users/connor/.codex/worktrees/ts-sprints-deps-clawdstrike/`.

## Method

Two ripgrep passes, scoped to ts/js/rust/py/yaml/toml, excluding `node_modules`, `dist`, `target`, `build`, `infra/vendor`, `vendor/`, `*.lock`, `*.snap`, `.audit/**`.

1. Marker words (case-insensitive): `TODO|FIXME|XXX|HACK|WORKAROUND|LEGACY|SHIM|TEMP-|TBD|KLUDGE|DELETE ME|DELETEME|REMOVE ME|REMOVEME` — **706 raw hits / 187 files**, dominated by false positives (`xxx` in fake credentials in tests, "hacker" in jailbreak/jailbreak-defense test fixtures, identifiers like `removeMember`, `RemoveMember`, `removeItem`).
2. Strict comment-style filter (`//|#|/*|*` followed by canonical marker words): **11 comment-form TODOs total** (10 in source + 1 in test scaffolding).
3. Legacy/fallback pass (`legacy|fallback|backward[ _-]?compat|backcompat|pre-rename|deprecated` in comments): **138 hits / ~40 unique compat surfaces**, almost all intentional `@deprecated` markers or load-bearing migration code.

False-positive sources excluded from this inventory:
- `apps/academy/src/lib/wasm-glue/hush_wasm.js:1111` — wasm-bindgen generated code, not authored.
- Test fixtures containing `xxx`/`hacker`/`HACKED` as deliberate attack-corpus content (e.g. `crates/libs/clawdstrike/tests/s2bench_attack_scenarios.rs`, `packages/sdk/hush-py/tests/conftest.py`, every `*ghp_xxx*` token in adapter tests).
- String literals embedded in scenario generators / draft template YAML (e.g. `scenario-generator.ts:424`, `use-draft-detection.ts:101`).
- `examples/hybrid-swarm/index.ts:215-216` and `examples/secure-agent-swarm/index.ts:104` — `query: 'TODO'`/`pattern: 'fixme'` are deliberate mock tool arguments.
- Code identifiers (`removeMember`, `removeListener`, `removeItem`, `_shipToDock`, etc.).

## Counts

| Bucket | Count |
| --- | --- |
| A. Trivially resolvable | 2 |
| B. In-scope refactors | 2 |
| C. Needs design decision (defer) | 5 |
| D. Stale comments to delete | 0 |
| E. Genuine backlog (leave alone) | 6 + intentional `@deprecated` API surface |

Age check: every comment-style TODO in the inventory was added between **2026-03-05** and **2026-03-22** per `git blame` (≤2.5 months old). **No TODOs older than 6 months; nothing rotted.**

---

## A. Trivial fixes

- `apps/workbench/src/lib/workbench/detection-workflow/use-swarm-launch.ts:80-81` — `/** @deprecated Kept for backward compatibility in existing test references. */ const SWARM_LAUNCH_EVENT = "workbench:swarm-launch-nodes";` — Const is never read anywhere in source (`apps/workbench/src/lib/workbench/__tests__/use-swarm-launch.test.ts` hard-codes its own `LAUNCH_EVENT = "workbench:swarm-launch-nodes"`; the bridge test only mentions the name in a comment). Source dispatches via `_dispatchSwarmNodes()`, not the event. Fix: delete both the JSDoc and the `const` line.
- `apps/workbench/src/lib/workbench/detection-workflow/__tests__/use-swarm-launch-bridge.test.ts:73-74` — Misleading comment `// We use a workaround: call the hook's internal logic via the module`. Calling `_dispatchSwarmNodes` is now the documented testability seam (see `use-swarm-launch.ts:204-207` which exports it for this exact purpose). Fix: drop the "workaround" framing, e.g. `// Use the testability seam _dispatchSwarmNodes (exported with leading underscore).`

## B. In-scope refactors

- `packages/adapters/clawdstrike-adapter-core/src/framework-adapter.ts:27` — `version: "0.1.1", // TODO: derive from package.json at build time`. Hardcoded value has already drifted: actual `package.json` is `0.2.7`. Only consumer is `tests/cross-adapter/interface-consistency.test.ts:48-49` which just asserts `typeof string`. Approach: enable `resolveJsonModule` and `import pkg from "../package.json" with { type: "json" };` (already used in other workspace packages), then `version: pkg.version`. Same one-line follow-up in the langchain adapter (next entry) — do both in one PR.
- `packages/adapters/clawdstrike-langchain/src/langchain-adapter.ts:22` — `readonly version = "0.1.1"; // TODO: derive from package.json at build time`. Same pattern, same fix as above. Co-resolve.

## C. Needs design decision (defer)

- `apps/workbench/src/components/workbench/swarm-board/receipt-detail-page.tsx:252` — `// TODO: When @clawdstrike/hush-wasm is available in the workbench, call verifyDetachedPayload() ...`. Question: are we ever going to ship hush-wasm into the workbench bundle, or should signature verification happen via a Tauri command that calls the Rust verifier directly? Answer determines whether to wire WASM or remove the comment in favour of an IPC call. Touches receipt verification UX.
- `crates/services/eas-anchor/src/eas_client.rs:104` and `:132` — `// TODO: Build and send the actual multiAttest/revoke transaction via alloy.` Two paired TODOs (submit + revoke) currently return placeholder errors. Question: what is the target chain (Base mainnet vs Sepolia vs configurable per-tenant?) and what is the signing key custody model for production EAS attestations? Cannot wire alloy without those answers.
- `crates/libs/logos-ffi/src/lib.rs:126` — `// TODO: Call LEAN 4 runtime via FFI`. Question: do we ship a Lean runtime as a sidecar binary, statically link via `lake build --link`, or treat Lean proofs as offline-verified only and never wire FFI? Affects deployment story and binary size. Currently returns `ProofResult::Unknown` which is the documented fail-soft.
- `crates/services/hush-cli/src/pkg_cli.rs:2531` — `// TODO: A '/api/v1/auth/register' endpoint will be added in a future phase`. Question: registry account-bootstrap UX — does it ride on existing OAuth identity providers, do we run our own user table in `clawdstrike-registry`, or do we federate to GitHub OIDC like npm? Until decided, manual key registration via admin is the documented path and the comment correctly tells users what to do.
- `crates/services/hushd/src/api/certification.rs:163` — `// Same temporary scope mapping as the legacy middleware.` Comment hints the scope-mapping logic is duplicated/in-flight. Question: should certification routes adopt the canonical RBAC scope check, or is the duplication intentional (different scope set)? The duplication is a footgun in roles/scopes coupling — needs RBAC owner sign-off before merge/delete.

## D. Stale comments to delete

(none found — all "legacy"/"backward compat" comments scanned point at code that is still load-bearing or at intentional `@deprecated` API surface)

## E. Genuine backlog (leave alone)

Comment-style TODOs that describe real, scoped future work and should stay:

- `packages/cli/create-plugin/tests/scaffold.integration.test.ts:163` — `// TODO: Enable after Phase 1 (testing harness) completes`. Blocked on the SCAF-07 `@clawdstrike/plugin-sdk/testing` subpath export shipping; the disabled `describe` block is preserved verbatim for reactivation.
- `crates/services/eas-anchor/src/eas_client.rs:104` and `:132` — also belong here once the design questions in §C are answered (the work itself is real, scope is clear).
- `crates/libs/logos-ffi/src/lib.rs:126` — same: real work, gated on §C decision.
- `apps/workbench/src/components/workbench/swarm-board/receipt-detail-page.tsx:252` — same.
- `crates/services/hush-cli/src/pkg_cli.rs:2531` — same.

Intentional `@deprecated` API surface (public/SDK contracts kept for one deprecation cycle — do not touch without major-version coordination):

- `crates/libs/clawdstrike-policy-event/src/edr/response.rs:176` — `#[deprecated(note = "terminate_process_tree is dry-run/modeling only; use EndpointResponsePlan::dry_run or suspend_process_tree_execution for live response plans")]`.
- `packages/adapters/clawdstrike-langchain/src/wrap.ts:37, 83, 99, 115, 138` — `wrapTool`, `wrapTools`, `wrapToolWithConfig`, `wrapToolsWithConfig`, `ClawdstrikeLike` superseded by `secureTool`/`secureTools`/`SecuritySource` but kept for one minor cycle.
- `packages/adapters/clawdstrike-langchain/src/errors.ts:7` — `ClawdstrikeBlockedError` rename.
- `packages/sdk/clawdstrike-hunt/src/types.ts:31, 39` — `QueryVerdict` superseded by `NormalizedVerdict` (only Python SDK still uses the older name internally).
- `apps/desktop/src/services/openclaw/gatewayProtocol.ts:67` — `@deprecated Use deviceToken instead. Kept for Rust protocol compatibility.`
- `apps/desktop/src/shell/plugins/types.ts:124` — `@deprecated Use getPluginIconPath()`.
- All `apps/workbench/src/features/**/stores/*.tsx` `@deprecated Use useXStore directly` exports (operator, reputation, sentinel, fleet, swarm-feed, swarm, signal, finding, intel, mission, project, settings) — pass-through wrappers from the Zustand migration. These are the largest concentration of `@deprecated` markers (~16 occurrences across the workbench feature tree); they should all sunset together once a follow-up sweep migrates remaining call sites.

Load-bearing legacy/fallback code (no marker is a TODO; the word "legacy" is a *description* of a real code path that must be preserved for on-disk-format / wire-format compatibility):

- `crates/services/control-api/src/models/hierarchy.rs:13-72` — `HierarchyNodeType::Agent` variant + `is_legacy_agent()` + "agent" -> Endpoint mapping. Needed for back-compat deser of pre-rename DB rows.
- `apps/agent/src-tauri/src/enrollment.rs:180-183, 348-369` — clears legacy NATS auth fields and migrates on-disk `agent.key` into keyring. Required during user upgrade path.
- `apps/agent/src-tauri/src/daemon.rs:1941-1959` — detects legacy guard keys (`fs_blocklist`, `exec_blocklist`, `egress_allowlist`) and falls back to built-in ruleset rather than crash-loop. Defensive guard for stale on-disk policies.
- `apps/desktop/src/shell/sessions/sessionStore.ts:29-69` — maps pre-rename persisted app IDs.
- `apps/workbench/src/App.tsx:296` — "migrate legacy credentials" during Stronghold init.
- `apps/workbench/src/components/workbench/hierarchy/hierarchy-page.tsx:1871` — fallback to older `scoped-policies` endpoint when `hierarchy/tree` is unavailable. Cross-version compat with older fleet daemons.
- `apps/workbench/src/lib/commands/file-commands.ts:53, 87` — `// Fallback to legacy save` in `file.save` / `file.saveAs`. Two-tier save: prefers tab-level edit state, falls back to global save. Intentional.
- `apps/workbench/src/lib/plugins/plugin-loader.ts:608` — undefined-`perms` = no enforcement, documented backward-compat.
- `apps/workbench/src/lib/plugins/bridge/bridge-host.ts:84, 158` — internal-plugin pass-through.
- `apps/workbench/src/features/fleet/fleet-client.ts:350, 362` — cleans up `LS_API_KEY`/`LS_CONTROL_TOKEN` from localStorage from a past security finding. Defensive; cheap to keep.
- `apps/desktop/src/context/OpenClawAgentProvider.tsx:189` — one-time migration from renderer storage to agent secure storage.
- `crates/libs/clawdstrike/src/curator_config.rs:27-30` — `CuratorConfigFile` flat-key format kept for `trusted_curators.toml` on-disk compatibility.
- `crates/libs/clawdstrike/src/sandbox/attestation.rs:270-273` — `legacy_contract_default`/`legacy_authorization_model_default` `serde(default = ...)` for forward-deser.
- `crates/libs/hunt-query/Cargo.toml:11-13` and `src/lib.rs:5-7`, `src/ocsf.rs:3-4` — `ocsf` cargo feature is an explicit no-op compatibility shim for downstream manifests; OCSF is built unconditionally now.
- `crates/services/clawdstrike-registry/src/keys.rs:46-377` (6 sites) — overlap-window logic for deprecated/rotated keys; required by key-rotation contract.
- `crates/services/hushd/src/rbac/mod.rs:733` — "If RBAC is disabled, treat identity roles as role IDs (legacy behavior)" — feature-gated fallback.
- `crates/services/control-api/src/services/hierarchy.rs:100, 321` — emits warnings on legacy "agent" usage while still mapping correctly.
- `crates/services/control-api/src/routes/policies.rs:1995` — "Best-effort compatibility broadcast for legacy subscribers" — NATS dual-publish for older subscriber versions. Could be removed when minimum supported agent version bumps (cross-team coordination).
- `crates/services/control-api/src/validation.rs:85` — `clamp_legacy_trust_levels` for directory contract enforcement on legacy inputs.
- `crates/services/hush-cli/src/sandbox_nono.rs:3` — describes nono replacing legacy `sandbox-exec`/`bwrap` wrappers (docstring, not a marker).
- `crates/services/hush-cli/src/main.rs:218, 569` — CLI flag accepts `legacy` sandbox mode and `--legacy` migration flag; user-facing surface.
- `crates/services/hush-cli/src/policy_migrate.rs:30` — `Full legacy input (only set for legacy OpenClaw migrations)` — load-bearing field doc.
- `crates/libs/clawdstrike/src/async_guards/threat_intel/spider_sense.rs:59, 111` — `Optional key status (active/deprecated/revoked)` and `Optional legacy inline public key`; intentional schema surface.
- `apps/workbench/src-tauri/src/commands/workbench.rs:1149, 1230, 1254` — legacy colon-delimited receipt payload format kept for older chains.
- `apps/desktop/src-tauri/src/commands/policy.rs:94` — "Check a legacy action against active policy" — public Tauri command doc.
- `apps/desktop/src/services/marketplaceSettings.ts:151` — flag to prefer Spine-mode feed loading over legacy HTTP/IPFS path.
- `packages/policy/clawdstrike-policy/src/policy/legacy.ts:1-50` + `packages/adapters/clawdstrike-openclaw/src/policy/schema.legacy.zod.ts` + `validator.ts` — full legacy OpenClaw v1.0 policy schema and translator. Load-bearing migration code for users on the old schema.
- `packages/adapters/clawdstrike-openclaw/src/plugin.ts:328, 374` — registers for both modern and legacy event names + falls back to legacy registration shapes.
- `packages/adapters/clawdstrike-openclaw/src/policy/loader.ts:378` — prefers first-class `spider_sense` over deprecated `custom` entries (intentional Spider Sense promotion code from 2026-03-03).
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:333` — "legacy name for callers still on ai@3-4".
- `packages/adapters/clawdstrike-openclaw/src/types.ts:371` — "Accepts both 'tool_call' (legacy) and 'before_tool_call' (v2026.2.1+)".
- `packages/sdk/hush-ts/src/guards/jailbreak.ts:6, 8, 10` — snake_case aliases for YAML policy fields.
- `apps/workbench/src/features/policy/hooks/use-policy-actions.ts:4` and `use-active-tab.ts:2` — describe the direct-store migration that replaced bridge hooks (factual, not a TODO).

## Notes for the cleanup PR

- The two Category A items together drop ~5 lines of dead code and one misleading comment with zero behavioural change.
- The two Category B items (`version` const drift in adapter-core + langchain-adapter) should be batched; both need the same `package.json` import pattern.
- All Category C items (5) should be filed as follow-up issues with the owner pings noted (chain integration / Lean runtime / registry auth bootstrap / WASM-in-workbench / certification scope mapping).
- No comments need deletion (Category D is empty). The "legacy" word is heavily used but consistently as a *description* of preserved compatibility surfaces, not as a stale leftover.
- The `apps/workbench/src/features/**/stores/*.tsx` cluster of `@deprecated` Provider wrappers (~16 markers) is the strongest candidate for a *future* sweep PR once remaining consumers are migrated to `useXStore` directly — but each one is currently consumed and load-bearing, so removing now would break callers.
