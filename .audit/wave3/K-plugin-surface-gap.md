# Plugin Surface Gap Audit

Wave 3 audit comparing the documented plugin surface (`docs/src/plugins/*`) to
the actual code that ships under `crates/libs/clawdstrike-guard-sdk*`,
`crates/libs/clawdstrike/src/plugins/`, `packages/sdk/plugin-sdk`,
`packages/dev/vite-plugin-clawdstrike`, `packages/cli/create-plugin`, and the
workbench loader at `apps/workbench/src/lib/plugins/`.

## Summary

| Surface              | Approx. LOC |
|----------------------|-------------|
| Plugin docs (9 chapters across `docs/src/plugins/`)        | **1,755 lines** of markdown across 15 files |
| TS Plugin SDK (`packages/sdk/plugin-sdk/src`)              | ~1,538 LOC (src) + ~1,329 LOC tests |
| TS create-plugin CLI (`packages/cli/create-plugin/src`)    | ~1,154 LOC |
| TS vite dev plugin (`packages/dev/vite-plugin-clawdstrike/src`) | **187 LOC** + 2 tests |
| Workbench loader (`apps/workbench/src/lib/plugins/`)       | ~22,962 LOC across 103 files (47 test files) |
| Rust guest SDK (`crates/libs/clawdstrike-guard-sdk*`)      | 307 LOC (guest) + 131 LOC macro |
| Rust host runtime (`crates/libs/clawdstrike/src/plugins/`) | 2,087 LOC (manifest + loader + WASM runtime + guard wrapper) |

**Headline:** **9 doc chapters describe a far more polished surface than ships.**
The TS-side plugin story has *substantial scaffolding* (createPlugin factory,
manifest validation, spy/mock testing utilities, view registry, sandbox iframe,
postMessage bridge, playground transpiler, dev console, HMR handler, 47 test
files) — this is **closer to a real product than the Wave 1 note suggested**.

But the documented "Tier-1" story has two cracks:

1. **Two parallel plugin worlds that do not talk to each other.**
   The TypeScript plugin world (UI/workbench contributions, `@clawdstrike/plugin-sdk`,
   `manifest.id = "acme.foo"`, `trust: "community"`, iframe sandbox) and the
   **Rust/WASM guard plugin world** (`clawdstrike.plugin.toml`, `PluginLoader`,
   `WasmGuard`, wasmtime sandbox, `cdylib` cargo crate, `#[clawdstrike_guard]`
   macro) share the word "plugin", a publishing CLI (`hush pkg`), and almost
   nothing else. The docs at `docs/src/plugins/` describe only the TS world.
2. **The TS SDK package is not actually consumed by the workbench.**
   `apps/workbench/package.json` does **not** depend on
   `@clawdstrike/plugin-sdk`, `@clawdstrike/create-plugin`, or
   `@clawdstrike/vite-plugin-clawdstrike` (the workbench has its own
   `src/lib/plugins/types.ts` copy of every contribution interface and even its
   own `manifest-validation.ts`). The SDK package is a *parallel re-export* of
   types whose source of truth lives in the workbench.

A third-party plugin built today against the documented `@clawdstrike/plugin-sdk`
**would type-check and unit-test against the spy context**, but there is no
publish path, no signed loader that consumes the SDK manifest in production,
and no end-to-end "install from registry → activate → see in workbench"
demo. The Rust/WASM side does have an end-to-end path (`hush pkg init/pack/install/test`)
but its docs live elsewhere and it is gated behind the `wasm-plugin-runtime`
cargo feature.

## Documented Surface

`docs/src/plugins/` chapters (1,755 LOC markdown total):

| # | Chapter | Claimed capability | Status | Evidence |
|---|---------|--------------------|--------|----------|
| 1 | `index.md` (13 LOC) | Three trust tiers (`internal`, `community`, `mcp`); lazy activation events | **PARTIAL** | Trust tier enum exists in `packages/sdk/plugin-sdk/src/types.ts:32`; activation matcher in `apps/workbench/src/lib/plugins/activation-events.ts`. "mcp" tier has no loader path in `apps/workbench/src/lib/plugins/plugin-loader.ts`. |
| 2 | `getting-started.md` (138 LOC) | `npm create @clawdstrike/plugin my-first-plugin --type guard` scaffolds a working project; HMR via `vite-plugin-clawdstrike` | **PARTIAL** | `packages/cli/create-plugin/src/cli.ts` + 9 template files (`templates/{guard,intel,ui,compliance,detection,config,full,source,test}.ts`) exist and have integration tests. But the docs invoke it as `npm create @clawdstrike/plugin` while the package is named `@clawdstrike/create-plugin` — the `create-*` rewrite is npm convention so this *probably* works, but no smoke test in repo confirms `npm create` resolution. |
| 3 | `manifest.md` (154 LOC) | `PluginManifest` interface with `id, name, displayName, version, publisher, categories, trust, activationEvents, contributions, installation, requiredSecrets` | **SHIPPED** (types) / **PARTIAL** (loader) | Types: `packages/sdk/plugin-sdk/src/types.ts:425-455`. Runtime validation: `packages/sdk/plugin-sdk/src/manifest-validation.ts:192`. **Production loader** in `apps/workbench/src/lib/plugins/manifest-validation.ts` re-implements this independently — risk of drift. |
| 4 | `contribution-points.md` + 6 subpages (853 LOC) | 16 contribution types (guards, commands, keybindings, fileTypes, detectionAdapters, activityBarItems, editorTabs, bottomPanelTabs, rightSidebarPanels, statusBarItems, threatIntelSources, complianceFrameworks, gutterDecorations, contextMenuItems, enrichmentRenderers) | **SHIPPED** (types + workbench registries) | All 16 interfaces defined in `packages/sdk/plugin-sdk/src/types.ts`. Workbench registries exist: `view-registry.ts`, `context-menu-registry.ts`, `gutter-extension-registry.ts`, `enrichment-type-registry.ts`, `../workbench/guard-registry.ts`, `../workbench/file-type-registry.ts`, `../workbench/status-bar-registry.ts`, `../workbench/threat-intel-registry.ts`. `plugin-loader.ts:41-49` wires them. |
| 5 | `api-reference.md` (106 LOC) | TypeDoc-generated public API surface for `@clawdstrike/plugin-sdk` | **PARTIAL** | Source comments are TSDoc-rich (`packages/sdk/plugin-sdk/src/index.ts`), typedoc config exists at `packages/sdk/plugin-sdk/typedoc.json`, but the doc page hardcodes a link to `../../api/plugin-sdk/README.md` which is generated artifact, not committed. `mise run docs:plugin-api` referenced but no mise task verified. |
| 6 | `dev-server.md` (58 LOC) | `vite-plugin-clawdstrike` watches plugin source dirs, emits `clawdstrike:plugin-update` WS event, workbench hot-reloads with preserved storage and <200ms cycle, adds a Plugin Dev Console panel | **PARTIAL** — chapter even self-flags _"requires Phase 3 implementation"_ | Vite plugin exists and emits the event: `packages/dev/vite-plugin-clawdstrike/src/index.ts`, `src/watcher.ts:40`. Workbench-side HMR handler exists: `apps/workbench/src/lib/plugins/dev/hmr-handler.ts` and **uses the same event constant** (`apps/workbench/src/lib/plugins/dev/types.ts:36`). Dev console store + interceptor exist (`dev/dev-console-store.ts`, `dev/console-interceptor.ts`). **But** the workbench is not configured to consume `vite-plugin-clawdstrike` in any committed `vite.config.ts`. Docs imply turnkey `plugins: ["../my-first-plugin"]` API but the actual Vite plugin requires the more verbose `plugins: [{ dir, pluginId, entry }]` shape (`src/types.ts`). |
| 7 | `testing.md` (255 LOC) | `createMockContext`, `createSpyContext`, `assertContributions`, `assertManifestValid` for vitest-style plugin tests | **SHIPPED** | `packages/sdk/plugin-sdk/src/testing.ts` implements all four (lines 106, 153, 254, 274). Covered by 7 test files including `tests/testing.test.ts` (446 LOC) and `tests/testing-assertions.test.ts` (200 LOC). |
| 8 | `publishing.md` (82 LOC) | `clawdstrike pkg sign` + `clawdstrike pkg publish` workflow with Ed25519-signed canonical-JSON manifest; `installation` block with `downloadUrl`, `size`, `checksum`, `signature` | **PARTIAL** — wrong CLI name | `hush pkg publish` exists at `crates/services/hush-cli/src/pkg_cli.rs:2538`, `hush pkg sign` not found (signing happens inline in `cmd_pkg_publish` via `clawdstrike::pkg::integrity::sign_package`). Publish operates on **`.cpkg` archives produced by `hush pkg pack`**, not on the TS plugin-SDK shape. Plugin-side `installation` fields are typed (`packages/sdk/plugin-sdk/src/types.ts:400`) but no documented end-to-end path takes a `createPlugin()` output, signs it, uploads, and shows it loading via the registry. |
| 9 | `playground.md` (41 LOC) | In-workbench live plugin editor with code editor, contribution inspector, plugin console; self-flagged _"requires Phase 5 implementation"_ | **SHIPPED** | All pieces exist: `apps/workbench/src/lib/plugins/playground/playground-store.ts`, `playground-runner.ts`, `playground-source-map.ts`, `playground-eval-server.ts`, `playground-plugin.ts`, `playground-transpiler.ts`, plus UI components `apps/workbench/src/components/plugins/playground/{PlaygroundEditor,PluginConsolePanel,PlaygroundEditorPane,PlaygroundToolbar,PlaygroundErrorBoundary,ContributionInspector}.tsx`. Activity bar item registered as `Plugin Dev` (`playground-plugin.ts:20`). |

## Actual Implementation Inventory

### TypeScript Plugin SDK — `packages/sdk/plugin-sdk` (1,538 src LOC, 1,329 test LOC)

- **Public surface (`src/index.ts`, 96 LOC):** `createPlugin`, all 16 contribution interfaces, `PluginManifest`, `PluginContributions`, `PluginContext`, 8 namespaced API interfaces (`CommandsApi`, `GuardsApi`, `FileTypesApi`, `StatusBarApi`, `SidebarApi`, `StorageApi`, `ViewsApi`, `SecretsApi`, `EnrichmentRenderersApi`), threat intel types, view prop interfaces.
- **Implementation:** Mostly *types-only*. The only executable code is `createPlugin` (an identity function, `src/create-plugin.ts:54`), `validateManifest` (`src/manifest-validation.ts:192`), `createMockContext` / `createSpyContext` / `assertContributions` / `assertManifestValid` (`src/testing.ts`).
- **Tests/examples:** 7 test files, no committed example plugin under this package.

### TS scaffolder — `packages/cli/create-plugin` (1,154 LOC)

- **Public surface:** `bin: create-plugin` (per `package.json`); 9 templates (guard, intel, ui, compliance, detection, config, full, source, test).
- **Tests:** 4 test files including `scaffold.integration.test.ts`.
- **Not verified end-to-end:** the docs claim `npm create @clawdstrike/plugin` works, but the package name is `@clawdstrike/create-plugin` — relying on npm's `create-*` convention.

### TS Vite dev plugin — `packages/dev/vite-plugin-clawdstrike` (187 LOC)

- **Public surface (`src/index.ts`, 39 LOC):** `clawdstrikePlugin(options)` returns a Vite `Plugin` that wires file watcher → custom HMR event.
- **Implementation:** `FilePluginMap` (72 LOC) maps file paths to plugin IDs; `setupPluginWatcher` (48 LOC) listens for chokidar `change`/`add` events.
- **Tests:** 2 test files (`watcher.test.ts`, `file-plugin-map.test.ts`).
- **Gap:** option shape `{ dir, pluginId, entry }` does not match docs' simpler `plugins: ["../my-first-plugin"]` syntax.

### Workbench plugin loader — `apps/workbench/src/lib/plugins` (22,962 LOC, 103 files, 47 test files)

- **Real, substantial implementation:**
  - `plugin-loader.ts` (1,279 LOC) — trust verification gate, lazy activation, sandbox routing, contribution wiring to 8+ registries, revocation drain, command-category normalization.
  - `sandbox/` and `bridge/` directories — iframe srcdoc construction and `PluginBridgeHost` / `PluginBridgeClient` postMessage bridge with integration tests.
  - `community-plugin-runtime.ts` — registry code resolution for community-tier plugins.
  - `playground/` (6 files including eval server, transpiler, source-map handling).
  - `dev/` (HMR handler, console interceptor, dev-console store, storage snapshot).
- **Duplicated types:** `apps/workbench/src/lib/plugins/types.ts` re-declares the contribution interfaces that the SDK also exports. The two definitions are *not* connected by `import`. **Drift risk**: e.g., SDK ships `NetworkPermission` and `PluginPermission` types implicitly referenced by `plugin-loader.ts:31-32` but **not** exported by the SDK's `index.ts`.

### Rust guest SDK — `crates/libs/clawdstrike-guard-sdk*` (438 LOC)

- **`clawdstrike-guard-sdk` (307 LOC across `lib.rs`, `types.rs`, `host.rs`, `prelude.rs`):**
  - `Guard` trait (`lib.rs:37`) with `name`, `handles`, `check`.
  - `GuardInput` / `GuardOutput` / `Severity` / `Verdict` / `Capability` types (`types.rs`).
  - `host::set_output` / `host::request_capability` — WASM hostcall wrappers (`host.rs`).
- **`clawdstrike-guard-sdk-macros` (131 LOC):** `#[clawdstrike_guard]` proc-macro that generates `clawdstrike_guard_init`, `clawdstrike_guard_handles`, `clawdstrike_guard_check` C ABI exports.
- **Tests:** 1 file (`tests/macro_expansion.rs`).

### Rust host plugin runtime — `crates/libs/clawdstrike/src/plugins` (2,087 LOC)

- **`manifest.rs` (350 LOC):** TOML manifest schema `clawdstrike.plugin.toml` with `[plugin]`, `[clawdstrike]`, `[[guards]]`, `[capabilities]`, `[resources]`, `[trust]`. Validates trust/capability invariants (untrusted plugins cannot request subprocess/fs-write/secrets). Tests inline.
- **`loader.rs` (423 LOC):** `PluginLoader` with `inspect()` / `plan_load()`. Validates trust policy, compatibility (semver), resource limits, entrypoint existence.
- **`runtime.rs` (806 LOC):** wasmtime-backed `execute_wasm_guard_bytes` / `execute_wasm_guard_module` / `validate_wasm_guard_module`. Hostcalls match the guest-SDK ABI version 1.
- **`guard.rs` (480 LOC):** `WasmGuard` adapter implementing the host-side `Guard` trait, plus `WasmGuardFactory`. Serializes `GuardAction` → JSON payload for guests.
- **Gating:** all of the above live behind `#[cfg(feature = "wasm-plugin-runtime")]` (see `mod.rs`).
- **CLI integration:** `hush guard validate` (in `crates/services/hush-cli/src/guard_cli.rs`) and `hush pkg test` (`pkg_cli.rs:3468`) consume this.

### Examples

- **No** `clawdstrike.plugin.toml` file exists anywhere in the repo (outside `.worktrees` / `.claude`).
- **No** TS example plugin under `examples/` consumes `@clawdstrike/plugin-sdk` (the closest is `examples/openclaw-plugin/` which is an *agent* example, not a workbench plugin).
- `apps/workbench/src/lib/plugins/examples/` exists — likely the only working "plugins" today.

## Gap Analysis

| Doc claim | Evidence in code | Verdict |
|-----------|-----------------|---------|
| `npm create @clawdstrike/plugin my-first-plugin --type guard` produces a runnable project | `packages/cli/create-plugin/src/cli.ts` + 9 templates + integration test | **SHIPPED-ish** (depends on npm `create-*` convention working with `@clawdstrike/create-plugin`) |
| `createPlugin()` factory with type-checked manifest + lifecycle | `packages/sdk/plugin-sdk/src/create-plugin.ts:54` | **SHIPPED** |
| 16 contribution types (guards/commands/keybindings/fileTypes/detectionAdapters/activityBarItems/editorTabs/bottomPanelTabs/rightSidebarPanels/statusBarItems/threatIntelSources/complianceFrameworks/gutterDecorations/contextMenuItems/enrichmentRenderers) | All 16 interfaces in `packages/sdk/plugin-sdk/src/types.ts`; 8+ workbench registries wire them in `plugin-loader.ts` | **SHIPPED** (types + registries) but **the SDK and workbench have parallel copies of the types — drift risk** |
| Three trust tiers determine load strategy | Enum at `packages/sdk/plugin-sdk/src/types.ts:32`; iframe sandbox + bridge for `community`, in-process for `internal` | **SHIPPED** for internal/community; **MISSING** for `mcp` (no MCP load path in `plugin-loader.ts`) |
| Activation events (`onStartup`, `onFileType:{x}`, `onCommand:{x}`, `onGuardEvaluate:{x}`) | `apps/workbench/src/lib/plugins/activation-events.ts` (`shouldActivateOnStartup`, `matchActivationEvent`) | **SHIPPED** |
| `createMockContext`/`createSpyContext`/`assertContributions`/`assertManifestValid` | `packages/sdk/plugin-sdk/src/testing.ts` (lines 106/153/254/274) | **SHIPPED** |
| `vite-plugin-clawdstrike` with HMR via `clawdstrike:plugin-update` and preserved storage state | `packages/dev/vite-plugin-clawdstrike` + `apps/workbench/src/lib/plugins/dev/hmr-handler.ts` use the **same** event constant; storage snapshot module exists | **PARTIAL** — pieces work in isolation, but no committed workbench `vite.config.ts` wires them, and the API shape in docs (`plugins: ["..."]`) does not match the implementation (`plugins: [{ dir, pluginId, entry }]`) |
| `Plugin Dev` activity bar item opens a CodeMirror playground with run/transpile/console | `playground/` directory in both `lib/plugins/` and `components/plugins/`; `playground-plugin.ts` registers the activity bar item | **SHIPPED** |
| Manifests are signed with Ed25519 over canonical (RFC 8785) JSON; verified at install time | `clawdstrike::pkg::integrity::sign_package` exists; manifest schema has `signature: string` field | **PARTIAL** — signing happens for `.cpkg` archives (Rust-side), not for TS `PluginManifest`-shape objects; doc command name `clawdstrike pkg sign` is wrong (binary is `hush`, and signing is part of `hush pkg publish` not a standalone subcommand) |
| `clawdstrike pkg publish` uploads to registry | `hush pkg publish` at `pkg_cli.rs:2538` | **SHIPPED** under wrong binary name |
| `minWorkbenchVersion`/`maxWorkbenchVersion` enforcement | Field is typed, no enforcement found in `plugin-loader.ts` or `plugin-trust.ts` | **MISSING** |
| `requiredSecrets` rendered as secret entry form in plugin settings UI | Type exists (`types.ts:463`); `SecretsApi` exists (`context.ts:113`); UI rendering for `requiredSecrets` form **not found** | **PARTIAL** |
| Sandbox permissions system mediates community-plugin API calls | `apps/workbench/src/lib/plugins/bridge/bridge-host.ts` + `sandbox/` exist with integration tests | **SHIPPED** |
| WASM guard plugins via `clawdstrike.plugin.toml` + `#[clawdstrike_guard]` macro + wasmtime sandbox | `crates/libs/clawdstrike-guard-sdk*` + `crates/libs/clawdstrike/src/plugins/` + `hush guard validate` / `hush pkg test` | **SHIPPED** — *but not documented anywhere under `docs/src/plugins/`* |
| Policy YAML references custom guards via `guards.custom[].package` | `crates/libs/clawdstrike/src/policy.rs:562` (`CustomGuardSpec`) — but only **4 hardcoded packages** are accepted (`clawdstrike-virustotal`, `clawdstrike-safe-browsing`, `clawdstrike-snyk`, `clawdstrike-spider-sense`); arbitrary plugin packages are **rejected** at validation time (`policy.rs:2088`) | **MISSING** the open-ended plugin → policy link the docs imply |

## Tier-1 Definition

The minimum coherent surface a third-party could use to **write a guard,
package it, install it, and load it from a policy** end-to-end:

1. **One plugin trait / contract.** Pick one: TS `createPlugin` (UI/workbench) **or** Rust `Guard` trait + `#[clawdstrike_guard]` (security guards). Cannot ship both as "the" plugin model.
2. **One manifest format.** Either the TS `PluginManifest` shape **or** TOML `clawdstrike.plugin.toml`. Currently both exist with overlapping but incompatible fields.
3. **One loader path that production actually uses.** The workbench loader at `apps/workbench/src/lib/plugins/plugin-loader.ts` exists and works for in-process plugins; the WASM path works for guards via `hush guard validate`. Tier-1 demands a *committed* `vite.config.ts` (or `tauri.conf.json`) snippet that proves the dev story.
4. **Signing + capability declaration enforced.** The signing primitives exist (`hush_core::Signature`, `clawdstrike::pkg::integrity::sign_package`); the manifest carries `signature`/`publisherKey`/`checksum`. Tier-1 requires the loader to *reject unsigned or improperly-signed* manifests.
5. **One working example checked into the repo.** No working example plugin exists today. Tier-1 requires either an `examples/plugin-guard-deny-paths/` (WASM/Rust) or `examples/plugin-ui-egress-dashboard/` (TS) that builds, loads, and runs in CI.

## Effort to Close Tier-1

| Item | Current status | Remaining work | Estimated effort |
|------|---------------|----------------|------------------|
| **1. Pick one plugin trait** | Two parallel models exist. | Document the split: "Rust/WASM = security guards; TS = workbench UX/contributions" and accept that they share branding only. Update `docs/src/plugins/index.md` to say so. | **Docs only, 1 day.** |
| **2. Pick one manifest format** | TS `PluginManifest` (typed) + Rust `clawdstrike.plugin.toml` (TOML) | Either generate one from the other, or explicitly document them as two formats. Easiest: rename docs section to "Workbench Plugins" and add a new "Guard Plugins" section pointing at TOML. | **Docs + small rename, 1–2 days.** |
| **3. Committed dev loader** | `vite-plugin-clawdstrike` exists; no committed workbench `vite.config.ts` consumes it; doc API shape doesn't match impl | Either (a) fix doc to match `{ dir, pluginId, entry }` syntax, or (b) extend `vite-plugin-clawdstrike` to accept the simpler `plugins: ["../my-first-plugin"]` form and auto-read the manifest. Add a `vite.config.example.ts` to workbench. | **0.5–2 days** depending on choice. |
| **4. Signing/loading enforcement** | Primitives exist; `installation.signature` field typed; no loader gate found in `plugin-loader.ts` | Implement Ed25519 verification in `plugin-trust.ts` against `installation.signature` + `installation.publisherKey` (or trusted publisher store). Add failing test for unsigned plugin. **For the workbench-plugin path; the Rust/WASM path already enforces via `hush pkg verify`.** | **2–4 days.** |
| **5. Working example plugin** | None exists | Author **one** end-to-end example. Recommend: a TS UI plugin (`examples/plugin-egress-dashboard/`) that uses `createPlugin`, contributes a `bottomPanelTabs` view, ships a test using `createSpyContext`, and is wired into a workbench `vite.config.ts` for HMR demo. Add to CI. | **2–3 days.** |
| **6. `mcp` trust tier loader** | Type exists, no loader path | Either remove from the type union (`PluginTrustTier = "internal" | "community"`) or implement an MCP bridge. Removal is faster. | **0.5–4 days** depending on choice. |
| **7. `requiredSecrets` UI** | Type exists, no UI found | Generic secret-entry form in plugin settings panel, backed by `SecretsApi`. | **1–2 days.** |
| **8. Policy → plugin guard wiring** | `policy.rs:2079` rejects unknown packages | Either add an extensible registry (`CustomGuardRegistry` exists at `engine.rs:1517` — make policy validation defer to it) or document the four-package allowlist explicitly. | **1–2 days.** |
| **9. Cross-package type drift** | SDK types duplicated in workbench | Make `apps/workbench/src/lib/plugins/types.ts` re-export from `@clawdstrike/plugin-sdk`; add the package to `apps/workbench/package.json` deps. | **0.5–1 day** (plus risk of revealing latent incompatibilities). |
| **10. Doc accuracy fixes** | `clawdstrike pkg sign` (wrong binary), `npm create @clawdstrike/plugin` (relies on convention), dev-server option shape mismatch | Pure doc updates. | **1 day total.** |

**Total Tier-1 close, Option A (implement to match docs):** ~10–18 person-days.

**Total Tier-1 close, Option B (trim docs to match reality):** ~3–5 person-days.

## Recommended Sequence

**Decision the user must make before any plugin doc gets touched:** is the plugin surface a **product** or a **scaffold**?

### Option A — Implement to match the docs (heavy lift, ~2 weeks)
1. Code: tier-1 items 3, 4, 5, 7, 8, 9 above.
2. Docs: keep current chapters, fix only the four factual errors in item 10.
3. CI: add a workflow that builds the example plugin and loads it in the workbench.
4. **Owners:** workbench team (loader, vite plugin, example), `clawdstrike` crate maintainer (custom-guard registry hook for policy), docs editor (binary name fix).

### Option B — Trim docs to match what ships (small lift, recommended ~3–5 days)
1. **Demote `docs/src/plugins/` to one chapter labeled "Workbench Plugin SDK (preview)"** with banner: _"This SDK has all types, a scaffolder, and a dev server, but the production loader is internal to the workbench app. Third-party plugins are not yet supported outside the workbench dev environment."_
2. **Delete or move:**
   - `playground.md` → move to a new `docs/src/workbench/playground.md` (it's not a plugin-author surface).
   - `dev-server.md` "Note: requires Phase 3" lines → reword as "preview" or delete.
3. **Add a new `docs/src/guards/wasm-plugins.md` chapter** that documents the **actually-shipped** Rust/WASM guard plugin path: `clawdstrike.plugin.toml`, `#[clawdstrike_guard]` macro, `hush guard validate`, `hush pkg test/publish`. This is the surface that has real loader + signing + sandboxing + CLI.
4. **Fix the binary-name and CLI-syntax errors** (`clawdstrike pkg sign` → `hush pkg publish`, the `npm create` invocation, and the vite plugin option shape).
5. **Owners:** docs editor only; no code change.

**Recommendation:** **Option B first**, then schedule Option A items 4 (signing enforcement) and 5 (one working example) as a follow-up phase. The current docs over-promise; the code under-delivers in *exactly the places* that decide whether a third party can ship a plugin without forking the repo. Trimming the docs is the higher-leverage move and removes the cliff that today's plugin authors fall off of when they finish the `getting-started.md` flow.

---

*Audit date: 2026-05-23. Branch: `fix/macos-es-ne-hardening`. Analyst: GSD Wave 3 K.*
