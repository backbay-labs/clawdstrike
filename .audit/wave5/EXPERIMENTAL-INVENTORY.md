# Experimental marker inventory

**Worktree:** `/Users/connor/.codex/worktrees/ts-sprints-deps-clawdstrike` (PR #314, supersedes PR #313)
**Scope:** `.ts`, `.tsx`, `.js`, `.rs`, `.yaml`, `.yml`, `.toml` excluding `node_modules`, `dist`, `target`, `infra/vendor`, `vendor/`.

## Search totals

- `experimental_<symbol>` (TS/JS prefix): 20 hits across 4 files
- Case-insensitive `experimental` (TS/JS/Rust): 82 hits
- Cargo/package/yaml `"experimental` features: 0 hits
- Rust `#[experimental]` / `#[unstable]` attributes: 0 hits

## Bucket A — Vendor-imposed (use stable APIs)

### A1. `experimental_wrapLanguageModel` — Vercel AI SDK back-compat shim

- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:172` — option field `aiSdk.experimental_wrapLanguageModel?` on `CreateClawdstrikeMiddlewareOptions`
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:264` — preference chain: `options.aiSdk?.wrapLanguageModel ?? options.aiSdk?.experimental_wrapLanguageModel`
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:331-341` — lazy import block falling back to legacy name (comment: "was removed in `ai@5+` and renamed")
- `packages/adapters/clawdstrike-vercel-ai/src/model-middleware.test.ts:31,44,61,72,85,136,158,188,210,239,261,392` — twelve test-fixture spies named `experimental_wrapLanguageModel`
- Source-of-truth: stable name `wrapLanguageModel` is exported from `ai@6.0.191` (verified in `node_modules/.bun/ai@6.0.191+27912429049419a2/node_modules/ai/dist/index.d.ts:6017`). Legacy `experimental_wrapLanguageModel` removed in `ai@5`. Adapter's `peerDependencies` declares `ai >= 5 < 7`.
- Action: Keep the runtime fallback (3 lines in `middleware.ts`) since back-compat is the explicit intent; rename test-fixture variable to `wrapLanguageModel` so suite reflects the stable API the production code prefers. The fallback path is exercised by the four `legacy aiSdk.experimental_wrapLanguageModel` cases (lines 31, 72, 136, 188, 239); collapse all but one of those to use the stable name.

### A2. `experimental_throttle` — `@ai-sdk/react` current option

- `packages/adapters/clawdstrike-vercel-ai/src/react/use-secure-chat.ts:20` — declares `experimental_throttle?: number` in `UseChatInitOptions` extension
- Vendor signature: `@ai-sdk/react@3.0.193` ships `experimental_throttle?: number` on `UseChatOptions`/`UseCompletionOptions` (verified in vendored `.d.ts:33,90`). The name is still `experimental_` in the current minor.
- The field is declared but never read by us; it is forwarded into `useChat({...chatOptions})` at line 112.
- Action: Leave as-is. Recheck after the next `@ai-sdk/react` major; if Vercel renames, drop the local declaration.

### A3. `experimental_toolCallStreaming` — `ai@4` flag inside a docs template

- `apps/workbench/src/lib/workbench/sdk-script-store.ts:439` — string literal inside a TypeScript script template the user copy/pastes
- Vendor status: removed in `ai@5+`; the stable replacement is `toolCallStreaming` on `streamText`.
- Action: Update the template string to use the stable spelling consistent with the installed `ai@6` version.

## Bucket B — Our own that became real (drop label)

### B1. SIEM exporters — `@experimental` jsdoc tag on six production-shaped classes

- `packages/sdk/hush-ts/src/siem/index.ts:3` — module-level `@experimental` on the SIEM barrel
- `packages/sdk/hush-ts/src/siem/exporters/datadog.ts:27` — `DatadogExporter`
- `packages/sdk/hush-ts/src/siem/exporters/splunk.ts:55` — `SplunkExporter`
- `packages/sdk/hush-ts/src/siem/exporters/elastic.ts:27` — `ElasticExporter`
- `packages/sdk/hush-ts/src/siem/exporters/sumo-logic.ts:26` — `SumoLogicExporter`
- `packages/sdk/hush-ts/src/siem/exporters/webhooks.ts:43` — `WebhookExporter`
- `packages/sdk/hush-ts/src/siem/exporters/alerting.ts:333` — `AlertingExporter`
- Evidence of production status:
  - 1335-line test file `packages/sdk/hush-ts/tests/siem-exporters.test.ts` (82 `describe`/`it` blocks)
  - Mirrored Go implementations in `packages/sdk/hush-go/siem/exporters/{datadog,splunk,sumologic,elastic,webhook}.go` with **no** `@experimental` markers
  - Re-exported from public SDK barrel `packages/sdk/hush-ts/src/index.ts:237` as `export * as siem`
  - Consumed by `apps/control-console/src/api/client.test.ts` and `apps/control-console/src/components/settings/SiemSettings.tsx`
  - `apps/agent/src-tauri/src/daemon.rs` ships `HushdRuntimeWebhookExporterConfig` integration
  - Has dedicated roadmap `docs/plans/siem-soar/roadmap.md` listing exporters as GA goals
- Action: Drop the seven `@experimental` jsdoc tags; the SIEM module is the documented integration surface and shipping in both TS and Go SDKs. If a stability disclaimer is still wanted, downgrade to a "best-effort delivery" note rather than `@experimental`.

## Bucket C — Work-in-progress (decide)

### C1. Terminal TUI "experimental" stage flag on 5 hunt screens

- `apps/terminal/src/tui/surfaces.ts:14,25,27,30,31` — surfaces marked `stage: "experimental"`: `interactive-run`, `hunt-rule-builder`, `hunt-diff`, `hunt-mitre`, `hunt-playbook`
- `apps/terminal/src/tui/app.ts:270,272,275,276` — same four hunt screens tagged `stage: "experimental"` in command list
- `apps/terminal/src/tui/types.ts:` — `ScreenStage = "supported" | "experimental"` enum
- `apps/terminal/src/tui/components/surface-header.ts:7` — renders `[exp]` badge for experimental stage
- `apps/terminal/src/tui/components/status-bar.ts:57` — same badge logic in status bar
- `apps/terminal/src/tui/screens/main.ts:903` — main screen filters/styles command list by stage
- `apps/terminal/test/tui-chrome.test.ts:10-13` — asserts `[exp]` badge renders
- `apps/terminal/test/investigation.test.ts:123-124` — asserts `hunt-diff` is `experimental`
- Implementation size: `hunt-rule-builder.ts` 368 LOC, `hunt-diff.ts` 423 LOC, `hunt-playbook.ts` 289 LOC, `hunt-mitre.ts` 299 LOC, `interactive-run.ts` 383 LOC — all wire to real `runCorrelate`/hunt bridge code, not stubs.
- Missing for "supported" promotion: no e2e/integration tests beyond `[exp]` badge rendering. Decide per-screen:
  - `interactive-run` — promote: already paired with `runs`/`run-detail` supported flow
  - `hunt-rule-builder`, `hunt-diff` — promote or extend tests; both call into stable `crates/.../hunt` bridges
  - `hunt-mitre`, `hunt-playbook` — confirm fixtures/playbook catalog exist before promoting
- Action: Create a follow-up to either (a) promote each screen to `supported` with a smoke e2e, or (b) keep tag and add a banner explaining what would unlock promotion. Either way, the `ScreenStage` enum should stay until at least one screen actually remains experimental.

## Bucket D — Dead (delete)

(None.)

Every `experimental` symbol found is one of: a vendor-imposed name (Bucket A), a de-facto-promoted class still marked experimental (Bucket B), or a labeled but in-use TUI surface (Bucket C). The remaining 60+ raw `experimental` hits not listed above all fall into a single non-classified category documented next.

## Non-classifications (Sigma vendor format string `status: experimental`)

These are **not** Clawdstrike code markers; they are the literal string `experimental` in the Sigma rule schema's `status` field (Sigma vendor format, alongside `test`, `stable`, `deprecated`, `unsupported`). Listed here for completeness so a follow-up doesn't try to "clean them up":

- `apps/workbench/src/lib/workbench/sigma-types.ts:5,39,52` — `SigmaStatus` type definition
- `apps/workbench/src/lib/workbench/sigma-schema.ts:29` — autocomplete entry
- `apps/workbench/src/lib/workbench/sigma-templates.ts:31,101,157,202,245` — 5 rule template defaults
- `apps/workbench/src/lib/workbench/file-type-registry.ts:56` — default Sigma file template
- `apps/workbench/src/lib/workbench/detection-mcp-tools.ts:265` — generated rule header
- `apps/workbench/src/lib/workbench/detection-workflow/use-draft-detection.ts:89` — draft rule template
- `apps/workbench/src/lib/workbench/detection-workflow/kql-translation.ts:273` — KQL→Sigma converter default
- `apps/workbench/src/lib/workbench/detection-workflow/eql-translation.ts:561` — EQL→Sigma converter default
- `apps/workbench/src/lib/workbench/detection-workflow/spl-translation-provider.ts:374` — SPL→Sigma converter default
- `apps/workbench/src/components/workbench/editor/sigma-visual-panel.tsx:33,565,686` — visual panel dropdown
- `apps/workbench/src/components/workbench/editor/visual-builder-pages.tsx:8` — visual builder template
- `apps/workbench/src/components/workbench/library/sigmahq-browser.tsx:326,335,684,693,744,753,856,865` — 8 SigmaHQ rule fixtures
- `apps/workbench/src/features/project/workspace-bootstrap.ts:47` — example workspace rule
- `apps/workbench/src/features/policy/__tests__/policy-stores-integration.test.tsx:103,337,593` — test fixture rules
- `apps/workbench/src/lib/workbench/__tests__/detection-workflow-e2e.test.ts:1026` — e2e fixture
- `apps/workbench/e2e/helpers/workbench-e2e.ts:42` — e2e helper fixture
- `apps/workbench/src-tauri/src/commands/detection.rs:1471,1830,1858,1890,1925` — Rust default + 4 template strings (Sigma conversion command)
- `rulesets/trusted_curators.example.toml:19` — commented-out curator example named `community-experimental`

## Summary

| Bucket | Items | Action |
|--------|-------|--------|
| A. Vendor-imposed | 3 (15 lines incl. tests) | Use stable name where available; keep legacy fallback for `ai@3-4` callers and current `@ai-sdk/react@3` |
| B. Our own promoted | 1 (7 jsdoc tags) | Drop `@experimental` from SIEM module + 6 exporter classes |
| C. Work-in-progress | 1 (5 TUI surfaces) | Decide promote-vs-keep per screen; needs separate follow-up |
| D. Dead | 0 | — |
