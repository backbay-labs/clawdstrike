# TS `any` Sprints 2 + 3 — Execution Plan

**Worktree:** `/Users/connor/.codex/worktrees/ts-sprints-deps-clawdstrike`
**Branch:** `chore/ts-sprints-23-deps-latest` (stacked on `chore/cleanup-tier-ab`, after Sprint 0+1 commit `ea6d5e9bd`)
**Audit input:** `.audit/wave3/D-typescript-any-inventory.md`
**Scope:** 3 packages — `@clawdstrike/policy`, `@clawdstrike/vercel-ai`, `@clawdstrike/openclaw`
**Style precedent:** `packages/sdk/hush-ts/src/types/wasm.ts` (hand-written interfaces, module-scoped, mirrors Rust/native source-of-truth in header doc)

---

## 1. Per-file `any` inventory (target packages, non-test)

Generated with:
```
grep -rn ": any\|<any\|as any\|any\[\]" \
  packages/policy/clawdstrike-policy/src \
  packages/adapters/clawdstrike-vercel-ai/src \
  packages/adapters/clawdstrike-openclaw/src \
  --include="*.ts" --include="*.tsx" \
  | grep -v "\.test\." | grep -v "\.d\.ts"
```

| File | Hits | Category |
|---|---:|---|
| `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts` | **60** | Hand-rolled validator: `(p.x as any).field` drill-down (lines 168–710) |
| `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts` | **51** | Vendor type gap (`LanguageModelV2*`) + prompt-walking helpers (lines 270–1269) |
| `packages/policy/clawdstrike-policy/src/policy/legacy.ts` | **17** | Legacy → canonical translation (`(legacy.x as any).field`) |
| `packages/policy/clawdstrike-policy/src/plugins/manifest.ts` | **17** | Manifest validator (`(value as any).field`) |
| `packages/policy/clawdstrike-policy/src/engine.ts` | **12** | `policy.custom_guards as any` access + guard-result narrowing |
| `packages/policy/clawdstrike-policy/src/policy/validator.ts` | **8** | Canonical lint (uses `as any` indexing; bodies do `Record<string, unknown>` cast then drill) |
| `packages/policy/clawdstrike-policy/src/policy/loader.ts` | **8** | Merge/loader (`(child as any).custom_guards`, `(spec as any).id`) |
| `packages/adapters/clawdstrike-openclaw/src/policy/loader.ts` | **6** | `deepMerge(base: any, overlay: any)`, canonical translator field reads |
| `packages/adapters/clawdstrike-vercel-ai/src/streaming-tool-guard.ts` | **3** | `chunk as any).name` fallback (StreamChunk's `name` field not in type) |
| `packages/policy/clawdstrike-policy/src/plugins/loader.ts` | **2** | `extractFactory(mod: any)` / `isFactory(value: any)` plugin module loader |
| `packages/adapters/clawdstrike-vercel-ai/src/react/use-secure-chat.ts` | **2** | `onToolCall?.({ toolCall } as any)` / `secureToolCall as any` — Vercel-AI `useChat` callback gap |
| `packages/policy/clawdstrike-policy/src/guards/registry.ts` | **1** | `optionalString(...) as any` (severity literal narrowing) |
| **Total (non-test)** | **187** | |

(Test files excluded — they carry another ~108 hits across `*.test.ts` and are addressed only opportunistically when test fixtures duplicate prod typing.)

Mapping to user-supplied counts:
- `@clawdstrike/policy` non-test: 65 (matches user estimate)
- `@clawdstrike/vercel-ai` non-test: 56 (≈53 estimate)
- `@clawdstrike/openclaw` non-test: 66 (matches)

---

## 2. Sprint 2 — zod-based policy schema migration

### 2.1 Dependency change

Add `zod ^3.23.0` (no schema-v4 features required) to:
- `packages/policy/clawdstrike-policy/package.json` (`dependencies`)
- `packages/adapters/clawdstrike-openclaw/package.json` (`dependencies` — already depends on `@clawdstrike/policy`, so the schemas can be re-exported and openclaw need only import them)

Rationale for zod over valibot: zod has the larger ecosystem (`zod-to-json-schema` lets us auto-generate `schemas/clawdstrike.plugin.schema.json` instead of maintaining it by hand), and the audit recommends it (`.audit/wave3/D-typescript-any-inventory.md:339`).

### 2.2 New files to create

#### `packages/policy/clawdstrike-policy/src/policy/schema.zod.ts`

Schemas that mirror the existing `schema.ts` interfaces 1:1 — re-export the inferred types from this file and **delete** the hand-written interface declarations in `schema.ts` (replacing them with `export type X = z.infer<typeof xSchema>` for back-compat).

Schemas required (one per existing interface):
- `policySchemaVersionSchema` = `z.enum(["1.1.0", "1.2.0", "1.3.0"])`
- `timeoutBehaviorSchema` = `z.enum(["allow", "deny", "warn", "defer"])`
- `asyncExecutionModeSchema` = `z.enum(["parallel", "sequential", "background"])`
- `mergeStrategySchema` = `z.enum(["replace", "merge", "deep_merge"])`
- `asyncCachePolicyConfigSchema`, `asyncRateLimitPolicyConfigSchema`, `asyncCircuitBreakerPolicyConfigSchema`, `asyncRetryPolicyConfigSchema`, `asyncGuardPolicyConfigSchema`
- `customGuardSpecSchema` (with `package: z.enum([...RESERVED_PACKAGES])` to fold the `RESERVED_PACKAGES` check from `validator.ts:11–16` into the schema)
- `pathAllowlistConfigSchema`
- `spiderSenseConfigSchema` — must encode the cross-field rules from `validator.ts:151–245`:
  - `templateId`/`templateVersion` set together (`.refine`)
  - `pattern_db_manifest_path` ↔ trust-store invariants (`.refine`)
  - LLM-deep-path requires template fields (`.refine`)
- `computerUseGuardSchema`, `remoteDesktopSideChannelSchema`, `inputInjectionCapabilityGuardSchema` (these live in openclaw — re-export from policy package so both can share)
- `guardConfigsSchema` — `z.object({…}).passthrough()` to preserve the `[key: string]: unknown` index signature documented in `schema.ts:63`
- `policySettingsSchema`, `postureStateSchema`, `postureTransitionSchema`, `postureConfigSchema` (encode the wildcard-`from`, no-wildcard-`to` rule from `validator.ts:381–387` as `.refine`)
- `policyCustomGuardSpecSchema`
- `policySchema` — root, with `.refine` for: `version === '1.1.0'` rejects `posture` and `path_allowlist` (matches `validator.ts:63,86`); duplicate `custom_guards[].id` detection (`validator.ts:110`).

Important: pass `{ errorMap }` to translate zod's default messages into the existing format (e.g. `"path_allowlist requires policy version 1.2.0"`, `"guards.custom[0].package unsupported custom guard package: foo"`). The existing tests assert on exact error strings.

Estimated size: ~250 lines.

#### `packages/policy/clawdstrike-policy/src/plugins/manifest.zod.ts`

Schemas mirroring `manifest.ts:1–60` interfaces. Replace `parsePluginManifest` (`manifest.ts:61–158`) body with `pluginManifestSchema.parse(value)` plus a thin error-message adapter. Key concerns:
- Guard-name uniqueness (`manifest.ts:112–115`) → `.refine` on `guards` array
- Trust sandbox default `"node"` (`manifest.ts:88`) → `.transform` adds default
- `clawdstrike.maxVersion` accepts wildcard ranges (`isSemverRange` `manifest.ts:352–357`) → custom refinement
- Filesystem `read: false | string[]` polymorphism (`manifest.ts:229–246`) → `z.union([z.literal(false), z.array(z.string().min(1))]).transform(v => v === false ? [] : v)`

Estimated size: ~120 lines.

#### `packages/adapters/clawdstrike-openclaw/src/policy/schema.legacy.zod.ts`

Schemas for the legacy `clawdstrike-v1.0` shape mirroring `types.ts:126–207` (`Policy`, `EgressPolicy`, `FilesystemPolicy`, `ExecutionPolicy`, `ToolPolicy`, `ResourceLimits`, `PolicyGuards`, plus all the *GuardConfig subtypes).

Encodes:
- `EGRESS_KEYS` / `FILESYSTEM_KEYS` / `EXECUTION_KEYS` / `TOOLS_KEYS` / `LIMITS_KEYS` / `GUARDS_KEYS` allowed-key sets via `z.object({...}).strict()` (no need for `ensureAllowedKeys` helper anymore — strict mode rejects unknown keys natively)
- `denied_patterns` regex validity check (`validator.ts:248–254`) via `.refine` on the array element
- Spider-Sense legacy executability rule (`validator.ts:454–464`) — kept as a top-level `.superRefine` because it cross-references `guards.custom` and `guards.spider_sense`
- Empty `allowed_domains` with `mode=allowlist` warning (`validator.ts:200–202`) — zod doesn't emit warnings, so this case needs `safeParse` then post-process

Estimated size: ~200 lines.

### 2.3 Migration of existing files

#### `packages/policy/clawdstrike-policy/src/policy/schema.ts`

Convert interface declarations to `z.infer` re-exports while keeping the public type names. Example:
```ts
// before:
export interface Policy { version?: string; guards?: GuardConfigs; … }
// after:
export type Policy = z.infer<typeof policySchema>;
```
Net: 0 `any` (file currently has 0 hits; structural rewrite only).

#### `packages/policy/clawdstrike-policy/src/policy/validator.ts` (8 `any` → 0)

Replace body of `validatePolicy(policy: unknown)` (lines 44–133) with:
```ts
const result = policySchema.safeParse(policy);
if (result.success) {
  return { valid: true, errors: [], warnings: collectWarnings(result.data) };
}
return { valid: false, errors: result.error.issues.map(formatIssue), warnings: [] };
```
Keep `formatIssue` matching the historical strings (one test per error message in `validator.test.ts` will need spot fixes). Delete helpers `validatePathAllowlist`, `validateSpiderSense`, `validateSpiderSenseRetry`, `validatePosture`, `validateCustomGuardSpec`, `validateAsyncConfig`, `validateStringArray`, `requireString`, `validatePlaceholders`, `envVarForPlaceholder`, `isStrictSemver`, `isValidDuration`, `isPlainObject`, `isFiniteNumber` (~580 lines → ~90 lines). Note `validatePlaceholders` checks `process.env` — keep this as a post-schema pass (it's a runtime check, not a shape check).

#### `packages/policy/clawdstrike-policy/src/policy/legacy.ts` (17 `any` → 0)

Replace `(legacy.x as any).field` reads at lines 19, 53–54, 59, 68–71, 89–95, 100–101, 108, 118 with discriminated narrowing via a `legacyPolicySchema.partial().safeParse(legacy)`. The translation function becomes typed against the inferred shape.

Specifically (line-by-line):
- `:19` `(value as any).version` → after schema-narrow, `legacy.version: string | undefined`
- `:53–54` `(legacy.guards as any).custom` → schema-typed `legacy.guards?.custom`
- `:59,68–71,89–95,100–101,108` — all consumed by the typed legacy schema
- `:118` `(out as any).legacy_openclaw = legacy` — re-type `Policy` to allow a `legacy_openclaw?: Record<string, unknown>` debug-passthrough field (or use `Object.assign(out, { legacy_openclaw: legacy } as { legacy_openclaw: unknown })`)

#### `packages/policy/clawdstrike-policy/src/policy/loader.ts` (8 `any` → 0)

- `:54` `(options as any).visited` — extend `PolicyLoadOptions` with a private `_visited?: Set<string>` field (named-conventionally to indicate internal use), drop the cast
- `:79`, `:147`, `:148`, `:166`, `:167`, `:168` — `(child as any).custom_guards` / `(base as any).custom_guards` — once `Policy` is the zod-inferred type, `custom_guards` is a known optional field; drop casts
- `:211`, `:218` `(cg as any).id` — type as `Pick<PolicyCustomGuardSpec, 'id'>` via narrowing helper

#### `packages/policy/clawdstrike-policy/src/engine.ts` (12 `any` → 0)

- `:79–81` `Array.isArray((policy as any).custom_guards) ? ((policy as any).custom_guards as unknown[]) : []` → typed `policy.custom_guards ?? []`
- `:85` `String((specs[0] as any).id ?? "")` — narrow via `policyCustomGuardSpecSchema.safeParse(specs[0])`
- `:95–98` `(spec as any).enabled`, `.id`, `.config` — typed once `specs: PolicyCustomGuardSpec[]`
- `:151–154` `(value as any).allowed/.severity/.message/.details` for normalizing custom guard results — define `customGuardResultSchema` in `async/types.ts` (the existing `GuardResult` interface is the target — add a zod schema and use `.safeParse` to narrow `unknown` into `Partial<GuardResult>`)
- `:207` `severity: overall.severity as any` — once `Decision.severity` is properly typed as `Severity` (it already is in `adapter-core`), this cast is removed by exporting the enum-typed shape from `aggregateOverall`

#### `packages/policy/clawdstrike-policy/src/plugins/manifest.ts` (17 `any` → 0)

Replace `parsePluginManifest` body with `pluginManifestSchema.parse(value)`. Keep the function signature `(value: unknown) => PluginManifest` for back-compat. Re-export the `PluginManifest` etc. types as `z.infer<...>`. Delete `parseCompatibility`, `parseCapabilities`, `parseResources`, `parseOptionalString`, `parseOptionalBoolean`, `parseOptionalPositiveInt`, `parseHandles`, `isPluginGuardHandle`, `isStrictSemver`, `isSemverRange`, `defaultCapabilities`, `defaultResources`, `isPlainObject` (~325 lines → ~60 lines).

#### `packages/policy/clawdstrike-policy/src/plugins/loader.ts` (2 `any` → 0)

- `:302` `function extractFactory(mod: any)` → `mod: unknown` + `isFactory` narrower
- `:310` `function isFactory(value: any): value is CustomGuardFactory` → `value: unknown` (legit unknown check — type guard signature requires `value: unknown` not `any` after migration)

#### `packages/policy/clawdstrike-policy/src/guards/registry.ts` (1 `any` → 0)

- `:68` `optionalString(cfg.severity_threshold) as any` — replace with `optionalString(cfg.severity_threshold) as Severity | undefined` and add a runtime check (or model `severity_threshold` as a zod `z.enum([...])`).

#### `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts` (60 `any` → 0)

Largest migration. Strategy:
1. Replace lines 144–448 (the giant `validatePolicy(policy: unknown)` body) with `legacyPolicySchema.safeParse(policy)`.
2. The version-routing branch at `validator.ts:155–172` (canonical 1.1.0/1.2.0/1.3.0 short-circuits to `validateCanonicalPolicy`) becomes:
   ```ts
   const versionResult = z.object({ version: z.string() }).safeParse(policy);
   if (versionResult.success && SUPPORTED_CANONICAL_VERSIONS.has(versionResult.data.version)) {
     return validateCanonicalPolicy(policy);  // policy: unknown is fine — canonical validator takes unknown
   }
   ```
3. The `validateCustomGuardSpec`, `validateAsyncConfig`, etc. helpers (lines 506–710) — fold into the schema's `customGuardSpecSchema` (shared with `@clawdstrike/policy`).
4. The Spider-Sense legacy executability rule at `validator.ts:454–464` becomes a `.superRefine` on the root legacy schema.

#### `packages/adapters/clawdstrike-openclaw/src/policy/loader.ts` (6 `any` → 0)

- `:46` `function deepMerge(base: any, overlay: any): any` — re-type as generic `deepMerge<T extends Record<string, unknown>>(base: T, overlay: Partial<T>): T` (or accept `unknown` and discriminate)
- `:54`, `:57`, `:62` — `(out as any)[key] = …` — replace with `out[key as keyof typeof out] = value as never` (or restructure to use a typed accumulator)
- `:258–259` `(guards as any).custom` — once `CanonicalPolicy` is the zod-inferred type from policy package, drop cast

### 2.4 API compat strategy

All exported function signatures stay identical:
- `validatePolicy(policy: unknown) => PolicyLintResult` — unchanged
- `parsePluginManifest(value: unknown) => PluginManifest` — unchanged
- `loadPolicyFromString(yaml, options) => Policy` — unchanged
- `loadPolicyFromFile(path, options) => Policy` — unchanged

Only the *internals* change. The `Policy` and `PluginManifest` types remain structurally identical because `z.infer<typeof policySchema>` produces the same shape as the existing hand-written interface. Run a tsc-snapshot diff between before and after on consumers to confirm zero break:
```bash
cd packages/adapters/clawdstrike-openclaw && bun run typecheck
cd packages/adapters/clawdstrike-vercel-ai && bun run typecheck
```

### 2.5 Test updates

- `packages/policy/clawdstrike-policy/src/policy/validator.test.ts` — error-message strings asserted in tests must match zod-formatted output. Use the `errorMap` (see 2.2) to preserve historical messages exactly.
- `packages/policy/clawdstrike-policy/src/policy/loader.legacy.test.ts` — assertions on warning text should still pass; the legacy-translation logic is unchanged.
- `packages/policy/clawdstrike-policy/src/plugins/manifest.test.ts` — same: preserve error text via `errorMap`.
- `packages/adapters/clawdstrike-openclaw/src/policy/validator.test.ts` — same.
- Add new regression: `packages/policy/clawdstrike-policy/src/policy/schema.zod.test.ts` with round-trip tests over all 13 fixtures in `rulesets/*.yaml` (paste fixture YAML inline as strings; assert `loadPolicyFromString` succeeds with `errors: []`).
- Add `packages/adapters/clawdstrike-openclaw/src/policy/schema.legacy.zod.test.ts` with round-trip over `packages/adapters/clawdstrike-openclaw/rulesets/{ai-agent-minimal,ai-agent}.yaml`.

### 2.6 Estimated `any` removal

| File | Before | After |
|---|---:|---:|
| `policy/clawdstrike-policy/src/policy/validator.ts` | 8 | 0 |
| `policy/clawdstrike-policy/src/policy/legacy.ts` | 17 | 0 |
| `policy/clawdstrike-policy/src/policy/loader.ts` | 8 | 0 |
| `policy/clawdstrike-policy/src/engine.ts` | 12 | 0 |
| `policy/clawdstrike-policy/src/plugins/manifest.ts` | 17 | 0 |
| `policy/clawdstrike-policy/src/plugins/loader.ts` | 2 | 0 |
| `policy/clawdstrike-policy/src/guards/registry.ts` | 1 | 0 |
| `adapters/clawdstrike-openclaw/src/policy/validator.ts` | 60 | 0 |
| `adapters/clawdstrike-openclaw/src/policy/loader.ts` | 6 | 0 |
| **Sprint 2 subtotal** | **131** | **0** |

### 2.7 Risks

1. **Stricter rejection of edge-case inputs.** Hand-rolled validators are forgiving (e.g. `Array.isArray(allowed)` + filter); zod `z.array(z.string())` rejects an array containing a non-string. Mitigation: use `z.array(z.string()).or(z.unknown().transform((v) => Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []))` for the 2 known forgiving spots (`legacy.ts:79–82,103–105`). Catalog all forgiveness sites by re-running `validator.test.ts` and `loader.legacy.test.ts` after each batch.
2. **Error message drift.** Many tests assert exact strings like `"egress.mode must be one of: allowlist, denylist, open, deny_all"`. Mitigation: write `formatIssue(issue: z.ZodIssue): string` that builds the old format from `issue.path`/`issue.code`. Add an end-to-end "every error-message string from old impl reproduces" assertion in a new `validator.regression.test.ts`.
3. **`extends` chain mutation order.** `loader.ts:87–89` deletes `extends` and `merge_strategy` from the merged policy. Once `Policy` is zod-inferred, those fields are still optional, so `delete merged.extends` should still work — verify via `loader.test.ts`.
4. **`onWarning` callback for legacy warnings.** Zod doesn't produce warnings — only errors. The `validatePolicy` return shape includes `warnings: string[]` (e.g. `validator.ts:170, 322, 449`). Solution: keep `warnings` collection as a post-`safeParse` pass over the parsed data (`spider_sense` 1.3.0 fields on 1.2.0 policy, empty `allowed_domains` etc.). About 6 warning sites in canonical, 3 in legacy.
5. **`process.env` placeholder validation.** `validator.ts:579–607` walks the whole policy looking for `${secrets.X}` placeholders and checks `process.env`. This is a runtime side-effect outside the schema's purview. Keep as a separate `validatePlaceholders(policy)` call after `safeParse` returns success.

---

## 3. Sprint 3 — Vercel AI + OpenClaw vendor-typed integration

### 3.1 Vercel AI typing

#### Installed versions (`packages/adapters/clawdstrike-vercel-ai/package.json`)

- `ai`: `^6.0.69` (devDep + optional peer)
- `@ai-sdk/react`: `^3.0.71` (devDep + optional peer)

These are AI SDK **v5+** generation. The middleware uses `experimental_wrapLanguageModel`, which in v5+ uses the `LanguageModelV2` interface (renamed from `LanguageModelV1` in v5). The runtime import in `middleware.ts:275–281` already does `await import("ai")` dynamically so the package isn't statically required, but the prompt-walking helpers (lines 846–1141) hand-walk what is a `LanguageModelV2Message[]` discriminated union.

#### Strategy: type-only import from `@ai-sdk/provider`

Add devDep `@ai-sdk/provider: ^2.0.0` (the v2-line ships `LanguageModelV2Prompt`, `LanguageModelV2Message`, `LanguageModelV2StreamPart`). This is a type-only dep — no runtime impact. Pin to a specific minor (`~2.0.x`) so the discriminant shape doesn't shift under us.

Then add `import type { LanguageModelV2CallOptions, LanguageModelV2Message, LanguageModelV2Prompt, LanguageModelV2StreamPart, LanguageModelV2ToolCallPart, LanguageModelV2TextPart } from '@ai-sdk/provider'` at the top of `middleware.ts`.

#### Per-line migration in `middleware.ts` (51 `any` → ~7)

| Line | Current | Target |
|---|---|---|
| 303 | `(wrapped as any)[prop] as (...args: unknown[]) => unknown` | Keep — this is the Proxy-forward at the unknown-shape boundary; legitimate. Annotate with `// eslint-disable-next-line` + comment. |
| 329 | `doGenerate: () => Promise<any>` | `doGenerate: () => Promise<Awaited<ReturnType<LanguageModelV2['doGenerate']>>>` |
| 330 | `params: any` | `params: LanguageModelV2CallOptions` |
| 351 | `result.toolCalls.map(async (call: any) => …)` | `call: LanguageModelV2ToolCallPart` |
| 371 | `doStream: () => Promise<any>; params: any` | same `LanguageModelV2CallOptions` |
| 402, 408 | `let current = chunk as any; current = guarded as any` | `let current: LanguageModelV2StreamPart = chunk` |
| 432, 435, 451 | `(stream as any).pipeThrough/[Symbol.asyncIterator]` | Define a local `interface ReadableLike<T>` with optional `pipeThrough` + `Symbol.asyncIterator` — uses `unknown` not `any` (3 hits → 0) |
| 647, 649 | `params: any, …): Promise<any>` | `params: LanguageModelV2CallOptions, ...): Promise<LanguageModelV2CallOptions>` (this is `applyPromptSecurityToParams`) |
| 673 | `(s: any) => s.id` | `s: { id: string }` |
| 711, 715 | `(out as any)?.prompt` / `(out as any).prompt` | After `applyPromptSecurityToParams` returns `LanguageModelV2CallOptions`, `out.prompt` is `LanguageModelV2Prompt`; drop casts |
| 925, 929 | `prompt: any[] … ): any[]` in `applyInstructionHierarchyToPrompt` | `prompt: LanguageModelV2Prompt … ): LanguageModelV2Prompt` |
| 933, 949 | `(msg as any).role; enforcer.enforce(inputs as any)` | `msg: LanguageModelV2Message` — `role` is a typed discriminant; `inputs` requires a typed shape on the `HierarchyEnforcer` side (see hush-ts) — that's a separate type, can stay `unknown`-cast-once at the call boundary |
| 959, 975 | `result.conflicts.map((c: any) => …)` | Add interface `HierarchyConflict { id: string; ruleId: string; severity: string; action: string; triggers: string[] }` in `middleware.ts` based on `@clawdstrike/sdk` instruction-hierarchy types |
| 984 | `const outPrompt: any[] = []` | `const outPrompt: LanguageModelV2Message[] = []` |
| 1018, 1020 | `prompt: any[] … ): Promise<any[]>` (`applyPromptWatermark`) | `LanguageModelV2Prompt` |
| 1056, 1067, 1069 | `chunk: any; (chunk as any).type/.textDelta` | `chunk: LanguageModelV2StreamPart` — `type` is discriminant |
| 1095, 1115, 1125, 1127 | `final.findings.map((f: any) => …)`, `(chunk as any).result/.toolName`, `r.findings.map((f: any) => …)` | Define `interface PromptSecurityFinding` mirroring `@clawdstrike/sdk` `SanitizationResult.findings[number]` |
| 1148, 1149, 1152, 1154 | `(msg as any).role/.content`, `(p: any) => p && …`, `parts.map((p: any) => p.text)` in `extractLastUserText` | `msg: LanguageModelV2Message`, `p: LanguageModelV2TextPart \| ...` |
| 1160, 1162, 1163, 1169, 1171, 1172 | `applyTextToPromptMessage(originalMessage: any, newText: string): any` | `originalMessage: LanguageModelV2Message, newText: string): LanguageModelV2Message` |
| 1193, 1195, 1196, 1198, 1201 | `isPromptMessageTextful(msg: any): boolean` | `msg: LanguageModelV2Message` |
| 1212, 1218, 1220 | `extractMessageText(msg: any): string` | `msg: LanguageModelV2Message` |
| 1229, 1248 | `result: any; r.findings.map((f: any) => …)` in `recordToolResultFindings` | typed `PromptSecurityFinding` |

**Acceptable-any residue in middleware.ts:** lines 303 (Proxy forward) and the 3 `(stream as any).pipeThrough/[Symbol.asyncIterator]` checks can collapse to `unknown`. Final state: ~3 documented `any` (or 0 if all Proxy/stream sites move to `unknown`).

#### `streaming-tool-guard.ts` (3 `any` → 0)

The 3 hits (lines 50, 66, 80) are `chunk.toolName ?? (chunk as any).name`. Fix: extend the local `StreamChunk` type (`streaming-tool-guard.ts:4–12`) to add `name?: string` (Vercel AI v5 chunks include both `name` and `toolName` in different stream-part variants):
```ts
export type StreamChunk = Record<string, unknown> & {
  type?: string;
  toolCallId?: string;
  toolName?: string;
  toolCallType?: string;
  name?: string;      // ADD
  args?: unknown;
  argsTextDelta?: string;
  result?: unknown;
};
```
Then drop `(chunk as any).name` → `chunk.name`.

#### `react/use-secure-chat.ts` (2 `any` → 0 or 2 documented)

- `:91` `return onToolCall?.({ toolCall } as any);` — `useChat`'s `onToolCall` signature in `@ai-sdk/react ^3.0.71` is `({ toolCall: { toolCallId: string; toolName: string; args: unknown } }) => unknown`. The local `secureToolCall` accepts a wider `{ toolName: string; args: unknown }` shape. Fix: re-import the `ToolCall` type from `@ai-sdk/react` or `ai` and align the local param.
- `:98` `onToolCall: secureToolCall as any` — once `secureToolCall` matches the `useChat` `onToolCall` signature, drop cast.

If the v5 type for `onToolCall` is too tightly coupled to a `tools` generic that we don't have, mark these 2 as `eslint-disable` with comment `// vendor-gap: @ai-sdk/react onToolCall is parameterized on Tools and not callable without a known tool set`.

### 3.2 OpenClaw concrete-type hand-typing

OpenClaw is the **policy adapter package** (not the OpenClaw upstream SDK). It depends on a peer `openclaw: >=2025.0.0` but uses none of its types directly in the files with `any` debt — all openclaw `any` hits cluster in the policy validator/loader and are addressed by Sprint 2.

**No additional hand-typing needed** beyond what Sprint 2 covers. The audit's mention of "OpenClaw stream/tool surface" in the user's brief is a misread of the `clawdstrike-openclaw` package name — its `any` debt is policy-validation `any`, not OpenClaw-SDK `any`.

Concrete check: hooks/{cua-bridge,tool-preflight,inbound-message,agent-bootstrap}/handler.ts files contain **zero `any`** in prod (the hits cataloged are entirely in `*.test.ts`). The `tools/policy-check.ts` is also clean. Sprint 3 OpenClaw scope = 0 prod `any` to remove.

### 3.3 Estimated `any` removal — Sprint 3

| File | Before | After |
|---|---:|---:|
| `adapters/clawdstrike-vercel-ai/src/middleware.ts` | 51 | 3 (documented) |
| `adapters/clawdstrike-vercel-ai/src/streaming-tool-guard.ts` | 3 | 0 |
| `adapters/clawdstrike-vercel-ai/src/react/use-secure-chat.ts` | 2 | 0 or 2 (documented) |
| **Sprint 3 subtotal** | **56** | **3–5** |

---

## 4. Acceptable-`any` list (intentional residue)

These hits should **stay** as `any` (or migrate to `unknown` only) with `// eslint-disable-next-line @typescript-eslint/no-explicit-any` + 1-line justification:

| File:Line | Reason |
|---|---|
| `vercel-ai/src/middleware.ts:303` | Proxy `Reflect.get` forward — `prop` is a `symbol \| string` indexed onto an opaque `LanguageModelV2` instance whose method set varies by provider. Typing this requires a discriminated union over every provider's method names. |
| `vercel-ai/src/middleware.ts:432,435,451` (×3) | `(stream as any).pipeThrough` / `(stream as any)[Symbol.asyncIterator]` — duck-typing across `ReadableStream<T>` (browser/Node Web Streams) and async-iterable streams. Both `WHATWG ReadableStream` and `AsyncIterable<T>` are valid runtime targets and have no shared TS supertype. Use `as unknown as { pipeThrough?(...): unknown; [Symbol.asyncIterator]?(): … }` if `unknown` is preferred. |
| `vercel-ai/src/react/use-secure-chat.ts:91,98` (×2) | `@ai-sdk/react` `useChat.onToolCall` signature is parameterized on a `Tools` generic the wrapper can't see at compile time (the engine is opaque). The Vercel AI team's own SDK examples use the same `as any` here. |
| `policy/clawdstrike-policy/src/policy/validator.ts:579` (placeholder walker) | Walks arbitrary unknown JSON looking for `${secrets.X}` placeholder strings — must accept `unknown` (already does) but cannot be schema-typed because it intentionally inspects *every* shape including arrays-of-objects-of-strings, so loose typing is correct. Already uses `unknown`, not `any` — no action. |

Total intentional residue after both sprints: **6 documented `any`** (3 in middleware + 2 in use-secure-chat + 1 acceptable use of `unknown` not `any`). All other 181 hits removed.

---

## 5. Execution batches

Six batches, each ≤4 files touched, each independently verifiable with `bun run typecheck` + `bun test`.

### Batch B1 — Add zod dep + define core schemas (no behavior change)

- **Files touched:** `packages/policy/clawdstrike-policy/package.json` (add `zod`), `packages/adapters/clawdstrike-openclaw/package.json` (add `zod`), new `packages/policy/clawdstrike-policy/src/policy/schema.zod.ts` (define schemas only, **don't** rewire callers yet)
- **`any` delta:** 0
- **Verify:**
  ```bash
  cd packages/policy/clawdstrike-policy && bun install && bun run typecheck && bun test
  cd packages/adapters/clawdstrike-openclaw && bun install && bun run typecheck && bun test
  ```
- **Goal:** schemas compile, all schemas have unit tests against a few fixture inputs.

### Batch B2 — Migrate canonical `validatePolicy` + `loader` + `legacy` + `engine` to zod

- **Files touched:**
  - `packages/policy/clawdstrike-policy/src/policy/validator.ts` (-8 `any`)
  - `packages/policy/clawdstrike-policy/src/policy/legacy.ts` (-17)
  - `packages/policy/clawdstrike-policy/src/policy/loader.ts` (-8)
  - `packages/policy/clawdstrike-policy/src/engine.ts` (-12)
  - `packages/policy/clawdstrike-policy/src/policy/schema.ts` (rewrite as `z.infer` re-exports)
  - `packages/policy/clawdstrike-policy/src/guards/registry.ts` (-1)
- **`any` delta:** −46
- **Verify:**
  ```bash
  cd packages/policy/clawdstrike-policy && bun run typecheck && bun test
  # Round-trip every ruleset
  for f in rulesets/*.yaml; do
    node -e "import('./packages/policy/clawdstrike-policy/dist/index.js').then(m => console.log(m.loadPolicyFromFile('$f')))"
  done
  ```

### Batch B3 — Migrate `parsePluginManifest` + plugin loader to zod

- **Files touched:**
  - `packages/policy/clawdstrike-policy/src/plugins/manifest.ts` (-17)
  - `packages/policy/clawdstrike-policy/src/plugins/manifest.zod.ts` (new)
  - `packages/policy/clawdstrike-policy/src/plugins/loader.ts` (-2)
  - Optionally regenerate `packages/policy/clawdstrike-policy/schemas/clawdstrike.plugin.schema.json` from the zod schema via `zod-to-json-schema` (devDep) to keep JSON Schema artifact in sync
- **`any` delta:** −19
- **Verify:**
  ```bash
  cd packages/policy/clawdstrike-policy && bun run typecheck && bun test
  diff <(cat schemas/clawdstrike.plugin.schema.json) <(node scripts/emit-plugin-schema.mjs)  # if regenerator added
  ```

### Batch B4 — Migrate openclaw legacy `validatePolicy` + `loader` to zod

- **Files touched:**
  - `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts` (-60)
  - `packages/adapters/clawdstrike-openclaw/src/policy/loader.ts` (-6)
  - `packages/adapters/clawdstrike-openclaw/src/policy/schema.legacy.zod.ts` (new)
- **`any` delta:** −66
- **Verify:**
  ```bash
  cd packages/adapters/clawdstrike-openclaw && bun run typecheck && bun run test
  # Run the regression bench
  bun run bench  # ensure no perf regression > 2x; zod-validated path should be within 1.5x hand-written
  # Round-trip openclaw rulesets
  bun run e2e
  ```

### Batch B5 — Type Vercel-AI middleware via `@ai-sdk/provider` types

- **Files touched:**
  - `packages/adapters/clawdstrike-vercel-ai/package.json` (add devDep `@ai-sdk/provider: ~2.0.0`)
  - `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts` (-48 of 51)
  - `packages/adapters/clawdstrike-vercel-ai/src/streaming-tool-guard.ts` (-3)
- **`any` delta:** −51
- **Verify:**
  ```bash
  cd packages/adapters/clawdstrike-vercel-ai && bun install && bun run typecheck && bun test
  ```

### Batch B6 — Type `useSecureChat` + add eslint-disable annotations to residue

- **Files touched:**
  - `packages/adapters/clawdstrike-vercel-ai/src/react/use-secure-chat.ts` (-0 or -2)
  - `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts` (annotate the 3 residual stream-duck-type sites)
  - `packages/adapters/clawdstrike-vercel-ai/eslint.config.mjs` or root eslint config (add `"@typescript-eslint/no-explicit-any": "error"`)
- **`any` delta:** −2 (with eslint-disable annotations on residue)
- **Verify:**
  ```bash
  cd packages/adapters/clawdstrike-vercel-ai && bun run typecheck && bun test
  # Repo-wide: zero un-disabled `any` in target packages
  grep -rn ": any\|<any\|as any\|any\[\]" \
    packages/policy/clawdstrike-policy/src \
    packages/adapters/clawdstrike-vercel-ai/src \
    packages/adapters/clawdstrike-openclaw/src \
    --include="*.ts" --include="*.tsx" \
    | grep -v "\.test\." | grep -v "eslint-disable" | wc -l
  # expect: 0
  ```

### Net cumulative `any` removal across batches

| Batch | Cumulative `any` removed |
|---|---:|
| B1 | 0 |
| B2 | 46 |
| B3 | 65 |
| B4 | 131 |
| B5 | 182 |
| B6 | 184 (residue 3 annotated) |

---

## 6. Verification commands (run after each batch)

```bash
# 1. Package-local checks
cd packages/policy/clawdstrike-policy && bun run typecheck && bun test
cd packages/adapters/clawdstrike-openclaw && bun run typecheck:workspace && bun run test:workspace
cd packages/adapters/clawdstrike-vercel-ai && bun run typecheck && bun test

# 2. Cross-package consumers (catches API-shape drift)
cd packages/sdk/hush-ts && bun run typecheck
cd packages/adapters/clawdstrike-claude && bun run typecheck
cd packages/adapters/clawdstrike-openai && bun run typecheck
cd packages/adapters/clawdstrike-langchain && bun run typecheck
cd apps/workbench && bun run typecheck    # depends on @clawdstrike/policy

# 3. Repo-wide formatting (biome is the configured formatter — see package.json:`format:check`)
cd packages/policy/clawdstrike-policy && bun run format:check
cd packages/adapters/clawdstrike-openclaw && bun run format:check
cd packages/adapters/clawdstrike-vercel-ai && bun run format:check

# 4. Workspace-wide test pass (Sprint exit criterion)
bun test                # from repo root, runs all *.test.ts

# 5. `any` grep regression gate (Sprint exit criterion)
HITS=$(grep -rn ": any\|<any\|as any\|any\[\]" \
  packages/policy/clawdstrike-policy/src \
  packages/adapters/clawdstrike-vercel-ai/src \
  packages/adapters/clawdstrike-openclaw/src \
  --include="*.ts" --include="*.tsx" \
  | grep -v "\.test\." | grep -v "eslint-disable-next-line" | wc -l)
test "$HITS" -le 4 || { echo "any-debt regression: $HITS hits"; exit 1; }

# 6. Rust workspace untouched (sanity)
cargo check -p clawdstrike-policy-event   # one quick smoke; full `cargo check --workspace` not needed
```

### Commit message template (per batch)

```
refactor(ts): TS-any Sprint <2|3> batch B<N> — <area> (-<delta> any)

<one-line summary of mechanical change>

- before: <X> hits in <files>
- after:  <Y> hits (residue <Z> documented with eslint-disable)
- verify: bun run typecheck && bun test pass clean

Refs: .audit/wave4/PLAN-ts-sprints-23.md §<batch-id>
```

---

## 7. Out-of-scope (do NOT touch in these sprints)

- `packages/sdk/hush-ts/**` — addressed in Sprint 0+1 (commit `ea6d5e9bd`)
- `apps/workbench/**` — separate sprint (see audit §5, §6)
- Test files (`*.test.ts`, `*.test.tsx`) — only update if a schema rename breaks them. Test-helper `any` is acceptable.
- Any Rust crates — these sprints are TS-only.
- `packages/adapters/clawdstrike-openclaw/src/e2e/openclaw-e2e.ts` — flagged as test-helper-leak in audit §12; minor (3 hits); skip unless trivially fixable from a Sprint 2 type rename.

---

## 8. Total expected outcome

| Metric | Before Sprint 2+3 | After |
|---|---:|---:|
| Non-test `any` in 3 target packages | 187 | 3–5 (all documented) |
| Test-file `any` (untouched) | ~108 | ~108 |
| Schema lib | none (hand-rolled) | `zod ^3.23` |
| Vendor type pinning | `ai` floating `^6.0.69` | `@ai-sdk/provider ~2.0.x` (type-only) |
| New schema files | 0 | 3 (`schema.zod.ts`, `manifest.zod.ts`, `schema.legacy.zod.ts`) |
| Eslint rule available to enable | n/a | `"@typescript-eslint/no-explicit-any": "error"` (B6) |

End state: the three target packages are zod-validated, vendor-typed, and have a working `no-explicit-any` lint gate. Annotated residue is grep-able via `eslint-disable-next-line @typescript-eslint/no-explicit-any`.

---

*Plan authored by claude-opus-4-7[1m], wave-4, 2026-05-23. Stacked on `chore/cleanup-tier-ab` via `chore/ts-sprints-23-deps-latest`.*
