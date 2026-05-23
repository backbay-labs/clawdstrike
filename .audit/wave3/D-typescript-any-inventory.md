# TypeScript `any` Inventory

**Audit date:** 2026-05-23
**Scope:** Non-test TypeScript/TSX under `packages/`, `apps/control-console/src/`, `apps/workbench/src/`, `apps/academy/src/`.
**Exclusions:** `*.test.*`, `*.spec.*`, `__tests__/`, `node_modules/`, `dist/`, `build/`, `*.d.ts`.

## Summary

| Metric | Count |
|---|---|
| `: any` / `<any>` / `any[]` / `Promise<any>` / `Array<any>` / `Record<…, any>` declarations | **122** |
| `as any` casts | **225** |
| **Total any usages** | **347** |

> Reconciliation note: the wave-1 figure (503 `any` + 189 `as any`) is higher because it almost certainly included test files, `.d.ts`, benchmark code, and/or the agent + cloud-dashboard / desktop / terminal apps. Restricted to the in-scope production source the actual prod-surface debt is ~347 hits. The audit below targets that 347.

### Distribution (top-level)

- **Adapters** dominate `as any` (74 + 28 + 1 = 103, ≈46% of all casts) — almost entirely shape-validation and vendor type-gap workarounds.
- **`@clawdstrike/policy` (clawdstrike-policy)** is the second-largest `as any` site (69) — virtually all are unsafe-narrowing inside hand-rolled YAML validators that should be using a typed schema (zod/valibot/io-ts).
- **`@clawdstrike/sdk` (hush-ts)** dominates `: any` declarations (40) — almost all are untyped WASM-module bindings and `request<any>` HTTP helpers.
- **apps/workbench** (39 + 36 = 75) is the only app with non-trivial debt; `control-console` is *clean* (zero hits) and `academy` has 1.

### Top offenders (single files)

| File | `any` decls | `as any` |
|---|---:|---:|
| `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts` | 0 | **58** |
| `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts` | 29 | 23 |
| `packages/policy/clawdstrike-policy/src/policy/legacy.ts` | 0 | 17 |
| `packages/policy/clawdstrike-policy/src/plugins/manifest.ts` | 0 | 17 |
| `apps/workbench/src/lib/plugins/plugin-loader.ts` | 14 | 1 |
| `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts` | 13 | 0 |
| `packages/sdk/hush-ts/src/client.ts` | 12 | 1 |
| `packages/policy/clawdstrike-policy/src/engine.ts` | 0 | 12 |
| `packages/sdk/hush-ts/src/crypto/backend.ts` | 10 | 4 |
| `apps/workbench/src/features/findings/stores/finding-store.tsx` | 0 | 9 |
| `apps/workbench/src/features/fleet/use-fleet-connection.ts` | 0 | 8 |
| `packages/policy/clawdstrike-policy/src/policy/loader.ts` | 0 | 8 |
| `packages/policy/clawdstrike-policy/src/policy/validator.ts` | 0 | 8 |
| `apps/workbench/src/features/sentinels/stores/sentinel-store.tsx` | 0 | 7 |
| `packages/sdk/hush-ts/src/siem/exporters/sumo-logic.ts` | 6 | 5 |

### Hardest-to-fix categories (preview)

1. **Hand-rolled policy YAML validators** (~110 `as any`) — replacing requires picking a schema lib and migrating 1000+ lines of validator code.
2. **WASM module untyped bindings** (~25 `: any`) — requires `wasm-bindgen`-generated `.d.ts` to be regenerated and re-published.
3. **Vercel-AI middleware vendor type gap** (~52) — requires lifting types from `ai` package internals or pinning to a typed wrapper.

## Per-Package Counts

| Package / app | `any` decls | `as any` | Total | LOC | Hits / 1k LOC |
|---|---:|---:|---:|---:|---:|
| `packages/adapters/clawdstrike-openclaw` | 2 | 74 | 76 | 12,515 | 6.1 |
| `packages/adapters/clawdstrike-vercel-ai` | 29 | 28 | 57 | 1,578 | **36.1** |
| `packages/policy/clawdstrike-policy` | 3 | 69 | 72 | 4,010 | 18.0 |
| `packages/sdk/hush-ts` | 40 | 17 | 57 | 12,570 | 4.5 |
| `packages/adapters/clawdstrike-langchain` | 2 | 1 | 3 | 778 | 3.9 |
| `packages/sdk/clawdstrike-hunt` | 4 | 0 | 4 | 4,116 | 1.0 |
| `packages/swarm-engine` | 1 | 0 | 1 | 6,923 | 0.1 |
| `packages/sdk/plugin-sdk` | 1 | 0 | 1 | 1,559 | 0.6 |
| `packages/adapters/clawdstrike-adapter-core` | 0 | 0 | 0 | 7,385 | 0.0 |
| `packages/adapters/clawdstrike-origin-core` | 0 | 0 | 0 | 545 | 0.0 |
| `packages/adapters/clawdstrike-broker-client` | 0 | 0 | 0 | 486 | 0.0 |
| `packages/adapters/clawdstrike-openai` / `claude` / `opencode` | 0 | 0 | 0 | ~440 | 0.0 |
| `packages/adapters/clawdstrike-engine-adaptive` / `hush-cli-engine` / `hushd-engine` | 0 | 0 | 0 | 752 | 0.0 |
| `apps/workbench/src` | 39 | 36 | 75 | 225,629 | 0.33 |
| `apps/control-console/src` | 0 | 0 | 0 | 24,157 | **0.0** |
| `apps/academy/src` | 1 | 0 | 1 | 6,362 | 0.16 |
| **Totals** | **122** | **225** | **347** | ~321k | 1.08 |

> `clawdstrike-vercel-ai` is the worst offender by density by an order of magnitude — 36 hits / 1k LOC vs the next-densest at 18.

## Category Inventory

### 1. Hand-rolled YAML / policy schema validators using `as any`-narrowing

**Count:** ~125 (dominant single category, ≈36% of all hits)

**Top 5 locations:**
- `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts:190` — `const mode = (p.egress as any).mode;`
- `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts:297-302` — `ensureBoolean((p.guards as any).forbidden_path, …)` × 6 in a block
- `packages/policy/clawdstrike-policy/src/policy/legacy.ts:53` — `if (isPlainObject(legacy.guards) && Array.isArray((legacy.guards as any).custom))`
- `packages/policy/clawdstrike-policy/src/plugins/manifest.ts:80` — `const level = (trust as any).level;`
- `packages/policy/clawdstrike-policy/src/policy/validator.ts:80` — `validateSpiderSense((p.guards as any).spider_sense, …)`

**Root cause:** these files implement validators by hand on top of a `Policy` / `PluginManifest` type that mostly declares the *valid* shape. To read fields off an `unknown`-shaped input the code reaches through `(x as any).field`. There is no runtime-validating schema library in use — `validateCanonicalPolicy(policy as any)` (validator.ts:168) is itself the legacy bridge.

**Remediation effort:** **large.** Migrate to `zod` (or `valibot` for size) and let `z.infer` provide types. Plan:
1. Define `policySchema = z.object({...})` (1–2 days; the validators encode the schema implicitly).
2. Replace bodies of `validateCanonicalPolicy`, `validatePolicy`, `parseManifest`, `legacyToCanonical` with `schema.safeParse(raw)`.
3. Re-emit `Policy`, `PluginManifest` as `z.infer<typeof …Schema>`.

Roughly 110 of the 225 `as any` casts evaporate. Estimate 4–6 days of work, plus regression tests against existing policy fixtures (rulesets/*.yaml round-trips).

**Concrete next step:** add `zod` to `packages/policy/clawdstrike-policy` and `packages/adapters/clawdstrike-openclaw`; write a `policy-schema.ts` mirroring schema v1.5.0; replace the three validator entry points one at a time, retaining the same error message format.

---

### 2. Vendor-SDK type gaps (Vercel AI middleware)

**Count:** ~52 (29 decl + 23 casts) — almost entirely in one file.

**Top 5 locations:**
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:250` — `const fn = (wrapped as any)[prop] as (...innerArgs: unknown[]) => unknown;`
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:276-277` — `doGenerate: () => Promise<any>; params: any;`
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:323` — `wrapStream: async ({ doStream, params }: { doStream: () => Promise<any>; params: any }) => {`
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:846-941` — `prompt: any[]` / `(msg as any).role` / `(msg as any).content` shape-drilling on Vercel AI prompt messages (≈25 hits in 100 lines)
- `packages/adapters/clawdstrike-vercel-ai/src/react/use-secure-chat.ts:91, 98` — `onToolCall?.({ toolCall } as any)` / `secureToolCall as any`

**Root cause:** the middleware wraps the `LanguageModelV1` / `LanguageModelV2` interface from the `ai` package. Those types ship but are intentionally generic (`prompt` is a tagged union the user is expected to discriminate). The author chose `any` rather than re-declaring the discriminant. Tool-call middleware in `react/use-secure-chat.ts` hits a real Vercel AI typing gap (`onToolCall` generic).

**Remediation effort:** **medium.** Import `LanguageModelV1Prompt`, `LanguageModelV1Message`, `LanguageModelV1StreamPart` from `ai` (or `@ai-sdk/provider`). The prompt-walking helpers (lines 846–1141) can all be re-typed as `LanguageModelV1Message[]` with a discriminated union switch. The 7 `as any` for `wrapLanguageModel` plumbing remain unavoidable unless we pin a specific `ai` version.

**Concrete next step:** add `@ai-sdk/provider` to deps (already transitive), rewrite the `extractMessageText` / `applyTextToPromptMessage` / `isPromptMessageTextful` helper trio with typed discriminants — that alone kills 16 of the 29 `: any` decls.

---

### 3. WASM module untyped bindings

**Count:** ~25 (predominantly `let inner: any` / `getWasmModule(): any`)

**Top 5 locations:**
- `packages/sdk/hush-ts/src/crypto/backend.ts:35` — `let wasmModule: any = null;`
- `packages/sdk/hush-ts/src/crypto/backend.ts:43` — `export function getWasmModule(): any {`
- `packages/sdk/hush-ts/src/policy-lab.ts:39, 42, 47` — `private readonly inner: any; … static async getWasmModule(): Promise<any>`
- `packages/sdk/hush-ts/src/instruction-hierarchy.ts:118` — `private inner: any;`
- `packages/sdk/hush-ts/src/{jailbreak,spider-sense,output-sanitizer}.ts:98/42/117` — `private readonly inner: any;` (×3)

**Root cause:** the `hush-wasm` crate ships pre-built `pkg/` artifacts but the TS SDK loads them through dynamic `import()` and aliases the module as `any` rather than importing `wasm-bindgen`'s generated `.d.ts`. The MEMORY note ("WASM `generate_keypair()` returns JS Map not plain object") confirms the team is hand-shimming.

**Remediation effort:** **small** for the typing side, **medium** for the loader plumbing.

1. Have `hush-wasm/build.sh` emit and publish the `pkg-web/hush_wasm.d.ts` + `pkg-node/`.
2. Re-export those types as `import type { Hash, ... } from '@clawdstrike/wasm';`.
3. Replace each `private inner: any` with `private inner: WasmJailbreakDetector` (etc.).

The runtime loader will still need a single `as unknown as WasmModule` at the dynamic-import boundary (≈3 places) but everything downstream becomes typed.

**Concrete next step:** in `packages/sdk/hush-ts/src/crypto/backend.ts` define `interface HushWasmModule { hash_sha256_bytes(b: Uint8Array): Uint8Array; ed25519_generate_keypair(): unknown; … }` — even hand-written, this kills ~25 `any` decls.

---

### 4. HTTP client typed-as-any (Promise<any> / body: any)

**Count:** ~22

**Top 5 locations:**
- `packages/sdk/hush-ts/src/client.ts:92` — `Promise<any[]>` (`listCertifications`)
- `packages/sdk/hush-ts/src/client.ts:102-108` — `getCertification(): Promise<any>; verifyCertification(id, body?: any): Promise<any>`
- `packages/sdk/hush-ts/src/client.ts:116-136` — `createCertification(body: any)` / `exportEvidence(…, body: any)` / `getEvidenceExport(): Promise<any>`
- `packages/sdk/hush-ts/src/siem/exporters/sumo-logic.ts:87` — `body: payload as any` / `JSON.parse(JSON.stringify(event)) as any` (lines 87, 127)
- `packages/sdk/hush-ts/src/siem/exporters/webhooks.ts:291, 309, 365` — `body: body as any; renderTemplate(template, event as any); let cur: any = obj;`

**Root cause:** the certification / evidence / SIEM exporter APIs were stubbed with `any` and never tightened. The OpenAPI/schema for these endpoints exists in the Rust side (`hushd` route definitions) but no codegen pipeline runs into TS.

**Remediation effort:** **small** if you accept hand-written types; **medium** if you wire `openapi-typescript` against the hushd OpenAPI spec.

**Concrete next step:** define `interface Certification { … }`, `interface EvidenceExport { … }` from the Rust structs (Cargo `crates/hush-certification/src/*` and `crates/hushd/src/api/*`). Drop into `packages/sdk/hush-ts/src/types/certifications.ts`. Replace `Promise<any>` → `Promise<Certification>` (etc.).

---

### 5. Workbench store update casts (`state.x = result as any`)

**Count:** ~30 (`findings/stores`: 9, `sentinels/stores`: 7, `fleet/use-fleet-connection`: 8, `operator/stores`: 4, plus tail)

**Top 5 locations:**
- `apps/workbench/src/features/findings/stores/finding-store.tsx:220, 233, 246, 259, 275, 289, 304, 330, 345` — `state.findings[idx] = result as any;`
- `apps/workbench/src/features/sentinels/stores/sentinel-store.tsx:166, 176, 201, 216, 231, 256, 269` — `state.sentinels[idx] = updated as any;`
- `apps/workbench/src/features/fleet/use-fleet-connection.ts:155, 271, 298, 340, 370, 422, 443, 509` — `actionType: check.action_type as any` / `state.connection = redactFleetConnection(connected) as any;`
- `apps/workbench/src/features/operator/stores/operator-store.tsx:266, 276, 295, 368` — `state.currentOperator = operator as any;`
- `apps/workbench/src/components/workbench/sentinel-swarm-pages.tsx:591` — `} as any);`

**Root cause:** the store types (Finding / Sentinel / Operator / FleetConnection) are a mix of API DTOs and view-model objects; the engine/API returns one shape and the immer-style mutation in the store expects the other. Rather than introduce a `toViewModel(…)` mapping the authors `as any` the assignment. Found in stores that were rewritten in the workbench Phase B (Zustand multi-policy-store decomposition).

**Remediation effort:** **small.** Pattern is uniform: introduce a `mapApiFinding(apiFinding): Finding` mapper and the casts disappear.

**Concrete next step:** in each store, define `toX(…)` conversion functions at the top; replace each `state.x[idx] = result as any` with `state.x[idx] = toFinding(result)`.

---

### 6. Internal-event-bus untyped handlers (`(event: any) =>`)

**Count:** ~16 (one file dominates)

**Top 5 locations:**
- `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts:299, 326, 344, 360` — `events.on("agent.spawned", (event: any) => { … })` × 4
- `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts:377, 423, 438, 494, 507` — `events.on("task.*", (event: any) => {…})` × 5
- `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts:520, 598, 604` — `events.on("guard.evaluated"|"topology.*", (event: any) => {…})`
- `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts:565` — `(event.result?.guardResults ?? []).map((g: any) => ({…}))`
- `packages/swarm-engine/src/events.ts:32` — `Array<{ handler: (data: any) => void; listener: EventListener }>`

**Root cause:** `@clawdstrike/swarm-engine` (`packages/swarm-engine/src/events.ts`) declares the event bus as `(data: any) => void` — there is no event-name → payload type map. The consumer (`use-engine-board-bridge.ts`) cannot do better than `any`.

**Remediation effort:** **small at the source**, but cascading.

1. In `packages/swarm-engine/src/events.ts` define `interface SwarmEventMap { 'agent.spawned': AgentSpawnedEvent; 'task.created': TaskCreatedEvent; … }`.
2. Type `EventBus.on<K extends keyof SwarmEventMap>(k: K, h: (e: SwarmEventMap[K]) => void)`.
3. The 13 `(event: any)` casts in `use-engine-board-bridge.ts` evaporate.

**Concrete next step:** the engine emits these events — payload types likely already exist in `packages/swarm-engine/src/types.ts`. Wire them via a mapped type.

---

### 7. Plugin / view registry component-type wildcards

**Count:** ~14 (concentrated)

**Top 5 locations:**
- `apps/workbench/src/lib/plugins/plugin-loader.ts:141-167` — `register(type: string, component: ComponentType<any>): Disposable;` and 6 nearby variations
- `apps/workbench/src/lib/plugins/plugin-loader.ts:730, 778-802, 977` — `ComponentType<any> | (() => Promise<{ default: ComponentType<any> }>)`
- `apps/workbench/src/lib/plugins/plugin-loader.ts:1044` — `const sourceImpl = (mod.default ?? mod) as Record<string, any>;`
- `apps/workbench/src/lib/plugins/plugin-loader.ts:1048` — `const dispose = registerThreatIntelSource(registeredSource as any);`
- `packages/sdk/plugin-sdk/src/types.ts:?` — `(data: any) => void` plugin contract

**Root cause:** the plugin loader has to register components for arbitrary plugin-defined props. `ComponentType<any>` is the standard React escape hatch and not pathological — but **it should be `ComponentType<Record<string, unknown>>` or a generic plugin-prop type** indexed by plugin-type id.

**Remediation effort:** **medium.** Worth doing for the public-facing `register(...)` API (the plugin contract) but the internal storage `Map<string, ComponentType<any>>` can legitimately stay.

**Concrete next step:** define `interface PluginViewProps<T extends keyof PluginViewMap>` and a registry typed as `Map<T, ComponentType<PluginViewProps<T>>>`.

---

### 8. Crypto / WASM Uint8Array → BufferSource casts

**Count:** 3 (small but worth a note)

- `apps/workbench/src/features/swarm/swarm-protocol.ts:398` — `await crypto.subtle.digest("SHA-256", encoded as any)`
- `apps/workbench/src/features/swarm/swarm-blob-client.ts:253` — `await crypto.subtle.digest("SHA-256", bytes as any)`
- `apps/workbench/src/lib/workbench/speakeasy-bridge.ts:231` — same shape

**Root cause:** TypeScript's `lib.dom.d.ts` recently tightened `BufferSource` to disallow `Uint8Array<ArrayBufferLike>` in some lib targets (TS 5.7+). This is a known TS/DOM lib quirk.

**Remediation effort:** **trivial.** Use `new Uint8Array(encoded).buffer` or update `tsconfig` `lib` to a current target so `Uint8Array` is accepted.

---

### 9. NATS / dynamic-require shims

**Count:** ~4

- `packages/sdk/clawdstrike-hunt/src/watch.ts:44` — `let natsModule: any;`
- `packages/sdk/clawdstrike-hunt/src/stream.ts:32, 90` — `let natsModule: any;`
- `packages/sdk/hush-ts/src/crypto/backend.ts:96, 102, 112, 114, 130, 160, 237` — `let getBuiltin: any = (globalThis as any)?.process?.getBuiltinModule;` etc.

**Root cause:** dynamic optional `import('nats')` / `import('node:module')` bindings where the type isn't statically known and may not be installed.

**Remediation effort:** **trivial.** Import `import type { NatsConnection } from 'nats'` (peerDep) and cast once at the boundary; remove `any` from the variable declarations.

---

### 10. Threat-intel JSON response shapes

**Count:** ~8

- `packages/policy/clawdstrike-policy/src/guards/threat-intel/virustotal.ts:178, 185, 223` — `(event.data as any).contentHash; const data = event.data as any; let cur: any = value;`
- `packages/policy/clawdstrike-policy/src/guards/threat-intel/snyk.ts:125, 135, 152` — `const root = json as any; const data = event.data as any;`
- `packages/policy/clawdstrike-policy/src/guards/threat-intel/safe-browsing.ts:80` — `Array.isArray((resp.json as any)?.matches)`

**Root cause:** parsing third-party HTTP JSON responses with no schema. Mostly OK if narrowed immediately, but here it isn't.

**Remediation effort:** **trivial-to-small.** Each guard has a well-defined wire format (documented by the vendor). Add a `interface VirusTotalResponse { data: { attributes: {…} } }` and parse `resp.json` against it; reduces 5–8 `any` per guard.

---

### 11. Legitimate `any` (kept; mostly utility helpers)

**Count:** ~10

- `apps/workbench/src/lib/workbench/simulation-engine.ts:931, 944` — `(config: any, scenario: TestScenario) => GuardSimResult` and `config: any` — guard sim config is genuinely polymorphic (heterogeneous per-guard schemas). Could be `unknown` + per-guard cast.
- `apps/workbench/src/components/ui/moving-border.tsx:24, 29, 82, 84` — UI utility wrapping arbitrary `as` props (ShadCN/aceternity pattern; widely accepted).
- `apps/workbench/src/features/nexus/components/NexusForceCanvas.tsx:50, 57, 110` — `GraphMethods<any, any>` is the `react-force-graph` library's own typing limitation.
- `apps/workbench/src/lib/create-selectors.ts:11` — `(store.use as any)[k] = …` — Zustand `createSelectors` pattern, documented hack.
- `apps/workbench/src/features/observatory/components/world-canvas/SpiritResonanceConnections.tsx:33` — `(line.material as any).dashOffset` — three.js untyped material property.

**Root cause:** legitimate vendor / library typing gaps. The escape hatch is correct.

**Remediation:** **none recommended.** Mark with `// eslint-disable-next-line @typescript-eslint/no-explicit-any` plus a 1-line justification comment to make them explicit and grep-able.

---

### 12. Test-helper leaks into prod

**Count:** 3

- `packages/adapters/clawdstrike-openclaw/src/e2e/openclaw-e2e.ts:49, 55, 61` — `({ … } as any)) as PolicyCheckResult;`

These are in `src/e2e/` which is shipped as part of the package (not under `__tests__/`). Either move to `tests/` directory or type the inputs properly.

**Remediation:** **trivial.** Type the test event objects.

---

### 13. CUA hook side-channel marker

**Count:** 2

- `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/handler.ts:382` — `(event as any).__cuaBridgeEvaluated = true;`
- `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts:481` — `if ((event as any).__cuaBridgeEvaluated) return;`

**Root cause:** monkey-patching the event with a "I already evaluated this" flag.

**Remediation:** **trivial.** Use a `WeakSet<PolicyEvent>` instead of mutating the event.

---

## Quick Wins (immediate type wins)

These are the lowest-effort, highest-clarity wins. Together they kill **~85 hits** in roughly **1 day** of work.

1. **CUA evaluated-flag → WeakSet** (2 hits)
   - `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/handler.ts:382`
   - `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts:481`
2. **`BufferSource` casts in crypto.subtle.digest** (3 hits)
   - `apps/workbench/src/features/swarm/swarm-protocol.ts:398`
   - `apps/workbench/src/features/swarm/swarm-blob-client.ts:253`
   - `apps/workbench/src/lib/workbench/speakeasy-bridge.ts:231`
3. **Move e2e test helpers out of `src/`** (3 hits)
   - `packages/adapters/clawdstrike-openclaw/src/e2e/openclaw-e2e.ts:49,55,61`
4. **Type NATS dynamic imports** (4 hits)
   - `packages/sdk/clawdstrike-hunt/src/{watch,stream}.ts`
5. **Workbench store mapper functions** (~30 hits)
   - 5 stores, ~6 lines each — define `toFinding/toSentinel/toFleetAgent/toOperator` and replace `as any` assignments
6. **Swarm event-bus typed event map** (~14 hits)
   - `packages/swarm-engine/src/events.ts` → typed `on<K>(k: K, …)` overload kills all 13 hits in `use-engine-board-bridge.ts`
7. **Threat-intel response interfaces** (~8 hits)
   - `packages/policy/clawdstrike-policy/src/guards/threat-intel/{virustotal,snyk,safe-browsing}.ts`
8. **HTTP client return types in `hush-ts/src/client.ts`** (12 hits)
   - hand-roll `Certification`, `EvidenceExport` interfaces from Rust source-of-truth in `crates/hush-certification` and `crates/hushd/src/api/`
9. **Sumo / webhooks SIEM exporter body typing** (10 hits)
   - `packages/sdk/hush-ts/src/siem/exporters/{sumo-logic,webhooks}.ts` — `body: payload` once `payload` is `Record<string, unknown>` clears most casts

## Hard Cases (need design)

These can't be fixed by typing the obvious thing — they need a new dependency, a generated artifact, or an architectural decision.

### H1. Policy YAML validators (~125 hits)

**Blocking:** decision on schema library. The validators in `clawdstrike-openclaw/src/policy/validator.ts` (58 casts), `clawdstrike-policy/src/policy/legacy.ts` (17), `clawdstrike-policy/src/plugins/manifest.ts` (17), `clawdstrike-policy/src/engine.ts` (12), `clawdstrike-policy/src/policy/{validator,loader}.ts` (16) all walk `unknown`-shaped input with `as any`. None of them can be fixed individually because they share the same untyped substrate. Pick **zod** (well-known, large) or **valibot** (small but newer) — must be the same for both packages because they cross-reference.

**Files affected:**
- `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts`
- `packages/adapters/clawdstrike-openclaw/src/policy/loader.ts`
- `packages/policy/clawdstrike-policy/src/policy/{validator,loader,legacy}.ts`
- `packages/policy/clawdstrike-policy/src/engine.ts`
- `packages/policy/clawdstrike-policy/src/plugins/{manifest,loader}.ts`

**Estimated effort:** 4–6 days, plus regression suite against `rulesets/*.yaml` fixtures.

### H2. Vercel AI middleware vendor types (~52 hits)

**Blocking:** the `ai` package version is unpinned in places; `LanguageModelV1Prompt` vs `LanguageModelV2Prompt` discriminant shape varies between versions. Need to (a) pin a specific `@ai-sdk/provider` range and (b) port the prompt-walking helpers to that version's discriminated union. The 7 `as any` plumbing around `experimental_wrapLanguageModel` will remain because that fn signature is intentionally generic.

**Files affected:**
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts` (52)
- `packages/adapters/clawdstrike-vercel-ai/src/streaming-tool-guard.ts` (3)
- `packages/adapters/clawdstrike-vercel-ai/src/react/use-secure-chat.ts` (2)

**Estimated effort:** 2–3 days, blocking on confirming Vercel AI version target.

### H3. WASM module typing (~25 hits)

**Blocking:** `hush-wasm/build.sh` does not currently publish `.d.ts` for the consumer SDK to import. Either (a) publish wasm-bindgen's generated `.d.ts` as part of `@clawdstrike/wasm` or (b) define `interface HushWasmModule { … }` in the TS SDK manually.

**Files affected:** `packages/sdk/hush-ts/src/crypto/backend.ts` and all 5 detector files (`policy-lab`, `jailbreak`, `spider-sense`, `output-sanitizer`, `instruction-hierarchy`, `watermarking`, `certification-badge`).

**Decision needed:** option (a) is correct long-term but requires `hush-wasm/build.sh` work + publishing pipeline; option (b) is 30 minutes of typing but drifts from the Rust source of truth.

**Estimated effort:** option (a) 1 week with build-pipeline changes; option (b) 1 hour.

### H4. Plugin SDK component-prop variance

**Blocking:** the plugin contract publicly exposes `ComponentType<any>` because plugins define their own prop shapes at runtime. Tightening this requires either a registry of plugin types (closed-set) or generic-parameterized registration. Either has API-stability implications for external plugins.

**Files affected:** `apps/workbench/src/lib/plugins/plugin-loader.ts`, `packages/sdk/plugin-sdk/src/types.ts`.

**Estimated effort:** 2–3 days plus a public-API decision.

## Recommended Sequence

### Sprint 0 (≈1 day): Quick wins, no library decisions
- All 9 quick-wins above (~85 hits eliminated)
- Add `eslint-disable-next-line @typescript-eslint/no-explicit-any` with justification on the ~10 legitimate cases (#11)
- Net: **~95 hits gone**, 252 remaining

### Sprint 1 (≈3 days): WASM + HTTP client typing
- Resolve H3 with option (b) hand-written `HushWasmModule` interface as bridge (1 hour)
- Type all `hush-ts/src/client.ts` HTTP returns from Rust source-of-truth (1 day)
- Type Vercel AI middleware prompt-walking helpers via `@ai-sdk/provider` types (1 day)
- Net: **~80 more hits gone**, ~170 remaining

### Sprint 2 (≈5 days): Policy schema migration (H1)
- Pick zod (recommended — larger ecosystem, generators exist)
- Migrate `clawdstrike-policy` validators
- Migrate `clawdstrike-openclaw` validators
- Migrate `clawdstrike-policy` plugin manifest
- Net: **~125 more hits gone**, ~45 remaining

### Sprint 3 (≈2 days): Vendor-gap finalization
- Pin Vercel AI version, finish H2 (~10 unavoidable plumbing casts remain)
- Resolve plugin SDK component-prop variance (H4) with closed-set registry if scope permits
- Net: **~30 hits gone**, ~15 documented-and-justified casts remaining

### End state (target ~2 working weeks)

After the four sprints:
- Total `any` / `as any` hits in prod TS: **<20**, all annotated with eslint-disable comments referencing the architectural reason (vendor gap, dynamic import, three.js material, etc.).
- Add `"@typescript-eslint/no-explicit-any": "error"` to repo eslint config; pin `noImplicitAny: true` in all `tsconfig.json`s.
- `npx tsc --noUncheckedIndexedAccess --strict` runs clean on:
  - `packages/sdk/hush-ts` (currently 57 hits → ~5)
  - `packages/policy/clawdstrike-policy` (72 → 0)
  - `packages/adapters/clawdstrike-openclaw` (76 → 0)
  - `packages/adapters/clawdstrike-vercel-ai` (57 → ~10 documented)
  - `apps/workbench/src` (75 → ~5 documented)

**Total estimated effort:** 11 working days.

---

*Audit by claude-opus-4-7[1m], wave-3 D-stream, 2026-05-23.*
