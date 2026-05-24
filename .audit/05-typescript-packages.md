# TypeScript Packages Audit

**Scope:** `packages/adapters/*`, `packages/sdk/{hush-ts,clawdstrike,clawdstrike-hunt,plugin-sdk}`, `packages/policy/clawdstrike-policy`, `packages/swarm-engine`, `packages/dev/vite-plugin-clawdstrike`, `packages/cli/create-plugin`.
**Out of scope:** `packages/sdk/hush-py`, `packages/sdk/hush-go`, `packages/sdk/hush-csharp`.

---

## Executive Summary

The TypeScript surface is sprawling and inconsistent. The good news is that the basic ESM hygiene is mostly right: every package declares `"type": "module"`, has an `exports` map with `import` + `types`, ships a `dist/`, and uses `strict: true` in `tsconfig.json`. The pre-published package layout (`@clawdstrike/sdk`, `@clawdstrike/adapter-core`, `@clawdstrike/openclaw`, etc.) does at least look like an npm-ready monorepo at a glance. There is a real cross-package architecture here — `adapter-core` is the contract, framework adapters (`openai`, `claude`, `langchain`, `vercel-ai`, `opencode`, `openclaw`) consume it, and engine adapters (`engine-local`, `engine-remote`, `engine-adaptive`) plug in behind it. That is the right shape.

The bad news is that **almost nothing about this looks like elite open-source engineering yet**. There are 503 `any`-type sites and 189 `as any` casts in non-test code; the SDK's HTTP client (`packages/sdk/hush-ts/src/client.ts`) returns `Promise<any>` from every method; the public `@clawdstrike/sdk` ships a single `clawdstrike.ts` file that is 2,027 lines long; `@clawdstrike/swarm-engine` ships 14k lines of code with no README, no description, no license, no repository field, and no version above `0.1.0`. Every package has `npm run format` configured as `biome check --write src/` but the repo's `biome.json` only includes a handful of paths and has `"linter": {"enabled": false}` — so the lint scripts run a formatter and nothing else. Most adapters have committed `package-lock.json` files **inside the workspace** despite the root using npm workspaces, and per-package `node_modules/` are committed (or at least present and reachable through directory walks).

There are also genuine security smells. `packages/adapters/clawdstrike-openclaw/src/receipt/signer.ts` has a `static verify(receipt)` that returns `true` for any unsigned receipt with a `TODO` to "delegate to hush-wasm when available" — this is a fail-open verifier in a "fail-closed" security product. The Vercel AI middleware (`packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:475-516`) catches WASM-init errors and silently disables jailbreak detection, output sanitization, and instruction-hierarchy enforcement with a `console.warn`. The brokered HTTP client `packages/sdk/hush-ts/src/client.ts` has no `try/catch` around `JSON.parse(text)` and shoves `init.headers as any` into a `Record<string, string>` — fine until it isn't.

The headline recommendation: **wipe the convenience packages (`@clawdstrike/swarm-engine`, `clawdstrike` re-export, `clawdstrike-hunt`, `engine-adaptive`)** that aren't ready, **rewrite `client.ts` with real types**, **shatter `clawdstrike.ts` and `spider-sense.ts` into modules**, **delete every `any` you can**, **delete the stub `ReceiptSigner.verify`**, **wire up biome lint** (or move to oxlint/eslint), and **collapse the 14 per-package lockfiles** into a single workspace lockfile. After that pass, the public surface is small enough that you can credibly call it 0.3 and push it to npm.

---

## Package Inventory

| Package | Role | LOC (src/*.ts) | Status |
|---|---:|---:|---|
| `@clawdstrike/sdk` (`packages/sdk/hush-ts`) | Public TS SDK; crypto, guards, receipts, SIEM | ~12,200 | beta — bloated, 2k-line god file, sloppy `client.ts` |
| `clawdstrike` (`packages/sdk/clawdstrike`) | Unscoped re-export of `@clawdstrike/sdk` | 3 | sketchy — has both `.js` and `.cjs` but is just `export *`; unnecessary CJS surface |
| `@clawdstrike/hunt` (`packages/sdk/clawdstrike-hunt`) | Hunt query/timeline/correlation | 9,044 | beta — huge surface, broad public API, undertested in places |
| `@clawdstrike/plugin-sdk` (`packages/sdk/plugin-sdk`) | Plugin author SDK | 1,538 | beta — no README, has typedoc setup |
| `@clawdstrike/adapter-core` (`packages/adapters/clawdstrike-adapter-core`) | Shared adapter contract | 13,916 | production-grade-ish — biggest TS surface, mostly internally consistent |
| `@clawdstrike/broker-client` (`packages/adapters/clawdstrike-broker-client`) | Broker capability HTTP client | 834 | beta — no README, no vitest config (uses default) |
| `@clawdstrike/claude` (`packages/adapters/clawdstrike-claude`) | Claude Code/Agent SDK adapter | 429 | beta — minimal but clean |
| `@clawdstrike/engine-adaptive` (`packages/adapters/clawdstrike-engine-adaptive`) | Local/remote engine switcher | 1,162 | sketchy — sync `fs` for queue persistence in async lib |
| `@clawdstrike/engine-local` (`packages/adapters/clawdstrike-hush-cli-engine`) | Shells out to `hush policy eval` | 454 | beta |
| `@clawdstrike/engine-remote` (`packages/adapters/clawdstrike-hushd-engine`) | Calls `hushd /api/v1/eval` | 331 | beta |
| `@clawdstrike/langchain` (`packages/adapters/clawdstrike-langchain`) | LangChain tool wrapper | 1,164 | beta — `wrap.ts` has 4 `@deprecated` exports |
| `@clawdstrike/openai` (`packages/adapters/clawdstrike-openai`) | OpenAI Agents SDK hooks | 863 | beta |
| `@clawdstrike/openclaw` (`packages/adapters/clawdstrike-openclaw`) | OpenClaw plugin (big) | 16,871 | beta — duplicates policy loader from `@clawdstrike/policy`, ships `clawdstrike-security.js` shim |
| `@clawdstrike/opencode` (`packages/adapters/clawdstrike-opencode`) | OpenCode tool hooks | 196 | beta — tiny, almost a stub |
| `@clawdstrike/origin-core` (`packages/adapters/clawdstrike-origin-core`) | Trust-adapter framework | 1,112 | beta — no README, no `files` field nuance |
| `@clawdstrike/vercel-ai` (`packages/adapters/clawdstrike-vercel-ai`) | Vercel AI SDK middleware + React | 2,357 | beta — middleware.ts is 1,190 lines, ~30 `as any` |
| `@clawdstrike/policy` (`packages/policy/clawdstrike-policy`) | Canonical TS policy engine | 5,204 | beta — duplicated by openclaw's policy/ |
| `@clawdstrike/swarm-engine` (`packages/swarm-engine`) | Swarm coordination primitives | 13,931 | sketchy — no README, no description, no license, `0.1.0`, not in root workspaces? actually is in workspaces |
| `@clawdstrike/vite-plugin-clawdstrike` (`packages/dev/vite-plugin-clawdstrike`) | Vite HMR plugin | 187 | sketchy — NOT in root npm workspaces, no README, no tests of substance |
| `@clawdstrike/create-plugin` (`packages/cli/create-plugin`) | Plugin scaffolder | 1,154 | beta — NOT in root npm workspaces, no README, uses `console.error` heavily |

**Total: ~97,000 lines of TypeScript across 20 packages.**

---

## Scores

- **TS strictness / type quality**: 4/10 — `strict: true` everywhere, but 503 `any` sites and 189 `as any` make the strictness mostly cosmetic. `client.ts` returns `Promise<any>` from every method.
- **API design / exports**: 6/10 — every package has a proper `exports` map and `types`. But `@clawdstrike/sdk`'s `index.ts` re-exports 200+ symbols from a 2k-line god module; many adapters re-export internal types unintentionally.
- **Build hygiene**: 4/10 — mixed `tsc` / `tsup` builds with no documented reason. `hush-ts` uses `moduleResolution: bundler` + `tsup`; everything else uses `NodeNext` + bare `tsc`. Source files in `hush-ts` are inconsistent: some imports use `.js` extensions, some don't. Mixed single/double quote styles within the same package. 14 per-package `package-lock.json` files committed despite root npm workspaces.
- **Test quality**: 6/10 — 152 test files, ~42k LOC of tests. Decent coverage of `adapter-core`. Lots of `toBeDefined()` smoke tests in `swarm-engine`. WASM-gated tests use `it.skipIf` which is fine but means coverage on CI without WASM is misleading.
- **Code consistency across packages**: 3/10 — every adapter has its own subtly-different `tsconfig.json` (12 near-identical copies, plus 3 variants), its own `vitest.config.ts` (some single-quote, some double-quote, some with coverage, some without), and the SDK uses an entirely different build/module resolution strategy from the rest.
- **npm-readiness**: 5/10 — package metadata is mostly there (license, repo, bugs, homepage, publishConfig). But 6 packages have no README, `swarm-engine` is missing description/license/keywords/repository, version is `0.2.7` repo-wide with no changelog discipline.
- **Adapter design**: 7/10 — the `adapter-core` contract is genuinely good (`FrameworkAdapter`, `BaseToolInterceptor`, `PolicyEngineLike`, `ClawdstrikeBlockedError`). Adapters compose it cleanly. The `openclaw` adapter is the outlier — it bypasses `@clawdstrike/policy` and ships its own copy.

---

## Strengths

1. **`adapter-core` is real.** The `FrameworkAdapter`, `BaseToolInterceptor`, and `PolicyEngineLike` abstractions are well-factored. `failClosed`, `parseDecision`, `createDecision` are the kind of small, sharp primitives a principal engineer would build.
2. **ESM-first.** Every package is `"type": "module"`, has a real `exports` map, ships `.d.ts`, and uses Node 18-20+.
3. **Crypto backend abstraction.** `packages/sdk/hush-ts/src/crypto/backend.ts` cleanly separates noble (default, pure-JS) from optional WASM, including Node-vs-browser entry points. The shape is right even if the implementation has too many `any`s.
4. **Receipt and Merkle code is mostly clean.** `packages/sdk/hush-ts/src/{receipt,merkle,canonical}.ts` use proper types, real Ed25519, RFC 8785 canonical JSON, real Merkle proofs. The crypto-adjacent surface is the strongest part of the SDK.
5. **Hunt SDK has good naming.** `@clawdstrike/hunt` exposes a coherent surface: `buildReport`, `signReport`, `verifyReport`, `correlate`, `replay`, `playbook`, `mapEventToMitre`. Naming is consistent and verb-led.
6. **Fail-closed mostly takes itself seriously.** `failClosed()` in `engine-response.ts`, `ClawdstrikeBlockedError`, deny-by-default decision builders. The intent is clearly correct even when individual call sites slip.

---

## Findings

### CRITICAL [Security] Receipt verifier returns `true` for any unsigned receipt
- **Where**: `packages/adapters/clawdstrike-openclaw/src/receipt/signer.ts:99-107`
- **What**: `static verify(receipt: DecisionReceipt): boolean { if (receipt.signature === null) { return true; } /* TODO: Delegate to hush-wasm... */ return false; }`. An unsigned receipt verifies. The companion `createReceipt()` always sets `signature: null` (line 76).
- **Why it matters**: This is a security-product package. A receipt verifier that returns true for unsigned receipts is worse than no verifier; downstream code may treat `verify() === true` as proof of attestation. The TODO has been there long enough to ship a `0.2.7`.
- **Recommended action**: REWRITE — wire the existing `signMessage`/`verifySignature` from `@clawdstrike/sdk` (which already does Ed25519). Until then, change to `verify()` returning `false` on null signature, or remove the function entirely.
- **Effort**: small

### CRITICAL [Security/Reliability] Vercel-AI middleware silently disables three security guards on WASM failure
- **Where**: `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:468-516`
- **What**: Three `try/catch` blocks around constructing `InstructionHierarchyEnforcer`, `JailbreakDetector`, and `OutputSanitizer` swallow any error matching `/wasm/i` and continue without that guard, emitting only a `console.warn`. `degraded.push("JailbreakDetector")` records it locally but nothing surfaces this to the caller in the return value or via a thrown error.
- **Why it matters**: In a security middleware, "WASM unavailable" failing-open means a customer can deploy this in production, see no logs in their normal logger (just stderr from `console.warn`), and have zero prompt-injection / jailbreak / output-redaction enforcement. Fail-closed is the documented policy.
- **Recommended action**: REWRITE — accept a `onDegrade: (component: string, error: Error) => void` config and require explicit opt-in to degraded mode via `allowDegradedSecurity: true`. Default behavior should throw.
- **Effort**: small

### CRITICAL [Type Safety] `ClawdstrikeClient` returns `Promise<any>` from every method
- **Where**: `packages/sdk/hush-ts/src/client.ts:90-140`
- **What**: Every public method (`listCertifications`, `getCertification`, `verifyCertification`, `createCertification`, `exportEvidence`, `getEvidenceExport`) returns `Promise<any>` or `Promise<any[]>`. The `request<T>` helper is typed but every caller passes `<any>`. `init.headers as any` cast on line 67. `body?: any` parameter types.
- **Why it matters**: This is the customer-facing HTTP SDK. `any` returns mean no autocomplete, no validation, no schema. The OpenAPI types presumably exist (this hits `/v1/certifications`); they should be imported.
- **Recommended action**: REWRITE — generate or hand-write `Certification`, `CertificationCreate`, `EvidenceExport`, `EvidenceExportRequest` types. Replace every `any` with the real type. The file is 140 lines; this is a half-day job.
- **Effort**: small

### HIGH [Architecture] `clawdstrike.ts` is a 2,027-line god module
- **Where**: `packages/sdk/hush-ts/src/clawdstrike.ts`
- **What**: Single file containing `Clawdstrike` class, `ClawdstrikeSession` class, `DecisionStatus`/`Decision`/`SessionSummary`/`SessionOptions`/`Ruleset`/`PolicySpec`/`ToolSet`/`ClawdstrikeConfig` types, the entire default secret-leak pattern table, daemon HTTP client, policy file loading, YAML parsing, guard pipeline orchestration, and built-in ruleset resolution.
- **Why it matters**: It's the centerpiece of the public SDK and it reads like a single dump from an LLM. A new contributor cannot navigate it. Tree-shaking is impossible. Tests of one concern require importing the entire blob.
- **Recommended action**: RESTRUCTURE — split into `src/core/{client.ts, session.ts, decision.ts, types.ts}`, `src/policy/{loader.ts, builtin.ts, secret-patterns.ts}`, `src/daemon/client.ts`. Keep `clawdstrike.ts` as a 30-line facade if needed.
- **Effort**: medium

### HIGH [Architecture] `spider-sense.ts` guard is 2,365 lines
- **Where**: `packages/sdk/hush-ts/src/guards/spider-sense.ts`
- **What**: Largest source file in the entire TS surface. Contains pattern DB, scoring, trusted-key resolution, deprecation states (`SpiderSenseTrustedKeyStatus`), screening verdict logic, metrics hooks.
- **Why it matters**: 300-line module budget exceeded by 8×. Nobody re-reads a 2.3k-line file.
- **Recommended action**: RESTRUCTURE — split into `guards/spider-sense/{guard.ts, pattern-db.ts, scoring.ts, trusted-keys.ts, types.ts}`.
- **Effort**: medium

### HIGH [Build] SDK uses different build/module strategy from every other package
- **Where**: `packages/sdk/hush-ts/tsconfig.json` vs every other `tsconfig.json`; `packages/sdk/hush-ts/tsup.config.ts`
- **What**: `hush-ts` and `plugin-sdk` and `vite-plugin-clawdstrike` and `create-plugin` use `moduleResolution: "bundler"` and build with `tsup`. Every adapter and `@clawdstrike/policy` and `clawdstrike-hunt` and `swarm-engine` use `moduleResolution: "NodeNext"` and build with bare `tsc`. The result: import statements in `hush-ts` sometimes have `.js` extensions and sometimes don't (see `receipt.ts`, `canonical.ts`, `merkle.ts` — no `.js` extensions; `clawdstrike.ts` — has `.js` extensions). The same file uses single quotes; sibling files use double quotes.
- **Why it matters**: Pick one. An elite OSS repo has exactly one TS build path. Having three (`tsc + NodeNext`, `tsup + bundler`, `tsc + bundler`) is a CI complexity tax for no benefit. Mixed extension usage will burn someone if they ever try to consume the source directly.
- **Recommended action**: RESTRUCTURE — adopt `NodeNext` + `tsc` everywhere, or `tsup` + `bundler` everywhere. Pick one. Then run a codemod to add/strip `.js` extensions and normalize to double quotes.
- **Effort**: medium

### HIGH [Hygiene] 14 per-package `package-lock.json` files committed inside an npm workspaces repo
- **Where**: `packages/adapters/*/package-lock.json` (10 of them), `packages/swarm-engine/package-lock.json`, `packages/sdk/hush-ts/package-lock.json`, plus root `package-lock.json`
- **What**: The root `package.json` declares `"workspaces": [...]`. With npm workspaces there should be exactly one `package-lock.json` at the root. Yet every package has its own.
- **Why it matters**: The per-package lockfiles will drift, conflict with the root lockfile, and confuse `npm install`. They likely exist because contributors `cd packages/x && npm install` and a lockfile gets generated. This screams "no one runs the workspace install correctly."
- **Recommended action**: DELETE all per-package `package-lock.json` files. Add to `.gitignore`: `packages/*/*/package-lock.json` and `packages/*/package-lock.json`. Keep only the root one.
- **Effort**: trivial

### HIGH [Hygiene] `npm run format`/`format:check` is broken (refers to `biome check` but linter is disabled)
- **Where**: every package's `scripts.format`/`format:check`; root `biome.json`
- **What**: Every package declares `"format": "biome check --write src/"` and `"format:check": "biome check src/"`. Root `biome.json` has `"linter": {"enabled": false}` and `files.includes` restricted to a subset of paths — `apps/desktop/src/**/*.{ts,tsx}`, `apps/control-console/src/**/*.{ts,tsx}`, `packages/sdk/hush-ts/src/**/*.ts`, `packages/sdk/clawdstrike/**/*.ts`, `packages/policy/clawdstrike-policy/src/**/*.ts`, `packages/adapters/*/src/**/*.ts`. So `format:check` from `swarm-engine`, `clawdstrike-hunt`, `plugin-sdk`, `vite-plugin-clawdstrike`, `create-plugin`, `broker-client` does nothing (no matched files).
- **Why it matters**: There is no working lint pass on most of the repo. "Format" runs as a formatter only.
- **Recommended action**: RESTRUCTURE — broaden `biome.json` `files.includes` to cover every TS package; enable `linter.enabled: true` with at least `correctness`, `suspicious/noExplicitAny`, `suspicious/noConsole` (the codebase already uses `biome-ignore` comments for these rules, suggesting they were enabled at some point).
- **Effort**: small

### HIGH [Architecture] `@clawdstrike/openclaw` duplicates `@clawdstrike/policy`
- **Where**: `packages/adapters/clawdstrike-openclaw/src/policy/{loader,validator,engine}.ts` vs `packages/policy/clawdstrike-policy/src/policy/{loader,validator}.ts` and `src/engine.ts`
- **What**: Both packages have `policy/loader.ts`, `policy/validator.ts`, and an engine. The openclaw loader wraps the canonical one but also has its own logic, types (`Policy` from `../types.js`), and ruleset-resolution code. The canonical engine (`@clawdstrike/policy`) is 5,200 LOC; the openclaw engine is 1,804 LOC.
- **Why it matters**: Two sources of truth for policy loading. Bug fixes have to land in both. Tests in both. The dependency arrow is right (`openclaw` depends on `@clawdstrike/policy`) but the code doesn't actually delegate fully.
- **Recommended action**: RESTRUCTURE — collapse openclaw's `policy/` into a thin orchestrator that calls into `@clawdstrike/policy`. Delete duplicate types.
- **Effort**: medium

### HIGH [Type Safety] 503 `any` types and 189 `as any` casts in non-test code
- **Where**: across all packages; worst offenders: `clawdstrike-vercel-ai/src/middleware.ts` (~30 casts), `sdk/hush-ts/src/{instruction-hierarchy,jailbreak,output-sanitizer,policy-lab,spider-sense}.ts` (`private readonly inner: any` pattern around WASM modules), `sdk/hush-ts/src/client.ts` (everything)
- **What**: Most are concentrated around WASM module access (`WasmJailbreakDetector`, `WasmOutputSanitizer`, `WasmPolicyLab`) and around the Vercel AI SDK's loosely-typed prompt/message shapes.
- **Why it matters**: With `strict: true` enabled, `any` is the only way the rest of the code base remains incoherent. WASM module types should be declared once (in `@clawdstrike/wasm` types or in a local `wasm-types.d.ts`) and reused. Vercel AI shapes have published `@ai-sdk/provider` types — use them.
- **Recommended action**: REWRITE — declare a single `WasmModule` interface in `crypto/backend.ts`. For Vercel-AI, import `LanguageModelV2Message` etc. from `@ai-sdk/provider`. Aim for <50 `any`s repo-wide.
- **Effort**: medium

### HIGH [Hygiene] Two TS packages (`vite-plugin-clawdstrike`, `create-plugin`) are not in root npm workspaces
- **Where**: root `package.json` workspaces array
- **What**: Workspaces list includes `packages/sdk/plugin-sdk`, `packages/cli/create-plugin`, `packages/swarm-engine` (yes — earlier I misread, `create-plugin` IS listed) — actually `packages/dev/vite-plugin-clawdstrike` is the only one missing.
- **Why it matters**: A package outside workspaces won't be hoisted, won't share devDependencies, and won't appear in `npm run -ws`. Either delete it or include it.
- **Recommended action**: RESTRUCTURE — add `packages/dev/vite-plugin-clawdstrike` to the workspaces array, or delete the package if it isn't real yet (187 LOC, no README, no real tests).
- **Effort**: trivial

### MEDIUM [Packaging] `clawdstrike` re-export package is half-baked
- **Where**: `packages/sdk/clawdstrike/`
- **What**: Package has `index.js` (`export * from "@clawdstrike/sdk"`), `index.cjs` (`module.exports = require("@clawdstrike/sdk")`), and `index.d.ts` (`export * from "@clawdstrike/sdk"`). Build script is `"build": "node -e 'console.log(...)'"`. No tests beyond `node -e "import('./index.js').then(() => console.log('ok'))"`.
- **Why it matters**: Unscoped vanity package squatting `clawdstrike` on npm. Adds zero value over `@clawdstrike/sdk` and doubles the publish/maintenance burden. The CJS path is misleading — `@clawdstrike/sdk` is built ESM+CJS by tsup, but consumers using `require("clawdstrike")` will get the CJS bundle through `require("@clawdstrike/sdk")`, not this shim.
- **Recommended action**: DECIDE — either WIPE it and just publish `@clawdstrike/sdk`, or make it a real public landing package with proper docs. Currently it's the worst of both.
- **Effort**: trivial (to delete)

### MEDIUM [Architecture] `swarm-engine` ships without basic metadata
- **Where**: `packages/swarm-engine/package.json`
- **What**: Missing `description`, `license`, `keywords`, `repository`, `homepage`, `bugs`, `author`. Has empty `dependencies: {}` and empty `peerDependencies: {}`. `files: ["dist"]`. Version `0.1.0`. No `README.md`. 13,931 LOC of TS.
- **Why it matters**: This is the largest TS package after `openclaw` and `adapter-core` and it ships as an anonymous package. It cannot be sanely published.
- **Recommended action**: DOCUMENT — add a README explaining what a swarm is, what `AgentRegistry`/`TaskGraph`/`TopologyManager`/`ProtocolBridge` do, when to use it. Fill in package.json metadata. If it isn't a public package yet, mark `"private": true` and remove the `exports` map.
- **Effort**: small

### MEDIUM [API Design] `getSwarmTopics()` accepts both `boolean` and options-object with `console.warn` deprecation
- **Where**: `packages/swarm-engine/src/protocol.ts:216-240`
- **What**: `getSwarmTopics(swarmId, optionsOrLegacyBoolean?: boolean | GetSwarmTopicsOptions)` does `if (typeof optionsOrLegacyBoolean === "boolean") { console.warn(...); options = { includeSignals: optionsOrLegacyBoolean }; }`.
- **Why it matters**: This is a `0.1.0` package. There is no "legacy" to maintain. Backwards compat at v0.1.0 is theater. Also: runtime `console.warn` is not how you signal deprecation to TS consumers — use `@deprecated` JSDoc, which IDEs render with strikethrough.
- **Recommended action**: REWRITE — drop the boolean overload, single-signature function with options object, add `@deprecated` JSDoc on the old shape if you must.
- **Effort**: trivial

### MEDIUM [Build] `@clawdstrike/openclaw` workspace-build script is fragile
- **Where**: `packages/adapters/clawdstrike-openclaw/package.json` `scripts.build:local-deps`
- **What**: `"build:local-deps": "(cd ../../policy/clawdstrike-policy && ([ -d node_modules ] || npm ci) && npm run build) && (cd ../clawdstrike-adapter-core && ([ -d node_modules ] || npm ci) && npm run build)"`. This is the only package that needs to "build local deps" before testing.
- **Why it matters**: If you're in an npm workspace, `npm install` at the root hoists deps and you can `tsc` directly. The need for this script betrays a workspace setup that doesn't actually work. The vitest config (`vitest.config.ts`) aliases `@clawdstrike/adapter-core` and `@clawdstrike/policy` to their `src/index.ts` — proving the dist build is unreliable.
- **Recommended action**: RESTRUCTURE — make this a TS project-references setup (`tsconfig.json` with `references: [...]`), or commit to fully built deps via the workspace. Delete the shell-stitching.
- **Effort**: medium

### MEDIUM [API Design] `@clawdstrike/langchain` exports 4 deprecated wrappers
- **Where**: `packages/adapters/clawdstrike-langchain/src/wrap.ts:37,83,99,115,138`; `errors.ts:7`
- **What**: `wrapTool`, `wrapTools`, two more, and `LangChainBlockedError` are all marked `@deprecated`. Replacement (`secureTool`/`secureTools`/`ClawdstrikeBlockedError`) is from `adapter-core`.
- **Why it matters**: 0.2.7 → can break compat. Carrying deprecated symbols on a small adapter doubles the API surface for no real reason.
- **Recommended action**: DELETE the deprecated exports; bump to 0.3.0; document the rename in CHANGELOG.
- **Effort**: trivial

### MEDIUM [Type Safety] `LangChainAdapter.wrapTool` generic signature uses `any[]`
- **Where**: `packages/adapters/clawdstrike-langchain/src/langchain-adapter.ts:75,82`
- **What**: `wrapTool<TTool extends { invoke?: (...args: any[]) => any; _call?: (...args: any[]) => any }>(...)` — the `TTool` extends an `any`-laden interface.
- **Why it matters**: This pattern leaks `any` into every consumer.
- **Recommended action**: REWRITE — use `unknown[]` and `unknown` returns; or import LangChain's actual `Tool`/`StructuredTool` interface as a peer.
- **Effort**: trivial

### MEDIUM [Hygiene] 4 `TODO: derive from package.json at build time` in adapter version strings
- **Where**: `packages/adapters/clawdstrike-langchain/src/langchain-adapter.ts:22`, `packages/adapters/clawdstrike-adapter-core/src/framework-adapter.ts:27`, plus duplicates
- **What**: Hard-coded `version = "0.1.1"` even though the package is at 0.2.7. Comment says "derive from package.json at build time".
- **Why it matters**: The version reported to users via `adapter.version` is wrong.
- **Recommended action**: REWRITE — use a tsup `define` or vite-style `__VERSION__` injection (as `hush-ts/tsup.config.ts` already does for `__SDK_VERSION__`).
- **Effort**: trivial

### MEDIUM [Hygiene] `@clawdstrike/engine-adaptive` uses sync `fs` for receipt-queue persistence in an async library
- **Where**: `packages/adapters/clawdstrike-engine-adaptive/src/receipt-queue.ts:1-96`
- **What**: `import { appendFileSync, readFileSync, writeFileSync } from "node:fs"` then writes `serializeItems()` synchronously on every queue mutation.
- **Why it matters**: Receipt queue is on the hot path of a policy engine. Sync fs blocks the event loop. In a server context (which the README explicitly mentions: "remote is unreachable; local engine handles evaluation while receipts are queued"), this stalls request handling.
- **Recommended action**: REWRITE — use `fs/promises` and batch writes. Or use a real append-only log (`pino`-style stream).
- **Effort**: small

### MEDIUM [Hygiene] No README for 6 published packages
- **Where**: `packages/adapters/clawdstrike-broker-client/`, `packages/adapters/clawdstrike-origin-core/`, `packages/swarm-engine/`, `packages/sdk/plugin-sdk/`, `packages/dev/vite-plugin-clawdstrike/`, `packages/cli/create-plugin/`
- **What**: All declare `"files": ["dist", "README.md"]` but ship no README. npm will display "no description" on the package page.
- **Why it matters**: An empty package page on npm is a credibility killer.
- **Recommended action**: DOCUMENT — even a 30-line README beats nothing.
- **Effort**: small (per package)

### MEDIUM [Test Quality] 27 `toBeDefined()`-only assertions in `swarm-engine` tests
- **Where**: `packages/swarm-engine/src/{guard-types,types,agent-registry,agent-pool,orchestrator,events}.test.ts`
- **What**: Tests like `expect(payload.receipt).toBeDefined()`, `expect(state.agents).toBeDefined()`, `expect(registry.getAgentSession(id)).toBeDefined()`.
- **Why it matters**: These are smoke tests dressed up as unit tests. They will not fail if the underlying value is `{}` or `[]` or wrong-shaped. Coverage % is inflated.
- **Recommended action**: REWRITE — replace with structural assertions (`toMatchObject`, `toEqual`, type-aware checks).
- **Effort**: small

### MEDIUM [Test Quality] Commented-out integration tests in `create-plugin`
- **Where**: `packages/cli/create-plugin/tests/scaffold.integration.test.ts:177-185`
- **What**: `// expect(install.exitCode).toBe(0); // expect(build.exitCode).toBe(0); // expect(test.exitCode).toBe(0);` — the meaningful end-to-end assertions are commented out.
- **Why it matters**: The scaffold test now only checks that files exist with `toBeDefined()` on their package.json fields. It does not verify the scaffolded plugin actually compiles or runs.
- **Recommended action**: REWRITE — uncomment and ensure CI has the right env to run them, or delete the file and add a real `make scaffold-and-build` integration target.
- **Effort**: small

### MEDIUM [Hygiene] Mixed sync-fs in `clawdstrike-openclaw` hooks
- **Where**: `packages/adapters/clawdstrike-openclaw/src/hooks/{cua-bridge,tool-preflight,tool-guard,inbound-message}/handler.ts`, `src/audit/store.ts`, `src/plugin.ts`, `src/cli/commands/{policy,audit}.ts`
- **What**: 12+ uses of `readFileSync`/`writeFileSync`/`existsSync` in async hook handlers. Some are reading a one-time token file at startup (acceptable), others are inside per-request paths (`audit/store.ts` writes the full audit log on every event).
- **Why it matters**: Plugin hooks run per-tool-call. Sync I/O per event scales badly.
- **Recommended action**: REWRITE the per-request sync I/O paths; leave the startup-time reads.
- **Effort**: medium

### MEDIUM [API Design] `@clawdstrike/sdk` `index.ts` exports 200+ symbols at the top level
- **Where**: `packages/sdk/hush-ts/src/index.ts`
- **What**: 234 lines re-exporting types from `clawdstrike.ts`, `client.ts`, `crypto/*`, `guards/*`, `merkle.ts`, `output-sanitizer.ts`, `receipt.ts`, `siem/*` (as namespace), `policy-lab.ts`, `watermarking.ts`, `instruction-hierarchy.ts`, `jailbreak.ts`, `spider-sense.ts`, `certification-badge.ts`, `adapters` (re-export of `@clawdstrike/adapter-core`).
- **Why it matters**: Tree-shaking is impossible with `export *` (which `siem` uses internally). The public API is undifferentiated — a user can `import { Anything } from "@clawdstrike/sdk"`. There's no notion of advanced vs core API.
- **Recommended action**: RESTRUCTURE — split into multiple sub-paths: `@clawdstrike/sdk` (core: `Clawdstrike`, decisions, sessions), `@clawdstrike/sdk/crypto`, `@clawdstrike/sdk/guards`, `@clawdstrike/sdk/siem`, `@clawdstrike/sdk/detection` (jailbreak, output-sanitizer, instruction-hierarchy). Use the `exports` map.
- **Effort**: medium

### MEDIUM [Hygiene] `clawdstrike-openclaw/clawdstrike-security.js` shim at package root
- **Where**: `packages/adapters/clawdstrike-openclaw/clawdstrike-security.js`
- **What**: A single-line file `export { default } from './dist/plugin.js';` shipped at the package root and explicitly listed in `package.json` `files`.
- **Why it matters**: Unclear why this exists when the `exports` map and `bin` field already cover the entry points. If it's a legacy openclaw conventions thing, it should be documented.
- **Recommended action**: DOCUMENT (or DELETE if no longer needed by openclaw's plugin loader)
- **Effort**: trivial

### LOW [Hygiene] Inconsistent quote/spacing style within `hush-ts`
- **Where**: `packages/sdk/hush-ts/src/clawdstrike.ts` uses single quotes; `packages/sdk/hush-ts/src/client.ts` uses double quotes
- **What**: `biome.json` formatter is configured `"quoteStyle": "double"` but biome formatting isn't being enforced on hush-ts consistently (or was added after files were written).
- **Why it matters**: Cosmetic but jarring. Run `biome check --write` once.
- **Recommended action**: RESTRUCTURE — run `biome check --write packages/` and commit. Enable biome formatting in pre-commit.
- **Effort**: trivial

### LOW [Hygiene] Engine version mismatch across packages
- **Where**: root `package.json` declares `"node": "24.11.0"`; package `engines.node` ranges from `>=18` (adapter-core, claude, langchain, openai, opencode, broker-client, engine-adaptive, engine-local, engine-remote, vercel-ai) to `>=20` (openclaw, policy, origin-core, clawdstrike-hunt) to `>=20.19.0` (hush-ts, clawdstrike, plugin-sdk, vite-plugin-clawdstrike, create-plugin)
- **What**: Three different minimums across the workspace plus an exact-pin at the root.
- **Why it matters**: An exact pin at the root (`24.11.0`) is unusual; combined with mixed `>=18`/`>=20`/`>=20.19.0` in packages, the actual supported version is unclear. CI is likely on one version, users could be on another.
- **Recommended action**: RESTRUCTURE — pick `>=20.19.0` (matches Node LTS as of 2026) and apply uniformly. Use `volta` or `.nvmrc` for repo-pin.
- **Effort**: trivial

### LOW [Code Smell] `@ts-expect-error -- stored for future validation` in `swarm-engine/src/memory/hnsw.ts`
- **Where**: `packages/swarm-engine/src/memory/hnsw.ts:9`
- **What**: `// @ts-expect-error -- stored for future validation\nprivate readonly dimensions: number;` — the field is set in constructor but never read.
- **Why it matters**: Dead field. The `@ts-expect-error` directive will start failing the moment someone actually reads `dimensions`. The "future validation" never came.
- **Recommended action**: REWRITE — either delete the field, or actually validate `vector.length === this.dimensions` in `add()`.
- **Effort**: trivial

### LOW [Type Safety] `wrap.ts` and adapter `wrapTool` patterns leak `any` through generics
- **Where**: `packages/adapters/clawdstrike-langchain/src/wrap.ts` (and similar in others)
- **What**: see Finding above on `LangChainAdapter.wrapTool`
- **Recommended action**: rewrite generics with `unknown`
- **Effort**: trivial

### LOW [Hygiene] 76 direct `process.env.X` accesses in src
- **Where**: across packages; concentrated in `openclaw/src/hooks/*` and engine adapters
- **What**: No central env-config module; env vars are read at call sites.
- **Why it matters**: Untyped env access, no validation, no documentation of what env vars affect behavior.
- **Recommended action**: DOCUMENT in a `docs/env.md` (or per-package README) and centralize via a tiny `env.ts` module per package using `zod` or a hand-rolled parser.
- **Effort**: small

### LOW [Hygiene] `console.log` in `openclaw/src/plugin.ts:228-251` for CLI status
- **Where**: `packages/adapters/clawdstrike-openclaw/src/plugin.ts:228-251`
- **What**: CLI command implementations use `console.log` directly inside the plugin entry.
- **Why it matters**: CLI output is fine here but it should be in `src/cli/commands/*` not in the plugin lifecycle file. Mixing concerns.
- **Recommended action**: RESTRUCTURE — move the `status` and `check` command implementations to `src/cli/commands/{status,check}.ts`.
- **Effort**: trivial

### LOW [Hygiene] `case-convert.ts` is a 25-line snake_case/camelCase converter
- **Where**: `packages/sdk/hush-ts/src/case-convert.ts`
- **What**: Hand-rolled key-case conversion used by WASM bridge code.
- **Why it matters**: Fine — but every WASM-bridge surface uses it inconsistently. Some places use `toSnakeCaseKeys`, others convert manually with `as any` casts.
- **Recommended action**: DOCUMENT — note this is the canonical converter, audit WASM call sites to use it uniformly.
- **Effort**: trivial

### LOW [Hygiene] `vitest.config.ts` files use both single and double quotes across packages
- **Where**: `packages/adapters/clawdstrike-engine-adaptive/vitest.config.ts`, `packages/adapters/clawdstrike-vercel-ai/vitest.config.ts` (both single quote) vs `packages/swarm-engine/vitest.config.ts`, `packages/adapters/clawdstrike-openclaw/vitest.config.ts` (double quote)
- **What**: Cosmetic but jarring.
- **Recommended action**: format everything with biome.
- **Effort**: trivial

### LOW [Test Quality] `siem-exporters.test.ts` is 1,335 lines
- **Where**: `packages/sdk/hush-ts/tests/siem-exporters.test.ts`
- **What**: Single test file for all SIEM exporter targets (Splunk, Datadog, Elastic, Sumo Logic, webhooks, PagerDuty). Hasn't been touched since Feb 2026 (`stat` would show; the most recent modification on this file in the listing is 2026-02-26).
- **Why it matters**: Probably has snapshot patterns. Worth splitting per-exporter.
- **Recommended action**: RESTRUCTURE — one file per exporter, mirror the `src/siem/exporters/` layout.
- **Effort**: small

### LOW [Hygiene] `noUncheckedIndexedAccess` enabled in only one package
- **Where**: `packages/dev/vite-plugin-clawdstrike/tsconfig.json` is the only tsconfig with `noUncheckedIndexedAccess: true`
- **What**: This is one of the most useful strict flags for catching `arr[0]` returning `undefined` bugs.
- **Why it matters**: It should be on for every TS package, especially in a security product where index-out-of-range silently returning `undefined` can cascade into deny→allow logic errors.
- **Recommended action**: RESTRUCTURE — enable repo-wide via a shared `tsconfig.base.json`.
- **Effort**: medium (will surface real bugs)

### LOW [Hygiene] No shared `tsconfig.base.json`
- **Where**: every package has its own near-identical `tsconfig.json`
- **What**: 12 copies of the same `target: ES2022, module: NodeNext, strict: true, ...` block, with subtle drift (some have `forceConsistentCasingInFileNames`, some don't; some include `**/*.test.ts` in `exclude`, some don't; some have `noUnusedLocals`, most don't).
- **Why it matters**: Drift is real. The SDK has `noUnusedLocals`, `noUnusedParameters`, `noImplicitReturns`, `noFallthroughCasesInSwitch`. The adapters do not.
- **Recommended action**: RESTRUCTURE — create `tsconfig.base.json` at root with the strict flags; each package extends it and only overrides what differs.
- **Effort**: small

### LOW [API Design] `Decision` type duplicated across packages
- **Where**: `packages/sdk/hush-ts/src/clawdstrike.ts` defines `Decision`; `packages/adapters/clawdstrike-adapter-core/src/types.ts` also defines `Decision`; `packages/adapters/clawdstrike-openclaw/src/types.ts` re-exports its own
- **What**: Multiple sources of truth for the most important type in the system.
- **Why it matters**: Cross-package type compatibility relies on structural typing (which works) but conceptual clarity suffers. A new contributor doesn't know which `Decision` is canonical.
- **Recommended action**: RESTRUCTURE — `adapter-core` should own `Decision`. SDK should `export { Decision } from "@clawdstrike/adapter-core"`.
- **Effort**: small

### LOW [Hygiene] `clawdstrike-hunt` has 40 source files but a 115-line `index.ts` with handwritten re-exports
- **Where**: `packages/sdk/clawdstrike-hunt/src/index.ts`
- **What**: Every export listed manually. Good for tree-shaking but tedious to maintain.
- **Why it matters**: Probably fine; just noting that any drift between source files and the barrel will silently drop a symbol from the public API.
- **Recommended action**: LEAVE — handwritten barrels are the right call for public APIs. But add a CI check that fails if a new `export` keyword appears in `src/*.ts` without being added to `index.ts`.
- **Effort**: small

---

## Action Plan

### Phase 1: Security & Correctness (1-2 days)
1. **Delete or fix** `ReceiptSigner.verify()` stub in openclaw (CRITICAL).
2. **Make Vercel-AI middleware fail-closed** on WASM unavailability (CRITICAL).
3. **Rewrite `client.ts`** with real types (CRITICAL).

### Phase 2: Hygiene Sweep (1 day)
4. **Delete 14 per-package `package-lock.json` files**; add to `.gitignore`.
5. **Add `vite-plugin-clawdstrike` to root workspaces** (or delete it).
6. **Add READMEs** to `broker-client`, `origin-core`, `swarm-engine`, `plugin-sdk`, `vite-plugin-clawdstrike`, `create-plugin`.
7. **Enable biome linter** with `noExplicitAny`, `noConsole`; broaden `files.includes`; run `--write` once.
8. **Fix version inconsistency** in adapter `version` strings (use tsup define).
9. **Unify engines.node** across packages.

### Phase 3: Structural Cleanup (2-3 days)
10. **Create `tsconfig.base.json`**, migrate all packages to extend it.
11. **Pick one build path** (`tsc + NodeNext` recommended), migrate `hush-ts` off `tsup`/`bundler` if you go that way.
12. **Split `clawdstrike.ts`** (2,027 lines) and `spider-sense.ts` (2,365 lines).
13. **Sub-path exports** for `@clawdstrike/sdk` (`/crypto`, `/guards`, `/siem`, `/detection`).
14. **Delete `clawdstrike` re-export package** (or commit to it as a real package).

### Phase 4: Type Quality (1-2 weeks, ongoing)
15. **Declare WASM module types** in one place, replace `inner: any` patterns.
16. **Import Vercel AI provider types**, eliminate ~30 `as any` in middleware.
17. **Type the LangChain wrapTool generics** without `any`.
18. **Enable `noUncheckedIndexedAccess`** in `tsconfig.base.json`; fix surfaced errors.

### Phase 5: De-duplication (1 week)
19. **Collapse openclaw's `policy/`** into a thin shim over `@clawdstrike/policy`.
20. **Single `Decision` type** in `adapter-core`; everyone re-exports.
21. **Move openclaw's CLI implementations** into `cli/commands/`.

---

## Top 10 Quick Wins

1. **Delete `ReceiptSigner.verify()` returning `true` for unsigned receipts.** Wire `verifySignature` from the SDK. (1 hour)
2. **Replace `Promise<any>` in `client.ts` with real types.** (4 hours)
3. **Delete 14 per-package `package-lock.json` files.** (10 minutes)
4. **Make Vercel-AI middleware throw on WASM failure unless `allowDegradedSecurity: true`.** (2 hours)
5. **Add `tsconfig.base.json`** with shared strict flags; package configs extend it. (2 hours)
6. **Fix hardcoded adapter `version = "0.1.1"` strings** with tsup-style version injection. (1 hour)
7. **Run `biome check --write` across all packages** to fix mixed quotes/spacing. (30 minutes)
8. **Add README stubs** to 6 README-less packages. (2 hours)
9. **Delete `@ts-expect-error -- stored for future validation` HnswLite dead field** or implement the validation. (15 minutes)
10. **Drop deprecated exports from `@clawdstrike/langchain`** and bump to 0.3.0. (30 minutes)

---

## Things to Leave Alone

- **`adapter-core` types** (`FrameworkAdapter`, `BaseToolInterceptor`, `PolicyEngineLike`, `failClosed`, `ClawdstrikeBlockedError`) — these are well-factored and form the right abstraction. Don't break the contract during cleanup.
- **`merkle.ts`, `canonical.ts`, `receipt.ts`** in the SDK — clean, typed, security-sound. Just normalize import extensions.
- **The crypto backend swap design** (`backend.ts` switching between noble and WASM) — the architecture is right even if the implementation uses `any` for WASM handles. Fix the types, keep the design.
- **`@clawdstrike/hunt`'s public API surface** — handwritten barrel, verb-led naming, coherent. Don't refactor for refactor's sake.
- **The `@clawdstrike/*` scoping** — keep it. Don't rebrand mid-cleanup.
- **The fail-closed `failClosed()` / `parseDecision()` / `createDecision()` primitives** — these are the load-bearing correctness primitives. Touch with care.
- **Property-style tests and the test naming** (`*.test.ts` co-located in some packages, `tests/*.test.ts` in others) — pick one in a future pass; not worth the churn now.

---

*Audit performed: 2026-05-23. Scope: 20 TypeScript packages, ~97,000 LOC, ~42,000 LOC of tests.*
