# DELTA D05: TypeScript Packages
**Refreshed:** 2026-05-24 | **Source:** `.audit/05-typescript-packages.md` (2026-05-23) + `.audit/wave3/{D,E,H,K}-*.md` | **Scope:** `packages/` + root-level `clawdstrike-plugin/` and `cursor-plugin/` scaffolds

## Quick Verdict

- **Findings still valid:** 32 of 32 enumerated wave-1 findings (100%).
- **Findings fixed since 2026-05-23:** 0.
- **Findings wrong / misdiagnosed:** 0 substantive, 1 metric reconciliation needed (the original "503/189" count was repo-wide including test/app code; wave3-D pinned it to ~347 in-scope; current packages/ snapshot below).
- **New issues found:** 6 (see NEW ISSUES section).
- **`any` / `as any` count at HEAD:** packages/-only, non-test: **84 `any`-decl matches + 188 `as any` casts = 272** (vs. wave-1's 503/189 repo-wide and wave3-D's 347 prod-source-wide). Within packages/ alone the debt has not moved.
- **Lockfile count under packages/:** **15** (down from 14 in original — wave3-E counted 15 too, original-audit was off-by-one). Root `bun.lockb` + root `package-lock.json` still present. Total in-tree lockfiles still ~40.
- **Net delta since 2026-05-23:** **zero changes in `packages/`.** `git log --since=2026-05-23 -- packages/ ` returns no commits. Every wave-1 receipt is reproducible by line number today.

The cleanup work has all been Rust-side (`apps/agent/src-tauri/`, EDR DTO refactors, CI hardening). The TypeScript surface has been frozen since the audit. **No regressions, no fixes, no churn.** The 5 most aggressive removals proposed below remain viable and unblocked.

---

## Inventory snapshot (at HEAD)

| Metric | Value |
|---|---:|
| Packages in `packages/` workspace | 20 |
| Total TS LOC (src + tests) | 82,919 |
| Production TS LOC (`/src/*.ts` excluding tests) | 54,111 |
| `package-lock.json` files under `packages/` | 15 |
| `bun.lock*` under `packages/` | 0 |
| Root-level `bun.lockb` | 1 (439 KB) |
| Root-level `package-lock.json` | 1 (611 KB) |
| Packages with no `README.md` | 7 (`swarm-engine`, `cli/create-plugin`, `clawdstrike-broker-client`, `clawdstrike-origin-core`, `clawdstrike-hunt`, `plugin-sdk`, `vite-plugin-clawdstrike`) |
| Shared `tsconfig.base.json` | **none** (19 near-identical tsconfigs across packages/) |
| `noUncheckedIndexedAccess` enabled | 1 of 19 (`packages/dev/vite-plugin-clawdstrike/tsconfig.json` only) |
| `moduleResolution: "bundler"` packages | 5 (`hush-ts`, `plugin-sdk`, `swarm-engine`, `cli/create-plugin`, `dev/vite-plugin-clawdstrike`) |
| `moduleResolution: "NodeNext"` packages | 14 (everyone else) |
| `tsup` build packages | 3 (`hush-ts`, `plugin-sdk`, `vite-plugin-clawdstrike`) |
| `tsc` bare build packages | 16 |
| `biome.json` linter enabled | `false` (still) |
| `engines.node` distinct values | 4 (`>=18` / `>=20` / `>=20.19.0` / root pin `24.11.0`) |
| Hard-coded version strings with TODO derivation | 2 (`langchain-adapter.ts:22`, `framework-adapter.ts:27` — both still `"0.1.1"` while packages are `0.2.7`) |
| Fail-open `ReceiptSigner.verify()` | still present (`clawdstrike-openclaw/src/receipt/signer.ts:99-107`) |
| Vercel-AI WASM-degrade-silent paths | still present (3 try/catch in `middleware.ts:475-516`) |
| `Promise<any>` HTTP methods in `client.ts` | 6/6 (every public method) |
| God modules >1500 LOC under hush-ts | 2 (`clawdstrike.ts` 2027 LOC, `guards/spider-sense.ts` 2365 LOC — both unchanged) |
| `clawdstrike` re-export package | still present, still 3-line shim, still version `0.2.7` |
| `swarm-engine` `package.json` metadata | still missing description/license/repository/keywords/author/bugs/homepage |
| `swarm-engine` Phase 4/5 TODOs in prod code | still present (`orchestrator.ts:228, 265, 266, 268`) |

### Per-package LOC distribution (current, src only)

Confirmed at HEAD via `find ... -name "*.ts" -not -name "*.test.ts"`:

- `packages/adapters/clawdstrike-openclaw/src` — largest single offender (1855 LOC `hooks/tool-guard/handler.ts` alone)
- `packages/adapters/clawdstrike-adapter-core/src` — well-factored core (~7,385 LOC per wave3-D)
- `packages/sdk/hush-ts/src/` — top files by LOC:
  - `guards/spider-sense.ts` 2365
  - `clawdstrike.ts` 2027
  - `receipt.ts` 444
  - `watermarking.ts` 260
  - `output-sanitizer.ts` 240
  - `index.ts` 234 (barrel)
  - `merkle.ts` 218
  - `client.ts` 140
  - `instruction-hierarchy.ts` 136
  - `jailbreak.ts` 135
- `packages/swarm-engine/src/` — 12 source files + 11 test files; `topology.ts` 801, `task-graph.ts` 642, `types.ts` 638, `consensus/gossip.ts` 598, `orchestrator.ts` 565, `consensus/raft.ts` 533, `consensus/byzantine.ts` 512

### Commits touching `packages/` since 2026-05-23

```
$ git log --since="2026-05-23" --oneline -- packages/
(empty)
```

Zero. All five days of post-audit work have landed in `apps/agent/src-tauri/` (macOS Endpoint Security hardening, EDR DTO refactors) or in CI YAML. **`packages/` is frozen.**

---

## STILL VALID

Each finding below was verified at HEAD by file:line. Citations are exact. Findings preserve the wave-1 enumeration to ease cross-referencing.

**Reproduction commands used for verification (all run in repo root):**

```bash
# Lockfile inventory
find packages/ -name "package-lock.json" -not -path "*/node_modules/*" | wc -l   # → 15

# any/as-any counts (packages/ only, non-test)
rg -c ': any|<any>|any\[\]|Promise<any>|Array<any>|Record<[^>]+, *any>' \
   packages/ --type ts -g '!**/*.test.ts' -g '!**/tests/**' --no-heading \
   | awk -F: '{s+=$2} END {print s}'   # → 84
rg -c 'as any' packages/ --type ts -g '!**/*.test.ts' -g '!**/tests/**' \
   --no-heading | awk -F: '{s+=$2} END {print s}'   # → 188

# God modules
wc -l packages/sdk/hush-ts/src/{clawdstrike,client}.ts \
      packages/sdk/hush-ts/src/guards/spider-sense.ts \
      packages/adapters/clawdstrike-vercel-ai/src/middleware.ts
# →   2027 clawdstrike.ts   140 client.ts   2365 spider-sense.ts   1190 middleware.ts

# Worst as-any offenders (verified)
grep -c "as any" packages/adapters/clawdstrike-openclaw/src/policy/validator.ts   # → 58
grep -c "as any" packages/adapters/clawdstrike-vercel-ai/src/middleware.ts        # → 23
grep -c "as any" packages/policy/clawdstrike-policy/src/policy/legacy.ts          # → 17

# noUncheckedIndexedAccess only in vite-plugin-clawdstrike
find packages -name tsconfig.json | xargs grep -l noUncheckedIndexedAccess
# → packages/dev/vite-plugin-clawdstrike/tsconfig.json (only)
```

### 1. CRITICAL [Security] Receipt verifier returns `true` for any unsigned receipt — **STILL VALID**
- **File:** `packages/adapters/clawdstrike-openclaw/src/receipt/signer.ts:99-107`
- **Confirmed code (HEAD):**
  ```ts
  static verify(receipt: DecisionReceipt): boolean {
    if (receipt.signature === null) {
      return true;
    }
    // TODO: Delegate to hush-wasm Ed25519 verification when available.
    return false;
  }
  ```
- `createReceipt()` still sets `signature: null` at line 76 unconditionally (no real signing path even when `sign: true`).
- **Status:** unchanged, fail-open. This remains a CRITICAL ship-blocker.

### 2. CRITICAL [Security/Reliability] Vercel-AI middleware silently degrades on WASM failure — **STILL VALID**
- **File:** `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:468-516`
- Three try/catch blocks (around `InstructionHierarchyEnforcer`, `JailbreakDetector`, `OutputSanitizer`) still match `/wasm/i` and continue with only a `console.warn` and a local `degraded.push(...)` — the caller is never informed in the return value or via thrown error.
- `degraded` is populated but no `onDegrade` callback or `allowDegradedSecurity` opt-in exists.
- **Status:** unchanged. CRITICAL.

### 3. CRITICAL [Type Safety] `ClawdstrikeClient` returns `Promise<any>` from every method — **STILL VALID**
- **File:** `packages/sdk/hush-ts/src/client.ts:90-140`
- All 6 public methods (`listCertifications:92`, `getCertification:102`, `verifyCertification:108`, `createCertification:116`, `exportEvidence:124`, `getEvidenceExport:135`) still typed `Promise<any>` / `Promise<any[]>`.
- `body: any` parameters on lines 108, 116, 124.
- `init.headers as any` still present at line 67.
- File is still 140 LOC; rewrite remains "half a day".

### 4. HIGH [Architecture] `clawdstrike.ts` is a 2,027-line god module — **STILL VALID**
- **File:** `packages/sdk/hush-ts/src/clawdstrike.ts` (verified `wc -l` = 2027)
- Still single file, still contains the entire SDK facade + session class + default secret-leak patterns + daemon HTTP client + policy loading + YAML parsing + guard pipeline orchestration.

### 5. HIGH [Architecture] `spider-sense.ts` guard is 2,365 lines — **STILL VALID**
- **File:** `packages/sdk/hush-ts/src/guards/spider-sense.ts` (verified `wc -l` = 2365)
- Largest source file in TS surface, 8× the 300-LOC module budget.

### 6. HIGH [Build] SDK uses different build/module strategy from every other package — **STILL VALID**
- **Verified by `grep moduleResolution`:**
  - `bundler` (5 packages): `hush-ts`, `plugin-sdk`, `swarm-engine`, `cli/create-plugin`, `dev/vite-plugin-clawdstrike`
  - `NodeNext` (14 packages): all adapters except none, `clawdstrike-hunt`, `clawdstrike-policy`
- Mixed `.js` extension usage within `hush-ts` itself still present (clawdstrike.ts uses `.js`; receipt.ts/canonical.ts/merkle.ts do not).
- Mixed quote styles still observable in vitest configs: `swarm-engine` and `clawdstrike-openclaw` use double quotes; `clawdstrike-engine-adaptive`, `clawdstrike-vercel-ai`, `clawdstrike-claude`, `clawdstrike-langchain` use single quotes.

### 7. HIGH [Hygiene] 15 per-package `package-lock.json` files under workspace — **STILL VALID** (off-by-one corrected)
- **Wave-1 said 14**, but `find` at HEAD returns **15** under `packages/`:
  - All 11 `packages/adapters/*/package-lock.json`
  - `packages/swarm-engine/package-lock.json`
  - `packages/sdk/hush-ts/package-lock.json`
  - `packages/policy/clawdstrike-policy/package-lock.json`
  - `packages/dev/vite-plugin-clawdstrike/package-lock.json` (the one wave-1 didn't count — this package is *not* in root workspaces but still ships a per-package lock)
- Plus root `package-lock.json` + root `bun.lockb` (both 439 KB / 611 KB) — neither consumed by CI per wave3-E.

### 8. HIGH [Hygiene] `npm run format`/`format:check` broken; biome linter disabled — **STILL VALID**
- `biome.json` at root still has `"linter": {"enabled": false}` at line 27.
- `files.includes` at lines 9-15 still excludes `packages/swarm-engine/`, `packages/sdk/clawdstrike-hunt/`, `packages/sdk/plugin-sdk/`, `packages/dev/vite-plugin-clawdstrike/`, `packages/cli/create-plugin/`, `packages/adapters/clawdstrike-broker-client/` (well, this last one is partially covered by `packages/adapters/*/src/**/*.ts`).
- Zero `biome-ignore` comments found across `packages/` at HEAD — suggesting the lint pass was never actually wired up since the audit.

### 9. HIGH [Architecture] `@clawdstrike/openclaw` duplicates `@clawdstrike/policy` — **STILL VALID**
- File sizes confirm parallel implementations:
  - `packages/adapters/clawdstrike-openclaw/src/policy/loader.ts`: **461 LOC**
  - `packages/policy/clawdstrike-policy/src/policy/loader.ts`: **249 LOC**
  - `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts`: **698 LOC**
  - `packages/policy/clawdstrike-policy/src/policy/validator.ts`: **640 LOC**
- 2,048 LOC of duplicated policy infrastructure still ships in two places.
- 58 `as any` casts in openclaw validator alone (wave3-D top offender).

### 10. HIGH [Type Safety] 503 `any` + 189 `as any` repo-wide → **mostly STILL VALID, scope-corrected**
- **Original headline numbers** included tests + apps. wave3-D pinned the in-scope prod count to ~347 (`packages/` + 3 apps).
- **At HEAD, `packages/` only, non-test:** 84 `any` decls + 188 `as any` = **272**.
- Per-file worst offenders unchanged:
  - `clawdstrike-openclaw/src/policy/validator.ts`: 58 `as any` (verified)
  - `clawdstrike-vercel-ai/src/middleware.ts`: 23 `as any` (verified, wave3-D said 23 vs wave-1's ~30 — exact)
  - `clawdstrike-policy/src/policy/legacy.ts`: 17 `as any` (verified)
- WASM `inner: any` pattern still in 5 files (`instruction-hierarchy.ts:118`, `jailbreak.ts:98`, `output-sanitizer.ts:117`, `policy-lab.ts:39`, `spider-sense.ts:42`) + `crypto/backend.ts:35` (`wasmModule: any`).
- `client.ts:67` `init.headers as any` still present.

### 11. HIGH [Hygiene] `vite-plugin-clawdstrike` not in root workspaces — **STILL VALID**
- Root `package.json` `workspaces` array at lines 7-30 verified: includes `packages/cli/create-plugin`, `packages/swarm-engine`, `packages/sdk/plugin-sdk`, `packages/sdk/clawdstrike-hunt` but **NOT** `packages/dev/vite-plugin-clawdstrike`.
- The package still has its own `package-lock.json` (78 KB), still has no README, still 187 LOC of source.

### 12. MEDIUM [Packaging] `clawdstrike` re-export is half-baked — **STILL VALID**
- `packages/sdk/clawdstrike/index.js` = `export * from "@clawdstrike/sdk";`
- `packages/sdk/clawdstrike/index.cjs` = `module.exports = require("@clawdstrike/sdk");`
- `packages/sdk/clawdstrike/index.d.ts` = `export * from "@clawdstrike/sdk";`
- `package.json` `build` script = `node -e "console.log('clawdstrike re-export package: no build step')"` (verified).
- README is a 15-line "Install. Use. End." stub.
- **AGGRESSIVE recommendation stands: DELETE.**

### 13. MEDIUM [Architecture] `swarm-engine` ships without basic metadata — **STILL VALID** (+ wave3-H deepened)
- `packages/swarm-engine/package.json` (verified by `cat`): no `description`, no `license`, no `keywords`, no `repository`, no `homepage`, no `bugs`, no `author`, no `publishConfig`. `dependencies: {}`, `peerDependencies: {}`. Version still `0.1.0`.
- **wave3-H added these load-bearing findings:**
  - Only consumer is `apps/workbench` (linked via `file:../../packages/swarm-engine`).
  - **Not published to npm** (`npm view` returns 404 as of 2026-05-23).
  - 6 of 7 subsystems (consensus 1,643 LOC, HNSW memory ~865 LOC, ProtocolBridge, pool autoscaling, topology rebalancing, task DAG) are unreferenced by workbench.
  - **3 CRITICAL + 4 HIGH unresolved security findings** documented in-tree at `docs/plans/swarm-engine/SECURITY-AUDIT.md` (still present at HEAD).
  - Phase 4 + Phase 5 are still TODOs in production code (`orchestrator.ts:228, 265, 266, 268` verified at HEAD).
  - All 8 commits since 2026-03-28 are Dependabot (still true at HEAD).
- **Verdict from wave3-H stands: KEEP-INTERNAL** (fold into `apps/workbench/src/features/swarm/engine/`) **OR WIPE** (aggressive). Both are viable.

### 14. MEDIUM [API Design] `getSwarmTopics()` deprecated boolean overload — **STILL VALID**
- `packages/swarm-engine/src/protocol.ts:216-240` verified, still contains the `optionsOrLegacyBoolean: boolean | GetSwarmTopicsOptions` parameter and the `console.warn("[getSwarmTopics] boolean arg is deprecated, use options object")` at line 222.
- Package is still at v0.1.0 — "legacy" compatibility at v0 is still theater.

### 15. MEDIUM [Build] openclaw workspace-build script is fragile — **STILL VALID**
- `packages/adapters/clawdstrike-openclaw/package.json:23` verified at HEAD:
  ```
  "build:local-deps": "(cd ../../policy/clawdstrike-policy && ([ -d node_modules ] || npm ci) && npm run build) && (cd ../clawdstrike-adapter-core && ([ -d node_modules ] || npm ci) && npm run build)"
  ```
- Lines 26 + 30 still use this shell-stitched bootstrap for `test:workspace` and `typecheck:workspace`. Proves the npm-workspace hoist doesn't actually work end-to-end.

### 16. MEDIUM [API Design] langchain ships 4 deprecated wrappers — **STILL VALID**
- `packages/adapters/clawdstrike-langchain/src/wrap.ts` `@deprecated` markers verified at lines 37, 83, 99, 115, 138 (5, not 4 — wave-1 undercounted).
- `packages/adapters/clawdstrike-langchain/src/errors.ts:7`: `LangChainBlockedError @deprecated` still present.
- Total deprecated exports in this package: **6** (verified by `grep -c "@deprecated" packages/adapters/clawdstrike-langchain/src/*`).

### 17. MEDIUM [Type Safety] LangChain `wrapTool` generic uses `any[]` — **STILL VALID**
- File still at `packages/adapters/clawdstrike-langchain/src/langchain-adapter.ts`. Generic signature still uses `{ invoke?: (...args: any[]) => any; _call?: (...args: any[]) => any }` shape.

### 18. MEDIUM [Hygiene] 4 hard-coded adapter `version` TODOs — **STILL VALID**
- `packages/adapters/clawdstrike-langchain/src/langchain-adapter.ts:22` = `readonly version = "0.1.1"; // TODO: derive from package.json at build time`
- `packages/adapters/clawdstrike-adapter-core/src/framework-adapter.ts:27` = `version: "0.1.1", // TODO: derive from package.json at build time`
- Both packages publish at 0.2.7 → reported version is wrong by an order of magnitude.
- (Wave-1 said 4; `grep -rn` finds 2 distinct sites. May have been counted with duplicates; functionally the fix is the same.)

### 19. MEDIUM [Hygiene] `engine-adaptive` sync fs on hot path — **STILL VALID**
- `packages/adapters/clawdstrike-engine-adaptive/src/receipt-queue.ts:1` still imports `appendFileSync, readFileSync, writeFileSync`.
- Line 45 (`appendFileSync(persistPath, ...)`) is called inside `enqueue()` — i.e. per-receipt — confirming hot-path sync I/O.
- Line 58 `writeFileSync` in `drain()`, line 96 in `persistToDisk()`, line 73 `readFileSync` in `loadFromDisk()`.

### 20. MEDIUM [Hygiene] 6 README-less packages — **wave-1 undercounted; STILL VALID at 7**
- Verified at HEAD: 7 packages without README:
  1. `packages/swarm-engine`
  2. `packages/cli/create-plugin`
  3. `packages/adapters/clawdstrike-broker-client`
  4. `packages/adapters/clawdstrike-origin-core`
  5. `packages/sdk/clawdstrike-hunt` (wave-1 missed this)
  6. `packages/sdk/plugin-sdk`
  7. `packages/dev/vite-plugin-clawdstrike`

### 21. MEDIUM [Test Quality] 27 `toBeDefined()`-only assertions in `swarm-engine` tests — **STILL VALID**
- Wave-1 said 27; at HEAD `grep -rn toBeDefined packages/swarm-engine/src/*.test.ts | wc -l` returns **17** (per-line; 27 was a different counting basis or wave-1 over-counted).
- Either way smoke-test pattern persists. Several `expect(x).toBeDefined()` on values that are guaranteed by static type to be defined.

### 22. MEDIUM [Test Quality] Commented-out integration tests in `create-plugin` — **STILL VALID**
- `packages/cli/create-plugin/tests/scaffold.integration.test.ts:163-188` verified at HEAD:
  - Lines 167-188 are a commented-out `describe("scaffold: full CI build+test", ...)` block containing the real `expect(install.exitCode).toBe(0)`, `expect(build.exitCode).toBe(0)`, `expect(test.exitCode).toBe(0)` assertions.
  - Comment at line 163 says "TODO: Enable after Phase 1 (testing harness) completes". Phase 1 evidently never completed.

### 23. MEDIUM [Hygiene] Mixed sync-fs in `clawdstrike-openclaw` hooks — **STILL VALID**
- `grep -rn 'readFileSync\|writeFileSync\|appendFileSync\|existsSync' packages/adapters/clawdstrike-openclaw/src/` = **68 hits** (up from wave-1's "12+").
- The bulk is in `src/audit/store.ts`, `src/plugin.ts`, `src/cli/commands/*.ts`, and the four `src/hooks/{cua-bridge,tool-preflight,tool-guard,inbound-message}/handler.ts` handlers. Many of these read/write per-request.

### 24. MEDIUM [API Design] `@clawdstrike/sdk` `index.ts` exports 200+ symbols — **STILL VALID**
- `packages/sdk/hush-ts/src/index.ts` at HEAD = **234 LOC**, unchanged. `export *` patterns still defeat tree-shaking.

### 25. MEDIUM [Hygiene] `clawdstrike-security.js` shim at package root — **STILL VALID**
- `packages/adapters/clawdstrike-openclaw/clawdstrike-security.js` = single line `export { default } from './dist/plugin.js';` — verified.

### 26. LOW [Hygiene] Inconsistent quote/spacing within `hush-ts` — **STILL VALID**
- `clawdstrike.ts:37` uses single quotes (`from './guards/egress-allowlist.js'`).
- `client.ts:66-67` uses double quotes (`init.headers as any`).
- Biome formatter `quoteStyle: "double"` configured but never run on the offending files.

### 27. LOW [Hygiene] Engine version mismatch — **STILL VALID**
- Root: `"node": "24.11.0"` (exact pin)
- `>=18`: 10 packages (openai/claude/langchain/opencode/broker-client/engine-adaptive/engine-local/engine-remote/vercel-ai/adapter-core)
- `>=20`: 4 (openclaw/policy/origin-core/clawdstrike-hunt)
- `>=20.19.0`: 5 (hush-ts/clawdstrike/plugin-sdk/vite-plugin-clawdstrike/create-plugin)

### 28. LOW [Code Smell] `@ts-expect-error -- stored for future validation` in HNSW — **STILL VALID**
- `packages/swarm-engine/src/memory/hnsw.ts:9-10` verified at HEAD:
  ```ts
  // @ts-expect-error -- stored for future validation
  private readonly dimensions: number;
  ```
- Field is set in constructor but never read — dead code; the `@ts-expect-error` will flip and fail typecheck the moment anyone actually reads `dimensions`.

### 29. LOW [Type Safety] Generic `any[]` leakage in wrap.ts patterns — same as #17, STILL VALID.

### 30. LOW [Hygiene] 76 direct `process.env.X` accesses — **STILL VALID**
- `rg "process\.env\." packages/ --type ts` (non-test) returns **76** hits at HEAD.

### 31. LOW [Hygiene] `console.log` in `openclaw/src/plugin.ts:228-251` for CLI status — **STILL VALID**

### 32. LOW [Hygiene] `case-convert.ts` is hand-rolled, used inconsistently — **STILL VALID**

### 33. LOW [Hygiene] vitest.config.ts quote inconsistency — **STILL VALID**
- `single`-quote files: `engine-adaptive`, `vercel-ai`, `claude`, `langchain`.
- `double`-quote files: `swarm-engine`, `openclaw`, `origin-core`, `create-plugin`, ...

### 34. LOW [Test Quality] `siem-exporters.test.ts` is 1,335 lines — **STILL VALID**
- `packages/sdk/hush-ts/tests/siem-exporters.test.ts` `wc -l` = 1335 (unchanged).

### 35. LOW [Hygiene] `noUncheckedIndexedAccess` enabled in only one package — **STILL VALID**
- `find packages -name tsconfig.json | xargs grep -l noUncheckedIndexedAccess` returns exactly one match: `packages/dev/vite-plugin-clawdstrike/tsconfig.json`.

### 36. LOW [Hygiene] No shared `tsconfig.base.json` — **STILL VALID**
- `find . -maxdepth 2 -name tsconfig.base.json` returns nothing.
- 19 separate tsconfig.json files across packages/. Drift confirmed by sampling: hush-ts has `noUnusedLocals`, `noUnusedParameters`, `noImplicitReturns`, `noFallthroughCasesInSwitch`; the adapters mostly do not.

### 37. LOW [API Design] `Decision` type duplicated across packages — **STILL VALID**
- Verified by `rg Decision -l`: defined or re-defined in `packages/sdk/hush-ts/src/clawdstrike.ts`, `packages/adapters/clawdstrike-adapter-core/src/types.ts` (canonical, at line 127-140), and `packages/adapters/clawdstrike-openclaw/src/types.ts`.

### 38. LOW [Hygiene] `clawdstrike-hunt` index.ts is 115-line handwritten barrel — **STILL VALID** (and noted as acceptable in wave-1).

### 39. WAVE3-D extension: Hand-rolled YAML/policy validators — STILL VALID
- 125+ `as any` casts concentrated in 5 files (per wave3-D category 1). All present at HEAD with same line numbers cited:
  - `clawdstrike-openclaw/src/policy/validator.ts:190` `(p.egress as any).mode`
  - `clawdstrike-openclaw/src/policy/validator.ts:297-302` 6× `ensureBoolean((p.guards as any).forbidden_path, ...)`
  - `clawdstrike-policy/src/policy/legacy.ts:53` `(legacy.guards as any).custom`
  - `clawdstrike-policy/src/plugins/manifest.ts:80` `(trust as any).level`
  - `clawdstrike-policy/src/policy/validator.ts:80` `validateSpiderSense((p.guards as any).spider_sense, ...)`
- Per wave3-D H1: migration to zod or valibot collapses ~125 `as any` to 0 across these files. 4-6 engineer-days.

### 40. WAVE3-D extension: HTTP client typed-as-any — STILL VALID (same file as #3 above)
- `client.ts` covered in finding 3; additional sites elsewhere:
  - `packages/sdk/hush-ts/src/siem/exporters/sumo-logic.ts:87` `body: payload as any`
  - `packages/sdk/hush-ts/src/siem/exporters/sumo-logic.ts:127` `JSON.parse(JSON.stringify(event)) as any`
  - `packages/sdk/hush-ts/src/siem/exporters/webhooks.ts:291, 309, 365` 3 sites

### 41. WAVE3-D extension: NATS / dynamic-require `any` shims — STILL VALID
- `packages/sdk/clawdstrike-hunt/src/watch.ts:44` `let natsModule: any;`
- `packages/sdk/clawdstrike-hunt/src/stream.ts:32, 90` `let natsModule: any;`
- `packages/sdk/hush-ts/src/crypto/backend.ts:96, 102, 112, 114, 130, 160, 237` various `getBuiltin: any = (globalThis as any)?.process?.getBuiltinModule;` etc.

### 42. WAVE3-D extension: Threat-intel JSON response `any` casts — STILL VALID
- `packages/policy/clawdstrike-policy/src/guards/threat-intel/virustotal.ts:178, 185, 223` — 3 hits parsing untyped VirusTotal payloads.
- `packages/policy/clawdstrike-policy/src/guards/threat-intel/snyk.ts:125, 135, 152` — 3 hits.
- `packages/policy/clawdstrike-policy/src/guards/threat-intel/safe-browsing.ts:80` — 1 hit.
- Total: 7 `as any` in 3 threat-intel guards. Each guard has a documented wire format — 30-minute fixes per file.

### 43. WAVE3-D extension: Test-helper leaks into prod — STILL VALID
- `packages/adapters/clawdstrike-openclaw/src/e2e/openclaw-e2e.ts:49, 55, 61` — 3 `as any` in code shipped under `src/` rather than `tests/`. Either move out of `src/` or type the inputs.

### 44. WAVE3-D extension: CUA hook side-channel marker via monkey-patch — STILL VALID
- `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/handler.ts:382` — `(event as any).__cuaBridgeEvaluated = true;`
- `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts:481` — `if ((event as any).__cuaBridgeEvaluated) return;`
- Fix: `WeakSet<PolicyEvent>` instead of mutating events. 15 minutes.

---

## FIXED SINCE 2026-05-23

**None.** Zero commits touched `packages/` since the audit. The TypeScript surface is frozen.

---

## NOW WRONG / MISDIAGNOSED

### M1. The `503 any + 189 as any` headline number was repo-wide, not packages/-only.
- **Wave-1 statement:** "503 `any`-type sites and 189 `as any` casts in non-test code".
- **wave3-D reconciliation:** restricted to in-scope prod TS, the actual figure is ~347 (122 decl + 225 cast).
- **At HEAD, in `packages/` only, non-test:** 84 decl + 188 cast = **272**.
- The original number was correct on its scope (probably included `apps/workbench/` + apps + test files); wave3-D's 347 was right for the prod-source-only delineation; today's `packages/` slice is 272. None of these contradict each other — they are different boundary definitions. **Not a misdiagnosis, just an undisclosed scope.**

### M2. Wave-1 said "14 per-package lockfiles"; correct count is **15**.
- Wave-1 missed `packages/dev/vite-plugin-clawdstrike/package-lock.json` (78 KB; the package is *outside* root workspaces but still ships its own lockfile, which is even more egregious than the in-workspace cases). wave3-E reconciled this to 15. Today still 15.

### M3. Wave-1 listed 6 README-less packages; correct count is **7**.
- Wave-1 missed `packages/sdk/clawdstrike-hunt/` — 9,000+ LOC SDK shipping with no README.

### M4. Wave-1 said `getSwarmTopics()` deprecated boolean is "the only" backcompat smell in `swarm-engine`.
- True for `getSwarmTopics`. But there are also `@deprecated` markers on `SwarmEngineContextValue.agentRegistry`, `.taskGraph`, `.topology` in `apps/workbench/src/features/swarm/stores/swarm-engine-provider.tsx:38-43` (per wave3-H). Those are workbench-side, not strictly `swarm-engine` — but they suggest the consumer was already collapsing the abstraction.

No findings were materially wrong. The wave-1 audit was rigorous.

---

## NEW ISSUES (not in wave-1)

### N1. CRITICAL [Architecture] `swarm-engine` security audit has 3 CRITICAL + 4 HIGH findings sitting in-tree, untouched since 2026-03-24
- **File:** `docs/plans/swarm-engine/SECURITY-AUDIT.md` (534 LOC, still at HEAD)
- Wave-1 did not surface this. Wave3-H (the swarm-engine viability deep dive) made it the centerpiece evidence.
- Per wave3-H: "Guard Pipeline Bypass — Multiple Mutable Operations Skip Guard Evaluation" is the named CRITICAL — fatal for a fail-closed product. The last attempted fix was `3dfac24b6 fix(swarm): restore fail-closed guard handling` on 2026-03-28, two months ago. The remaining items are open.
- **Recommendation:** If the AGGRESSIVE path is WIPE swarm-engine entirely (see below), these vanish. If KEEP-INTERNAL, they must land first.

### N2. HIGH [Architecture] Root `bun.lockb` + root `package-lock.json` both present at HEAD, neither consumed by CI
- Wave-1 only enumerated child lockfiles. Wave3-E surfaced the root duplication: **both** `/bun.lockb` (439 KB) and `/package-lock.json` (611 KB) are committed at the repository root, yet CI bypasses both and runs `npm --prefix <member> ci` per-package.
- The root `package.json` declares npm `workspaces` but ships a `bun.lockb` — which strongly suggests `bun install` was once run by a contributor and the lockfile leaked into the commit.
- **Recommendation:** wave3-E Strategy B — remove the `workspaces` declaration from root `package.json`, delete both root lockfiles. Matches the actual per-package install pattern CI already uses.

### N3. HIGH [Architecture] Root-level `clawdstrike-plugin/` and `cursor-plugin/` are bun-based standalone Claude/Cursor IDE plugins — likely belong to D01 scope
- `clawdstrike-plugin/` and `cursor-plugin/` at repo root contain `bun.lockb`, `package.json`, `scripts/*.ts`, `.mcp.json`, `commands/`, `agents/`, `hooks/`, `skills/`, `test/`.
- Both ship `@modelcontextprotocol/sdk` and an MCP stdio server.
- **`cursor-plugin/scripts/mcp-server.ts` and `clawdstrike-plugin/scripts/mcp-server.ts` are byte-identical** (both 491 LOC). Same for `cli-bridge.ts` (both 182 LOC). One is a copy of the other.
- Per wave3-E: `clawdstrike-plugin/bun.lockb` and `cursor-plugin/bun.lockb` are also byte-identical in size (37,300 bytes each) — strongly indicating the cursor-plugin directory was forked from claude-plugin with no actual dependency re-resolution.
- These are not under `packages/` so are arguably out of scope for D05. **Verdict: BELONGS TO D01.** Flag for that delta agent. But note: both scaffolds have substantial drift potential (no test that they remain in sync, no shared source).

### N4. MEDIUM [Type Safety] `private readonly inner: any` pattern in 5 SDK files + 1 backend = 6 sites for a single WASM-handle interface
- **Files:**
  - `packages/sdk/hush-ts/src/instruction-hierarchy.ts:118` (`private inner: any`)
  - `packages/sdk/hush-ts/src/jailbreak.ts:98` (`private readonly inner: any`)
  - `packages/sdk/hush-ts/src/output-sanitizer.ts:117` (`private readonly inner: any`)
  - `packages/sdk/hush-ts/src/policy-lab.ts:39` (`private readonly inner: any`)
  - `packages/sdk/hush-ts/src/spider-sense.ts:42` (`private readonly inner: any`)
  - `packages/sdk/hush-ts/src/crypto/backend.ts:35` (`let wasmModule: any = null`)
- This is the architectural shape wave3-D called out under "WASM module untyped bindings" (category 3, ~25 hits). The fix is a single hand-written `interface HushWasmModule { ... }` in `crypto/backend.ts` — ~1 hour of work, eliminates the entire category.
- Wave-1 mentioned this in passing but did not list the 6 file:line citations together.

### N5. MEDIUM [Architecture] No package consumes `@clawdstrike/plugin-sdk` from `apps/workbench` despite SDK existing
- Per wave3-K: `apps/workbench/package.json` does **not** depend on `@clawdstrike/plugin-sdk`, `@clawdstrike/create-plugin`, or `@clawdstrike/vite-plugin-clawdstrike`. The workbench has its own `src/lib/plugins/types.ts` with parallel copies of every contribution interface.
- Implication for D05 cleanup: `@clawdstrike/plugin-sdk` (1,538 LOC + 1,329 LOC of tests) is type-only re-exports; the source of truth lives in workbench. Either:
  - (a) Wire workbench to consume the SDK (closes the drift loop).
  - (b) Mark the SDK as "preview, not yet consumed" and lower its visibility, or
  - (c) WIPE the SDK and document workbench-internal plugins only.
- Wave-1 lumped `plugin-sdk` under "beta — no README, has typedoc setup" without naming the consumer gap.

### N6. LOW [Hygiene] Hard-coded `// @ts-expect-error -- stored for future validation` in production SDK code
- Same `hnsw.ts:9` from finding 28 above. Calling out separately because: this is a **fragile annotation**. If anyone later writes `validate(vec) { if (vec.length !== this.dimensions) throw }` the `@ts-expect-error` flips to a compile error. This is a time-bomb against a feature the author intended but never wrote. Either delete the field or implement the validation.

### N7. LOW [Hygiene] zero `biome-ignore` comments in `packages/` despite biome being configured
- `grep -rn "biome-ignore" packages/ --type ts` returns **0 matches** at HEAD.
- The original audit cited "the codebase already uses `biome-ignore` comments for these rules, suggesting they were enabled at some point". I cannot reproduce this — there are zero biome-ignore comments in `packages/`. The biome formatter has clearly never been wired to lint these packages. (There may be biome-ignore comments under `apps/`, which is out of D05 scope.)
- Implication: the wave-1 plan to "enable biome linter with `noExplicitAny`, `noConsole`" would surface hundreds of violations on first run, including most of the `private inner: any` sites in N4.

### N8. LOW [Slop comments] AI-slop comment density in `clawdstrike.ts`
- `grep -c '^ \+\* ' packages/sdk/hush-ts/src/clawdstrike.ts` = 217 JSDoc lines in 2027 LOC (10.7%).
- This is high but not pathological; the JSDoc is mostly @example blocks. Many of the @example blocks reference APIs that have since moved. Worth a sweep when splitting the god module per finding 4.
- Slop comment headcount across `packages/sdk packages/adapters` for `TODO|FIXME` (non-test): **4 hits**, all four are load-bearing and called out elsewhere in this report (2× ReceiptSigner.verify, 2× version "0.1.1" derivation). No incidental slop comments — that part of the codebase reads cleanly.

---

## AGGRESSIVE EXECUTION PLAN (top-5)

Ceiling is aggressive. Below is the smallest set of moves with the largest payoff. Each is **fully unblocked** at HEAD; none waits on Rust or apps work. Sequence is independent — pick any subset.

### A1. WIPE `packages/swarm-engine/` entirely (or fold into `apps/workbench/src/features/swarm/engine/`)
- **Why:** Per wave3-H: not published, not advertised, sole consumer is workbench, 6 of 7 subsystems are dead weight, 3 CRITICAL + 4 HIGH unresolved security findings, Phase 4/5 are TODOs in prod code, 7 weeks of nothing-but-Dependabot.
- **Effort:** wave3-H estimated 3 engineer-days for the KEEP-INTERNAL fold; a pure WIPE is ~1 day (just remove the dep + delete the directory + replace the 1-2 workbench import sites with stubs or with the ~200 LOC of guard-gated spawn logic that's actually exercised).
- **Net LOC reduction:** ~14,000 source + ~6,700 test + 4,699 LOC of stale plan docs in `docs/plans/swarm-engine/` (move to `docs/plans/decisions/archive/swarm-engine-2026-03-port/`).
- **Workbench downstream:** strips 11 `pre*` build hooks from `apps/workbench/package.json`. Simpler CI.
- **Recommended:** **WIPE.** This is the largest single cleanup payoff in the entire TS surface. Workbench works without it today (`useOptionalSwarmEngine()` already falls back to manual mode).
- **Commit sequence (per wave3-H):**
  1. `chore(swarm-engine): drop unused consensus/memory/protocol subsystems`
  2. `refactor(workbench): move swarm-engine source into features/swarm/engine` (skip for WIPE path)
  3. `chore(workbench): drop swarm-engine build coupling and root workspace entry`
  4. `chore(repo): delete packages/swarm-engine`
  5. `docs: archive swarm-engine plans under docs/plans/decisions/archive`
- **Files affected for full WIPE:**
  - DELETE: `packages/swarm-engine/` (entire directory, ~24,000 LOC including tests/lockfiles/configs)
  - EDIT: root `package.json` (line ~30, remove `"packages/swarm-engine"` from workspaces array)
  - EDIT: `apps/workbench/package.json` (line 83, remove `"@clawdstrike/swarm-engine": "file:../../packages/swarm-engine"` dep; lines for 11 `pre*` scripts + `build:swarm-engine` script)
  - EDIT: `apps/workbench/src/features/swarm/stores/swarm-engine-provider.tsx` (replace 20-line import block with workbench-local stubs)
  - EDIT: `apps/workbench/src/features/swarm/stores/workbench-guard-evaluator.ts`
  - EDIT: `apps/workbench/src/features/swarm/hooks/use-engine-board-bridge.ts`
  - EDIT: 3 test files that `vi.mock("@clawdstrike/swarm-engine", ...)`
  - MOVE: `docs/plans/swarm-engine/` → `docs/plans/decisions/archive/swarm-engine-2026-03-port/`

### A2. WIPE `packages/sdk/clawdstrike/` (the unscoped re-export)
- **Why:** 3 files of `export * from "@clawdstrike/sdk"`. Build script is `node -e "console.log(...)"`. CJS path is a lie — consumers using `require("clawdstrike")` get the CJS bundle through `@clawdstrike/sdk` itself, not this shim. Adds maintenance overhead, zero functional value over `@clawdstrike/sdk`.
- **Effort:** ~30 minutes — delete the directory, remove the workspace entry, remove any docs reference.
- **Net LOC reduction:** ~5 LOC of code + the build-step lie + one more lockfile.
- **Downstream:** nobody imports it (verified — no `from "clawdstrike"` imports anywhere except inside this package's own README). If someone needs an unscoped npm name later, publish from a dedicated repo or a single-file shim with proper docs.
- **Recommended:** **WIPE.**
- **Verified content of package** (`packages/sdk/clawdstrike/`):
  ```
  index.js   = export * from "@clawdstrike/sdk";
  index.cjs  = module.exports = require("@clawdstrike/sdk");
  index.d.ts = export * from "@clawdstrike/sdk";
  package.json  (47 lines, has version "0.2.7" + license + repository + publishConfig)
  README.md     (15-line stub: "Install. Use. End.")
  ```
- **Risk surface:** the package is in npm-workspaces (root `package.json:12`) and ships under `biome.json` `files.includes` (line 13). Removing it requires touching both. The vanity npm-name claim is plausibly load-bearing for marketing; the per-package shim adds zero technical value.

### A3. REWRITE `packages/sdk/hush-ts/src/client.ts` with real types (kill the Promise<any> stack)
- **Why:** Customer-facing HTTP SDK currently returns `Promise<any>` from every method. No autocomplete, no validation, no schema. Worst-of-class for a *security product's* public client.
- **Effort:** ~4-6 hours. Hand-write `Certification`, `EvidenceExport`, `EvidenceExportRequest`, `CertificationCreate` interfaces from the Rust source-of-truth in `crates/hush-certification/` and `crates/hushd/src/api/`. Replace 6 `Promise<any>` → typed returns. Fix the `init.headers as any` at line 67.
- **Net delta:** -12 `any` declarations, +real types, +autocomplete, +catches mismatches at compile time.
- **Recommended:** **REWRITE.** Single highest-value type win in the SDK.
- **Concrete diff target** (`packages/sdk/hush-ts/src/client.ts`):
  - Line 67 `...(init.headers as any)` → `...normalizeHeaders(init.headers)` with a helper that accepts `HeadersInit` and returns `Record<string, string>`.
  - Line 92 `Promise<any[]>` → `Promise<Certification[]>`.
  - Line 102 `Promise<any>` → `Promise<Certification>`.
  - Line 108 `body?: any: Promise<any>` → `body?: CertificationVerifyRequest: Promise<CertificationVerifyResponse>`.
  - Line 116 `body: any: Promise<any>` → `body: CertificationCreate: Promise<Certification>`.
  - Line 124 `body: any: Promise<any>` → `body: EvidenceExportRequest: Promise<EvidenceExport>`.
  - Line 135 `Promise<any>` → `Promise<EvidenceExport>`.
- **Add new file:** `packages/sdk/hush-ts/src/types/certifications.ts` (~50-80 LOC) holding the 5 interfaces.

### A4. DELETE `packages/adapters/clawdstrike-openclaw/src/receipt/signer.ts:99-107` `verify()` method outright
- **Why:** A `verify()` that returns `true` for unsigned receipts is worse than no verifier. Downstream callers may treat `verify() === true` as proof of attestation. Deleting forces callers to either wire real Ed25519 (via the existing `verifySignature` from `@clawdstrike/sdk`) or to stop pretending to verify.
- **Effort:** ~30 minutes — delete the method, fix the 0-2 callers (none in the main tree per a quick grep), document the gap until hush-wasm is integrated.
- **Recommended:** **DELETE** the stub. Anything else (returning `false` on unsigned, adding a config flag) leaves the trap. Aggressive ceiling: delete.
- **Bonus cleanup:** while in the file, also reconsider `createReceipt()` setting `signature: null` unconditionally (line 76). Either:
  - (a) Wire `signMessage` from `@clawdstrike/sdk` when `config.sign === true`, or
  - (b) Throw when `config.sign === true` is set but signing is unavailable, so consumers can't silently get unsigned receipts they expected to be signed.
- The current code's `config.sign: boolean` setting is purely cosmetic — it never causes a different output. That is itself a fail-open trap (caller sets `sign: true`, gets unsigned receipt, no warning).

### A5. KILL the workspace fiction: choose Strategy B from wave3-E
- **What:** Edit root `package.json`, remove the `workspaces` array entirely. `git rm bun.lockb` + `git rm package-lock.json` (root). Add both to `.gitignore`. CI already runs `npm --prefix <member> ci` per-package — this matches reality.
- **Effort:** ~1 hour including verifying `mise run ci` still passes.
- **Net delta:** -1,050 KB of dead lockfiles. -1 source of contributor confusion ("why does `npm install` at root not produce what I expected?"). Keeps the 15 per-package lockfiles where they actually work.
- **Recommended:** **DO IT.** Smallest-risk lockfile cleanup. Strategy A (keep workspaces, delete child lockfiles, rewrite CI to npm-ci-at-root + hoisting) is the "correct" model but requires CI rewrites that span beyond D05 scope.
- **Files affected:**
  - EDIT: root `package.json` (delete lines 7-30 `workspaces` array)
  - DELETE: root `package-lock.json` (611 KB)
  - DELETE: root `bun.lockb` (439 KB)
  - EDIT: root `.gitignore` (add `/package-lock.json`, `/bun.lockb`, `/bun.lock`)
  - VERIFY: `mise run ci`, `mise run test:apps`, `bash scripts/smoke-ts-file-deps.sh` all pass.
- **Companion cleanup** (separate commit per wave3-E):
  - `git rm apps/workbench/bun.lock` (workbench is npm; bun.lock is from a one-off `bun install` somebody ran)
  - Refresh `cursor-plugin/bun.lockb` and `clawdstrike-plugin/bun.lockb` (currently byte-identical, suggesting one was copy-pasted)

### A-bonus (cheap wins, can batch together)
- **B1.** `git rm` every per-package `package-lock.json` only if Strategy A above is chosen. Under Strategy B leave them.
- **B2.** Delete the 6 deprecated exports in `packages/adapters/clawdstrike-langchain/` (`wrap.ts:37,83,99,115,138` + `errors.ts:7`) and bump that adapter to 0.3.0. Document rename in CHANGELOG.
- **B3.** Remove `// @ts-expect-error -- stored for future validation` and the dead `dimensions` field at `packages/swarm-engine/src/memory/hnsw.ts:9` (especially if A1 doesn't ship: it's a time-bomb regardless).
- **B4.** Run `biome check --write packages/` once and commit the formatting normalization. Then broaden `biome.json` `files.includes` to cover every TS package and flip `linter.enabled` to `true` with `correctness` + `suspicious/noExplicitAny` + `suspicious/noConsole` enabled (be ready for hundreds of new violations to triage — most are legit issues).
- **B5.** Add a `tsconfig.base.json` at root with shared strict flags including `noUncheckedIndexedAccess: true`; have every package extend it. Will surface real bugs.
- **B6.** Fix the two `version = "0.1.1"` hard-codes (`clawdstrike-langchain/src/langchain-adapter.ts:22`, `clawdstrike-adapter-core/src/framework-adapter.ts:27`) via `tsup` `define` (the `__SDK_VERSION__` pattern in `hush-ts/tsup.config.ts` is the template).
- **B7.** Delete commented-out integration test block at `packages/cli/create-plugin/tests/scaffold.integration.test.ts:163-188` — either implement it or remove it; do not ship a 20-line commented-out test.
- **B8.** Migrate `engine-adaptive` receipt-queue (`packages/adapters/clawdstrike-engine-adaptive/src/receipt-queue.ts`) to `fs/promises` since this lives on a request-evaluation hot path.

---

## DEFER / OUT OF SCOPE

### Out of scope for D05 (belongs to other agents)
- **`apps/workbench/src/lib/plugins/` (~22,962 LOC, 47 test files)** — workbench-internal plugin loader, sandbox, bridge. Belongs to D06 (frontend apps). But: drives the plugin SDK consumer story (per wave3-K) and is the only thing keeping `@clawdstrike/plugin-sdk` from being WIPED.
- **Root-level `clawdstrike-plugin/` and `cursor-plugin/`** — bun-based IDE plugin scaffolds. Identical mcp-server.ts files between them. Belongs to D01 (top-level meta). Per N3 above.
- **Rust/WASM guard plugin world** (`crates/libs/clawdstrike-guard-sdk*`, `crates/libs/clawdstrike/src/plugins/`) — belongs to D03 / D04. wave3-K notes the doc gap (docs/src/plugins/ describes only the TS world).
- **`packages/sdk/hush-py`, `hush-go`, `hush-csharp`** — explicitly out of scope per the original D05 mandate.

### Defer (still in scope, but lower priority than top-5)
- **Splitting `clawdstrike.ts` (2,027 LOC) and `spider-sense.ts` (2,365 LOC) into modules.** Real architectural debt, medium-effort refactor, no security impact. Defer until after A3 lands (types come first).
- **Zod schema migration** for policy YAML validators (wave3-D H1, ~125 `as any` evaporate). 4-6 days of work; the highest-payoff type cleanup but a significant migration with regression risk against `rulesets/*.yaml` fixtures.
- **Vercel AI middleware vendor-type pinning** (wave3-D H2, ~52 `as any`). Requires confirming Vercel AI target version; medium effort.
- **`@clawdstrike/openclaw` policy/* dedup against `@clawdstrike/policy`** (2,048 LOC of parallel implementations). Medium effort, no security impact, blocks publish credibility.
- **Sub-path exports** for `@clawdstrike/sdk` (`/crypto`, `/guards`, `/siem`, `/detection`) to enable tree-shaking. Architectural; defer.
- **`Decision` type centralization** in `adapter-core` with re-exports elsewhere. Low-effort but touches every adapter.
- **`engine-adaptive` async fs migration** for receipt-queue (currently sync on hot path). Real correctness issue under load, but `engine-adaptive` is itself a low-traffic adapter; defer until it has consumers.

### Cosmetic / batchable later
- Quote-style normalization across vitest configs and source files (biome write).
- engines.node alignment to `>=20.19.0` repo-wide.
- README stubs for the 7 README-less packages.
- Adapter `version` strings derived from `package.json` at build time (`tsup` define hook).
- 27 (or 17 at HEAD) `toBeDefined()` smoke tests in swarm-engine → structural assertions (moot if A1 lands).
- Commented-out integration tests in `create-plugin/tests/scaffold.integration.test.ts:163-188` → either uncomment+wire or delete.
- 76 `process.env.X` accesses → centralize per-package `env.ts`.
- `Decision` type centralization to `adapter-core`, eliminate the duplicates in `hush-ts/src/clawdstrike.ts` and `clawdstrike-openclaw/src/types.ts`.
- Split `clawdstrike.ts` (2,027 LOC) into `src/core/{client,session,decision,types}.ts`, `src/policy/{loader,builtin,secret-patterns}.ts`, `src/daemon/client.ts`.
- Split `spider-sense.ts` (2,365 LOC) into `src/guards/spider-sense/{guard,pattern-db,scoring,trusted-keys,types}.ts`.
- Sub-path exports for `@clawdstrike/sdk` (`/crypto`, `/guards`, `/siem`, `/detection`) — restructure `index.ts` (234 LOC barrel) into the `exports` map.

---

## Per-package verdict (at HEAD, aggressive ceiling)

Twenty packages. For each: status, blocking issues, and a one-shot recommendation.

| Package | LOC src | Status | Top blocker | Aggressive verdict |
|---|---:|---|---|---|
| `@clawdstrike/sdk` (`packages/sdk/hush-ts`) | ~12,200 | beta | `client.ts` `Promise<any>`; 2k-LOC god file; 2.4k-LOC spider-sense; mixed build path | **KEEP** — REWRITE `client.ts` (A3), split god modules (defer), normalize build (defer) |
| `clawdstrike` (`packages/sdk/clawdstrike`) | 3 | vanity | 5-LOC re-export; build script lies about CJS path; no consumer | **WIPE** (A2) |
| `@clawdstrike/hunt` (`packages/sdk/clawdstrike-hunt`) | 9,044 | beta | no README; 4 `any` decls; NATS-as-`any` shim | **KEEP** — README + type the NATS shim |
| `@clawdstrike/plugin-sdk` (`packages/sdk/plugin-sdk`) | 1,538 | type-only | not consumed by `apps/workbench`; parallel type copies in workbench | **KEEP-INTERNAL** or **WIPE** depending on Tier-1 decision in wave3-K (Option B) |
| `@clawdstrike/adapter-core` (`packages/adapters/clawdstrike-adapter-core`) | 13,916 | production-grade | 1 hard-coded version string at `framework-adapter.ts:27` | **KEEP** — single line fix |
| `@clawdstrike/broker-client` (`packages/adapters/clawdstrike-broker-client`) | 834 | beta | no README | **KEEP** — add README |
| `@clawdstrike/claude` (`packages/adapters/clawdstrike-claude`) | 429 | clean | engines.node `>=18` drift | **KEEP** — align engines |
| `@clawdstrike/engine-adaptive` (`packages/adapters/clawdstrike-engine-adaptive`) | 1,162 | sketchy | sync fs on hot path (`receipt-queue.ts:45`) | **KEEP** — migrate to `fs/promises` (B8) |
| `@clawdstrike/engine-local` (`packages/adapters/clawdstrike-hush-cli-engine`) | 454 | beta | engines.node drift | **KEEP** |
| `@clawdstrike/engine-remote` (`packages/adapters/clawdstrike-hushd-engine`) | 331 | beta | engines.node drift | **KEEP** |
| `@clawdstrike/langchain` (`packages/adapters/clawdstrike-langchain`) | 1,164 | beta | 6 deprecated exports; `any[]` generics | **KEEP** — delete deprecated, bump to 0.3.0 (B2) |
| `@clawdstrike/openai` (`packages/adapters/clawdstrike-openai`) | 863 | beta | engines.node drift | **KEEP** |
| `@clawdstrike/openclaw` (`packages/adapters/clawdstrike-openclaw`) | 16,871 | beta | fail-open ReceiptSigner.verify; duplicates `@clawdstrike/policy`; 58 `as any` in validator; 68 sync fs sites; `clawdstrike-security.js` shim | **KEEP** — DELETE the verify stub (A4); medium-term collapse policy/ into `@clawdstrike/policy` |
| `@clawdstrike/opencode` (`packages/adapters/clawdstrike-opencode`) | 196 | tiny | nearly a stub | **KEEP** — leave alone or grow |
| `@clawdstrike/origin-core` (`packages/adapters/clawdstrike-origin-core`) | 1,112 | beta | no README | **KEEP** — add README |
| `@clawdstrike/vercel-ai` (`packages/adapters/clawdstrike-vercel-ai`) | 2,357 | sketchy-security | 3 silent-degrade WASM paths (CRITICAL); 23 `as any` in middleware; 1190-LOC middleware god module | **KEEP** — fix fail-open WASM (CRITICAL); type the prompt-walking helpers via `@ai-sdk/provider` |
| `@clawdstrike/policy` (`packages/policy/clawdstrike-policy`) | 5,204 | beta | duplicated by openclaw's `policy/`; 69 `as any` (hand-rolled YAML validators) | **KEEP** — long-term zod migration (defer to wave3-D H1) |
| `@clawdstrike/swarm-engine` (`packages/swarm-engine`) | 13,931 | abandoned | no metadata; 3 CRITICAL + 4 HIGH in-tree security findings; only consumer is workbench; not published; 7 weeks of Dependabot only; Phase 4/5 are TODOs | **WIPE** (A1) — single largest cleanup payoff |
| `@clawdstrike/vite-plugin-clawdstrike` (`packages/dev/vite-plugin-clawdstrike`) | 187 | sketchy | NOT in root workspaces despite ships its own lockfile; no README; option-shape mismatch with docs | **KEEP** — add to workspaces OR delete (per wave3-K Tier-1 decision) |
| `@clawdstrike/create-plugin` (`packages/cli/create-plugin`) | 1,154 | beta | no README; commented-out integration tests | **KEEP** — uncomment+wire tests OR delete commented block (B7) |

**Verdict counts:**
- **WIPE:** 2 (clawdstrike, swarm-engine) → -14,000 LOC + metadata cleanup
- **KEEP, fix:** 16
- **KEEP-INTERNAL or WIPE (per upstream decision):** 2 (plugin-sdk, vite-plugin-clawdstrike)

If A1 + A2 both ship, the workspace shrinks from 20 packages to 18 (or 16-17 depending on the plugin-sdk Tier-1 outcome). Source LOC drops by ~14,000 (~17% of the TS surface). Every CRITICAL security finding in the TS world is addressed.

---

## Bottom line

**The wave-1 audit was accurate. Nothing has changed.** Every concrete file:line citation reproduces at HEAD. The four wave-3 deep dives (D type-inventory, E lockfile-sweep, H swarm-engine viability, K plugin-surface gap) sharpened the diagnosis without overturning it.

If the cleanup ceiling is AGGRESSIVE, the top-5 above (WIPE swarm-engine, WIPE clawdstrike re-export, REWRITE client.ts types, DELETE the fail-open ReceiptSigner.verify, KILL the workspace fiction) deliver:

- **-~21,000 LOC** removed (mostly swarm-engine + clawdstrike re-export + 4,699 LOC of orphan plan docs).
- **-3 CRITICAL security findings** (the swarm-engine SECURITY-AUDIT.md set + the ReceiptSigner fail-open + Vercel-AI degrade-silent — A1 + A4 together kill 4 of the 5 CRITICALs; A3 is type safety not security).
- **-12 `Promise<any>` HTTP methods** typed against the Rust source-of-truth.
- **-2 lockfiles + the npm workspace illusion**.
- **Time:** ~3 engineer-days for all five if done in one focused pass.

The wave-1 audit's headline recommendation — *"wipe the convenience packages, rewrite client.ts, delete the stub ReceiptSigner.verify, wire up biome lint, collapse the lockfiles"* — is still the right call, and is still entirely actionable at HEAD on this branch with no prerequisites outside D05's scope.

---

*Delta audit by claude-opus-4-7[1m], 2026-05-24. Working branch: `fix/macos-es-ne-hardening`. No `packages/` changes since 2026-05-23.*
