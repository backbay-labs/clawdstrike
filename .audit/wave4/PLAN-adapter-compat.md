# Adapter Compatibility Audit — TS Upstream SDKs

**Scope:** `packages/adapters/*` in `clawdstrike` repo.
**Date:** 2026-05-23 (npm versions queried live).
**Method:** read each `package.json`, grep for upstream imports, enumerate tests, cross-reference latest npm `dist-tags.latest`.

---

## Summary Table

| Adapter | Upstream pkg(s) | Pinned spec (peer / dev) | Latest stable on npm | Direct upstream imports in src? | Test coverage of upstream surface | Verdict |
|---|---|---|---|---|---|---|
| `clawdstrike-openclaw` | `openclaw` (peer, optional) | `>=2025.0.0` | unknown (not on public npm) | **No** — `OpenClawPluginAPI` is declared as a local interface (`src/plugin.ts:35-49`) | E2E fixture-driven (`tests/e2e/hello-agent.test.ts`, `tests/plugin-runtime-compat.test.ts`); no live `openclaw` runtime exercised | **Safe** (structural; upstream is optional peer) |
| `clawdstrike-vercel-ai` | `ai`, `@ai-sdk/react` | peer `>=3.0.0`; dev `ai@^6.0.69`, `@ai-sdk/react@^3.0.71` | `ai@6.0.191`, `@ai-sdk/react@3.0.193` | **Yes** — `import { useChat } from "@ai-sdk/react"`, `import type { ChatInit, UIMessage } from "ai"` (`src/react/use-secure-chat.ts:1,4`); dynamic `await import("ai")` for `experimental_wrapLanguageModel` (`src/middleware.ts:275`) | 5 vitest files including `model-middleware.test.ts` (gated on WASM), `use-secure-chat.test.tsx` (mocks `@ai-sdk/react`) | **Coordinated** — peer range `>=3.0.0` lies; code requires v4+ for `experimental_wrapLanguageModel` shape, and v6 already removed it; raise peer floor + remove or rename dynamic import |
| `clawdstrike-langchain` | `@langchain/core` (peer, optional) | `>=0.1.0` | `@langchain/core@1.1.48`, `langchain@1.4.2` | **No** — uses structural `LangChainToolLike` (`src/wrap.ts:17-28`), `_call`/`invoke` duck-typing | 5 vitest files; all use in-package fakes, no `@langchain/core` import in tests | **Safe** (structural) — but peer floor `>=0.1.0` is misleadingly low; recommend `>=0.3.0 <2` documentation note |
| `clawdstrike-claude` | `@anthropic-ai/sdk` | **not declared** (no peer/dep) | `0.98.0` | **No** — structural `ClaudeToolLike` (`src/secure-tools.ts:13-16`) | 3 vitest files (`tool-boundary`, `secure-tools`, `claude-cua-translator`); no SDK import | **Safe** (no surface coupling) — but add a peer/optional or `peerDependenciesMeta` entry for clarity |
| `clawdstrike-openai` | `openai` | **only listed in `keywords`** (`package.json:51`), no peer/dep declaration | `6.39.0` | **No** — structural `OpenAIToolLike` (`src/secure-tools.ts:14-17`); broker code targets the HTTPS surface (`src/broker.ts:28-30`) | 4 vitest files (`tool-boundary`, `secure-tools`, `openai-cua-translator`, `provider-conformance-runtime`); no SDK import | **Safe** (no surface coupling) — same as Claude; declare optional peer for honesty |
| `clawdstrike-opencode` | `opencode` / `@opencode-ai/*` | **not declared** | n/a (project is binary distro) | **No** — pure `FrameworkToolBoundary` re-export | 2 vitest files | **Safe** (structural) — flag: no integration test against real opencode binary |
| `clawdstrike-adapter-core` | none (base) | n/a | n/a | n/a | 19 vitest files including cross-adapter parity suite (`tests/cross-adapter/*`) | **Safe** (foundation) |
| `clawdstrike-broker-client` | `@noble/ed25519` | dep `^3.0.0` | `3.1.0` | Yes (`src/client.ts:3`) — uses `getPublicKeyAsync`, `signAsync` (async APIs introduced in 2.x and stable in 3.x) | 1 vitest file (`client.test.ts`, ~330 lines, covers issue/execute/stream/proof) | **Safe** — `3.0.0 → 3.1.0` is patch-range bump under `^3.0.0`, no API change |

**Key cross-cutting finding:** with the single exception of `clawdstrike-vercel-ai`, every adapter sources upstream framework types **structurally** (locally declared interfaces over duck-typed shapes), so upstream major version bumps do not directly invalidate types. The cost of that decoupling is that you also have **zero compile-time guarantee** that the shapes still match real upstream tools — the contract is enforced only by runtime tests that mostly use hand-built fakes.

---

## 1. `clawdstrike-openclaw`

- **Current upstream pin:** optional peer `openclaw >=2025.0.0` (`package.json:51`). No upstream import in source.
- **Latest stable:** `openclaw` is not published on npm under that bare name; the peer is satisfied by host runtime injection. Verdict on "latest" requires the OpenClaw distribution channel, not npm.
- **Integration surface:**
  - Plugin entry implements a hand-rolled `OpenClawPluginAPI` interface (`src/plugin.ts:35-78`) covering `registerTool`, `registerHook`, `registerTypedHook`, `logger`, `config`. Nothing is imported from `openclaw`.
  - All upstream-shaped types (`ToolCallEvent`, `InboundMessageEvent`, `CommandBuilder`, `HookHandler`, `PolicyEvent`) are owned locally (`src/types.ts`).
- **Test coverage (29 files):** see `tests/` and `src/**/*.test.ts`. Coverage hot spots: `plugin-runtime-compat.test.ts` mocks `@clawdstrike/adapter-core` and asserts hook ordering against an `EXPECTED_EVENTS` list; `cua-bridge/fixture-runtime.test.ts` runs JSON fixtures from `fixtures/policy-events/openclaw-bridge/v1/cases.json`. **No test exercises a real OpenClaw runtime**, only mocks of its hook surface.
- **Known breaking changes:** unknown — OpenClaw publishes its own release notes outside npm; web fetch needed if you want a precise drift report. Since nothing is imported, breakage can only manifest as runtime hook-signature mismatch.
- **Verdict:** **Safe** to bump alongside OpenClaw releases; risk is bounded to plugin-runtime-compat assertions if OpenClaw renames hook IDs.
- **Concrete changes for an upgrade:** none in source until a host hook is renamed; update fixture cases under `fixtures/policy-events/openclaw-bridge/v1/cases.json` and the `EXPECTED_EVENTS` list at `tests/plugin-runtime-compat.test.ts:21-30` if OpenClaw evolves the event taxonomy.

---

## 2. `clawdstrike-vercel-ai`  ⚠ highest-risk adapter

- **Current upstream pin:** peer `ai >=3.0.0`, `@ai-sdk/react >=3.0.0` (both optional, `package.json:30-41`). devDeps already on `ai@^6.0.69` and `@ai-sdk/react@^3.0.71` (`package.json:47-52`).
- **Latest stable:** `ai@6.0.191`, `@ai-sdk/react@3.0.193`, `@ai-sdk/provider@3.0.10` (all queried 2026-05-23). `ai@7` exists only as `7.0.0-canary.*`. `@ai-sdk/react@4` is also canary-only.
- **Integration surface (real imports):**
  - `src/react/use-secure-chat.ts:1` — `import { useChat } from "@ai-sdk/react";`
  - `src/react/use-secure-chat.ts:4` — `import type { ChatInit, UIMessage } from "ai";`
  - `src/react/use-secure-chat.ts:20` — derives `UseChatInitOptions<UI_MESSAGE>` by intersecting `ChatInit<UI_MESSAGE>` with `experimental_throttle` / `resume`.
  - `src/middleware.ts:275` — `const ai = (await import("ai")) as { experimental_wrapLanguageModel?: (args: unknown) => unknown };` then calls it at `src/middleware.ts:282`. Throws if missing.
  - The middleware also consumes the upstream `LanguageModelV1`-shaped object via `Proxy`, but only structurally (`src/middleware.ts:294-309`).
- **Test coverage (5 files):**
  - `src/middleware.test.ts`, `src/middleware-fail-closed.test.ts`, `src/tools.test.ts` — operate on local fakes; **do not** exercise real `ai` package.
  - `src/model-middleware.test.ts:6` — `import { getWasmModule, initWasm, isWasmBackend } from "@clawdstrike/sdk";` and gates the entire suite on WASM availability; the wrapping of `experimental_wrapLanguageModel` is not directly hit in CI when WASM is unavailable.
  - `src/react/use-secure-chat.test.tsx:12` — `vi.mock('@ai-sdk/react', () => ({ useChat: … }))`; verifies blocked tool semantics with a mocked `useChat`.
- **Known breaking changes (cross-checked against version history):**
  - `ai` v3→v4: rename `experimental_streamData`, `streamText` API revamp, `Message`/`UIMessage` split.
  - `ai` v4→v5: `experimental_wrapLanguageModel` **removed**; replaced with `wrapLanguageModel` (no `experimental_` prefix) and stricter `LanguageModelV1` provider contract. Tool format changed (`inputSchema` instead of `parameters` in some helpers).
  - `ai` v5→v6: further provider-V1→provider-V2 migration, `ChatInit` type changes, `UIMessage` parts model becomes canonical.
  - `@ai-sdk/react` v1→v2→v3: `useChat` lost `experimental_*` knobs, `onToolCall` callback shape changed (`toolCall.input` vs `toolCall.args`).
  - The repo is **already locked to `ai@^6` and `@ai-sdk/react@^3`** in devDependencies but the peer range still claims `>=3.0.0`. This is the misleading state.
- **Verdict:** **Coordinated upgrade required and partially complete.** The peer range is the lie; the source already targets v6 idioms (e.g. typed `ChatInit<UI_MESSAGE>` introduced in v5+, parameterized `UIMessage`). Two real risks remain:
  1. `experimental_wrapLanguageModel` is no longer exported by `ai@5+`. The dynamic `await import("ai")` at `src/middleware.ts:275-280` will throw the "not available" error on any consumer using `ai@5/6`. Tests do not catch this — WASM gating skips the path.
  2. `useChat`'s `onToolCall` callback in `@ai-sdk/react@3` no longer receives `{ toolCall: { toolName, args } }`; it now receives `{ toolCall: { toolName, input } }`. The cast at `src/react/use-secure-chat.ts:69` and the `args` field at `:70` are silently wrong against the real upstream.
- **Concrete code changes when bumping:**
  - `src/middleware.ts:275` — replace `experimental_wrapLanguageModel` with `wrapLanguageModel`; drop dynamic import and import statically: `import { wrapLanguageModel } from "ai";`. Remove the `Proxy`-over-promise wrapper at `:266-310` since `wrapLanguageModel` is synchronous in v5+.
  - `src/react/use-secure-chat.ts:67-71` — update tool-call shape: `toolCall: { toolName: string; input: unknown }`; rename local `args` access to `input`.
  - `src/react/use-secure-chat.ts:20-23` — `experimental_throttle` was promoted to `throttleMs` in `@ai-sdk/react@2`; remove `experimental_` prefix.
  - `package.json:30-41` — tighten peer ranges to `"ai": "^6.0.0"` and `"@ai-sdk/react": "^3.0.0"` (or, if you intend v4 canary, `^4.0.0-0`).
  - `src/react/use-secure-chat.test.tsx:12-15` — update the `vi.mock` shape; assertion at `:48-50` checks `args` which must become `input`.
  - Add an integration test that actually imports `ai`'s `wrapLanguageModel` (no WASM gate) to prevent the next silent regression.

---

## 3. `clawdstrike-langchain`

- **Current upstream pin:** optional peer `@langchain/core >=0.1.0` (`package.json:25-32`). No devDep of `@langchain/core`.
- **Latest stable:** `@langchain/core@1.1.48`, umbrella `langchain@1.4.2`.
- **Integration surface:** **structural only.** `src/wrap.ts:17-28` declares:
  ```ts
  type LangChainToolLike = Partial<{ invoke: ... }> & Partial<{ _call: ... }> & { name?: string };
  ```
  Callback handler implements the `BaseCallbackHandler` contract by duck-typing (`src/callback-handler.ts:24-30`) — `name = "clawdstrike"` and `handleToolStart`/`handleToolEnd`/`handleToolError` methods, no inheritance from upstream `BaseCallbackHandler`.
- **Test coverage (5 files):** `wrap.test.ts`, `langgraph.test.ts`, `langchain-adapter.test.ts`, `callback-handler.test.ts`, `index-compat.test.ts`. All use in-package fakes; `@langchain/core` is never imported in tests either.
- **Known breaking changes:**
  - `@langchain/core@0.2`: `Runnable.invoke` signature stable; `BaseCallbackHandler` typing tightened.
  - `@langchain/core@0.3`: LCEL legacy paths deprecated; `RunnableConfig` extended with `configurable`.
  - `@langchain/core@1.0`: officially stable; published Nov 2025. Some experimental modules removed; `tool()` helper now canonical, `StructuredTool`'s `_call` is still supported.
  - `langgraph` (peer not even declared) moved to `@langchain/langgraph@^0.2`/`^0.3`/`^1` with `StateGraph` API changes; `langgraph.ts` only assumes a `state: Record<string, unknown>` shape so it remains compatible.
- **Verdict:** **Safe** structurally; the `invoke`/`_call` duck-typing has held across 0.1 → 1.x. Risk is purely cosmetic: a peer floor of `0.1.0` discourages bumping in consumer apps.
- **Concrete changes for an upgrade:**
  - `package.json:25-32` — raise peer to `"@langchain/core": "^0.3.0 || ^1.0.0"` to signal a supported window.
  - Optionally add `@langchain/langgraph` as documented (not declared) peer for `src/langgraph.ts`.
  - No source-file edits required for `@langchain/core@1.x`.

---

## 4. `clawdstrike-claude`

- **Current upstream pin:** **none.** `@anthropic-ai/sdk` is not declared as dep, peer, or devDep. README presumably tells users to bring their own SDK.
- **Latest stable:** `@anthropic-ai/sdk@0.98.0`.
- **Integration surface:** **structural only.** `src/secure-tools.ts:13-16`:
  ```ts
  type ClaudeToolLike<TInput=unknown,TOutput=unknown> = {
    execute?: (...) => ...;
    call?: (...) => ...;
  };
  ```
  CUA translator (`src/claude-cua-translator.ts`) hardcodes the Claude tool-name set `computer / computer_use / computer.use / computer-use` and the action normalization map (`mouse_click → click`, `key_type → type`, etc.). These are derived from Anthropic's Computer Use spec, not from SDK exports.
- **Test coverage (3 files):** `tool-boundary.test.ts`, `secure-tools.test.ts`, `claude-cua-translator.test.ts`. All in-package fakes.
- **Known breaking changes:**
  - `@anthropic-ai/sdk@0.20+`: streaming switched from `event: ...` SSE wrapper to typed `MessageStream`; tool-use events became first-class.
  - `0.30+`: `tools` parameter shape, beta-headers consolidation.
  - `0.50+`: Computer Use beta header / tool name iteration (`computer_20240514` → `computer_20250124` → ...); tool-name token changes potentially invalidate the `cuaToolNames` set at `src/claude-cua-translator.ts:5`.
  - `0.90+` and `0.98`: continued tool versioning; no SDK-shape breaks that would affect this adapter because nothing is imported.
- **Verdict:** **Safe** as source; **flag** test coverage gap — no test against any real Anthropic tool object shape; the CUA name set could silently desync from the latest `computer_*` tool version.
- **Concrete changes for an upgrade:**
  - `package.json` — add an optional peer entry, e.g. `"peerDependencies": { "@anthropic-ai/sdk": ">=0.30 <1" }` with `peerDependenciesMeta` marking it optional, to make the integration explicit.
  - `src/claude-cua-translator.ts:5-6` — confirm the `cuaToolNames` set against the current `computer_2025NNNN` tool variant; consider matching by *prefix* `computer_*` already covered by `cuaToolPrefixes`, so likely no edit needed.
  - Add a contract test that mounts a real `@anthropic-ai/sdk` tool definition (or a fixture mirroring the published JSON schema) through `secureTools`.

---

## 5. `clawdstrike-openai`

- **Current upstream pin:** `openai` appears only in `keywords` (`package.json:51`); no peer/dep/devDep entry. There is an in-tree dep on `@clawdstrike/broker-client` to call OpenAI through the broker proxy.
- **Latest stable:** `openai@6.39.0`.
- **Integration surface:** **structural only** (mirrors Claude adapter). `src/secure-tools.ts:14-17` declares `OpenAIToolLike` with optional `execute`/`call`. Broker code (`src/broker.ts:30-31`) targets `https://api.openai.com/v1/responses` with hand-built fetch via the broker; no `openai` SDK import.
- **Test coverage (4 files):** `tool-boundary.test.ts`, `secure-tools.test.ts`, `openai-cua-translator.test.ts`, `provider-conformance-runtime.test.ts` (this one cross-validates the OpenAI vs Claude CUA translators with property-style checks — see `src/provider-conformance-runtime.test.ts:10,76,89`). All fakes.
- **Known breaking changes:**
  - `openai@4`: full TypeScript rewrite, `client.chat.completions.create` vs old `openai.createChatCompletion`.
  - `openai@5`: Responses API GA, `client.responses.create` becomes canonical; streaming uses `client.responses.stream`.
  - `openai@6`: Realtime API expansion, breaking changes to `Tool` typing, deprecation of `function_call` in favor of `tool_calls`. None of these affect this adapter because nothing is imported.
  - Broker `path` default `/v1/responses` (`src/broker.ts:30`) is consistent with `openai@5+`; consumers on `openai@4` with old `/v1/chat/completions` shape must override `path`.
- **Verdict:** **Safe** structurally. Test coverage gap: no contract test against a real `openai.Tool` object.
- **Concrete changes for an upgrade:**
  - `package.json` — add explicit optional peer `"openai": ">=4 <7"` for honesty.
  - `src/broker.ts:30` — leave default at `/v1/responses` (current stable); document the override path for legacy chat-completions users in the README.
  - Consider parameterizing `DEFAULT_TOOL_NAME = "responses.create"` (`src/broker.ts:28`) when the Realtime API path is wanted.

---

## 6. `clawdstrike-opencode`

- **Current upstream pin:** **none.** `opencode` is not declared anywhere.
- **Latest stable:** opencode is primarily a CLI/binary; the `@opencode-ai/*` JS publishes exist but the adapter does not depend on them.
- **Integration surface:** **none.** `src/index.ts` re-exports `FrameworkToolBoundary` with the framework name string `"opencode"` (`src/index.ts:18`). No upstream import.
- **Test coverage (2 files):** `secure-tools.test.ts`, `tool-boundary.test.ts`. All fakes.
- **Known breaking changes:** N/A — there is no upstream coupling. The risk is that opencode's tool-call IPC shape evolves and no test catches it.
- **Verdict:** **Safe** (zero coupling); **flag**: thinnest test coverage of any adapter; cannot detect upstream protocol drift.
- **Concrete changes for an upgrade:** none in source. Suggested: add a fixture-based integration test under `tests/` exercising at least one real opencode tool-call JSON.

---

## 7. `clawdstrike-adapter-core`

- **Current upstream pin:** none — this is the framework-agnostic base. devDeps: `typescript@^6.0.3`, `vitest@^4.0.18`, `@types/node@^25.2.0`.
- **Integration surface:** internal only. Defines `FrameworkAdapter`, `FrameworkToolBoundary`, `BaseToolInterceptor`, `BrokerExecutor`, `createCuaTranslator`, etc. — see exports in `src/index.ts:1-60`.
- **Test coverage:** 19 files including the cross-adapter parity suite at `tests/cross-adapter/` (`decision-parity.test.ts`, `fail-closed.test.ts`, `session-lifecycle.test.ts`, `interface-consistency.test.ts`). This is the strongest test surface in the workspace.
- **Verdict:** **Safe.** The only "upstream" is `typescript` / `vitest` / `@types/node` — bumps already at very recent versions.
- **Concrete changes for an upgrade:** none.

---

## 8. `clawdstrike-broker-client`

- **Current upstream pin:** `@noble/ed25519 ^3.0.0` (`package.json:32`).
- **Latest stable:** `@noble/ed25519@3.1.0`.
- **Integration surface:** `src/client.ts:3` — `import * as ed25519 from "@noble/ed25519";`. Uses `getPublicKeyAsync` (`:382`) and `signAsync` (`:406`). Both are stable 3.x APIs (sync `getPublicKey`/`sign` removed in 2.x in favor of `*Async` variants; 3.x is stable on that contract).
- **Test coverage:** 1 file (`src/client.test.ts`, ~330 lines): covers issue → execute, stream execution, DPoP proof binding, OpenAI provider routing.
- **Known breaking changes:**
  - `@noble/ed25519@2.0`: removed sync APIs; renamed to `*Async`.
  - `@noble/ed25519@3.0`: dropped Node 16, ESM-only, internals refactor; public API unchanged from 2.x for `getPublicKeyAsync` / `signAsync`.
  - `3.0 → 3.1`: patch-range under `^3.0.0`, no API change.
- **Verdict:** **Safe.** A semver-minor bump to `3.1.0` is already covered by `^3.0.0`.
- **Concrete changes for an upgrade:** none in source. Optionally pin to `^3.1.0` in `package.json:32` once `3.1.0` is in the lockfile.

---

## Coverage / Risk Heatmap

- **Adapters that cannot be safely upgraded without writing new tests first:**
  - `clawdstrike-opencode` — 2 test files, no upstream protocol fixture; cannot detect opencode IPC drift.
  - `clawdstrike-claude` — 3 test files, no real `@anthropic-ai/sdk` tool object exercised.
  - `clawdstrike-openai` — 4 test files but none import `openai` SDK; needs a contract test against a real `Tool` shape.

- **Adapters with stale or misleading peer ranges:**
  - `clawdstrike-vercel-ai` — peer `>=3.0.0` but code targets v6 idioms. Tighten.
  - `clawdstrike-langchain` — peer `>=0.1.0` but tests run against current core; raise to `>=0.3 || ^1`.
  - `clawdstrike-claude`, `clawdstrike-openai`, `clawdstrike-opencode` — no peer declared at all. Add optional peers.

- **Single confirmed runtime bug under latest upstream:**
  - `clawdstrike-vercel-ai/src/middleware.ts:275-282` — relies on `ai.experimental_wrapLanguageModel`, which was removed in `ai@5`. WASM-gated test (`src/model-middleware.test.ts`) is the only path that touches it, and it silently skips when WASM is unavailable. **Fix is mandatory** before declaring v6 support, even though devDeps already pin `ai@^6.0.69`.

- **Single confirmed type drift:**
  - `clawdstrike-vercel-ai/src/react/use-secure-chat.ts:69-70` — reads `toolCall.args`, but `@ai-sdk/react@3`'s `onToolCall` callback delivers `toolCall.input`. The `onToolCall?.({ toolCall } as any)` cast hides the mismatch from the compiler.

---

## Recommended Upgrade Order

1. **`clawdstrike-vercel-ai`** — fix `experimental_wrapLanguageModel` removal and `onToolCall` shape **before** any other bump, since devDeps already pull `ai@6`. This is the only adapter with a real bug under latest upstream.
2. **`clawdstrike-broker-client`** — trivial bump `@noble/ed25519` to `^3.1.0` in `package.json` (already within `^3.0.0`).
3. **`clawdstrike-langchain`** — raise peer floor in `package.json` only; no source change. Add a smoke test that imports `tool()` from `@langchain/core@1.x` to lock in compatibility.
4. **`clawdstrike-claude` / `clawdstrike-openai`** — add optional peer declarations and contract tests against real SDK tool objects.
5. **`clawdstrike-opencode`** — add a fixture-based integration test before any future bump.
6. **`clawdstrike-openclaw`** — no action required until OpenClaw renames a hook ID or evolves the bridge taxonomy; track via `fixtures/policy-events/openclaw-bridge/v1/cases.json`.
7. **`clawdstrike-adapter-core`** — no action.

---

## Files referenced in this audit

- `packages/adapters/clawdstrike-openclaw/package.json`
- `packages/adapters/clawdstrike-openclaw/src/plugin.ts`
- `packages/adapters/clawdstrike-openclaw/src/types.ts`
- `packages/adapters/clawdstrike-openclaw/tests/plugin-runtime-compat.test.ts`
- `packages/adapters/clawdstrike-vercel-ai/package.json`
- `packages/adapters/clawdstrike-vercel-ai/src/middleware.ts:275-310`
- `packages/adapters/clawdstrike-vercel-ai/src/react/use-secure-chat.ts:1-71`
- `packages/adapters/clawdstrike-vercel-ai/src/react/use-secure-chat.test.tsx:5-50`
- `packages/adapters/clawdstrike-vercel-ai/src/model-middleware.test.ts`
- `packages/adapters/clawdstrike-langchain/package.json`
- `packages/adapters/clawdstrike-langchain/src/wrap.ts:17-28`
- `packages/adapters/clawdstrike-langchain/src/callback-handler.ts:24-30`
- `packages/adapters/clawdstrike-langchain/src/langgraph.ts`
- `packages/adapters/clawdstrike-claude/package.json`
- `packages/adapters/clawdstrike-claude/src/secure-tools.ts:13-16`
- `packages/adapters/clawdstrike-claude/src/claude-cua-translator.ts:5-10`
- `packages/adapters/clawdstrike-openai/package.json`
- `packages/adapters/clawdstrike-openai/src/secure-tools.ts:14-17`
- `packages/adapters/clawdstrike-openai/src/broker.ts:28-30`
- `packages/adapters/clawdstrike-openai/src/openai-cua-translator.ts:3-7`
- `packages/adapters/clawdstrike-openai/src/provider-conformance-runtime.test.ts`
- `packages/adapters/clawdstrike-opencode/package.json`
- `packages/adapters/clawdstrike-opencode/src/index.ts`
- `packages/adapters/clawdstrike-adapter-core/src/index.ts`
- `packages/adapters/clawdstrike-broker-client/package.json`
- `packages/adapters/clawdstrike-broker-client/src/client.ts:3,382,406`
- `packages/adapters/clawdstrike-broker-client/src/client.test.ts`
