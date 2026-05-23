# Wave 4 — Dependency Upgrade Plan (chore/ts-sprints-23-deps-latest)

Branch: `chore/ts-sprints-23-deps-latest`
Worktree: `/Users/connor/.codex/worktrees/ts-sprints-deps-clawdstrike`
Generated: 2026-05-23 (audit only — no edits in this run)

## Headline findings

1. **TS workspace is already bleeding-edge.** Most packages are on TypeScript 6.0.3, Vitest 4.0.18, React 19.2, Vite 6 or 8, Tauri 2.x latest. The work here is mostly *coherency* (harmonising drift) rather than version bumps.
2. **Rust workspace is mostly current** — only ~14 distinct direct deps have updates available (output: `/tmp/cargo-outdated-full.txt`).
3. **`infra/vendor/` is a full 836-crate offline cargo vendor mirror**, not a patch surface. The vendored `async-nats 0.40.0` is stock (`git sha1 6426b96…`) per the chore commit `6851ec5fd` audit. **Only remaining `[patch.crates-io]` blocks are in `fuzz/Cargo.toml:21` and `examples/autonomous-sandbox/Cargo.toml:12`**, both still pointing at vendored async-nats — both *can* be dropped if the source map covers them.
4. **Three risky ecosystem-coupled bumps**: `async-nats 0.40→0.48`, `alloy 1.8→2.0`, and `thiserror 1→2` in the agent/desktop Tauri apps. Everything else is patch-/minor-safe.
5. **Tauri apps are slightly behind workspace.** `apps/agent/src-tauri` and `apps/workbench/src-tauri` are on tauri 2.11.1 vs latest 2.11.2; desktop is 2.11.2. Plugin drift: `tauri-plugin 2.5.3 / 2.5.4 / 2.6.2` across apps. Should standardise.
6. **MSRV mixed.** Workspace + desktop + workbench tauri = 1.93. `apps/agent/src-tauri/Cargo.toml:6` declares `rust-version = "1.80"` — should align to 1.93 (or explicitly accept the 1.80 floor as a constraint for the hardened ES/NE extension).
7. **`hush-ts` requires Node ≥20.19, root `engines.node = "24.11.0"`.** Mostly consistent. Several adapter packages still declare `"node": ">=18"` — bump to `>=20` to match deployment story.

---

## Section A — Rust workspace deps

Catalog of every outdated direct dep across `[workspace.dependencies]` (root `Cargo.toml`) and individual crate `Cargo.toml`s. Source: `cargo outdated --workspace --root-deps-only` saved to `/tmp/cargo-outdated-full.txt`.

### A.1 Workspace-level pins (root `Cargo.toml` `[workspace.dependencies]`)

All currently *exactly at* the latest stable EXCEPT the ones called out below. Current pin locations are `Cargo.toml:LINE`.

| Crate | Current pin (file:line) | Latest stable | Risk | Notes |
|---|---|---|---|---|
| (none in workspace deps need bumping per cargo-outdated) | — | — | — | All `[workspace.dependencies]` direct pins are already current. Drift lives in *individual crate* Cargo.tomls below. |

### A.2 Per-crate outdated (direct deps not flowing through workspace pin)

Safe-patch (no semver bump):

| Crate | Dep | Current | Latest | File | Risk |
|---|---|---|---|---|---|
| `crates/bridges/darwin-telemetry-bridge` | `fsevent-sys` | 4.1.0 | 5.2.0 | `Cargo.toml` | **major** macOS only — verify FSEvents API surface unchanged |
| `crates/services/eas-anchor` | `alloy` | 1.8.3 | 2.0.5 | `Cargo.toml` | **major** — Ethereum stack 2.0 has breaking changes (provider API, RPC types). Defer. |

Minor-bump (API stable, no major):

| Crate | Dep | Current | Latest | File | Risk |
|---|---|---|---|---|---|
| `crates/libs/hush-spine` | `x509-parser` | 0.16.0 | 0.18.1 | `Cargo.toml` | minor — review extension parser changes |
| `crates/services/hush-cli` | `regorus` | 0.9.1 | 0.10.1 | `Cargo.toml` | minor — OPA Rego engine; run rego-eval tests |
| `crates/bridges/tetragon-bridge` | `prost-build` | 0.13.5 | 0.14.3 | `Cargo.toml` (build-deps) | minor — proto codegen; rebuild + diff generated `.rs` |
| `crates/bridges/tetragon-bridge` | `tonic-build` | 0.13.1 | 0.14.6 | `Cargo.toml` (build-deps) | minor — must move with prost-build |
| `crates/bridges/hubble-bridge` | `prost-build` | 0.13.5 | 0.14.3 | `Cargo.toml` (build-deps) | minor — same |
| `crates/bridges/hubble-bridge` | `tonic-build` | 0.13.1 | 0.14.6 | `Cargo.toml` (build-deps) | minor — same |
| `crates/services/hushd` | `tokio-tungstenite` | 0.28.0 | 0.29.0 | `Cargo.toml` (dev-deps) | minor — test-only |

Major-bump (changelog review required):

| Crate | Dep | Current | Latest | File | Risk |
|---|---|---|---|---|---|
| `crates/libs/hush-core` | `criterion` | 0.5.1 | 0.8.2 | `Cargo.toml` (dev) | major — benchmark harness; rewrite of `criterion-rs` API |
| `crates/libs/clawdstrike` | `criterion` | 0.5.1 | 0.8.2 | `Cargo.toml` (dev) | major — same |
| `crates/libs/hush-core` | `getrandom` (wasm32 target) | 0.2.17 | 0.4.2 | `Cargo.toml` `[target.cfg(wasm32)]` | **major (×2)** — getrandom 0.3 dropped `js` feature, 0.4 reshaped wasm backend (`wasm_js` feature). Coupled with `rand` ecosystem move. |
| `vendor/hushspec` (workspace member or path dep) | `rand` | 0.8.6 | 0.10.1 | `vendor/hushspec/Cargo.toml` | **major (×2)** — rand 0.9 + 0.10 traits restructure |
| `vendor/hushspec` | `reqwest` | 0.12.28 | 0.13.3 | `vendor/hushspec/Cargo.toml` | major — feature names changed (`rustls-tls` is now obsolete) |
| `vendor/hushspec` | `sha2` | 0.10.9 | 0.11.0 | `vendor/hushspec/Cargo.toml` | major — RustCrypto 0.11 line |
| `infra/vendor/nono` (vendored member) | `sha2` | 0.10.9 | 0.11.0 | `infra/vendor/nono/Cargo.toml` | major — RustCrypto 0.11 |
| `infra/vendor/nono` | `getrandom` | 0.4.1 | 0.4.2 | `infra/vendor/nono/Cargo.toml` | patch but on a major-line |
| `infra/vendor/nono` | `landlock` (linux) | 0.4.4 | 0.4.5 | `infra/vendor/nono/Cargo.toml` | patch |
| `crates/libs/hush-certification` | `zip` | 0.6.6 | 8.6.0 | `Cargo.toml` | **major (×8)** — completely rewritten API. Major review. |
| `crates/services/control-api` | `zip` | 0.6.6 | 8.6.0 | `Cargo.toml` (dev) | same |
| `crates/libs/hunt-scan` | `json5` | 0.4.1 | 1.3.1 | `Cargo.toml` | **major** — API stabilised at 1.x |
| `crates/libs/hunt-scan` | `md-5` | 0.10.6 | 0.11.0 | `Cargo.toml` | major — RustCrypto 0.11 |
| `crates/libs/logos-ffi` | `sha2` | 0.10.9 | 0.11.0 | `Cargo.toml` | major — must move with all RustCrypto |

### A.3 Patches and vendor overrides

Confirmed remaining `[patch.crates-io]` blocks (audit must address before any upgrade):

- `fuzz/Cargo.toml:21` — `async-nats = { path = "../infra/vendor/async-nats" }`
- `examples/autonomous-sandbox/Cargo.toml:12` — `async-nats = { path = "../../infra/vendor/async-nats" }`

Both target the same vendored `async-nats 0.40.0` (stock per `git sha1 6426b96…`, validated in commit `6851ec5fd`). Action: **drop these two patch blocks** once the source-map in `.cargo/config.toml` (`[source.vendored-sources] directory = "infra/vendor"`) is verified to cover them — which it should, since the offline mirror is the workspace's only source. Verify by running `cargo build` in each crate with the patch removed and `--offline`.

No other crates carry `[patch.crates-io]` overrides. Earlier worry about per-app patches is resolved (commit `6851ec5fd` dropped them from `apps/agent/src-tauri/Cargo.toml`, `apps/desktop/src-tauri/Cargo.toml`, `apps/workbench/src-tauri/Cargo.toml`, and root `Cargo.toml`).

### A.4 Ecosystem coupling groups

Move these atomically inside the same batch:

- **Tokio ecosystem (already current)** — `tokio 1.50`, `tokio-stream 0.1`, `tokio-rustls 0.26` are all at latest. Patch bumps available in Tauri apps (`tokio 1.50.0 → 1.52.3`). Bump root `[workspace.dependencies] tokio = "1.50"` → `"1.52"` (`Cargo.toml:81`).
- **Serde** — already current; `serde 1.0.228`, `serde_core` split is correctly resolved.
- **Tracing** — already current.
- **RustCrypto (sha2, sha3, md-5)** — `sha2 0.10.9 → 0.11.0` requires `digest` 0.11. Touches `hush-core` (transitively), `hunt-scan` (`md-5`), `logos-ffi`, vendored `nono`, and `vendor/hushspec`. **Move all in one batch.**
- **Rand + getrandom** — `rand 0.8/0.9/0.10` mixed (see lockfile diff). `getrandom 0.2 / 0.4` mixed. `rand 0.9.4` already pinned in workspace. WASM-targeted `getrandom` is a separate path (`hush-core`, `hush-wasm`). Plan a **dedicated batch** for rand+getrandom alignment.
- **Reqwest** — currently `reqwest 0.12.28` (workspace) and `0.13.3` (apps/agent/src-tauri). Workspace pin is `"0.13"` (`Cargo.toml:143`) but lock shows 0.12.28 still resolving because `vendor/hushspec` and others pull a `0.12.x` semver line. Need a workspace-wide audit to converge on 0.13.
- **libp2p (desktop app only)** — `libp2p-core 0.43`, `libp2p-gossipsub 0.49.4`, `libp2p-noise 0.46`, `libp2p-swarm 0.47`, `libp2p-tcp 0.44`, `libp2p-yamux 0.47`, `libp2p-identity 0.2.13` (`apps/desktop/src-tauri/Cargo.toml:51-57`). Per cargo-outdated these did NOT show updates from the inner workspace, so they appear current at their respective MAJOR axes — but a full `libp2p 0.56` umbrella exists upstream. **Confirm via `cargo search libp2p-core --limit 3` in batch 3; if a coordinated bump is published, move all 7 crates together.**
- **Tauri ecosystem** — `tauri 2.11.1 / 2.11.2`, `tauri-plugin 2.5.3 / 2.5.4 / 2.6.2`. All on the 2.x series; align across all three apps (workbench, desktop, agent) and matching `tauri-build`. `@tauri-apps/api` JS is 2.11.0 / `@tauri-apps/cli` is 2.11.2 — JS side matches.
- **wasm-bindgen ecosystem** — Lockfile shows `wasm-bindgen 0.2.112`, `0.2.114`, `0.2.122` across the three Tauri lockfiles, and `0.2.122` in the workspace lock. Latest is 0.2.122. Bump the lockfiles via `cargo update -p wasm-bindgen` per app. Also: `crates/libs/hush-wasm/Cargo.toml` only pins `wasm-bindgen = "0.2"` (caret range OK).
- **alloy (eas-anchor only)** — `alloy 1.8.3 → 2.0.5` is a major version. Read alloy 2.0 changelog; reshaped provider/network types. **Defer** until after smaller batches land.
- **jsonwebtoken** — `10.4.0` is current.
- **axum / tower-http** — current at workspace level (0.8, 0.6). Agent tauri pins separately — bump to match workspace (`apps/agent/src-tauri/Cargo.toml:30,32`).

### A.5 Crypto-sensitive deps

| Dep | Current | Latest | Notes |
|---|---|---|---|
| `ed25519-dalek` | 2.2.0 | 2.2.0 | current |
| `ring` | 0.17.14 | 0.17.x | current |
| `rustls` | 0.23.40 | 0.23.x | current |
| `rustls-pki-types` | 1.14.1 | current | |
| `tokio-rustls` | 0.26.x | current | |
| `sha2` | 0.10.9 | 0.11.0 | RustCrypto 0.11 line — major; **batch separately** (Batch 6) — affects FIPS posture / digest trait surface |
| `sha3` | 0.10.x | 0.10.x | current |
| `aws_lc_rs` (jsonwebtoken backend) | implicit via `jsonwebtoken 10.4` | current | |
| `openssl` | 0.10 vendored | current | |

No crypto-bump emergencies.

---

## Section B — TypeScript workspace deps

Root: `package.json` declares only Biome 2.4.4 dev-dep; workspace is npm-managed (`packageManager: npm@10.9.0`, `bun.lock` is NOT present — the lockfile is `package-lock.json`). Note the CLAUDE doc says "bun workspaces" but the actual root uses npm. **Confirm before running `bun outdated`.**

### B.1 Already-current direct deps (npm view 2026-05-23)

| Dep | Pin range | npm latest | Status |
|---|---|---|---|
| `typescript` | ^6.0.3 (most packages) / ^5.0.0 (apps/workbench, apps/desktop) / ^5.9.3 (control-console, plugin-sdk, etc.) | **6.0.3** | drift — converge to 6.0.3 |
| `vitest` | ^4.0.18 / ^4.1.0 / ^4.1.7 / ^3.1.0 (control-console) | **4.1.7** | drift — bump control-console 3.1→4.1 |
| `vite` | ^6.0.0 (workbench, desktop) / ^8.0.14 (control-console) | **8.0.14** | drift — workbench, desktop need vite 8 migration (config changes minimal but `optimizeDeps` reshape) |
| `react` / `react-dom` | ^19.0.0 / ^19.2.x | **19.2.6** | bump caret base to 19.2.6 for explicitness |
| `@types/react` / `@types/react-dom` | ^19.0.0 / ^19.2.x | latest 19.2.x | drift |
| `@types/node` | ^22.0.0 (academy) / ^24.3.1 (workbench) / ^25.2.0 (most) / ^25.9.1 (vite-plugin) | **25.9.1** | drift |
| `next` | ^16.2.6 (academy) | **16.2.6** | current |
| `@biomejs/biome` | ^2.4.4 | **2.4.15** | minor bump |
| `tailwindcss` | ^4.0.0 / ^4.1.18 / ^4.3.0 (control-console) | **4.3.0** | drift — workbench/desktop/academy on 4.0 (or 4.x caret) need 4.3 |
| `@tauri-apps/api` | ^2.0.0 (workbench, desktop) | **2.11.0** | bump |
| `@tauri-apps/cli` | ^2.0.0 (workbench, desktop) | **2.11.2** | bump |
| `@modelcontextprotocol/sdk` | ^1.12.1 (workbench, workbench/mcp-server) | **1.29.0** | bump (no expected breaking changes in 1.x) |
| `@playwright/test` | ^1.55.0 (workbench) / ^1.60.0 (control-console) | **1.60.0** | bump workbench |
| `eslint` | ^9.0.0 (desktop) | **10.4.0** | major — defer (eslint 10 has new config surface) |
| `zod` | ^4.4.3 (workbench, devDep) / ^3.23.8 (terminal) | **4.4.3** | bump terminal (zod 3→4 is breaking — review) |
| `three` | ^0.170.0 (desktop) / ^0.183.2 (workbench) | **0.184.0** | bump |
| `@react-three/fiber` | ^9.0.0 | **9.6.1** | bump |
| `@react-three/drei` | ^10.0.0 / ^10.7.7 | **10.7.7** | bump desktop |
| `motion` | ^12.33.0 | **12.40.0** | bump |
| `framer-motion` | ^12.40.0 (control-console) | **12.40.0** | current |
| `zustand` | ^5.0.12 / ^5.0.13 | **5.0.13** | bump |

### B.2 Adapter upstream SDK pins

| Adapter | Peer/devDep | Current pin | npm latest | Risk |
|---|---|---|---|---|
| `@clawdstrike/vercel-ai` | `ai` (devDep) | ^6.0.69 | **6.0.191** | minor bump within v6 (already on AI SDK v6, ahead of "5.x" docs) |
| `@clawdstrike/vercel-ai` | `@ai-sdk/react` (devDep) | ^3.0.71 | **3.0.193** | minor bump |
| `@clawdstrike/vercel-ai` | `ai` (peer) | `>=3.0.0` | n/a | broad peer; consider tightening to `>=5 <7` |
| `@clawdstrike/vercel-ai` | `@ai-sdk/react` (peer) | `>=3.0.0` | n/a | broad peer; consider `>=2 <4` |
| `@clawdstrike/langchain` | `@langchain/core` (peer) | `>=0.1.0` | **1.1.48** | peer too broad — tighten to `>=0.3 <2`; review langchain 1.0 breaking changes |
| `@clawdstrike/claude` | (no upstream peer) — Claude Agent SDK is `@anthropic-ai/sdk` | not present | **0.98.0** | confirm whether claude adapter ships its own minimal interface; if it imports `@anthropic-ai/sdk` at runtime via apps, no pin needed here |
| `@clawdstrike/openai` | (no upstream peer) | not present | OpenAI SDK **6.39.0** / `@openai/agents` **0.11.5** | same as above — verify runtime expectations |
| `@clawdstrike/opencode` | (no peer declared) | — | — | confirm whether `opencode` package is published; current adapter has no peerDependency line |
| `@clawdstrike/openclaw` | `openclaw` (peer) | `>=2025.0.0` | unknown (private?) | skip if private |

### B.3 WASM toolchain

| Tool | Where | Current | Latest | Notes |
|---|---|---|---|---|
| `wasm-pack` | CLI tool, not a package dep | — | **0.15.0** | track separately in `mise.toml` if managed |
| `@wasm-tool/wasm-pack-plugin` | not present in any package.json scanned | — | — | not in use |
| `esbuild-wasm` | not present | — | — | not in use |
| `wasm-bindgen` (Rust) | see Section A.4 | 0.2.122 | 0.2.122 | current |

### B.4 Per-package drift summary

Run individually to confirm:

```bash
for p in packages/*/*/package.json apps/*/package.json crates/libs/hush-wasm/package.json apps/workbench/mcp-server/package.json; do
  echo "=== $p ==="
  (cd "$(dirname $p)" && npm outdated --json 2>/dev/null || true)
done > /tmp/ts-outdated-by-package.txt
```

(Note: workspaces use a single root install — `npm outdated` from root after `npm install` will give a flat view: `npm install && npm outdated --json > /tmp/ts-outdated-root.txt`.)

---

## Section C — Tauri apps

### C.1 `apps/agent/src-tauri/Cargo.toml`

- `package.rust-version = "1.80"` (line 6) — **inconsistent**. Workspace is 1.93. Either bump to 1.93 (preferred) or document why the EDR ES/NE extension constrains MSRV to 1.80.
- `tauri = "2"` resolves to **2.11.1** (lock); latest 2.11.2 → minor patch.
- `tauri-build = "2"` (build-deps line 9) — bump in lockfile.
- `tauri-plugin-shell = "2"` / `tauri-plugin-notification = "2"` — confirm both move with core tauri.
- `axum = "0.8"` (line 30) — matches workspace 0.8 ✓.
- `tower = "0.5"` / `tower-http = "0.6"` (lines 31-32) — match workspace ✓.
- `reqwest = "0.12"` (line 29) — **drift**: workspace is `0.13`. Bump to `0.13`.
- `tokio-tungstenite = "0.24"` (line 37) — workspace doesn't pin this; agent uses 0.24 while hushd dev-dep uses 0.28. Bump to 0.28 or 0.29.
- `thiserror = "1"` (line 41) — workspace is `"2.0"`; **major**. Bump to 2 and address renamed `#[from]` semantics if any. (`apps/desktop/src-tauri/Cargo.toml:32` and `apps/agent/src-tauri/Cargo.toml:41` both still on 1.)
- `dirs = "5"` (line 53) — workspace is `"6.0"`; bump to 6 (API stable, minor renames).
- `keyring = "3"` (line 54) — latest is 4.0.1; major.
- `which = "6"` (line 58) — latest is 8.0.2; bump through 7 → 8 (audit `which::which` signature changes).
- `async-nats = "0.40"` (line 67) — latest 0.48; **major coupled** (see Batch 7).
- `ed25519-dalek` features `["pem", "pkcs8"]` (line 68) — workspace omits these features; either accept duplicate resolution or hoist features to workspace pin.

### C.2 `apps/desktop/src-tauri/Cargo.toml`

- `rust-version = "1.93"` ✓
- `tauri = "2"` → resolves 2.11.2 ✓
- `reqwest = "0.13"` ✓ matches workspace
- `dirs = "6"` ✓
- `thiserror = "1"` (line 32) — **drift** to 2.0
- `async-nats = "0.40"` (line 47) — major bump candidate
- `libp2p-*` block (lines 51-57): all coupled, currently at libp2p umbrella ~0.56-equivalent. Verify availability of newer.
- `socket2 = "0.6"` (line 25) — current
- No `tauri-plugin-shell` lock drift to fix here (`tauri-plugin 2.6.2`).

### C.3 `apps/workbench/src-tauri/Cargo.toml`

- `rust-version = "1.93"` ✓
- `tauri = "2"` → 2.11.1 (vs latest 2.11.2). Bump.
- `tauri-plugin-dialog = "2"` → 2.6.0; latest 2.7.1 (minor). Bump.
- `tauri-plugin-fs = "2"` → 2.4.5; latest 2.5.1. Bump.
- `tauri-plugin-http = "2"` → 2.5.7; latest 2.5.9. Bump.
- `tauri-plugin-opener = "2"` → 2.5.3; latest 2.5.4. Bump.
- `tauri-plugin-window-state = "2"` — confirm latest; not in outdated table (likely current).
- `tauri-plugin-stronghold = "2"` + `iota_stronghold = "2"` — DELICATE crypto plugin; verify before bump.
- `portable-pty = "0.8"` (line 19) → latest 0.9.0; **SEC-PTY-001 comment in file** notes "upgrade/remove once transitive `serial` is eliminated" — pre-existing security TODO, check whether 0.9.0 drops `serial` dep.
- `toml = "0.8"` (line 17) → latest `1.1.2+spec-1.1.0`. Major. Workspace is `"0.9"` (`Cargo.toml:139`). Either bump workspace to 1.x or align workbench down to 0.9.
- `getrandom = "0.2"` (line 39) — should align to 0.4 with workspace move.

### C.4 Coherence checklist

- `tauri` line should be `version = "=2.11.2"` across all three apps after batch (avoid silent drift).
- `tauri-build` must equal `tauri` major.
- Add a workspace-level `tauri = "2.11.2"` (or `tauri.workspace = true`) — currently each app pins independently.

---

## Section D — Python (`packages/sdk/hush-py`)

### D.1 `packages/sdk/hush-py/pyproject.toml`

| Dep | Pin | Latest | Notes |
|---|---|---|---|
| `pynacl` | `>=1.5.0` | 1.5.0 | current |
| `pyyaml` | `>=6.0` | 6.0.2 | current |
| `pycryptodome` | `>=3.19.0` | 3.21.x | bump floor to `>=3.21` |
| `wcmatch` | `>=8.5` | 10.x | minor |
| `httpx` (optional) | `>=0.25` | 0.28.x | bump floor |
| `nats-py` (optional) | `>=2.0` | 2.10.x | bump floor |
| `pytest` (dev) | `>=7.0` | 8.x | bump floor |
| `pytest-asyncio` (dev) | `>=0.21` | 0.25.x | bump |
| `pytest-cov` (dev) | `>=4.0` | 6.x | bump |
| `mypy` (dev) | `>=1.0` | 1.13.x | bump |
| `ruff` (dev) | `>=0.1` | 0.8.x | bump floor to `>=0.8` |
| `openai-agents` (dev) | `>=0.0.7` | 0.x | bump |
| `requires-python` | `>=3.10` | — | consider bumping floor to 3.11 since 3.10 EOL is 2026-10 |

### D.2 `packages/sdk/hush-py/hush-native/Cargo.toml`

| Dep | Pin | Latest | Notes |
|---|---|---|---|
| `pyo3` | `0.28` | 0.28.x | current (latest 0.x release) — verify against pyo3-build-config matching |
| `pyo3-build-config` | `0.28` | 0.28.x | must equal pyo3 |
| `hex` | `"0.4"` | 0.4.3 | current |

### D.3 Maturin

Not declared in `pyproject.toml` `[build-system].requires` (uses `hatchling`). The native extension uses `pyo3` directly via `cargo build` orchestration. No maturin to upgrade.

---

## Section E — Adapter compatibility matrix

| Adapter | Upstream SDK | Current pin | Latest stable | Breaking changes since pin | Test command | Likely-broken integration points |
|---|---|---|---|---|---|---|
| `clawdstrike-vercel-ai` | `ai` | devDep `^6.0.69`, peer `>=3.0.0` | 6.0.191 | v6 introduced `streamText` reshape; we're already on v6 | `npm --workspace=packages/adapters/clawdstrike-vercel-ai test` | `tool({ execute })` arg shape; `useChat` hook (`@ai-sdk/react` 3.x) — confirm |
| `clawdstrike-vercel-ai` | `@ai-sdk/react` | devDep `^3.0.71` | 3.0.193 | message-part `type` field broadened; UI part schema | same | React 19 hook compat — already on react ^19 |
| `clawdstrike-langchain` | `@langchain/core` | peer `>=0.1.0` | 1.1.48 | LangChain 1.0 (Aug 2025) renamed agent abstractions, deprecated `RunnableSequence.from`, repositioned tool calling | `npm --workspace=packages/adapters/clawdstrike-langchain test` | tool wrapping signature in src/* — review imports of `@langchain/core/tools` |
| `clawdstrike-claude` | (none declared) | — | `@anthropic-ai/sdk` 0.98.0 | streaming API stabilised in 0.30+; tool_use blocks unchanged in 0.9x | `npm --workspace=packages/adapters/clawdstrike-claude test` | Run `poc:fail-closed` script to verify hook surface still matches Claude Agent SDK |
| `clawdstrike-openai` | (none declared) | — | `openai` 6.39.0; `@openai/agents` 0.11.5 | OpenAI SDK 5→6 added `Responses` API; `agents` SDK is pre-1.0 | `npm --workspace=packages/adapters/clawdstrike-openai test` and `npm --workspace=packages/adapters/clawdstrike-openai run poc:fail-closed` | tool calling event shape; broker-client integration in `@clawdstrike/openai` depends on `@clawdstrike/broker-client` |
| `clawdstrike-openclaw` | `openclaw` peer `>=2025.0.0` | — | private/unknown | unknown | `npm --workspace=packages/adapters/clawdstrike-openclaw test` + `e2e` | plugin manifest in `dist/plugin.js` |
| `clawdstrike-opencode` | (no peer declared) | — | unknown | unknown | `npm --workspace=packages/adapters/clawdstrike-opencode test` | none in package.json — likely accepts any opencode shape via duck typing |
| `clawdstrike-origin-core` | (foundation package) | — | — | own surface | `npm --workspace=packages/adapters/clawdstrike-origin-core test` | none external |

Action: in Batch 8 (adapter SDK pins), for each adapter package:
1. Read `src/index.ts` imports to identify the actual upstream symbols used.
2. Cross-check against latest upstream `CHANGELOG.md` / migration guide.
3. Tighten the `peerDependencies` range from `>=0.1.0`-style to bounded `>=X <Y`.
4. Bump devDep test pins to latest matching peer band.
5. Run the adapter's `vitest run` and any `poc:fail-closed` script before moving on.

---

## Section F — Phased execution plan

Each batch is intentionally small and independently revertible. Run `cargo build --workspace && cargo test --workspace` (Rust) and `npm install && npm run typecheck -ws` (TS) at the end of every batch.

### Batch 1 — Patch-only Rust bumps (safe)

**Scope:**
- `tauri 2.11.1 → 2.11.2` across `apps/agent/src-tauri` and `apps/workbench/src-tauri`.
- `tauri-plugin-dialog 2.6.0 → 2.7.1`, `-fs 2.4.5 → 2.5.1`, `-http 2.5.7 → 2.5.9`, `-opener 2.5.3 → 2.5.4` in `apps/workbench/src-tauri/Cargo.toml`.
- `axum 0.8.8 → 0.8.9`, `tower-http 0.6.8 → 0.6.11`, `tracing-subscriber 0.3.22 → 0.3.23`, `libc → 0.2.186`, `semver → 1.0.28`, `serde_json → 1.0.150`, `mac-notification-sys → 0.6.12` in `apps/agent/src-tauri/Cargo.toml` (most flow through lock update).
- Lock-only refreshes for the main workspace.

**Files:** `apps/agent/src-tauri/Cargo.toml`, `apps/workbench/src-tauri/Cargo.toml`, three `Cargo.lock` files.

**Verification:**
```bash
cargo build --workspace
(cd apps/agent/src-tauri && cargo build && cargo test)
(cd apps/desktop/src-tauri && cargo build)
(cd apps/workbench/src-tauri && cargo build)
```

**Rollback:** `git restore Cargo.lock apps/*/src-tauri/Cargo.{toml,lock}` and re-run `cargo build`.

---

### Batch 2 — Patch-only TS coherency

**Scope:** Harmonise pins (no major bumps):
- `typescript` → `^6.0.3` everywhere it's not already.
- `vitest` → `^4.1.7` (control-console moves 3.1 → 4.1; others 4.0.18 → 4.1.7).
- `@types/node` → `^25.9.1` everywhere (academy 22→25, workbench 24→25).
- `@biomejs/biome` → `^2.4.15`.
- `react`/`react-dom` caret floor → `^19.2.6`.
- `@types/react` / `@types/react-dom` → latest 19.2.x.
- `@playwright/test` → `^1.60.0` (workbench).
- `tailwindcss` → `^4.3.0` across apps that use it.
- `@tauri-apps/api` → `^2.11.0`, `@tauri-apps/cli` → `^2.11.2` (workbench, desktop).
- `motion` / `zustand` / `three` / `@react-three/fiber` / `@react-three/drei` to latest.

**Files:** every `apps/*/package.json` and `packages/*/*/package.json`, root `package.json`.

**Verification:**
```bash
rm -rf node_modules package-lock.json
npm install
for p in $(node -e "console.log(require('./package.json').workspaces.join(' '))"); do
  (cd "$p" && npm run typecheck 2>&1 | tail -5)
done
npm run format:check -ws
```

**Rollback:** `git restore package.json apps/**/package.json packages/**/package.json package-lock.json`.

---

### Batch 3 — Drop redundant `[patch.crates-io]` blocks

**Scope:** Remove the two remaining async-nats patches now that the vendor mirror handles resolution.

**Files:**
- `fuzz/Cargo.toml` (delete lines 21-22)
- `examples/autonomous-sandbox/Cargo.toml` (delete lines 12-13)

**Verification:**
```bash
(cd fuzz && cargo build --offline)
(cd examples/autonomous-sandbox && cargo build --offline)
```

**Rollback:** trivially restore the deleted block.

---

### Batch 4 — Vite 6 → 8 in `apps/workbench` and `apps/desktop`

**Scope:** Migrate from Vite 6 to Vite 8 (control-console already on 8).
- Bump `vite ^6 → ^8.0.14`.
- Bump `@vitejs/plugin-react` to ^6.0.2 (already there in some places).
- Apply Vite 7 / 8 config changes: `optimizeDeps.entries`, `build.target` defaults, removed legacy `splitVendorChunkPlugin`.

**Files:** `apps/workbench/package.json`, `apps/desktop/package.json`, `apps/*/vite.config.{ts,js}`.

**Verification:**
```bash
(cd apps/workbench && npm run build && npm run typecheck && npm test)
(cd apps/desktop && npm run build && npm run typecheck)
```

**Rollback:** restore `vite: "^6.0.0"` pin and config.

---

### Batch 5 — Minor Rust bumps (API-stable)

**Scope:**
- `x509-parser 0.16 → 0.18` (hush-spine)
- `regorus 0.9.1 → 0.10.1` (hush-cli)
- `tokio-tungstenite 0.28 → 0.29` (hushd dev-dep + agent/desktop apps)
- `dirs 5 → 6` (agent app — already current in workspace + desktop)
- `which 6 → 7` (agent app; defer 8 to Batch 9)
- Workspace `tokio = "1.50" → "1.52"` (`Cargo.toml:81`)

**Files:** `crates/libs/spine/Cargo.toml`, `crates/services/hush-cli/Cargo.toml`, `crates/services/hushd/Cargo.toml`, `apps/agent/src-tauri/Cargo.toml`, root `Cargo.toml`.

**Verification:**
```bash
cargo test --workspace
(cd apps/agent/src-tauri && cargo test)
```

**Rollback:** restore the pins; re-run `cargo build`.

---

### Batch 6 — RustCrypto 0.11 atomic move (sha2, md-5)

**Scope:** Move every direct `sha2 0.10` / `md-5 0.10` pin to `0.11`. Touches:
- `vendor/hushspec/Cargo.toml`
- `infra/vendor/nono/Cargo.toml`
- `crates/libs/hunt-scan/Cargo.toml` (`md-5`)
- `crates/libs/logos-ffi/Cargo.toml` (`sha2`)
- Workspace pin if any code uses `sha2` indirectly (none directly in `[workspace.dependencies]`; `sha2 = "0.10"` is the workspace pin in `Cargo.toml:66` — bump to `"0.11"`).
- Any code using `Digest` trait must add `digest 0.11` upgrade — the trait surface changes `update(&mut self, &[u8])` ergonomics.

**Files:** `Cargo.toml:66` (`sha2 = "0.11"`, `sha3 = "0.11"` if matching), `crates/libs/{hunt-scan,logos-ffi}/Cargo.toml`, `vendor/hushspec/Cargo.toml`, `infra/vendor/nono/Cargo.toml`, plus the vendored `infra/vendor/sha2/` mirror needs updating (`cargo vendor` re-run).

**Verification:**
```bash
cargo build --workspace
cargo test -p hush-core -p clawdstrike -p hunt-scan -p logos-ffi
(cd apps/workbench/src-tauri && cargo build)
```

**Rollback:** trivial via git restore + re-vendor.

---

### Batch 7 — async-nats 0.40 → 0.48 atomic move

**Scope:** Major bump across every consumer.
- Workspace doesn't pin async-nats in `[workspace.dependencies]`; each crate pins independently.
- Consumers: `crates/libs/spine/Cargo.toml`, `crates/services/hushd/Cargo.toml`, `crates/services/eas-anchor/Cargo.toml`, `crates/services/hush-cli/Cargo.toml` (dev), `apps/agent/src-tauri/Cargo.toml`, `apps/desktop/src-tauri/Cargo.toml`.
- Re-vendor `async-nats 0.48.0` into `infra/vendor/async-nats/` (delete and re-run `cargo vendor`).
- Update all 6 `Cargo.toml` files to `async-nats = "0.48"`.

**Breaking changes 0.40 → 0.48:**
- `Client::connect_with_options` signature reshape (auth flow).
- `Subject` and `Subscriber` types stricter (no longer `Clone`).
- `jetstream::Context` API expanded; some method renames.
- `ConnectError` enum expanded.

**Files:** 6 `Cargo.toml`, 1 `infra/vendor/async-nats/` directory, lockfiles for all three Tauri apps + main workspace, any Rust code that constructs `async_nats::*` types — search with `rg "async_nats::"`.

**Verification:**
```bash
cargo build --workspace
cargo test --workspace
(cd apps/agent/src-tauri && cargo build)
(cd apps/desktop/src-tauri && cargo build)
```

**Rollback:** restore vendored 0.40.0 from git, restore all pins.

---

### Batch 8 — Adapter SDK upgrades (one adapter per PR-equivalent)

**Order (least → most risky):**
1. `clawdstrike-vercel-ai` — bump `ai ^6.0.69 → ^6.0.191`, `@ai-sdk/react ^3.0.71 → ^3.0.193`; tighten peer ranges.
2. `clawdstrike-openai` — confirm/declare `openai 6.x` and `@openai/agents 0.11.x` as peers; bump test scaffolding.
3. `clawdstrike-claude` — confirm `@anthropic-ai/sdk 0.98.0` compat; add to peer if used directly.
4. `clawdstrike-langchain` — peer `>=0.1.0 → >=0.3 <2`; review LangChain 1.0 migration (rename of `RunnableSequence` paths if used).
5. `clawdstrike-openclaw` / `clawdstrike-opencode` — verify peer ranges; if peers are private/optional, skip.

**Files per sub-batch:** one `packages/adapters/<name>/package.json`, plus `src/**/*.ts` for any import-name changes.

**Verification per sub-batch:**
```bash
npm --workspace=packages/adapters/<name> test
npm --workspace=packages/adapters/<name> run typecheck
[ -f packages/adapters/<name>/package.json ] && grep -q poc:fail-closed packages/adapters/<name>/package.json && \
  npm --workspace=packages/adapters/<name> run poc:fail-closed
```

**Rollback:** revert the single adapter package.json + src.

---

### Batch 9 — Major Rust bumps requiring code changes

**Scope:** sequenced sub-batches; each is its own PR.
1. **`thiserror 1 → 2`** in `apps/agent/src-tauri` + `apps/desktop/src-tauri`. Mostly transparent; check `#[error]` attribute usage and removed `#[backtrace]` shim.
2. **`zip 0.6 → 8`** in `crates/libs/hush-certification` and `crates/services/control-api` (dev). API completely rewritten — `ZipWriter::start_file` signature change, options builder pattern.
3. **`json5 0.4 → 1.3`** in `crates/libs/hunt-scan`. Mostly cleanup; parser entry-point renamed.
4. **`keyring 3 → 4`** in `apps/agent/src-tauri`. macOS keychain entry-point changes.
5. **`which 7 → 8`** in `apps/agent/src-tauri`. Return-type change to `PathBuf` only.
6. **`portable-pty 0.8 → 0.9`** in `apps/workbench/src-tauri`. Confirm whether 0.9 drops `serial` (resolves SEC-PTY-001).
7. **`toml 0.8 → 1.x`** in `apps/workbench/src-tauri` + root workspace pin `toml = "0.9"` → `"1.1"`. Major; format rewritten with `toml_edit` 0.22.
8. **rand+getrandom alignment** — `rand 0.8/0.9 → 0.10`, `getrandom 0.2/0.4 → 0.4` across `vendor/hushspec`, `hush-core` (wasm32 target), `hush-wasm`, `apps/workbench/src-tauri`. Requires `wasm_js` feature on getrandom 0.4; rand 0.10 has `Rng::random_range` rename.

**Verification:** per sub-batch, `cargo test -p <affected>` and integration build of the Tauri app(s) involved.

---

### Batch 10 — libp2p coordinated move (if upstream 0.56 published)

**Scope:** Only if `cargo search libp2p-core` shows a newer umbrella. `apps/desktop/src-tauri/Cargo.toml` lines 51-57 must move together.

**Files:** `apps/desktop/src-tauri/Cargo.toml`, lockfile.

**Verification:** `(cd apps/desktop/src-tauri && cargo build && cargo test)` plus any P2P-discovery integration test.

---

### Batch 11 — alloy 1.x → 2.x (eas-anchor only)

**Scope:** `crates/services/eas-anchor/Cargo.toml` bumps `alloy 1.8.3 → 2.0.5`. Major: provider trait reshape, RPC types moved, EIP-1559 fee defaulting changed.

**Files:** `crates/services/eas-anchor/Cargo.toml`, `crates/services/eas-anchor/src/**/*.rs`.

**Verification:** `cargo test -p eas-anchor` and a manual `--check` against Sepolia/local anvil if available.

**Rollback:** straightforward.

---

### Batch 12 — Python SDK

**Scope:** `packages/sdk/hush-py/pyproject.toml` floors:
- `pycryptodome>=3.21`, `wcmatch>=10`, `httpx>=0.28`, `nats-py>=2.10`, `pytest>=8`, `pytest-asyncio>=0.25`, `pytest-cov>=6`, `mypy>=1.13`, `ruff>=0.8`, `openai-agents` bump to current.
- Optionally bump `requires-python>=3.11`.

**Files:** `packages/sdk/hush-py/pyproject.toml`.

**Verification:**
```bash
cd packages/sdk/hush-py
uv pip install -e .[dev]
pytest -x
mypy src/clawdstrike
ruff check src tests
```

**Rollback:** restore pyproject.toml.

---

### Batch 13 — Rust toolchain (defer / decide)

**Scope:** Optional bump of MSRV. Current is `rust-version = "1.93"` in workspace + 1.93 in workbench/desktop; agent declares 1.80. Latest stable is whatever rustc has shipped (verify `rustc --version`). Bumping workspace MSRV would let us simplify some `cfg` shims but breaks anyone consuming SDK crates on older toolchains.

**Action:** **Do not bump** as part of this dependency upgrade run. Open a separate `chore/msrv-bump` later. Do, however:
- Align `apps/agent/src-tauri/Cargo.toml:6` from `"1.80"` to `"1.93"` (or document why it lags).

---

## Section G — Things to defer / require human decision

1. **`eslint 9 → 10`** (apps/desktop) — flat-config v10 is a meaningful migration; defer to a dedicated lint-only PR.
2. **`alloy 1 → 2`** (Batch 11) — runs through production attestation flow (`eas-anchor`); needs Ethereum integration sign-off. Don't lump in with other batches.
3. **`zip 0.6 → 8`** (Batch 9.2) — API completely rewritten. Defer if zip surface is only used in test fixtures; pin tighter and re-evaluate.
4. **`zod 3 → 4`** (apps/terminal) — schema validation lib in a CLI entrypoint. Defer until terminal app is back in active development.
5. **`rand 0.8 → 0.10` in `vendor/hushspec`** — `hushspec` is a vendored sibling that the formal-verification pipeline depends on. Coordinate with Aeneas/Lean owners before bumping (per CLAUDE.md note: "invasive refactors can break the formal pipeline").
6. **MSRV bump beyond 1.93** — out of scope.
7. **`tauri-plugin-stronghold` + `iota_stronghold` 2.x → next** — security-sensitive enclave plugin; bump only after reading IOTA Stronghold release notes and validating wallet flows.
8. **`portable-pty 0.8 → 0.9`** (apps/workbench) — verify the SEC-PTY-001 TODO is resolved by 0.9 before bumping; if not, file a separate issue.
9. **Re-pinning peer ranges across adapters** — needs product call on whether to support old upstream majors. The plan tightens to `>=0.3 <2` for langchain et al. as a suggested default but this is a policy choice.
10. **Vendor mirror refresh** — every Rust bump that touches a vendored crate needs `cargo vendor --offline` re-run and the resulting diff in `infra/vendor/` reviewed. Set aside a parallel review channel for vendor diffs (they're noisy and easy to rubber-stamp).
11. **`hushspec` path-versioning** — the workspace references `hushspec = { version = "0.1.1", path = "../../../vendor/hushspec" }` in `crates/libs/clawdstrike/Cargo.toml:34`. Confirm `vendor/hushspec/Cargo.toml` is the source of truth before any bump touches it.
12. **CLAUDE.md says "bun workspaces"** but `package.json` declares `packageManager: npm@10.9.0` and the repo carries `package-lock.json` not `bun.lock`. Confirm tooling story before running batches.

---

## Parallelisation map (for 4-5 agents)

Batches can run concurrently when they touch disjoint files:

- **Agent 1 (Rust patch lane):** Batch 1 → Batch 3 → Batch 5 → Batch 6
- **Agent 2 (TS lane):** Batch 2 → Batch 4 → Batch 8 (sub-batches sequential)
- **Agent 3 (Rust major lane):** Batch 7 (async-nats) → Batch 9 (thiserror, zip, json5, keyring, which, portable-pty, toml, rand+getrandom — strictly sequential)
- **Agent 4 (Python lane):** Batch 12 (independent)
- **Agent 5 (deferred / decisions):** Batch 10 (libp2p check) + Batch 11 (alloy) + Section G triage

Agents 1 and 3 must serialise around `apps/agent/src-tauri/Cargo.toml` since Batch 1 (patch) and Batch 9.1 (thiserror) both touch it — do Batch 1 first, then Batch 9.1 after.
