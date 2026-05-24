# Frontend Apps Audit

**Auditor:** Claude (Opus 4.7, 1M context)
**Scope:** Web/UI layers of `apps/control-console`, `apps/workbench`, `apps/desktop`, `apps/academy` — explicitly excluding `src-tauri/`, native platform code, and the backend `agent/` and `terminal/` shells.
**Date:** 2026-05-23

---

## Executive Summary

The frontend portfolio is split between three philosophies that have not been reconciled, and that fracture is the single most damaging professionalism signal. **`control-console`** is a tight, internally consistent React 19 SPA that sits on top of a `@backbay/glia-desktop` "OS shell" with a cohesive design system ("Artifact OS v1 — Forged Gold on Black Glass"), a custom SVG sigil set, lazy-loaded process registry, and proper light/dark theming. A senior frontend engineer would find it odd-looking but defensible — the metaphor is committed-to. **`academy`** is the most plainly polished: Next.js 16, Radix primitives, Tailwind v4 design tokens, a small focused component set, and an MDX/Pagefind content pipeline. It looks like one person who knows what they're doing built it in a weekend. **`workbench`** is the problem. It is 1032 source files (~302K LOC), 29 Zustand stores, 47 routes, a 4868-line 3D scene component, a "Spirit/Observatory/Hunt/Nexus" gamification layer that contradicts the workbench's own `MOTION_PLAN.md` ("Delight = precision engineering, NOT playfulness"), no ESLint config, no Biome coverage, both `bun.lock` AND `package-lock.json` checked in, and 102 `console.log` calls in shipped source. **`desktop`** appears to be vestigial (`package.json` name is `sdr-desktop`, a previous product), with a `SessionRail.tsx` weighing 1544 lines and a `DockSystem.tsx` at 1148 lines — and a sibling `cloud-dashboard/` directory that is a build artifact not in git.

Would a senior FE engineer be embarrassed? **Mixed.** They would not be embarrassed by `academy`. They would mildly defend `control-console` (the visual gold/obsidian aesthetic is opinionated, and the abuse of inline styles is the main weakness). They would absolutely be embarrassed by **`workbench`** — not because of any single decision, but because of the maximalism. A "Workbench IDE for security engineers" should not contain a stack with `wawa-vfx`, `r3f-forcegraph`, `react-three-rapier`, `ecctrl`, `postprocessing`, GLSL star-nest shaders, a "Spirit Ritual Manifestation Canvas", an "Observatory World" with 5840 lines of "world" logic, an avatar character controller, and weather/ghost-memory systems — alongside a CodeMirror editor that exists to write detection rules. The product has been confused with the demo. The desktop "shell" app is the second worry: it duplicates 70% of what control-console already does (CommandPalette, dock, SessionRail), runs under a stale product name, and has no clear differentiated purpose.

There is good news. The bones of a serious tool exist throughout. The `glia-desktop` framework is interesting (a real componentized OS abstraction), the academy is genuinely shippable, the `control-console` design language (gold seal stamps, noise grain, "stamp-press" decision animations) is distinctive and on-brand. Test coverage in workbench is non-trivial (300 test files) and one of them (`workbench-chunking.test.ts`) is the kind of test a careful engineer writes. The accessibility signal in workbench is reasonable (222 aria-* usages, focus-visible patterns from Base UI), and `prefers-reduced-motion` is at least mentioned. The path forward is not "wipe everything" — it is **wipe the gamification layer**, **delete `desktop/` and `cloud-dashboard/`**, **kill the inline-style habit in `control-console`**, and **enforce a single styling philosophy** before any GA conversation.

The thing to stop doing immediately: shipping the Observatory/Spirit/Nexus/Hunt 3D experience as part of a security IDE. Whatever it is, it is a different product, and its presence in `workbench` is the single biggest "this was vibe-coded" tell in the entire repo.

---

## App Inventory

| App | Purpose | Stack | Maturity | Verdict |
|---|---|---|---|---|
| `apps/control-console` | Operator web SPA — desktop OS shell with 25 windowed apps for monitoring, broker mission control, audit, policies | React 19 + Vite + TS, Tailwind v4, Zustand, framer-motion, `@backbay/glia-desktop`, biome | Beta. Solid bones, sprawling pages | **KEEP + harden** |
| `apps/workbench` | "Detection IDE" for SOC analysts — CodeMirror editor, fleet management, swarm/sentinel UI, plus 3D Observatory/Spirit/Nexus gamification | React 19 + Vite + TS, Tailwind v4, Zustand (29 stores), Base UI, R3F + drei + rapier + postprocessing + ecctrl + leva, react-router 7 HashRouter | Alpha/experimental, mixed | **HEAVILY RESTRUCTURE** |
| `apps/academy` | Static learning site — guard gallery, threat scenarios, policy lab | Next.js 16 + Tailwind v4 + Radix + MDX + Shiki + Pagefind | Beta, smallest/cleanest | **KEEP** |
| `apps/desktop` | Second desktop shell — SOC overview, swarm, attack graph, dock system | React 19 + Vite + Tauri 2, `@backbay/glia` + `glia-three`, R3F, biome + eslint | Half-built, name says "sdr-desktop" | **DELETE or REWRITE w/ clear differentiation** |
| `apps/cloud-dashboard` | Stale build artifacts only — empty source tree | n/a — `dist/` only, not in git | Dead | **DELETE** |
| `apps/agent` | Tauri shell, no frontend src | n/a | n/a | Out of scope |
| `apps/terminal` | Bun CLI, no UI | Bun + Zod | n/a | Out of scope |

---

## Scores (1–10)

| Dimension | Score | Reasoning |
|---|---:|---|
| Visual polish (from code reading) | **6/10** | `control-console` has a distinctive committed-to look; `academy` is restrained and on-brand; `workbench` is visually all-over-the-place because three subteams' aesthetics coexist (Bloomberg-terminal editor + 3D space station + Base UI primitives) |
| Component design | **5/10** | `control-console/components/ui` is 5 thin primitives — fine; `workbench` has 17 UI primitives + 461 TSX feature components and a 4868-line single file; no shared design-system package; sibling apps reinvent the same dock, palette, error boundary, lock screen |
| Accessibility signal | **5/10** | `workbench` uses Base UI + 222 aria-*, has `prefers-reduced-motion` references and focus-visible; `control-console` has 31 aria-* and 5 `role=` — its inline-styled buttons rely on `<button>` semantics but have no visible focus styles defined |
| State management | **4/10** | 29 Zustand stores in `workbench` with no clear taxonomy (4 swarm stores, 2 spirit stores, 2 observatory stores, 2 policy stores, 2 settings, 2 findings, 2 operator, etc.). Each invented its own selector pattern. No shared `create-selectors.ts` discipline applied consistently |
| Code consistency | **3/10** | 929 + 941 inline `style={{ }}` objects across two apps that both have Tailwind installed; mixed naming (PascalCase pages vs kebab-case features); workbench has no ESLint config but a `lint` script; workbench excluded from the root `biome.json` |
| Test coverage signal | **6/10** | 300 + 28 + 13 test files; some genuinely good (`workbench-chunking.test.ts`), some smoke (`App.test.tsx` shallow-mocks every page); no UI snapshot, no story system, no Playwright fixtures asserted at structural level |
| Removed/dead code | **3/10** | `apps/cloud-dashboard` is a tree of stale build output; `apps/desktop` has 70% duplicate functionality with `control-console`; `workbench/MOTION_PLAN.md` and `REALIZATION_ROADMAP.md` live in the app root; `tsbuildinfo` and `test-results/` exist in working tree; `noUnusedLocals: false` in workbench tsconfig — dead variables are silently allowed |

---

## Strengths

1. **`control-console` design language is distinctive and committed.** The "Artifact OS v1 — Forged Gold on Black Glass" CSS variable system (`apps/control-console/src/index.css:5-67`) is a real design system: surface palette, identity gold, decision-stamp semantics, animation primitives (`stamp-press`, `breathe-teal`, `glint-sweep`). It is the kind of thing a senior FE engineer would point at as evidence the team cares.
2. **Custom SVG sigil set.** `apps/control-console/src/state/processRegistry.tsx:70-543` defines 24 hand-drawn SVG icons rather than reaching for lucide. Each uses the design tokens (`var(--gold)`, `var(--teal)`). That is elite-level taste even if oversized.
3. **Lazy-loaded process registry with explicit windowing.** Pages are wrapped with `React.lazy` + `Suspense`, the desktop shell loads windows by `processId`, deep linking via `PATH_TO_PROCESS` is explicit (`ClawdStrikeDesktop.tsx:266-306`). Memoized `WindowItem`. This is the right shape.
4. **`academy` is genuinely shippable.** Routes are MDX content under `app/tracks/...`, Pagefind indexes after build, Shiki for syntax, Radix for accessible primitives, single design-token system. Small surface, well-scoped.
5. **`workbench/build/workbench-chunking.test.ts`** is a 137-line test for Vite chunk allocation — exactly the kind of guardrail a careful engineer writes for a 461-component app.
6. **Tauri Stronghold secret migration on workbench boot** (`App.tsx:295-317`) is genuine fail-closed credential hygiene.
7. **Workbench `MOTION_PLAN.md` articulates a real design philosophy** ("CRT phosphor decay, not rubber balls"). The fact that the rest of the codebase contradicts it is the problem, not the document itself.
8. **`features/panes/pane-tree.ts`** + binary-tree pane system is a real editor primitive — Athas-inspired and competently done.
9. **Centralized command registry** at `apps/workbench/src/lib/command-registry.ts` is the right pattern. It exists; the question is whether the rest of the app actually routes through it.

---

## Findings

### [CRITICAL] Product confusion: `workbench` is two products glued together

- **Where**: `apps/workbench/src/features/{observatory,spirit,nexus,hunt}/**`, ~5840 LOC in `observatory/world/` alone, 4868 lines in `features/observatory/components/ObservatoryWorldCanvas.tsx`, 1449 lines in `features/spirit/components/spirit-ritual/canvas/model.ts`
- **What**: A SOC detection IDE ships with: a 3D space-station "Observatory World" with character avatar (`OBSERVATORY_ASTRONAUT_OPERATOR_*`), GLTF model loading, weather system (`observatory-weather.ts`), ghost memory (`observatory-ghost-memory.ts`), NPC crew (`npcCrew.tsx`), mission probe dispatch, "Hero Prop" autofocus DOF, spirit kinds (`tracker | lantern | forge | loom | ledger`), spirit mood reactor, spirit experience tracker, spirit field injector, spirit ritual manifestation canvas, GLSL star-nest shader. Dependencies include `wawa-vfx`, `@react-three/rapier`, `ecctrl` (character controller), `r3f-forcegraph`, `postprocessing`, `leva` (dev panel left in devDeps).
- **Why it matters**: This is the single loudest "vibecoded" signal in the entire repo. The product's stated audience is "senior security engineers, SOC analysts, threat hunters" (per `MOTION_PLAN.md`). A senior security engineer launching a detection IDE and being asked to bind a "spirit kind" to their session will close the tab. Worse, the workbench's own motion plan declares "Delight = precision engineering, NOT playfulness" — the Spirit/Observatory layer is precisely the playfulness the doc forbids. It also forces ~30 MB of WebGL dependencies into the bundle of an app whose actual job is editing detection YAML.
- **Recommended action**: **WIPE.** Move the Spirit/Observatory/Nexus/Hunt 3D layer to a separate experimental app (`apps/labs/` or similar), or delete it. Remove `wawa-vfx`, `ecctrl`, `r3f-forcegraph`, `react-three-rapier`, `postprocessing`, `leva` from workbench `package.json`. The workbench should be: editor + panes + fleet + missions + receipts. Period.
- **Effort**: large (multi-day surgical extraction, but the boundary is clean — these are all under `features/{spirit,observatory,nexus,hunt}/`)

### [CRITICAL] `apps/desktop` is vestigial and duplicates `control-console`

- **Where**: `apps/desktop/package.json` (name is `sdr-desktop`), `apps/desktop/src/shell/dock/SessionRail.tsx` (1544 lines), `apps/desktop/src/shell/dock/DockSystem.tsx` (1148 lines), `apps/desktop/src/shell/components/CommandPalette.tsx` (271 lines — duplicates control-console's), `apps/desktop/src/shell/ShellApp.tsx`
- **What**: A second Tauri+React desktop shell exists whose package name is still `sdr-desktop` (a prior product's name), reimplementing CommandPalette, dock, NavRail, ProfileMenu, SettingsView (854 lines), and 15 feature views (attack-graph, cyber-nexus, forensics, forensics-river, marketplace, network-map, openclaw, operations, policies, security-overview, settings, swarm, threat-radar, workflows). Most of these duplicate functionality already in `control-console` or `workbench`.
- **Why it matters**: Two desktop shells, three apps with their own dock + command palette, no clear differentiation in the README. A senior engineer reviewing the repo will see "they don't know what the product is."
- **Recommended action**: **DELETE** or **REWRITE with a one-sentence differentiated purpose at the top of its README** and rename it (the `sdr-desktop` name is by itself disqualifying). If the answer is "this is the operator HUD and control-console is admin", say so in code.
- **Effort**: small (delete) to medium (rewrite scope)

### [CRITICAL] `apps/cloud-dashboard` is not source code

- **Where**: `apps/cloud-dashboard/dist/`, `apps/cloud-dashboard/tsconfig.tsbuildinfo` — `git ls-files apps/cloud-dashboard/` returns nothing
- **What**: A directory in `apps/` that contains only a `dist/` build output and a `tsbuildinfo`. The source tree was deleted but the artifacts remain locally. Not tracked in git.
- **Why it matters**: Anyone exploring `apps/` sees five frontend apps and assumes cloud-dashboard is real. It's not. This is the kind of thing that gets the repo a "looks abandoned" comment in an OSS first-impression.
- **Recommended action**: **WIPE.** `rm -rf apps/cloud-dashboard`. Add it to `.gitignore` or fix whatever creates it.
- **Effort**: trivial

### [HIGH] `workbench` has no ESLint config but ships a `lint` script

- **Where**: `apps/workbench/package.json:34` (`"lint": "eslint src/"`), no `.eslintrc*`, no `eslint.config.*`, not included in root `biome.json` `files.includes`
- **What**: The lint script exists, no config exists, and ESLint will either no-op or refuse to run. The root `biome.json` explicitly lists `apps/desktop/src/**` and `apps/control-console/src/**` but omits workbench. So 461 TSX + 571 TS files have **no enforced formatting and no linting**.
- **Why it matters**: This is the largest app in the repo and it has no automated style enforcement. The 102 `console.log` calls and 41 `: any` declarations would all be caught by a stock `@typescript-eslint/recommended` + `no-console` config.
- **Recommended action**: **REWRITE** — either include workbench in `biome.json` (preferred, matches the rest of the repo) or commit an `eslint.config.js`. Either way, run it in CI.
- **Effort**: small (config + initial autofix)

### [HIGH] Mixed lockfiles in `workbench`

- **Where**: `apps/workbench/bun.lock` (104 KB) AND `apps/workbench/package-lock.json` (320 KB) both committed
- **What**: Workbench has both Bun and npm lockfiles checked in. `predev`/`prebuild` scripts use `npm` (`"build:swarm-engine": "npm --prefix ../../packages/swarm-engine run build"`), but a sibling `bun.lock` exists, plus `apps/desktop/bun.lockb` and `apps/control-console/package-lock.json`. The root has both `bun.lockb` and `package-lock.json`.
- **Why it matters**: Inevitable drift. Different installs produce different trees. CI will pick whichever runs first; local dev will pick whichever the dev's muscle memory picks. This is the kind of thing that produces "works on my machine."
- **Recommended action**: **WIPE one.** Pick a package manager. The fact that the parent monorepo uses Bun, that two of three apps have `bun.lock*`, and that the project README references `bun`, suggests Bun. Delete every `package-lock.json` and ensure `engines` is set.
- **Effort**: small

### [HIGH] 929 + 941 inline `style={{ }}` objects across the two big apps

- **Where**: `apps/control-console/src/**/*.tsx` (929 occurrences), `apps/workbench/src/**/*.tsx` (941 occurrences). Concentrated examples: `apps/control-console/src/components/shell/ClawdStrikeDesktop.tsx` (200+ inline-style lines for taskbar items, desktop icons, error fallback), `apps/control-console/src/pages/BrokerMissionControl.tsx:820-895` (mixed Tailwind + inline style on the same element repeatedly)
- **What**: Both apps install Tailwind v4 and use it for some things, but every page also defines large `style={{ display: "flex", flexDirection: "column", ... }}` blocks. The "Stamp" component (`apps/control-console/src/components/ui/Stamp.tsx`) has 12 lines of inline styles for what should be Tailwind classes or CSS module rules.
- **Why it matters**: Inline styles defeat Tailwind's purge, defeat CSS variable inheritance, can't be dark-mode-toggled at the CSS layer (only by re-running the JS expression), and signal "I started with one approach and didn't finish." This is the most pervasive code-quality tell across the two apps.
- **Recommended action**: **REWRITE** — pick Tailwind utility classes for layout (`flex flex-col items-center gap-3.5 p-6`) and CSS module / `@apply` blocks for the design-system primitives that recur (`.glass-panel`, `.stamp`). Inline `style={{}}` should be reserved for genuinely dynamic values (computed colors, computed positions).
- **Effort**: medium to large (mechanical but app-wide)

### [HIGH] 102 `console.log/warn/error` calls in shipped workbench code

- **Where**: 102 occurrences across `apps/workbench/src/**/*.tsx` (verified count). Examples: `App.tsx:155` `console.warn("[workspace-bootstrap] Init failed:", err)`, `App.tsx:308`/`314` warn calls, error boundary `console.error`
- **What**: A real logger (with namespace, levels, dev/prod gate) is absent. Direct `console` usage is sprinkled through bootstrap, error boundaries, and async catches.
- **Why it matters**: Production bundles ship `console.log`, console gets noisy in DevTools and obscures real signals, no log levels, no namespacing, no production-stripping. A senior engineer would `add a logger and a `no-console` lint rule`.
- **Recommended action**: **REWRITE** — add `apps/workbench/src/lib/logger.ts` with `debug/info/warn/error` and a `NODE_ENV` guard. Codemod all `console.*` calls. Enable `no-console` in ESLint/biome.
- **Effort**: small

### [HIGH] 29 Zustand stores in `workbench` with no taxonomy

- **Where**: All under `apps/workbench/src/features/*/stores/` and `apps/workbench/src/lib/workbench/`. Notable bloat: 4 swarm stores (`swarm-board-store.tsx` 1551 lines, `swarm-feed-store.tsx` 2101 lines, `swarm-store.tsx`, `signal-store.tsx`), 2 spirit stores, 2 observatory stores, 2 findings stores (`finding-store.tsx`, `intel-store.tsx`), 2 settings, 2 policy stores
- **What**: 29 independent stores, each invented by whoever was building that feature. Some are `.tsx` (which means they ship JSX in a store file — usually wrong), some `.ts`. No discernible naming convention (some `xxx-store`, some `useXxx`). The `lib/create-selectors.ts` helper exists but is not consistently applied.
- **Why it matters**: A new contributor cannot answer "where does X state live?" Cross-store synchronization is ad-hoc; transactional updates across stores are impossible. Memoization patterns differ store-to-store. This is what the user means by "sprawled Zustand stores."
- **Recommended action**: **RESTRUCTURE** — consolidate to ~8 stores along boundaries: `editor`, `panes`, `project`, `fleet`, `findings`, `swarm`, `operator`, `ui`. Move spirit/observatory into the experimental app per the CRITICAL finding above. Document the taxonomy in a `STATE.md` at `src/`.
- **Effort**: large

### [HIGH] 4868-line single component file

- **Where**: `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx`
- **What**: A single React component file that imports `Billboard, CameraShake, Html, Line, OrbitControls, Sparkles, Stars, Text, useGLTF` from drei, manages probe state, mission loop, ghost memory, weather, eruptions, post-FX, bloom luminance overrides, autofocus DOF, NPC crew, hero-prop interactions, and more. 4868 lines.
- **Why it matters**: Untestable, unreviewable, single point of merge conflict, single point of bundle bloat. The fact that this exists is a process failure.
- **Recommended action**: **WIPE** (per the CRITICAL on gamification removal), but if kept: decompose into one file per scene system, hoist state to a store, and split into ~30 ~150-line files.
- **Effort**: large (or trivial if deleted)

### [HIGH] Two competing UI component philosophies coexist in one repo

- **Where**: `apps/control-console/src/components/ui/` (5 primitives: GlassButton, NoiseGrain, Plate, Stamp) — bespoke, inline-style-heavy, custom CSS vars. Versus `apps/workbench/src/components/ui/` (17 primitives wrapping `@base-ui/react/*` + `cva`) — modern shadcn-style. Versus `apps/academy/src/components/ui/` (8 primitives, also shadcn-style on Radix). Versus `apps/desktop/src/components/ui/` (yet another set on `@backbay/glia`).
- **What**: Four different UI primitive systems for one product family. Buttons look different in each app, focus rings behave differently, motion durations differ.
- **Why it matters**: There is no shared design-system package. Updating button hover behavior requires changing it in four places. The user perceives "different teams built each app", because they did.
- **Recommended action**: **RESTRUCTURE** — create `packages/ui/` and migrate all four apps to it. Pick one approach (Base UI + cva is the modern choice and matches academy + workbench). control-console's "Glass" theme becomes a `theme` slot on the shared primitives.
- **Effort**: large

### [HIGH] `workbench` `tsconfig.json` disables unused-locals checks

- **Where**: `apps/workbench/tsconfig.json:21-22` — `"noUnusedLocals": false, "noUnusedParameters": false`
- **What**: TypeScript will not warn about unused variables or parameters. Combined with no ESLint, the codebase has zero dead-code signal.
- **Why it matters**: Direct cause of unreachable functions, abandoned hooks, orphan imports persisting across 1000+ files.
- **Recommended action**: **REWRITE** — flip to `true`, accept the build break, fix it. This will surface a lot of dead code, which is the point.
- **Effort**: medium (one-time cleanup)

### [HIGH] `sentinel-swarm-pages.tsx` is a 939-line "barrel of pages"

- **Where**: `apps/workbench/src/components/workbench/sentinel-swarm-pages.tsx` (939 lines), imported 6 times from `workbench-routes.tsx:93-127`
- **What**: A single file exports `SentinelsPage, SentinelCreatePage, SentinelDetailPage, FindingsPage, FindingDetailPage, IntelDetailPage`. Each `lazy()` call imports the same 939-line module to extract one named export — which defeats code-splitting (all six routes pull the full file).
- **Why it matters**: Bundle bloat (one route load = six routes' worth of code), unreviewable, and a senior FE would catch this in the first PR.
- **Recommended action**: **RESTRUCTURE** — split into six files, one per page, in `sentinels/` and `findings/` folders that already exist.
- **Effort**: small

### [MEDIUM] `apps/desktop` package name is `sdr-desktop`

- **Where**: `apps/desktop/package.json:2` — `"name": "sdr-desktop"`
- **What**: The package name references a previous product. The directory is `desktop/`. Build artifacts and any future npm publish would carry the wrong name.
- **Why it matters**: Vestigial-product naming is one of the loudest "this codebase is not loved" signals.
- **Recommended action**: **REWRITE** — rename to `@clawdstrike/desktop` (or delete, per CRITICAL above).
- **Effort**: trivial

### [MEDIUM] Workbench `App.tsx` ErrorBoundary is inline-styled with 100+ style lines

- **Where**: `apps/workbench/src/App.tsx:191-278`
- **What**: A class component error boundary with a fallback UI defined as 60 lines of inline `style={{}}` objects, then a `<style>{` block inside the render to define `@keyframes`.
- **Why it matters**: The exact same pattern is in `apps/control-console/src/components/shell/ClawdStrikeDesktop.tsx:89-146`, duplicated. The error boundary is precisely the kind of thing that should live in a shared `ui/` package and use the design system.
- **Recommended action**: **REWRITE** — promote `ErrorBoundary` to a shared package, replace inline styles with Tailwind + the existing CSS vars.
- **Effort**: small

### [MEDIUM] `workbench` ships `leva` (3D dev panel) in devDeps but no dev-only gate

- **Where**: `apps/workbench/package.json:devDependencies.leva`
- **What**: Leva is a runtime debug panel. It's in devDeps (good), but I see no `import.meta.env.DEV` gate in any `leva`-importing file (no matches for `from "leva"` actually — but the dependency exists, suggesting either drift or import via dynamic require)
- **Why it matters**: If imported, it bundles into prod. If not imported, it's dead dep. Either way, decide.
- **Recommended action**: **DOCUMENT** the intent or **WIPE** the dep.
- **Effort**: trivial

### [MEDIUM] Workbench `App.test.tsx` shallow-mocks every page

- **Where**: `apps/workbench/src/__tests__/App.test.tsx:17-50` — uses `vi.mock(...)` to replace every page component with `<div data-testid="page-X">X</div>` then asserts the right testid renders
- **What**: The "App test" is testing the router with all real page components replaced by stubs. This catches routing typos but cannot catch any real regression in a page.
- **Why it matters**: Test-coverage-by-line is misleading; this is the test pattern the user flagged ("test files that just shallow-render and check existence").
- **Recommended action**: **DOCUMENT** the test's narrow purpose ("router smoke") and add at least one real integration test per critical user flow (open file, run lint, deploy policy).
- **Effort**: medium

### [MEDIUM] `control-console` ErrorBoundary and shell duplicated logic

- **Where**: `apps/control-console/src/components/shell/ClawdStrikeDesktop.tsx:88-146` — error boundary fallback inlined per-window with 100 lines of inline styles, then again at `apps/control-console/src/components/shell/ErrorBoundary.tsx` (112 lines)
- **What**: Two error-boundary UIs, one nested inside another (`<ErrorBoundary>` wraps the app; `<ErrorBoundary fallback={...}>` wraps each window). The window-level fallback is inline JSX rather than a component.
- **Why it matters**: Inconsistency, unreviewable.
- **Recommended action**: **REWRITE** as a single `<WindowErrorFallback />` component used in both places.
- **Effort**: trivial

### [MEDIUM] 1194 `useMemo`/`useCallback` calls in workbench (avg ~2.6 per TSX file)

- **Where**: `apps/workbench/src/**/*.tsx` — 1194 occurrences across 461 files
- **What**: The density suggests defensive memoization rather than measured optimization. `ObservatoryWorldCanvas.tsx` alone has dozens; `desktop-layout.tsx` uses `useMemo` for `wrappedRegistration` whose only "computation" is object-spread.
- **Why it matters**: `useMemo`/`useCallback` are not free; they trade GC pressure and code complexity for re-render avoidance that often does not happen. React 19's compiler obviates most of these.
- **Recommended action**: **DOCUMENT** the policy: "memoize only after profiling shows a hotspot." Run the React Compiler on the project (already on React 19) and delete most manual memoization.
- **Effort**: medium

### [MEDIUM] `workbench/MOTION_PLAN.md` and `REALIZATION_ROADMAP.md` live in app root

- **Where**: `apps/workbench/MOTION_PLAN.md`, `apps/workbench/REALIZATION_ROADMAP.md`, `apps/control-console/REVIEW.md`
- **What**: Working planning docs in `apps/*/` root. These are valuable artifacts but should not be co-located with the runtime app — they survive build/deploy and clutter the package.
- **Why it matters**: Repository hygiene; planning docs belong in `docs/plans/`.
- **Recommended action**: **RESTRUCTURE** — move to `docs/plans/{workbench,control-console}/`.
- **Effort**: trivial

### [MEDIUM] Workbench has 47 routes registered (40 lazy imports) — most pages untouchable in normal flow

- **Where**: `apps/workbench/src/components/desktop/workbench-routes.tsx` (432 lines)
- **What**: 47 routes for one IDE app: lab, hunt, simulator, swarm-board, topology, compliance, receipts, library, settings, approvals, fleet, audit, home, sentinels, findings, intel, swarms, missions, guards, observatory, nexus, spirit, plus duplicates with detail variants.
- **Why it matters**: Without a sitemap or in-app navigation that surfaces all of them, most routes are orphan pages — discoverable only via URL. The user flagged "stale routes / orphan pages."
- **Recommended action**: **DOCUMENT** which routes have an entry point in the activity bar / command palette / navigation, **WIPE** the ones that don't.
- **Effort**: medium (audit + delete)

### [MEDIUM] `apps/control-console/src/pages/ExecutionProof.tsx` is 1434 lines

- **Where**: `apps/control-console/src/pages/ExecutionProof.tsx`
- **What**: One file containing the proof-loading hook, the page layout, the receipt-chain renderer, the correlation-check builder, the export hooks, the verification result rendering, the provider-state-staleness widget. 1434 lines.
- **Why it matters**: Same problem as the workbench mega-component: untestable, unreviewable, single point of conflict.
- **Recommended action**: **RESTRUCTURE** — extract `<ReceiptChain />`, `<CorrelationChecks />`, `<ProviderStates />`, `<ExportControls />` to siblings; move data fetching to `hooks/useExecutionProof.ts`.
- **Effort**: medium

### [MEDIUM] `BrokerMissionControl.tsx` is 1070 lines and mixes layout + data

- **Where**: `apps/control-console/src/pages/BrokerMissionControl.tsx`
- **What**: Loads capabilities, previews, frozen providers, replay, bundles; renders the mission, ledger, lineage, identity, execution evidence; defines `PreviewCard`, `IdentityCard`, `LineageCard`, `ExecutionTags` inline. Lots of mixed Tailwind + inline-style.
- **Why it matters**: Same family of issue. Plus duplicate `BrokerWallet` (535) and `BrokerTheater` (265) — three broker pages with overlapping responsibility could share more.
- **Recommended action**: **RESTRUCTURE** — extract sub-cards to `components/broker/*`, move data-fetching to `hooks/useBrokerMission.ts`.
- **Effort**: medium

### [LOW] Google Fonts loaded via `@import url(...)` in CSS

- **Where**: `apps/control-console/src/index.css:1`, `apps/workbench/src/globals.css:4`
- **What**: Render-blocking `@import url("https://fonts.googleapis.com/...")` at the top of stylesheets.
- **Why it matters**: Performance + privacy (FQDN ping to Google on first paint). Best practice is `<link rel="preload">` or self-hosted via `fontsource`.
- **Recommended action**: **REWRITE** — self-host fonts via `@fontsource/inter` etc., or use `next/font` for academy.
- **Effort**: small

### [LOW] Accessibility: keyboard activation for taskbar items uses ad-hoc divs

- **Where**: `apps/control-console/src/components/shell/ClawdStrikeDesktop.tsx:341-378` — a taskbar item is a `<div role="button" tabIndex={0} onKeyDown={(e) => e.key === "Enter" && handleClick(...)}>`
- **What**: Custom keyboard handling on a div rather than using a real `<button>` element. Spacebar activation is missing; Tab order behavior relies on the explicit `tabIndex={0}`.
- **Why it matters**: Real buttons are free; divs-as-buttons leak edge cases (Spacebar, screen reader semantics, contextual menus). control-console only has 31 aria-* attributes and 5 `role=` declarations across the whole src tree — a11y is weak.
- **Recommended action**: **REWRITE** — replace with `<button type="button">` styled appropriately.
- **Effort**: trivial

### [LOW] `apps/workbench/src/components/plugins/playground/` and `bottom-panel/PluginDevConsole.tsx` look like dev-only tooling

- **Where**: `apps/workbench/src/components/plugins/playground/`, `apps/workbench/src/components/bottom-panel/PluginDevConsole.tsx`
- **What**: Plugin dev tooling that should be gated behind a dev flag, not shipped to operators.
- **Why it matters**: Dev surfaces in prod = "demo shipped by mistake" (one of the user's flagged patterns).
- **Recommended action**: **DOCUMENT** whether prod ships these. If yes, **REWRITE** to gate behind `import.meta.env.DEV`. If no, mark with build-time exclusion.
- **Effort**: small

### [LOW] HashRouter used in workbench despite Tauri 2 supporting custom protocols

- **Where**: `apps/workbench/src/App.tsx:294` — "Uses HashRouter (required for Tauri -- file:// protocol does not support HTML5 history pushState)"
- **What**: The comment is outdated. Tauri 2 with `tauri://localhost` (custom protocol) supports BrowserRouter cleanly. HashRouter URLs (`/#/route`) are uglier and break some routing patterns.
- **Why it matters**: Cosmetic but a senior engineer would catch the outdated comment.
- **Recommended action**: **DOCUMENT** as known limitation or **REWRITE** to BrowserRouter with Tauri custom protocol.
- **Effort**: small

### [LOW] `apps/desktop` and `apps/workbench` both depend on `@react-three/fiber` without sharing config

- **Where**: `apps/desktop/package.json`, `apps/workbench/package.json`
- **What**: Two apps using R3F, two different versions of `three` (`^0.170.0` vs `^0.183.2`), two different `@react-three/drei` major versions. No shared R3F harness.
- **Why it matters**: Drift, two test setups, two perf budgets.
- **Recommended action**: **DOCUMENT** the divergence or move shared R3F primitives to a `packages/three-shared` if desktop survives.
- **Effort**: medium

### [LOW] `cn` utility and `tailwind-merge` patterns differ across apps

- **Where**: `apps/workbench/src/lib/utils.ts`, `apps/academy/src/lib/...`, `apps/desktop/src/lib/...`
- **What**: Each app reimplements its own `cn(...)` helper. Trivial but emblematic of "no shared lib."
- **Why it matters**: Same reason as the UI primitives — atomic duplication is the cumulative tax.
- **Recommended action**: **RESTRUCTURE** to `packages/ui/lib/cn.ts` once `packages/ui/` exists.
- **Effort**: trivial

### [LOW] `apps/control-console/src/state/lightTheme.ts` is unidiomatic

- **Where**: `apps/control-console/src/state/lightTheme.ts` — declares a `Record<string, string>` of CSS var overrides, applied via JS at runtime in `useTheme.ts:9-13`
- **What**: Light theme is applied by iterating an object and calling `documentElement.style.setProperty(prop, value)`. The CSS-native approach is `:root[data-theme="light"] { --gold: ... }` in `index.css`.
- **Why it matters**: JS-applied theme tokens lose `@media (prefers-color-scheme: light)` integration and are a FOUC vector.
- **Recommended action**: **REWRITE** to a CSS-only theme override in `index.css`.
- **Effort**: trivial

### [LOW] `processRegistry.tsx` is 989 lines for what is essentially a static config

- **Where**: `apps/control-console/src/state/processRegistry.tsx`
- **What**: 24 SVG sigil components + 25 process definitions + desktop icon groups + pinned-app config in one file.
- **Why it matters**: The icons are beautiful but they're inline data that should live in `assets/sigils/` (one SVG per file or one file of `<symbol>`s).
- **Recommended action**: **RESTRUCTURE** — extract `sigils.tsx` with the icons; keep `processRegistry.tsx` as just the process catalog.
- **Effort**: small

### [LOW] `apps/control-console` has no Storybook / no visual regression

- **Where**: N/A (absent)
- **What**: A design-system-heavy app with no visual testing. Stamp/GlassButton/NoiseGrain/Plate are pure visual primitives with no story.
- **Why it matters**: Without stories or chromatic snapshots, the design system's discipline is invisible to new contributors.
- **Recommended action**: **DOCUMENT** decision or add `@storybook/react-vite`.
- **Effort**: medium

### [LOW] Workbench `App.tsx:83-159` `useWorkspaceBootstrap` does I/O inside a hook with manual loading flag

- **Where**: `apps/workbench/src/App.tsx:83-159`
- **What**: A 77-line `useEffect` that does dynamic imports, calls `useProjectStore.getState()` imperatively (bypassing the subscriber model), and uses a manual `loadingRef` flag. Empty dep array suppresses the warning.
- **Why it matters**: Hard to test, mixes I/O with rendering lifecycle. A startup orchestrator (`bootstrap.ts`) called from `main.tsx` would be cleaner.
- **Recommended action**: **REWRITE** as a pure async bootstrap module.
- **Effort**: small

### [LOW] `apps/academy/src/app/test-mdx/page.mdx` is a test page shipped to prod

- **Where**: `apps/academy/src/app/test-mdx/page.mdx`
- **What**: A route literally named `test-mdx` exists at production URL.
- **Why it matters**: Demo route in prod — user explicitly flagged this category.
- **Recommended action**: **WIPE** or move under `__dev__/`.
- **Effort**: trivial

### [LOW] `apps/control-console/test-results/` directory exists in working tree

- **Where**: `apps/control-console/test-results/`
- **What**: Playwright output directory; should be gitignored.
- **Why it matters**: Tree noise.
- **Recommended action**: **WIPE** + add to `.gitignore`.
- **Effort**: trivial

---

## Action Plan

**Week 0 (do this before anyone else looks at the repo):**
1. `rm -rf apps/cloud-dashboard` and gitignore future copies.
2. Decide on `apps/desktop`: rename + scope it or delete it.
3. Move `MOTION_PLAN.md`, `REALIZATION_ROADMAP.md`, `REVIEW.md` to `docs/plans/`.
4. Delete `apps/academy/src/app/test-mdx/`.
5. Pick a package manager. Delete the other lockfile family.

**Week 1 (eliminate the largest tells):**
6. Extract `features/{spirit,observatory,nexus,hunt}` to `apps/labs/` (or delete). Drop `wawa-vfx`, `ecctrl`, `r3f-forcegraph`, `react-three-rapier`, `postprocessing`, `leva` from workbench.
7. Add `apps/workbench/` to `biome.json` `files.includes`. Run `biome format --write`.
8. Add a `logger` module, codemod all `console.log/warn/error` to it, enable `no-console`.
9. Split `sentinel-swarm-pages.tsx` into six files.

**Week 2 (consistency pass):**
10. Set `noUnusedLocals: true` in workbench tsconfig and fix the fallout.
11. Codemod inline `style={{}}` blocks that map cleanly to Tailwind utilities (start with layout: `flex`, `gap`, `padding`).
12. Promote shared `ErrorBoundary`, `LoadingFallback`, `Stamp`, `GlassButton`, and `cn` to a `packages/ui/` workspace.
13. Audit the 47 workbench routes; delete the ones with no entry point.

**Week 3+ (deep restructure):**
14. Decompose `ObservatoryWorldCanvas.tsx` (if kept) and `ExecutionProof.tsx` and `BrokerMissionControl.tsx`.
15. Consolidate Zustand stores to a ~8-store taxonomy.
16. Self-host fonts; remove Google Fonts `@import url(...)`.
17. Stand up React Compiler; strip defensive memoization.
18. Storybook + visual regression for the design-system primitives.

---

## Top 10 Quick Wins

1. **Delete `apps/cloud-dashboard/`** (5 min, eliminates "looks abandoned" signal).
2. **Delete `apps/academy/src/app/test-mdx/`** (1 min, kills a prod demo route).
3. **Rename `sdr-desktop` → `@clawdstrike/desktop` in `apps/desktop/package.json`** (1 min, vestigial product name).
4. **Move `MOTION_PLAN.md`, `REALIZATION_ROADMAP.md`, `REVIEW.md` into `docs/plans/`** (5 min, repo hygiene).
5. **Add `apps/workbench/src/**/*.{ts,tsx}` to root `biome.json`** (2 min, unlocks 1000+ formatting/lint fixes).
6. **Codemod `console.log/warn/error` → `logger.*` and enable `no-console`** (1 hour, removes 102 instances).
7. **Pick a package manager; delete the other set of lockfiles** (5 min decision + 1 min delete).
8. **Flip `noUnusedLocals: true` in `apps/workbench/tsconfig.json` and fix the fallout** (a few hours, exposes dead code).
9. **Split `sentinel-swarm-pages.tsx` into six files** (1 hour, restores code-splitting).
10. **Self-host fonts via `@fontsource/inter`, `@fontsource/jetbrains-mono`** (30 min, removes render-blocking Google Fonts and a privacy concern).

---

## Things to Leave Alone

- **`apps/control-console/src/index.css` design tokens.** The "Forged Gold on Black Glass" palette is opinionated, documented inline, and committed-to. Don't dilute it.
- **`apps/control-console/src/state/processRegistry.tsx` SVG sigils.** Distinctive, on-brand, and the kind of detail that separates "thoughtful" from "scaffolded." Split out of the registry file, but do not replace with lucide icons.
- **`apps/control-console/src/components/ui/Stamp.tsx` decision-stamp animation.** The `stamp-press` keyframe is a perfect micro-interaction for a security app — "decision recorded" in motion form. Keep.
- **`apps/academy` overall structure.** Don't touch beyond the `test-mdx` cleanup; it's the cleanest app in the repo.
- **`apps/workbench/build/workbench-chunking.test.ts`.** This is the test pattern other features should imitate. Don't simplify it.
- **`apps/workbench/src/features/panes/` (pane-tree, pane-store, pane-session).** Binary-tree pane system is the right primitive for an editor; the implementation is clean.
- **`apps/workbench/src/lib/command-registry.ts`** + the `lib/commands/` directory. Command registry is the right pattern; just ensure the rest of the app actually flows through it.
- **`@backbay/glia-desktop` integration in `control-console`.** The "OS-as-app" abstraction is a real architectural commitment and works.
- **The Stronghold credential migration on workbench boot** (`App.tsx:295-317`). Real security hygiene; don't simplify away.
- **Tauri Stronghold + secure-store layering in `features/settings/secure-store.ts`.** Fail-closed credential storage is the kind of thing the product page should brag about.

---

*Audit complete. ~30 findings across 4 apps. Net: the bones are good in `academy` and `control-console`; `workbench` needs a product decision (is this an IDE or a game?) before any other cleanup matters; `desktop` and `cloud-dashboard` are subtraction wins.*
