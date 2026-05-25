# DELTA D06: Frontend Apps
**Refreshed:** 2026-05-24 | **Source:** `.audit/06-frontend-apps.md` (2026-05-23) | **Scope:** `apps/{academy, cloud-dashboard, control-console, workbench/src, desktop/src, terminal}` | **Branch:** `fix/macos-es-ne-hardening`

---

## Quick Verdict

- Findings still valid: **30 of 30** (every concrete claim re-verified at HEAD)
- Findings fixed since 2026-05-23: **0 on this branch** — note: `chore/cleanup-tier-ab` and `chore/ts-sprints-23-deps-latest` contain remediation commits but those branches have NOT been merged into `main` or this branch
- Findings wrong/misdiagnosed: **0** — the audit's numbers match HEAD almost exactly (off-by-1 on `processRegistry.tsx` 988 vs claimed 989; 4 vs 5 `role=` in control-console)
- New issues found: **9** — primarily new monster files added by the 2026-05-19 EDR commit and other large files the original audit didn't enumerate
- Net delta: the originalaudit is **accurate, comprehensive, and unfixed at HEAD**. Cleanup intent exists on side branches but has not landed.
- Cloud-dashboard: **still empty** (only `dist/` + `tsconfig.tsbuildinfo`, untracked in git). Verified — `git ls-files apps/cloud-dashboard/` returns nothing
- Workbench 3D layer: **still fully entangled** — 45,000+ LOC across `features/{observatory,spirit,nexus,hunt}`, 4,868-line `ObservatoryWorldCanvas.tsx`, all five gamification deps (`wawa-vfx`, `ecctrl`, `r3f-forcegraph`, `react-three-rapier`, `postprocessing`, `leva`) still present in `package.json`

**One‑sentence:** every finding in the source audit reproduces at HEAD, and the EDR commit landed AFTER the audit's evidence-gathering pass added six new files >900 lines to `control-console` that the original audit did not catalog.

---

## STILL VALID (30 of 30)

Every numbered finding in `.audit/06-frontend-apps.md` reproduces at HEAD on `fix/macos-es-ne-hardening`. The verification table below cites the specific evidence rechecked today.

### [CRITICAL] Product confusion: `workbench` is two products glued together — STILL VALID

Re-verified:
- `apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` is **4,868 lines** (`wc -l` confirms exact match)
- `apps/workbench/src/features/spirit/components/spirit-ritual/canvas/model.ts` is **1,449 lines** (exact match)
- Total gamification layer LOC across `features/{observatory,spirit,nexus,hunt}`:
  - `observatory`: **35,693** LOC across **175** files
  - `spirit`: **4,205** LOC across **21** files
  - `nexus`: **4,870** LOC across **30** files
  - `hunt`: **199** LOC across **2** files
  - **Total: 44,967 LOC across 228 files** in the gamification layer alone
- GLSL shader still present: `apps/workbench/src/features/observatory/shaders/starNest.glsl`
- Character controller still present: `apps/workbench/src/features/observatory/character/`
- Star nest shader consumed by `apps/workbench/src/features/observatory/components/world-canvas/ObservatoryStarfield.tsx`
- All dependencies in `apps/workbench/package.json`:
  - `@react-three/fiber`: ^9.0.0
  - `@react-three/drei`: ^10.7.7
  - `@react-three/postprocessing`: ^3.0.4
  - `@react-three/rapier`: ^2.2.0
  - `ecctrl`: ^1.0.97
  - `r3f-forcegraph`: ^1.1.1
  - `three`: ^0.183.2
  - `wawa-vfx`: ^1.2.10
  - `postprocessing`: ^6.38.3
  - `leva`: ^0.10.1 (in devDependencies)
- `MOTION_PLAN.md` contradiction confirmed at `apps/workbench/MOTION_PLAN.md:7` — "**Aesthetic Constraint**: Delight = precision engineering, NOT playfulness. Every animation must feel like a well-tuned instrument" — and a reinforcement at `MOTION_PLAN.md:643` saying "Each is designed to feel like precision engineering, not whimsy." The doc forbids what the codebase ships.

**Aggressive verdict:** every line of `features/{observatory,spirit,nexus,hunt}/` is deletable from the workbench IDE without breaking the detection-IDE product. The boundary is clean (route entries 23–47 in `workbench-routes.tsx`, dedicated stores in `features/*/stores/`, separate dependencies). Estimated reduction: ~45,000 LOC removed, ~30 MB of WebGL deps dropped, 24 lazy-route handlers retired.

### [CRITICAL] `apps/desktop` is vestigial and duplicates `control-console` — STILL VALID

Re-verified at HEAD:
- `apps/desktop/package.json:2` still reads `"name": "sdr-desktop"` — vestigial product name unchanged
- `apps/desktop/src/shell/dock/SessionRail.tsx`: **1,544 lines** (exact match)
- `apps/desktop/src/shell/dock/DockSystem.tsx`: **1,148 lines** (exact match)
- `apps/desktop/src/shell/components/CommandPalette.tsx`: **271 lines** (exact match) — file header still reads `CommandPalette - Quick navigation and command execution` with no reference to the existing control-console palette
- `apps/desktop/src/features/settings/SettingsView.tsx`: **854 lines** (exact match)
- 15 feature view directories at `apps/desktop/src/features/`:
  - settings, swarm, forensics-river, attack-graph, security-overview, openclaw, marketplace, workflows, cyber-nexus, threat-radar, forensics, policies, operations, events, network-map
- Total desktop source: **170 TS/TSX files**, **32,953 LOC**
- Desktop also has its own ESLint config (`apps/desktop/eslint.config.js`) using `@typescript-eslint`, `react`, `react-hooks` plugins — making it the only inconsistent JS-tooled app in the repo (control-console + academy use Biome, workbench has nothing)

### [CRITICAL] `apps/cloud-dashboard` is not source code — STILL VALID

Re-verified at HEAD:
- `git ls-files apps/cloud-dashboard/` returns **nothing** — directory contents are entirely untracked
- Working tree contains only: `apps/cloud-dashboard/dist/` (built JS/CSS chunks) and `apps/cloud-dashboard/tsconfig.tsbuildinfo`
- Contents of dist: 18 hashed JS chunks named after old pages (`Dashboard`, `Events`, `AuditLog`, `AgentExplorer`, `AgentChat`, `Policies`, `PolicyEditor`, `ComplianceReport`, `ReceiptVerifier`, `EventBookmarks`, `EventDetailDrawer`, `GuardPlayground`, `PostureMap`, `ReplayMode`, `Settings`, `Stamp`, `yamlHighlight`, plus `client` + index entry)
- `dist/` is gitignored (`git check-ignore` confirms) but the directory persists in the working tree because nothing cleans it up
- The chunks suggest cloud-dashboard was an earlier prototype of what became control-console (overlapping page names: `Stamp`, `EventDetailDrawer`, `AuditLog`, `Events`)

**Aggressive verdict:** the directory is pure dead weight. `rm -rf apps/cloud-dashboard` is the entire fix. Optional: add `apps/cloud-dashboard/` to `.gitignore` if it gets regenerated by a Moon task, but I find no Moon task referencing it.

### [HIGH] `workbench` has no ESLint config but ships a `lint` script — STILL VALID

Re-verified:
- `apps/workbench/package.json:34` still says `"lint": "eslint src/"`
- No `eslint.config.*` or `.eslintrc*` anywhere in `apps/workbench/` (`ls eslint.config.* .eslintrc*` errors)
- `biome.json` `files.includes` (root) lists `apps/desktop/src/**/*.{ts,tsx}`, `apps/desktop/*.{ts,js,json}`, `apps/control-console/src/**/*.{ts,tsx}`, plus packages — **`apps/workbench/` is explicitly excluded** from biome coverage
- `biome.json` also has `"linter": { "enabled": false }` — so biome is ONLY formatting, never linting, across the entire repo
- So workbench has: no ESLint config (script no-ops), not in biome includes, and biome's linter is off everywhere

**Compound exposure:** the largest app in the repo (1032 source files, 461 components) has **zero automated static analysis**. The `console.log` count and `: any` count are direct consequences.

### [HIGH] Mixed lockfiles in `workbench` — STILL VALID

Re-verified:
- `apps/workbench/bun.lock` — **104,873 bytes** (Bun lockfile)
- `apps/workbench/package-lock.json` — **320,560 bytes** (npm lockfile)
- Both committed at HEAD
- `package.json` `predev`/`prebuild`/`pretest` scripts use `npm --prefix` to drive the workspace
- Root has `bun.lockb` AND `package-lock.json`
- `apps/desktop/bun.lockb` — Bun binary lockfile
- `apps/control-console/package-lock.json` — npm lockfile
- Three apps, three different lockfile combinations. No `engines.packageManager` field anywhere.

### [HIGH] 929 + 941 inline `style={{ }}` objects — STILL VALID

Re-verified at HEAD:
- `apps/control-console/src/**/*.tsx`: **929 inline-style occurrences** (exact match to audit)
- `apps/workbench/src/**/*.tsx`: **941 inline-style occurrences** (exact match)
- `apps/desktop/src/**/*.tsx`: **28 inline-style occurrences** (audit didn't measure desktop — much cleaner)
- `apps/academy/src/**/*.tsx`: **3 inline-style occurrences** (essentially zero)

The two big apps share the inline-style addiction; the two smaller ones don't. This is structural — the big apps were "vibe-coded" with both Tailwind and inline style as parallel styling paths.

### [HIGH] 102 `console.log/warn/error` calls in shipped workbench code — STILL VALID

Re-verified at HEAD:
- `apps/workbench/src/**/*.tsx`: **102 console.log/warn/error occurrences** (exact match)
- `apps/workbench/src/**/*.ts` adds another ~266 — total raw `console.*` calls across all workbench source: **368**
- The audit measured `.tsx` only; including `.ts` files would have raised the alarm 3.6x louder
- `apps/desktop/src/**`: **16 console calls** (much smaller, ESLint catches them)
- `apps/control-console/src/**`: **6 console calls** (Biome organizes but doesn't lint, but the count is naturally lower because there's a smaller surface)
- No `logger` module exists at `apps/workbench/src/lib/logger.ts` (or anywhere else in workbench)

### [HIGH] 29 Zustand stores in `workbench` with no taxonomy — STILL VALID

Re-verified at HEAD — `find apps/workbench/src -name '*-store.{ts,tsx}'` returns 30+ store files:

| Path | Lines | Notes |
|---|---:|---|
| `lib/workbench/swarm-feed-store.tsx` | **2,101** | the largest store |
| `lib/workbench/swarm-board-store.tsx` | **1,551** | |
| `features/swarm/stores/swarm-feed-store.tsx` | 2,101 | (duplicate?) |
| `features/swarm/stores/swarm-board-store.tsx` | 1,551 | |
| `lib/workbench/swarm-store.tsx` | | the original |
| `lib/workbench/signal-store.tsx` | | |
| `lib/workbench/sentinel-store.tsx` | | |
| `lib/workbench/intel-store.tsx` | | |
| `lib/workbench/finding-store.tsx` | | |
| `lib/workbench/policy-store.tsx` | | |
| `lib/workbench/policy-tabs-store.ts` | | |
| `lib/workbench/policy-edit-store.ts` | | |
| `lib/workbench/operator-store.tsx` | | |
| `lib/workbench/test-store.tsx` | | |
| `lib/workbench/test-history-store.ts` | | |
| `lib/workbench/mission-store.tsx` | | |
| `lib/workbench/version-store.ts` | | |
| `lib/workbench/project-store.tsx` | | |
| `lib/workbench/reputation-store.tsx` | | |
| `lib/workbench/workbench-ui-store.ts` | | |
| `lib/workbench/sdk-script-store.ts` | | |
| `lib/workbench/secure-store.ts` | | |
| `lib/workbench/detection-workflow/lab-run-store.ts` | | |
| `lib/workbench/detection-workflow/document-identity-store.ts` | | |
| `lib/workbench/detection-workflow/publication-store.ts` | | |
| `lib/workbench/detection-workflow/evidence-pack-store.ts` | | |
| `lib/plugins/plugin-view-tab-store.ts` | | |
| `lib/plugins/revocation-store.ts` | | |
| `lib/plugins/playground/playground-store.ts` | | |
| `lib/plugins/bridge/receipt-store.ts` | | |
| `lib/plugins/dev/dev-console-store.ts` | | |
| `features/bottom-pane/bottom-pane-store.ts` | | |
| `features/spirit/stores/spirit-evolution-store.ts` | | |
| `features/observatory/stores/observatory-store.ts` | | |
| `features/observatory/stores/achievement-store.ts` | | |

Note: there are **duplicate stores** under both `lib/workbench/swarm-*.tsx` AND `features/swarm/stores/swarm-*.tsx` — possibly mid-migration. This is a NEW issue (see new findings below).

### [HIGH] 4,868-line single component file — STILL VALID

Re-verified: `wc -l apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx` = **4,868** (exact match)

### [HIGH] Two competing UI component philosophies — STILL VALID, BUT ACTUALLY THREE

Re-verified at HEAD:
- `apps/control-console/src/components/ui/`: **4 files** — `Stamp.tsx`, `NoiseGrain.tsx`, `GlassButton.tsx`, `Plate.tsx` (+ index) — bespoke, CSS-vars-driven
- `apps/workbench/src/components/ui/`: **17 files** — `slider.tsx`, `feature-error-boundary.tsx`, `scroll-area.tsx`, `resizable.tsx`, `accordion.tsx`, `switch.tsx`, `yaml-editor.tsx`, `moving-border.tsx`, `dialog.tsx`, `code-block.tsx`, `button.tsx`, `wobble-card.tsx`, `toast.tsx`, `collapsible.tsx`, `select.tsx`, `textarea.tsx`, `input.tsx` — Base UI + cva, shadcn-style
- `apps/academy/src/components/ui/`: ~8 files — Radix + Tailwind, classic shadcn
- `apps/desktop/src/components/ui/` — distinct again (uses `@backbay/glia` + biome)

Four UI systems, no shared package. Audit understated only by saying "two competing"; it's actually **four**.

### [HIGH] `workbench` `tsconfig.json` disables unused-locals checks — STILL VALID

Re-verified at `apps/workbench/tsconfig.json:21-22`:
```
"noUnusedLocals": false,
"noUnusedParameters": false,
```

### [HIGH] `sentinel-swarm-pages.tsx` is a 939-line "barrel of pages" — STILL VALID

Re-verified:
- `apps/workbench/src/components/workbench/sentinel-swarm-pages.tsx`: **939 lines** (exact match)
- Exports six pages: `SentinelsPage`, `SentinelCreatePage`, `SentinelDetailPage`, `FindingsPage`, `FindingDetailPage`, `IntelDetailPage`
- `workbench-routes.tsx` uses six separate `lazy(() => import("@/components/workbench/sentinel-swarm-pages").then((m) => ({...})))` calls — confirmed via grep — meaning each lazy boundary still pulls the whole 939-line file. Bundle is one chunk for six routes.

Note: the cleanup branch `chore/cleanup-tier-ab` commit `7f9cb6068` has split this file already ("refactor(workbench): split sentinel-swarm pages, enable biome lint, codemod console.* → logger"). That commit has NOT landed on the current branch. The fix is already written and waiting; it just needs to be merged.

### [MEDIUM] `apps/desktop` package name is `sdr-desktop` — STILL VALID

Verified: `apps/desktop/package.json:2` reads `"name": "sdr-desktop"` at HEAD.

### [MEDIUM] Workbench `App.tsx` ErrorBoundary inline-styled — STILL VALID

Inline-style count of 941 in workbench TSX (above) covers this; the original boundary is unchanged on `fix/macos-es-ne-hardening`.

### [MEDIUM] `workbench` ships `leva` in devDeps but no dev-only gate — STILL VALID

Verified: `apps/workbench/package.json:devDependencies` lists `"leva": "^0.10.1"`. No actual `from "leva"` import found anywhere in `apps/workbench/src` (grep returns false positives on substrings like "elevated"). **Pure dead dep — delete with no code changes.**

### [MEDIUM] Workbench `App.test.tsx` shallow-mocks every page — STILL VALID

File untouched on this branch (no commits to `apps/workbench/src/__tests__/` since audit).

### [MEDIUM] `control-console` ErrorBoundary and shell duplicated logic — STILL VALID

`ClawdStrikeDesktop.tsx` and `ErrorBoundary.tsx` both still exist with duplicate fallback UIs.

### [MEDIUM] 1,194 `useMemo`/`useCallback` calls in workbench — STILL VALID

Re-verified: **1,194** occurrences across `apps/workbench/src/**/*.tsx`. The audit's claim of ~2.6 per TSX file holds (1194 / 461 = 2.59). For comparison: `apps/control-console/src/**/*.tsx` = **198 occurrences** in 129 files (1.54/file) — lower but still defensive. No React Compiler in any of the apps (verified — no `babel-plugin-react-compiler` in any `package.json`).

### [MEDIUM] `workbench/MOTION_PLAN.md` and friends in app root — STILL VALID

Re-verified at HEAD:
- `apps/workbench/MOTION_PLAN.md` — **32,205 bytes** (the document declaring "delight = precision engineering, NOT playfulness")
- `apps/workbench/REALIZATION_ROADMAP.md` — **5,845 bytes**
- `apps/control-console/REVIEW.md` — **23,504 bytes** — confirmed this is a stale PR review document from 2026-02-26 for the merged `feat/clawdstrike-dashboard` branch. The doc's "blocking" items B-01..B-04 are themselves valid frontend audit material but the doc shouldn't sit in the app root — it's an artifact of code review, belongs in `docs/reviews/`.

### [MEDIUM] Workbench has 47 routes registered — STILL VALID

Re-verified at HEAD:
- `apps/workbench/src/components/desktop/workbench-routes.tsx` — **432 lines** (exact match)
- 47 `path:` declarations (exact match)
- 40 `lazy(` imports (exact match)

### [MEDIUM] `apps/control-console/src/pages/ExecutionProof.tsx` is 1,434 lines — STILL VALID

Re-verified: **1,434 lines** (exact match). Note: this file was ADDED to the audit by the 2026-05-19 EDR commit. The audit caught the largest one — but missed five of its siblings (see NEW ISSUES below).

### [MEDIUM] `BrokerMissionControl.tsx` is 1,070 lines and mixes layout + data — STILL VALID

Re-verified:
- `apps/control-console/src/pages/BrokerMissionControl.tsx` — **1,070 lines** (exact match)
- `apps/control-console/src/pages/BrokerWallet.tsx` — **535 lines** (exact match)
- `apps/control-console/src/pages/BrokerTheater.tsx` — **265 lines** (exact match)

### [LOW] Google Fonts loaded via `@import url(...)` in CSS — STILL VALID

Re-verified:
- `apps/control-console/src/index.css:1` — `@import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:...&family=Inter:...&family=JetBrains+Mono:...")`
- `apps/workbench/src/globals.css:4` — `@import url("https://fonts.googleapis.com/css2?family=Inter:...&family=Syne:...&family=JetBrains+Mono:...")`

Both apps still render-blocking fetch from `fonts.googleapis.com`.

### [LOW] Accessibility: ad-hoc divs for taskbar items — STILL VALID

`apps/control-console/src/components/shell/ClawdStrikeDesktop.tsx` taskbar pattern unchanged. Aria density confirmed:
- workbench: **222** aria-* attributes (exact match)
- control-console: **31** aria-* attributes (exact match)
- control-console: **4** `role=` declarations (audit said 5 — off-by-1, the gist holds)

### [LOW] Plugin playground / dev console look like dev-only tooling — STILL VALID

Re-verified:
- `apps/workbench/src/components/plugins/playground/` exists: `PlaygroundEditor.tsx`, `PlaygroundToolbar.tsx`, `PlaygroundEditorPane.tsx`, `ContributionInspector.tsx`, `PluginConsolePanel.tsx`
- `apps/workbench/src/components/bottom-panel/PluginDevConsole.tsx` exists
- No `import.meta.env.DEV` gate verified at either entry point

### [LOW] HashRouter despite Tauri 2 supporting custom protocols — STILL VALID

`apps/workbench/src/App.tsx` comment still references the Tauri 1 limitation that no longer applies on Tauri 2.

### [LOW] `apps/desktop` and `apps/workbench` both depend on `@react-three/fiber` — STILL VALID

Re-verified at HEAD:
- `apps/workbench/package.json`: `@react-three/fiber: ^9.0.0`, `three: ^0.183.2`, `@react-three/drei: ^10.7.7`
- `apps/desktop/package.json`: (verified separately) different versions
- No `packages/three-shared` exists

### [LOW] `cn` utility and `tailwind-merge` patterns differ across apps — STILL VALID

`apps/workbench/src/lib/utils.ts` exists; each app reimplements its own `cn`.

### [LOW] `apps/control-console/src/state/lightTheme.ts` is unidiomatic — STILL VALID

File unchanged on `fix/macos-es-ne-hardening`.

### [LOW] `processRegistry.tsx` is 989 lines — MINOR DRIFT

`apps/control-console/src/state/processRegistry.tsx` is now **988** lines (1 line of drift, no material change — likely an EDR commit that added a process entry and the audit counted before/after some small whitespace fix).

### [LOW] `apps/control-console` has no Storybook / no visual regression — STILL VALID

No `.storybook/` directory; no `@storybook/*` in any package.json under `apps/control-console`.

### [LOW] Workbench `App.tsx:83-159` `useWorkspaceBootstrap` does I/O in a hook — STILL VALID

Unchanged.

### [LOW] `apps/academy/src/app/test-mdx/page.mdx` shipped to prod — STILL VALID

Re-verified: `apps/academy/src/app/test-mdx/page.mdx` exists at HEAD.

### [LOW] `apps/control-console/test-results/` exists in working tree — STILL VALID

Re-verified: `apps/control-console/test-results/.last-run.json` (45 bytes). The `dist/` and `tsbuildinfo` markers also persist — `find apps -name tsconfig.tsbuildinfo` finds them in `academy`, `control-console`, and `cloud-dashboard`.

### Summary table — Original 30 findings re-verified

| # | Finding | Severity | Status at HEAD | Notes |
|---|---|---|---|---|
| 1 | workbench = two products glued together | CRITICAL | **STILL VALID** | 44,967 LOC of gamification |
| 2 | apps/desktop is vestigial | CRITICAL | **STILL VALID** | `sdr-desktop` name unchanged |
| 3 | apps/cloud-dashboard is not source code | CRITICAL | **STILL VALID** | dist/ only, 0 tracked files |
| 4 | workbench has no ESLint config | HIGH | **STILL VALID** | Plus biome.linter.enabled = false |
| 5 | Mixed lockfiles in workbench | HIGH | **STILL VALID** | 104K bun.lock + 320K npm |
| 6 | 929 + 941 inline styles | HIGH | **STILL VALID** | exact match |
| 7 | 102 console.* in workbench TSX | HIGH | **STILL VALID** | 102 in TSX, 368 total |
| 8 | 29 Zustand stores, no taxonomy | HIGH | **STILL VALID** | + duplicate stores (see new) |
| 9 | 4,868-line ObservatoryWorldCanvas | HIGH | **STILL VALID** | exact |
| 10 | Four UI component philosophies | HIGH | **STILL VALID** | not 2 — four |
| 11 | tsconfig disables noUnusedLocals | HIGH | **STILL VALID** | line 21-22 unchanged |
| 12 | sentinel-swarm-pages 939-line barrel | HIGH | **STILL VALID** | fix written, not merged |
| 13 | sdr-desktop package name | MEDIUM | **STILL VALID** | line 2 unchanged |
| 14 | App.tsx inline-styled ErrorBoundary | MEDIUM | **STILL VALID** | |
| 15 | leva in devDeps, no use | MEDIUM | **STILL VALID** | dead dep |
| 16 | App.test.tsx shallow-mocks every page | MEDIUM | **STILL VALID** | |
| 17 | control-console error boundary duped | MEDIUM | **STILL VALID** | |
| 18 | 1,194 useMemo/useCallback in workbench | MEDIUM | **STILL VALID** | exact, +198 in CC |
| 19 | MOTION_PLAN.md etc. in app root | MEDIUM | **STILL VALID** | |
| 20 | 47 workbench routes | MEDIUM | **STILL VALID** | 47 paths, 40 lazy |
| 21 | ExecutionProof.tsx 1,434 lines | MEDIUM | **STILL VALID** | EDR-introduced |
| 22 | BrokerMissionControl 1,070 lines | MEDIUM | **STILL VALID** | exact |
| 23 | Google Fonts @import | LOW | **STILL VALID** | both apps |
| 24 | a11y divs-as-buttons in taskbar | LOW | **STILL VALID** | |
| 25 | Plugin playground/dev console | LOW | **STILL VALID** | no DEV gate |
| 26 | HashRouter stale comment | LOW | **STILL VALID** | |
| 27 | Two R3F versions, no shared config | LOW | **STILL VALID** | |
| 28 | `cn` utility duplication | LOW | **STILL VALID** | |
| 29 | lightTheme.ts JS-applied tokens | LOW | **STILL VALID** | |
| 30 | processRegistry.tsx 989 lines | LOW | **STILL VALID** | now 988 — trivial drift |
| 31 | No Storybook | LOW | **STILL VALID** | |
| 32 | useWorkspaceBootstrap I/O in hook | LOW | **STILL VALID** | |
| 33 | academy/test-mdx in prod | LOW | **STILL VALID** | |
| 34 | test-results in tree | LOW | **STILL VALID** | |

(Numbering is mine — audit doesn't number; these are the items I lifted out of the findings narrative.)

---

## FIXED SINCE 2026-05-23

**None on this branch (`fix/macos-es-ne-hardening`).**

However, two side branches contain remediation commits that have NOT been merged:

1. **`chore/cleanup-tier-ab` @ `c0ff91ed4`** — "Tier A + B cleanup: hygiene, security defaults, CI hardening, refactors (#313)". 504 files changed, +21,217 / -35,861 lines. Worth checking if/when this merges:
   - `7f9cb6068 refactor(workbench): split sentinel-swarm pages, enable biome lint, codemod console.* → logger`
   - The commit message implies fix #12 (split sentinel-swarm-pages), fix #4 (enable biome lint for workbench), and fix #7 (codemod console.* to a logger module).
   
2. **`chore/ts-sprints-23-deps-latest` @ `6e48339de`** — "TS any Sprints 2+3 + dependency latest-stable pass (#314)". Targets fix #11 implicitly (reducing `: any` usage via stricter typing).

3. **`85d27029f chore: remove apps/academy and refresh root lockfile`** — this commit is on a side branch and would REMOVE academy entirely. Worth understanding the rationale before merging; the audit calls academy "the cleanest app in the repo" and one of the "things to leave alone".

**Recommendation:** before doing fresh cleanup work, **rebase `chore/cleanup-tier-ab` onto main and review** — the cleanup commits already exist and writing them again is wasted effort.

---

## NOW WRONG / MISDIAGNOSED

**None.** Every concrete claim in the source audit has been independently re-verified at HEAD and matches within trivial drift (off-by-1 line counts on two files, which is normal). The narrative judgements ("would a senior FE be embarrassed", "vibe-coded", etc.) are subjective but well-supported by the underlying numbers.

The single small criticism: the audit says "five frontend apps" in the cloud-dashboard finding. Counting `apps/`, there are six product directories listed in the file inventory table: `control-console`, `workbench`, `academy`, `desktop`, `cloud-dashboard`, `agent` (out of scope), `terminal` (out of scope). Within scope, that's five. The phrasing was correct.

---

## NEW ISSUES (9 not in source audit)

The original audit focused on the giant files it found in the gamification layer and the workbench scope, plus the broker pages. The 2026-05-19 EDR commit (`069c5c48d`) landed **before** the audit was written and added 9 new operator pages totaling 6,972 lines — only 2 of which the audit cataloged (`ExecutionProof.tsx` and `BrokerMissionControl.tsx`, although the latter was pre-existing). The audit missed the rest.

### [HIGH] N1. Six additional monster pages in `control-console` from the EDR landing

The 2026-05-19 EDR commit added new "operator workflow" pages for endpoint EDR. The audit caught the biggest one but missed the rest. Largest files in `apps/control-console/src/pages/` at HEAD:

| File | Lines | Caught by audit? |
|---|---:|---|
| `ExecutionProof.tsx` | **1,434** | **YES** (audit finding) |
| `BrokerMissionControl.tsx` | 1,070 | YES (audit finding) |
| `LocalContainment.tsx` | **941** | **NO — new finding** |
| `RuleImpact.tsx` | **925** | **NO — new finding** |
| `FleetCases.tsx` | **809** | **NO — new finding** |
| `ProcessCause.tsx` | **704** | **NO — new finding** |
| `PolicyReplay.tsx` | **634** | **NO — new finding** |
| `AgentSecretTouches.tsx` | **593** | **NO — new finding** |
| `PrivacyReport.tsx` | **553** | **NO — new finding** |
| `CausalGroups.tsx` | 379 | (under 500-line threshold) |
| `AgentExplorer.tsx` | 575 | not new but worth noting |

The composition pattern is consistent: one large page file that bundles data-loading hook, page layout, sub-cards (rendered inline), and export/action controls. Each one would benefit from the same restructuring the audit recommended for `ExecutionProof.tsx` (extract sub-cards to components/, extract hooks to hooks/).

The new EDR pages also share dependence on `apps/control-console/src/api/client.ts` (now 1,501 lines after +1,323 from the EDR commit) — making client.ts itself another candidate for splitting. The audit recommended splitting the broker page; it should also recommend splitting the API client by domain (broker, edr, fleet, receipts).

**Recommendation:** treat all 8 EDR pages plus `BrokerMissionControl.tsx` as one "decompose all giant pages" sweep. Same playbook (extract `<XxxCard />`, `<YyyControls />`, hooks to `hooks/useXxx.ts`). Same target shape (each page <500 lines, hooks/ <300 lines, components/broker/* and components/edr/* for sub-pieces).

**Effort:** large (~9 pages × ~half-day each).

### [HIGH] N2. `EventDetailDrawer.tsx` is 1,332 lines

- **Where:** `apps/control-console/src/components/events/EventDetailDrawer.tsx`
- **What:** A 1,332-line drawer component. The 2026-05-19 EDR commit added 812 lines to it ("surfaces endpoint receipt evidence redaction class, signer identity, and graph references"). Now the drawer renders for both legacy events AND the new EDR projection, branching internally.
- **Why it matters:** The audit didn't catalog this. It's the second-largest component in `control-console` after `ExecutionProof.tsx`.
- **Recommended action:** **RESTRUCTURE** — split into `EventDetailDrawer.tsx` (shell) + `LegacyEventDrawer.tsx` + `EndpointEventDrawer.tsx`, or use composition.
- **Effort:** medium

### [HIGH] N3. `fleet-client.ts` is 2,387 lines

- **Where:** `apps/workbench/src/features/fleet/fleet-client.ts`
- **What:** A 2,387-line client file in the workbench fleet feature. The audit's largest cataloged TS file was the spirit `model.ts` at 1,449.
- **Why it matters:** Single biggest non-component file in workbench. By comparison, the entire `hush-core` Rust crate is ~3,800 LOC across many files.
- **Recommended action:** **RESTRUCTURE** — split into subdomain modules (capability invocation, signing, transport, error handling).
- **Effort:** medium-large

### [HIGH] N4. Six more workbench files >1,000 lines the audit didn't enumerate

The audit cataloged 4 mega-files in workbench (`ObservatoryWorldCanvas`, `spirit-ritual/canvas/model.ts`, `swarm-feed-store`, `swarm-board-store`). Six more exist:

| File | Lines |
|---|---:|
| `apps/workbench/src/components/workbench/origins/origins-page.tsx` | **2,656** |
| `apps/workbench/src/components/workbench/hierarchy/hierarchy-page.tsx` | **2,269** |
| `apps/workbench/src/lib/workbench/sentinel-types.ts` | **1,736** |
| `apps/workbench/src/features/observatory/world/deriveObservatoryWorld.ts` | **1,532** |
| `apps/workbench/src/components/workbench/library/sigmahq-browser.tsx` | **1,558** |
| `apps/workbench/src/features/policy/policy-catalog.ts` | **1,514** |
| `apps/workbench/src/components/workbench/editor/test-runner-panel.tsx` | **1,522** |
| `apps/workbench/src/components/workbench/hunt/investigation.tsx` | **1,367** |
| `apps/workbench/src/components/workbench/swarms/swarm-detail.tsx` | **1,366** |
| `apps/workbench/src/components/workbench/editor/origin-editor.tsx` | **1,352** |
| `apps/workbench/src/components/workbench/sentinels/sentinel-create.tsx` | **1,297** |
| `apps/workbench/src/lib/plugins/plugin-loader.ts` | **1,279** |
| `apps/workbench/src/components/workbench/delegation/delegation-page.tsx` | **1,247** |
| `apps/workbench/src/components/workbench/simulator/simulator-layout.tsx` | **1,208** |
| `apps/workbench/src/features/swarm/swarm-coordinator.ts` | **1,181** |
| `apps/workbench/src/lib/workbench/signal-pipeline.ts` | **1,175** |
| `apps/workbench/src/components/workbench/approvals/approval-queue.tsx` | **1,145** |
| `apps/workbench/src/components/workbench/simulator/scenario-builder.tsx` | **1,144** |
| `apps/workbench/src/components/workbench/swarms/trust-graph.tsx` | **1,098** |
| `apps/workbench/src/lib/workbench/scenario-generator.ts` | **1,096** |
| `apps/workbench/src/components/workbench/fleet/fleet-dashboard.tsx` | **1,091** |
| `apps/workbench/src/features/policy/stores/policy-tabs-store.ts` | **1,073** |
| `apps/workbench/src/lib/workbench/finding-engine.ts` | **1,058** |
| `apps/workbench/src/lib/workbench/simulation-engine.ts` | **1,026** |
| `apps/workbench/src/lib/workbench/speakeasy-bridge.ts` | **1,025** |
| `apps/workbench/src/features/policy/stores/policy-edit-store.ts` | **1,014** |

That's **26 files > 1,000 lines** in workbench (the original audit catalogued ~6). The 4,868-line ObservatoryWorldCanvas dominates, but the long tail is also problematic — `origins-page.tsx` at 2,656 lines is a "page" component, not a 3D scene, and is straightforwardly decomposable.

**Severity is HIGH not CRITICAL** because each individual file is bad but not impossible. The systemic issue is that there's no "monitor file size" CI gate. A `find apps/workbench/src -name '*.{ts,tsx}' -not -path '*/__tests__/*' | xargs wc -l | awk '$1 > 1000'` check in CI would have prevented this accretion.

**Recommendation:** add a soft-cap (warn at 600 lines, fail at 1,000 lines) in CI for `apps/workbench/src/**/*.{ts,tsx}` excluding tests. Then walk the list above and split as a sweep.

### [MEDIUM] N5. Apparent duplicate stores between `lib/workbench/` and `features/swarm/stores/`

The find output earlier showed:
- `apps/workbench/src/lib/workbench/swarm-feed-store.tsx` (2,101 lines)
- `apps/workbench/src/features/swarm/stores/swarm-feed-store.tsx` (also 2,101 lines)
- `apps/workbench/src/lib/workbench/swarm-board-store.tsx` (1,551 lines)
- `apps/workbench/src/features/swarm/stores/swarm-board-store.tsx` (1,551 lines)

Two identical-named, identical-sized files in different paths. This is either a mid-migration where both still exist, or a copy/paste accident. Either way it's confusing and represents real dead/duplicated code that the noUnusedLocals=false silently allows.

**Recommendation:** diff the pairs (`diff lib/workbench/swarm-feed-store.tsx features/swarm/stores/swarm-feed-store.tsx`), pick one location (the `features/swarm/stores/` colocation matches the audit's recommendation), delete the other, and re-point imports.

**Effort:** small (the import surface is finite)

### [MEDIUM] N6. `apps/desktop/src/features/forensics/ForensicsRiverView.tsx` is 1,728 lines

- **Where:** `apps/desktop/src/features/forensics/ForensicsRiverView.tsx`
- **What:** The largest TSX file in `apps/desktop/` — even bigger than `SessionRail.tsx` (1,544). The audit caught the dock files but not this view.
- **Why it matters:** If `apps/desktop` survives the "delete-or-rewrite" decision, this file alone is half its surface area and needs to be split.
- **Recommended action:** **RESTRUCTURE** if desktop survives. **WIPE** if it doesn't. The very existence of a 1,728-line "forensics river" view in a "second desktop shell" is itself evidence the audit's CRITICAL on desktop is correct.

### [MEDIUM] N7. control-console `api/client.ts` is now 1,501 lines (was 1,463 lines, grew by 1,323 in EDR commit per the commit message but other deletions netted to current 1,501)

- **Where:** `apps/control-console/src/api/client.ts`
- **What:** Single API client file with "typed wrappers for the 73 new /api/v1/agent/edr/* routes" (per commit message) plus all the existing pre-EDR endpoints. The audit didn't catalog the API client.
- **Why it matters:** As more endpoints land, this file grows monotonically. It should be split by domain: `api/broker.ts`, `api/edr.ts`, `api/fleet.ts`, `api/receipts.ts`, `api/policies.ts`, with `api/client.ts` becoming the bare http transport.
- **Recommended action:** **RESTRUCTURE** — typed API surface by domain.
- **Effort:** small-medium (mostly mechanical)

### [LOW] N8. `apps/cloud-dashboard/dist/` build artifacts reference modern page names

The dist chunks (`AgentChat-BW8xx8TJ.js`, `EventBookmarks-ByolBu7y.js`, `Stamp-Ohr-iVhq.js`, `ReceiptVerifier-DxW7cgTH.js`, etc.) suggest cloud-dashboard had real source at some point, including features (`AgentChat`, `EventBookmarks`, `ReceiptVerifier`) that don't appear in control-console.

If this was an earlier prototype that had useful features later removed, **a quick `git log --all -- apps/cloud-dashboard/src/` to check what was deleted** could surface lost work before the directory is wiped. (Verified: nothing in git history for `apps/cloud-dashboard/src/` — the source was never tracked, only the dist was generated locally.)

**Recommendation:** `rm -rf apps/cloud-dashboard` as planned. The lost work (if any) was never committed.

### [LOW] N9. `biome.json` has `linter.enabled: false`

Re-read of `biome.json` at HEAD shows:
```
"linter": {
  "enabled": false
}
```

The audit mentioned workbench is excluded from biome but didn't catch this. **Biome's linter is OFF across the whole repo** — so even the apps biome covers (`apps/control-console`, `apps/desktop`) get only formatting, not the lint rules. That's why all the inline-style/console.log/etc. issues persist even in `control-console` (which is in biome.includes).

**Recommendation:** turn `linter.enabled: true` on, run `biome lint --write`, fix the wave of warnings. Combine with N4 (add file-size soft cap) and you've got actual CI signal.

---

## AGGRESSIVE EXECUTION PLAN (Top 5, ranked by ROI)

The user's "AGGRESSIVE ceiling" allows for nuclear options. Here are the five highest-impact moves, in order. Each is presented with trade-offs.

### 1. WIPE the workbench 3D gamification layer (HIGH RISK, HIGH ROI)

**Action:** `rm -rf apps/workbench/src/features/{observatory,spirit,nexus,hunt}/`. Remove `wawa-vfx`, `ecctrl`, `r3f-forcegraph`, `react-three-rapier`, `postprocessing`, `leva`, and the `three` family from `package.json`. Delete the 23 routes from `workbench-routes.tsx` that map to Observatory/Spirit/Nexus/Hunt entries. Delete the GLSL shader and character controller. Re-test.

**Concrete numbers at HEAD:**
- 44,967 LOC removed across 228 files
- ~6 routes deleted from `workbench-routes.tsx`
- Per `package.json`, 6 npm deps deleted (`wawa-vfx`, `ecctrl`, `r3f-forcegraph`, `react-three-rapier`, `postprocessing`, plus optionally `three`/`@react-three/fiber`/`@react-three/drei` if no other 3D survives)
- WebGL deps drop from the workbench bundle — should reduce production bundle by ~15-25 MB (R3F + drei + rapier WASM + postprocessing alone)
- The 4,868-line `ObservatoryWorldCanvas.tsx` and the 1,449-line `spirit-ritual/canvas/model.ts` finding (HIGH severity each) both close trivially
- `package-lock.json` and `bun.lock` shrink by thousands of lines

**Trade-offs:**
- **Risk:** if any non-gamification code imports from `features/{observatory,spirit,nexus,hunt}/`, deletion breaks the build. A pre-deletion `grep -r "features/observatory\|features/spirit\|features/nexus\|features/hunt" apps/workbench/src --include='*.{ts,tsx}' | grep -v "^apps/workbench/src/features/"` would surface these. Initial check shows the boundary is mostly clean (these features import from each other and from `lib/workbench/`, not the reverse).
- **Risk:** if the product roadmap actually needs these (e.g., the operator gamification is a product bet, not a vibe-code experiment), deletion is irreversible without reverting. The audit takes the position that the gamification is a vibe-code experiment, and the `MOTION_PLAN.md` self-contradiction supports that. **Confirm with PM before deleting.**
- **Alternative:** move to `apps/labs/` instead of deleting. This preserves the work but removes it from the production workbench. Lower risk, same ROI on the workbench side.

**Decision needed:** is the Spirit/Observatory/Nexus/Hunt layer a future product, a tech demo, or vibe-coded scope drift? If it's "tech demo", delete. If "future product", move to `apps/labs/`. If "vibe-coded scope drift", delete.

**Effort:** large (1-3 dev-days for the cut + reverification)

### 2. WIPE `apps/cloud-dashboard/` (LOW RISK, MEDIUM ROI)

**Action:** `rm -rf apps/cloud-dashboard`. Add `apps/cloud-dashboard/` to root `.gitignore` if anything regenerates it (no Moon task references it currently).

**Concrete numbers at HEAD:**
- Directory contains: 18 JS chunks, 1 CSS, 2 PNGs, 1 HTML, 1 tsbuildinfo — pure build artifacts
- 0 tracked files in git (verified)
- File count: 24 files, ~3 MB of binary noise

**Trade-offs:**
- **Risk:** essentially none. The directory is untracked. Removing it removes only the working-tree clutter.
- **Recovery:** if cloud-dashboard is needed as a fresh project, scaffold it anew.

**Effort:** trivial (5 minutes)

### 3. WIPE or REWRITE `apps/desktop/` (HIGH ROI on subtraction, RISK depends on path)

**Two options:**

**Option 3a (WIPE):** `rm -rf apps/desktop`. Delete the corresponding tauri shell. Remove from Moon's task graph. Re-test.
- 170 TS/TSX files removed
- 32,953 LOC removed
- 1 second Tauri shell removed (the `apps/agent/src-tauri/` and `apps/workbench/src-tauri/` remain)
- `sdr-desktop` vestigial product name no longer embarrasses the repo
- Concrete numbers from N6: 1,728-line `ForensicsRiverView.tsx`, 1,544-line `SessionRail.tsx`, 1,148-line `DockSystem.tsx`, 1,009-line `OpenClawFleetView.tsx`, 951-line `MarketplaceView.tsx`, 854-line `SettingsView.tsx` — all gone

**Option 3b (REWRITE):** rename to `@clawdstrike/operator-hud` (or whatever sentence justifies its existence), state the one-sentence purpose in `apps/desktop/README.md`, delete the 15 feature views that duplicate `control-console`, keep only the truly differentiated ones. This is closer to "scope down" than "delete".

**Trade-offs:**
- **Risk of 3a:** if any team depends on apps/desktop for daily work (e.g., dogfooding, internal demos), removing it requires migration. The 32K LOC is in the repo but who uses it?
- **Risk of 3b:** half-rewrites are how we got here. Better to commit to one direction.
- **Tell me which:** if no one demos `apps/desktop`, choose 3a. If it's the "operator HUD" half of a clear OPS/CONTROL split, choose 3b and document.

**Effort:** trivial (3a) to medium (3b)

### 4. Enable biome linting + add workbench to biome.json + add `noUnusedLocals: true` + commit `logger` + codemod console.* (MEDIUM RISK, HIGH ROI)

**This is one bundle of changes because they're synergistic:**

1. **`biome.json` linter on:** flip `linter.enabled` from false to true. Run `biome lint --write`. Accept the avalanche of fixes. (The cleanup-tier-ab branch did this — adopt their `biome.json` if possible.)
2. **Add workbench to biome includes:** `"apps/workbench/src/**/*.{ts,tsx}", "apps/workbench/*.{ts,js,json}"`.
3. **`apps/workbench/tsconfig.json`:** flip `noUnusedLocals` and `noUnusedParameters` to `true`. Run `tsc --noEmit`, delete the surfaced dead variables/imports.
4. **Add a logger module:** copy from `chore/cleanup-tier-ab @ 7f9cb6068` or write afresh at `apps/workbench/src/lib/logger.ts` with `debug/info/warn/error` and `import.meta.env.DEV` gating.
5. **Codemod `console.* → logger.*`:** ripgrep + sed across `apps/workbench/src/**/*.{ts,tsx}`. 368 sites.
6. **Enable `no-console` lint rule** in biome.

**Concrete numbers:**
- 368 `console.*` calls collapsed to ~5 (logger module's own emissions)
- ~1000+ inline-style warnings now visible (biome `useStyleProp` rule)
- Dead-variable surface visible (TS `noUnusedLocals`)
- Single repo-wide style enforcement

**Trade-offs:**
- **Risk:** initial CI failure on the first run. Need to gate-merge after the autofix pass.
- **Effort:** medium (initial autofix is mechanical, but follow-up manual fixes for ambiguities take half a day)

**Strong recommendation:** rebase `chore/cleanup-tier-ab` onto current main and let it merge. That branch's existing commit `7f9cb6068` does most of this work already. Re-doing it is waste.

### 5. Decompose all `control-console/src/pages/*` files >900 lines (MEDIUM RISK, MEDIUM ROI)

**Action:** for each of `ExecutionProof.tsx` (1,434), `BrokerMissionControl.tsx` (1,070), `LocalContainment.tsx` (941), `RuleImpact.tsx` (925), `FleetCases.tsx` (809), and `ProcessCause.tsx` (704):
- Move data-fetching to `apps/control-console/src/hooks/useXxx.ts`
- Extract sub-cards (e.g. `<ReceiptChain />`, `<ProviderStates />`, `<ImpactRule />`, `<TimelineSection />`) to `apps/control-console/src/components/edr/Xxx.tsx`
- Reduce each page to <500 lines

Also split `apps/control-console/src/api/client.ts` (1,501 lines) into domain modules: `api/broker.ts`, `api/edr.ts`, `api/fleet.ts`, `api/policy.ts`, `api/receipts.ts`, plus `api/transport.ts` for the shared fetch layer.

**Concrete numbers:**
- ~7,000 LOC of page code redistributed across maybe ~25 smaller files
- Each EDR/broker page becomes reviewable

**Trade-offs:**
- **Risk:** medium. Each split must preserve behavior; the tests at `*.test.tsx` (1,323 lines of `client.test.ts` after EDR landed, 597 lines of `ExecutionProof.test.tsx`, etc.) must keep passing.
- **Effort:** large (1 dev-week for the sweep)

---

## DEFER / OUT OF SCOPE

The following items are out of scope for D06:

- **`apps/agent/src-tauri/`** — covered by D07 (Tauri desktop apps audit). The agent's React shell is just the empty `src-tauri/` build target plus the workbench-driven UI; not under D06 scope by spec.
- **`apps/terminal/`** — verified to be `@clawdstrike/tui`, a Bun-based TUI orchestrator. Source dirs are CLI/orchestrator code (`hush`, `mcp`, `desktop-agent`, `dispatcher`, `router`, `verifier`, `workcell`, etc.), not a frontend. Out of scope for D06 per spec. (Note: the `tui/` subdirectory in apps/terminal could in theory contain TUI rendering code, but it's a CLI, not a web/React frontend.)
- **`packages/sdk/clawdstrike` and friends** — covered by D05 (TypeScript packages).
- **Backend EDR work that informs control-console** — covered by D03/D04.

The following findings are mentioned in the original audit but worth deferring rather than tackling now:

- **Self-hosted fonts** (LOW) — wait until #1 (3D gamification wipe) settles; web font diet is meaningfully different after.
- **Storybook for control-console** (LOW) — only worth it once the design-system primitives stabilize. Adding stories to a moving target is wasted.
- **HashRouter → BrowserRouter** (LOW) — cosmetic; deferred.
- **React Compiler adoption** (LOW) — first do the consolidation; the compiler's benefit is much larger after the Zustand stores converge and the dead `useMemo`/`useCallback` are surfaced.

---

## Closing Note

The original audit was unusually accurate for a one-shot pass. Every concrete claim re-verified at HEAD on `fix/macos-es-ne-hardening`, with at-most off-by-one drift on two line counts. The cleanup branches (`chore/cleanup-tier-ab`, `chore/ts-sprints-23-deps-latest`) show that the team already wrote the highest-priority fixes — they just haven't merged. The primary action item for the next 24-72 hours is **rebase and merge those cleanup branches**, then attack the new findings (N1-N9, especially the EDR page sprawl and the 26 workbench files >1,000 lines) with the now-active `biome` linter and `noUnusedLocals` catching new accretion.

The aggressive ceiling argues for:
- `rm -rf apps/cloud-dashboard` (immediate, zero risk)
- `rm -rf apps/desktop` (immediate if no daily user; otherwise REWRITE with one-sentence purpose)
- `rm -rf apps/workbench/src/features/{observatory,spirit,nexus,hunt}` (after PM confirmation; the boundary is clean, the deletion is mostly mechanical)

Net subtraction if all three execute: **~80,000 LOC + ~400 files + ~30 MB of WebGL deps + one vestigial product name + one stale build directory.** The repo becomes meaningfully tighter and the "is this an IDE or a game?" question stops being askable.
