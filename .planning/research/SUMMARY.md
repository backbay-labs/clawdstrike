# Project Research Summary

**Project:** Huntronomer Workbench — 3D/Spirit/Observatory Integration
**Domain:** R3F immersive 3D features embedded in a Tauri 2 + React 19 VS Code-like IDE workbench
**Researched:** 2026-03-18
**Confidence:** HIGH — all four research files grounded in first-party source code inspection and official library documentation

---

## Executive Summary

This milestone ports the huntronomer 3D spirit companion, observatory world, cyber nexus, and forensics river features from the standalone `apps/desktop` shell into the production IDE workbench at `apps/workbench`. All source features are implemented and testable — the work is integration and adaptation, not greenfield engineering. The recommended approach follows a strict three-tier layering model: Tier 1 (pure CSS + Zustand state, no WebGL), Tier 2 (targeted R3F embeds — sidebar companion, bottom-pane tape, spirit chamber tab), Tier 3 (full immersive pane tabs — observatory and nexus). This ordering is mandatory because every visual feature depends on `spirit-store.ts` and `observatory-store.ts`, neither of which exist yet in the workbench.

The stack is locked. No new framework choices are required: `@react-three/fiber@^9.0.0`, `@react-three/drei@^10.0.0`, `three@^0.170.0`, and `@react-three/rapier@^2.2.0` (physics, Tier 3 only) are already in the huntronomer source at these exact versions. The workbench does not yet have R3F; packages must be added before any Tier 2 work begins. The integration contract for 3D views follows three invariants: each pane-tab Canvas uses `position: absolute; inset: 0` to escape the `overflow-auto` pane wrapper; per-frame animation values live in refs, never in Zustand; and new routes are registered in `WORKBENCH_ROUTE_OBJECTS` — not in a parallel router.

**KEY DECISION REQUIRED — WebGL Context Architecture:** The stack researcher and pitfalls researcher reached opposite conclusions on the root Canvas strategy, and this is the most consequential architectural choice for the entire milestone. It must be resolved before writing any Canvas placement.

- The **Stack researcher recommends separate Canvas per pane tab** (not drei `View`) because `View` requires a single persistent parent Canvas that conflicts with the binary tree pane system's mount/unmount semantics, and `View` has a confirmed z-index issue (drei GitHub #2471) that breaks modal/dialog stacking in the workbench.
- The **Pitfalls researcher recommends a root Canvas + drei `View` ports** because Tauri uses WebKit, which enforces a hard 8-context WebGL limit. With a separate Canvas per pane tab, opening three 3D tabs simultaneously (observatory + spirit companion + forensics river) is already at the Safari/WebKit ceiling, and one more context silently destroys the oldest one.

Both concerns are real and verified. The decision table is: **if the modal/dialog stacking issue in drei #2471 can be mitigated** (e.g., by managing z-index via a portal host div and CSS containment), the root Canvas + View approach is the safer long-term architecture for a multi-pane IDE. **If the z-index fix is too brittle**, the separate-Canvas approach with a documented ceiling of 3 simultaneous R3F contexts is acceptable for the current feature set, with a plan to consolidate later. This decision must be made explicitly and documented before Tier 2 begins.

---

## Key Findings

### Recommended Stack

The workbench stack requires four new npm packages: `@react-three/fiber@^9.0.0`, `@react-three/drei@^10.0.0`, `three@^0.170.0`, and `@types/three@^0.170.0` (dev). Physics (`@react-three/rapier@^2.2.0`) and the character controller (`ecctrl@^1.0.97`) are deferred to Tier 3 and should not be installed until the observatory flow-mode Easter egg is actively being built. VRM avatar rendering (`@pixiv/three-vrm`) is explicitly out of scope per PROJECT.md. The offscreen worker API (`@react-three/offscreen`) is pre-production and Safari-incompatible; `frameloop="demand"` + `invalidate()` provides sufficient CPU relief for non-animating panels.

Full Canvas configuration details: `.planning/research/STACK.md`

**Core technologies:**
- `@react-three/fiber@^9.0.0`: React renderer for Three.js — the R3F v9 major is the only version compatible with React 19; v8 is not
- `@react-three/drei@^10.0.0`: Helper components (OrbitControls, Stars, Html, Line, useGLTF, PerformanceMonitor, View) — v10 is coupled to fiber v9
- `three@^0.170.0`: Three.js peer dependency — matches huntronomer source; drei 10 / fiber 9 require three ≥ 0.168
- `@react-three/rapier@^2.2.0`: Physics for observatory flow mode only — v2 adds R3F v9 + React 19 support; defer to Tier 3
- `motion@^12.33.0` + `zustand@^5.0.12`: Already in workbench — used for CSS animations and 2 new stores respectively

### Expected Features

Full feature list with dependency graph: `.planning/research/FEATURES.md`

**Must have — table stakes (Tier 1, no R3F):**
- `spirit-store.ts` — foundation for all downstream visual features; every other feature reads from it
- `observatory-store.ts` — observatory seam badges, probe state, scene state derivation
- Spirit field CSS stain on sidebar and pane backgrounds — the ambient "spirit is alive" signal; zero GPU cost
- Spirit accent color (`--spirit-accent` CSS custom property) — bleeds into hunt UI chrome
- Activity bar badges from observatory seam (artifactCount, hasUnread per station)
- Route bridge: station click → `pane-store.openApp()` — makes the system navigable, not decorative
- Commands: `spirit.bind`, `spirit.release`, `observatory.open`, `observatory.probe`, `nexus.open`

**Should have — differentiators (Tier 2, targeted R3F):**
- Animated spirit orb in ActivityBar (CSS/SVG animation, no R3F canvas)
- Mini spirit companion R3F canvas in right sidebar — living 3D presence without full-tab demand
- Spirit chamber as full pane tab (`/spirit-chamber/:huntId`) — the bind/reconfigure ritual
- Forensics river "Tape" tab in bottom pane — ambient live telemetry; glia-three audit required first

**Defer — full immersive views (Tier 3):**
- Observatory world as full editor pane (`/observatory/:huntId`, atlas mode default)
- Cyber nexus as Hunt Deck pane tab (`/hunt-deck`)
- Spirit creation chamber (`/spirit-creation/:huntId`)
- Character controller flow mode Easter egg — opt-in, lazy-loaded, never default

**Anti-features explicitly excluded:**
- VRM avatar rendering — too heavy for IDE sidebar
- Full Rapier physics simulation in nexus — background CPU/GPU pressure with 50+ physics nodes
- Full-screen spirit awakening animation — modal full-screens in an IDE are hostile after the first use
- Audio feedback — inappropriate for security operators in open-plan or call environments
- Real-time WebGL receipt previews in editor tabs — conflicts with CodeMirror

### Architecture Approach

The integration slots 3D views into the existing binary tree pane system via three mechanisms: (1) new routes in `WORKBENCH_ROUTE_OBJECTS` (observatory, nexus, spirit-chamber) handled by lazy-loaded components with Suspense; (2) two new Zustand stores (`spirit-store`, `observatory-store`) that inject CSS vars at `DesktopLayout` and feed Zustand selectors to ActivityBar, RightSidebar, BottomPane, and pane-tab components; (3) a route bridge that maps 3D station/strikecell clicks to `pane-store.openApp()` calls. The pane system naturally unmounts R3F canvases on tab switch, which eliminates the need for explicit pause logic — but creates a shader recompilation stutter for large scenes that must be mitigated with visibility-toggle instead of unmount for the observatory and nexus tabs.

Full component diagram and data flow: `.planning/research/ARCHITECTURE.md`

**Major components:**
1. `spirit-store.ts` — bound spirit state (kind, mood, accentColor, motion envelope); ambient, affects everything
2. `observatory-store.ts` — active hunt ID, seam summary, scene state; scoped to hunt-deck views
3. `SpiritFieldInjector` — side-effect component in DesktopLayout that writes CSS vars to `<html>`
4. `ActivityBar` (modified) — spirit orb badge + observatory seam badge counts
5. `RightSidebar` (modified) — new `spirit-companion` panel housing mini R3F canvas
6. `BottomPane` (modified) — new `tape` tab housing forensics river embed
7. `ObservatoryTab` — full R3F pane at `/observatory` (Tier 3)
8. `NexusTab` — full R3F pane at `/nexus` (Tier 3); most entangled — needs NexusStateContext → Zustand migration first
9. `SpiritChamberTab` — pane at `/spirit-chamber`; CSS animation canvas, zero R3F (Tier 2)
10. `SpiritCompanionCanvas` — mini R3F in right sidebar; demand frameloop (Tier 2)
11. `ForensicsTapeTab` — glia-three RiverView embed in bottom pane (Tier 2/3 boundary)

### Critical Pitfalls

Full 10-pitfall analysis with recovery strategies: `.planning/research/PITFALLS.md`

1. **`overflow-auto` collapses Canvas to 150px** — Every 3D route component must start with `<div className="absolute inset-0 overflow-hidden">` to escape the `PaneContainer` scroll wrapper. This is the first thing to verify on any new Canvas tab.

2. **WebGL context exhaustion (WebKit hard limit: 8)** — Tauri targets WebKit which enforces 8 simultaneous WebGL contexts. With separate Canvas per pane tab, opening observatory + nexus + companion + tape = 4 contexts, leaving margin for browser overhead. Root Canvas + drei View is the bulletproof solution but carries the z-index risk (see KEY DECISION above).

3. **Tab switch causes shader recompilation stutter (500ms+ freeze)** — The pane system unmounts inactive routes. For large 3D scenes, use CSS `visibility: hidden` + `frameloop="never"` instead of letting the route unmount. Establish this pattern before the first full observatory tab.

4. **`useFrame` writing to Zustand triggers 60fps React reconcile** — Per-frame animation values must live in `useRef`, never in Zustand setters. Zustand is for user-action-triggered state only. This is a project-wide coding contract, not a per-component concern.

5. **NexusStateContext does not bridge into R3F Canvas** — The existing `NexusStateContext` (React context) is invisible to components inside the Canvas's R3F fiber renderer. The nexus state must be migrated to a `nexus-store.ts` Zustand store before any NexusCanvas porting begins.

6. **glia-three `RiverView` likely owns its own Canvas** — ForensicsRiverView imports from `@backbay/glia-three/three`. If that package bundles its own Canvas (likely), it creates a context boundary problem. Audit the package source before committing to the Tape tab implementation.

---

## KEY DECISION REQUIRED: WebGL Context Architecture

**This must be decided and documented before writing any Canvas placement. It affects every R3F surface in Tiers 2 and 3.**

### Option A: Separate Canvas Per Pane Tab (Stack researcher recommendation)
- Each 3D view owns its own `<Canvas>` instance
- Simpler integration: pane mount/unmount lifecycle works naturally
- Avoids drei View z-index issue (#2471) that breaks modal/dialog stacking
- **Risk:** WebKit (Tauri target) enforces 8-context hard limit. With companion + tape + observatory + nexus simultaneously open: 4 contexts used. Acceptable if the workbench enforces "only one heavy pane tab at a time" as a rule, and the ActivityBar orb uses CSS/SVG (no canvas).
- **Mitigation:** Enforce a maximum of 3 simultaneous R3F contexts via pane system; document the ceiling; let the browser silently kill the 4th if exceeded.

### Option B: Root Canvas + drei View Ports (Pitfalls researcher recommendation)
- Single `<Canvas>` at the App shell level
- All 3D surfaces use drei `<View>` (scissor sub-views) into the root Canvas
- One WebGL context total — zero context exhaustion risk
- **Risk:** drei View requires a persistent parent Canvas that conflicts with pane mount/unmount semantics; confirmed z-index bug (#2471) breaks modal stacking in workbenches
- **Mitigation:** Manage z-index via a dedicated portal host div in DesktopLayout with explicit CSS containment; accept that View + modal z-index requires careful layer management.

### Recommendation for Resolution
Audit drei issue #2471 to determine if it has been resolved in drei@^10.0.0 (R3F v9 era). If resolved or mitigatable: use Option B. If still active and affecting modals: use Option A with a 3-context ceiling and clear documentation that the ActivityBar spirit orb must be CSS-only (no Canvas).

---

## Implications for Roadmap

Based on research, suggested four-phase structure mirroring the Tier dependency model:

### Phase 1: Spirit + Observatory State Foundation
**Rationale:** Every visual feature depends on `spirit-store` and `observatory-store`. These are zero-risk (no R3F, no new packages) and deliver visible results immediately (CSS field stain, accent colors, live badge counts). Unblocks all subsequent work. Must also resolve the KEY DECISION on Canvas architecture at the end of this phase so Tier 2 begins on a locked contract.
**Delivers:** Two Zustand stores, CSS field stain on sidebar and pane backgrounds, spirit accent color system, activity bar seam badges, route bridge wiring, 5 command palette commands.
**Addresses:** spirit-store.ts (P1), observatory-store.ts (P1), spirit field CSS stain (P1), spirit accent color (P1), activity bar badges (P1), route bridge (P1), commands (P1)
**Avoids:** Stale command closure pitfall (Pitfall 10), CSS spirit stain stacking context (Pitfall 9)
**Research flag:** Standard patterns — no deeper research needed; all implementation is direct port of known-working huntronomer source code.

### Phase 2: R3F Package Install + WebGL Architecture Contract
**Rationale:** Installing R3F packages is a prerequisite for all Tier 2 work. More importantly, the WebGL context architecture decision (KEY DECISION above) must be locked here — it cannot be deferred to "when we see a bug." This phase is short in code but high in consequence.
**Delivers:** R3F packages installed in `apps/workbench`; Canvas architecture decision documented; `absolute inset-0` host div pattern validated in a spike Canvas component; drei `<Html>` clipping strategy validated.
**Uses:** `@react-three/fiber@^9.0.0`, `@react-three/drei@^10.0.0`, `three@^0.170.0`, `@types/three@^0.170.0`
**Avoids:** overflow-auto canvas height collapse (Pitfall 1), WebGL context exhaustion (Pitfall 2), Html labels escaping pane bounds (Pitfall 7)
**Research flag:** Needs targeted research — audit drei@^10.0.0 changelog and issue #2471 status to resolve the KEY DECISION; audit `@backbay/glia-three` package source for own-Canvas detection.

### Phase 3: Targeted R3F Embeds (Tier 2)
**Rationale:** Small 3D surfaces with bounded scope. Spirit chamber tab is CSS-only (no R3F) but requires spirit-store from Phase 1. Mini companion canvas is the first real WebGL surface — validates the Canvas architecture decision in a low-risk context before the large scenes. Forensics tape tab depends on the glia-three audit from Phase 2.
**Delivers:** Animated spirit orb in ActivityBar (CSS/SVG), mini spirit companion R3F canvas in right sidebar (demand frameloop), spirit chamber pane tab (CSS animation canvas), forensics tape tab (conditional on glia-three audit).
**Implements:** SpiritCompanionCanvas, SpiritChamberTab, ForensicsTapeTab, right-sidebar spirit panel switch, bottom-pane tape tab
**Avoids:** useFrame Zustand write at 60fps (Pitfall 4), tab switch stutter — companion canvas is small enough to allow remount
**Research flag:** Standard patterns for companion canvas and chamber tab; conditional on glia-three findings for tape tab (if glia-three has own Canvas, a fork/adapter plan is needed before Phase 3 completes).

### Phase 4: Full Immersive Pane Tabs (Tier 3)
**Rationale:** Observatory and nexus are the largest components and the most entangled. Observatory depends on stable spirit-store and observatory-store from Phase 1. Nexus is the most entangled (imports ObservatoryWorldCanvas, NexusSpiritCompanion, strikecell adapter) and requires the NexusStateContext-to-Zustand migration before any canvas port. Character controller is an Easter egg and must be the last item.
**Delivers:** Observatory world as full editor pane (atlas mode, no character controller by default), cyber nexus as Hunt Deck pane tab, spirit creation chamber, character controller flow mode (opt-in, lazy-loaded).
**Implements:** ObservatoryTab, NexusTab, nexus-store.ts (Zustand migration), deriveObservatoryWorld port, observatory-world.ts, SpiritCreationChamber
**Avoids:** NexusStateContext context isolation in Canvas (Pitfall 5), OrbitControls vs pane activation (Pitfall 6), tab switch scene recompile stutter on Observatory/Nexus (Pitfall 3)
**Research flag:** Needs phase-level research — NexusStateContext migration scope is large and must be fully mapped before implementation begins. Observatory character controller (Rapier physics, ecctrl, animation state machine) needs its own scoped research sub-task.

### Phase Ordering Rationale

- **State before rendering:** Both Zustand stores are required by every visual feature. Starting with CSS-only work means real visible progress on day 1 without any WebGL risk.
- **Architecture contract before any canvas:** The KEY DECISION must be locked before the first `<Canvas>` is written. A wrong architecture discovered at Phase 4 is a rewrite; discovered at Phase 2 spike, it is a 1-day pivot.
- **Small canvas before large canvas:** The spirit companion validates the Canvas host pattern (absolute inset-0, frameloop, GL config) at a small scale. If the pattern is wrong, fixing it on a 100px sidebar widget costs minutes; fixing it after ObservatoryWorldCanvas is wired would cost hours.
- **Nexus last:** NexusStateContext migration, ObservatoryWorldCanvas import, NexusSpiritCompanion wiring, and strikecell adapter are all dependencies. Nexus is the only component that cannot be built without all other components being stable first.

### Research Flags

Phases needing deeper research during planning:
- **Phase 2:** drei@^10.0.0 issue #2471 status audit (KEY DECISION); glia-three package own-Canvas audit. Both are one-off investigations, not broad research.
- **Phase 4:** NexusStateContext full dependency mapping before migration; Rapier + ecctrl integration for observatory flow mode Easter egg.

Phases with standard patterns (skip research-phase):
- **Phase 1:** Direct port of known-working huntronomer code. Patterns are established (createSelectors, CSS vars, buildSpiritFieldStainStyle). No research needed.
- **Phase 3:** Spirit companion canvas pattern is a strict subset of ObservatoryWorldCanvas — already researched. Spirit chamber tab is CSS-only — no new patterns.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All versions verified against huntronomer `apps/desktop/package.json` and official R3F/drei v9/v10 migration docs. No ambiguity. |
| Features | HIGH | Based on direct source code analysis of both apps. Features are implemented and running in huntronomer source; integration complexity is known. |
| Architecture | HIGH | All component boundaries and store designs grounded in direct inspection of workbench and huntronomer source. The pane system, route registration, and store patterns are established in the codebase. |
| Pitfalls | HIGH | 8 of 10 pitfalls verified against official R3F GitHub issues and docs. Two (glia-three own-Canvas, Tauri WebKit context limit specifics) are MEDIUM — confirmed as general patterns but Tauri-specific behavior needs validation. |

**Overall confidence:** HIGH

### Gaps to Address

- **drei View z-index status in v10:** Issue #2471 was documented against an earlier drei version. Whether it is resolved or mitigatable in drei@^10.0.0 (paired with R3F v9) is unconfirmed. This is the primary open question. Resolution: check the drei@10.0.0 changelog and test a spike with a modal overlay during Phase 2.

- **glia-three Canvas ownership:** `@backbay/glia-three/three` `RiverView` usage pattern suggests it renders its own Canvas, but this was not confirmed by direct source inspection of the glia-three package. Resolution: read glia-three source before committing to Phase 3 ForensicsRiverView implementation.

- **Exact WebKit context limit in current Tauri 2 + WebKit version:** The 8-context limit is documented for Safari/WebKit in general, but the exact behavior under Tauri 2's WebView may differ slightly. Resolution: write a context-count test in Phase 2 spike by opening multiple R3F canvases and checking for context loss warnings.

- **Observatory character controller scope:** The Rapier + ecctrl + animation state machine integration for flow mode is large. No detailed research was done on the Phase 4 Easter egg because it is deliberately deferred. Resolution: dedicated research sub-task when observatory atlas mode (Phase 4 primary) is complete.

---

## Sources

### Primary (HIGH confidence)
- R3F official docs (r3f.docs.pmnd.rs) — Canvas props, frameloop, dpr, v9 migration, performance pitfalls
- drei official docs (drei.docs.pmnd.rs) — PerformanceMonitor, View, Html component
- Direct inspection: `huntronomer-workspace-orch/apps/desktop/package.json` — R3F package versions
- Direct inspection: `huntronomer-workspace-orch/apps/desktop/src/features/hunt-observatory/` — observatory types, world, probe
- Direct inspection: `huntronomer-workspace-orch/apps/desktop/src/features/cyber-nexus/` — nexus canvas, context, state
- Direct inspection: `huntronomer-workspace-orch/apps/desktop/src/shell/workbench/spirit/` — spirit types, field stain, scene math
- Direct inspection: `apps/workbench/src/features/panes/pane-store.ts`, `pane-root.tsx`, `pane-container.tsx`
- Direct inspection: `apps/workbench/src/components/desktop/workbench-routes.tsx`, `desktop-layout.tsx`
- Direct inspection: `apps/workbench/src/features/activity-bar/`, `right-sidebar/`, `bottom-pane/`
- GitHub: R3F issues #514, #3093 (WebGLRenderer leak on unmount)
- GitHub: R3F discussions #2716 (multiple canvas), #2457 (WebKit context limit), #2080 (state management without restarter)
- GitHub: R3F issue #2149 (canvas resize after container resize)

### Secondary (MEDIUM confidence)
- GitHub: drei issue #2471 (View z-index) — documented against earlier drei version; v10 status unconfirmed
- GitHub: Tauri issue #6559 (R3F + Tauri WebGL context) — Tauri-version-dependent; may not apply to Tauri 2

### Tertiary (LOW confidence)
- WebSearch: drei View pattern for multi-panel architectures — general community patterns, not verified against current versions

---
*Research completed: 2026-03-18*
*Ready for roadmap: yes*
