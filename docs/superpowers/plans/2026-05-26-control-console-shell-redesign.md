# Control Console Shell Redesign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every
> implementer MUST also invoke `frontend-design` and the named impeccable taste skill(s), and
> read `apps/control-console/.impeccable.md` for Design Context.

**Goal:** Add a sleek left navigation **sidebar** (rail / expanded / two-pane variants) and a top
**header bar** to the ClawdStrike Control Console, slim the bottom taskbar, and consolidate the
floating status widgets — all while preserving the existing `@backbay/glia-desktop` OS window
manager and "Forged Gold on Black Glass" brand.

**Architecture:** Keep `App.tsx` providers and the glia-desktop window manager untouched.
Restructure only the `ClawdStrikeDesktop` composition from a single flex-column into a flex-row:
`[Sidebar] [ main column: HeaderBar + window canvas ]` above a slimmed `Taskbar`. The sidebar is
the new primary launcher (replacing the taskbar StartMenu and the desktop icon grid); it derives
all nav data from the existing `processRegistry` (`desktopIconGroups`, `processes`,
`PROCESS_ICONS`, `pinnedAppIds`) and drives the window manager via `processes.launch` /
`windows.focus`. Sidebar variant + collapse are user preferences persisted to localStorage.

**Tech Stack:** React 19, TypeScript, Vite, Tailwind 4, `@backbay/glia-desktop` (window manager,
`Taskbar`, `useDesktopOS`), zustand, framer-motion, Vitest + Testing Library, Biome.

**Design source of truth:** `/tmp/design_handoff/clawdstrike/project/` (read `js/sidebar.jsx`,
`js/desktop.jsx`, `js/taskbar.jsx`, `js/icons.jsx`, `js/monitor-window.jsx`, and
`chats/chat1.md`). All px/color values below are extracted from those files. Implementers should
open them for exact reference but **must rebuild in idiomatic React/TS for this codebase — do not
copy the prototype's `window.X` globals, inline `<script type=text/babel>`, or the `tweaks-panel`.**

---

## Product decisions (locked)

These were decided from the design handoff + chat intent + taste review. Do not re-litigate:

1. **Sidebar replaces the taskbar StartMenu** as primary navigation. Remove `<StartMenu />` from
   the taskbar; delete `StartMenu.tsx` (its only consumer is the taskbar; no tests reference it).
2. **Sidebar replaces the desktop icon grid.** Remove the `DesktopSurface` icon grid from behind
   windows; the canvas shows the active window or a clean empty state. (The sidebar is now the
   launcher, so an icon grid is redundant and less intuitive — the stated goal was "more
   intuitive.")
3. **Floating `DesktopWidgets` (Violations / Connected / Uptime) are consolidated** into the
   sidebar footer pulses (expanded/two-pane) and the header chips (rail). Delete `DesktopWidgets.tsx`.
4. **Slim taskbar** = "Console online" status crest · running-app pills · spacer · notification
   bell · system tray · clock. Height 48px → **44px** via `--glia-spacing-taskbar-height`.
5. **Default sidebar variant = `expanded`** (248px). Variants: `rail` (64px), `expanded` (248px),
   `twopane` (60px section rail + 220px app column). Collapsing `expanded` renders `rail`.
6. **Wordmark text = solid gold** (`--gold`). Forged-gold gradient is allowed only on the SVG "C"
   glyph. (impeccable BAN 2: no gradient text.)
7. Keep the existing CommandPalette (⌘K). Sidebar/header search **opens** it (no new search UI).

---

## File structure

**New files**
- `src/state/useShellPreferences.ts` — zustand store: `sidebarVariant`, `sidebarCollapsed`, setters; localStorage-persisted with cross-tab sync.
- `src/hooks/useConsoleStatus.ts` — derives `{ sseLive, violations, uptime, build }` from shared SSE (`events`, `connected`).
- `src/components/shell/StatusPulse.tsx` — small label/value/tone status card (sidebar footer + header chips).
- `src/components/shell/BrandMark.tsx` — engraved gold "C" glyph (gradient on glyph OK) + optional solid-gold wordmark.
- `src/components/shell/sidebar/Sidebar.tsx` — variant switcher; reads `useShellPreferences`; wires glia-desktop.
- `src/components/shell/sidebar/SidebarHeader.tsx` — BrandMark + wordmark + version + collapse toggle.
- `src/components/shell/sidebar/NavItem.tsx` — `NavIconButton` (rail) + `NavRowButton` (expanded/twopane) + `Tooltip`.
- `src/components/shell/sidebar/SidebarSearch.tsx` — ⌘K search trigger button (expanded).
- `src/components/shell/sidebar/SidebarRail.tsx` — 64px icon rail (pinned subset per group).
- `src/components/shell/sidebar/SidebarExpanded.tsx` — 248px grouped nav + search + footer pulses.
- `src/components/shell/sidebar/SidebarTwoPane.tsx` — 60px section rail + 220px app column.
- `src/components/shell/HeaderBar.tsx` — breadcrumb + (rail/twopane) ⌘K pill + status pulse chips.
- `src/components/shell/CanvasEmptyState.tsx` — "No window open / Launch Monitor".
- `src/components/shell/useNavApps.ts` — selector: maps `desktopIconGroups` → `{ group, apps:[{processId,label,running,active,tone,Sigil,desc}] }` from `useDesktopOS`.
- Co-located tests: `*.test.tsx` / `*.test.ts` next to the above (TDD).

**Modified files**
- `src/state/processRegistry.tsx` — sigils → `stroke/fill="currentColor"`; add `PROCESS_TONE: Record<string,"gold"|"teal"|"muted">` (mirror design `SIGIL_TONE`); export it.
- `src/components/shell/ClawdStrikeDesktop.tsx` — flex-row shell; mount Sidebar + HeaderBar + CanvasEmptyState; remove `DesktopSurface` + `DesktopWidgets`; slim `ComposedTaskbar` (drop StartMenu, add console crest).
- `src/index.css` — `--glia-spacing-taskbar-height: 44px`; add `@keyframes pulse`; sidebar/wallpaper helper classes if needed.
- `src/components/shell/DesktopWallpaper.tsx` — add faint `cs` wordmark watermark + dot-grid/bloom polish (ember/void/crimson moods already exist via wallpapers).
- `src/pages/Settings.tsx` (+ `src/components/settings/`) — add a sidebar-variant control (Interface/Appearance), writing via `useShellPreferences`.

**Deleted files**
- `src/components/shell/StartMenu.tsx`, `src/components/shell/DesktopWidgets.tsx` (+ any of their tests).

---

## Integration contracts (exact)

- `const { processes, windows } = useDesktopOS()`.
- **Launch / focus a nav app:** `processes.launch(processId)` (glia focuses an existing singleton
  or opens it). All console processes are `singleton: true`.
- **Running set:** `new Set(processes.instances.map(i => i.processId))`.
- **Active (focused) process:** find `processes.instances.find(i => i.windowId === windows.focusedId)?.processId`.
- **Active app definition / breadcrumb:** `processes.getDefinition(processId)` → `{ name, description, category }`.
- **Sigil:** `PROCESS_ICONS[processId]` (after refactor, inherits `currentColor`).
- **Groups:** `desktopIconGroups` = `[{id:"core",label:"Operations",icons}, {id:"policy-ops",label:"Policy + Runtime",icons}, {id:"advanced",label:"Tools",icons}]`; each icon `{id,processId,label,group}`.
- **Rail pinned subset:** `pinnedAppIds`.
- **Status:** `const { events, connected } = useSharedSSE()` → feed `useConsoleStatus`.
- **⌘K:** `ClawdStrikeDesktop` already owns `commandPaletteOpen`; pass `onCmdK={() => setCommandPaletteOpen(true)}` into Sidebar/HeaderBar.

---

## Design spec (extracted px/colors — the contract for "adhere to the design well")

**Sidebar — Expanded (248px):** bg `linear-gradient(180deg, rgba(11,13,16,.97), rgba(7,8,10,.97))`,
right border `1px rgba(27,34,48,.6)`, shadow `inset -1px 0 0 rgba(214,177,90,.05), 4px 0 32px rgba(0,0,0,.5)`.
Header (BrandMark 36×36 rounded-9 with radial gold + claw-crimson glyph; wordmark solid gold 14px/600;
"Control Console · v0.2.5" mono 8.5px uppercase muted; collapse chevron 24×24). SearchBar (mono 11px,
⌘K chip). Groups: mono label 9.5px `letter-spacing .18em` uppercase muted; rows = `NavRowButton`.
Footer: 2×2 grid of `StatusPulse` (SSE / Violations / Uptime / Build).

**Sidebar — Rail (64px):** `NavIconButton` 44×44 rounded-10; active = gold gradient fill + inset gold
ring + 16px gold bloom; hover = faint gold wash + tone-colored icon; running = 3×16 left bar (gold if
active else teal); tooltips on hover. Pinned subset per group, divided by hairlines. Settings pinned in footer.

**Sidebar — Two-Pane:** 60px section rail (group glyphs: operations=Monitor, policy=Policies,
tools=Settings sigil; active = gold gradient + 2px left bar) + 220px app column (Section label +
group title; `NavRowButton compact`; 2-up footer pulses SSE/Violations).

**NavRowButton:** row, gap 12, padding `9px 12px` (compact `7px 10px`), radius 9; active = gold
gradient `linear-gradient(90deg, rgba(214,177,90,.16), rgba(214,177,90,.03))` + inset gold ring +
**2px gold left active-indicator bar** (functional state, allowed); label mono 11.5px uppercase
`ls .05em`; running dot 5px (gold if active else teal). Icon tone from `PROCESS_TONE`.

**HeaderBar (height 50px):** absolute top of canvas; `border-bottom 1px rgba(27,34,48,.5)`;
`background linear-gradient(180deg, rgba(11,13,16,.55), rgba(11,13,16,.2))` + `backdrop-filter blur(12px)`.
Breadcrumb: `CLAWDSTRIKE / <Group> / <ActiveApp+sigil>` (mono, uppercase, gold on active leaf).
For **rail/twopane only**: right-aligned ⌘K "Search" pill + `StatusPulse` chips (SSE LIVE teal w/
pulse dot · Violations gold/crimson · Uptime gold mono). For **expanded**: breadcrumb only (search +
pulses live in the sidebar).

**StatusPulse:** column, label mono 8.5px uppercase muted + value mono (13–15px), tone color
(gold/teal/crimson); border `1px rgba(27,34,48,.85)`, bg `rgba(0,0,0,.4)`, radius 8.

**Taskbar (44px):** "● Console online" teal crest (left) · `|` divider · running-app pills · spacer ·
notification bell (crimson badge = violation count) · system tray · clock (mono 12.5px tnum + roman subtitle).

**Wallpaper:** keep ember/void/crimson moods; radial gold bloom + 32px dot-grid masked to center +
faint `cs` wordmark watermark bottom-right (`opacity .04`, Space Grotesk 600, ~240px, `--gold`).

**Window canvas:** active window absolutely positioned `top:70 left:28 right:28 bottom:28`,
`max-width:1280; margin:0 auto` (70px clears the 50px header + gap). Empty state centered.

---

## Tasks

> Each task: implementer invokes `frontend-design` + named impeccable skill(s), reads
> `.impeccable.md`, follows TDD (write/colocate tests), runs `npm run typecheck` + `npm test` +
> `npm run format`, and commits only files under `apps/control-console/`. Then a spec-compliance
> review and a code-quality review run before the task is marked complete.

### Task 1: Foundations — sigil refactor, preferences store, status hook
**Files:** Modify `src/state/processRegistry.tsx`; Create `src/state/useShellPreferences.ts`,
`src/hooks/useConsoleStatus.ts`; Tests: `useShellPreferences.test.ts`, `useConsoleStatus.test.ts`,
extend `src/state/processRegistry.test.ts`.

- [ ] **Sigils → `currentColor`:** replace every `stroke="var(--gold)"` / `stroke="var(--teal)"` /
  `fill="var(--gold)"` etc. in the 24 sigil components with `currentColor` so icons inherit the
  caller's text color. Add and export `PROCESS_TONE: Record<string, "gold" | "teal" | "muted">`
  mirroring the design's `SIGIL_TONE` (icons.jsx lines 206-215): teal = event-stream, agent-explorer,
  privacy-report, causal-groups, process-cause, local-containment, guard-playground, posture-map,
  agent-chat, broker-theater; muted = settings; gold = the rest.
- [ ] **`useShellPreferences`** (zustand): state `{ sidebarVariant: "rail"|"expanded"|"twopane";
  sidebarCollapsed: boolean }`, actions `setSidebarVariant`, `setSidebarCollapsed`, `toggleCollapsed`.
  Persist to localStorage keys `cs_sidebar_variant`, `cs_sidebar_collapsed`; hydrate on init; sync
  across tabs via `storage` event + dispatch `clawdstrike:shell-prefs-changed` (mirror the wallpaper
  pattern in `wallpapers.ts` / `DesktopWallpaper.tsx`). Default variant `expanded`, collapsed `false`.
- [ ] **`useConsoleStatus(events, connected)`** → `{ sseLive: boolean; violations: number;
  uptime: string; build: string }`. `sseLive = connected`; `violations` = count of `events` where
  `allowed === false || event_type === "violation"`; `uptime` = `HH:MM:SS`/`Xh Ym` from oldest
  event timestamp to now (match `DesktopWidgets` semantics — read it before deleting); `build` =
  app version `"0.2.5"` (from package.json or a constant). Memoize.
- [ ] Tests: variant persistence round-trips localStorage; `useConsoleStatus` counts violations and
  formats uptime; `PROCESS_TONE` has an entry for every process id and sigils contain no hard-coded
  `var(--gold)`/`var(--teal)` stroke. Run `npm test`; commit.
**Impeccable skills:** none (logic task). **Model:** standard.

### Task 2: Shared primitives — StatusPulse + BrandMark
**Files:** Create `src/components/shell/StatusPulse.tsx`, `src/components/shell/BrandMark.tsx`;
Tests co-located.

- [ ] **`StatusPulse`** props `{ label: string; value: string; tone?: "gold"|"teal"|"crimson";
  pulse?: boolean; small?: boolean }`. Matches design `SystemPulse`/`TopChip`. Optional pulsing dot
  (uses `@keyframes pulse`). Tokens only.
- [ ] **`BrandMark`** props `{ size?: number; showWordmark?: boolean }`. 36×36 (default) engraved tile:
  radial gold highlight + `linear-gradient(180deg,#1a1410,#0a0807)` base + gold edge + inset
  highlight; centered SVG "C" glyph with **gradient fill on the glyph** (`#f3d889→#a07e2c`) and a
  crimson claw accent (design sidebar.jsx lines 147-169). When `showWordmark`, render "clawdstrike"
  in **solid `--gold`** (NOT gradient text) + "Control Console · v{version}" mono caption.
- [ ] Tests: StatusPulse renders label/value + applies tone color; BrandMark renders the glyph and,
  when `showWordmark`, the wordmark uses solid color (assert no `-webkit-background-clip:text` on
  text). Commit.
**Impeccable skills:** `typeset`, `colorize`. **Model:** standard.

### Task 3: Sidebar core — header, nav items, search, switcher, expanded + rail
**Files:** Create `src/components/shell/sidebar/{Sidebar,SidebarHeader,NavItem,SidebarSearch,
SidebarExpanded,SidebarRail}.tsx`, `src/components/shell/useNavApps.ts`; Tests for `Sidebar`,
`NavItem`, `useNavApps`.

- [ ] **`useNavApps()`**: from `useDesktopOS()` + `desktopIconGroups` build
  `{ id, label, apps: Array<{ processId, label, desc, Sigil, tone, running, active }> }[]`, where
  `running` ∈ running set, `active` = focused process. Memoize on `instances` + `focusedId`.
- [ ] **`NavItem`**: export `NavIconButton` (rail, 44×44, tooltip, running bar) and `NavRowButton`
  (row, optional `compact`, 2px gold active-indicator bar, running dot). Icon color by state:
  muted default → `tone` accent on hover → gold when active. Keyboard accessible (`<button>`,
  focus-visible ring in gold). Spec above.
- [ ] **`SidebarHeader`** (`collapsed`, `onToggle`): BrandMark; when expanded show wordmark + caption
  + collapse chevron; bottom hairline.
- [ ] **`SidebarSearch`** (`onCmdK`): button styled like design SearchBar; calls `onCmdK`.
- [ ] **`SidebarExpanded`** (`onCmdK`, `onCollapse`, status): header + search + grouped `NavRowButton`s
  + 2×2 footer `StatusPulse` (SSE/Violations/Uptime/Build).
- [ ] **`SidebarRail`**: header (collapsed) + pinned-per-group `NavIconButton`s with hairline
  dividers + settings in footer. Tooltips on hover.
- [ ] **`Sidebar`**: reads `useShellPreferences`; `effectiveVariant = (variant==="expanded" &&
  collapsed) ? "rail" : variant`; renders the matching variant; passes `useConsoleStatus` values and
  `onCmdK`; `onCollapse` sets collapsed. (Two-pane handled in Task 4.)
- [ ] Tests: renders all three groups + labels; clicking a nav row calls `processes.launch`; active
  app highlighted; collapse toggles rail. Mock `@backbay/glia-desktop` `useDesktopOS`. Commit.
**Impeccable skills:** `layout`, `typeset`, `polish`. **Model:** most-capable.

### Task 4: Sidebar two-pane variant
**Files:** Create `src/components/shell/sidebar/SidebarTwoPane.tsx`; wire into `Sidebar.tsx`; test.

- [ ] **`SidebarTwoPane`**: 60px section rail (group glyphs, active gold + 2px bar, settings footer)
  + 220px app column (Section caption + active group title + `NavRowButton compact` list + 2-up
  footer pulses). Selected group follows the active app's group; clicking a section switches it.
- [ ] Wire as the `twopane` branch in `Sidebar.tsx`. Test: switching sections changes the listed
  apps; active app's group auto-selects. Commit.
**Impeccable skills:** `layout`, `polish`. **Model:** most-capable.

### Task 5: Header bar + canvas empty state
**Files:** Create `src/components/shell/HeaderBar.tsx`, `src/components/shell/CanvasEmptyState.tsx`; tests.

- [ ] **`HeaderBar`** (`activeProcessId`, `variant`, `onCmdK`, status): 50px bar; breadcrumb
  `CLAWDSTRIKE / <group label> / <active app + sigil>` (gold on leaf). When `variant !== "expanded"`,
  right side shows the ⌘K "Search" pill + `StatusPulse` chips (SSE/Violations/Uptime). When
  `expanded`, breadcrumb only.
- [ ] **`CanvasEmptyState`** (`onLaunch`): centered "No window open" + "Launch Monitor" ghost button.
- [ ] Tests: breadcrumb reflects active app + group; pulses render for rail/twopane and are absent
  for expanded; empty-state button calls `onLaunch`. Commit.
**Impeccable skills:** `layout`, `polish`. **Model:** standard.

### Task 6: Shell integration + slim taskbar + wallpaper watermark
**Files:** Modify `src/components/shell/ClawdStrikeDesktop.tsx`, `src/index.css`,
`src/components/shell/DesktopWallpaper.tsx`; Delete `src/components/shell/StartMenu.tsx`,
`src/components/shell/DesktopWidgets.tsx` (+ their tests if any). Integration test for the shell.

- [ ] Restructure `ClawdStrikeDesktop` return: outer `position:fixed inset:0 flex column`; **shell row**
  `flex:1 flex row min-h:0`: `<Sidebar onCmdK=… />` then `<main flex:1 position:relative overflow:hidden>`
  containing `<HeaderBar … />`, the absolutely-positioned `WindowContainer` window region
  (`top:70 left:28 right:28 bottom:28 max-width:1280 margin:auto`), and `<CanvasEmptyState>` when no
  window is open; then the `<Taskbar>` row. Keep `DesktopWallpaper`, `LockScreen`, and all system
  services (AutoLaunch, SSETrayItem, SSENotifier, KeyboardShortcuts, CommandPalette, ContextMenu).
- [ ] Remove `DesktopSurface` (icon grid) and `<DesktopWidgets>`; remove now-unused imports. Derive
  `activeProcessId` from `windows.focusedId`; pass `useConsoleStatus(events, connected)` to Sidebar
  + HeaderBar. Sidebar variant comes from `useShellPreferences`.
- [ ] **Slim `ComposedTaskbar`:** drop `<StartMenu />`; add a left "● Console online" teal crest +
  hairline divider; keep `Taskbar.RunningApps` pills, spacer, `NotificationCenter`, `Taskbar.SystemTray`,
  `showClock`. Delete `StartMenu.tsx` + `DesktopWidgets.tsx` and their imports/tests.
- [ ] `index.css`: set `--glia-spacing-taskbar-height: 44px`; add `@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.5} }`.
- [ ] `DesktopWallpaper`: add the faint `cs` wordmark watermark (bottom-right, opacity .04) + ensure
  dot-grid + radial bloom read per the spec; keep wallpaper-id reactivity.
- [ ] Verify the app renders with each variant (expanded default), windows open/focus from the
  sidebar, taskbar is slim, no floating widgets, no icon grid. Run `npm run typecheck` + `npm test`;
  commit.
**Impeccable skills:** `layout`, `polish`, `delight`. **Model:** most-capable.

### Task 7: Settings — sidebar variant control
**Files:** Modify `src/pages/Settings.tsx` (+ a small `src/components/settings/` control following
`ThemeToggle`/`WallpaperPicker` patterns); test.

- [ ] Add an "Interface" (or extend "Appearance") section with a 3-way segmented control for sidebar
  variant (Icon Rail / Expanded / Two-Pane) bound to `useShellPreferences`. Match existing settings
  styling. Test: changing the control updates the store + persists. Commit.
**Impeccable skills:** `polish`. **Model:** standard.

### Task 8: Taste pass — critique → refine
**Files:** Any shell files needing refinement, per critique.

- [ ] Invoke impeccable `critique` on the assembled shell (sidebar + header + taskbar + canvas) against
  `.impeccable.md` and the design spec. Then apply `polish`, `colorize`, and `typeset` fixes for the
  highest-value issues: gold-rarity (60-30-10), spacing rhythm, type scale/contrast, focus-visible
  states, hover/active transitions (transform/opacity only, ease-out, no bounce), reduced-motion
  support, and removal of any AI-slop tells. Re-run typecheck/test/format; commit.
**Impeccable skills:** `critique`, `polish`, `colorize`, `typeset`. **Model:** most-capable.

### Task 9: Final verification
- [ ] Run `npm run typecheck`, `npm run format:check`, `npm test`, `npm run build` in
  `apps/control-console`. Fix any failures (root-cause, not suppress). Confirm: build passes, all
  tests green, no console errors on load, design adhered to. Report results, then hand off via
  `superpowers:finishing-a-development-branch`.

---

## Self-review (author)

- **Spec coverage:** sidebar (3 variants) ✓ T3/T4; header ✓ T5; slim taskbar ✓ T6; consolidate
  widgets ✓ T1(status)/T5(header chips)/T3(footer pulses)/T6(delete); brand "C" + solid wordmark
  ✓ T2; wallpaper watermark ✓ T6; preferences + Settings ✓ T1/T7; OS feel preserved (window
  manager, taskbar, ⌘K untouched) ✓ T6. Monitor window already exists — out of scope (the handoff
  re-mocked it but the real `Dashboard`/Monitor page stays).
- **Type consistency:** `sidebarVariant` union, `PROCESS_TONE` tone union, `useConsoleStatus` return
  shape, and `useNavApps` app shape are referenced identically across T1/T3/T4/T5/T6.
- **No placeholders:** every task names exact files, contracts, and acceptance tests.
- **Risk:** sigil `currentColor` refactor affects taskbar pills (improves them — pill div already
  sets gold/muted color, which the icons now inherit). Verified in T6.
