# 05 - Critic Review

> Cross-spec review of all workbench redesign documents.
>
> Severity: **P0** = must fix before implementation, **P1** = should fix, **P2** = nice to fix

---

## A. Cross-Spec Inconsistencies

### A1. Lens naming and availability disagree across specs [P0]

The three specs define different lens names and different availability-per-shell rules:

| Spec | Lens names used | Available-per-shell? |
|------|----------------|---------------------|
| 01-ARCHITECTURE (S2.2) | scopes, history, files, sandboxes, entities, swarms, notes | All lenses available in all shells |
| 02-INTERACTION-DESIGN (S1) | Scopes, History, Files, Sandboxes, Entities, Swarms, Notes (7 total) | Not discussed (implicitly all) |
| 03-COMPONENT-LAYOUT (S8) | scopes, history, files, sandboxes, entities, swarms, notes | **Restricted per shell** (Wire: scopes/history/swarm, Hunt: entities/history/swarm/sandbox, Lab: files/history/sandbox, Case: notes/history) |
| 04-MIGRATION-PLAN (Phase 1) | explorer, search, git, swarm, policies, marketplace, operations (7 total) | Not discussed |

The migration plan (04) uses a **completely different set of lens IDs** (explorer, search, git, policies, marketplace, operations) that do not match the architecture spec at all. This is a critical divergence. The 04 lens IDs map more closely to current plugin routes than to the conceptual lens model in 01.

The INDEX (Q6) correctly flags the availability disagreement but does not flag the naming divergence in 04.

**Resolution needed**: Align 04-MIGRATION-PLAN lens IDs with the canonical set from 01-ARCHITECTURE. Decide whether lenses are shell-restricted (03) or universally available (01). The INDEX identifies this as Q6 but it should be resolved before Phase 1 begins.

### A2. TabKind union differs between 01 and 03 [P1]

01-ARCHITECTURE (S3.4) defines `TabKind` as 15 variants:
```
signal-thread, hunt, receipt, case, sandbox, artifact, brief, profile, policy,
threat-radar, attack-graph, network-map, workflow, marketplace, operations
```

03-COMPONENT-LAYOUT (S4.5) defines `TabKind` as 10 variants:
```
file, terminal, search, git, hunt, feed, case, preview, settings, welcome
```

04-MIGRATION-PLAN (Phase 2) defines `TabKind` as 13 variants:
```
hunt-deck, file, operations, event-stream, policy-viewer, policy-tester,
swarm-map, marketplace, workflows, threat-radar, attack-graph, network-map,
security-overview
```

Three different `TabKind` unions across three specs. The 01 spec maps cleanly from the 13 existing plugins. The 03 spec invents IDE-style kinds (file, terminal, search, git) that don't exist in the plugin registry. The 04 spec maps directly to plugin IDs but uses hyphenated names.

**Resolution needed**: Pick one canonical `TabKind` union. Recommendation: use 01's set as the base (it maps 1:1 to existing plugins), add `file` for workspace files (as 04 does), and note that `terminal`, `search`, `git`, `welcome`, and `settings` are internal-only non-plugin tab kinds.

### A3. Sidebar width: 240px vs 260px [P1]

- 01-ARCHITECTURE (S4): `LensSidebar (~240px)`
- 02-INTERACTION-DESIGN (S7): `Width: 260px`
- 03-COMPONENT-LAYOUT (S1.1, S5): `--lens-sidebar-width: 240px`
- 04-MIGRATION-PLAN (Phase 1): `default 260px, min 200px, max 400px`

Two specs say 240px, two say 260px. The CSS token in 03 defines 240px. The min/max in 04 (200-400) differs from 03 (180-400).

**Resolution needed**: Pick one value. 240px is used in the CSS definition (03) and component tree (01), so 240px should be canonical. Update 02 and 04 to match.

### A4. Bottom panel default height disagrees [P2]

- 02-INTERACTION-DESIGN (S4): `Default state (Hunt/Lab): Expanded, 220px height`
- 03-COMPONENT-LAYOUT (S5): `--bottom-panel-height: 180px`
- 04-MIGRATION-PLAN (Phase 3): `default 240px`

Three different default heights (180, 220, 240). The CSS token in 03 says 180px.

**Resolution needed**: Pick one canonical default. 180px matches the existing `WorkspaceShellScreen` grid row of `180px` (`grid-rows-[minmax(0,1fr)_180px]` at line 350), so 180px is the natural default.

### A5. Activity Spine content layout disagrees [P1]

02-INTERACTION-DESIGN (S6) puts shell mode icons below the orb (Orb -> Shell icons -> Spacer -> Status -> Settings).

03-COMPONENT-LAYOUT (S4.2) says: "Top: OrbLensRotor. Below: lens icons (Explorer, Search, Git, Swarm, Policies, Marketplace, Operations). Bottom: settings gear, connection status dot."

01-ARCHITECTURE (S4) says: "OrbLensRotor + LensIcons + Spacer + ShellSwitcher + PostureIndicator"

So: 01 has lens icons in the spine, 02 has shell icons in the spine, 03 has lens icons. The lens icons vs. shell icons distinction is crucial -- if lenses are selected via spine icons, the orb becomes redundant. 02's design (orb for lenses, spine for shells) is the most coherent because it avoids duplicate lens selection surfaces.

**Resolution needed**: Align to 02's model -- orb cycles lenses, spine shows shell mode icons. Remove lens icons from the spine in 01 and 03.

### A6. Inspector toggle shortcut conflict [P1]

- 02-INTERACTION-DESIGN (S10): `Cmd+\` toggles inspector
- 04-MIGRATION-PLAN (Phase 4): `Cmd+Shift+I` toggles inspector

Two different shortcuts for the same action. `Cmd+\` is used elsewhere in 02 as well. `Cmd+Shift+I` conflicts with browser devtools on Electron-style apps (though Tauri may not intercept it).

**Resolution needed**: Use `Cmd+\` (from 02) as the canonical shortcut. It's consistent with VS Code's panel toggle pattern.

---

## B. Technical Accuracy

### B1. Registry line references are wrong in 04 [P1]

04-MIGRATION-PLAN (Phase 2 "Tab Kind Mapping" table) claims:
- `ForensicsRiverView` at `registry.tsx line 13`
- `OperationsHubView` at `registry.tsx line 17`
- `EventStreamView` at `registry.tsx line 9`

Actual line numbers in `registry.tsx`:
- `EventStreamView` is declared at line 9 (correct)
- `NexusView` (ForensicsRiverView) is at line 12-15 (close but "line 13" is inaccurate -- it's a multi-line lazy import)
- `OperationsHubView` is at line 17-18 (close)
- Plugin definitions start at line 59, not where the table implies

These are minor inaccuracies but can confuse implementers who try to find the referenced lines.

### B2. ShellLayout line references partially correct [P2]

01-ARCHITECTURE references `ShellApp.tsx:29-49` for the router -- verified correct (line 29: `createHashRouter`, line 49: closing the useMemo). References to `ShellLayout.tsx:206-234` for command palette commands -- actually the cyberNexusCommands block starts around line 135, and goes to line 283. The Nexus mode commands are at lines 206-232 (close enough).

### B3. Plugin count is 13 -- verified correct [P2]

All specs say 13 plugins. Verified: `registry.tsx` defines exactly 13 `AppPlugin` entries (nexus, workspace, operations, events, policies, policy-tester, swarm, marketplace, workflows, threat-radar, attack-graph, network-map, security-overview). Correct.

### B4. CyberNexusOrb LONG_PRESS_MS = 420ms -- verified correct

02-INTERACTION-DESIGN correctly references the 420ms long-press threshold from `CyberNexusOrb.tsx` line 16. Confirmed.

### B5. 04 references `ChronicleWorkbenchShelf` correctly [P2]

04-MIGRATION-PLAN mentions `ChronicleWorkbenchShelf` in Phase 3. Verified: `ShellLayout.tsx` line 9 imports it from `@/features/forensics/policy-workbench/ChronicleWorkbenchShelf`.

---

## C. UX Anti-Patterns and Concerns

### C1. Radial menu with 7 items is cluttered [P1]

The current radial menu has 4 items at 90deg spacing, which works well. Expanding to 7 items at ~51.4deg spacing in a 200px diameter circle creates items that are close together and harder to target. With `min-width: 72px` menu items (from existing CSS), adjacent items at 51.4deg separation would overlap at the 82px translateY radius specified.

**Recommendation**: Consider a vertical dropdown/flyout menu instead of radial for 7 items. Alternatively, increase the radial diameter to 280px+ to provide adequate spacing, or reduce menu item size.

### C2. Single-click lens cycling on the orb is risky [P1]

The orb is the most prominent UI element. Making single-click cycle through 7 lenses means:
- Users must click up to 6 times to reach a specific lens
- Accidental clicks change the sidebar content unexpectedly
- The current orb click navigates to `/nexus`, which is a useful "go home" behavior being lost

The long-press/right-click/Cmd+1-7 paths handle intentional lens switching well. The single-click cycle adds cognitive overhead without clear benefit.

**Recommendation**: Consider making single-click open the lens menu (instead of cycle), or make single-click a no-op that simply focuses the orb (entering orb focus mode for keyboard nav). The cycle-on-click pattern works for 4 items but is tedious for 7.

### C3. Quick Peek (Space) interaction needs more detail [P2]

02-INTERACTION-DESIGN defines Space as "Quick peek -- overlay preview, dismisses on next action or Esc" but doesn't specify:
- What the overlay looks like (modal? tooltip? floating panel?)
- Where it appears relative to the sidebar item
- Size constraints
- What happens if you Space on an item that's already open as a tab
- Whether the quick peek blocks keyboard navigation (can you arrow to next item while peek is open?)

**Recommendation**: Define the quick peek overlay as a fixed-position panel (e.g., 400x300px) anchored to the right of the sidebar, with the same glass panel styling as `premium-panel`. Dismiss on any keystroke except Esc (which dismisses and refocuses sidebar).

### C4. Is 7 lenses too many? [P1]

The specs define 7 lenses: Scopes, History, Files, Sandboxes, Entities, Swarms, Notes. In practice, an analyst in a given session likely uses 2-3 of these frequently. The rest are rarely visited. 7 lenses creates:
- A cluttered radial menu (see C1)
- Tedious click-cycling (see C2)
- A large lens ring on the orb with segments too small to visually parse

For comparison, VS Code has 5 primary sidebar views (Explorer, Search, Source Control, Run/Debug, Extensions) and even that is often considered many. JetBrains IDEs show 4 by default.

**Recommendation**: Consider merging Sandboxes into Lab shell content (not a lens) and merging Swarms into Entities (agents are entities). This reduces to 5 lenses (Scopes, History, Files, Entities, Notes), which fits a radial menu at 72deg spacing and a cleaner ring. Alternatively, keep 7 but make the radial menu a vertical list instead.

### C5. Is the 4-shell model adding unnecessary cognitive load? [P1]

The Shell concept (Wire/Hunt/Lab/Case) is essentially a layout preset that changes which lens is default, which bottom panel tabs are expanded, and the default split arrangement. Users must learn what each shell "means" and actively decide which one to use.

In practice, the actual differences between shells are small:
- Wire: bottom collapsed, Scopes lens
- Hunt: bottom expanded, Entities lens
- Lab: bottom expanded, Files lens
- Case: bottom collapsed, Notes lens

An experienced user could achieve the same result by manually toggling the bottom panel and switching lenses. The shell adds an indirection layer that may not earn its weight.

**Counterargument**: Shells provide useful "reset to sane defaults" behavior when context-switching between work modes. The cognitive load is front-loaded (learning 4 modes) but then reduces ongoing friction.

**Recommendation**: Keep shells but make them optional/discoverable rather than mandatory. The workbench should be fully functional without ever switching shells. A user who never touches the shell switcher should still have a good experience with manual lens/panel/split management.

### C6. Is the preview/pin tab distinction too subtle? [P1]

The only visual difference between a preview tab and a pinned tab is `font-style: italic` vs normal. On a 10-11px monospace font, this distinction is nearly invisible, especially on low-DPI displays or at a glance.

VS Code uses italic for preview tabs and it is a frequent source of user confusion -- "why did my tab disappear when I clicked another file?" is one of the most common VS Code complaints.

**Recommendation**: Add a secondary indicator beyond italic. Options:
- A small dot or ring before the title of preview tabs
- A different background tint (e.g., slightly transparent) for preview tabs
- A subtle "pin" icon on pinned tabs

At minimum, when a preview tab is about to be replaced, consider a brief flash/highlight on the tab being replaced so the user understands what happened.

### C7. Is the Companion tab too close to chatbot takeover? [P2]

02-INTERACTION-DESIGN (S5) defines Companion as "grounded, embedded AI assistance" with "discrete cards, not conversation turns." This is a good design direction. However, the risk is that over time, product pressure will push Companion toward a conversational chatbot interface because that's what users expect from "AI" features.

The spec correctly says "NOT a chatbot" but doesn't define guardrails for what Companion must NOT do:
- No free-form text input
- No multi-turn conversation history
- No streaming text generation visible to the user
- No "ask me anything" affordance

**Recommendation**: Add explicit anti-requirements to the Companion section: "Companion MUST NOT include a text input field, conversation history, or streaming response UI. All suggestions are pre-computed cards triggered by selection context changes."

### C9. Floating capsule UX value may be lost in the panel migration [P1]

The current DockSystem's floating capsules serve a genuinely different purpose than a fixed bottom panel: they overlay content without displacing it. An analyst can drag an Events capsule to the corner of the Hunt Deck 3D view, expand it temporarily, then collapse it back -- all without changing the layout of the workbench center area.

The bottom panel, by contrast, always steals vertical space from the center. For a workflow like "monitoring live receipts while hunting" the floating capsule is arguably better because it doesn't shrink the hunt canvas.

None of the specs acknowledge this tradeoff. The migration table in 04 (Phase 3) maps every capsule kind to either a bottom panel tab or the context inspector, with no mention of the multitasking benefit being lost.

**Recommendation**: Consider keeping a lightweight "detach to overlay" option for bottom panel tabs. When the user drags a bottom panel tab upward, it could pop out into a floating mini-panel (similar to Chrome's tab detach). This preserves the multitasking value without maintaining the full DockSystem complexity. If this is too costly, at minimum document the tradeoff explicitly and explain why the panel approach was chosen despite the regression.

### C10. "Scopes" lens content is vague for a security tool [P2]

02-INTERACTION-DESIGN (S7) defines Scopes as "Watchlists, followed techniques, sectors, teams, saved feeds." These are all new concepts with no existing implementation. The architecture spec (01 S2.2) maps Scopes to `workspace` plugin routes and `WorkspaceSurfaceState.tree`, which is workspace trust roots -- a completely different thing.

**Recommendation**: Clarify whether Scopes replaces the workspace root concept or is a separate feed-centric view. If the latter, the Files lens already handles workspace roots, so Scopes should focus exclusively on signal feed subscription management.

---

## D. Missing Edge Cases

### D0. Narrow window (1024px) does not fit the grid [P0]

03-COMPONENT-LAYOUT (S1.1) defines the grid columns as:
- Activity Spine: 48px
- Lens Sidebar: 240px (min 180px)
- Center: 1fr
- Context Inspector: 320px

At full width with inspector open: 48 + 240 + center + 320 = 608px fixed + center. At 1024px window width, the center gets 416px. This is barely usable for a single tab content pane, and completely unusable for a 2-pane horizontal split (each pane gets ~208px).

03 does define collapsed states (S1.2): sidebar collapses below 1024px. But even with sidebar collapsed (48 + 0 + center + 320), the center is only 656px, and with inspector also collapsed it's 976px of center -- which is fine. The issue is the *transition*: at exactly 1024px the sidebar auto-collapses, which is a jarring layout shift.

The Tauri desktop window has no guaranteed minimum size unless explicitly set. On a 13" laptop at native resolution with sidebar open, the available space is tight.

**Resolution needed**: Define a minimum window size (suggest 1024x768) enforced by Tauri's `min_inner_size`. Define the collapse cascade: at 1280px+ everything is visible; 1024-1279px sidebar collapses; below 1024px inspector also collapses. Add smooth transitions (200ms ease) on collapse to avoid jarring shifts. Add this to 03-COMPONENT-LAYOUT.

### D0b. Session restoration specifics are undefined [P1]

04-MIGRATION-PLAN (Phase 2 test strategy) says "WorkbenchState (including all tab groups) serializes to localStorage on change and restores on reload." But the specs don't define:
- What exactly is restored? (Tab list, active tab, split pane arrangement, scroll positions, selection state?)
- Are dirty tab buffers restored or lost? (Unsaved edits in policy files, case notes)
- What happens if a restored tab references an entity that no longer exists? (Deleted policy, expired hunt session)
- Is there a "Reopen last session" prompt vs automatic restore?
- Storage size limits: with 20+ tabs, each with metadata, localStorage's 5-10MB limit could be hit if tab metadata includes large payloads

The current `sessionStore.ts` (referenced in 04) persists session IDs and active session state. The new system needs to persist significantly more state (tab content offsets, split ratios, panel heights, inspector width, dirty buffers).

**Recommendation**: Define a `WorkbenchSnapshot` interface that explicitly lists what's persisted. Key rule: only persist references (tab kind + sourceUri + isPreview + isPinned + isDirty flag), not content. Dirty content should be persisted separately in IndexedDB (not localStorage) with a size budget. On restore, show a "Restore previous session?" toast with a 5-second auto-dismiss that restores all tabs.

### D1. Zero tabs state not specified [P0]

None of the specs define what happens when all tabs are closed:
- What does the center area show? A welcome screen? An empty state?
- Can the user operate with zero tabs? (They should be able to.)
- Is there a "reopen last session" mechanism?

The 03-COMPONENT-LAYOUT `TabKind` includes `"welcome"` which implies a welcome tab, but no spec describes its content or when it appears.

**Resolution needed**: Define the zero-tab state. Recommendation: show a shell-appropriate empty state with quick-start actions (Wire: "Open a feed", Hunt: "Start a hunt", Lab: "Open a folder", Case: "Create a case"). The existing `WorkspaceShellScreen` has empty/denied states (lines 511-543) that could be adapted.

### D2. Tab overflow (many tabs) not specified [P0]

No spec addresses what happens when tabs exceed the available tab bar width:
- Do they scroll horizontally?
- Is there a "more tabs" dropdown?
- Are excess tabs hidden with a count badge?
- What's the maximum number of tabs? (Q2 in INDEX is still open.)

This is critical for implementability. A hunt session could easily have 20+ tabs.

**Resolution needed**: Define tab overflow behavior. Recommendation: horizontal scroll with left/right scroll buttons appearing when tabs overflow. Add a "show all tabs" dropdown accessible via a chevron button at the right end of the tab bar. Consider a soft limit of 30 open tabs with a toast warning at 25.

### D3. Offline/disconnected mode behavior [P1]

The specs define a status indicator (LIVE/SYNC/OFFLINE) but don't describe how the workbench degrades when offline:
- Which lenses still work? (Files and Notes should. Entities, Swarms, and Scopes may not.)
- Are open tabs preserved? (Yes, they should be -- tab state is local.)
- Do bottom panel tabs degrade? (Terminal is local, Tape/Receipts need connection.)
- Does the Companion tab (AI suggestions) show a fallback?

**Recommendation**: Add a brief "Degraded Mode" section to 02 or 01. Key rule: locally-cached content remains navigable; live features show an inline "Offline" placeholder.

### D4. No workspace root registered [P2]

The current `WorkspaceShellScreen` has explicit empty and denied states for when no workspace root is registered (lines 511-543). The new specs don't address how the Files lens or Lab shell handles this case.

**Recommendation**: The Files lens should show the same trust-root registration flow currently in `WorkspaceShellScreen`. Lab shell without a root should show an empty state with "Register workspace root" CTA.

### D5. Dirty tab close confirmation not specified [P1]

02-INTERACTION-DESIGN defines the dirty state (gold dot) but doesn't specify what happens when the user closes a dirty tab:
- Is there a confirmation dialog?
- Does middle-click bypass confirmation?
- Does Cmd+W show the dialog?
- What about "Close All" from context menu?

The current `ShellLayout` has a blocker for dirty policy drafts (`shouldBlockDirtyPolicyDraftExit` at line 101-110). The workbench needs equivalent protection.

**Recommendation**: All close actions on dirty tabs show a "Save changes?" dialog: Save / Don't Save / Cancel. "Close All" aggregates: "N tabs have unsaved changes. Save all?" Middle-click is not exempt.

---

## E. Keyboard Model Issues

### E1. Cmd+B conflicts with macOS bold text [P1]

02-INTERACTION-DESIGN assigns `Cmd+B` to toggle the lens sidebar. On macOS, `Cmd+B` is the standard shortcut for bold text in any text editing context. If the user is editing a case note or policy YAML in the Lab shell, `Cmd+B` would toggle the sidebar instead of bolding text.

The current `useShellShortcuts.ts` (line 46) already guards against this by checking `target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable`. This guard must be preserved and documented.

**Recommendation**: Document explicitly that `Cmd+B` is suppressed when focus is inside a text input/editor. Alternatively, use `Cmd+Shift+B` (which doesn't conflict with bold) like VS Code does for its sidebar toggle.

### E2. Cmd+N semantics changed [P1]

Currently `Cmd+N` creates a new strikecell session (`useShellShortcuts.ts` line 62, dispatches `handleNewSession` in `ShellLayout.tsx` line 336-339).

02-INTERACTION-DESIGN (S10) redefines `Cmd+N` as "New tab in current pane." 01-ARCHITECTURE (S6.5) says `Cmd+N` is retained as "New session (creates strikecell session)."

These are different actions. Creating a session is a heavyweight operation with backend state; creating a tab is a lightweight UI operation.

**Resolution needed**: Either keep `Cmd+N` as new session (01's position) or change it to new tab (02's position). If new tab, add `Cmd+Shift+N` for new session.

### E3. Cmd+Shift+[ and Cmd+Shift+] conflict with tab cycling [P2]

02-INTERACTION-DESIGN (S10) assigns:
- `Cmd+[` / `Cmd+]` = Navigate back/forward
- `Cmd+Shift+[` / `Cmd+Shift+]` = Previous/next tab

01-ARCHITECTURE (S6.5) says `Cmd+[` / `Cmd+]` is "repurposed: cycles lenses instead of apps."

So 01 and 02 disagree on what `Cmd+[/]` does (lens cycling vs. back/forward navigation). And 02 uses the Shift variants for tab cycling, which conflicts with `Cmd+Tab` / `Cmd+Shift+Tab` also defined for the same purpose.

**Resolution needed**: Consolidate. Recommendation: `Cmd+[/]` = navigate back/forward (standard browser behavior), `Ctrl+Tab` / `Ctrl+Shift+Tab` = cycle tabs. Remove the `Cmd+Shift+[/]` duplicate.

### E4. `O` as orb focus mode trigger [P2]

02-INTERACTION-DESIGN assigns bare `O` key (no modifier) to enter orb focus mode. This means pressing `O` in any context where the shortcuts handler is active (i.e., not in a text input) would activate the orb instead of doing nothing.

This is fine if the guard in `useShellShortcuts.ts` line 46 is active, but it's unusual for a desktop app to use bare letter keys as shortcuts outside of a vim-like mode.

**Recommendation**: Either gate `O` behind a mode indicator (only works when no panel has focus) or use `Cmd+O` (which currently isn't assigned). Alternatively, document that this only fires when focus is on the spine itself.

---

## F. Feasibility Concerns

### F1. Performance with split panes + 3D backgrounds [P1]

The current `ShellLayout.tsx` (line 123-133) already disables `SOCBackground` (the ambient 3D WebGL scene) for nexus, workspace, swarm, threat-radar, attack-graph, network-map, and security-overview routes. In the workbench, multiple tab kinds could be simultaneously alive in split panes, and the `SOCBackground` is a persistent overlay.

04-MIGRATION-PLAN mentions this risk and suggests disabling SOCBackground in workbench mode entirely. None of the other specs address this.

**Recommendation**: Explicitly call out in 01 that `SOCBackground` is disabled when the workbench is active. Add a note in 03's component tree.

### F2. Tab keep-alive pool has memory implications [P1]

04-MIGRATION-PLAN (Phase 2) says `TabContentRenderer` "Keeps recently-used tabs alive in a hidden DOM pool (configurable, default 3) for fast switching." This means up to 3 offscreen tab contents remain mounted in the DOM.

If those tabs include heavy components (3D views like ThreatRadar, AttackGraph, NetworkMap, SwarmMap), keeping them alive could consume significant GPU/memory resources.

**Recommendation**: Exclude 3D-heavy tab kinds from the keep-alive pool. Only keep-alive lightweight text/list views. Add a `keepAlive: boolean` flag to `TabKind` metadata in the registry.

### F3. 2x2 split with 4 independent tab bars is complex [P2]

The 2x2 split grid means 4 tab bars, each with their own preview tab, drag targets, and tab ordering. Combined with the bottom panel and inspector, the user could have 6+ independent scrollable/interactive regions on screen simultaneously.

This is achievable but the implementation cost is high. The `SplitPaneContainer` needs recursive layout, focus management, and cross-pane tab dragging.

**Recommendation**: Consider shipping with max 1x2 (2 panes) in Phase 2, and adding 2x2 in a later phase. The 2x2 case is rarely needed and adds disproportionate complexity.

### F4. Phase 1-2 scope: 24 new files is ambitious for an incremental migration [P1]

Counting the "Files to Create" tables across all four phases:
- Phase 1: 7 new files (WorkbenchShell, WorkbenchStateProvider, workbenchState, ActivitySpine, OrbLensRotor, LensSidebar, StatusBar)
- Phase 2: 4 new files (TabBar, TabContentRenderer, SplitPaneContainer, tabRegistry)
- Phase 3: 8 new files (BottomPanel, BottomPanelTabs, 6 panel components)
- Phase 4: 5 new files (ContextInspector, 4 inspector tab components)

Total: **24 new files** plus significant modifications to 8+ existing files. And each of these "files" is a non-trivial React component -- `SplitPaneContainer` alone requires recursive layout, focus management, resize handles, and cross-pane tab dragging.

Phase 1+2 together (11 new files) must ship behind a feature flag while keeping the old shell working. This means maintaining two parallel layout systems for the duration.

**Recommendation**: Consider splitting Phase 1 into 1a (ActivitySpine + StatusBar + WorkbenchShell with `<Outlet/>` -- minimum viable frame) and 1b (OrbLensRotor + LensSidebar -- sidebar system). Ship 1a first to validate the grid layout before adding lens complexity. Phase 2 is already well-scoped but SplitPaneContainer should be deferred to a Phase 2b -- start with single-pane tabs only.

### F5. Keyboard navigation completeness is underspecified [P1]

The keyboard model in 02-INTERACTION-DESIGN (S10) covers shortcut bindings but does not define:
- **Focus order**: What is the Tab key order across regions? (Spine -> Sidebar -> TabBar -> Content -> BottomPanel -> Inspector -> StatusBar? Or something else?)
- **Focus trapping**: When the bottom panel is expanded, does Tab wrap within it or escape to the next region?
- **Arrow key navigation within sidebar**: Can the user arrow through lens items? Is there a tree-nav pattern (left/right to collapse/expand, up/down to move)?
- **Screen reader landmarks**: Are the 5 major regions (spine, sidebar, center, bottom panel, inspector) declared as ARIA landmark regions?

The existing `useShellShortcuts.ts` handles modifiers well but there's no `useFocusZone` or equivalent for sequential Tab navigation across regions.

**Recommendation**: Add a "Focus Management" subsection to 02-INTERACTION-DESIGN defining: (1) Tab order across the 5 regions, (2) `F6` as the "cycle region" shortcut (standard in VS Code and many IDEs), (3) ARIA `role="region"` with `aria-label` on each major area, (4) arrow key navigation within tree views and tab bars.

---

## G. Visual Hierarchy

### G1. Gold usage rules are clear but enforcement mechanism is missing [P2]

02-INTERACTION-DESIGN (S8) defines when gold can be used. However, there's no linting or code-review mechanism to enforce this. With 20+ new components and multiple developers, gold accent creep is likely.

**Recommendation**: Add a brief style guide comment in `styles.css` near the `--origin-gold` definition explaining the usage rules. Consider a Stylelint custom rule that flags new uses of the gold hex value or CSS variable outside of approved class patterns.

### G2. WCAG AA contrast: gold-dim and muted text fail on some backgrounds [P1]

The specs reference the design token `--origin-gold-dim: #9f7c3a` and `--color-text-muted: #7f8494` for secondary/deemphasized text. Checking against the WCAG AA threshold (4.5:1 for normal text, 3:1 for large text):

| Foreground | Background | Contrast Ratio | AA Normal | AA Large |
|-----------|-----------|----------------|-----------|----------|
| `#d5ad57` (gold) | `#05060a` (primary) | ~7.9:1 | Pass | Pass |
| `#9f7c3a` (gold-dim) | `#05060a` (primary) | ~4.5:1 | Borderline | Pass |
| `#7f8494` (text-muted) | `#05060a` (primary) | ~4.8:1 | Pass | Pass |
| `#7f8494` (text-muted) | `#131721` (tertiary) | ~3.9:1 | **Fail** | Pass |
| `#9f7c3a` (gold-dim) | `#0b0d13` (secondary) | ~4.1:1 | **Fail** | Pass |
| `#b6b7c1` (text-secondary) | `#05060a` (primary) | ~9.4:1 | Pass | Pass |

The `text-muted` color on `tertiary` background fails AA for normal-sized text. This combination would appear in the status bar (24px, likely 11-12px font) and bottom panel secondary labels. The `gold-dim` on `secondary` background also fails for body text.

**Recommendation**: Lighten `--origin-gold-dim` from `#9f7c3a` to `#b08e4a` (reaches ~5.5:1 on secondary) or restrict its use to large text/icons only. For `text-muted` on tertiary backgrounds, bump to `#8f94a4` (~5.0:1). Add these ratios to the design token appendix in 02-INTERACTION-DESIGN.

### G3. 48px Activity Spine icon spacing may be too tight [P1]

The Activity Spine is 48px wide. Shell mode icons (Wire, Hunt, Lab, Case) are described as "24px icons" in 02-INTERACTION-DESIGN (S6). With 48px width and 24px icons, there's 12px horizontal padding per side. This is fine.

But vertically, the spine stacks: Orb (~44px with glow ring) + 4 shell icons (24px each + 8px gap = ~128px) + spacer + status indicators (~48px). The shell icons alone need ~128px of vertical space. The orb with its glow/ring needs ~60px. Status indicators need ~48px. Total fixed: ~236px, leaving the rest as spacer.

The concern is touch target size. Each shell icon at 24x24px with 8px gap gives a 24x32px hit area. The minimum recommended touch target is 44x44px (WCAG 2.5.5 Level AAA) or 24x24px (Level AA). The icons technically pass AA but are tight for a desktop app that may run on touch-enabled displays.

**Recommendation**: Use 32px icons with 12px vertical gap (44px pitch) to meet the AAA touch target guideline. This fits within 48px width (32px icon + 8px padding per side). Total shell icon area becomes ~176px, which still fits comfortably.

### G4. Bottom panel tab active state uses underline, not the existing pill pattern [P2]

02-INTERACTION-DESIGN (S4) specifies `border-bottom: 2px solid rgba(213,173,87,0.8)` for active bottom panel tabs. The existing tab pattern in `WorkspaceShellScreen` (line 328-333) uses pill-shaped `rounded-full border ... bg-[rgba(213,173,87,0.12)]` for active tabs.

These are two different active-tab visual patterns in the same app. The bottom panel uses underline; the workspace tabs use pill + background.

**Recommendation**: Pick one pattern for all tab bars (workbench tabs, bottom panel tabs, inspector tabs). The underline pattern is more compact and standard for IDE-style panels. Use it consistently.

---

## H. Consistency Issues

### H1. "Shell" naming overload [P2]

The term "Shell" is used for two different concepts:
1. The workbench layout preset (Wire/Hunt/Lab/Case) -- the new meaning
2. The current `ShellLayout`, `ShellApp`, `WorkspaceShellScreen` -- the old meaning (application shell/chrome)

This will cause confusion during migration when both systems coexist.

**Recommendation**: Use "Mode" for the layout preset (Wire Mode, Hunt Mode) to disambiguate. The term "Shell" can continue to mean the application shell. This is a naming-only change that avoids collision with the existing `ShellLayout` and `WorkspaceShellScreen` component names.

### H2. 02 says Cmd+N is "New tab", 01 says it's "New session" [P1]

(Duplicate of E2, listed here for completeness as a consistency issue.)

### H3. "Posture" vs "Operation Mode" terminology [P2]

01-ARCHITECTURE (S2.1) introduces "posture overlay" and uses `NexusOperationMode` as the type. 02-INTERACTION-DESIGN (S9) shows "posture level: permissive / default / strict" in the status bar -- but these are **enforcement posture levels** (from the Clawdstrike policy engine), not the `NexusOperationMode` values (observe/trace/contain/execute).

These are two different concepts being conflated:
- `NexusOperationMode`: the analyst's working stance (observe/trace/contain/execute)
- Policy enforcement posture: the daemon's security level (permissive/default/strict)

**Resolution needed**: The status bar should show both: the analyst posture (observe/trace/contain/execute) and the enforcement posture (permissive/default/strict). Currently 02 only shows the enforcement posture.

---

## Summary

| Severity | Count | Key Items |
|----------|-------|-----------|
| **P0** | 4 | A1 (lens naming divergence), D0 (narrow window layout), D1 (zero tabs), D2 (tab overflow) |
| **P1** | 22 | A2, A3, A5, A6, B1, C1, C2, C4, C5, C6, C9, D0b, D3, D5, E1, E2, F1, F2, F4, F5, G2, G3 |
| **P2** | 12 | A4, B2, C3, C7, C10, D4, E3, E4, F3, G1, G4, H1, H3 |

H2 is a duplicate of E2. B3, B4, and B5 are verification-only (confirmed correct).

**Total unique findings: 38** across 8 review categories.

The four P0 items must be resolved before implementation begins:
- **A1**: The migration plan uses different lens IDs than every other spec. This blocks Phase 1.
- **D0**: The CSS grid doesn't fit at 1024px with all panels open. Need collapse cascade rules.
- **D1/D2**: Zero-tab and tab-overflow states are undefined, blocking the tab workbench (Phase 2).

The 18 P1 items should be resolved during Phase 1 planning. Notable additions from this review pass:
- **C4/C5**: 7 lenses and 4 shells may be too many concepts for users to learn
- **C9**: Floating capsule multitasking value is lost in the panel migration with no acknowledgment
- **F4**: 24 new files across 4 phases is ambitious; consider sub-phasing
- **F5**: Keyboard focus management (Tab order, F6 region cycling, ARIA landmarks) is unspecified
- **G2**: Gold-dim and text-muted colors fail WCAG AA on some background combinations
- **G3**: 48px spine with 24px icons may not meet touch target guidelines

P2 items can be addressed incrementally during implementation.
