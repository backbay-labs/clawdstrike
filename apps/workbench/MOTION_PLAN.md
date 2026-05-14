# ClawdStrike Workbench -- Motion Design & Delight Plan

**Product**: ClawdStrike Detection IDE (Workbench)
**Audience**: Senior security engineers, SOC analysts, threat hunters
**Brand Personality**: Precision-engineered. Obsidian dark. Bloomberg Terminal meets cybersecurity
**Tech Stack**: React 19, Tailwind CSS 4, Motion (framer-motion successor, `motion/react`), Tauri desktop
**Aesthetic Constraint**: Delight = precision engineering, NOT playfulness. Every animation must feel like a well-tuned instrument

---

## Design Principles

1. **Surgical precision**: Animations communicate state, not personality. A tab sliding into place says "your action registered" -- it does not wink at the user.
2. **Instrument-grade feedback**: Like a hardware oscilloscope or a Bloomberg keyboard -- every press, every change has immediate, proportional acknowledgment.
3. **Fail-closed polish**: If an animation cannot run at 60fps, it does not run. `prefers-reduced-motion` is respected everywhere.
4. **Obsidian physics**: Elements in this UI have weight. They decelerate exponentially. They do not bounce, do not overshoot, do not wobble. Think CRT phosphor decay, not rubber balls.

### Motion Tokens (CSS custom properties, add to `globals.css`)

```css
:root {
  /* Durations */
  --duration-instant: 80ms;      /* micro-feedback: button press, toggle */
  --duration-fast: 150ms;        /* state changes: hover, filter toggle */
  --duration-normal: 250ms;      /* layout shifts: tab switch, panel open */
  --duration-slow: 400ms;        /* entrance animations: modal, palette */
  --duration-emphasis: 600ms;    /* hero moments: coverage milestone */

  /* Easings */
  --ease-out-quart: cubic-bezier(0.25, 1, 0.5, 1);
  --ease-out-expo: cubic-bezier(0.16, 1, 0.3, 1);
  --ease-in-quart: cubic-bezier(0.5, 0, 0.75, 0);
  --ease-in-out-quart: cubic-bezier(0.76, 0, 0.24, 1);

  /* Motion scales */
  --scale-press: 0.97;
  --scale-hover: 1.02;
  --slide-distance: 8px;
}

@media (prefers-reduced-motion: reduce) {
  :root {
    --duration-instant: 0ms;
    --duration-fast: 0ms;
    --duration-normal: 0ms;
    --duration-slow: 0ms;
    --duration-emphasis: 0ms;
    --slide-distance: 0px;
  }
}
```

### Motion Library Usage

The workbench already uses `motion` v12+ (the framer-motion successor) via `motion/react`. The toast system already demonstrates the pattern with `AnimatePresence` and `motion.div`. All new animations should use this library for orchestrated, interruptible animations and CSS transitions/keyframes for simple state changes.

---

## 1. Tab System (`policy-tab-bar.tsx`)

### 1.1 Tab Creation

| Property | Value |
|----------|-------|
| **What** | New tab element slides in from the right and fades up |
| **How** | `initial={{ opacity: 0, x: 20, scaleX: 0.9 }}` -> `animate={{ opacity: 1, x: 0, scaleX: 1 }}` |
| **When** | `NEW_TAB` or `DUPLICATE_TAB` dispatch |
| **Duration** | 250ms, ease-out-expo |
| **Priority** | Must-have |

**Implementation**: Wrap the tab list in `<AnimatePresence>` and each `TabItem` in `<motion.div layout>`. The `layout` prop handles reflow when tabs are added/removed. Use `layoutId={tab.id}` for tab identity.

```tsx
<AnimatePresence mode="popLayout">
  {tabs.map((tab) => (
    <motion.div
      key={tab.id}
      layout
      initial={{ opacity: 0, scaleX: 0.9 }}
      animate={{ opacity: 1, scaleX: 1 }}
      exit={{ opacity: 0, scaleX: 0.8, transition: { duration: 0.15 } }}
      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
    >
      <TabItem ... />
    </motion.div>
  ))}
</AnimatePresence>
```

### 1.2 Tab Switching -- Active Indicator

| Property | Value |
|----------|-------|
| **What** | The 2px colored bottom border slides from the previously active tab to the newly active tab |
| **How** | `layoutId="tab-active-indicator"` on the bottom border div, using shared layout animation |
| **When** | `SWITCH_TAB` dispatch |
| **Duration** | 200ms, ease-out-quart |
| **Priority** | Must-have |

**Implementation**: Use Motion's `layoutId` for the active indicator. Only the active tab renders the indicator, and Motion automatically interpolates the position.

```tsx
{isActive && (
  <motion.div
    layoutId="tab-active-indicator"
    className="absolute bottom-0 left-0 right-0 h-[2px]"
    style={{ backgroundColor: FILE_TYPE_REGISTRY[tab.fileType ?? "clawdstrike_policy"].iconColor }}
    transition={{ type: "tween", duration: 0.2, ease: [0.25, 1, 0.5, 1] }}
  />
)}
```

### 1.3 Tab Close

| Property | Value |
|----------|-------|
| **What** | Tab shrinks horizontally and fades out |
| **How** | `exit={{ opacity: 0, scaleX: 0.8 }}` |
| **When** | `CLOSE_TAB` dispatch |
| **Duration** | 150ms (exits are 75% of entrance duration), ease-in-quart |
| **Priority** | Must-have |

### 1.4 Tab Reorder (Drag)

| Property | Value |
|----------|-------|
| **What** | Tabs smoothly reflow to their new positions during drag |
| **How** | `layout` prop on each tab handles positional interpolation automatically |
| **When** | `REORDER_TABS` dispatch after drop |
| **Duration** | 200ms, ease-out-quart |
| **Priority** | Must-have |

### 1.5 Format Dot Pulse on New Tab

| Property | Value |
|----------|-------|
| **What** | The 8px format dot beside the tab name briefly scales up and glows when a new tab is created |
| **How** | `animate={{ scale: [1, 1.4, 1] }}` with a box-shadow keyframe matching the format color |
| **When** | Tab creation, plays once |
| **Duration** | 400ms, ease-out-quart |
| **Priority** | Nice-to-have |

### 1.6 Dirty Dot Appearance

| Property | Value |
|----------|-------|
| **What** | The gold dirty-indicator dot (1.5px) scales from 0 to full size |
| **How** | `initial={{ scale: 0 }}` -> `animate={{ scale: 1 }}` |
| **When** | Tab `dirty` state transitions from false to true |
| **Duration** | 150ms, ease-out-expo |
| **Priority** | Must-have |

### 1.7 New Tab Dropdown

| Property | Value |
|----------|-------|
| **What** | Format dropdown menu slides down from the button and fades in |
| **How** | `initial={{ opacity: 0, y: -4, scaleY: 0.95 }}` -> `animate={{ opacity: 1, y: 0, scaleY: 1 }}` with `transformOrigin: "top"` |
| **When** | Dropdown caret click |
| **Duration** | 200ms enter, 150ms exit, ease-out-expo |
| **Priority** | Must-have |

### 1.8 Close Confirmation Popover

| Property | Value |
|----------|-------|
| **What** | Inline "Unsaved changes" popover slides down from the tab |
| **How** | `initial={{ opacity: 0, y: -6 }}` -> `animate={{ opacity: 1, y: 0 }}` |
| **When** | First click on dirty tab close button |
| **Duration** | 200ms, ease-out-expo |
| **Priority** | Must-have |

---

## 2. Command Palette (`command-palette.tsx`)

### 2.1 Palette Open

| Property | Value |
|----------|-------|
| **What** | Backdrop fades in; palette container scales up from 0.96 and slides down 8px |
| **How** | Backdrop: `initial={{ opacity: 0 }}` -> `animate={{ opacity: 1 }}`. Container: `initial={{ opacity: 0, y: -8, scale: 0.96 }}` -> `animate={{ opacity: 1, y: 0, scale: 1 }}` |
| **When** | Cmd+K / palette open |
| **Duration** | Backdrop: 200ms. Container: 300ms, ease-out-expo |
| **Priority** | Must-have |

### 2.2 Palette Close

| Property | Value |
|----------|-------|
| **What** | Container scales down and fades; backdrop fades out |
| **How** | Container: `exit={{ opacity: 0, scale: 0.96, y: -4 }}`. Backdrop: `exit={{ opacity: 0 }}` |
| **When** | Escape key or backdrop click |
| **Duration** | 150ms, ease-in-quart |
| **Priority** | Must-have |

### 2.3 Search Filter Transition

| Property | Value |
|----------|-------|
| **What** | Command items that match the query stay in place; non-matching items collapse out with height 0 and opacity 0 |
| **How** | Wrap items in `<AnimatePresence>` with `<motion.div layout>` on each. Non-matching items exit with `exit={{ opacity: 0, height: 0 }}` |
| **When** | Search query changes |
| **Duration** | 150ms, ease-out-quart |
| **Priority** | Nice-to-have (simpler approach: just re-render filtered list with no animation) |

### 2.4 Selection Highlight

| Property | Value |
|----------|-------|
| **What** | The active-item highlight bar slides vertically between items |
| **How** | Use a shared `layoutId="palette-highlight"` on the active item background, or use CSS `transition: background-color 80ms` |
| **When** | Arrow key navigation or mouse hover |
| **Duration** | 80ms (instant feedback), ease-out-quart |
| **Priority** | Must-have (CSS transition is sufficient -- already partially implemented via `transition-colors`) |

### 2.5 Command Execution Flash

| Property | Value |
|----------|-------|
| **What** | Selected command row briefly flashes gold (#d4a84b at 15% opacity) before the palette closes |
| **How** | CSS: `@keyframes cmd-execute { 0% { background: #d4a84b26; } 100% { background: transparent; } }` |
| **When** | Enter key or click on a command |
| **Duration** | 120ms |
| **Priority** | Nice-to-have |

---

## 3. Editor Panels

### 3.1 Sigma Visual Panel -- Section Collapse/Expand (`sigma-visual-panel.tsx`)

| Property | Value |
|----------|-------|
| **What** | Section content area expands/collapses with height animation |
| **How** | Use `grid-template-rows: 0fr` -> `1fr` technique via CSS transition, or use Motion's `<AnimatePresence>` with `initial={{ opacity: 0, height: 0 }}` -> `animate={{ opacity: 1, height: "auto" }}` |
| **When** | Section header click |
| **Duration** | 200ms, ease-out-quart |
| **Priority** | Must-have |

**Implementation** (CSS grid approach, no JS measurement needed):

```tsx
<div
  className="grid transition-[grid-template-rows] duration-200"
  style={{ gridTemplateRows: open ? "1fr" : "0fr" }}
>
  <div className="overflow-hidden">
    <div className="flex flex-col gap-3 px-4 pb-4 pt-1">
      {children}
    </div>
  </div>
</div>
```

### 3.2 Section Chevron Rotation

| Property | Value |
|----------|-------|
| **What** | Chevron icon rotates 90 degrees between collapsed (right) and expanded (down) |
| **How** | CSS `transition: transform 150ms var(--ease-out-quart)` with `rotate(90deg)` |
| **When** | Section open/close toggle |
| **Duration** | 150ms, ease-out-quart |
| **Priority** | Must-have (partially exists -- chevron switches between two icons; should use rotation on one icon instead) |

**Current issue**: The component swaps between `IconChevronDown` and `IconChevronRight`. This should be a single `IconChevronRight` with a CSS rotation transform for smooth animation.

```tsx
<span className="transition-transform duration-150" style={{ transform: open ? "rotate(90deg)" : "rotate(0deg)" }}>
  <IconChevronRight size={12} stroke={1.5} className="text-[#6f7f9a]/70" />
</span>
```

### 3.3 Visual Panel Error Banner

| Property | Value |
|----------|-------|
| **What** | Parse error banner slides in from top with a subtle left-border accent |
| **How** | `initial={{ opacity: 0, y: -4, height: 0 }}` -> `animate={{ opacity: 1, y: 0, height: "auto" }}` |
| **When** | YAML parse errors appear or disappear |
| **Duration** | 200ms, ease-out-expo |
| **Priority** | Nice-to-have |

### 3.4 Status/Level Badge Color Transition

| Property | Value |
|----------|-------|
| **What** | When the user changes the status or level dropdown, the summary badge at the top smoothly transitions its color |
| **How** | CSS `transition: color 200ms, background-color 200ms, border-color 200ms` on the badge elements |
| **When** | Status or level field change |
| **Duration** | 200ms, ease-out-quart |
| **Priority** | Nice-to-have |

### 3.5 Split View Transition

| Property | Value |
|----------|-------|
| **What** | When toggling split view, the editor panel divides with a smooth width animation |
| **How** | CSS `transition: flex-basis 300ms var(--ease-out-quart)` on the editor panes |
| **When** | Split view toggle |
| **Duration** | 300ms, ease-out-quart |
| **Priority** | Must-have |

### 3.6 Visual-YAML Sync Highlight

| Property | Value |
|----------|-------|
| **What** | When a field changes in the visual panel, the corresponding YAML lines in the code editor briefly highlight with a gold (#d4a84b) gutter flash |
| **How** | CodeMirror decoration with CSS animation `@keyframes sync-flash { 0% { background: #d4a84b15; } 100% { background: transparent; } }` |
| **When** | Visual panel field edit syncs to YAML |
| **Duration** | 600ms fade-out |
| **Priority** | Nice-to-have (high-value delight moment for detection engineers) |

---

## 4. Problems Panel (`problems-panel.tsx`)

### 4.1 New Diagnostic Slide-In

| Property | Value |
|----------|-------|
| **What** | New problem rows slide in from the left (matching the left severity border) and fade in |
| **How** | Wrap rows in `<AnimatePresence>`. Each row: `initial={{ opacity: 0, x: -12 }}` -> `animate={{ opacity: 1, x: 0 }}` |
| **When** | New diagnostics appear in the list |
| **Duration** | 200ms, ease-out-expo, stagger 50ms per item (cap at 5 items = 250ms total) |
| **Priority** | Must-have |

### 4.2 Severity Count Badge Update

| Property | Value |
|----------|-------|
| **What** | When error/warning/info count changes, the count number briefly scales up |
| **How** | CSS keyframe: `@keyframes count-bump { 0% { transform: scale(1); } 50% { transform: scale(1.15); } 100% { transform: scale(1); } }` triggered by key change |
| **When** | Diagnostic count changes |
| **Duration** | 200ms |
| **Priority** | Nice-to-have |

### 4.3 Filter Toggle Indicator

| Property | Value |
|----------|-------|
| **What** | Active filter button has a sliding background highlight (like a tab indicator) |
| **How** | Use `layoutId="problems-filter-highlight"` on the active filter's background element |
| **When** | Filter button click |
| **Duration** | 200ms, ease-out-quart |
| **Priority** | Nice-to-have |

### 4.4 "All Clear" State -- Zero Problems

| Property | Value |
|----------|-------|
| **What** | When the last problem is resolved, the checkmark icon fades in with a subtle scale-up and brief gold ring flash |
| **How** | `initial={{ opacity: 0, scale: 0.8 }}` -> `animate={{ opacity: 1, scale: 1 }}`. A ring element: `@keyframes clear-ring { 0% { box-shadow: 0 0 0 0 #3dbf8440; } 100% { box-shadow: 0 0 0 12px transparent; } }` |
| **When** | Problem count transitions from >0 to 0 |
| **Duration** | 400ms, ease-out-expo |
| **Priority** | Must-have (key delight moment -- validation passing is a milestone) |

**This is a Delight Moment**: When all problems clear, the icon gets a single expanding ring (like a sonar ping) in verdict-allow green (#3dbf84). Subtle. Satisfying. The kind of feedback that makes an engineer feel the tool is responsive and aware.

### 4.5 Diagnostic Exit

| Property | Value |
|----------|-------|
| **What** | Resolved diagnostics collapse out with height -> 0 and opacity -> 0 |
| **How** | `exit={{ opacity: 0, height: 0, marginBottom: 0 }}` with `overflow: hidden` |
| **When** | Diagnostic removed from list |
| **Duration** | 150ms, ease-in-quart |
| **Priority** | Must-have |

---

## 5. File Explorer (`explorer-panel.tsx`, `explorer-tree-item.tsx`)

### 5.1 Directory Expand/Collapse

| Property | Value |
|----------|-------|
| **What** | Child nodes slide in vertically with staggered timing when a directory expands |
| **How** | Wrap visible children in `<AnimatePresence>`. Each child: `initial={{ opacity: 0, x: -4 }}` -> `animate={{ opacity: 1, x: 0 }}` with `transition={{ delay: index * 0.03 }}` |
| **When** | Directory toggle |
| **Duration** | 150ms per item, 30ms stagger, cap total stagger at 300ms (10 items) |
| **Priority** | Must-have |

**Note**: The explorer uses `flattenTree` to produce a flat list. Animation should be handled at the item level with `<AnimatePresence>` wrapping the list and `key={file.path}` on each `motion.div`.

### 5.2 Chevron Rotation

| Property | Value |
|----------|-------|
| **What** | Directory chevron rotates 90deg |
| **How** | Already implemented via `transition-transform duration-150` and `rotate-90` class. Keep as-is |
| **When** | Directory toggle |
| **Duration** | 150ms |
| **Priority** | Already done |

### 5.3 Active File Indicator

| Property | Value |
|----------|-------|
| **What** | Gold left-border accent (2px) slides vertically to the newly selected file |
| **How** | Use `layoutId="explorer-active-indicator"` on the gold accent div |
| **When** | File selection change |
| **Duration** | 200ms, ease-out-quart |
| **Priority** | Nice-to-have |

### 5.4 File Hover Reveal

| Property | Value |
|----------|-------|
| **What** | On hover, a subtle background highlight fades in |
| **How** | Already implemented via `hover:bg-[#131721]/40` with `transition-colors`. Keep as-is |
| **When** | Mouse hover |
| **Duration** | 150ms |
| **Priority** | Already done |

### 5.5 Format Filter Dot Toggle

| Property | Value |
|----------|-------|
| **What** | Format filter dot scales up and fills with color when activated; scales down and hollows when deactivated |
| **How** | CSS `transition: transform 150ms var(--ease-out-expo), background-color 150ms, opacity 150ms` |
| **When** | Format dot click |
| **Duration** | 150ms, ease-out-expo |
| **Priority** | Must-have (partially exists via `scale-110` class; add transition smoothing) |

### 5.6 Empty State -- "Open a folder"

| Property | Value |
|----------|-------|
| **What** | Folder icon fades in with slight upward drift; "Open Folder" button appears with 200ms delay |
| **How** | Staggered entrance: icon at 0ms, text at 100ms, button at 200ms. Each: `initial={{ opacity: 0, y: 4 }}` -> `animate={{ opacity: 1, y: 0 }}` |
| **When** | Explorer mounts with no project |
| **Duration** | 400ms total sequence |
| **Priority** | Nice-to-have |

---

## 6. MITRE ATT&CK Heatmap (`mitre-heatmap.tsx`)

### 6.1 Cell Hover -- Tooltip Entrance

| Property | Value |
|----------|-------|
| **What** | Tooltip fades in and slides up 4px from the cell |
| **How** | `initial={{ opacity: 0, y: 4 }}` -> `animate={{ opacity: 1, y: 0 }}` |
| **When** | Cell mouse enter |
| **Duration** | 150ms, ease-out-expo |
| **Priority** | Must-have |

### 6.2 Coverage Progress Bar Fill

| Property | Value |
|----------|-------|
| **What** | Progress bar width animates from 0 to the coverage percentage |
| **How** | Already implemented via `transition-all duration-500`. Enhance: use `ease-out-expo` easing and add a subtle glow trailing edge |
| **When** | Component mount and coverage recalculation |
| **Duration** | 600ms, ease-out-expo |
| **Priority** | Must-have (partially exists; improve easing) |

**Enhancement**: Add a subtle light sweep effect that follows the progress bar fill:

```css
.coverage-bar-fill::after {
  content: "";
  position: absolute;
  top: 0; right: 0; bottom: 0;
  width: 20px;
  background: linear-gradient(90deg, transparent, currentColor);
  opacity: 0.3;
  animation: coverage-sweep 600ms var(--ease-out-expo) forwards;
}
```

### 6.3 Cell Click -- Detail Panel Slide

| Property | Value |
|----------|-------|
| **What** | Detail panel slides in from the right edge |
| **How** | `initial={{ opacity: 0, x: 20 }}` -> `animate={{ opacity: 1, x: 0 }}` |
| **When** | Cell click selects a technique |
| **Duration** | 250ms, ease-out-expo |
| **Priority** | Must-have |

### 6.4 Cell Click -- Selected Ring

| Property | Value |
|----------|-------|
| **What** | Selected cell gets a gold ring that appears with a brief pulse |
| **How** | Already implemented via `ring-1 ring-[#d4a84b] scale-[1.02]`. Add transition smoothing |
| **When** | Cell click |
| **Duration** | 150ms |
| **Priority** | Already partially done; add CSS transition |

### 6.5 Coverage Change -- Cell Intensity Transition

| Property | Value |
|----------|-------|
| **What** | When a rule is added/modified that changes coverage, affected cells smoothly transition their background opacity |
| **How** | CSS `transition: background-color 400ms var(--ease-out-quart), border-color 400ms` |
| **When** | Coverage map recalculation |
| **Duration** | 400ms, ease-out-quart |
| **Priority** | Must-have |

### 6.6 Coverage Milestone Celebration

| Property | Value |
|----------|-------|
| **What** | When coverage crosses 25%, 50%, 75%, or 100% thresholds, the percentage number briefly glows and the progress bar color transitions |
| **How** | Percentage text: `@keyframes milestone-glow { 0% { text-shadow: 0 0 8px currentColor; } 100% { text-shadow: none; } }`. Color transitions via CSS transition on the bar |
| **When** | Coverage percentage crosses a threshold |
| **Duration** | 800ms glow fade |
| **Priority** | Nice-to-have (delight moment for detection engineers building coverage) |

---

## 7. SigmaHQ Browser (`sigmahq-browser.tsx`)

### 7.1 Rule Card Hover

| Property | Value |
|----------|-------|
| **What** | Card lifts slightly with a subtle border-color shift toward the level color |
| **How** | CSS `transition: transform 150ms var(--ease-out-quart), border-color 150ms, box-shadow 150ms`. On hover: `translateY(-1px)` and `box-shadow: 0 4px 12px -4px #00000040` |
| **When** | Mouse hover on rule card |
| **Duration** | 150ms, ease-out-quart |
| **Priority** | Must-have |

### 7.2 Preview Expand/Collapse

| Property | Value |
|----------|-------|
| **What** | Rule preview section (YAML content) expands with height animation |
| **How** | `grid-template-rows: 0fr -> 1fr` CSS transition |
| **When** | Preview toggle click |
| **Duration** | 250ms, ease-out-quart |
| **Priority** | Must-have |

### 7.3 Import Success Toast

| Property | Value |
|----------|-------|
| **What** | After importing a SigmaHQ rule, a success toast appears (already handled by toast system) AND the card briefly flashes green on its left border |
| **How** | Card left-border flash: `@keyframes import-success { 0% { border-left-color: #3dbf84; } 100% { border-left-color: transparent; } }` |
| **When** | Import button click |
| **Duration** | Toast: existing behavior. Card flash: 400ms |
| **Priority** | Nice-to-have |

### 7.4 Search Results Filter Transition

| Property | Value |
|----------|-------|
| **What** | Cards that do not match the search filter collapse out; matching cards reflow |
| **How** | Wrap card list in `<AnimatePresence>`. Each card: `<motion.div layout>` with exit animation |
| **When** | Search query or filter changes |
| **Duration** | 200ms, ease-out-quart |
| **Priority** | Nice-to-have |

### 7.5 Tag Badge Hover

| Property | Value |
|----------|-------|
| **What** | ATT&CK tag badges slightly brighten and scale on hover |
| **How** | CSS `transition: transform 100ms, opacity 100ms`. Hover: `scale(1.05)`, `opacity: 1` |
| **When** | Mouse hover on tag badge |
| **Duration** | 100ms |
| **Priority** | Nice-to-have |

---

## 8. Micro-interactions (Cross-Cutting)

### 8.1 Button Press State

| Property | Value |
|----------|-------|
| **What** | All buttons scale down on press |
| **How** | Already exists in `globals.css`: `button:active:not(:disabled) { transform: scale(0.98); }`. Enhance with transition |
| **When** | Mouse down on any button |
| **Duration** | 80ms |
| **Priority** | Already done; add `transition: transform 80ms var(--ease-out-quart)` to button base |

**Refinement**: The current implementation has no transition -- the scale snaps. Add to `globals.css`:
```css
button {
  transition: transform var(--duration-instant) var(--ease-out-quart);
}
```

### 8.2 Copy-to-Clipboard Feedback

| Property | Value |
|----------|-------|
| **What** | After a copy action, a brief "Copied" tooltip appears near the trigger, or the icon transitions from clipboard to checkmark |
| **How** | Icon swap with crossfade: `<AnimatePresence mode="wait">`. Clipboard icon exits, check icon enters |
| **When** | Copy button click |
| **Duration** | Icon swap: 150ms. Auto-dismiss after 1500ms |
| **Priority** | Must-have (currently no copy feedback exists) |

### 8.3 Toggle Switch

| Property | Value |
|----------|-------|
| **What** | Switch thumb slides smoothly; track color transitions |
| **How** | Already exists in `globals.css` with `transition: transform 200ms` and `background-color 200ms`. Keep as-is |
| **When** | Toggle click |
| **Duration** | 200ms |
| **Priority** | Already done |

### 8.4 Input Focus Glow

| Property | Value |
|----------|-------|
| **What** | Input fields get a subtle gold border glow on focus |
| **How** | Already partially exists via `focus:border-[#7c9aef]/50` (Sigma accent) and `focus:border-[#d4a84b]/40` (explorer search). Ensure all inputs have `transition: border-color 150ms` |
| **When** | Input focus |
| **Duration** | 150ms |
| **Priority** | Partially done; standardize across all inputs |

### 8.5 Toolbar Icon Hover

| Property | Value |
|----------|-------|
| **What** | Toolbar icons (refresh, expand all, collapse all) brighten on hover |
| **How** | Already implemented via `hover:text-[#ece7dc]` with `transition-colors`. Keep as-is |
| **When** | Mouse hover |
| **Duration** | 150ms |
| **Priority** | Already done |

### 8.6 Context Menu Entrance

| Property | Value |
|----------|-------|
| **What** | Right-click context menus (tab context menu) appear with a subtle scale-up from the click origin |
| **How** | `initial={{ opacity: 0, scale: 0.95 }}` -> `animate={{ opacity: 1, scale: 1 }}` with `transformOrigin` set to click position |
| **When** | Right-click on tab |
| **Duration** | 150ms, ease-out-expo |
| **Priority** | Nice-to-have |

---

## 9. Delight Moments

These are carefully placed moments that transform the tool from functional to memorable. Each is designed to feel like precision engineering, not whimsy.

### 9.1 First Rule Created

**Trigger**: User creates their first Sigma/YARA/Policy rule (detected via local storage counter)
**Behavior**: The format dot in the tab bar does a single, precise pulse (scale 1 -> 1.3 -> 1, 300ms). The toast reads: "First detection rule created. Your coverage map is live."
**Tone**: Operational acknowledgment, not congratulation. Like a system confirming initialization.

### 9.2 First Validation Pass (Zero Problems)

**Trigger**: Problems panel transitions from >0 to 0 problems for the first time in a session
**Behavior**: The "No problems detected" checkmark icon gets the expanding-ring sonar ping (see 4.4). The status bar briefly shows "All clear" with a green dot that fades after 3s.
**Tone**: Like an "all-green" status board in a SOC.

### 9.3 100% ATT&CK Coverage Achieved

**Trigger**: MITRE heatmap reaches 100% technique coverage
**Behavior**: The coverage percentage text briefly glows gold (#d4a84b). The progress bar fill gets a single left-to-right light sweep. Toast: "Full ATT&CK coverage. {N} techniques across {M} rules."
**Tone**: Mission accomplished. Brief, dignified.

### 9.4 Rapid Tab Switching

**Trigger**: User switches tabs more than 3 times within 2 seconds (power user behavior)
**Behavior**: Tab transition animations automatically shorten to 100ms (from 200ms). This respects the user's pace without them needing to configure anything.
**Tone**: The tool adapts to the operator. No message needed.

### 9.5 Loading States

**Trigger**: SigmaHQ library load, project folder scan, validation run
**Behavior**: Use skeleton screens with a subtle shimmer effect (not a spinner). The shimmer uses a gradient sweep:

```css
@keyframes skeleton-shimmer {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}

.skeleton {
  background: linear-gradient(
    90deg,
    #131721 25%,
    #1a1f2e 37%,
    #131721 63%
  );
  background-size: 200% 100%;
  animation: skeleton-shimmer 1.5s ease-in-out infinite;
}
```

**Tone**: The tool is working. No cute messages -- just a clear visual indicator of activity.

### 9.6 Error States with Guidance

**Trigger**: YAML parse failure, invalid policy, broken rule syntax
**Behavior**: Error banner slides in (see 3.3) with a 2px left border in verdict-deny red. The error message is actionable:

- Instead of: "Parse error at line 14"
- Use: "Parse error at line 14: expected mapping value. Check the indentation after `detection:`"

No playful copy. No apologetic tone. Diagnostic precision.

### 9.7 Keyboard Shortcut Discovery

**Trigger**: User performs an action via mouse that has a keyboard shortcut (e.g., clicking "New Policy" instead of Cmd+N)
**Behavior**: After the 3rd time, subtly show the shortcut badge next to the action for 3 seconds. Non-intrusive. Like a training hint in professional software.

---

## 10. Accessibility -- Reduced Motion

All animations MUST respect `prefers-reduced-motion`. Implementation strategy:

### CSS Animations
Add to `globals.css`:
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

### Motion Library Animations
Create a shared hook:
```tsx
import { useReducedMotion } from "motion/react";

export function useMotionConfig() {
  const prefersReduced = useReducedMotion();
  return {
    transition: prefersReduced
      ? { duration: 0 }
      : { duration: 0.25, ease: [0.16, 1, 0.3, 1] },
    animatePresenceMode: prefersReduced ? "sync" as const : "popLayout" as const,
  };
}
```

### What to Preserve Under Reduced Motion
- Focus indicators (always visible)
- Color transitions (instantaneous, but still change)
- Progress bar fills (show final state, skip animation)
- Loading skeleton shimmer (replace with static pulsing opacity)

---

## 11. Implementation Priority

### Phase 1 -- Foundation (Must-Have)
1. Add motion tokens to `globals.css`
2. Add reduced-motion media query to `globals.css`
3. Tab system: `AnimatePresence` + `layout` animations (1.1, 1.2, 1.3, 1.4)
4. Command palette: open/close animations (2.1, 2.2)
5. Button press transition smoothing (8.1)

### Phase 2 -- Core Feedback
6. Problems panel: diagnostic slide-in + "all clear" celebration (4.1, 4.4, 4.5)
7. Explorer: directory expand/collapse animations (5.1)
8. Sigma visual panel: section collapse/expand + chevron rotation fix (3.1, 3.2)
9. Heatmap: detail panel slide + cell transitions (6.3, 6.5)

### Phase 3 -- Polish & Delight
10. Tab dirty dot animation (1.6)
11. Format dot pulse (1.5)
12. Copy-to-clipboard feedback (8.2)
13. SigmaHQ card hover + preview expand (7.1, 7.2)
14. Coverage milestone celebration (6.6)
15. Loading skeleton shimmer (9.5)

### Phase 4 -- Advanced
16. Visual-YAML sync highlight (3.6)
17. Keyboard shortcut discovery (9.7)
18. Rapid tab switching adaptation (9.4)
19. Context menu entrance animation (8.6)
20. Search filter transitions (2.3, 7.4)

---

## 12. Performance Budget

- **Animation frame budget**: 16.67ms (60fps). All animations use `transform` and `opacity` only -- no layout properties.
- **Total animation weight**: Motion library is already bundled (~15KB gzipped). No additional dependencies needed.
- **`will-change`**: Only apply on elements that are actively animating. Remove via `onAnimationComplete` callback.
- **Stagger caps**: Never stagger more than 10 items. For lists longer than 10, animate the first 10 and show the rest instantly.
- **GPU acceleration**: All transforms are GPU-composited. Avoid animating `box-shadow` directly (use a pseudo-element with opacity animation instead).

---

## Summary

This plan defines 45 animation and micro-interaction points across 7 components and 2 cross-cutting concern areas. The implementation is divided into 4 phases, prioritizing structural animations (tab system, command palette) before polish (celebrations, sync highlights).

Every animation serves one of three purposes:
1. **State acknowledgment**: The user's action was received (button press, tab switch)
2. **Spatial continuity**: Elements have a physical location and move to their new position (tab reorder, panel slide)
3. **Completion signal**: A workflow milestone was reached (all clear, coverage threshold)

None of the animations are decorative. None are playful. All of them make the tool feel like a precision instrument that responds to the operator's intent with immediate, proportional feedback.
