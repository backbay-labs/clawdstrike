# 02 - Interaction Design Specification

> Huntronomer Workbench Redesign -- UI/UX Interaction Grammar
>
> Status: DRAFT | Author: ux-designer | Date: 2026-03-07

---

## 1. Orb Behavior (Lens Rotor)

### Current Orb (CyberNexusOrb)

The existing `CyberNexusOrb` (`src/shell/components/CyberNexusOrb.tsx`) cycles through four **nexus operation modes** -- observe, trace, contain, execute -- defined in `src/features/cyber-nexus/mode.ts` as `NEXUS_MODES`. These are operational postures (passive monitoring vs. active response), not navigation targets. The orb also navigates to `/nexus` on click and opens a 4-item radial menu on long-press (420ms) or right-click.

### New Orb: Lens Rotor

The redesigned orb replaces operation mode cycling with **lens cycling**. Lenses are sidebar content contexts, not operational postures. The orb sits at the top of the Activity Spine (section 6).

**Lens sequence** (7 lenses, 0-indexed):

| Index | Lens       | Color accent                          | Shortcut     |
|-------|-----------|---------------------------------------|--------------|
| 0     | Scopes    | `rgba(213,173,87,0.82)` (gold)        | Cmd/Ctrl+1   |
| 1     | History   | `rgba(126,139,167,0.78)` (steel)      | Cmd/Ctrl+2   |
| 2     | Files     | `rgba(107,140,190,0.78)` (blue)       | Cmd/Ctrl+3   |
| 3     | Sandboxes | `rgba(61,191,132,0.78)` (green)       | Cmd/Ctrl+4   |
| 4     | Entities  | `rgba(212,168,75,0.78)` (amber)       | Cmd/Ctrl+5   |
| 5     | Swarms    | `rgba(199,125,46,0.78)` (orange)      | Cmd/Ctrl+6   |
| 6     | Notes     | `rgba(122,111,143,0.78)` (purple)     | Cmd/Ctrl+7   |

**Interaction grammar:**

| Gesture               | Action                                                                 |
|-----------------------|------------------------------------------------------------------------|
| Single click          | Toggle between current and previous lens (like Alt+Tab). If no previous lens exists, opens the lens picker menu instead. |
| Press + hold (420ms)  | Open radial lens menu (reuse `nexus-orb-mode-menu` pattern)            |
| Right-click           | Toggle radial lens menu                                                |
| Cmd/Ctrl+1..7         | Jump directly to lens by index                                         |
| `O` then Arrow keys   | Enter orb focus mode; Left/Right cycle lenses, Enter confirms, Esc exits |

> **Design rationale (C2):** Cycling through 7 lenses on single-click is tedious (up to 6 clicks to reach a target) and accidental clicks cause unexpected sidebar changes. The toggle-between-two pattern mirrors Alt+Tab muscle memory and covers the most common use case: switching between two lenses the analyst is actively using. The full set is always reachable via long-press, right-click, or Cmd+1-7.

**Visual ring adaptation:**

The existing `nexus-orb-mode-ring` uses a 4-segment conic gradient with `data-mode-index` controlling `--orb-angle`. The new ring needs 7 segments. Each segment spans ~45deg with 6.4deg gaps:

```css
.lens-rotor-ring {
  /* 7 segments, each 45deg, with ~6.4deg gaps */
  background:
    conic-gradient(
      from -90deg,
      var(--orb-track-color) 0deg 45deg,
      transparent 45deg 51.4deg,
      var(--orb-track-color) 51.4deg 96.4deg,
      transparent 96.4deg 102.8deg,
      var(--orb-track-color) 102.8deg 147.8deg,
      transparent 147.8deg 154.3deg,
      var(--orb-track-color) 154.3deg 199.3deg,
      transparent 199.3deg 205.7deg,
      var(--orb-track-color) 205.7deg 250.7deg,
      transparent 250.7deg 257.1deg,
      var(--orb-track-color) 257.1deg 302.1deg,
      transparent 302.1deg 308.6deg,
      var(--orb-track-color) 308.6deg 353.6deg,
      transparent 353.6deg 360deg
    ),
    conic-gradient(
      from var(--lens-angle),
      var(--lens-active-color) 0deg 45deg,
      transparent 45deg 360deg
    );
  /* Reuse existing ring mask */
  -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 3px));
  mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 3px));
  filter: drop-shadow(0 0 8px rgba(213, 173, 87, 0.26));
}
```

The `--lens-angle` and `--lens-active-color` are set per `data-lens-index` and `data-lens-tone` attributes, mirroring the existing `data-mode-index` / `data-tone` pattern.

**Live activity indicator:** When any live state exists for the current lens (running sandbox, active swarm, incoming feed), the ring pulses using the existing `nexus-orb-pulse` keyframe at `animation-duration: 2s` instead of the default 4s.

**Radial menu adaptation:**

The existing radial menu positions 4 items at 90deg intervals via `--orb-menu-angle`. For 7 items, the menu expands from 156px to **280px** diameter to provide adequate spacing (51.4deg intervals at a larger radius avoid item overlap):

```css
.lens-rotor-menu {
  width: 280px;
  height: 280px;
}

.lens-rotor-menu-item {
  /* Same base styles as nexus-orb-mode-menu-item */
  min-width: 60px;   /* reduced from 72px to fit tighter arc */
  font-size: 10px;
  transform: translate(-50%, -50%)
    rotate(var(--orb-menu-angle))
    translateY(-116px)                  /* increased from 82px for larger radius */
    rotate(calc(var(--orb-menu-angle) * -1));
}
```

Items are spaced at 0deg, 51.4deg, 102.8deg, 154.3deg, 205.7deg, 257.1deg, 308.6deg. At the 116px translate radius, adjacent items have ~102px center-to-center distance, providing comfortable targeting even at 51.4deg separation.

---

## 2. Tab Interaction Grammar

### Mouse Interactions

| Gesture on sidebar item | Action                                                    |
|------------------------|-----------------------------------------------------------|
| Single click            | **Preview** in current pane -- italic tab title, ephemeral (replaced by next preview) |
| Double click            | **Pin** as persistent tab -- non-italic title, stays open until explicitly closed     |
| Cmd/Ctrl+click          | **Open in new tab** -- always pinned, appended to tab bar                             |
| Alt+click               | **Split right** -- open item in new split pane to the right (see section 3)           |

| Gesture on tab bar      | Action                                                   |
|------------------------|-----------------------------------------------------------|
| Click tab               | Activate that tab                                         |
| Middle click tab        | Close tab (pinned or preview)                             |
| Drag tab                | Reorder within tab bar, or drag to edge to create split   |

| Keyboard (when sidebar has focus) | Action                                        |
|----------------------------------|-----------------------------------------------|
| Arrow Up/Down                     | Navigate sidebar items                        |
| Space                             | **Quick peek** -- overlay preview, dismisses on next action or Esc |
| Enter                             | **Persistent open** -- equivalent to double-click (pin) |

### Tab States

| State     | Visual indicator                                      | Behavior                                    |
|-----------|------------------------------------------------------|---------------------------------------------|
| Preview   | Tab title in *italic*, `font-style: italic`          | Ephemeral; replaced by next preview action  |
| Pinned    | Tab title in normal weight, non-italic               | Persistent; must be explicitly closed       |
| Dirty     | Gold dot indicator `rgba(238,220,166,0.96)` after title | Unsaved changes (reuses existing dirty dot from `WorkspaceShellScreen`) |

The existing dirty dot pattern from `WorkspaceShellScreen.tsx` line 337:
```tsx
{isDirty ? <span className="text-[color:rgba(238,220,166,0.96)]">*</span> : null}
```

### Tabbable Object Types

All of these objects can be opened as tabs in the main content area:

- **Signal thread** -- feed item from Wire shell
- **Hunt** -- hunt flow from Hunt shell
- **Receipt** -- Clawdstrike validation receipt
- **Case** -- investigation case bundle
- **Sandbox** -- live or stopped sandbox session
- **Artifact** -- file, binary, evidence item
- **Brief** -- analysis brief or report
- **Profile** -- entity profile (host, user, identity, service)
- **Policy** -- security policy YAML
- **File** -- raw file (code, config, log)

Tab titles use `font-family: var(--font-mono)`, `font-size: 11px`, `letter-spacing: 0.06em`, consistent with the existing tab chip styling in `WorkspaceShellScreen`.

### Tab Overflow

When tabs exceed the available tab bar width:

- **Horizontal scroll**: The tab bar becomes scrollable. Fade indicators appear at the left/right edges when more tabs exist in that direction.
- **All-tabs dropdown**: A chevron button (`>`) at the right end of the tab bar opens a dropdown listing all open tabs, grouped by pinned first then by open order. Clicking an entry activates that tab.
- **Soft limit**: A toast warning appears at 25 open tabs ("Consider closing unused tabs"). At 30 tabs, new preview tabs replace the oldest unpinned preview tab.

---

## 3. Split Pane Model

### Layout Rules

- **Default**: Single pane fills the main content area.
- **Creating splits**: Alt+click on any sidebar item, or drag a tab to the right/bottom edge of the content area.
- **Maximum grid**: 2x2 (4 panes). Attempting to split beyond this is a no-op.
- **Resize handles**: 4px drag handles between panes, `background: var(--color-border-subtle)` on hover becoming `var(--origin-gold-dim)` (#9f7c3a) while dragging.
- **Each pane owns its tab bar**: Every split pane has its own row of tabs with the same interaction grammar from section 2.
- **Collapsing**: Closing the last tab in a split pane collapses that pane and redistributes space to adjacent panes.
- **Focus**: Clicking inside a pane sets it as the focused pane. The focused pane has a 1px left border accent in `rgba(213,173,87,0.6)`. The existing `focusedPane` state from `WorkspaceSurfaceState` (`workspaceShellState.ts`) drives this.

### Per-Shell Default Splits

Each shell mode starts with a suggested split layout. Users can always change this.

| Shell | Default layout                          | Left/Top pane         | Right/Bottom pane    |
|-------|-----------------------------------------|----------------------|----------------------|
| Wire  | Single pane (no split)                  | Feed                  | --                   |
| Hunt  | Vertical split (60/40)                  | Hunt flow graph       | Replay timeline      |
| Lab   | Vertical split (55/45)                  | Editor                | Terminal             |
| Case  | Single pane                             | Case detail           | --                   |

---

## 4. Bottom Panel

The bottom panel is a collapsible drawer anchored to the bottom edge of the main content area (below split panes, above the status bar).

### Tabs

| Tab       | Content                                               | Icon style        |
|-----------|------------------------------------------------------|-------------------|
| Tape      | Live validation/receipt stream (scrolling log)        | Horizontal lines  |
| Terminal  | PTY tabs (multiple terminal sessions)                 | Angle bracket `>`  |
| Receipts  | Receipt browser with filter bar                       | Shield             |
| Tasks     | Active swarm tasks with status indicators             | Checkmark list     |
| Replay    | Hunt replay timeline (scrubber + event markers)       | Play triangle      |
| Diff      | Side-by-side diff viewer                              | Split columns      |

### Behavior

| Property                  | Value                                                          |
|--------------------------|----------------------------------------------------------------|
| Default state (Wire)     | Collapsed (hidden, 0px height)                                 |
| Default state (Hunt/Lab) | Expanded, 220px height                                        |
| Toggle shortcut           | `Cmd+J` or click any panel tab when collapsed                  |
| Resize                    | Drag top edge; min 120px, max 50% of viewport height           |
| Per-shell memory          | Each shell mode remembers its own active tab and panel height   |
| Collapse                  | `Cmd+J` when expanded, or click active tab label again          |

**Panel top edge resize handle:**
```css
.bottom-panel-resize-handle {
  height: 4px;
  cursor: ns-resize;
  background: transparent;
}
.bottom-panel-resize-handle:hover {
  background: var(--color-border-subtle);
}
.bottom-panel-resize-handle:active {
  background: var(--origin-gold-dim);
}
```

**Tab bar styling:**

Panel tabs sit in a row at the top of the bottom panel. Active tab uses the existing gold accent pattern:
- Active: `border-bottom: 2px solid rgba(213,173,87,0.8); color: var(--color-text-primary)`
- Inactive: `border-bottom: 2px solid transparent; color: var(--color-text-muted)`
- Tab font: `font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase`

### Tape (Live Validation Stream)

Dense, terminal-style scrolling log. Each line shows:
```
[HH:MM:SS] [VERDICT] guard_name -- action_summary
```
Color-coded by verdict: `--color-verdict-allowed` (green), `--color-verdict-blocked` (red), `--color-verdict-warn` (amber).

### Terminal

Multiple PTY sessions as sub-tabs within the Terminal panel tab. Each sub-tab shows the shell name and CWD. New terminal: click `+` in sub-tab bar or `Cmd+Shift+\``.

---

## 5. Right Context Pane (Inspector)

The inspector is a fixed-width pane on the far right, always driven by the current selection (active tab + selected item within that tab). It replaces the existing static `InspectorCard` pattern from `WorkspaceShellScreen.tsx` lines 403-427.

### Tabs

| Tab         | Content                                                        |
|------------|----------------------------------------------------------------|
| Context     | Metadata, linked entities, related hunts, timestamps           |
| Graph       | Mini entity/relationship graph (force-directed, max ~50 nodes) |
| Proof       | Receipt chain, validation summary, policy provenance           |
| Companion   | AI suggestions (summarize, pivot, propose hunt, flag issues)   |

### Behavior

| Property         | Value                                                              |
|-----------------|--------------------------------------------------------------------|
| Toggle shortcut  | `Cmd+\`                                                            |
| Width            | 320px (matches existing inspector column from WorkspaceShellScreen grid: `320px`) |
| Min width        | 260px (drag to resize)                                             |
| Max width        | 440px                                                              |
| Selection-driven | Content updates whenever the active tab or selected item changes   |

### Tab bar styling

Same pattern as bottom panel tabs: mono font, 10px, uppercase, gold underline for active.

### Context Tab

Shows metadata for the currently selected object:

- **For a signal thread**: source, severity, technique IDs (MITRE), first/last seen, linked entities
- **For a hunt**: parameters, start time, status, matched IOCs, assigned analyst
- **For a receipt**: decision, policy name, guard results, timestamp, signer identity
- **For an artifact**: file type, size, hashes (SHA-256), provenance, trust level

Uses the existing `InspectorCard` component pattern: `rounded-xl border border-sdr-border bg-sdr-bg-primary/30 p-3` with `text-xs uppercase tracking-[0.12em] text-sdr-text-muted` labels.

### Graph Tab

Renders a small force-directed graph using the same node/edge model as the existing `NexusGraph` type. Nodes are colored by kind (host=blue, identity=amber, technique=red, service=green). Clicking a node in the graph updates the Context tab and navigates to that entity.

### Proof Tab

Shows the Clawdstrike receipt chain for the selected object:
- Receipt ID (truncated, copy on click)
- Decision badge: Allowed (green), Blocked (red), Warn (amber) using `--color-verdict-*` tokens
- Guard-by-guard results as a compact list
- Policy name and version
- Signer identity with Ed25519 fingerprint

### Companion Tab

Grounded, embedded AI assistance. NOT a chatbot -- it is a contextual suggestion panel.

Content types:
- **Summarize**: 2-3 sentence summary of the selected object
- **Suggest pivot**: "Related entities you might investigate next" with clickable links
- **Propose hunt**: Pre-filled hunt parameters based on current context
- **Flag contradictions**: Highlight inconsistencies in the current case/evidence

Each suggestion is a discrete card, not a conversation turn. Cards have an "Apply" button where relevant (e.g., "Apply" on a proposed hunt opens the Hunt shell with pre-filled params).

---

## 6. Activity Spine

The Activity Spine replaces the current 220px `NavRail` (`src/shell/components/NavRail.tsx`). It is a narrow icon column on the far left edge of the window.

### Layout

| Property     | Value                                                |
|-------------|------------------------------------------------------|
| Width        | 48px                                                 |
| Background   | `linear-gradient(180deg, rgba(9,11,18,0.98) 0%, rgba(4,6,10,0.99) 100%)` (reuses NavRail bg) |
| Border right | `1px solid rgba(213,173,87,0.18)`                    |
| z-index      | 20 (matches existing NavRail)                        |

### Icon column (top to bottom)

```
+------------------+
| [Orb]            |  -- Lens Rotor (section 1)
| --- divider ---  |
| [Wire icon]      |  -- Shell mode: Wire
| [Hunt icon]      |  -- Shell mode: Hunt
| [Lab icon]       |  -- Shell mode: Lab
| [Case icon]      |  -- Shell mode: Case
|                  |
|   (flex spacer)  |
|                  |
| [Status sigil]   |  -- Connection status (reuses origin-status-sigil)
| [Settings icon]  |  -- Opens settings
+------------------+
```

### Shell Mode Icons

Each shell mode icon is a 32x32px hit target centered in the 48px column.

| Shell | Icon concept        | Active indicator                              |
|-------|-------------------|-----------------------------------------------|
| Wire  | Signal wave        | 3px left border `rgba(213,173,87,0.82)`       |
| Hunt  | Crosshair          | 3px left border `rgba(213,173,87,0.82)`       |
| Lab   | Flask/beaker       | 3px left border `rgba(213,173,87,0.82)`       |
| Case  | Folder/briefcase   | 3px left border `rgba(213,173,87,0.82)`       |

**Interaction:**

| Gesture   | Action                                  |
|----------|-----------------------------------------|
| Click     | Switch to that shell mode               |
| Hover     | Tooltip with shell name (e.g., "Wire -- Signal Feed") appears to the right |

**Active state styling:**
```css
.spine-shell-icon[data-active="true"] {
  color: var(--origin-gold);
  border-left: 3px solid rgba(213, 173, 87, 0.82);
  background: rgba(213, 173, 87, 0.08);
}

.spine-shell-icon[data-active="false"] {
  color: var(--color-text-muted);
  border-left: 3px solid transparent;
}
```

### Status Sigil

Reuses the existing `origin-status-sigil` pattern from `NavRail.tsx` lines 149-170. The sigil shows connection state: green dot + "LIVE", amber dot + "SYNC", or red dot + "OFFLINE".

### Divider

The orb and shell icons are separated by a 1px horizontal line:
```css
.spine-divider {
  width: 24px;
  height: 1px;
  margin: 8px auto;
  background: rgba(213, 173, 87, 0.22);
}
```

---

## 7. Lens Sidebar Content

The lens sidebar sits between the Activity Spine (48px) and the main content area. Width: 240px (see `--lens-sidebar-width` in 03-COMPONENT-LAYOUT.md S5), min 180px, max 400px, collapsible with `Cmd+Shift+B`.

### Scopes

Watchlists and subscribed feeds for the analyst's focus areas.

- **Watchlists**: User-created groups of IOCs, technique IDs, or entity patterns
- **Followed techniques**: MITRE ATT&CK technique subscriptions with alert counts
- **Sectors**: Industry verticals the analyst monitors
- **Teams**: Team feeds and shared scope filters
- **Saved feeds**: Bookmarked signal feed queries

Each item is a compact row: 28px height, `font-size: 12px`, left-aligned with a colored dot indicating activity level.

### History

Navigation and command history, most recent first.

- **Open tabs**: Currently open tabs across all panes (clickable to focus)
- **Recent tabs**: Last 20 closed tabs (clickable to reopen)
- **Recent commands**: Last 50 command palette entries
- **Navigation history**: Breadcrumb trail of visited views (Back/Forward with `Cmd+[` / `Cmd+]`)
- **Session stack**: Active sessions with timestamps

Sections are collapsible tree groups. Each row: `font-family: var(--font-mono); font-size: 11px`.

### Files

Reuses the existing `WorkspaceTreeView` component from `src/features/workspace/tree/WorkspaceTreeView.tsx`.

- **Artifacts**: Evidence files, captured packets, memory dumps
- **Files**: Source code, configuration, scripts
- **Run outputs**: Logs and outputs from completed runs
- **Evidence bundles**: Grouped evidence packages for cases
- **Scripts**: Automation and hunt scripts
- **Notes**: Markdown notes and scratchpads

Tree nodes use the existing `onToggleDirectory` / `onSelectEntry` callbacks. `expandedPaths` and `selectedPath` state from `WorkspaceSurfaceState` drive the tree.

### Sandboxes

Live and historical sandbox environments.

- **Live sandboxes**: Running environments with green status dot (`--color-sdr-accent-green`)
- **Stopped sandboxes**: Terminated environments with muted status
- **Mounts**: Attached filesystems and volumes
- **Terminals**: PTY sessions bound to sandboxes
- **State snapshots**: Checkpoint captures with timestamps

Each sandbox row shows: name, status dot, runtime duration, resource usage summary.

### Entities

All observed entities across the investigation.

- **Hosts**: Machines, VMs, containers
- **Pods**: Kubernetes pods
- **Identities**: Service accounts, API keys, certificates
- **Users**: Human identities
- **IPs**: Network addresses with geolocation hint
- **Repos**: Git repositories under observation
- **Services**: Network services and endpoints
- **Clusters**: Kubernetes clusters

Entity rows show: icon (by kind), name, last-seen timestamp, severity badge if flagged. Group headers are collapsible.

### Swarms

Agent orchestration state.

- **Profiles**: Swarm configuration profiles
- **Live runs**: Currently executing swarm runs with progress
- **Agents**: Individual agent instances with status
- **Stations**: Agent deployment targets
- **Queues**: Pending task queues with depth counters
- **Budgets**: Token/compute budget usage bars
- **Blocked branches**: Branches awaiting approval with reason

Live runs show a compact progress bar using `rgba(213,173,87,0.6)` fill on `rgba(213,173,87,0.12)` track.

### Notes

Analyst working notes and references.

- **Brief fragments**: Sections extracted from analysis briefs
- **Case notes**: Per-case investigation notes
- **Saved citations**: Bookmarked references from feeds or reports
- **Scratchpads**: Unnamed quick-note buffers

Notes use `font-size: 12px; line-height: 1.5` for readability. Each note shows a title, first line preview, and last-modified timestamp.

---

## 8. Visual Hierarchy Guidelines

### Gold Usage (Strict)

Gold `rgba(213,173,87,*)` is the primary accent. It must be reserved for:

- **Focus and selection**: Active tab border, focused pane border, selected sidebar item
- **Current shell/lens**: Active spine icon, orb ring active segment
- **Active live state**: Running process indicators, connected status
- **Critical structural elements**: Panel borders on hover, resize handle active state

Gold must NOT be used for: decorative backgrounds, inactive elements, body text, or bulk content areas. Overuse dilutes its signal value.

### Muted Graphite Borders

Everything that is not gold-accented uses muted borders:
- Default panels: `border-color: var(--color-sdr-border)` (#2d3240)
- Subtle separators: `border-color: var(--color-sdr-border-subtle)` (#212634)
- Inactive items: `border-color: rgba(45,50,64,0.5)`

### Glow Effects

Glow is reserved for **live state only**:
- Connected status: `box-shadow: 0 0 8px rgba(61,191,132,0.55)` (green, from `sessionStatusClass`)
- Active hunt: `box-shadow: 0 0 8px rgba(213,173,87,0.24)` (gold)
- Running sandbox: `box-shadow: 0 0 8px rgba(61,191,132,0.45)` (green)
- Error state: `box-shadow: 0 0 8px rgba(196,92,92,0.45)` (red)

Static elements must never glow.

### Density Rules

| Context              | Treatment                                  |
|---------------------|-------------------------------------------|
| Wire feed            | Dense rows, 28-32px height, no cards       |
| Sidebar lists        | Compact tree/list items, 26-30px height    |
| Entity lists         | Dense table rows with mono font            |
| Hunt flow            | Graph nodes, not cards                     |
| Selected thread      | Card treatment (rounded-xl, padding, border) |
| Hunt header          | Card treatment                             |
| Case summary         | Card treatment                             |
| Proof panel          | Card treatment                             |

The default density model is **terminal wire**, not **social card wall**. Cards are the exception, used only when an item needs expanded detail or is the primary focus of the view.

Sidebar items: `padding: 4px 8px; font-size: 12px; line-height: 1.3`. No shadow, no rounded card treatment.

---

## 9. Status Bar

The status bar is the absolute bottom edge of the application window, spanning full width.

### Layout

```
+---------------------------------------------------------------------------------+
| Wire | Scopes       LIVE  observe  strict  3 sessions    providence  2  K       |
| [shell] [lens]    [status] [mode] [posture] [sessions]  [cluster] [unread] [kbd] |
+---------------------------------------------------------------------------------+
```

### Properties

| Property    | Value                                                              |
|------------|---------------------------------------------------------------------|
| Height      | 24px                                                               |
| Background  | `rgba(5,6,10,0.98)` (slightly darker than `--color-sdr-bg-primary`) |
| Border top  | `1px solid var(--color-sdr-border-subtle)`                         |
| Font        | `font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.06em` |
| Color       | `var(--color-text-muted)` for labels, `var(--color-text-secondary)` for values |
| z-index     | 30 (above all content, below modals)                               |

### Segments

**Left zone:**
- Shell mode label: uppercase, `color: var(--origin-gold)` when active
- Lens name: `color: var(--color-text-muted)`

**Center zone:**
- Live/Offline indicator: green dot + "LIVE" or red dot + "OFFLINE" (reuses `origin-status-sigil-dot` styling)
- Operation mode: Current `NexusOperationMode` (observe / trace / contain / execute) -- the analyst's working stance
- Enforcement posture: Current policy enforcement level (permissive / default / strict) -- the daemon's security level. These are distinct concepts: operation mode is the analyst's intent, enforcement posture is the system's security strictness.
- Session count: Number of active sessions

**Right zone:**
- Cluster name: Which cluster this instance is connected to
- Unread validations: Badge count for unseen receipts, gold background when >0
- Keyboard mode indicator: Shows "VIM" or "STD" when relevant

Unread badge when count > 0:
```css
.statusbar-unread-badge {
  background: rgba(213, 173, 87, 0.85);
  color: var(--color-sdr-bg-primary);
  padding: 0 5px;
  border-radius: var(--radius-full);
  font-size: 9px;
  font-weight: 600;
}
```

---

## 10. Keyboard Shortcut Map

### Global Shortcuts

These override the current `useShellShortcuts` mapping (`src/shell/keyboard/useShellShortcuts.ts`) which binds Cmd+1-9 to view navigation (nexus, operations, security-overview, etc.). The new mapping binds Cmd+1-7 to lenses instead.

| Shortcut          | Action                                |
|-------------------|---------------------------------------|
| Cmd/Ctrl+1..7     | Jump to lens by index (Scopes..Notes) |
| Cmd/Ctrl+K        | Command palette (preserved)           |
| Cmd/Ctrl+N        | New tab in current pane               |
| Cmd/Ctrl+Shift+N  | New strikecell session                |
| Cmd/Ctrl+W        | Close current tab                     |
| Cmd/Ctrl+F        | Focus search (preserved)              |
| Cmd/Ctrl+,        | Settings (preserved)                  |
| Cmd/Ctrl+J        | Toggle bottom panel                   |
| Cmd/Ctrl+\        | Toggle inspector (right pane)         |
| Cmd/Ctrl+Shift+B  | Toggle lens sidebar                   |
| Cmd/Ctrl+[        | Navigate back                         |
| Cmd/Ctrl+]        | Navigate forward                      |
| Cmd/Ctrl+Shift+\  | New terminal in bottom panel          |
| Escape             | Dismiss modal/overlay/quick-peek (preserves existing `onCloseModal` handler) |

### Shell Switching

| Shortcut          | Action              |
|-------------------|---------------------|
| Cmd/Ctrl+Shift+1  | Switch to Wire      |
| Cmd/Ctrl+Shift+2  | Switch to Hunt      |
| Cmd/Ctrl+Shift+3  | Switch to Lab       |
| Cmd/Ctrl+Shift+4  | Switch to Case      |

### Tab Navigation

| Shortcut              | Action                      |
|-----------------------|-----------------------------|
| Cmd/Ctrl+Tab           | Next tab in active pane     |
| Cmd/Ctrl+Shift+Tab     | Previous tab in active pane |
| Cmd/Ctrl+Shift+[       | Previous tab (alternative)  |
| Cmd/Ctrl+Shift+]       | Next tab (alternative)      |

### Orb Focus Mode

| Shortcut | Action                                          |
|----------|-------------------------------------------------|
| O        | Enter orb focus (when not in an input field)     |
| Arrow L/R | Cycle lenses while in orb focus                |
| Enter    | Confirm lens selection and exit orb focus        |
| Escape   | Cancel and exit orb focus                        |

---

## 11. Accessibility

### Keyboard Navigation

All interactive elements are reachable via Tab key navigation. Focus order follows the visual layout:

1. Activity Spine (orb, shell icons, status, settings)
2. Lens sidebar (tree items, list items)
3. Main content pane(s) (tab bar, then content)
4. Bottom panel (tab bar, then content)
5. Inspector (tab bar, then content)
6. Status bar

### ARIA Labels

| Element              | ARIA attribute                                                    |
|---------------------|-------------------------------------------------------------------|
| Orb                  | `aria-label="Lens rotor. Current lens: {name}. Click to cycle, hold for menu."` |
| Orb radial menu      | `role="menu" aria-label="Lens selection"`                         |
| Orb menu items       | `role="menuitemradio" aria-checked={isActive}`                    |
| Shell mode icons     | `aria-label="Switch to {shell} mode" role="tab"`                 |
| Activity Spine       | `role="tablist" aria-label="Shell modes"`                        |
| Tab bar              | `role="tablist" aria-label="{pane} tabs"`                        |
| Tab                  | `role="tab" aria-selected={isActive} aria-label="{title} {state}"` |
| Bottom panel tabs    | `role="tablist" aria-label="Bottom panel"`                       |
| Inspector tabs       | `role="tablist" aria-label="Inspector"`                          |
| Lens sidebar         | `role="navigation" aria-label="{lens} sidebar"`                  |

### Focus Ring

Reuses the existing `origin-focus-ring` class:
```css
.origin-focus-ring:focus-visible {
  outline: 2px solid var(--origin-gold);
  outline-offset: 2px;
}
```

All buttons, tabs, tree items, and interactive elements must have this class.

### Screen Reader Announcements

Use `aria-live="polite"` regions for:
- Shell mode changes: "Switched to {shell} mode"
- Lens changes: "Lens changed to {lens}"
- Tab changes: "Opened {title} tab" / "Closed {title} tab"
- Panel toggle: "{panel} panel expanded" / "{panel} panel collapsed"

### Reduced Motion

When `prefers-reduced-motion: reduce` is active:
- Disable `nexus-orb-pulse` animation (set `animation: none`)
- Disable all glow `box-shadow` animations
- Radial menu appears instantly (no transform transition)
- Panel expand/collapse uses `display` toggle instead of height animation
- Tab transitions use `opacity` only, no `transform`

```css
@media (prefers-reduced-motion: reduce) {
  .nexus-orb-glow,
  .lens-rotor-ring {
    animation: none;
  }

  .lens-rotor-menu-item,
  .dock-capsule-wrapper,
  .bottom-panel,
  .inspector-panel {
    transition-duration: 0.01ms !important;
  }
}
```

---

## Appendix: Design Token Reference

Key tokens from `src/styles.css` used throughout this spec:

| Token                          | Value                       | Usage                      |
|-------------------------------|-----------------------------|----------------------------|
| `--origin-gold`               | `#d5ad57`                   | Primary accent             |
| `--origin-gold-dim`           | `#9f7c3a`                   | Dimmed gold (resize handles) |
| `--origin-steel`              | `#5b667f`                   | Secondary accent           |
| `--origin-steel-bright`       | `#7e8ba7`                   | Bright secondary           |
| `--color-sdr-bg-primary`      | `#05060a`                   | App background             |
| `--color-sdr-bg-secondary`    | `#0b0d13`                   | Panel background           |
| `--color-sdr-border`          | `#2d3240`                   | Default borders            |
| `--color-sdr-border-subtle`   | `#212634`                   | Subtle separators          |
| `--color-sdr-text-primary`    | `#ece7dc`                   | Primary text               |
| `--color-sdr-text-secondary`  | `#b6b7c1`                   | Secondary text             |
| `--color-sdr-text-muted`      | `#7f8494`                   | Muted text                 |
| `--color-sdr-accent-green`    | `#3dbf84`                   | Success / live             |
| `--color-sdr-accent-red`      | `#c45c5c`                   | Error / blocked            |
| `--color-sdr-accent-amber`    | `#d4a84b`                   | Warning / contain          |
| `--font-sans`                 | `"Rajdhani", "Inter", ...`  | Body text                  |
| `--font-mono`                 | `"JetBrains Mono", ...`     | Labels, tabs, code         |
| `--font-serif`                | `"Cinzel", ...`             | Headlines (rare)           |
| `--origin-panel-border`       | `rgba(213,173,87,0.34)`     | Panel gold border          |
| `--radius-sm`                 | `8px`                       | Small radius               |
| `--radius-md`                 | `10px`                      | Medium radius              |
| `--radius-lg`                 | `14px`                      | Large radius               |
| `--radius-full`               | `999px`                     | Pill shape                 |
| `--nav-rail-width`            | `220px` (current) -> `48px` | Activity Spine width       |
