# 04 — Cleaner Tile Chrome

**Status:** Proposed
**Author:** Architecture
**Date:** 2026-03-25
**Scope:** Swarm Board node components, inspector drawer, CSS animations

---

## 1. Problem Statement

The Swarm Board's six custom React Flow nodes have accumulated visual density
that creates cognitive overload at the board level. When 8-12 nodes are visible
simultaneously (the common case during a multi-agent hunt), the user cannot
quickly scan for what matters — which sessions are active, which receipts need
attention, where a failure occurred.

Specific symptoms:

- **AgentSessionNode** shows 4 distinct information zones (title bar, terminal
  body, footer metrics bar, status bar) in a single card, plus a pulsing
  radial-gradient overlay, a breathing box-shadow animation, a left-border
  accent, AND a status dot — all competing for attention.
- **ReceiptNode** renders the full guard result list inline on the card, a
  signature hash footer, and a verification badge — information that is only
  relevant during detailed inspection, not at-a-glance board scanning.
- **DiffNode** shows 22px hero numbers for +/- lines AND a full file list up
  to 5 entries — appropriate for an inspector panel, excessive on a small
  board card.
- **TerminalTaskNode** exposes the raw session ID as text on every card, even
  though users never use it at the board level.
- Multiple `@keyframes` animations run simultaneously (breathe-gold,
  breathe-amber, breathe-red, heartbeat, eval-glow, swarmEdgePulse,
  edgeActivityPulse, receiptEdgeFlow, glow-pulse-allow, glow-pulse-deny)
  creating a "Christmas tree" effect where every node is competing for
  peripheral attention.

The "Bloomberg terminal" density aesthetic documented in the node file headers
was appropriate when the board was a single-agent monitoring view. At swarm
scale (3-8 concurrent sessions), it produces noise that defeats the purpose of
a spatial overview.

### The goal

Learn from collab-public's minimal tile chrome: quiet surfaces that let content
breathe, with detail available on demand through progressive disclosure.

---

## 2. Reference Aesthetic — collab-public Tile System

### 2.1 Architecture

The reference implementation is a vanilla JS canvas at:

```
collab-public/collab-electron/src/windows/shell/
  ├── src/canvas-state.js       # Tile data model (position, size, type, zIndex)
  ├── src/tile-renderer.js      # DOM construction — createTileDOM()
  ├── src/tile-interactions.js   # Drag, resize, marquee selection
  ├── src/tile-manager.js        # Lifecycle, persistence, webview spawning
  └── src/shell.css              # All visual styling
```

### 2.2 DOM Structure (from `tile-renderer.js`)

Each tile is a flat three-layer sandwich:

```
div.canvas-tile[data-tile-id][data-tile-type]
  ├── div.tile-title-bar          ← drag handle, 6px top/bottom padding
  │     ├── span.tile-title-text  ← parent path (muted) + filename
  │     ├── div.tile-btn-group    ← copy path, open in viewer, close
  │     └── (optional: URL input for browser tiles)
  └── div.tile-content            ← 100% of remaining space
        └── div.tile-content-overlay  ← click-through overlay for focus mgmt
```

Key observations:

- **No footer.** No metrics bar, no status bar. The tile is title + content.
- **No icons in the title bar.** The title text alone conveys the type (filename
  extension, "Terminal", hostname).
- **Action buttons are invisible until hover.** `opacity: 0.4` at rest,
  `opacity: 0.8` on hover. The close button `&times;` uses `font-size: 18px`.
- **No status indicators at all.** The tile content itself (terminal output,
  code, note text) IS the status.

### 2.3 CSS Treatment (from `shell.css`)

```css
.canvas-tile {
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.5);
  border: 1px solid rgba(128, 128, 128, 0.2);
  background: var(--bg);                        /* rgb(248,248,248) / rgb(18,18,18) */
}

.tile-title-bar {
  padding: 6px 8px;                             /* compact, not cramped */
  background: var(--bg);                        /* same as tile body */
  border-bottom: none;                          /* no separator line */
  cursor: grab;
}

.tile-title-text {
  font-size: 11px;
  font-weight: 500;
  opacity: 0.7;                                 /* deliberately dimmed */
}

.tile-content {
  flex: 1;
  overflow: hidden;
  border-radius: 0 0 7px 7px;                  /* clips content at bottom */
}
```

Characteristics to adopt:

| Property | collab-public | Current swarm nodes |
|---|---|---|
| Border radius | `8px` (friendly) | `rounded-sm` / `rounded-none` (harsh) |
| Title bar height | Auto (~26px from padding) | Hardcoded `28px` / `18px` |
| Title bar separator | None | Implicit via different background |
| Title font size | `11px` | `9px` (too small to scan) |
| Action buttons | `opacity: 0.4`, hover `0.8` | Always-visible status labels |
| Body padding | `0` (content fills) | `0-8px` varies |
| Footer | None | 24px metrics bar + 18px status bar |
| Animations | Zero. `transition: none`. | 6+ concurrent `@keyframes` |
| Focus indicator | `0 0 0 1px rgba(X,X,X,0.5)` ring | `ring-1 ring-[#c49a3c]/20` |
| Selected indicator | `border-color: #4a9eff` | Multiple overlaid signals |

### 2.4 Visual Hierarchy

collab-public achieves progressive disclosure through exactly three states:

1. **At rest:** Title text (muted) + content area. No indicators, no badges.
2. **Focused (tile-focused):** Box-shadow ring appears. Webview becomes
   interactive. Title text does NOT change.
3. **Selected (tile-selected):** Border turns accent blue `#4a9eff`. Used for
   multi-tile operations (group drag, delete).

There is no hover-tooltip layer. There is no inspector drawer. Detail comes
from focusing the tile and interacting with the content directly (reading the
terminal, editing the note, browsing the code).

### 2.5 Color Palette

```
Light mode:
  --bg: rgb(248, 248, 248)
  --fg: rgb(32, 32, 32)
  --border: rgb(206, 206, 206)
  --muted: rgb(113, 113, 123)

Dark mode:
  --bg: rgb(18, 18, 18)
  --fg: rgb(220, 220, 220)
  --border: rgba(255, 255, 255, 0.2)
  --muted: rgb(132, 132, 132)
```

The swarm board's dark theme (`#0a0c11` body, `#07080c` title bars) is roughly
equivalent. The key difference is not in base colors but in accent overuse:
the current nodes apply 5+ accent colors (`#c49a3c`, `#5580cc`, `#38a876`,
`#b85450`, `#7c5cbf`) at full saturation simultaneously, while collab-public
uses a single muted accent (`var(--muted)`) everywhere except the selection
border.

---

## 3. Current Swarm Board Node Audit

### 3.1 AgentSessionNode

**File:** `src/components/workbench/swarm-board/nodes/agent-session-node.tsx`

| Element | Currently shown | Assessment |
|---|---|---|
| Status dot (6px, pulsing) | Always | KEEP — primary status signal |
| Agent model label | Always (title bar) | MOVE to hover tooltip |
| Branch name | Always (title bar) | MOVE to hover tooltip |
| Policy mode label | Always (title bar) | MOVE to inspector |
| Status label (RUN/WAIT/FAIL) | Always (title bar) | KEEP — complements dot |
| Exit code | Always when set | MOVE to inspector |
| Maximize/minimize buttons | Always | KEEP — functional |
| Close button | Always | KEEP — functional |
| Terminal body | Always | KEEP — this IS the content |
| Footer metrics bar (4 icons) | Always (24px) | REMOVE from node |
| Risk indicator | Always (footer) | MOVE to inspector |
| Status bar (worktree, bypass) | Always (18px) | REMOVE from node |
| Left border accent (2px) | Always when active | SIMPLIFY — keep but static |
| Breathing box-shadow animation | Running/blocked/failed | REMOVE |
| Heartbeat radial pulse overlay | Running | REMOVE |

**Net savings:** ~42px vertical space (footer + status bar) removed. Two
running animations removed.

### 3.2 TerminalTaskNode

**File:** `src/components/workbench/swarm-board/nodes/terminal-task-node.tsx`

| Element | Currently shown | Assessment |
|---|---|---|
| Status label (bold, colored) | Always | KEEP — this is the node's purpose |
| Title text | Always | KEEP |
| Elapsed time | Always | KEEP — useful at a glance |
| Task description (2 lines) | Always | TRUNCATE to 1 line; full in inspector |
| Session ID (7px raw text) | Always | REMOVE — never useful at board level |
| Left border accent | Always | KEEP — type differentiation |

**Net savings:** Session ID row removed, description truncated. Cleaner.

### 3.3 ArtifactNode

**File:** `src/components/workbench/swarm-board/nodes/artifact-node.tsx`

This node is already close to the collab-public aesthetic (icon + label, no
card background). Minimal changes needed.

| Element | Currently shown | Assessment |
|---|---|---|
| File type icon (20px) | Always | KEEP |
| Filename label (9px) | Always | KEEP |
| File type badge (7px) | Always | REMOVE — redundant with icon color |
| Selection drop-shadow | Selected | KEEP |

### 3.4 DiffNode

**File:** `src/components/workbench/swarm-board/nodes/diff-node.tsx`

| Element | Currently shown | Assessment |
|---|---|---|
| +N / -N hero numbers (22px) | Always | REDUCE to 14px; still readable |
| "added" / "removed" labels | Always | REMOVE — the +/- is self-explanatory |
| File list (up to 5 items) | Always | MOVE to inspector entirely |
| File count footer | Always | KEEP as single line: "3 files" |

**Net savings:** File list section removed (variable height, often 40-80px).
Hero numbers scaled down.

### 3.5 NoteNode

**File:** `src/components/workbench/swarm-board/nodes/note-node.tsx`

This node is already well-designed. The warm amber tint and slight rotation
are intentional personality. Minor tweaks only.

| Element | Currently shown | Assessment |
|---|---|---|
| Title ("Note") | Always | KEEP |
| Edit/Save button | Always | KEEP |
| Note content body | Always | KEEP |
| Editing hint text | When editing | KEEP |
| 1.2deg rotation | Always | KEEP — personality is good |

No structural changes. Only apply the shared spacing and border-radius
tokens.

### 3.6 ReceiptNode

**File:** `src/components/workbench/swarm-board/nodes/receipt-node.tsx`

| Element | Currently shown | Assessment |
|---|---|---|
| Verdict icon + label (18px) | Always | KEEP but reduce to 14px |
| Passed/failed count | Always | KEEP |
| Timestamp | Always | MOVE to inspector |
| Guard results list (up to 6) | Always | MOVE to inspector entirely |
| Signature hash footer | Always | MOVE to inspector |
| Verification badge | Always | MOVE to inspector |
| Top border accent | Always | KEEP |

**Net savings:** Guard list and signature footer removed. The receipt node
becomes verdict + pass/fail count only — the "stamp" metaphor realized more
cleanly.

---

## 4. Design Principles

Derived from collab-public's approach, adapted for the swarm context:

### P1: Progressive Disclosure

| Level | What's shown | Interaction |
|---|---|---|
| **Glance** (board scan) | Type icon/shape, name, status dot, status label | No interaction |
| **Hover** (3-5px tooltip) | Branch, model, elapsed time, compact metrics | Mouse hover |
| **Click** (selection + focus) | Full node content visible, inspector opens | Single click |
| **Inspect** (drawer detail) | All metadata, guard results, file lists, signatures | Inspector drawer |

### P2: Content-First

The terminal output, note text, or diff summary IS the content. Chrome should
occupy less than 30% of the node's pixel area. Currently AgentSessionNode
devotes ~42px to footer bars in a 240px minimum height — that is 17.5% to
chrome that could be terminal output.

### P3: Quiet Until Relevant

Status indicators should be:
- **Static** for steady states (idle, completed).
- **Subtly visible** for active states (running = status dot only, no animation).
- **Prominent** for states requiring attention (failed, blocked = dot color
  change + optional single brief transition, not a continuous animation).

### P4: Consistent Sizing and Spacing

All nodes should share:
- `border-radius: 6px` (between collab's `8px` and current `rounded-sm`)
- Title bar padding: `6px 8px` (matches collab-public)
- Title font: `11px` weight `500` (matches collab-public)
- Action button opacity: `0.35` idle, `0.7` hover (matches collab-public's
  `0.4`/`0.8` but slightly more subtle in the dark theme)
- Focus ring: `box-shadow: 0 0 0 1px var(--accent)` (single ring, no glow)
- Selected: `border-color: #c49a3c` (swarm accent, not blue — different
  product identity)

---

## 5. Node-by-Node Redesign

### 5.1 AgentSessionNode — Redesigned

```
┌──────────────────────────────────────┐
│ ● RUN  session-name          ▭  ✕   │  ← 28px title bar
│                                      │
│  $ npm test                          │
│  ✓ 14 passed                         │
│  ✗ 1 failed                          │  ← terminal body fills remaining space
│  > Running fix...                    │
│                                      │
└──────────────────────────────────────┘
```

**Title bar (28px):**
- Left: status dot (6px, colored, NO animation) + status label (9px mono, colored)
  + session title (11px, `#8a96ab`)
- Right: maximize button + close button (both `opacity: 0.35`, hover `0.7`)

**Body:**
- Terminal renderer OR preview lines — fills 100% remaining space
- No footer metrics bar
- No status bar

**Hover tooltip (appears after 400ms):**
```
claude-3.5 · feat/swarm-auth · strict
3 files · 2 receipts · 0 blocked
```

**Left border accent:** 2px solid, colored by status, but NO opacity animation.
Static color only. Use `transition: border-color 0.3s ease` for state changes.

**Dimensions:**
- Min width: 280px (down from 320)
- Min height: 180px (down from 240)
- Default: 360 x 400

**Removed entirely:**
- `FooterMetric` component and its 24px bar
- Status bar (18px worktree/bypass)
- `breathe-gold`, `breathe-amber`, `breathe-red` box-shadow animations
- `heartbeat` radial-gradient pulse overlay
- `statusAnimation` computed property
- `statusOpacityClass` (completed nodes at 0.7 opacity — use a muted title
  color instead)

### 5.2 TerminalTaskNode — Redesigned

```
┌───────────────────────────┐
│ RUN  Fix auth timeout  4m │  ← single row, badge-like
│ Run failing auth tests... │  ← 1-line description
└───────────────────────────┘
```

**Single header row:**
- Status label (bold, colored) + title (truncated) + elapsed time (muted)

**Description row:**
- Task prompt, `line-clamp-1` (down from 2)

**Removed:**
- Session ID display

**Dimensions:**
- Min width: 200px (down from 220)
- Min height: 56px (down from 80)

### 5.3 ArtifactNode — Redesigned

No structural change. Remove the file type text badge below the filename.

```
   ┌────┐
   │ TS │    ← icon, 40x40, colored by type
   └────┘
  index.ts   ← filename, 9px, truncated
```

**Removed:**
- `d.fileType` text span below filename (the icon color already conveys this)

### 5.4 DiffNode — Redesigned

```
┌──────────────────────┐
│  +47    -12           │  ← 14px numbers, not 22px
│  3 files              │  ← compact summary
└──────────────────────┘
```

**Hero numbers:** Reduced from `22px` to `14px`. Still green/red.

**File count:** Single line "N files" replaces the full file list + separate
count footer.

**Removed:**
- "added"/"removed" text labels under numbers
- Inline file list (moved to inspector)
- Separate file count footer

**Dimensions:**
- Min width: 160px (down from 200)
- Min height: 64px (down from 100)

### 5.5 NoteNode — No Structural Change

Apply shared tokens only:
- `border-radius: 6px` (from `rounded`)
- Title font: `11px` (from `10px`)
- Keep rotation, warm tint, edit/save button

### 5.6 ReceiptNode — Redesigned

```
┌───────────────────────────┐
│  ✓ ALLOW   4/4 passed     │  ← verdict hero (icon + label + count)
└───────────────────────────┘
```

**Verdict section:**
- Icon (16px) + verdict label (14px bold) + passed/failed count
- All in a single flex row

**Removed:**
- Timestamp (moved to inspector)
- Guard results list (moved to inspector)
- Signature hash footer (moved to inspector)
- Verification badge (moved to inspector)

**Dimensions:**
- Min width: 180px (down from 240)
- Min height: 56px (down from 160)

This makes receipt nodes roughly the same visual weight as TerminalTaskNodes —
consistent, scannable, lightweight.

---

## 6. Inspector Enhancement

**File:** `src/components/workbench/swarm-board/swarm-board-inspector.tsx`

The inspector drawer currently shows detail sections per node type. As nodes
get simpler, the inspector absorbs their former inline content. New or
promoted sections per type:

### 6.1 AgentSession Inspector — New Sections

| Section | Content | Source |
|---|---|---|
| **metrics** | Files changed, receipt count, blocked actions, tool boundary events, confidence — icon+number pairs like the removed footer | Absorbed from `FooterMetric` |
| **risk** | Risk level with colored badge | Absorbed from footer |
| **policy** | Policy mode, bypass state | Absorbed from status bar |
| **worktree** | Full worktree path | Absorbed from status bar |

The existing `session`, `files`, and `output` sections remain unchanged.

### 6.2 TerminalTask Inspector — New Sections

| Section | Content | Source |
|---|---|---|
| **session** | Full session ID (copyable) | Absorbed from node |

### 6.3 Receipt Inspector — New Sections

| Section | Content | Source |
|---|---|---|
| **timing** | Created-at timestamp, total guard evaluation time | Absorbed from node |
| **guards** | Full guard result list (already exists) | Already in inspector |
| **signature** | Full hash, verification status badge | Absorbed from node |

### 6.4 Diff Inspector — New Sections

| Section | Content | Source |
|---|---|---|
| **changed files** | Full file list (already exists) | Already in inspector |

No new sections needed — the inspector already has `changed files`.

### 6.5 Inspector Hover Preview

When a node is hovered (not selected), the inspector should show a lightweight
preview card at the bottom of the drawer (if the inspector is already open for
a different node) or as a floating tooltip. This bridges the gap between "glance
at the node" and "click to inspect."

Implementation: add `onNodeMouseEnter`/`onNodeMouseLeave` handlers in
`swarm-board-page.tsx` that set a `hoveredNodeId` in the store. The inspector
renders a `<HoverPreview>` component when `hoveredNodeId !== selectedNodeId`.

---

## 7. Animation Cleanup

### 7.1 Animations to REMOVE

| Animation | Defined in | Used by | Reason |
|---|---|---|---|
| `breathe-gold` | `swarm-board-page.tsx` inline style | AgentSessionNode (`running`) | Continuous glow on every running node — visual noise at swarm scale |
| `breathe-amber` | `swarm-board-page.tsx` inline style | AgentSessionNode (`blocked`) | Same — continuous ambient animation |
| `breathe-red` | `swarm-board-page.tsx` inline style | AgentSessionNode (`failed`) | Same |
| `heartbeat` | `swarm-board-page.tsx` inline style | AgentSessionNode radial overlay | Pulsing scale transform on running sessions — distracting |
| `eval-glow` | `swarm-board-page.tsx` inline style | AgentSessionNode (`evaluating`) | Same class of ambient glow |
| `pulse` (on status dot) | `agent-session-node.tsx` inline style | Status dot in AgentSessionNode | The dot color alone conveys status; pulsing is redundant |
| `swarmEdgePulse` | `swarm-edge.tsx` injected style | Spawned edges at rest | Edges already use opacity differentiation; ambient pulse adds noise |
| `glow-pulse-allow` | `globals.css` | Various receipt UI | Low-value ambient decoration |
| `glow-pulse-deny` | `globals.css` | Various receipt UI | Same |
| `verdict-pulse-ring` | `globals.css` | Receipt verdict display | Ambient decoration |
| `verdict-alert-flash` | `globals.css` | Receipt verdict display | Ambient decoration |
| `hb-glow`, `hb-ring`, `hb-seg`, `hb-sweep`, `hb-diamond`, `hb-facets`, `hb-core` | `globals.css` | Heartbeat UI widgets | Remove from swarm board context (may still be used elsewhere in the app) |

### 7.2 Animations to KEEP

| Animation | Defined in | Used by | Reason |
|---|---|---|---|
| `nodeEnter` | `swarm-board-page.tsx` inline style | `.react-flow__node` | Meaningful: entrance transition when a node is added to the board |
| `edgeActivityPulse` | `swarm-edge.tsx` injected style | Recently-active edges | Meaningful: communicates a message just traveled this edge (time-limited to 3s) |
| `receiptEdgeFlow` | `swarm-edge.tsx` injected style | Receipt edges | Meaningful: directional flow animation shows data movement |
| `fade-in` | `globals.css` | Various | General utility |
| `page-enter` | `globals.css` | Page transitions | General utility |

### 7.3 Animations to ADD

| Animation | Purpose | Spec |
|---|---|---|
| Status dot color transition | Smooth state change on the dot | `transition: background-color 0.4s ease` on the status dot element |
| Border accent color transition | Smooth state change on left border | `transition: border-color 0.3s ease` on the node container |
| Inspector slide-in | Already exists (`motion/react` spring) | No change needed |
| Tooltip fade | Hover tooltip appearance | `opacity 0 -> 1` over `150ms`, `200ms` delay before show |

### 7.4 Removal Strategy

The `breathe-*` and `heartbeat` animations are defined in a `<style>` tag
inside `swarm-board-page.tsx` (lines 552-580). They can be removed in a single
edit. The `statusAnimation` computed value in `agent-session-node.tsx` (lines
105-113) and the heartbeat overlay div (lines 136-144) should be deleted in the
same pass.

For `globals.css`, the `glow-pulse-allow`, `glow-pulse-deny`,
`verdict-pulse-ring`, and `verdict-alert-flash` keyframes should be searched
for usage across the app before deletion. If used only by swarm board
components, delete. If used elsewhere, leave in `globals.css` but remove
references from swarm board components.

---

## 8. Implementation Plan

### Phase 1: CSS-First (No Component Structure Changes)

**Estimated effort:** 1-2 hours
**Risk:** Zero — purely visual, easily reversible

1. **Remove animation keyframes** from `swarm-board-page.tsx` inline `<style>` block.
   Delete `breathe-gold`, `breathe-amber`, `breathe-red`, `heartbeat`,
   `eval-glow`. Keep `nodeEnter`.

   File: `src/components/workbench/swarm-board/swarm-board-page.tsx` (lines 552-579)

2. **Remove `swarmEdgePulse`** from `swarm-edge.tsx` `ensureKeyframes()`.
   Keep `edgeActivityPulse` and `receiptEdgeFlow`.

   File: `src/components/workbench/swarm-board/edges/swarm-edge.tsx` (lines 27-31)

3. **Add shared CSS tokens** to the swarm board scope. Create or update a CSS
   file with variables:

   ```css
   .swarm-board {
     --node-radius: 6px;
     --title-font-size: 11px;
     --title-font-weight: 500;
     --title-padding: 6px 8px;
     --action-opacity: 0.35;
     --action-hover-opacity: 0.7;
     --focus-ring: 0 0 0 1px rgba(196, 154, 60, 0.4);
     --selected-border: #c49a3c;
   }
   ```

4. **Update `nodeEnter` duration** from `0.3s` to `0.2s` (snappier).

### Phase 2: AgentSessionNode Simplification

**Estimated effort:** 2-3 hours
**Risk:** Low — only removes elements, does not change data flow

1. Delete the `statusAnimation` computed property (lines 105-113).
2. Delete the heartbeat radial overlay `<div>` (lines 136-144).
3. Delete the `statusOpacityClass` computed property (lines 99-103).
   Replace with a muted title color for `completed` status.
4. Delete the `FooterMetric` component and the footer metrics bar `<div>`
   (lines 278-296).
5. Delete the status bar `<div>` (lines 299-319).
6. Replace the `STATUS_PULSE` map usage — remove the `animation` and
   `boxShadow` properties from the status dot's inline style.
7. Add `transition: background-color 0.4s ease` to the status dot.
8. Update `minHeight` from `240` to `180`, `minWidth` from `320` to `280`.
9. Apply shared border-radius token.

   File: `src/components/workbench/swarm-board/nodes/agent-session-node.tsx`

### Phase 3: ReceiptNode and DiffNode Simplification

**Estimated effort:** 2 hours
**Risk:** Low

**ReceiptNode:**

1. Remove the guard results list section (lines 132-158).
2. Remove the signature footer section (lines 162-189).
3. Remove the timestamp display from the verdict hero (lines 121-128).
4. Collapse the verdict section into a single flex row.
5. Update `minHeight` from `160` to `56`, `minWidth` from `240` to `180`.

   File: `src/components/workbench/swarm-board/nodes/receipt-node.tsx`

**DiffNode:**

1. Reduce hero number font size from `22px` to `14px`.
2. Remove the "added"/"removed" label spans.
3. Remove the inline file list (lines 83-105).
4. Replace with a single "N files" line.
5. Remove the file count footer (lines 108-117).
6. Update `minHeight` from `100` to `64`, `minWidth` from `200` to `160`.

   File: `src/components/workbench/swarm-board/nodes/diff-node.tsx`

### Phase 4: TerminalTaskNode and ArtifactNode Cleanup

**Estimated effort:** 30 minutes
**Risk:** Trivial

**TerminalTaskNode:**

1. Remove the session ID display block (lines 109-118).
2. Change task description from `line-clamp-2` to `line-clamp-1`.
3. Update `minHeight` from `80` to `56`.

   File: `src/components/workbench/swarm-board/nodes/terminal-task-node.tsx`

**ArtifactNode:**

1. Remove the `d.fileType` text badge (lines 113-120).

   File: `src/components/workbench/swarm-board/nodes/artifact-node.tsx`

### Phase 5: Inspector Absorption

**Estimated effort:** 2-3 hours
**Risk:** Medium — adds new UI, needs design review

1. Add `MetricsSection` to `AgentSessionDetail` in the inspector. Reuse the
   `FooterMetric` icon+number pattern but in a horizontal flow within the
   inspector's wider layout.
2. Add `RiskBadge` to the inspector header for agent sessions.
3. Add `PolicySection` showing mode and bypass state.
4. Add `TimingSection` to `ReceiptDetail` showing timestamp.
5. Ensure `ReceiptDetail` already shows guard results and signature (it does —
   verify no regressions after node simplification).
6. Add hover preview component for `hoveredNodeId` state.

   File: `src/components/workbench/swarm-board/swarm-board-inspector.tsx`
   File: `src/components/workbench/swarm-board/swarm-board-page.tsx` (hover handlers)

### Phase 6: Hover Tooltip System

**Estimated effort:** 2 hours
**Risk:** Medium — new interaction layer

1. Create a `NodeHoverTooltip` component that renders via React Flow's
   `EdgeLabelRenderer` (positioned at the hovered node's coordinates).
2. Content varies by node type:
   - AgentSession: `model · branch · policy` on line 1, `N files · N receipts`
     on line 2.
   - TerminalTask: Full task prompt (no truncation).
   - Diff: File list (up to 5).
   - Receipt: Timestamp + guard summary.
   - Artifact/Note: Nothing (already fully visible on node).
3. Tooltip styling: `bg-[#0e1018]`, `border: 1px solid #1a1e2840`,
   `border-radius: 4px`, `padding: 6px 10px`, `font-size: 10px`,
   `max-width: 280px`, `opacity` transition `150ms`.
4. Show after `400ms` hover delay, hide immediately on mouse leave.

   File: new `src/components/workbench/swarm-board/node-hover-tooltip.tsx`
   File: `src/components/workbench/swarm-board/swarm-board-page.tsx` (wire handlers)

### Migration Order

```
Phase 1 (CSS)  ←  safe to ship alone, immediate visual improvement
  ↓
Phase 2 (AgentSessionNode)  ←  biggest payoff, most visual change
  ↓
Phase 3 (Receipt + Diff)  ←  moderate payoff
  ↓
Phase 4 (Task + Artifact)  ←  small cleanup
  ↓
Phase 5 (Inspector)  ←  absorbs removed content, unblocks Phase 6
  ↓
Phase 6 (Tooltips)  ←  final progressive disclosure layer
```

Phases 1-4 can be shipped together as a single PR. Phases 5-6 are a follow-up
PR since they add new UI rather than removing existing UI.

### Test Updates

The following test files will need assertion updates to match removed DOM
elements:

- `__tests__/agent-session-node.test.tsx` — remove assertions for footer
  metrics, status bar, animation classes
- `__tests__/receipt-node.test.tsx` — remove assertions for guard list,
  signature footer
- `__tests__/diff-node.test.tsx` — remove assertions for file list, hero
  number size
- `__tests__/terminal-task-node.test.tsx` — remove assertion for session ID
  display
- `__tests__/artifact-node.test.tsx` — remove assertion for file type badge
- `__tests__/swarm-board-inspector.test.tsx` — add assertions for new
  metrics/risk/policy/timing sections

---

## Appendix: File Reference

### collab-public (REFERENCE)

| File | Purpose |
|---|---|
| `collab-electron/src/windows/shell/src/tile-renderer.js` | Tile DOM construction — the model for minimal chrome |
| `collab-electron/src/windows/shell/src/tile-manager.js` | Tile lifecycle — shows that tiles have no state indicators |
| `collab-electron/src/windows/shell/src/tile-interactions.js` | Drag/resize — no hover tooltips, no state animations |
| `collab-electron/src/windows/shell/src/canvas-state.js` | Tile data model — 6 types, no status fields |
| `collab-electron/src/windows/shell/src/shell.css` | All CSS — zero `@keyframes`, zero pulse/glow effects |
| `collab-electron/packages/shared/src/styles/Theme.css` | Design tokens — muted palette, restrained accents |
| `collab-electron/packages/theme/src/styles.css` | Tailwind theme — spacing/radius/color system |
| `collab-electron/packages/components/src/Terminal/TerminalTab.css` | Terminal styling — 7 lines of CSS, zero decoration |

### clawdstrike-swarm-engine (TARGET)

| File | Purpose |
|---|---|
| `src/components/workbench/swarm-board/nodes/agent-session-node.tsx` | Heaviest node — primary target for simplification |
| `src/components/workbench/swarm-board/nodes/terminal-task-node.tsx` | Task badge — minor cleanup |
| `src/components/workbench/swarm-board/nodes/artifact-node.tsx` | File icon — already minimal, remove type badge |
| `src/components/workbench/swarm-board/nodes/diff-node.tsx` | Diff card — reduce hero size, remove file list |
| `src/components/workbench/swarm-board/nodes/note-node.tsx` | Sticky note — no structural change |
| `src/components/workbench/swarm-board/nodes/receipt-node.tsx` | Receipt stamp — major simplification |
| `src/components/workbench/swarm-board/swarm-board-inspector.tsx` | Inspector drawer — absorbs removed node content |
| `src/components/workbench/swarm-board/swarm-board-page.tsx` | Board page — animation keyframes defined here |
| `src/components/workbench/swarm-board/edges/swarm-edge.tsx` | Edge renderer — remove `swarmEdgePulse` |
| `src/components/workbench/swarm-board/terminal-renderer.tsx` | Terminal WASM mount — no changes needed |
| `src/features/swarm/swarm-board-types.ts` | Type definitions — no changes needed |
| `src/globals.css` | Global keyframes — audit `glow-pulse-*` and `verdict-*` usage |
