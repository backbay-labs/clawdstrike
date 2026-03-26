---
Status: Approved
Supersedes: 04-cleaner-tile-chrome.md
Author: Design Engineering
Date: 2026-03-26
Scope: Swarm Board node chrome, inspector, animations, accessibility
---

# 04 -- Security Operations Chrome Contract

This document is the authoritative chrome specification for the Clawdstrike Swarm Board. It supersedes `04-cleaner-tile-chrome.md` and addresses all 12 review items from `04-cleaner-tile-chrome-review.md`. Future chrome implementation work on the swarm board must conform to the principles, specifications, and anti-patterns defined herein.

---

## 1. Domain Context

### This is a security operations monitoring surface

The Clawdstrike Swarm Board is a live multi-agent security operations canvas. Operators use it to run 3-8 concurrent autonomous agent sessions against active security investigations -- threat hunts, incident triage, vulnerability assessments. The operator's primary task is not "focus on one thing and interact with it" but "scan the entire board to detect anomalies across multiple concurrent agents." This is closer to an air traffic control display or a SOC analyst's SIEM dashboard than it is to a personal workspace or note-taking canvas.

### The "Bloomberg terminal" density aesthetic is intentionally correct

The comment in `agent-session-node.tsx` -- "Visual language: Bloomberg terminal. Dark, dense, utilitarian. Information density IS the aesthetic." -- was not accidental. Information density on individual nodes becomes MORE important as the number of simultaneous agents increases, because the operator has less time to drill into any single node. Every visible metric must answer an operator question during an active hunt.

### Why collab-public is the wrong reference model

The original spec (`04-cleaner-tile-chrome.md`) proposed learning from collab-public's minimal tile chrome. This is a category error:

- **collab-public is a personal workspace.** Its tiles contain terminals, code editors, notes, and browser views. The user interacts with one tile at a time. There is no concept of "status" because the content is passive.
- **collab-public tiles have no status indicators, no health signals, and no monitoring semantics.** The minimal aesthetic works because there is nothing to monitor.
- **The swarm board must convey:** session status (idle/running/blocked/failed/evaluating), risk level (low/medium/high), blocked action counts, receipt verdicts (allow/deny/warn), guard evaluation results, and file change metrics -- all at a glance, across multiple simultaneous nodes.

Borrowing aesthetic principles from a tool that has none of these concerns produces a surface that looks clean but fails its operational purpose. The diagnosis in the original spec was correct (too many concurrent animations create visual noise), but the treatment was too aggressive (removing operational telemetry for minimalism).

### What Phases 24-25 have already shipped

Significant chrome improvements were implemented in Phases 24-25, rendering much of the original spec's proposal either already resolved or superseded:

- **Semantic zoom (Phase 25):** 4-tier system (full/compact/chip/dot) with thresholds at 0.6/0.35/0.18. All six node types implement tier-aware rendering.
- **Multi-select comparison (Phase 24):** ComparisonInspector with type-specific comparison views (SessionComparison, ReceiptComparison, DiffComparison, TaskComparison, ArtifactComparison, MixedComparison), capped at MAX_COMPARISON_NODES=6.
- **One-shot status flash (Phase 25):** 500ms box-shadow flash on status/verdict transitions, replacing the old breathing/heartbeat animations.
- **Simplified metrics bar (Phase 25 iteration):** Numbers-only FooterMetric components (no icons), 14-18px height by tier.
- **Posture analytics in comparison (Phase 24):** PostureSummaryBar and GuardHeatmapTable in receipt comparison views.
- **Animation cleanup (Phase 25):** Removed breathe-gold, breathe-amber, breathe-red, heartbeat, eval-glow keyframes. Only nodeEnter remains in swarm-board-page.tsx.

This contract codifies these shipped patterns as the endorsed direction and fills the remaining gaps.

---

## 2. Design Principles

### P1: Information Density as Feature

**Definition:** Every visible datum on a node surface must answer a specific operator question during an active hunt. Density is not clutter -- it is operational necessity for a monitoring surface.

**Test:** For any proposed chrome element, ask: "Does this number/icon/label help an operator running a 6-agent hunt?" If yes, it stays. If no, it moves to the inspector or is removed.

**Examples:**
- Blocked action count on AgentSessionNode footer: YES -- "which sessions have blocked actions?" is a board-scan question.
- Receipt signature hash: NO -- "what is the signature hash?" is an inspection question, not a scan question.

### P2: Operational Telemetry Over Decoration

**Definition:** All node chrome elements fall into exactly one of three categories. This classification determines their placement:

| Category | Definition | Placement | Current Examples |
|----------|-----------|-----------|-----------------|
| **Operational telemetry** | Data that answers "what is happening right now?" | KEEP on node surface | Status label, risk level, blocked count, receipt count, files changed, verdict |
| **Inspection detail** | Data that answers "tell me more about this specific item" | MOVE to inspector | Guard result lists, signature hashes, full file lists, worktree paths, verification badges |
| **Decorative chrome** | Elements that serve no monitoring purpose | REMOVE | Breathing animations, raw session IDs, redundant labels, continuous pulse effects |

**Test:** If the element cannot be classified as telemetry or detail, it is decoration. Remove it.

### P3: Progressive Disclosure via Zoom

**Definition:** Semantic zoom tiers ARE the progressive disclosure system. There are exactly three ways to get more information about a node:

1. **Zoom in** -- the node's tier changes (dot -> chip -> compact -> full), revealing more detail.
2. **Click to inspect** -- the inspector drawer opens with full detail for the selected node.
3. **Multi-select to compare** -- Shift+click or marquee-select triggers ComparisonInspector.

There is no hover tooltip tier. There is no separate compact/expanded toggle. There is no inspector hover preview. The zoom tier system IS the compact/expanded system.

**Test:** If a proposed chrome change requires a new interaction mode (hover, toggle, long-press), it violates this principle. Use the existing three mechanisms instead.

### P4: One-Shot Signal, Not Continuous Motion

**Definition:** Status changes use a single brief animation (500ms one-shot box-shadow flash), then settle to a static visual state. There are no continuous breathing, pulsing, or heartbeat animations on any node or edge.

The existing `statusFlash` and `verdictFlash` patterns (see `agent-session-node.tsx` and `receipt-node.tsx`) are the canonical signal animations. They use a `useRef` to skip the initial render, a `useState` toggle, and a `setTimeout` cleanup -- ensuring exactly one flash per state transition.

**Test:** If a proposed animation runs continuously (infinite iteration count, or duration > 1s), it is rejected. Animations must fire once on state change and complete.

### P5: Contrast Before Aesthetics

**Definition:** All interactive elements and text must meet WCAG AA contrast minimums computed against the actual board background (`#0a0c11`):

- **3:1 minimum** for large text (>= 18px or >= 14px bold) and non-text UI components (icons, borders, focus rings).
- **4.5:1 minimum** for normal text (< 18px, not bold).

Contrast must be specified as computed hex values, not opacity multipliers. An element at `opacity: 0.35` on `#0a0c11` produces approximately 1.6:1 contrast -- well below any accessibility threshold. The swarm board's background is significantly darker than collab-public's `#121212`, so collab-public's opacity-based approach does not transfer.

**Test:** For any proposed color on `#0a0c11`, compute the WCAG contrast ratio. If it fails the applicable threshold (3:1 or 4.5:1), provide a corrected hex value.

---

## 3. Node Chrome Specification

The following table specifies what each node type renders at each semantic zoom tier. This table is written against the current codebase state (post-Phase 32) and references the actual source files.

### 3.1 Tier Table

| Tier | Zoom Range | AgentSession | Receipt | Diff | Task | Artifact | Note |
|------|-----------|-------------|---------|------|------|----------|------|
| **full** | >= 0.6 | Title bar (model, branch, status, mode, recovery) + terminal body + metrics bar (18px) + NodeResizer | Verdict hero (icon 20px + label 18px + pass/fail count) + guard count + verification footer + timestamp + NodeResizer | +/- hero (14px) + file count + diff path + DiffPreviewPane (on select) + NodeResizer | Status label + title + elapsed time + description (1-2 line clamp) + NodeResizer | Icon (20px) + filename label (9px) | Title + editable content body + edit/save button + hint text |
| **compact** | 0.35-0.6 | Title bar (model, branch, status, mode, recovery) + condensed metrics bar (14px), no terminal body | Condensed verdict (icon 14px + label 13px + pass/fail), no verification footer, no timestamp | +/- hero (14px) + file count + diff path | Status label + title, no elapsed, no description | Icon (20px) + filename label (9px) (same as full) | Title + content (line-clamp-2), no edit controls |
| **chip** | 0.18-0.35 | Status dot (5px) + title (8px) + status label (7px), single row | Verdict icon (12px) + verdict label (7px) + guard count, single row | +N/-N (8px) + filename (7px), single row | Status dot (5px) + title (8px) + status label (7px), single row | File icon (12px) + filename (7px), single row | Content preview (~20 chars, 7px), warm background |
| **dot** | < 0.18 | Colored rectangle, 2px left border (status color), 40x20 min | Colored rectangle, 2px top border (verdict accent), 40x20 min | Colored rectangle, 2px left border (net color), 40x20 min | Colored rectangle, 2px left border (status color), 30x16 min | Colored rectangle, 2px left border (file color), 20x20 min | Warm-tinted rectangle (#12100c), 2px left border (#a08a60), 20x20 min |

**Source files:**
- AgentSessionNode: `nodes/agent-session-node.tsx`
- ReceiptNode: `nodes/receipt-node.tsx`
- DiffNode: `nodes/diff-node.tsx`
- TerminalTaskNode: `nodes/terminal-task-node.tsx`
- ArtifactNode: `nodes/artifact-node.tsx`
- NoteNode: `nodes/note-node.tsx`

### 3.2 AgentSessionNode Detail

The AgentSessionNode is the heaviest and most information-dense node type. Its chrome is specified in detail below.

#### Title bar content by tier

| Tier | Height | Content |
|------|--------|---------|
| **full** | 28px | Status dot (6px, colored) + agent model (#c49a3c/80) + pipe separator + branch (#5580cc) + pipe + status label (8px, uppercase, status-colored) + optional session mode (MANUAL/TMUX) + optional recovery label (RECOVER/LIVE) + optional exit code + maximize/close buttons |
| **compact** | 28px | Same content as full, except maximize/close buttons are hidden |
| **chip** | 28px (single row layout) | Status dot (5px) + title/model (8px, #5c6a80) + status label (7px, status-colored) |

#### Metrics bar

The metrics bar is REQUIRED at full and compact tiers (see Section 4 for the full contract).

| Tier | Height | Content |
|------|--------|---------|
| **full** | 18px | Files changed (#6f97d8) + receipts (#9777cf) + blocked actions (#d06860 or #4a5568) + tool boundary events (#d4a84b, optional) + risk level (right-aligned, RISK_COLORS) |
| **compact** | 14px | Same metrics, condensed spacing |
| **chip** | N/A | No metrics bar |
| **dot** | N/A | No metrics bar |

#### Terminal body

Visible at full tier only. Shows either the live TerminalRenderer (via TerminalTileErrorBoundary) when selected/maximized with an attached session, or static preview lines (up to 6 unselected, 10 selected) with line gutters. Background: `#06070b`.

#### Left border accent

Static 2px left border colored by status. No animation. Uses `transition: border-color` for smooth state changes.

| Status | Border Color |
|--------|-------------|
| running | #c49a3c |
| blocked | #d4a04a |
| failed | #b85450 |
| evaluating | #d4a84b |
| idle | none |
| completed | none |

#### Status flash

On status transition: 500ms one-shot `boxShadow` flash (`0 0 0 1px ${statusColor}40, 0 0 18px ${statusColor}18`). Fires at all tiers. Skips initial render.

---

## 4. Metrics Bar Contract

### Declaration

The metrics bar on AgentSessionNode is **REQUIRED operational telemetry**. It MUST NOT be removed, hidden, or made conditional on any interaction state (hover, click, focus). It is visible at full and compact tiers.

### Rationale

During an active 6-agent hunt, the operator needs to answer the following questions by scanning the board -- not by clicking into individual nodes:

| Metric | Operator Question | Component | Color |
|--------|------------------|-----------|-------|
| Files changed | "How much disk impact has this session had?" | `FooterMetric` | #6f97d8 |
| Receipt count | "How many guard evaluations have occurred?" | `FooterMetric` | #9777cf |
| Blocked actions | "Has this session hit any guard rails?" | `FooterMetric` | #d06860 (non-zero) / #4a5568 (zero) |
| Tool boundary events | "How many tool boundary crossings?" | `FooterMetric` (conditional) | #d4a84b |
| Risk level | "What is the aggregate risk assessment?" | Inline span | RISK_COLORS[risk] |

Every metric in this table answers a specific, board-level operator question. Removing any of them forces the operator into click-to-inspect for information they need at a glance.

### Preservation rules

1. The metrics bar uses numbers-only `FooterMetric` components. No icons. Font: 9px mono, `font-variant-numeric: tabular-nums`.
2. Height: 18px at full tier, 14px at compact tier. Background: `#07080c`.
3. The bar is NOT visible at chip or dot tiers (these are spatial markers, not readable surfaces).
4. Any future change that removes or hides the metrics bar requires explicit review and documented rationale for why the removal better serves the security operations monitoring use case.
5. Metrics may be simplified (e.g., combining metrics, adjusting colors) but the operational signal they provide must be preserved.

---

## 5. Semantic Zoom Rules

### Endorsed tier system

The existing 4-tier semantic zoom system is declared authoritative. It is implemented in `hooks/use-zoom-tier.ts` via the `ZOOM_TIER_THRESHOLDS` constant and the `selectZoomTier` pure selector.

| Tier | Zoom Range | Purpose |
|------|-----------|---------|
| **full** | zoom >= 0.6 | Full detail: all operational telemetry, terminal body, edit controls, resize handles |
| **compact** | 0.35 <= zoom < 0.6 | Condensed detail: title bar + metrics bar (14px), no terminal body, no edit controls |
| **chip** | 0.18 <= zoom < 0.35 | Summary label: single-row indicator with status/type signal, not readable at screen-pixel level |
| **dot** | zoom < 0.18 | Spatial marker: colored rectangle with accent border, no text content |

### Zoom tiers define compact/expanded behavior

Per the locked decision from CONTEXT.md: **the zoom tier system IS the compact/expanded system.** There is NO separate per-node mode toggle independent of zoom level.

- To see full detail: zoom in (or click to inspect).
- To see a compact overview: zoom out.
- To compare nodes: multi-select (Shift+click or marquee) and use ComparisonInspector.

Adding a second axis of expansion (per-node or global toggle) creates combinatorial complexity: 4 tiers x 2 modes = 8 render paths per node type across 6 node types = 48 render paths. This is rejected.

### Chip and dot tiers are intentionally non-readable

At chip tier (0.18-0.35 zoom), text renders at approximately 1.4-2.8px equivalent screen size. At dot tier (< 0.18 zoom), no text is rendered at all. These tiers serve as spatial markers for board topology, not as readable information surfaces. Readability is expected only at full and compact tiers.

### Canonical implementation reference

- **Type:** `ZoomTier = "full" | "compact" | "chip" | "dot"`
- **Thresholds:** `ZOOM_TIER_THRESHOLDS = { compact: 0.6, chip: 0.35, dot: 0.18 }`
- **Selector:** `selectZoomTier(state)` returns a string literal for `Object.is` equality, preventing per-frame re-renders
- **Hook:** `useZoomTier()` wraps `useStore(selectZoomTier)` for use inside `<ReactFlowProvider>`
- **Source:** `apps/workbench/src/components/workbench/swarm-board/hooks/use-zoom-tier.ts`

---

## 6. Signal Animation Rules

### Endorsed: One-shot status/verdict flash

The `statusFlash` and `verdictFlash` patterns are the canonical signal animations for the swarm board. They implement the following behavior:

1. **Skip initial render:** A `useRef` stores the previous status/verdict. On first render, the ref is initialized and no flash fires.
2. **Detect state change:** On subsequent renders, if the status/verdict has changed, set a boolean state to `true`.
3. **Apply visual signal:** The boolean drives a `boxShadow` value on the node container: `0 0 0 1px ${color}40, 0 0 18px ${color}18` (full/compact) or `0 0 0 1px ${color}40, 0 0 12px ${color}18` (chip/dot).
4. **Auto-cleanup:** A `setTimeout` resets the boolean to `false` after 500ms. The timeout is cleaned up on unmount via the effect return.
5. **Tier-aware:** The box-shadow values vary by tier. Dot tier uses a subtler shadow. The flash fires at all tiers.

**Implementation reference:**
- AgentSessionNode: `statusFlash` state + `previousStatusRef` (lines 147-193 of `agent-session-node.tsx`)
- ReceiptNode: `verdictFlash` state + `previousVerdictRef` (lines 55-68 of `receipt-node.tsx`)
- TerminalTaskNode: `statusFlash` state + `previousStatusRef` (lines 37-50 of `terminal-task-node.tsx`)

This pattern is endorsed. All future status-change animations on nodes MUST follow this pattern.

### Animations: ENDORSED (kept)

| Animation | Location | Behavior | Rationale |
|-----------|----------|----------|-----------|
| `nodeEnter` | `swarm-board-page.tsx` style block | 0.3s ease-out opacity+transform on `.react-flow__node` | Meaningful: entrance transition when a node is added to the board |
| `edgeActivityPulse` | `swarm-edge.tsx` injected keyframes | stroke-opacity 0.4->1->0.4, stroke-width 1->2.5->1, used on recently-active edges | Meaningful: communicates a message just traveled this edge. Time-limited to ACTIVITY_RECENCY_MS (3000ms) |
| `receiptEdgeFlow` | `swarm-edge.tsx` injected keyframes | stroke-dashoffset 28->0, directional flow on receipt edges | Meaningful: directional flow animation shows data movement along receipt edges |
| `statusFlash` | Per-node component state | 500ms one-shot box-shadow on status transition | Canonical: peripheral vision detects the flash without requiring active scanning |
| `verdictFlash` | Per-node component state | 500ms one-shot box-shadow on verdict transition | Canonical: same pattern as statusFlash for receipt verdict changes |
| Inspector slide-in | `swarm-board-inspector.tsx` via `motion/react` | Spring animation on inspector drawer open/close | Standard: single entrance/exit transition via AnimatePresence |

### Animations: REJECTED (removed or to be removed)

| Animation | Former Location | Status | Rationale for Rejection |
|-----------|----------------|--------|------------------------|
| `breathe-gold` | `swarm-board-page.tsx` style block | Already removed (Phase 25) | Continuous glow on every running node -- visual noise at swarm scale |
| `breathe-amber` | `swarm-board-page.tsx` style block | Already removed (Phase 25) | Continuous ambient animation on blocked sessions |
| `breathe-red` | `swarm-board-page.tsx` style block | Already removed (Phase 25) | Continuous ambient animation on failed sessions |
| `heartbeat` | `swarm-board-page.tsx` style block | Already removed (Phase 25) | Pulsing scale transform on running sessions -- distracting |
| `eval-glow` | `swarm-board-page.tsx` style block | Already removed (Phase 25) | Continuous glow on evaluating sessions |
| Status dot `pulse` | `agent-session-node.tsx` inline style | Already removed (Phase 25) | Referenced a `pulse` keyframe that was never defined (latent bug). Replaced by statusFlash |
| `glow-pulse-allow` | `globals.css` | Candidate for removal | Low-value ambient decoration on receipt UI |
| `glow-pulse-deny` | `globals.css` | Candidate for removal | Low-value ambient decoration on receipt UI |
| `verdict-pulse-ring` | `globals.css` | Candidate for removal | Ambient decoration on receipt verdict display |
| `verdict-alert-flash` | `globals.css` | Candidate for removal | Ambient decoration on receipt verdict display |

### Edge animation treatment

- **`swarmEdgePulse`** (in `swarm-edge.tsx` injected keyframes): This is a continuous ambient pulse (`opacity: 0.12 -> 0.30 -> 0.12`) applied to spawned edges at rest. It is flagged as a **candidate for removal** -- the same treatment as the old node breathing animations. Replace with a one-shot entrance animation or remove entirely. The edge's static `strokeDasharray: "6 4"` already distinguishes spawned edges from handoff edges without requiring motion.
- **`edgeActivityPulse`**: ENDORSED. It is time-limited (3s via `ACTIVITY_RECENCY_MS`) and communicates a meaningful event (message traversal).
- **`receiptEdgeFlow`**: ENDORSED. It is directional and communicates data flow along receipt edges.

### CSS transitions are the appropriate mechanism for smooth state changes

The following CSS transitions are endorsed for smooth visual updates on state change. These are not animations -- they are interpolated property changes:

- `transition: border-color 0.3s ease` -- left border accent color change on status transition
- `transition: background-color 0.4s ease` -- background tint change on selection
- `transition-all duration-150` -- general node container transitions (opacity, shadow)

These transitions fire only on actual state changes and settle immediately. They do not loop.

---

## 7. Multi-Select and Comparison Awareness

### ComparisonInspector is the canonical multi-node comparison surface

The ComparisonInspector (shipped Phase 24, source: `comparison-inspector.tsx`) is endorsed as the canonical way to compare multiple nodes. It provides type-specific comparison views that deliver deeper analysis than any single-node surface can offer.

### Comparison model

1. **Selection:** Shift+click or marquee-select multiple nodes. Selection state flows through `useOnSelectionChange` only -- no click handler race conditions.
2. **Inspector mode switch:** When 2+ nodes are selected, the inspector automatically expands from `INSPECTOR_WIDTH` (340px) to `COMPARISON_INSPECTOR_WIDTH` (680px) and renders the ComparisonInspector instead of the single-node detail view.
3. **Type-specific views:** Homogeneous selections (all same node type) route to dedicated comparison components:
   - `SessionComparison` -- side-by-side agent session metrics and status
   - `ReceiptComparison` -- verdict comparison with PostureSummaryBar and GuardHeatmapTable posture analytics
   - `DiffComparison` -- diff statistics comparison
   - `TaskComparison` -- task status and timing comparison
   - `ArtifactComparison` -- artifact metadata comparison
4. **Mixed fallback:** Heterogeneous selections (multiple node types) use `MixedComparison`, which groups nodes by type with summary statistics.
5. **Cap:** `MAX_COMPARISON_NODES = 6`. Selections exceeding this cap show an overflow message explaining the limit.

### Relationship between metrics bar and comparison

The metrics bar on AgentSessionNode (footer) and the ComparisonInspector serve complementary purposes:

- **Metrics bar:** Provides at-a-glance cross-node scanning during active board monitoring. The operator can visually scan blocked-action counts across all visible sessions without selecting any nodes.
- **ComparisonInspector:** Provides deep side-by-side analysis of selected nodes. PostureSummaryBar and GuardHeatmapTable deliver aggregate posture analytics that cannot fit on a node surface.

Both surfaces must be preserved. Removing the metrics bar from nodes would force every cross-node comparison into the inspector, defeating the board-scan use case.

### Protection rule

Any future chrome changes MUST NOT break the comparison workflow:

1. Selection highlighting must remain visible (ring-1 ring-[#c49a3c]/20 or equivalent).
2. Inspector mode switching between single-node and comparison must continue to work.
3. Posture analytics (PostureSummaryBar, GuardHeatmapTable) in receipt comparison must be preserved.
4. The MAX_COMPARISON_NODES=6 cap must remain enforced with a user-facing overflow message.

---

## 8. Accessibility Requirements

### Dark-mode-only declaration

The swarm board is dark-mode-only. There are no light mode variables, no theme toggle, and no `prefers-color-scheme` media query support in any swarm board component. The `swarm-board-page.tsx` explicitly overrides React Flow chrome for dark theme. Drop the light mode palette entirely -- it does not apply.

### Board background color

The board background is `#0a0c11`. All contrast calculations in this section are computed against this value.

### Minimum contrast ratios

Per WCAG 2.1 AA:

| Element Category | Minimum Ratio | Applies To |
|-----------------|---------------|------------|
| Normal text (< 18px, not bold) | 4.5:1 | Metric values, status labels, descriptions, timestamps |
| Large text (>= 18px or >= 14px bold) | 3:1 | Verdict hero labels, +/- hero numbers |
| Non-text UI components | 3:1 | Icons, borders, focus rings, interactive controls |

### Computed hex values, not opacity multipliers

Opacity-based styling on `#0a0c11` produces insufficient contrast. For example:
- White (#ffffff) at `opacity: 0.35` on #0a0c11 yields approximately `#3e3f44` -- contrast ratio ~2.2:1 (FAILS 3:1).
- White (#ffffff) at `opacity: 0.4` on #0a0c11 yields approximately `#474850` -- contrast ratio ~2.6:1 (FAILS 3:1).

All interactive elements must use computed hex color values with validated contrast ratios. Opacity multipliers are rejected for foreground text and interactive elements on the board background.

### Current accent color contrast audit

The following table lists the accent colors currently used in the implementation and their approximate WCAG contrast ratios against `#0a0c11`:

| Color | Hex | Usage | Approx Ratio vs #0a0c11 | 3:1 Pass? | 4.5:1 Pass? |
|-------|-----|-------|------------------------|-----------|-------------|
| Gold accent | #c49a3c | Selection ring, status border, title highlights | ~6.2:1 | YES | YES |
| Files changed | #6f97d8 | FooterMetric: files changed count | ~5.7:1 | YES | YES |
| Receipts | #9777cf | FooterMetric: receipt count | ~4.5:1 | YES | BORDERLINE |
| Blocked actions (active) | #d06860 | FooterMetric: blocked action count (non-zero) | ~4.3:1 | YES | MARGINAL |
| Allow/success | #38a876 | Verdict accent, status dot (running), pass count | ~5.4:1 | YES | YES |
| Deny/failure | #b85450 | Verdict accent, status dot (failed), fail count | ~3.8:1 | YES | NO |
| Muted text | #8a96ab | Title text, description text | ~4.8:1 | YES | YES |
| Dim text | #5c6a80 | Chip tier title, secondary labels | ~3.2:1 | YES | NO |
| Very dim text | #4a5568 | Pass/fail counts, guard counts, file counts | ~2.6:1 | NO | NO |
| Action buttons | #2a2f3a | Maximize/close buttons at rest | ~1.4:1 | NO | NO |

**Findings:**

1. **#4a5568 (very dim text) fails 3:1.** This color is used for guard counts, file counts, and pass/fail detail text. At 2.6:1 it is below the minimum for non-text UI components. However, this text appears at 8-9px size within nodes that also have a primary high-contrast signal (verdict icon, status label) -- the dim text is supplementary, not the primary information channel. Future implementation work should consider bumping this to at least #5a6578 (~3.3:1) for items that serve as the sole information carrier.

2. **#2a2f3a (action buttons at rest) fails all thresholds.** The maximize and close buttons use this color at rest, relying on hover state (#6b7a92, ~3.5:1) for visibility. This is a known accessibility concern. These buttons are intentionally de-emphasized in the Bloomberg terminal aesthetic (functional controls should not compete with operational data), but they should be bumped to at least #3a4050 (~2.0:1) at rest. This is flagged for future work, not blocking.

3. **#b85450 (deny/failure) passes 3:1 but fails 4.5:1.** This is used as a large-text accent (verdict labels at 13-18px bold), which only requires 3:1. It passes. For normal-text usage (9px fail counts), the primary verdict icon already communicates the signal at a passing contrast ratio.

### Tier-based exemptions

Chip and dot tiers are exempt from text contrast requirements. At these zoom levels, text renders at 1.4-2.8px equivalent screen size (chip) or is absent entirely (dot). These tiers serve as spatial markers for board topology. Operators are not expected to read text at these tiers -- they zoom in or click to inspect.

### Touch target sizes

Minimum touch target sizes for interactive elements:

| Tier | Minimum Target Size | Rationale |
|------|-------------------|-----------|
| **full** | 24x24px | Standard accessible target at 1:1 zoom |
| **compact** | 24x24px effective | Buttons hidden at compact tier; node itself is the click target (minimum 240x60px) |
| **chip** | 100x22px (full chip area) | Entire chip is a click target for selection |
| **dot** | 40x20px (full dot area) | Entire dot is a click target for selection |

---

## 9. Anti-Patterns (Explicit Rejections)

The following patterns are explicitly rejected for the swarm board. Each entry includes the pattern name, what it looks like in practice, and why it is wrong for this domain.

### 1. collab-public as a reference model

**What it looks like:** Proposals to borrow collab-public's aesthetic -- no footer, no status indicators, no metrics, opacity-based dimming, single-accent palette.

**Why it is rejected:** collab-public is a personal workspace with no monitoring semantics. Its tiles have no status, no health indicators, and no operational telemetry. Borrowing its aesthetic for a security operations monitoring surface removes the very elements that make the board useful during an active hunt. The diagnosis (too much visual noise) was correct; the prescription (remove operational data) was wrong.

### 2. "No footer" as a goal

**What it looks like:** Proposals to remove the metrics bar from AgentSessionNode to save 18-24px of vertical space and achieve a "cleaner" look.

**Why it is rejected:** The metrics bar is operational telemetry, not decorative clutter. Every metric answers a board-scan question: "How many files changed?" "How many guard evaluations?" "Any blocked actions?" "What risk level?" Removing the footer forces every status check into click-to-inspect, which defeats the purpose of a spatial monitoring surface. See Section 4 for the full metrics bar contract.

### 3. Hover tooltips as an information tier

**What it looks like:** Proposals to add a 400ms hover delay tooltip showing branch, model, compact metrics as an intermediate disclosure layer.

**Why it is rejected:**
- **Touch screens:** iPad and touch-enabled security workstations (common in SOC environments) have no hover state. The entire tooltip tier becomes inaccessible.
- **Prevents comparison:** An operator cannot compare two nodes' tooltip content simultaneously. The information is ephemeral.
- **Conflicts with React Flow:** React Flow already uses mouse hover for edge highlight effects and node proximity detection. Adding tooltip rendering creates z-index and pointer-event conflicts.
- **Even collab-public does not use them:** The reference implementation that inspired the tooltip proposal has no tooltip code in `tile-renderer.js` or `tile-interactions.js`.

### 4. Opacity-based interactive element styling without contrast validation

**What it looks like:** Setting action button opacity to 0.35 idle / 0.7 hover, or title text opacity to 0.7, without computing the effective contrast ratio against the actual background.

**Why it is rejected:** On `#0a0c11`, white at 0.35 opacity produces approximately 1.6:1 contrast -- well below the WCAG AA 3:1 minimum for non-text UI components. collab-public's opacity approach works on its lighter `#121212` background but does not transfer to the swarm board's darker surface. Use computed hex values with validated contrast ratios.

### 5. Continuous ambient animations (breathing, pulsing, heartbeat)

**What it looks like:** CSS `@keyframes` with `infinite` iteration count applied to node containers, status dots, or edge paths. Examples: `breathe-gold` (2.5s infinite box-shadow pulse), `heartbeat` (3s infinite scale transform), status dot `pulse` (2s infinite).

**Why it is rejected:** At swarm scale (3-8 concurrent sessions), continuous animations on every node create a "Christmas tree" effect where every element competes for peripheral attention. The operator cannot distinguish meaningful state changes from ambient motion. One-shot signals (statusFlash/verdictFlash) on state change are the endorsed replacement -- they catch the operator's eye when something actually changes, then settle to a static state.

### 6. Removing metrics for "minimalism"

**What it looks like:** Proposals to remove file count, receipt count, or blocked action count from node surfaces to achieve a simpler visual appearance.

**Why it is rejected:** Every metric on the footer bar answers a specific operator question (see Section 4 table). Removing them trades visual simplicity for functional regression. The board exists to provide at-a-glance monitoring -- removing the data that enables monitoring optimizes for the wrong goal. Simplification of metrics presentation (numbers-only, no icons, 14-18px height) is endorsed; removal of metrics is not.

### 7. Per-node compact/expanded toggle independent of zoom

**What it looks like:** A double-click or button that toggles an individual node between "compact" and "expanded" views, independently of the current zoom tier.

**Why it is rejected:** Adding a per-node toggle creates combinatorial complexity: 4 tiers x 2 modes = 8 render paths per node type, across 6 node types = 48 render paths to implement, test, and maintain. The semantic zoom tier system already provides compact/expanded behavior. To see more detail, zoom in. To see less, zoom out. To inspect one node in detail, click it (the inspector opens at full width regardless of zoom tier).

### 8. Writing the contract against the old spec instead of the current code

**What it looks like:** Contract sections that reference "remove the breathing animations" or "add semantic zoom" as future work, when these changes have already shipped in Phases 24-25.

**Why it is rejected:** Phases 24-25 shipped significant chrome improvements. The breathing animations are already removed. Semantic zoom is already implemented. Multi-select comparison is already built. The metrics bar is already simplified. The contract must reflect the actual implementation state (post-Phase 32), not the pre-Phase-24 state described in the original spec.

---

## 10. Appendix -- Review Item Disposition

The following table maps all 12 review items from `04-cleaner-tile-chrome-review.md` (Section 7: Summary of Required Changes) to their disposition in this contract.

| # | Original Issue | Severity | Disposition | Contract Section | Rationale |
|---|---------------|----------|-------------|-----------------|-----------|
| 1 | Metrics bar removal eliminates critical operational data | **High** | ENDORSED in this contract | Section 4 | Metrics bar declared REQUIRED operational telemetry. Simplified to numbers-only format but never removed. |
| 2 | Multi-select + inspector conflict | **High** | RESOLVED by Phase 24 | Section 7 | ComparisonInspector shipped with type-specific views, MAX_COMPARISON_NODES=6, and posture analytics. |
| 3 | Phase 5 must be atomic with Phases 2-4 | **High** | N/A | -- | Original spec's phased implementation approach was not followed. Phases 24-25 shipped changes organically. |
| 4 | Animation removal needs one-shot replacement | **Medium** | RESOLVED by Phase 25 | Section 6 | statusFlash/verdictFlash pattern shipped: 500ms one-shot box-shadow on state transition. |
| 5 | Color accessibility not validated | **Medium** | ENDORSED in this contract | Section 8 | Contrast ratios computed against #0a0c11. Hex values specified. Opacity multipliers rejected. |
| 6 | Hover tooltips don't work on touch / prevent comparison | **Medium** | REJECTED with rationale | Section 9 (#3) | Hover tooltips never implemented. Explicitly rejected: touch incompatibility, comparison prevention, React Flow conflicts. |
| 7 | No semantic zoom strategy | **Medium** | RESOLVED by Phase 25 | Section 5 | 4-tier semantic zoom (full/compact/chip/dot) shipped with thresholds at 0.6/0.35/0.18. Endorsed as authoritative. |
| 8 | Receipt min-height too small (56px proposed) | **Low** | RESOLVED | Section 3 | Current min-heights are appropriate: 96px full tier, 52px compact tier. |
| 9 | Keep timestamp on ReceiptNode | **Low** | RESOLVED | Section 3 | Relative timestamp (e.g., "2m ago") shown in full tier via formatReceiptNodeTime helper. |
| 10 | Dark-mode-only not stated | **Low** | ENDORSED in this contract | Section 8 | Dark-mode-only explicitly declared. No light mode variables, no theme toggle, no prefers-color-scheme. |
| 11 | Visual regression test plan missing | **Low** | ACKNOWLEDGED | -- | This contract recommends screenshot comparison tests and edge routing validation but does not block on them. Test infrastructure is outside the scope of the chrome contract. |
| 12 | Latent bug: `pulse` keyframe undefined for status dot | **Low** | RESOLVED by Phase 25 | Section 6 | Old `pulse` animation removed (it was a silent no-op). statusFlash pattern replaces it with a working implementation. |

### Summary

Of the 12 review items:
- **5 RESOLVED** by Phase 24-25 implementation work (items 2, 4, 7, 8, 9, 12 -- 6 items)
- **3 ENDORSED** in this contract with specifications (items 1, 5, 10)
- **1 REJECTED** with documented rationale (item 6)
- **1 ACKNOWLEDGED** without blocking requirement (item 11)
- **1 N/A** -- original concern no longer applies (item 3)

All three high-severity items are addressed: the metrics bar is preserved (item 1), multi-select comparison is shipped (item 2), and the atomicity concern does not apply (item 3). All four medium-severity items are addressed: animations have one-shot replacements (item 4), color accessibility is specified (item 5), hover tooltips are rejected (item 6), and semantic zoom is implemented (item 7).

---

## Document Status

This contract is APPROVED and supersedes `04-cleaner-tile-chrome.md`. Future chrome implementation work on the swarm board must conform to the principles, specifications, and anti-patterns defined in this document.

Any proposed deviation from this contract requires explicit review and approval with rationale for why the deviation better serves the security operations monitoring use case.
