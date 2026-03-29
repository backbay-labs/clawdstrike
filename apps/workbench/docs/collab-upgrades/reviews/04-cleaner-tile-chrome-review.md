# Review: 04 -- Cleaner Tile Chrome

**Reviewer:** Design Engineering
**Date:** 2026-03-25
**Verdict:** APPROVE WITH CHANGES

---

## 1. Factual Accuracy

The spec is largely accurate against the actual source. A few corrections and clarifications:

### Correct

- **AgentSessionNode** structure matches the code. The title bar (28px), terminal body, footer metrics bar (24px with `FooterMetric` components at line 278-296), status bar (18px at lines 299-319), heartbeat radial pulse overlay (lines 136-144), `statusAnimation` computed property (lines 105-113), and `statusOpacityClass` (lines 99-103) all exist exactly as described.
- **TerminalTaskNode** session ID display at lines 109-118, `line-clamp-2` on the task description at line 103, and the minWidth/minHeight of 220/80 all match.
- **ArtifactNode** file type text badge at lines 112-120 matches.
- **DiffNode** 22px hero numbers (line 59/71), "added"/"removed" labels (lines 64-66/75-77), file list (lines 82-105), and file count footer (lines 107-117) all match.
- **ReceiptNode** guard results list (lines 132-158), signature footer (lines 161-189), timestamp display (lines 121-128), verdict section with 18px label (line 109) all match.
- **Animation keyframes** in `swarm-board-page.tsx` (lines 552-580) match: `breathe-gold`, `breathe-amber`, `breathe-red`, `heartbeat`, `eval-glow`, `nodeEnter`. Line references are accurate.
- **Edge animations** in `swarm-edge.tsx` (lines 28-41): `swarmEdgePulse`, `edgeActivityPulse`, `receiptEdgeFlow` all confirmed.
- **globals.css** animations: `glow-pulse-allow`, `glow-pulse-deny`, `verdict-pulse-ring`, `verdict-alert-flash`, and all `hb-*` keyframes confirmed present.

### Minor Inaccuracies

- The spec says animations are defined at "lines 552-580" in swarm-board-page.tsx. The actual range is lines 552-580 for the `<style>` block, but the closing tag is at line 580. This is correct.
- The spec says the `swarmEdgePulse` keyframe is at "lines 27-31" in swarm-edge.tsx. The actual definition spans lines 28-31. Off by one, trivial.
- The spec describes `STATUS_PULSE` as having an `animation` property on the dot, but the actual code applies `animation: "pulse 2s ease-in-out infinite"` as an inline style (line 172). The `pulse` keyframe itself is NOT defined anywhere in the codebase I can find -- it would need to be a browser/Tailwind built-in or it silently fails. The spec does not flag this latent bug.
- The spec claims `DiffNode` has `rounded-none` and `AgentSessionNode` has `rounded-sm`. Confirmed: DiffNode line 25 uses `rounded-none`, AgentSessionNode line 119 uses `rounded-sm`. The comparison table in section 2.3 is accurate.

### collab-public Reference Accuracy

The spec's description of collab-public is accurate against the actual code:
- `tile-renderer.js` DOM structure matches the described three-layer sandwich.
- `shell.css` confirms: `border-radius: 8px`, `padding: 6px 8px`, `font-size: 11px`, `font-weight: 500`, `opacity: 0.7` on title text, `opacity: 0.4`/`0.8` on action buttons.
- Only two `@keyframes` in shell.css: `spin` (loading spinner) and `seek-highlight-flash` (brief edge-indicator flash). Zero ambient/decorative animations.
- Selection indicator is `border-color: #4a9eff` at line 1086. Focus indicator uses `box-shadow` with `0 0 0 1px` rings (lines 793-803). All confirmed.

---

## 2. Design Critique

### The Reference Model is Wrong for This Domain

The spec's core thesis -- "learn from collab-public's minimal tile chrome" -- is a category error that needs to be addressed head-on.

**collab-public is a personal workspace.** Its tiles contain terminals, code editors, notes, and browser views. The user interacts with one tile at a time. There is no concept of "status" because the content is passive -- a file does not have a health indicator. The minimal aesthetic works because there is nothing to monitor.

**The swarm board is a monitoring surface.** It displays 3-8 concurrent autonomous agent sessions that are actively making changes, hitting guard rails, and producing receipts in real time. The user's primary task is not "focus on one thing and interact with it" but "scan the entire board to detect anomalies." This is closer to an air traffic control display or a SOC analyst's SIEM dashboard than it is to a personal note-taking canvas.

The Bloomberg terminal aesthetic in the current node headers was not accidental. The spec itself acknowledges this in passing ("the 'Bloomberg terminal' density aesthetic documented in the node file headers"). The spec then dismisses it by saying "it was appropriate when the board was a single-agent monitoring view." But the opposite is true: information density on individual nodes becomes MORE important as the number of simultaneous agents increases, because the user has less time to drill into any single node.

That said, the spec is right that the *animation* noise is excessive. The breathing box-shadows, heartbeat pulses, and radial gradients genuinely do create a Christmas-tree effect. The diagnosis is correct; the treatment is too aggressive.

### Multi-Select Blindspot

The `SWARM_BOARD_STATUS.md` confirms that Shift+multi-select exists. The inspector only shows detail for `selectedNode` (singular -- see `swarm-board-inspector.tsx` line 60-61). If the spec removes metrics from nodes and pushes them to the inspector, a user who selects 3 agent sessions to compare their blocked-action counts has no way to see all three simultaneously. They would need to click back and forth, which is worse than the current state where the footer metrics are always visible on every node.

**This is a blocking issue.** Either:
1. The inspector needs to support multi-node comparison (side-by-side or stacked detail panels), or
2. The metrics that support cross-node comparison (file count, receipt count, blocked actions, risk level) must stay on the node surface.

### At-a-Glance Status During Active Hunts

Consider the primary user scenario: an operator running a 6-agent hunt against a detected intrusion. They are watching the board while simultaneously communicating with their team. They need to answer questions like:

- "Which sessions have blocked actions?" -- Currently answered by the red `IconShieldOff` count in the footer. Under the proposed design: not visible without hovering or clicking each node.
- "What's the risk level of session 3?" -- Currently answered by the risk label in the footer. Under the proposed design: not visible without clicking to inspect.
- "Is any session in strict policy mode with bypass?" -- Currently answered by the status bar text. Under the proposed design: not visible without clicking to inspect.

The spec claims the left rail can partially compensate, but the left rail only shows session name + status dot + branch (see `swarm-board-left-rail.tsx` lines 113-146). It does not show metrics, risk, or policy mode.

---

## 3. Progressive Disclosure Tension

### The Hover Layer is Problematic

The spec proposes a four-tier hierarchy: glance, hover, click, inspect. The hover tier (Phase 6) has serious issues:

**Touch screens.** The spec proposes a 400ms hover delay tooltip. iPad and touch-enabled security workstations (common in SOC environments) have no hover state. This entire tier of information becomes inaccessible.

**Ephemerality prevents comparison.** If an operator wants to compare the branch and model of two agent sessions, they must hover over one, remember the info, then hover over the other. There is no way to pin a tooltip or see two nodes' hover info simultaneously.

**Hover conflicts with React Flow interactions.** React Flow already uses mouse hover for edge highlight effects and node proximity detection. Adding a 400ms tooltip that renders via `EdgeLabelRenderer` at node coordinates creates potential z-index and pointer-event conflicts, especially near edges or overlapping nodes.

### A Better Alternative: Compact/Expanded Node Modes

Instead of the hover layer, consider a persistent toggle:

- **Compact mode** (the spec's proposed "glance" state): status dot, label, title, terminal content. No footer metrics or status bar.
- **Expanded mode** (closer to current): includes the footer metrics bar and a condensed status line.

This could be controlled globally ("compact all" / "expand all" toggle in the toolbar) or per-node (double-click to toggle). This preserves comparison capability (expand two nodes side by side), works on touch screens, and avoids the ephemeral hover problem.

The collab-public reference itself does not use hover tooltips for any tile information (confirmed: no tooltip code in `tile-renderer.js` or `tile-interactions.js`). The spec is proposing a mechanism that even the reference implementation did not need.

---

## 4. Information Architecture -- Node-by-Node Assessment

### AgentSessionNode

**Removing the metrics bar is a mistake.**

The footer metrics bar (files changed, receipts, blocked actions, tool boundary events) is 24px of critical operational data. For a security operations tool, these numbers are the equivalent of vital signs on a patient monitor. Removing them forces every status check into a click-to-inspect flow.

**Recommendation:** Keep the metrics bar but simplify it. Remove the icon labels, keep just the colored numbers. Reduce the bar height from 24px to 18px. This saves 6px while preserving at-a-glance monitoring value.

**Removing the status bar is defensible.** The worktree path and bypass state are genuinely secondary. They belong in the inspector. That saves 18px.

**Removing all animations is correct.** The `breathe-*` and `heartbeat` animations should go. The spec is right that the static status dot color, combined with the left border accent, is sufficient. However, see section 5 on the replacement signal for "running."

**Net change from my recommendation:** Remove status bar (save 18px), keep simplified metrics bar (save 6px), remove animations. Net vertical savings: 24px instead of the spec's 42px. Still a meaningful improvement.

### ReceiptNode

**The verdict IS the node -- the spec gets this right.**

The guard results list is inspector-appropriate detail. The signature hash footer is never useful at a glance. Moving these to the inspector is correct.

**However:** Reducing from 160px min-height to 56px creates a very small node that may be hard to click/select on the board, especially at reduced zoom levels. A min-height of 72px would be safer (still compact but large enough to be a reliable click target at 50% zoom).

**Keep the timestamp on the node.** Receipts are temporal artifacts -- "when did this guard evaluation happen?" is a board-scan question, not an inspector question. An operator scanning for "which receipts arrived in the last 30 seconds" needs timestamps visible. A compact format like "2m ago" would suffice.

### DiffNode

**Reducing hero numbers from 22px to 14px is fine.** The +/- numbers at 22px are oversized for a board card. 14px is still readable at zoom levels down to ~60%.

**Removing the file list is correct.** The inspector already has the `changed files` section.

**Removing the "added"/"removed" labels is correct.** The `+` and `-` signs are universally understood.

### TerminalTaskNode

**Removing the session ID is correct.** At 7px text colored `#1a1e28` (nearly invisible), it was already a dead element.

**Truncating description to 1 line is fine.** The inspector shows the full prompt.

### ArtifactNode

**Removing the file type badge is correct.** The icon color already conveys type. The badge is redundant.

### NoteNode

**No structural changes -- correct.** The note node is well-designed. Applying shared spacing tokens is appropriate.

---

## 5. Missing Considerations

### Color Accessibility

The spec proposes a "muted palette" with action button opacity of 0.35 idle / 0.7 hover. On the dark background (#0a0c11), let's check contrast ratios:

- Button at 0.35 opacity against #0a0c11: this produces an effective color with extremely low contrast. WCAG 2.1 AA requires 4.5:1 for normal text, 3:1 for large text. A 0.35 opacity white element on near-black is roughly 1.6:1 -- well below any accessibility threshold.
- The current buttons at `color: #2a2f3a` on `#07080c` background are already at approximately 1.4:1, which fails WCAG AA.
- collab-public's 0.4 opacity works because its dark mode background (#121212) is lighter and the foreground (#dcdcdc) at 0.4 opacity yields roughly #616161 on #121212, which is approximately 3.6:1 -- borderline.

**The spec needs to specify minimum contrast ratios for all interactive elements and provide actual computed color values, not just opacity multipliers.** Opacity-based styling produces different effective contrast depending on the background, and the swarm board's background (#0a0c11) is significantly darker than collab-public's (#121212).

### Dark Theme Exclusivity

The swarm board is dark-only. The `swarm-board-page.tsx` explicitly overrides React Flow chrome for dark theme (line 57 comment). No light mode variables, no theme toggle, no `prefers-color-scheme` media queries exist in the swarm board components. The spec's collab-public palette section lists both light and dark mode variables, which could mislead implementers into thinking a light mode exists.

**The spec should explicitly state that only dark mode values apply and drop the light mode palette from section 2.5.**

### Node Readability at Different Zoom Levels

React Flow supports zoom from 0.1x to 2x+. The spec proposes reducing min font sizes (e.g., title from 11px to 9px for status labels). At 50% zoom, an 9px font renders at 4.5px equivalent -- completely unreadable. At 75% zoom, 11px renders at 8.25px -- borderline.

**The spec should define minimum zoom thresholds for readability and consider whether nodes should show progressively less detail as zoom decreases** (e.g., below 60% zoom, only show status dot + title; below 40% zoom, show only a colored rectangle). This is a semantic zoom approach that the spec does not address.

### Animation Removal Needs a Replacement Signal

The spec removes the pulsing animation on the status dot and the breathing box-shadow for running sessions. The replacement is "static color only."

In the current design, the breathing animation serves as an **attention-free motion signal** -- peripheral vision detects motion even when the user is focused on another node. This is a well-documented UX pattern in monitoring interfaces. If a session transitions from idle to running, the breathing animation catches the operator's eye without requiring a direct look.

With static colors only, the operator must actively scan every node's status dot to detect state changes. This is a regression for monitoring usability.

**Recommendation:** Instead of continuous breathing animations, use a **one-shot transition animation** when status changes occur. For example:
- Status change: the left border does a brief 0.5s brightness pulse, then settles to the new static color.
- This provides the "something changed" peripheral signal without the continuous Christmas-tree effect.

The spec already proposes `transition: border-color 0.3s ease` and `transition: background-color 0.4s ease`, which partially addresses this, but a CSS transition only fires on actual state changes and is easy to miss at 300ms. Consider a slightly more prominent one-shot animation (e.g., a 0.8s `box-shadow` flash that fires once on status change via a CSS class toggle + `animationend` removal).

### Visual Regression Testing

The spec claims Phase 1 is "Zero risk -- purely visual, easily reversible." This is overconfident. CSS changes to nodes inside React Flow can cause:
- Node measurement invalidation (React Flow measures node dimensions for edge routing).
- Handle position shifts (if padding/border changes alter the node's bounding box).
- Edge path recalculation failures (if nodes become smaller than expected minimum sizes).

**The spec should require:**
1. Screenshot comparison tests for each node type at 3 zoom levels (50%, 100%, 150%).
2. Edge routing validation after node resizing (do edges still connect to handles?).
3. Manual QA pass on a board with 8+ nodes to verify no overlap or clipping regressions.

The test update section (section 8) only mentions assertion updates for removed DOM elements. It does not mention visual regression tests.

---

## 6. Implementation Risk

### Phase Ordering Creates a Temporary Degradation

The spec proposes shipping Phases 1-4 (remove content from nodes) before Phase 5 (inspector absorption). This means there will be a period where:
- Metrics, risk, policy, guard details, file lists, and signatures are gone from nodes.
- They are NOT yet in the inspector.
- The information is simply unavailable.

Even if Phases 1-4 and Phase 5 ship in the same PR (the spec suggests phases 1-4 as one PR and 5-6 as a follow-up), the follow-up PR creates a gap where the inspector has not yet absorbed the removed content.

**Recommendation:** Phase 5 (inspector absorption) must ship in the SAME PR as Phases 2-4. The removal and the absorption must be atomic from the user's perspective.

### The Hover Tooltip (Phase 6) is Speculative

Phase 6 creates a new component (`NodeHoverTooltip`), a new store field (`hoveredNodeId`), new event handlers (`onNodeMouseEnter`/`onNodeMouseLeave`), and uses `EdgeLabelRenderer` for positioning. This is a non-trivial new interaction layer built on assumptions about how operators will use the board.

**Recommendation:** Phase 6 should be preceded by user research or at minimum a prototype with actual SOC operators. Do not build a hover tooltip system based on the aesthetic preferences of a personal workspace tool (collab-public does not even have tooltips).

---

## 7. Summary of Required Changes

| # | Issue | Severity | Recommendation |
|---|---|---|---|
| 1 | Metrics bar removal eliminates critical operational data | **High** | Keep a simplified metrics bar (numbers only, no icons, 18px height) |
| 2 | Multi-select + inspector conflict | **High** | Either support multi-node inspector or keep comparison data on nodes |
| 3 | Phase 5 must be atomic with Phases 2-4 | **High** | Merge into single PR; no information gap |
| 4 | Animation removal needs one-shot transition replacement | **Medium** | Add a brief status-change flash animation (fires once, not continuous) |
| 5 | Color accessibility not validated | **Medium** | Specify computed color values meeting WCAG AA 3:1 for interactive elements |
| 6 | Hover tooltips don't work on touch / prevent comparison | **Medium** | Replace with compact/expanded toggle mode; deprioritize or cut Phase 6 |
| 7 | No semantic zoom strategy | **Medium** | Define what nodes show at <60% and <40% zoom |
| 8 | Receipt min-height too small | **Low** | Change from 56px to 72px |
| 9 | Keep timestamp on ReceiptNode | **Low** | Use relative format ("2m ago") instead of absolute |
| 10 | Dark-mode-only not stated | **Low** | Drop light mode palette from section 2.5 |
| 11 | Visual regression test plan missing | **Low** | Add screenshot comparison and edge routing validation requirements |
| 12 | Latent bug: `pulse` keyframe undefined for status dot | **Low** | Fix or document; currently a silent no-op |

---

## 8. Overall Verdict

**APPROVE WITH CHANGES.**

The diagnosis is sound: the swarm board has too many concurrent animations and too much decorative chrome. The animation cleanup (Phase 1) and the reduction of clearly secondary information (session IDs, signature hashes, file lists on DiffNode) are correct and should proceed.

But the treatment overshoots. This spec was written with a personal workspace (collab-public) as the north star, when the actual product is a security operations monitoring surface. The metrics bar on AgentSessionNode, the timestamp on ReceiptNode, and the ability to compare node data without clicking into an inspector are not "chrome" -- they are operational telemetry. Removing them trades visual simplicity for functional regression.

Resolve the three high-severity items (metrics bar retention, multi-select strategy, atomic phasing), address the medium-severity accessibility and interaction issues, and this spec is ready for implementation.
