# Sidebar Interaction Spec

> **Status:** Proposed | **Date:** 2026-03-08
> **Audience:** Desktop product, interaction, and implementation workers
> **Scope:** Define the closed-state, wake-up behavior, motion grammar, confidence gates, and
> prediction model for a sidebar that feels "before I thought of it"

## Why This Spec Exists

The current sidebar is more capable than it was, but it still exposes too much drawer machinery:

- the closed state still reads as a sidebar implementation detail instead of an intent surface
- the visible lens sliver announces navigation structure, not the next likely action
- the first reveal is still "there is a drawer here" instead of "here is what you probably want"

This spec replaces the standing collapsed rail with a dock-anchored anticipation model.

## North Star

The sidebar should feel like:

> it appears from the relevant dock icon or context seam only when the operator is moving toward a
> likely next step, and when it appears it is already focused on the right action, section, and
> semantic target

The sidebar should not feel like:

- a permanently half-visible drawer
- a lens navigator that expects the operator to translate intent into UI structure
- an AI system that twitches or takes action without commitment

## Product Rules

1. Closed means visually closed.
   No standing `SCOPES` sliver, no persistent rail fragment, no exposed lens label.
2. The first reveal is action-first, not lens-first.
   Show `Attach to Hunt 26`, not `Entities`.
3. The wake-up point is dock-anchored, not edge-anchored.
   The drawer should feel like it grows from the relevant dock icon or local surface.
4. Confidence controls aggression.
   Low confidence hints. Medium confidence peeks. High confidence commits to a spring-open.
5. Predictions explain themselves.
   Every promoted action, section, or open mode carries a visible reason string.
6. Anticipation never commits destructive work automatically.

## State Model

The sidebar interaction model is a six-state machine:

### 1. Idle

The sidebar is fully closed.

- No visible collapsed rail slice.
- Only the permanent dock is visible.
- Relevant dock icons may carry a faint warmth if confidence is medium or higher.
- No explanatory copy is visible yet.

### 2. Pre-Wake

The system has enough signal to prepare a reveal, but not enough to show a full peek yet.

- A relevant dock icon sharpens or glows softly.
- A 2-4px seam may appear between the dock and canvas, but only while intent is live.
- The seam is not labeled with a lens name.
- No full drawer layout is shown.

### 3. Ghost Peek

The sidebar surfaces one predicted action in a compact whisper state.

- Width: `32-64px` visual reveal beyond the dock boundary.
- Origin: morph from the most relevant dock icon or local sidebar seam.
- Content:
  - one short verb-led prediction
  - one concise reason line
  - optional single secondary affordance
- Example copy:
  - `Attach to Hunt 26`
  - `Mount to active run`
  - `Cite in current note`
  - `Compare with open receipt`

### 4. Commit Open

The system has enough confidence, dwell, or drag commitment to open the full drawer.

- The panel expands to the normal sidebar width.
- The predicted lens is already active.
- The promoted section is already visible and expanded.
- Semantic drop zones are visible if the user is dragging.
- The rest of the drawer appears after the promoted section, not before it.

### 5. Engaged Drawer

The user has committed into the drawer.

- Manual control dominates.
- The sidebar remains open until the user collapses it or leaves it idle under retract rules.
- Promoted sections retain explanation text while the relevant context remains active.
- Section ordering may still adapt, but only gently.

### 6. Retract

The system backs out without leaving the layout mangled.

- Ghost peek retracts first.
- Promoted section chrome fades before the panel fully closes.
- Dock icon warmth lingers briefly if the same intent is still plausible.
- If the user never committed, the sidebar returns all the way to Idle.

## Trigger Grammar

### Trigger Sources

The sidebar may wake from any of these sources:

- cursor approach toward the dock corridor
- hover on a draggable or promotable object
- drag start
- dwell over a dock icon
- dwell over a compatible drop target
- recent pivot chain plus current shell/lens context
- active hunt, run, case, or note context

### Dock Corridor

Use a proximity corridor rather than direct edge hover alone.

- Corridor width from dock edge: `48px`
- Stronger weighting when cursor trajectory points toward the dock
- Disabled when the operator is moving rapidly across the canvas with no recent relevant object

### Timing

- Pre-wake activation: `80-110ms`
- Ghost peek reveal: `110-140ms`
- Lens spring-load on dwell: `280-320ms`
- Ghost peek retract: `160-200ms`
- Full drawer retract after non-commit: `220-280ms`

These timings should remain asymmetric:

- opening should feel gentle and predictive
- closing should feel responsive but not snap shut

## Confidence Tiers

### Low Confidence

- Warm one dock icon or one compatible surface
- Optional faint seam only
- No ghost peek
- No auto-open

### Medium Confidence

- Warm the relevant dock icon
- Show ghost peek with one predicted action and reason
- Optionally pre-expand one section if the drawer is already open
- Do not spring-switch the lens yet

### High Confidence

- Show ghost peek immediately on dwell or drag
- Spring-open the drawer after dwell or drag commitment
- Preselect the likely lens
- Pre-expand the likely section
- Surface semantic drop targets inline

## Visual Grammar

### Closed State

Closed state should render:

- the permanent dock
- optional dock-icon emphasis
- optional 2-4px seam during live anticipation only

Closed state should not render:

- vertical lens text
- a persistent collapsed drawer slice
- static rail chrome
- a visible resize affordance

### Ghost Peek Layout

Ghost peek is the bridge between no drawer and full drawer.

- Shape: soft blade or glass whisper emerging from the relevant dock icon lane
- Width: `32-64px`
- Height: enough for one action and one reason
- Position: aligned to the triggering dock icon or promoted lane
- Copy hierarchy:
  - line 1: action
  - line 2: reason

Example:

```text
Attach to Hunt 26
current hunt is active
```

### Full Drawer Layout

When the drawer opens from anticipation:

- top slot is the promoted action or promoted section
- the promoted section appears before generic lens navigation content
- explanation text sits beside or directly under the promoted control
- semantic targets are centered and easiest to hit

## Motion Grammar

The sidebar should use staged motion, but the stages should serve intent instead of calling
attention to themselves.

### Idle -> Pre-Wake

- dock icon sharpen: opacity and glow only
- optional seam fade in
- no width animation yet

### Pre-Wake -> Ghost Peek

- ghost peek grows from dock icon lane or seam
- content fades in after shape, not before
- no full drawer border yet

### Ghost Peek -> Commit Open

- drawer width expands from the ghost peek anchor
- promoted section fades in first
- general section list follows slightly after
- semantic targets animate in only if relevant

### Commit Open -> Retract

- promoted section and semantic targets exit first
- body content exits next
- drawer width collapses last
- dock warmth may remain for one beat if confidence stays live

### Motion Constraints

- no bounce
- no large overshoot
- no full-width snap
- no label movement without corresponding surface movement
- no animation that exposes structural lens names before predicted actions

## Action-First Copy Rules

The sidebar should speak in verbs and destinations while closed or partially open.

Preferred:

- `Attach to Hunt 26`
- `Mount to active run`
- `Cite in current note`
- `Open related receipts`
- `Compare with open receipt`

Avoid in pre-open states:

- `Scopes`
- `Files`
- `Notes`
- `History`

Lens labels are appropriate only after the drawer is fully open.

## Prediction Matrix

### Entity

- Primary dock anchor: `Entities`
- Likely default actions:
  - `Attach to active hunt`
  - `Use as run input`
  - `Watch in current hunt`
- Likely promoted section:
  - `Current Hunt`
  - `Suggested Targets`

### File

- Primary dock anchor: `Files` or `Sandboxes`
- Likely default actions:
  - `Mount to active run`
  - `Attach as evidence`
  - `Preview beside current tab`
- Likely promoted section:
  - `Inputs`
  - `Sandbox Mounts`

### Receipt

- Primary dock anchor: `Notes` or `History`
- Likely default actions:
  - `Cite in current note`
  - `Compare with open receipt`
  - `Attach as evidence`
- Likely promoted section:
  - `Citations`
  - `Recent Receipts`

### Signal Thread

- Primary dock anchor: `Scopes`
- Likely default actions:
  - `Promote to hunt`
  - `Open related entities`
  - `Add to watchlist`
- Likely promoted section:
  - `Suggested Targets`
  - `Watchlists`

### Note

- Primary dock anchor: `Notes`
- Likely default actions:
  - `Link to case`
  - `Open related files`
  - `Pin beside current surface`
- Likely promoted section:
  - `Related Notes`
  - `Case Link`

## Explainability

Every anticipatory reveal needs one visible reason string close to the changed affordance.

Reason templates:

- `current hunt is active`
- `same run context`
- `you opened a note from this case`
- `matches recent pivot chain`
- `similar receipt type`

Do not bury the explanation in a detached overlay if the changed surface is local.

## Anti-Goals

The sidebar should not:

- remain visibly half-open while idle
- expose lens structure before action intent
- open from generic edge hover with no contextual signal
- reorder large regions so aggressively that the user loses their place
- trigger full drawer animation for low-confidence guesses

## Implementation Contract

The next implementation slice should introduce these explicit concepts:

1. `useSidebarWakeController()`
   Produces `idle | prewake | ghost-peek | committed | retracting` plus anchor lane and timing.
2. `SidebarWakeAnchor`
   Resolves which dock icon or seam the peek should grow from.
3. `SidebarGhostPeek`
   Renders action-first whisper UI and reason text.
4. `SidebarDirectorState.wake`
   Extends director output with:
   - `wakeState`
   - `anchorLens`
   - `predictedActionLabel`
   - `predictedReason`
   - `peekWidth`
   - `shouldCommitOpen`
5. `LensSidebar`
   Stops rendering a persistent collapsed slice and instead renders:
   - no closed chrome by default
   - transient seam only during live anticipation
   - ghost peek before full drawer

## Delivery Order

1. Remove the standing collapsed sliver.
2. Add dock-icon warming and seam-only pre-wake.
3. Add ghost peek with action-first copy and reason strings.
4. Promote one section-first open path for `Entities`, `Files`, and `Notes`.
5. Tune timings and retract rules by live dogfooding.

## Acceptance Criteria

The spec is satisfied when all of these are true:

- The sidebar is visually absent while idle.
- The first anticipatory reveal is a dock-anchored action hint, not a lens label.
- Dragging an object makes the likely destination obvious before drop.
- High-confidence flows open directly into the right lens and promoted section.
- The user can always tell why the sidebar promoted that action.
- If the user ignores the anticipation, the layout returns to idle cleanly.
