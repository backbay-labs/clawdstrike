# Phase 34: Panel Empty States - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Replace the bare text empty states in three panels with structured placeholder content that hints at what the panel shows when populated. The Replay panel (already has good UI density) is not in scope.

</domain>

<decisions>
## Implementation Decisions

### Explainability Empty State (EMP-01)
- Current: "Select a station to inspect" (bare text)
- New: Show section headers (STATION, PRESSURE LANES, ANOMALIES) with muted placeholder text/icons under each
- Include hint text: "Click a station or press E while hovering"
- Use --hud-text-muted for placeholder content, --hud-text for section headers

### Mission Empty State (EMP-02)
- Current: "No active mission" (bare text)
- New: Show section outline (BRIEFING, OBJECTIVES, NARRATIVE) with muted labels
- Include hint: "Start a mission from the command palette"
- Show a subtle mission icon or indicator

### Ghost Memory Empty State (EMP-03)
- Current: "GHOST MEMORY / 0 traces / No prior findings or receipts" (minimal)
- New: Keep the "0 traces" header but add a muted explanation paragraph explaining what ghost memory records (prior hunt findings, receipt verdicts, case-note traces) and when traces appear (after probing stations, completing missions)
- Make it informative, not just empty

### Claude's Discretion
- Exact placeholder text for each section
- Whether to use muted SVG icons or just text-based section headers
- Spacing and typography within empty states
- Whether section headers use borders/dividers between them

</decisions>

<code_context>
## Existing Code Insights

### Key Files
- `components/hud/panels/ExplainabilityDrawerPanel.tsx` — has empty state guard when `!selectedStationId`
- `components/hud/panels/MissionDrawerPanel.tsx` — has empty state guard when `!mission`
- `components/hud/panels/GhostMemoryDrawerPanel.tsx` — has empty state when `memories.length === 0`
- `observatory-hud.css` — CSS tokens for consistent styling

### Styling Patterns
- Panel content uses `color: var(--hud-text)` for primary, `var(--hud-text-muted)` for secondary
- Monospace typography throughout (font-family: monospace)
- Section headers typically uppercase, letter-spacing: 0.05em

</code_context>

<specifics>
## Specific Ideas

From dogfooding: "Explainability just says 'Select a station to inspect' — no visual structure, no sections, no hints about what clicking a station would show"

</specifics>

<deferred>
## Deferred Ideas

None

</deferred>
