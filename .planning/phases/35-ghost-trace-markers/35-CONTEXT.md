# Phase 35: Ghost Trace Markers - Context

**Gathered:** 2026-03-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Render translucent holographic 3D markers at stations where past findings occurred. Data comes from existing `deriveObservatoryGhostMemories()`. Markers respond to the GHOST analyst preset (full opacity when active, 20% when inactive).
</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
- Infrastructure phase wiring existing data to new 3D meshes. All visual choices at Claude's discretion.
- Ghost markers should use emissive materials with `toneMapped: false` for bloom compatibility
- Use instanced meshes if marker count could be high
- Finding type glyphs can be drei Text or simple geometric indicators (sphere=probe, cube=receipt, pyramid=case-note)
- Mount in ObservatoryWorldCanvas scene tree, gated by ghost memory data availability
</decisions>

<code_context>
## Existing Code Insights

- `deriveObservatoryGhostMemories()` in `observatory-ghost-memory.ts` — returns scored, deduped, capped traces
- `observatory-store.ts` — `analystPresetId` field tracks active preset
- `ObservatoryWorldCanvas.tsx` — scene composition root (mount point for new markers)
- `OBSERVATORY_STATION_POSITIONS` in `observatory-world-template.ts` — station world coordinates
- Existing pattern: `StationBeacon.tsx` (emissive sprite at station position, good reference for visibility-at-distance)
</code_context>

<specifics>No specific requirements</specifics>
<deferred>None</deferred>
