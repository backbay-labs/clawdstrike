# Phase 37: Analyst Preset Overlays - Context

**Gathered:** 2026-03-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Each analyst preset (THREAT/EVIDENCE/RECEIPTS/GHOST) transforms the world's visual mood when activated. THREAT adds red tint + danger particles, EVIDENCE shows gold halos, RECEIPTS shows verdict badges, GHOST dims world and reveals traces. Deactivating restores neutral in one frame.
</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
- THREAT: Red emissive wash on high-pressure districts + wawa-vfx or Sparkles motes
- EVIDENCE: Gold emissive halos reusing the affinity ring mesh pattern from v3.0 Phase 6
- RECEIPTS: Small floating verdict icons (ALLOW=green, DENY=red, AUDIT=amber) near stations
- GHOST: Reduce scene ambient light intensity by 40%, apply desaturation shader or material override, set ghost trace markers to full opacity
- All overlays mount as conditional children in ObservatoryWorldCanvas, gated by `analystPresetId` from store
- One-frame reset: overlays unmount immediately when preset deactivates (React conditional render)
</decisions>

<code_context>
## Existing Code Insights

- `observatory-store.ts` — `analystPresetId: ObservatoryAnalystPresetId | null`
- `ObservatoryAnalystPresetId = "threat" | "evidence" | "receipts" | "ghost"` in types.ts
- Phase 35 ghost trace markers — GHO-03 opacity gating will be driven by this phase's GHOST preset
- `AffinityRingMesh` pattern from v3.0 — emissive ring at station position (reference for EVIDENCE halos)
- `ObservatoryVFXPools.tsx` — existing particle pool system for THREAT danger motes
</code_context>

<specifics>No specific requirements</specifics>
<deferred>None</deferred>
