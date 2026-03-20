# Phase 27: Flight State Bridge + Autopilot Wiring - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase wires two missing cross-phase connections identified by the v6.0 milestone audit:
1. FlightState store bridge — SpaceFlightController.onStateChange prop must be passed through ObservatoryFlowRuntimeScene so store.flightState updates at 60fps
2. Autopilot ref bridge — SpaceFlightController must create an autopilotRef synced from store.autopilotTargetStationId and pass it to useFlightLoop

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure/wiring phase. The code patterns are dictated by existing architecture:
- ObservatoryFlowRuntimeSceneProps already has optional callback slots
- SpaceFlightController already accepts onStateChange prop
- useFlightLoop already accepts autopilotRef and onAutopilotCancel options

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `SpaceFlightController.tsx` (line 39): Already has `onStateChange?: (state: FlightState) => void` prop — just never receives it
- `useFlightLoop.ts` (line 98): Already has `autopilotRef?: React.RefObject<HuntStationId | null>` option — just never receives it
- `observatory-store.ts`: Has `setFlightState`, `resetFlightState`, `setAutopilotTarget`, `clearAutopilot` actions
- `ObservatoryFlowRuntimeScene.tsx`: Bridge component that destructures props and forwards to LazySpaceFlightController

### Established Patterns
- Store access: `useObservatoryStore.getState().actions.setFlightState(state)` for imperative calls
- Ref-based bridges: `flightInputEnabledRef` pattern already used in SpaceFlightController for docking
- Throttled store writes: useFlightLoop already throttles onStateChange to ~100ms intervals

### Integration Points
- `ObservatoryFlowRuntimeSceneProps` interface in `observatory-player-types.ts` — needs `onStateChange` callback
- `ObservatoryFlowRuntimeScene.tsx` — needs to forward `onStateChange` to `LazySpaceFlightController`
- `ObservatoryWorldCanvas.tsx` — needs to pass `onStateChange` when rendering `LazyObservatoryFlowRuntimeScene`
- `SpaceFlightController.tsx` — needs autopilotRef creation + store sync + pass to useFlightLoop

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase. The exact fix is prescribed by the milestone audit.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>
