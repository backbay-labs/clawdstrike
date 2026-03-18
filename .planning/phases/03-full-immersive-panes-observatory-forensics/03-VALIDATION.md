# Phase 03: Validation Map

**Phase:** 03-full-immersive-panes-observatory-forensics
**Source:** Extracted from 03-RESEARCH.md Validation Architecture section

## Requirement → Test Map

| Req ID | Behavior | Test Type | Automated Command | Test File |
|--------|----------|-----------|-------------------|-----------|
| OBS-03 | `ObservatoryTab` renders without crash; route `/observatory` maps to ObservatoryTab not WebGLSpikeCanvas | unit | `npm test --workspace=apps/workbench -- ObservatoryTab` | `apps/workbench/src/features/observatory/__tests__/observatory-tab.test.tsx` |
| OBS-04 | `probeRuntime.ts` state machine: dispatch → active, advance → cooldown, advance → ready | unit | `npm test --workspace=apps/workbench -- probeRuntime` | `apps/workbench/src/features/observatory/__tests__/probe-runtime.test.ts` |
| OBS-05 | ObservatoryTab mode toggle: click flow → mode state = "flow"; canvas re-renders | unit | `npm test --workspace=apps/workbench -- ObservatoryTab` | `apps/workbench/src/features/observatory/__tests__/observatory-tab.test.tsx` (same file as OBS-03) |
| OBS-06 | Character controller Easter-egg: double-click in flow mode shows toast; `characterControllerEnabled` flips | unit | `npm test --workspace=apps/workbench -- FlowModeController` | `apps/workbench/src/features/observatory/__tests__/flow-mode-controller.test.tsx` |
| FRNX-01 | `ForensicsTapePanel` renders mock events; `BottomPaneTab` type includes "tape"; bottom-pane renders Tape tab button | unit | `npm test --workspace=apps/workbench -- ForensicsTapePanel` | `apps/workbench/src/features/forensics/__tests__/forensics-tape-panel.test.tsx` |

## Phase Gate

All 5 test files must pass before `/gsd:verify-work`:

```bash
npm test --workspace=apps/workbench
```

## Sampling Rate

- Per task commit: `npm test --workspace=apps/workbench -- --reporter=dot`
- Per wave merge: `npm test --workspace=apps/workbench`
- Phase gate: full suite green
