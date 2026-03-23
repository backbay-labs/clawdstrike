# Research: Evidence 3D Preview + Forensics River

**Project:** ClawdStrike Workbench — Huntronomer Integration Milestone
**Researched:** 2026-03-19
**Scope:** Two feature ideas: receipt/evidence 3D preview in editor tabs; live forensics river in bottom pane Tape tab

---

## Feature 1: Receipt/Evidence 3D Preview in Editor Tabs

### What Would This Look Like

When a user opens a `.receipt` or evidence-typed file in an editor tab, instead of a code editor, they get a centered 3D hero prop viewer — think VS Code's built-in image preview but for security artifacts. The prop rotates slowly on a dark field, glows with the station's accent color, and a metadata panel overlays the bottom with the receipt's Ed25519 signature, policy decision, timestamp, and verdict.

The canonical hero prop for evidence/receipts already exists in the observatory: **`evidence-vault-rack`**, the station at the "receipts" observatory station with glow color `#7ee6f2`. This is the correct prop to feature as the default receipt viewer geometry.

### File Type to 3D Model Mapping

The current `FileType` discriminated union (`clawdstrike_policy | sigma_rule | yara_rule | ocsf_event`) does not include a receipt or evidence type. Adding receipt support requires:

1. Add `"receipt"` (and optionally `"evidence_bundle"`) to the `FileType` union in `/apps/workbench/src/lib/workbench/file-type-registry.ts`.
2. Add extension mappings: `.receipt` → `"receipt"`, `.hush` → `"receipt"` (or a separate `"hush_evidence"` type).
3. Update `inferFileTypeFromPath` in `project-store.tsx` to recognize these extensions.
4. The pane system already routes by path/route — a receipt tab route could be `/receipt-preview?file=<path>` opened by `pane-store.openApp()`.

**Prop mapping table:**

| File type / classification | Prop asset ID | Fallback kind | Glow color |
|---|---|---|---|----|
| `receipt` (any verdict) | `evidence-vault-rack` | `vault-rack` | `#7ee6f2` |
| Receipt with `deny` verdict | same | same | `#c45c5c` (override) |
| Receipt with `allow` verdict | same | same | `#3dbf84` (override) |
| `ocsf_event` | `signal-dish-tower` | `tower-dish` | `#7cc8ff` |

The fallback procedural geometry (`vault-rack`) is already implemented in `ObservatoryWorldCanvas.tsx` — all observatory hero props use procedural fallbacks since GLBs are deferred (`availability: "slot"`). The receipt viewer can reuse `ObservatoryHeroPropFallbackModel` directly.

### Interaction Model

The viewer is a small, isolated R3F `Canvas` (not sharing with Observatory) with:
- `frameloop="demand"` when idle, switches to `"always"` during active drag
- `OrbitControls` enabling mouse-drag rotate and scroll-to-zoom
- Auto-rotate: slow ambient spin (0.3 rad/s) when user is not interacting
- Click: no selection; the prop is purely decorative/atmospheric
- A `className="absolute inset-0"` Canvas with a 2D metadata overlay above or below it using HTML (`position: relative`)

Layout:
```
┌──────────────────────────────────────┐
│  [3D hero prop canvas, ~60% height]  │
│       evidence-vault-rack glow       │
├──────────────────────────────────────│
│  Receipt metadata panel (HTML)       │
│  verdict: ALLOW | policy: strict     │
│  sig: Ed25519 a1b2c3... | t: 12:04   │
└──────────────────────────────────────┘
```

### Can We Reuse Observatory Hero Prop Patterns

**Yes, with surgical extraction.** The workbench already has:
- `ObservatoryHeroPropFallbackModel` and `ObservatoryHeroProp` in `ObservatoryWorldCanvas.tsx`
- The `ObservatoryHeroPropAssetId` type and `OBSERVATORY_HERO_PROP_ASSETS` record in `propAssets.ts`
- All fallback geometry for every station prop (`vault-rack`, `scan-rig`, etc.)

The receipt viewer should extract the fallback prop geometry into a standalone scene component rather than import from `ObservatoryWorldCanvas.tsx` directly (that file owns a full scene — importing from it risks pulling in stations, camera rig, etc.). The correct approach is to copy the relevant `ObservatoryHeroPropFallbackModel` geometry into a small `ReceiptHeroPropScene` component with its own lights.

**WebGL context budget:** Each R3F `Canvas` creates a new WebGL context. Browsers allow 8-16 active WebGL contexts before losing older ones. The workbench currently has 3 Canvas instances in non-test code: `ObservatoryWorldCanvas`, `SpiritCompanionCanvas`, `WebGLSpikeCanvas` (the spike canvas is a development artifact and likely can be removed). A receipt preview Canvas would be a 4th. This is safe, **but only one receipt preview should be mounted at a time** — if two receipt tabs are open side-by-side, only the active/visible one should mount its Canvas. Use a `usePaneIsActive()` guard or `visibility: hidden` + `frameloop="never"` for off-screen tabs.

### Dependencies

- `@react-three/fiber` (Canvas, useFrame) — already in workbench `package.json`
- `@react-three/drei` (OrbitControls, Stars, Text) — already present
- `three` — already present
- No new packages needed

### Complexity Estimate

**Medium** — 3-4 days of focused work.

- Add `receipt` to `FileType` and `inferFileTypeFromPath`: 1 hour
- Extract fallback prop geometry into `ReceiptHeroPropScene`: 2 hours
- Build `ReceiptPreviewTab` component (Canvas + metadata overlay): 4 hours
- Wire pane-store to open receipt files as `ReceiptPreviewTab`: 2 hours
- Add Tauri `read_file` call to load receipt JSON from disk: 2 hours
- Context budget guard (hide Canvas when tab not active): 1 hour

### Blocking Questions

1. **File content schema:** What does a ClawdStrike receipt file look like on disk? Is it raw JSON matching the Rust `Receipt` type? Need to confirm the Rust `crates/clawdstrike/src/` serialization format before building the metadata overlay.
2. **Tauri command:** Is there an existing Tauri command to read file content, or does the workbench need to add `fs::read_to_string` + a new `invoke` command?
3. **Detection project roots:** Does the workbench's `DetectionProject` tree scan for `.receipt` files? Currently only policy/sigma/yara/ocsf types are indexed. Receipts may live outside project roots entirely (e.g., `~/.clawdstrike/receipts/`).

---

## Feature 2: Live Forensics River in Bottom Pane Tape Tab

### Current State

`ForensicsTapePanel` is a CSS horizontal scroll of `TapeEventCard` items — mock data, no live telemetry. The bottom pane renders it as the "tape" tab in a `<div className="min-h-0 flex-1">` container with no fixed height constraint beyond the pane's resize handle.

### Auditing @backbay/glia-three — What Does It Export

`@backbay/glia-three` is a real package installed in the `ui-improvements` worktree at `node_modules/@backbay/glia-three`. The `@backbay/glia-three/three` subpath is the R3F-heavy bundle.

**RiverView is exported from `@backbay/glia-three/three` as a namespace** (`import { RiverView as River } from "@backbay/glia-three/three"`). The namespace shape:

```typescript
// Confirmed from dist/three/index.d.ts lines 3618-3714
River.RiverView         // The full-page river component
River.RiverAction       // type
River.CausalLink        // type
River.DetectorData      // type
River.IncidentData      // type
River.PolicySegment     // type
River.SignalData        // type
River.AGENT_COLORS      // string[] palette
River.ACTION_KIND_COLORS // Record<ActionKind, string>
River.RiverBed          // R3F mesh — river surface (useFrame, must be inside Canvas)
River.FlowParticles     // R3F component — particles along curve
River.AgentLane         // R3F component — per-agent lane ribbon
River.createRiverCurve  // helper — produces CatmullRomCurve3
River.getPointOnRiver   // helper — point at t on curve
// ... plus ActionNode, PolicyRail, CausalThread, IncidentVortex, etc.
```

**Critical finding: `RiverView` owns its own Canvas.** Confirmed by reading the compiled chunk (`chunk-Q37MPPVY.js`):

```javascript
// RiverView return statement (actual compiled output):
return jsx("div", {
  style: { position: "relative", width: "100%", height: "100%",
           background: "linear-gradient(to bottom, #0a0a15, #050510)", ...style },
  children: [
    jsx(Canvas8, {          // ← Canvas8 is @react-three/fiber Canvas
      camera: { position: [0, 10, 8], fov: 45, near: 0.1, far: 100 },
      dpr: [1, 1.5],
      children: jsx(RiverScene, { ... })
    }),
    // ... ReplayControls, InspectorPanel overlaid as HTML
  ]
})
```

`River.RiverBed`, `River.FlowParticles`, `River.AgentLane` are R3F primitives — they use `useFrame` and must live inside an existing `Canvas`. They are the building-block API.

### Does RiverView Own Its Own Canvas

**Yes.** The top-level `RiverView` function creates a `Canvas` internally. This means:

- Dropping `<River.RiverView>` into the bottom pane adds a 4th (or 5th) WebGL context.
- If Observatory and Spirit canvases are simultaneously mounted, this pushes the count higher.
- The bottom pane is always visible — unlike Observatory/Nexus pane tabs which are only mounted when open, the Tape tab is always in the DOM (even if behind other tabs). However React only renders the active tab's content, so the Canvas is only mounted when "tape" is the active bottom pane tab.

**Context budget assessment:**

| Canvas | Mounted when | Notes |
|---|---|---|
| `ObservatoryWorldCanvas` | Observatory pane tab open | frameloop=demand |
| `SpiritCompanionCanvas` | Right sidebar rendered | Small, ambient |
| `WebGLSpikeCanvas` | Dev artifact — should be removed | |
| `SpiritManifestationCanvas` | Spirit chamber tab open | |
| `RiverView` (bottom pane) | Tape tab active | NEW |
| Receipt preview Canvas | Receipt tab open | NEW (if built) |

Realistic worst-case simultaneous: Observatory + Spirit Companion + RiverView tape = 3 active contexts. This is safe on any modern GPU (browser limit ~16). The spike canvas should be removed.

### Data Interface

`RiverViewProps` (confirmed from `dist/three/index.d.ts` line 3618):

```typescript
interface RiverViewProps {
  actions: RiverAction[];        // required
  agents: Array<{ id: string; label: string; color?: string }>; // required
  policies?: PolicySegment[];
  signals?: SignalData[];
  incidents?: IncidentData[];
  detectors?: DetectorData[];
  causalLinks?: CausalLink[];
  timeRange: [number, number];   // required — absolute ms timestamps
  initialTime?: number;
  autoPlay?: boolean;
  showPolicyRails?: boolean;
  showCausalThreads?: boolean;
  showSignals?: boolean;
  showDetectors?: boolean;
  showIncidents?: boolean;
  riverWidth?: number;
  onActionSelect?: (id: string | null) => void;
  onIncidentSelect?: (id: string | null) => void;
  onTimeChange?: (time: number) => void;
  className?: string;
  style?: React.CSSProperties;
}
```

Mapping ClawdStrike `TapeEvent` → `RiverAction`:

```typescript
// TapeEvent { id, timestamp, kind, label, stationId? }
// RiverAction needs: id, kind (ActionKind), label, agentId, timestamp,
//                   policyStatus, riskScore, noveltyScore, blastRadius

const TAPE_KIND_TO_ACTION_KIND: Record<TapeEventKind, ActionKind> = {
  allow:   "query",     // generic — or "fs" if file-related
  deny:    "exec",      // or "shell" — most deny events are shell/exec
  receipt: "codepatch", // receipt = audit/signing action
  probe:   "message",   // probe = query/message to station
};

const TAPE_KIND_TO_POLICY_STATUS: Record<TapeEventKind, PolicyStatus> = {
  allow:   "allowed",
  deny:    "denied",
  receipt: "allowed",
  probe:   "uncovered",
};
```

`agentId` defaults to a single `"system"` agent until real session data is available. `riskScore`, `noveltyScore`, `blastRadius` can be stubbed as `deny` → 0.8, `allow` → 0.1, `receipt` → 0.3.

### Telemetry Flow

The existing `ForensicsTapePanel` uses static mock events. The huntronomer `ForensicsRiverView` polls OpenClaw `sessions.preview` over a Tauri bridge. For the workbench river:

**Phase 1 (this milestone — mock):** Build `ForensicsRiverPanel` as a wrapper that converts `MOCK_EVENTS` → `RiverAction[]` and renders `<River.RiverView>`. Replaces the CSS tape with live 3D river on mock data. Functional immediately with no Tauri work.

**Phase 2 (future milestone):** Wire a Tauri `invoke("get_audit_events")` command that returns recent `TapeEvent[]` from the ClawdStrike audit log. Poll every 2 seconds in `live` mode. This is the same Tauri bridge work already deferred in the existing CSS tape footer ("live telemetry deferred").

### Can It Be Embedded Without Owning a Separate Canvas

**No — not using `River.RiverView` directly.** But there is a viable alternative:

**Option A: Full `River.RiverView`** — drop it directly into the tape tab. Adds 1 WebGL context (safe). Height constraint: `River.RiverView` expects `width: 100%, height: 100%` on its parent. The bottom pane's `<div className="min-h-0 flex-1">` already provides this. Set `style={{ height: "100%" }}` on the wrapper. The pane's resize handle naturally controls the river height.

**Option B: Build a custom mini-river from primitives** — use `River.RiverBed`, `River.FlowParticles`, `River.AgentLane` inside a workbench-owned Canvas. Avoids the extra Canvas (shares with existing pane), but requires implementing replay controls, camera, and the action node positioning logic from scratch. High effort for negligible benefit.

**Recommendation: Option A.** The WebGL context count remains safe. Option B is a significant over-engineering of what amounts to a cosmetic upgrade.

### Package Availability

`@backbay/glia-three` is **not currently in the workbench's `package.json`**. The worktree only has `@react-three/fiber`, `@react-three/drei`, `@react-three/rapier`, `three`. Adding `@backbay/glia-three` requires:

1. Add to `package.json` — use `workspace:*` protocol if the backbay monorepo is the source, or pin the version from `ui-improvements/node_modules/@backbay/glia-three/package.json`.
2. Check if it resolves via the Bun workspace symlink. The backbay platform monorepo does not appear to have a `glia-three` package (only `glia-cli`). The package is a pre-built external package installed from a registry or private source.
3. The `ui-improvements` worktree has it installed — copy the `package.json` version specifier from there.

**This is the single hardest dependency question** and must be resolved before implementation begins.

### Implementation Plan for ForensicsRiverPanel

```tsx
// apps/workbench/src/features/forensics/components/ForensicsRiverPanel.tsx

import { RiverView as River } from "@backbay/glia-three/three";
import type { TapeEvent } from "../types";
import { useMemo } from "react";

// Convert TapeEvent → RiverAction
function tapeEventToRiverAction(e: TapeEvent): River.RiverAction {
  return {
    id: e.id,
    kind: TAPE_KIND_TO_ACTION_KIND[e.kind],
    label: e.label,
    agentId: "system",
    timestamp: e.timestamp,
    policyStatus: TAPE_KIND_TO_POLICY_STATUS[e.kind],
    riskScore: e.kind === "deny" ? 0.8 : e.kind === "allow" ? 0.1 : 0.3,
    noveltyScore: 0.2,
    blastRadius: e.kind === "deny" ? 0.6 : 0.1,
  };
}

export function ForensicsRiverPanel({ events }: { events: TapeEvent[] }) {
  const actions = useMemo(() => events.map(tapeEventToRiverAction), [events]);
  const timeRange: [number, number] = useMemo(() => {
    if (!events.length) return [Date.now() - 30000, Date.now() + 5000];
    const ts = events.map((e) => e.timestamp);
    return [Math.min(...ts) - 1000, Date.now() + 5500];
  }, [events]);

  return (
    <River.RiverView
      actions={actions}
      agents={[{ id: "system", label: "ClawdStrike" }]}
      timeRange={timeRange}
      autoPlay
      showPolicyRails
      showSignals={false}
      showDetectors={false}
      showIncidents={false}
      className="h-full w-full"
    />
  );
}
```

### Complexity Estimate

**Low-Medium** — 2-3 days once the `@backbay/glia-three` dependency is resolved.

- Add `@backbay/glia-three` to workbench `package.json` and verify install: 1-2 hours
- Build `ForensicsRiverPanel` with mock event conversion: 3 hours
- Replace `ForensicsTapePanel` with `ForensicsRiverPanel` in `bottom-pane.tsx`: 30 min
- Height/sizing verification in bottom pane: 1 hour
- Regression: ensure tape tab unmounts Canvas when switching to other tabs: 1 hour

### Blocking Questions

1. **`@backbay/glia-three` availability:** Where is this package published? Is there a registry entry, or must it be installed from a tarball/path? The `ui-improvements` worktree has it — check that `package.json` for the version and source.
2. **`@backbay/contract` peer dep:** `glia-three` imports from `@backbay/contract`. The workbench must also have this in its dependency tree. Check whether it resolves through the Bun workspace or needs to be added.
3. **Bottom pane height for 3D:** The bottom pane default height is ~140px (typical for terminal panes). RiverView's 3D river looks best at 200px+. Is resizing the default pane height acceptable, or should the tape tab hint a preferred minimum?

---

## Cross-Feature Notes

### WebGL Context Budget Summary

With both features:

| Canvas | Simultaneous mount condition |
|---|---|
| ObservatoryWorldCanvas | Observatory pane tab open |
| NexusTab (reuses ObservatoryWorldCanvas) | Nexus Hunt Deck tab open — same Canvas component |
| SpiritManifestationCanvas | Spirit chamber tab open |
| SpiritCompanionCanvas | Right sidebar rendered |
| ForensicsRiverPanel (River.RiverView) | Tape bottom tab active |
| ReceiptPreviewTab | Receipt editor tab active AND visible |

Realistic maximum simultaneous: 4-5 if user has Observatory, Spirit companion, river tape, and one receipt tab all open. This is within browser limits. The one mitigation to keep in mind: if the user opens multiple receipt tabs (split pane), mount Canvas only for the focused/visible one. This is a `usePaneIsActive()` guard in the receipt preview component.

### Tauri Bridge Work

Both features are fully buildable in mock/stub mode without Tauri. The live telemetry bridge for the river and the receipt file read are separate future-milestone items. The CSS tape's footer already says "live telemetry deferred" — the 3D river can say the same.

### Shared Infrastructure

Both features could share a `useForensicsEvents()` hook that:
- In mock mode: returns `MOCK_EVENTS`
- In live mode: polls a Tauri `get_audit_events` command
- Provides a `RiverDataset` (for the river) and `TapeEvent[]` (for the receipt metadata panel)

This hook lives in `apps/workbench/src/features/forensics/hooks/useForensicsEvents.ts` and is the right abstraction point for the Tauri bridge.

---

## Recommendation

**Build the forensics river first.** It is lower complexity, has a proven reference implementation in the `ui-improvements` worktree, and the data interface is already fully typed. The only real blocker is confirming `@backbay/glia-three` installation.

**Build receipt preview second.** It requires the new `FileType`, a new `ReceiptPreviewTab` component, and Tauri file I/O. It is self-contained and does not block the river.

Both features should remain in mock/stub mode for this milestone. Live telemetry is a follow-on milestone.
